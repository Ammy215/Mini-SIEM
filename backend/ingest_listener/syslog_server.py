"""Live syslog receiver, UDP and TCP, for a lab or home network.

Off unless ENABLE_SYSLOG_LISTENER=true. Syslog carries no authentication and a
UDP sender's address can be forged, so the listener:
  - accepts only senders inside SYSLOG_ALLOWED_SOURCES, and won't start without it;
  - binds 127.0.0.1 unless SYSLOG_HOST says otherwise, and never every interface in production;
  - rate-limits each sender, caps message size, TCP connections and idle time;
  - queues into a fixed-size buffer, counting what it drops rather than growing.

A hosted deployment (Render's free tier) can't receive syslog at all; this is
for running Mini SIEM on your own machine, next to the devices that log to it.
"""

import asyncio
import contextlib
import ipaddress
import logging
import re
import time
from dataclasses import asdict, dataclass

import ingest_service
from parsers import pipeline
from parsers.base import ParseContext

logger = logging.getLogger(__name__)

MAX_DATAGRAM_BYTES = 8 * 1024
MAX_TCP_MESSAGE_BYTES = 64 * 1024
MAX_TCP_CONNECTIONS = 20
TCP_IDLE_SECONDS = 60
QUEUE_SIZE = 10_000
FLUSH_MAX_EVENTS = 500
FLUSH_INTERVAL_SECONDS = 1.0
MAX_TRACKED_SENDERS = 4096

_OCTET_COUNT_RE = re.compile(rb"^(\d{1,6}) ")
_PRI_RE = re.compile(r"^<(\d{1,3})>")
_RFC5424_RE = re.compile(r"^<\d{1,3}>\d{1,2} ")


class ListenerConfigError(ValueError):
    pass


def parse_allowlist(text: str | None) -> list:
    networks = []
    for part in (text or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise ListenerConfigError(
                f"SYSLOG_ALLOWED_SOURCES has an entry that isn't an IP address or CIDR range: {part[:64]!r}"
            ) from None
    if not networks:
        raise ListenerConfigError(
            "SYSLOG_ALLOWED_SOURCES must list the senders allowed to log here, e.g. 192.168.1.0/24"
        )
    return networks


def is_allowed(peer_ip: str, networks) -> bool:
    try:
        address = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address.version == network.version and address in network for network in networks)


def check_bind(host: str, app_env: str) -> None:
    if (host or "").strip() in ("", "0.0.0.0", "::") and app_env == "production":
        raise ListenerConfigError(
            "SYSLOG_HOST can't listen on every interface in production; name the one interface to use"
        )


class TokenBucket:
    """`rate` messages a second on average, with bursts of up to `burst`."""

    def __init__(self, rate: float, burst: int, now: float | None = None):
        self.rate = rate
        self.burst = burst
        self.tokens = float(burst)
        self.updated = time.monotonic() if now is None else now

    def take(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


def split_frames(buffer: bytes) -> tuple[list[bytes], bytes, bool]:
    """Splits a TCP byte stream into syslog messages (RFC 6587): octet-counted
    ("57 <34>1 …") or newline-terminated. Returns (messages, bytes left over
    for the next read, whether a message went over the size cap — in which case
    the connection should be closed)."""
    frames: list[bytes] = []
    while buffer:
        counted = _OCTET_COUNT_RE.match(buffer)
        # Octet counting only when a syslog header follows; "12 apples\n" is a plain line.
        if counted and buffer[counted.end():counted.end() + 1] in (b"<", b""):
            length = int(counted.group(1))
            if length > MAX_TCP_MESSAGE_BYTES:
                return frames, b"", True
            end = counted.end() + length
            if len(buffer) < end:
                break
            frames.append(buffer[counted.end():end])
            buffer = buffer[end:]
            continue
        newline = buffer.find(b"\n")
        if newline == -1:
            if len(buffer) > MAX_TCP_MESSAGE_BYTES:
                return frames, b"", True
            break
        frame, buffer = buffer[:newline], buffer[newline + 1:]
        if len(frame) > MAX_TCP_MESSAGE_BYTES:
            return frames, b"", True
        frames.append(frame)
    return frames, buffer, False


def prepare_line(text: str) -> tuple[str, dict]:
    """A received message as a log line, and what its syslog header said.
    RFC 3164 messages lose their <PRI> prefix, so the same line parsers read
    them as would read an uploaded file; RFC 5424 keeps it, because that format
    requires it."""
    line = text.replace("\x00", "").strip()
    extra: dict = {"via": "syslog"}
    pri = _PRI_RE.match(line)
    if pri:
        value = int(pri.group(1))
        if value <= 191:
            extra.update({"facility": value // 8, "severity": value % 8})
        if not _RFC5424_RE.match(line):
            line = line[pri.end():].lstrip()
    return line, extra


@dataclass
class ListenerStats:
    received: int = 0
    stored: int = 0
    not_allowed: int = 0
    oversize: int = 0
    rate_limited: int = 0
    queue_full: int = 0
    insert_failed: int = 0
    tcp_connections: int = 0
    tcp_refused: int = 0


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, listener: "SyslogListener"):
        self.listener = listener

    def datagram_received(self, data: bytes, addr) -> None:
        self.listener.accept(addr[0], data, MAX_DATAGRAM_BYTES)


class SyslogListener:
    def __init__(self, pool, *, host: str, port: int, allowed: list, rate_per_second: float, burst: int):
        self.pool = pool
        self.host = host
        self.port = port
        self.allowed = allowed
        self.rate_per_second = rate_per_second
        self.burst = burst
        self.stats = ListenerStats()
        self.udp_port: int | None = None
        self.tcp_port: int | None = None
        self._queue: asyncio.Queue | None = None
        self._buckets: dict[str, TokenBucket] = {}
        self._udp = None
        self._tcp = None
        self._flusher: asyncio.Task | None = None
        self._writers: set = set()
        self._ctx = ParseContext()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=QUEUE_SIZE)
        self._udp, _ = await loop.create_datagram_endpoint(lambda: _UdpProtocol(self), local_addr=(self.host, self.port))
        self.udp_port = self._udp.get_extra_info("sockname")[1]
        self._tcp = await asyncio.start_server(self._handle_tcp, self.host, self.port)
        self.tcp_port = self._tcp.sockets[0].getsockname()[1]
        self._flusher = asyncio.create_task(self._flush_loop())
        logger.warning(
            "syslog listener on %s (udp %s, tcp %s), accepting %s",
            self.host, self.udp_port, self.tcp_port, ", ".join(map(str, self.allowed)),
        )

    async def stop(self) -> None:
        if self._udp is not None:
            self._udp.close()
        if self._tcp is not None:
            self._tcp.close()
            for writer in list(self._writers):
                writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._tcp.wait_closed(), 5)
        if self._flusher is not None:
            self._flusher.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flusher
        # Whatever was already accepted still gets stored.
        pending = []
        while self._queue is not None and not self._queue.empty():
            pending.append(self._queue.get_nowait())
        if pending:
            await self._store(pending)

    def describe(self) -> dict:
        return {
            "host": self.host,
            "udp_port": self.udp_port,
            "tcp_port": self.tcp_port,
            "allowed_sources": [str(network) for network in self.allowed],
            "rate_per_second": self.rate_per_second,
            "burst": self.burst,
            "queued": self._queue.qsize() if self._queue is not None else 0,
            "stats": asdict(self.stats),
        }

    def accept(self, peer_ip: str, payload: bytes, max_bytes: int) -> None:
        """One received message, from UDP or a TCP frame."""
        self.stats.received += 1
        if not is_allowed(peer_ip, self.allowed):
            self.stats.not_allowed += 1
            return
        if len(payload) > max_bytes:
            self.stats.oversize += 1
            return
        bucket = self._buckets.get(peer_ip)
        if bucket is None:
            if len(self._buckets) >= MAX_TRACKED_SENDERS:
                self._buckets.clear()
            bucket = self._buckets[peer_ip] = TokenBucket(self.rate_per_second, self.burst)
        if not bucket.take():
            self.stats.rate_limited += 1
            return
        text = payload.decode("utf-8", errors="replace")
        if not text.strip():
            return
        try:
            self._queue.put_nowait((peer_ip, text))
        except asyncio.QueueFull:
            self.stats.queue_full += 1

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = (writer.get_extra_info("peername") or ("",))[0]
        if not is_allowed(peer, self.allowed):
            self.stats.not_allowed += 1
            writer.close()
            return
        if len(self._writers) >= MAX_TCP_CONNECTIONS:
            self.stats.tcp_refused += 1
            writer.close()
            return

        self._writers.add(writer)
        self.stats.tcp_connections += 1
        buffer = b""
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(65536), TCP_IDLE_SECONDS)
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    if buffer.strip():  # a last message without a trailing newline
                        self.accept(peer, buffer, MAX_TCP_MESSAGE_BYTES)
                    break
                frames, buffer, overflow = split_frames(buffer + chunk)
                for frame in frames:
                    self.accept(peer, frame, MAX_TCP_MESSAGE_BYTES)
                if overflow:
                    self.stats.oversize += 1
                    break
        except (ConnectionError, OSError):
            pass
        finally:
            self._writers.discard(writer)
            writer.close()

    async def _flush_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            batch = [await self._queue.get()]
            deadline = loop.time() + FLUSH_INTERVAL_SECONDS
            while len(batch) < FLUSH_MAX_EVENTS:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self._queue.get(), remaining))
                except asyncio.TimeoutError:
                    break
            await self._store(batch)

    async def _store(self, batch: list[tuple[str, str]]) -> None:
        events = []
        for peer, text in batch:
            line, extra = prepare_line(text)
            if not line:
                continue
            for event in pipeline.parse_lines([line], self._ctx).events:
                event["raw"] = {**(event.get("raw") or {}), **extra, "peer": peer}
                events.append(event)
        if not events:
            return
        try:
            async with self.pool.acquire() as conn:
                self.stats.stored += await ingest_service.insert_events(conn, events)
        except Exception:
            logger.exception("syslog listener could not store %s events", len(events))
            self.stats.insert_failed += len(events)


def from_settings(pool, settings) -> SyslogListener | None:
    """The configured listener, not yet started, or None when it's switched off.
    Raises ListenerConfigError for settings that would make it unsafe."""
    if not settings.enable_syslog_listener:
        return None
    allowed = parse_allowlist(settings.syslog_allowed_sources)
    check_bind(settings.syslog_host, settings.app_env)
    if not 1 <= settings.syslog_port <= 65535:
        raise ListenerConfigError("SYSLOG_PORT must be between 1 and 65535")
    return SyslogListener(
        pool, host=settings.syslog_host.strip(), port=settings.syslog_port, allowed=allowed,
        rate_per_second=settings.syslog_rate_per_second, burst=settings.syslog_burst,
    )
