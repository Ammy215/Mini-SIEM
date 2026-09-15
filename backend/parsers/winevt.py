"""Windows Event Logs, as the Windows tools themselves export them.

    Event Viewer "Save All Events As… XML"   <Events><Event xmlns=…>…</Event>…</Events>
    wevtutil qe Security /f:xml                <Event> elements one after another, no root
    Get-WinEvent … | ConvertTo-Json            a JSON array of event objects
    … | ConvertTo-Json -Compress, one per line JSON lines

XML carries every field by name, so each event ID maps fully. Plain
ConvertTo-Json only lists EventData values by position; names are applied only
where that order is verified (see _POSITIONAL_FIELDS). For every field of every
event ID from PowerShell, export the XML alongside:

    Get-WinEvent -LogName Security -MaxEvents 5000 |
      Select-Object Id, TimeCreated, MachineName, @{n='Xml'; e={$_.ToXml()}} |
      ConvertTo-Json | Out-File security.json

Both Event Viewer and Windows PowerShell 5.1 write UTF-16 with a byte-order
mark; pipeline.decode_upload handles that before anything here runs.
"""

import ipaddress
import json
import re
from datetime import datetime, timezone
from io import BytesIO
from xml.etree.ElementTree import ParseError

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import iterparse

from parsers.timeutil import parse_flexible

MAX_XML_DEPTH = 32
MAX_MESSAGE_CHARS = 16_000

# Windows event XML never has a DTD, and a DTD is how billion-laughs and XXE
# payloads are built, so any DOCTYPE or ENTITY near the top refuses the whole
# document. defusedxml (forbid_dtd) is the second layer behind this check.
_DTD_SCAN_CHARS = 64 * 1024
_DTD_RE = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)", re.IGNORECASE)
_XML_DECLARATION_RE = re.compile(r"^\s*<\?xml[^>]*\?>", re.IGNORECASE)
_MS_JSON_DATE_RE = re.compile(r"^/Date\((-?\d+)(?:[+-]\d{4})?\)/$")
_LONG_FRACTION_RE = re.compile(r"(\.\d{6})\d+")

# EventID -> (action, outcome). Anything else is kept with action "winevent".
_ACTIONS: dict[int, tuple[str, str | None]] = {
    4624: ("login_success", "success"),
    4625: ("login_failed", "failure"),
    4634: ("logoff", None),
    4647: ("logoff", None),
    4648: ("explicit_credential_logon", None),
    4672: ("privileged_logon", None),
    4688: ("process_created", None),
    4720: ("account_created", None),
    4722: ("account_enabled", None),
    4725: ("account_disabled", None),
    4726: ("account_deleted", None),
    4728: ("group_member_added", None),
    4732: ("group_member_added", None),
    4756: ("group_member_added", None),
    4740: ("account_locked", None),
    # Kerberos pre-authentication failed — a domain controller's view of a
    # wrong password, so it counts toward brute force like 4625 does.
    4771: ("login_failed", "failure"),
    1102: ("audit_log_cleared", None),
}
_GROUP_ADDS = {4728, 4732, 4756}

# EventData field order for ConvertTo-Json exports, which carry values only by
# position. Verified against Microsoft's documented event XML
# (learn.microsoft.com, auditing/event-4624 and event-4625). Later event
# versions only append fields, so these prefixes hold for every version.
_LOGON_SUBJECT_AND_TARGET = (
    "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
    "TargetUserSid", "TargetUserName", "TargetDomainName",
)
_POSITIONAL_FIELDS: dict[int, tuple[str, ...]] = {
    4624: _LOGON_SUBJECT_AND_TARGET + (
        "TargetLogonId", "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName",
        "LogonGuid", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName",
        "IpAddress", "IpPort",
    ),
    4625: _LOGON_SUBJECT_AND_TARGET + (
        "Status", "FailureReason", "SubStatus", "LogonType", "LogonProcessName", "AuthenticationPackageName",
        "WorkstationName", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName",
        "IpAddress", "IpPort",
    ),
}


class WindowsLogRejected(ValueError):
    """The whole document was refused; `reason` is the skip reason to report."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class NotWindowsXml(ValueError):
    """XML, but not Windows event XML — leave it to the other parsers."""


def looks_like_xml(text: str) -> bool:
    head = text.lstrip("﻿ \t\r\n")[:256]
    return head.startswith("<?xml") or head.startswith("<Event")


def is_winevent_object(obj) -> bool:
    return (
        isinstance(obj, dict)
        and any(key in obj for key in ("Id", "EventID", "EventId"))
        and any(key in obj for key in ("TimeCreated", "ProviderName", "LogName", "MachineName", "Xml"))
    )


def parse_xml_document(text: str) -> tuple[list[dict | None], str | None]:
    """Every <Event> in the document, and a skip reason if parsing stopped part
    way through. Raises WindowsLogRejected for an unsafe document and
    NotWindowsXml for XML of some other kind."""
    if _DTD_RE.search(text[:_DTD_SCAN_CHARS]):
        raise WindowsLogRejected("xml_dtd_forbidden")

    # The declaration often says encoding="UTF-16" while the text reaching us
    # has already been decoded; re-encoded as UTF-8 it would contradict itself.
    body = _XML_DECLARATION_RE.sub("", text.lstrip("﻿"), count=1).strip()
    if body.startswith("<Event") and not body.startswith("<Events"):
        body = f"<Events>{body}</Events>"  # wevtutil output has no root element

    events: list[dict | None] = []
    depth = 0
    seen_root = False
    try:
        for kind, element in iterparse(BytesIO(body.encode("utf-8")), events=("start", "end"), forbid_dtd=True):
            if kind == "start":
                if not seen_root:
                    seen_root = True
                    if _local(element.tag) not in ("Events", "Event"):
                        raise NotWindowsXml(_local(element.tag))
                depth += 1
                if depth > MAX_XML_DEPTH:
                    raise WindowsLogRejected("xml_too_deep")
                continue
            depth -= 1
            if _local(element.tag) == "Event":
                events.append(_from_xml_element(element))
                element.clear()
    except DefusedXmlException:
        raise WindowsLogRejected("xml_forbidden_construct")
    except ParseError:
        if not events:
            raise WindowsLogRejected("malformed_xml")
        return events, "malformed_xml"
    return events, None


def from_json_object(obj: dict) -> dict | None:
    xml = obj.get("Xml")
    if isinstance(xml, str) and xml.lstrip().startswith("<Event"):
        try:
            events, _ = parse_xml_document(xml)
        except (WindowsLogRejected, NotWindowsXml):
            events = []
        if events and events[0] is not None:
            return events[0]

    event_id = _int(obj.get("Id", obj.get("EventID", obj.get("EventId"))))
    values = [item.get("Value") if isinstance(item, dict) else item for item in obj.get("Properties") or []]
    names = _POSITIONAL_FIELDS.get(event_id)
    if names and len(values) >= len(names):
        data = {name: _as_text(value) for name, value in zip(names, values)}
        data.update({f"Data{index}": _as_text(value) for index, value in enumerate(values) if index >= len(names)})
    else:
        data = {f"Data{index}": _as_text(value) for index, value in enumerate(values)}

    message = obj.get("Message")
    return _build(
        event_id=event_id,
        event_time=_json_time(obj.get("TimeCreated")),
        provider=obj.get("ProviderName"),
        computer=obj.get("MachineName"),
        channel=obj.get("LogName") or obj.get("ContainerLog"),
        record_id=obj.get("RecordId"),
        level=obj.get("LevelDisplayName") or obj.get("Level"),
        data=data,
        message=message if isinstance(message, str) else None,
    )


def parse_json_line(line: str) -> dict | None:
    """One compact Get-WinEvent object, or one <Event> element, per line."""
    stripped = line.strip()
    if stripped.startswith("<Event"):
        try:
            events, _ = parse_xml_document(stripped)
        except (WindowsLogRejected, NotWindowsXml):
            return None
        return events[0] if events else None
    if not stripped.startswith("{"):
        return None
    try:
        obj = json.loads(stripped, parse_constant=_reject_json_constant)
    except ValueError:
        return None
    return from_json_object(obj) if is_winevent_object(obj) else None


def _from_xml_element(event) -> dict | None:
    system = _child(event, "System")
    if system is None:
        return None

    data: dict[str, str] = {}
    event_data = _child(event, "EventData")
    if event_data is not None:
        for index, item in enumerate(_children(event_data, "Data")):
            # Classic (non-manifest) events have unnamed <Data> items.
            data[item.get("Name") or f"Data{index}"] = (item.text or "").strip()
    user_data = _child(event, "UserData")
    if user_data is not None and len(user_data):
        # e.g. 1102: <UserData><LogFileCleared><SubjectUserName>…
        for field in user_data[0]:
            data[_local(field.tag)] = (field.text or "").strip()

    provider = _child(system, "Provider")
    time_created = _child(system, "TimeCreated")
    rendering = _child(event, "RenderingInfo")
    return _build(
        event_id=_int(_text(system, "EventID")),
        event_time=_iso_time(time_created.get("SystemTime")) if time_created is not None else None,
        provider=provider.get("Name") if provider is not None else None,
        computer=_text(system, "Computer"),
        channel=_text(system, "Channel"),
        record_id=_text(system, "EventRecordID"),
        level=_text(system, "Level"),
        data=data,
        message=_text(rendering, "Message") if rendering is not None else None,
    )


def _build(*, event_id, event_time, provider, computer, channel, record_id, level, data, message) -> dict | None:
    if event_id is None:
        return None

    action, outcome = _classify(event_id, provider, data)
    raw = {
        "channel": channel,
        "provider": provider,
        "record_id": _int(record_id) if _int(record_id) is not None else record_id,
        "level": level,
        "logon_type": _clean(data.get("LogonType")),
        "domain": _clean(data.get("TargetDomainName")) or _clean(data.get("SubjectDomainName")),
        "workstation": _clean(data.get("WorkstationName")) or _clean(data.get("Workstation")),
        "status": _clean(data.get("Status")),
        "sub_status": _clean(data.get("SubStatus")),
        "process_name": _clean(data.get("NewProcessName")) or _clean(data.get("ProcessName")),
        "command_line": _clean(data.get("CommandLine")),
        "group_name": _clean(data.get("TargetUserName")) if event_id in _GROUP_ADDS else None,
        "event_data": data,
    }
    raw = {key: value for key, value in raw.items() if value not in (None, "", {})}
    if event_time is None:
        event_time = datetime.now(timezone.utc)
        raw["_time_inferred"] = True

    event = {
        "event_time": event_time,
        "source_type": "windows",
        "event_code": str(event_id),
        "action": action,
        "raw_message": (message or _summary(event_id, provider, computer, data))[:MAX_MESSAGE_CHARS],
        "raw": raw,
    }
    if outcome:
        event["outcome"] = outcome
    host = _clean(computer)
    if host and len(host) <= 256:
        event["host"] = host
    username = _username(event_id, data)
    if username:
        event["username"] = username
    source_ip = _ip(data.get("IpAddress"))
    if source_ip:
        event["source_ip"] = source_ip
    port = _int(data.get("IpPort"))
    if port and 0 < port <= 65535:
        event["src_port"] = port
    return event


def _classify(event_id: int, provider, data: dict) -> tuple[str, str | None]:
    if event_id in (4768, 4776):
        # Kerberos TGT request / NTLM credential check: the Status code says
        # whether the password was right.
        status = (_clean(data.get("Status")) or "").lower()
        if status and status not in ("0x0", "0"):
            return "login_failed", "failure"
        succeeded = "kerberos_ticket_granted" if event_id == 4768 else "credential_validated"
        return succeeded, "success" if status else None
    if event_id == 104:
        # "The System log file was cleared" — only from the Eventlog provider;
        # other providers reuse ID 104 for unrelated things.
        if "eventlog" in str(provider or "").lower():
            return "audit_log_cleared", None
        return "winevent", None
    return _ACTIONS.get(event_id, ("winevent", None))


def _username(event_id: int, data: dict) -> str | None:
    keys = ("MemberName", "TargetUserName", "SubjectUserName") if event_id in _GROUP_ADDS else ("TargetUserName", "SubjectUserName")
    for key in keys:
        value = _clean(data.get(key))
        if value and len(value) <= 256:
            return value
    return None


def _ip(value) -> str | None:
    text = _clean(value)
    if not text:
        return None
    if text.lower().startswith("::ffff:"):
        text = text[7:]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _summary(event_id: int, provider, computer, data: dict) -> str:
    source = f"{provider or 'Windows'} event {event_id}" + (f" on {computer}" if computer else "")
    fields = "; ".join(f"{key}={value}" for key, value in data.items() if _clean(value))
    return f"{source}: {fields}" if fields else source


def _json_time(value) -> datetime | None:
    if isinstance(value, dict):
        value = value.get("value") or value.get("DateTime")
    if not isinstance(value, str):
        return None
    match = _MS_JSON_DATE_RE.match(value.strip())
    if match:
        try:
            return datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    return _iso_time(value)


def _iso_time(value) -> datetime | None:
    # Windows writes 7 or 9 fractional digits; Python's parser wants at most 6.
    return parse_flexible(_LONG_FRACTION_RE.sub(r"\1", value)) if isinstance(value, str) else None


def _reject_json_constant(name: str):
    raise ValueError(f"{name} is not valid JSON")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(parent, name: str):
    return next((child for child in parent if _local(child.tag) == name), None)


def _children(parent, name: str) -> list:
    return [child for child in parent if _local(child.tag) == name]


def _text(parent, name: str) -> str | None:
    child = _child(parent, name)
    if child is None or child.text is None:
        return None
    return child.text.strip() or None


def _clean(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-") else text


def _as_text(value) -> str:
    return "" if value is None else str(value)


def _int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdecimal():
        return int(value.strip())
    return None
