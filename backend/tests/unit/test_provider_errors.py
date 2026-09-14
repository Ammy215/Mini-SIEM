"""Threat-intel provider failures: typed errors, and API keys that never leak.

HTTP is routed to an in-process httpx.MockTransport, so nothing here reaches
the internet or spends a free-tier quota."""

import httpx
import pytest

from config import settings
from enrichment import abuseipdb, ipinfo, otx
from enrichment.errors import ProviderError, ProviderNotConfigured

pytestmark = pytest.mark.asyncio(loop_scope="session")

SECRET = "sekret-provider-token-must-never-leak"
_RealAsyncClient = httpx.AsyncClient

PROVIDERS = [
    pytest.param(abuseipdb, "abuseipdb_api_key", id="abuseipdb"),
    pytest.param(otx, "otx_api_key", id="otx"),
    pytest.param(ipinfo, "ipinfo_token", id="ipinfo"),
]


@pytest.fixture
def fake_http(monkeypatch):
    def install(handler):
        requests = []

        def recording_handler(request):
            requests.append(request)
            return handler(request)

        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda **kwargs: _RealAsyncClient(transport=httpx.MockTransport(recording_handler), **kwargs),
        )
        return requests

    return install


@pytest.mark.parametrize("module,setting", PROVIDERS)
@pytest.mark.parametrize("status", [401, 429, 503])
async def test_http_failure_names_the_status_but_never_the_secret(module, setting, status, fake_http, monkeypatch):
    monkeypatch.setattr(settings, setting, SECRET)
    requests = fake_http(lambda request: httpx.Response(status, json={}))

    with pytest.raises(ProviderError) as exc_info:
        await module.query("8.8.8.8")

    assert str(status) in str(exc_info.value)
    assert SECRET not in str(exc_info.value)
    # The key travels in a header. A URL ends up in error messages and logs.
    assert SECRET not in str(requests[0].url)


@pytest.mark.parametrize("module,setting", PROVIDERS)
async def test_network_failure_names_only_the_error_type(module, setting, fake_http, monkeypatch):
    monkeypatch.setattr(settings, setting, SECRET)

    def unreachable(request):
        raise httpx.ConnectError(f"cannot connect to {request.url}")

    fake_http(unreachable)

    with pytest.raises(ProviderError, match=r"request failed \(ConnectError\)") as exc_info:
        await module.query("8.8.8.8")
    assert SECRET not in str(exc_info.value)


@pytest.mark.parametrize("module,setting", PROVIDERS)
async def test_non_json_response_is_a_provider_error(module, setting, fake_http, monkeypatch):
    monkeypatch.setattr(settings, setting, SECRET)
    fake_http(lambda request: httpx.Response(200, text="<html>maintenance</html>"))

    with pytest.raises(ProviderError, match="isn't JSON"):
        await module.query("8.8.8.8")


@pytest.mark.parametrize("module,setting", PROVIDERS[:2])
async def test_missing_key_raises_not_configured_without_calling_out(module, setting, fake_http, monkeypatch):
    monkeypatch.setattr(settings, setting, "")
    requests = fake_http(lambda request: httpx.Response(200, json={}))

    with pytest.raises(ProviderNotConfigured):
        await module.query("8.8.8.8")
    assert requests == []


async def test_ipinfo_sends_its_token_as_a_bearer_header(fake_http, monkeypatch):
    monkeypatch.setattr(settings, "ipinfo_token", SECRET)
    requests = fake_http(lambda request: httpx.Response(200, json={"country": "US", "city": "Mountain View"}))

    result = await ipinfo.query("8.8.8.8")

    assert result["country"] == "US"
    assert requests[0].headers["Authorization"] == f"Bearer {SECRET}"
    assert "token" not in str(requests[0].url)
