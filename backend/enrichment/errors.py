"""Exceptions shared by the threat-intel provider clients.

Error messages are built only from the provider name and an HTTP status or
exception class — never from str(httpx_error), which embeds the full request
URL. ipinfo's URL used to carry its API token, so that string could reach any
logged-in user through the IP Intel page.
"""

import httpx


class ProviderNotConfigured(Exception):
    """No API key is set for this provider, so nothing was sent."""


class ProviderError(Exception):
    """The provider was contacted but didn't return usable data. Worth retrying."""


def provider_http_error(provider: str, exc: httpx.HTTPError) -> ProviderError:
    if isinstance(exc, httpx.HTTPStatusError):
        return ProviderError(f"{provider} returned HTTP {exc.response.status_code}")
    return ProviderError(f"{provider} request failed ({type(exc).__name__})")
