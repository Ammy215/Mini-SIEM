from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from middleware.proxy_secret import ProxySecretMiddleware


def _client(secret: str) -> TestClient:
    async def ok(request):
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/api/health", ok), Route("/api/auth/login", ok, methods=["POST"])])
    app.add_middleware(ProxySecretMiddleware, secret=secret)
    return TestClient(app)


def test_missing_secret_is_rejected():
    r = _client("s3cret").post("/api/auth/login", headers={"X-Forwarded-For": "203.0.113.7"})
    assert r.status_code == 403


def test_wrong_secret_is_rejected():
    r = _client("s3cret").post("/api/auth/login", headers={"X-Internal-Proxy-Secret": "nope"})
    assert r.status_code == 403


def test_correct_secret_passes():
    r = _client("s3cret").post("/api/auth/login", headers={"X-Internal-Proxy-Secret": "s3cret"})
    assert r.status_code == 200


def test_health_is_exempt_for_keepalive():
    assert _client("s3cret").get("/api/health").status_code == 200


def test_blank_secret_disables_check():
    assert _client("").post("/api/auth/login").status_code == 200
