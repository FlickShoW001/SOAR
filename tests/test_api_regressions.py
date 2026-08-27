"""Focused API regressions for the dashboard and detection pipeline."""

import asyncio

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

import main
from models import AuditLog, Base, Event


def run_async(coroutine):
    """Run an ASGI request without depending on TestClient version coupling."""
    return asyncio.run(coroutine)


def test_login_page_has_security_headers_and_is_not_cached():
    async def request_login():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get("/login")

    response = run_async(request_login())

    assert response.status_code == 200
    assert 'id="login-form"' in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-request-id"]


def test_invalid_login_preserves_username_without_password():
    async def submit_login():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.post(
                "/login",
                data={"username": "operator-name", "password": "incorrect"},
            )

    response = run_async(submit_login())

    assert response.status_code == 401
    assert 'value="operator-name"' in response.text
    assert "incorrect" not in response.text


def test_login_origin_check_uses_the_browser_visible_host():
    def allowed(origin, host="test"):
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "scheme": "http",
                "path": "/login",
                "raw_path": b"/login",
                "query_string": b"",
                "headers": [
                    (b"origin", origin.encode()),
                    (b"host", host.encode()),
                ],
                "client": ("127.0.0.1", 12345),
                "server": ("127.0.0.1", 8000),
            }
        )
        return main._origin_is_allowed(request)

    assert allowed("https://test")
    assert allowed("http://localhost:8000", "127.0.0.1:8000")
    assert not allowed("https://attacker.example")


def test_dashboard_data_supports_authenticated_etag_revalidation():
    token = main._create_session_token(main.ADMIN_USERNAME)
    async def request_dashboard():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            cookies={main.SESSION_COOKIE_NAME: token},
        ) as client:
            first = await client.get("/dashboard/data")
            second = await client.get(
                "/dashboard/data",
                headers={"If-None-Match": first.headers["etag"]},
            )
            return first, second

    first, second = run_async(request_dashboard())

    assert first.status_code == 200
    assert second.status_code == 304
    assert second.headers["cache-control"] == "no-store"


def test_authenticated_dashboard_template_renders_command_center():
    token = main._create_session_token(main.ADMIN_USERNAME)

    async def request_dashboard_page():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            cookies={main.SESSION_COOKIE_NAME: token},
        ) as client:
            return await client.get("/")

    response = run_async(request_dashboard_page())

    assert response.status_code == 200
    assert 'id="main-content"' in response.text
    assert 'id="review-dialog"' in response.text
    assert "Security operations" in response.text


def test_pipeline_failure_is_persisted_and_audited(tmp_path, monkeypatch):
    database_path = tmp_path / "pipeline.db"
    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    sessions = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def override_db():
        db = sessions()
        try:
            yield db
        finally:
            db.close()

    def fail_enrichment(*_args, **_kwargs):
        raise RuntimeError("simulated enrichment failure")

    main.app.dependency_overrides[main.get_db] = override_db
    monkeypatch.setattr(main, "enrich_ip", fail_enrichment)
    try:
        async def submit_detection():
            transport = httpx.ASGITransport(app=main.app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://test",
                auth=(main.ADMIN_USERNAME, main.ADMIN_PASSWORD),
            ) as client:
                return await client.post(
                    "/detections",
                    json={
                        "source_ip": "192.168.1.20",
                        "event_type": "pipeline_test",
                        "severity": 4,
                        "raw_log_line": "synthetic regression event",
                    },
                )

        response = run_async(submit_detection())
    finally:
        main.app.dependency_overrides.clear()

    db = sessions()
    try:
        event = db.query(Event).one()
        actions = [entry.action for entry in db.query(AuditLog).order_by(AuditLog.id)]
        assert response.status_code == 500
        assert event.status == "processing_failed"
        assert actions == ["detect", "pipeline_error"]
    finally:
        db.close()
        engine.dispose()
