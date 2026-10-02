from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_ok():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "backend"}


def test_api_health_reports_dependencies_honestly():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    # Must not claim a dependency is healthy without having checked it.
    assert body["dependencies"]["postgres"] == "not_yet_checked"
    assert body["dependencies"]["kafka"] == "not_yet_checked"


def test_correlation_id_is_generated_when_absent():
    resp = client.get("/health")
    assert "X-Correlation-ID" in resp.headers
    assert len(resp.headers["X-Correlation-ID"]) > 0


def test_correlation_id_is_echoed_back_when_provided():
    resp = client.get("/health", headers={"X-Correlation-ID": "test-corr-123"})
    assert resp.headers["X-Correlation-ID"] == "test-corr-123"


def test_unknown_route_returns_404_not_500():
    resp = client.get("/does-not-exist")
    assert resp.status_code == 404
