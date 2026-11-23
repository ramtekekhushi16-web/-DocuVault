import base64
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import encryption
from app.database.connection import Base, get_db
from app.database.models import AuditLog, ShareLink
from app.main import app


@pytest.fixture()
def api(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session_local = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(encryption.settings, "encryption_key",
                        base64.urlsafe_b64encode(b"s" * 32).decode("ascii"))
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        yield client, session_local
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def login(client, email):
    client.post("/auth/register", json={"email": email, "password": "Correct horse 123!"})
    token = client.post("/auth/login", data={
        "username": email, "password": "Correct horse 123!"
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_share_link_reveals_read_only_document_until_revoked(api):
    client, session_local = api
    owner = login(client, "owner@example.com")
    document = client.post("/documents", headers=owner, json={
        "title": "Shared", "content": "shared content"
    }).json()
    created = client.post(f"/shares/{document['id']}", headers=owner, json={"expires_in_days": 1})
    assert created.status_code == 201
    share = created.json()
    public = client.get(f"/shares/public/{share['token']}")
    assert public.status_code == 200
    assert public.json()["content"] == "shared content"
    assert client.delete(f"/shares/{document['id']}/{share['id']}", headers=owner).status_code == 204
    assert client.get(f"/shares/public/{share['token']}").status_code == 404


def test_expired_share_and_immutable_audit_rows(api):
    client, session_local = api
    owner = login(client, "owner@example.com")
    document = client.post("/documents", headers=owner, json={"title": "Private", "content": "text"}).json()
    share = client.post(f"/shares/{document['id']}", headers=owner, json={}).json()
    with session_local() as db:
        link = db.query(ShareLink).filter_by(id=share["id"]).one()
        link.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
        audit = db.query(AuditLog).filter_by(action="document.created").one()
        audit_id = audit.id
        audit.action = "tampered"
        with pytest.raises(ValueError, match="immutable"):
            db.commit()
        db.rollback()
        audit = db.get(AuditLog, audit_id)
        db.delete(audit)
        with pytest.raises(ValueError, match="immutable"):
            db.commit()
        db.rollback()
    assert client.get(f"/shares/public/{share['token']}").status_code == 404


def test_password_protected_one_time_share_is_consumed_only_on_success(api):
    client, session_local = api
    owner = login(client, "owner@example.com")
    document = client.post("/documents", headers=owner, json={
        "title": "Password protected", "content": "one-time body"
    }).json()
    response = client.post(f"/shares/{document['id']}", headers=owner, json={
        "password": "Share password 123!",
        "one_time": True,
    })
    assert response.status_code == 201
    share = response.json()

    assert client.get(f"/shares/public/{share['token']}").status_code == 401
    assert client.get(
        f"/shares/public/{share['token']}",
        headers={"X-Share-Password": "Wrong password 123!"},
    ).status_code == 401
    with session_local() as db:
        stored = db.query(ShareLink).filter_by(id=share["id"]).one()
        assert stored.password_hash != "Share password 123!"
        assert stored.one_time is True

    allowed = client.get(
        f"/shares/public/{share['token']}",
        headers={"X-Share-Password": "Share password 123!"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["content"] == "one-time body"
    assert client.get(
        f"/shares/public/{share['token']}",
        headers={"X-Share-Password": "Share password 123!"},
    ).status_code == 404


def test_audit_endpoint_lists_actor_and_owned_document_events(api):
    client, _ = api
    owner = login(client, "owner@example.com")
    document = client.post("/documents", headers=owner, json={
        "title": "Audited", "content": "body"
    }).json()
    assert client.get(f"/documents/{document['id']}/download", headers=owner).status_code == 200

    response = client.get("/audit", headers=owner)
    assert response.status_code == 200
    actions = [event["action"] for event in response.json()]
    assert "auth.login" in actions
    assert "document.version_created" in actions
    assert "document.downloaded" in actions
    downloaded = next(event for event in response.json() if event["action"] == "document.downloaded")
    assert downloaded["ip_address"]