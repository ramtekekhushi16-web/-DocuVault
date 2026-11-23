import base64

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core import encryption
from app.database.connection import Base, get_db
from app.main import app


@pytest.fixture()
def client(monkeypatch):
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
                        base64.urlsafe_b64encode(b"d" * 32).decode("ascii"))
    monkeypatch.setattr("app.core.config.settings.max_document_bytes", 2_000_000)
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client, session_local
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def create_user(client, email):
    response = client.post("/auth/register", json={"email": email, "password": "Correct horse 123!"})
    assert response.status_code == 201
    token = client.post("/auth/login", data={
        "username": email, "password": "Correct horse 123!"
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_document_crud_version_restore_and_encrypted_storage(client):
    client, session_local = client
    owner = create_user(client, "owner@example.com")
    created = client.post("/documents", headers=owner, json={
        "title": "Design", "content": "first private version"
    })
    assert created.status_code == 201
    document = created.json()
    assert document["role"] == "owner"
    with session_local() as db:
        from app.database.models import Document
        stored = db.get(Document, document["id"])
        assert b"first private version" not in stored.encrypted_content

    updated = client.patch(f"/documents/{document['id']}", headers=owner, json={
        "title": "Design v2", "content": "second private version"
    })
    assert updated.status_code == 200
    assert updated.json()["content"] == "second private version"
    versions = client.get(f"/documents/{document['id']}/versions", headers=owner).json()
    assert [item["version_number"] for item in versions] == [2, 1]
    restored = client.post(f"/documents/{document['id']}/versions/1/restore", headers=owner)
    assert restored.status_code == 200
    assert restored.json()["content"] == "first private version"
    assert len(client.get(f"/documents/{document['id']}/versions", headers=owner).json()) == 3
    assert client.get(f"/documents/{document['id']}", headers=owner).json()["title"] == "Design"


def test_document_download_is_authorized_decrypted_and_audited(client):
    test_client, session_local = client
    owner = create_user(test_client, "owner@example.com")
    viewer = create_user(test_client, "viewer@example.com")
    document = test_client.post("/documents", headers=owner, json={
        "title": "Private report", "content": "downloadable encrypted body"
    }).json()
    document_id = document["id"]
    assert test_client.put(f"/documents/{document_id}/permissions", headers=owner, json={
        "user_email": "viewer@example.com", "role": "viewer"
    }).status_code == 204

    response = test_client.get(f"/documents/{document_id}/download", headers=viewer)
    assert response.status_code == 200
    assert response.content == b"downloadable encrypted body"
    assert "attachment" in response.headers["content-disposition"]
    with session_local() as db:
        from app.database.models import AuditLog, Document
        stored = db.get(Document, document_id)
        assert b"downloadable encrypted body" not in stored.encrypted_content
        event = db.query(AuditLog).filter_by(action="document.downloaded").one()
        assert event.actor_id is not None
        assert event.ip_address

    outsider = create_user(test_client, "outsider@example.com")
    assert test_client.get(f"/documents/{document_id}/download", headers=outsider).status_code == 404


def test_permissions_enforce_viewer_editor_and_owner_roles(client):
    client, _ = client
    owner = create_user(client, "owner@example.com")
    viewer = create_user(client, "viewer@example.com")
    editor = create_user(client, "editor@example.com")
    document = client.post("/documents", headers=owner, json={"title": "Team", "content": "body"}).json()
    doc_id = document["id"]
    assert client.put(f"/documents/{doc_id}/permissions", headers=owner, json={
        "user_email": "viewer@example.com", "role": "viewer"
    }).status_code == 204
    assert client.put(f"/documents/{doc_id}/permissions", headers=owner, json={
        "user_email": "editor@example.com", "role": "editor"
    }).status_code == 204
    assert client.get(f"/documents/{doc_id}", headers=viewer).status_code == 200
    assert client.patch(f"/documents/{doc_id}", headers=viewer, json={"title": "No"}).status_code == 403
    assert client.delete(f"/documents/{doc_id}", headers=viewer).status_code == 403
    assert client.patch(f"/documents/{doc_id}", headers=editor, json={"title": "Edited"}).status_code == 200
    assert client.delete(f"/documents/{doc_id}", headers=editor).status_code == 403
    assert client.delete(f"/documents/{doc_id}/permissions/2", headers=viewer).status_code == 403
    assert client.delete(f"/documents/{doc_id}/permissions/2", headers=owner).status_code == 204
    assert client.get(f"/documents/{doc_id}", headers=viewer).status_code == 404
    assert client.delete(f"/documents/{doc_id}", headers=owner).status_code == 204
    assert client.get(f"/documents/{doc_id}", headers=owner).status_code == 404


def test_search_uses_accessible_documents_and_handles_empty_update(client):
    client, _ = client
    owner = create_user(client, "owner@example.com")
    client.post("/documents", headers=owner, json={"title": "Annual Report", "content": "one"})
    client.post("/documents", headers=owner, json={"title": "Meeting Notes", "content": "two"})
    assert len(client.get("/search", headers=owner, params={"q": "report"}).json()) == 1
    assert client.get("/search", headers=owner, params={"q": "missing"}).json() == []
    document_id = client.get("/documents", headers=owner).json()[0]["id"]
    assert client.patch(f"/documents/{document_id}", headers=owner, json={}).status_code == 422
    assert client.patch(f"/documents/{document_id}", headers=owner, json={"title": None}).status_code == 422
    assert client.post("/documents", headers=owner, json={"title": "   ", "content": "body"}).status_code == 422


def test_permissions_and_version_failures_and_document_size_cap(client, monkeypatch):
    test_client, _ = client
    owner = create_user(test_client, "owner@example.com")
    doc_id = test_client.post("/documents", headers=owner, json={"title": "Doc", "content": "x"}).json()["id"]
    assert test_client.post(f"/documents/{doc_id}/versions/999/restore", headers=owner).status_code == 404
    assert test_client.put(f"/documents/{doc_id}/permissions", headers=owner, json={
        "user_email": "nobody@example.com", "role": "viewer"
    }).status_code == 404
    monkeypatch.setattr("app.core.config.settings.max_document_bytes", 3)
    assert test_client.post("/documents", headers=owner, json={
        "title": "Big", "content": "more than three bytes"
    }).status_code == 413


def test_permission_grant_accepts_email_alias_and_enforces_owner_role(client):
    test_client, _ = client
    owner = create_user(test_client, "owner@example.com")
    editor = create_user(test_client, "editor@example.com")
    target = create_user(test_client, "target@example.com")
    document_id = test_client.post("/documents", headers=owner, json={
        "title": "Shared", "content": "body"
    }).json()["id"]
    assert test_client.put(f"/documents/{document_id}/permissions", headers=owner, json={
        "user_email": "editor@example.com", "role": "editor"
    }).status_code == 204

    assert test_client.put(f"/documents/{document_id}/permissions", headers=editor, json={
        "email": "target@example.com", "role": "viewer"
    }).status_code == 403
    assert test_client.put(f"/documents/{document_id}/permissions", headers=owner, json={
        "email": "target@example.com", "role": "admin"
    }).status_code == 422
    assert test_client.put(f"/documents/{document_id}/permissions", headers=owner, json={
        "email": "target@example.com", "role": "viewer"
    }).status_code == 204
    assert test_client.get(f"/documents/{document_id}", headers=target).status_code == 200


def test_postgres_search_uses_indexable_english_full_text_query():
    from types import SimpleNamespace

    from sqlalchemy.dialects import postgresql

    from app.routes.search import search_documents

    class Query:
        def __init__(self):
            self.expressions = []

        def outerjoin(self, *args):
            return self

        def filter(self, expression):
            self.expressions.append(expression)
            return self

        def distinct(self):
            return self

        def order_by(self, *args):
            return self

        def limit(self, _limit):
            return self

        def all(self):
            return []

    query = Query()
    db = SimpleNamespace(
        bind=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")),
        query=lambda _model: query,
    )
    assert search_documents("vault", db, SimpleNamespace(id=1), 20) == []
    sql = str(query.expressions[-1].compile(dialect=postgresql.dialect()))
    assert "to_tsvector('english', documents.title)" in sql
    assert "@@ websearch_to_tsquery('english'" in sql