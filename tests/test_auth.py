import base64
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.core import encryption
from app.core.security import create_token, decode_token, verify_password
from app.database.connection import Base, get_db
from app.database.models import RefreshToken, User
from app.main import app


@pytest.fixture()
def client(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

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
                        base64.urlsafe_b64encode(b"a" * 32).decode("ascii"))
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()


def register(client, email="owner@example.com"):
    response = client.post("/auth/register", json={"email": email, "password": "Correct horse 123!"})
    assert response.status_code == 201
    return response.json()


def login(client, email="owner@example.com"):
    return client.post("/auth/login", data={"username": email, "password": "Correct horse 123!"})


def test_registration_login_and_refresh_rotation(client):
    user = register(client)
    assert user["email"] == "owner@example.com"
    response = login(client)
    assert response.status_code == 200
    original = response.json()
    rotated = client.post("/auth/refresh", json={"refresh_token": original["refresh_token"]})
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != original["refresh_token"]
    rejected = client.post("/auth/refresh", json={"refresh_token": original["refresh_token"]})
    assert rejected.status_code == 401
    assert client.get("/documents", headers={"Authorization": f"Bearer {rotated.json()['access_token']}"}).status_code == 200


def test_login_accepts_email_form_field_and_issues_access_token(client):
    user = register(client, "Owner@Example.com")

    response = client.post("/auth/login", data={
        "email": " OWNER@EXAMPLE.COM ",
        "password": "Correct horse 123!",
    })

    assert response.status_code == 200
    claims = decode_token(response.json()["access_token"], "access")
    assert claims["sub"] == str(user["id"])


def test_registration_normalizes_email_and_persists_bcrypt_hash(client):
    register(client, "Owner@Example.com")
    db_override = app.dependency_overrides[get_db]
    db_generator = db_override()
    db = next(db_generator)
    try:
        user = db.query(User).filter_by(email="owner@example.com").one()
        assert user.password_hash != "Correct horse 123!"
        assert verify_password("Correct horse 123!", user.password_hash)
    finally:
        db_generator.close()


def test_duplicate_registration_is_rejected_case_insensitively(client):
    register(client)
    assert client.post("/auth/register", json={
        "email": "OWNER@example.com", "password": "Correct horse 123!"
    }).status_code == 409


def test_login_rejects_incorrect_password_and_unknown_email(client):
    register(client)
    assert client.post("/auth/login", data={
        "username": "owner@example.com", "password": "wrong password"
    }).status_code == 401
    assert client.post("/auth/login", data={
        "username": "unknown@example.com", "password": "Correct horse 123!"
    }).status_code == 401


def test_logout_revokes_refresh_and_missing_access_is_unauthorized(client):
    register(client)
    tokens = login(client).json()
    assert client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]}).status_code == 204
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert client.get("/documents").status_code == 401


def test_refresh_rejects_malformed_and_wrong_token_type(client):
    assert client.post("/auth/refresh", json={"refresh_token": "not-a-token"}).status_code == 401
    register(client)
    tokens = login(client).json()
    assert client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]}).status_code == 401


def test_access_tokens_reject_refresh_and_expired_tokens(client):
    register(client)
    tokens = login(client).json()

    assert client.get("/documents", headers={
        "Authorization": f"Bearer {tokens['refresh_token']}"
    }).status_code == 401

    expired = create_token("1", "access", timedelta(seconds=-1))
    assert client.get("/documents", headers={
        "Authorization": f"Bearer {expired}"
    }).status_code == 401


def test_swagger_oauth_flow_points_to_form_login_endpoint(client):
    openapi = client.get("/openapi.json").json()

    assert openapi["components"]["securitySchemes"]["OAuth2PasswordBearer"]["flows"][
        "password"
    ]["tokenUrl"] == "/auth/login"


def test_health_checks_database_and_reports_unavailable_database(client):
    assert client.get("/health").status_code == 200
    previous_override = app.dependency_overrides[get_db]

    class UnavailableSession:
        def execute(self, _statement):
            raise SQLAlchemyError("database unavailable")

    def failing_db():
        yield UnavailableSession()

    app.dependency_overrides[get_db] = failing_db
    try:
        response = client.get("/health")
    finally:
        app.dependency_overrides[get_db] = previous_override

    assert response.status_code == 503
    assert response.json() == {"detail": "Database unavailable"}