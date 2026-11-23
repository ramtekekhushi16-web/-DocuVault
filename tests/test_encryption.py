import base64

import pytest
from cryptography.exceptions import InvalidTag
from pydantic import ValidationError

from app.core import encryption


@pytest.fixture(autouse=True)
def encryption_key(monkeypatch):
    monkeypatch.setattr(encryption.settings, "encryption_key",
                        base64.urlsafe_b64encode(b"e" * 32).decode("ascii"))


def test_encrypt_round_trip_and_random_nonce():
    first = encryption.encrypt("private document text")
    second = encryption.encrypt("private document text")
    assert first != second
    assert b"private document text" not in first
    assert encryption.decrypt(first) == "private document text"


def test_ciphertext_tampering_is_rejected():
    ciphertext = bytearray(encryption.encrypt("secret"))
    ciphertext[-1] ^= 1
    with pytest.raises(InvalidTag):
        encryption.decrypt(bytes(ciphertext))


def test_invalid_key_and_truncated_ciphertext_are_rejected(monkeypatch):
    monkeypatch.setattr(encryption.settings, "encryption_key", "invalid")
    with pytest.raises(ValueError, match="32-byte key"):
        encryption.encrypt("secret")
    monkeypatch.setattr(encryption.settings, "encryption_key",
                        base64.urlsafe_b64encode(b"e" * 32).decode("ascii"))
    with pytest.raises(ValueError, match="truncated"):
        encryption.decrypt(b"short")


def test_config_reads_documented_encryption_environment_variable(monkeypatch):
    from app.core.config import Settings

    encoded = base64.urlsafe_b64encode(b"c" * 32).decode("ascii")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test")
    monkeypatch.setenv("JWT_SECRET_KEY", "j" * 32)
    monkeypatch.setenv("DOCUVAULT_ENCRYPTION_KEY", encoded)
    assert Settings(_env_file=None).encryption_key == encoded


def test_settings_require_database_url_and_jwt_secret(monkeypatch):
    from app.core.config import Settings

    for key in ("DATABASE_URL", "JWT_SECRET_KEY", "DOCUVAULT_ENCRYPTION_KEY"):
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)

    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test")
    monkeypatch.setenv("DOCUVAULT_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"f" * 32).decode())
    monkeypatch.setenv("JWT_SECRET_KEY", "too-short")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)