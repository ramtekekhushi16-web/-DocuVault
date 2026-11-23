import base64
import binascii
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import settings


def _key() -> bytes:
    try:
        key = base64.b64decode(settings.encryption_key.encode("ascii"), altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("DOCUVAULT_ENCRYPTION_KEY must be a URL-safe base64-encoded 32-byte key") from exc
    if len(key) != 32:
        raise ValueError("DOCUVAULT_ENCRYPTION_KEY must decode to exactly 32 bytes")
    return key


def validate_key() -> None:
    _key()


def encrypt(plaintext: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(_key()).encrypt(nonce, plaintext.encode("utf-8"), None)


def decrypt(ciphertext: bytes) -> str:
    if len(ciphertext) < 28:
        raise ValueError("Encrypted document payload is truncated")
    nonce, encrypted = ciphertext[:12], ciphertext[12:]
    return AESGCM(_key()).decrypt(nonce, encrypted, None).decode("utf-8")