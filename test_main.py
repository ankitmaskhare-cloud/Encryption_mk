"""
MR-KING PHANTOM — unit tests.

These tests:
  - Do NOT require Firebase credentials.
  - Do NOT require MRK_MASTER_KEY_B64.
  - Import main.py safely (no side effects at import time).

Run:
    pip install pytest
    pytest -q test_main.py
"""

from __future__ import annotations

import base64
import os
import secrets

import pytest
from fastapi import HTTPException
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Ensure safe defaults even if env is polluted.
os.environ.setdefault("ENV", "development")

# Import AFTER setting ENV (but main.py no longer needs env at import time).
import main  # noqa: E402


# ---------------------------------------------------------------------------
# Master key helpers
# ---------------------------------------------------------------------------

def _b64_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def test_decode_master_key_accepts_32_bytes():
    k = main._decode_master_key(_b64_key(), "test")
    assert isinstance(k, bytes) and len(k) == 32


def test_decode_master_key_rejects_16_bytes():
    bad = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    with pytest.raises(RuntimeError):
        main._decode_master_key(bad, "test")


def test_decode_master_key_rejects_non_base64():
    with pytest.raises(RuntimeError):
        main._decode_master_key("!!!not-base64!!!", "test")


def test_load_master_keys_reads_versioned_env():
    current = _b64_key()
    v1 = _b64_key()
    env = {
        "MRK_MASTER_KEY_B64_V1": v1,
    }
    keys = main._load_master_keys_from_env(current, 2, env)
    assert set(keys.keys()) == {1, 2}
    assert len(keys[1]) == 32 and len(keys[2]) == 32


# ---------------------------------------------------------------------------
# Round-trip: empty AND non-empty plaintext
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("plaintext", ["", "a", "hello phantom", "🔥" * 100])
def test_encrypt_decrypt_roundtrip(plaintext: str):
    kek = secrets.token_bytes(32)
    master_keys = {1: kek}
    dek = AESGCM.generate_key(bit_length=256)

    parts = main._encrypt_with_dek(
        plaintext.encode("utf-8"), dek, kek, "uid-A", 1
    )

    out = main._decrypt_envelope(
        owner_uid="uid-A",
        key_version=1,
        master_keys=master_keys,
        data_iv_b64=parts["dataIv"],
        wrapped_key_iv_b64=parts["wrappedKeyIv"],
        wrapped_key_b64=parts["wrappedKey"],
        ciphertext_b64=parts["ciphertext"],
        auth_tag_b64=parts["authTag"],
    )
    assert out.decode("utf-8") == plaintext


def test_empty_plaintext_ciphertext_is_empty_but_valid():
    """Empty plaintext → empty ciphertext, 16-byte authTag (still valid)."""
    kek = secrets.token_bytes(32)
    dek = AESGCM.generate_key(bit_length=256)
    parts = main._encrypt_with_dek(b"", dek, kek, "uid-A", 1)
    assert base64.b64decode(parts["ciphertext"]) == b""
    assert len(base64.b64decode(parts["authTag"])) == 16


# ---------------------------------------------------------------------------
# Tampering / wrong owner / wrong version
# ---------------------------------------------------------------------------

def _make_valid_parts(uid="uid-A", kv=1):
    kek = secrets.token_bytes(32)
    dek = AESGCM.generate_key(bit_length=256)
    parts = main._encrypt_with_dek(b"secret-data", dek, kek, uid, kv)
    return kek, parts


def test_tampered_ciphertext_is_rejected():
    kek, parts = _make_valid_parts()
    ct = bytearray(base64.b64decode(parts["ciphertext"]))
    ct[0] ^= 0x01
    parts["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    with pytest.raises(HTTPException) as exc:
        main._decrypt_envelope(
            owner_uid="uid-A", key_version=1, master_keys={1: kek},
            data_iv_b64=parts["dataIv"],
            wrapped_key_iv_b64=parts["wrappedKeyIv"],
            wrapped_key_b64=parts["wrappedKey"],
            ciphertext_b64=parts["ciphertext"],
            auth_tag_b64=parts["authTag"],
        )
    assert exc.value.status_code == 400


def test_tampered_auth_tag_is_rejected():
    kek, parts = _make_valid_parts()
    tag = bytearray(base64.b64decode(parts["authTag"]))
    tag[0] ^= 0x01
    parts["authTag"] = base64.b64encode(bytes(tag)).decode()
    with pytest.raises(HTTPException):
        main._decrypt_envelope(
            owner_uid="uid-A", key_version=1, master_keys={1: kek},
            data_iv_b64=parts["dataIv"],
            wrapped_key_iv_b64=parts["wrappedKeyIv"],
            wrapped_key_b64=parts["wrappedKey"],
            ciphertext_b64=parts["ciphertext"],
            auth_tag_b64=parts["authTag"],
        )


def test_tampered_wrapped_key_is_rejected():
    kek, parts = _make_valid_parts()
    wk = bytearray(base64.b64decode(parts["wrappedKey"]))
    wk[-1] ^= 0x01
    parts["wrappedKey"] = base64.b64encode(bytes(wk)).decode()
    with pytest.raises(HTTPException):
        main._decrypt_envelope(
            owner_uid="uid-A", key_version=1, master_keys={1: kek},
            data_iv_b64=parts["dataIv"],
            wrapped_key_iv_b64=parts["wrappedKeyIv"],
            wrapped_key_b64=parts["wrappedKey"],
            ciphertext_b64=parts["ciphertext"],
            auth_tag_b64=parts["authTag"],
        )


def test_wrong_owner_uid_via_aad_is_rejected():
    """Even if caller lies about ownerUid, AAD mismatch fails decryption."""
    kek, parts = _make_valid_parts(uid="uid-A")
    with pytest.raises(HTTPException):
        main._decrypt_envelope(
            owner_uid="uid-B",  # different UID → AAD mismatch
            key_version=1, master_keys={1: kek},
            data_iv_b64=parts["dataIv"],
            wrapped_key_iv_b64=parts["wrappedKeyIv"],
            wrapped_key_b64=parts["wrappedKey"],
            ciphertext_b64=parts["ciphertext"],
            auth_tag_b64=parts["authTag"],
        )


def test_unknown_key_version_is_rejected():
    _, parts = _make_valid_parts()
    with pytest.raises(HTTPException) as exc:
        main._decrypt_envelope(
            owner_uid="uid-A", key_version=99, master_keys={1: secrets.token_bytes(32)},
            data_iv_b64=parts["dataIv"],
            wrapped_key_iv_b64=parts["wrappedKeyIv"],
            wrapped_key_b64=parts["wrappedKey"],
            ciphertext_b64=parts["ciphertext"],
            auth_tag_b64=parts["authTag"],
        )
    assert exc.value.status_code == 400


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------

def test_bad_base64_is_rejected():
    kek = secrets.token_bytes(32)
    with pytest.raises(HTTPException) as exc:
        main._decrypt_envelope(
            owner_uid="uid-A", key_version=1, master_keys={1: kek},
            data_iv_b64="not-base64!!!",
            wrapped_key_iv_b64="AAAA",
            wrapped_key_b64="AAAA",
            ciphertext_b64="AAAA",
            auth_tag_b64="AAAA",
        )
    assert exc.value.status_code == 400


def test_bad_iv_length_is_rejected():
    kek = secrets.token_bytes(32)
    with pytest.raises(HTTPException) as exc:
        main._decrypt_envelope(
            owner_uid="uid-A", key_version=1, master_keys={1: kek},
            data_iv_b64=base64.b64encode(b"short").decode(),
            wrapped_key_iv_b64=base64.b64encode(b"short").decode(),
            wrapped_key_b64=base64.b64encode(b"x" * 48).decode(),
            ciphertext_b64=base64.b64encode(b"ct").decode(),
            auth_tag_b64=base64.b64encode(b"y" * 16).decode(),
        )
    assert exc.value.status_code == 400


def test_bad_auth_tag_length_is_rejected():
    kek = secrets.token_bytes(32)
    with pytest.raises(HTTPException) as exc:
        main._decrypt_envelope(
            owner_uid="uid-A", key_version=1, master_keys={1: kek},
            data_iv_b64=base64.b64encode(b"x" * 12).decode(),
            wrapped_key_iv_b64=base64.b64encode(b"y" * 12).decode(),
            wrapped_key_b64=base64.b64encode(b"z" * 48).decode(),
            ciphertext_b64=base64.b64encode(b"ct").decode(),
            auth_tag_b64=base64.b64encode(b"short").decode(),
        )
    assert exc.value.status_code == 400


# ---------------------------------------------------------------------------
# Pydantic model — plaintext size
# ---------------------------------------------------------------------------

def test_pydantic_rejects_oversize_plaintext():
    from pydantic import ValidationError
    too_big = "a" * (main.MAX_PLAINTEXT_BYTES + 1)
    with pytest.raises(ValidationError):
        main.EncryptRequest(plaintext=too_big)


def test_pydantic_accepts_empty_plaintext():
    m = main.EncryptRequest(plaintext="")
    assert m.plaintext == ""


# ---------------------------------------------------------------------------
# App factory — /health works without keys or Firebase
# ---------------------------------------------------------------------------

def test_health_endpoint_has_no_secrets():
    """Health payload must not contain keys, tokens, or env details."""
    app = main.create_app()
    # Extract the /health route via the ASGI app; call it directly.
    from fastapi.testclient import TestClient
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body.get("status") == "ok"
    assert "version" in body
    # No secrets leaked:
    text = r.text.lower()
    for word in ("key", "token", "secret", "password"):
        assert word not in text