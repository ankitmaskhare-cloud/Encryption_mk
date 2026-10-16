"""
MR-KING PHANTOM — FastAPI Backend v2.1
Server-side AES-256-GCM envelope encryption + Firebase Authentication.

Architecture:
  - Per-request random 256-bit DEK.
  - AES-256-GCM for plaintext, AES-256-GCM for DEK wrapping (separate IVs).
  - AAD binds (ownerUid, keyVersion, formatVersion).
  - Firebase ID token → verified UID is the ONLY source of truth for owner.
  - Versioned master keys (KEK) for future rotation with backward compatibility.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Deque, Dict, List, Optional, Tuple

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

import firebase_admin
from firebase_admin import auth as fb_auth, credentials

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Logging — never log secrets, tokens, plaintext, or keys.
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("mrk-phantom")

# ---------------------------------------------------------------------------
# Configuration (all via environment variables)
# ---------------------------------------------------------------------------

ENV = os.environ.get("ENV", "production").strip().lower()

MRK_MASTER_KEY_B64 = os.environ.get("MRK_MASTER_KEY_B64", "").strip()
MRK_MASTER_KEY_VERSION = int(os.environ.get("MRK_MASTER_KEY_VERSION", "1"))

FIREBASE_SERVICE_ACCOUNT_JSON = os.environ.get(
    "FIREBASE_SERVICE_ACCOUNT_JSON", ""
).strip()
FIREBASE_PROJECT_ID = os.environ.get(
    "FIREBASE_PROJECT_ID", "encryption-ee299"
).strip()

ALLOWED_ORIGINS_RAW = os.environ.get("ALLOWED_ORIGINS", "").strip()

# Size limits
MAX_PLAINTEXT_BYTES = 2 * 1024 * 1024        # 2 MiB
MAX_ENVELOPE_BYTES = 4 * 1024 * 1024         # 4 MiB
MAX_REQUEST_BODY_BYTES = 6 * 1024 * 1024     # 6 MiB (hard ASGI cap)

# Rate limits (per UID, sliding window)
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_ENCRYPT = int(os.environ.get("RATE_LIMIT_ENCRYPT", "30"))
RATE_LIMIT_DECRYPT = int(os.environ.get("RATE_LIMIT_DECRYPT", "60"))

# Payload format constants (canonical v2)
PAYLOAD_FORMAT = "MRK-PHANTOM-SERVER"
PAYLOAD_VERSION = 2
PAYLOAD_CIPHER = "AES-256-GCM"
PAYLOAD_KEY_MODE = "SERVER_WRAPPED_DATA_KEY"

# ---------------------------------------------------------------------------
# Master key loading (versioned)
# ---------------------------------------------------------------------------

def _decode_master_key(raw: str, label: str) -> bytes:
    if not raw:
        raise RuntimeError(f"{label} is empty.")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise RuntimeError(f"{label} is not valid base64.") from exc
    if len(key) != 32:
        raise RuntimeError(
            f"{label} must decode to exactly 32 bytes (AES-256). Got {len(key)}."
        )
    return key


def _load_master_keys() -> Dict[int, bytes]:
    """Return {version: key}. Current version from MRK_MASTER_KEY_VERSION."""
    if not MRK_MASTER_KEY_B64:
        raise RuntimeError(
            "MRK_MASTER_KEY_B64 is not set.\n"
            "Generate one with:\n"
            "  python -c \"import secrets,base64; "
            "print(base64.b64encode(secrets.token_bytes(32)).decode())\""
        )
    keys: Dict[int, bytes] = {
        MRK_MASTER_KEY_VERSION: _decode_master_key(
            MRK_MASTER_KEY_B64, "MRK_MASTER_KEY_B64"
        )
    }
    # Optional older keys: MRK_MASTER_KEY_B64_V1, _V2, ...
    for name, value in os.environ.items():
        if not name.startswith("MRK_MASTER_KEY_B64_V"):
            continue
        suffix = name[len("MRK_MASTER_KEY_B64_V"):]
        if not suffix.isdigit():
            continue
        ver = int(suffix)
        if ver in keys:
            continue
        keys[ver] = _decode_master_key(value, name)
    return keys


MASTER_KEYS: Dict[int, bytes] = _load_master_keys()
CURRENT_KEY_VERSION: int = MRK_MASTER_KEY_VERSION

# ---------------------------------------------------------------------------
# Firebase Admin initialization
# ---------------------------------------------------------------------------

def _init_firebase() -> None:
    if firebase_admin._apps:  # already initialized
        return
    if not FIREBASE_SERVICE_ACCOUNT_JSON:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON is not set. Provide the full service "
            "account JSON as a single-line environment variable."
        )
    try:
        sa_info = json.loads(FIREBASE_SERVICE_ACCOUNT_JSON)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON."
        ) from exc

    # Verify project ID matches expectation (defense in depth).
    sa_project = sa_info.get("project_id")
    if sa_project and FIREBASE_PROJECT_ID and sa_project != FIREBASE_PROJECT_ID:
        raise RuntimeError(
            f"Service account project_id='{sa_project}' does not match "
            f"FIREBASE_PROJECT_ID='{FIREBASE_PROJECT_ID}'."
        )
    firebase_admin.initialize_app(credentials.Certificate(sa_info))


_init_firebase()

# ---------------------------------------------------------------------------
# CORS configuration (safe by default in production)
# ---------------------------------------------------------------------------

def _resolve_allowed_origins() -> List[str]:
    """Return list of allowed origins. Production refuses '*'."""
    if not ALLOWED_ORIGINS_RAW:
        if ENV == "production":
            logger.warning(
                "ALLOWED_ORIGINS is empty in production. Cross-origin browser "
                "requests will be blocked. Set ALLOWED_ORIGINS to your frontend "
                "HTTPS origin(s), comma-separated."
            )
            return []
        return ["*"]

    parts = [o.strip() for o in ALLOWED_ORIGINS_RAW.split(",") if o.strip()]
    if "*" in parts:
        if ENV == "production":
            raise RuntimeError(
                "Refusing to start: ALLOWED_ORIGINS contains '*' while "
                "ENV=production. List explicit origins instead, e.g. "
                "https://app.example.com."
            )
        return ["*"]
    return parts


ALLOWED_ORIGINS = _resolve_allowed_origins()

# ---------------------------------------------------------------------------
# Rate limiting (in-memory, single-instance — see README for multi-instance)
# ---------------------------------------------------------------------------

class _SlidingWindowLimiter:
    """Thread-safe in-memory sliding-window limiter keyed by an opaque string."""

    def __init__(self, window_seconds: int, max_events: int) -> None:
        self.window = window_seconds
        self.max_events = max_events
        self._buckets: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> Tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets[key]
            cutoff = now - self.window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_events:
                retry_after = int(self.window - (now - bucket[0])) + 1
                return False, max(retry_after, 1)
            bucket.append(now)
            return True, 0


_ENCRYPT_LIMITER = _SlidingWindowLimiter(RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_ENCRYPT)
_DECRYPT_LIMITER = _SlidingWindowLimiter(RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_DECRYPT)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="MR-KING PHANTOM",
    description="Server-side AES-256-GCM encryption API with Firebase Auth.",
    version="2.1.0",
    docs_url="/docs" if ENV != "production" else None,
    redoc_url=None,
    openapi_url="/openapi.json" if ENV != "production" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)


@app.middleware("http")
async def body_size_guard(request: Request, call_next):
    """Reject oversized request bodies early (before parsing)."""
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"error": "Request body too large."},
                )
        except ValueError:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": "Invalid Content-Length header."},
            )
    return await call_next(request)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class EncryptRequest(BaseModel):
    plaintext: str = Field(..., description="UTF-8 text, max 2 MiB.")

    @field_validator("plaintext")
    @classmethod
    def _check_size(cls, v: str) -> str:
        if v is None:
            raise ValueError("plaintext is required")
        if len(v.encode("utf-8")) > MAX_PLAINTEXT_BYTES:
            raise ValueError("plaintext exceeds 2 MiB limit")
        return v


class EncryptedPayload(BaseModel):
    """Canonical v2 envelope."""

    format: str
    version: int
    cipher: str
    keyMode: str
    ownerUid: str
    keyVersion: int
    dataIv: str
    wrappedKeyIv: str
    wrappedKey: str
    ciphertext: str
    authTag: str
    createdAt: Optional[int] = None


class DecryptRequest(BaseModel):
    payload: EncryptedPayload


class EncryptResponse(BaseModel):
    payload: EncryptedPayload


class DecryptResponse(BaseModel):
    plaintext: str
    ownerUid: str


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except Exception:
        # Do not echo the input.
        raise HTTPException(status_code=400, detail="Malformed encrypted payload.")


def _aad_v2(owner_uid: str, key_version: int) -> bytes:
    """AAD binds wrapped key + ciphertext to (owner, keyVersion, formatVersion)."""
    return (
        f"MRK-PHANTOM|v{PAYLOAD_VERSION}|kv{key_version}|{owner_uid}".encode("utf-8")
    )


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

def verify_firebase_token(
    authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Empty bearer token.")
    try:
        decoded = fb_auth.verify_id_token(token, check_revoked=True)
    except fb_auth.RevokedIdTokenError:
        raise HTTPException(status_code=401, detail="Firebase ID token was revoked.")
    except fb_auth.ExpiredIdTokenError:
        raise HTTPException(status_code=401, detail="Firebase ID token has expired.")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Firebase ID token.")
    uid = decoded.get("uid") or decoded.get("user_id")
    if not uid:
        raise HTTPException(status_code=401, detail="Token has no user id.")
    return {"uid": uid}


def _enforce_rate_limit(limiter: _SlidingWindowLimiter, uid: str) -> None:
    ok, retry_after = limiter.check(uid)
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please retry later.",
            headers={"Retry-After": str(retry_after)},
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "MR-KING PHANTOM",
        "version": PAYLOAD_VERSION,
        "keyVersion": CURRENT_KEY_VERSION,
        "time": int(time.time()),
    }


@app.post("/v1/encrypt", response_model=EncryptResponse)
def encrypt(
    body: EncryptRequest,
    user: Dict[str, Any] = Depends(verify_firebase_token),
) -> EncryptResponse:
    uid: str = user["uid"]
    _enforce_rate_limit(_ENCRYPT_LIMITER, uid)

    plaintext_bytes = body.plaintext.encode("utf-8")
    if len(plaintext_bytes) > MAX_PLAINTEXT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Plaintext exceeds 2 MiB limit.",
        )

    key_version = CURRENT_KEY_VERSION
    kek = MASTER_KEYS[key_version]
    aad = _aad_v2(uid, key_version)

    # 1. Fresh 256-bit DEK per encryption.
    dek = AESGCM.generate_key(bit_length=256)

    # 2. Encrypt plaintext with DEK (unique 12-byte IV).
    data_iv = secrets.token_bytes(12)
    ct_and_tag = AESGCM(dek).encrypt(data_iv, plaintext_bytes, aad)
    ciphertext, auth_tag = ct_and_tag[:-16], ct_and_tag[-16:]

    # 3. Wrap DEK with KEK (unique 12-byte IV).
    wrapped_key_iv = secrets.token_bytes(12)
    wrapped_key_and_tag = AESGCM(kek).encrypt(wrapped_key_iv, dek, aad)

    payload = EncryptedPayload(
        format=PAYLOAD_FORMAT,
        version=PAYLOAD_VERSION,
        cipher=PAYLOAD_CIPHER,
        keyMode=PAYLOAD_KEY_MODE,
        ownerUid=uid,
        keyVersion=key_version,
        dataIv=_b64e(data_iv),
        wrappedKeyIv=_b64e(wrapped_key_iv),
        wrappedKey=_b64e(wrapped_key_and_tag),  # 32-byte key + 16-byte GCM tag
        ciphertext=_b64e(ciphertext),
        authTag=_b64e(auth_tag),
        createdAt=int(time.time()),
    )
    return EncryptResponse(payload=payload)


@app.post("/v1/decrypt", response_model=DecryptResponse)
def decrypt(
    body: DecryptRequest,
    user: Dict[str, Any] = Depends(verify_firebase_token),
) -> DecryptResponse:
    uid: str = user["uid"]
    _enforce_rate_limit(_DECRYPT_LIMITER, uid)

    payload = body.payload

    # Format / version validation.
    if payload.format != PAYLOAD_FORMAT or payload.version != PAYLOAD_VERSION:
        raise HTTPException(status_code=400, detail="Unsupported or malformed payload.")
    if payload.cipher != PAYLOAD_CIPHER or payload.keyMode != PAYLOAD_KEY_MODE:
        raise HTTPException(status_code=400, detail="Unsupported or malformed payload.")

    # Ownership check — token UID is the only source of truth.
    if payload.ownerUid != uid:
        raise HTTPException(status_code=403, detail="You do not own this payload.")

    kek = MASTER_KEYS.get(payload.keyVersion)
    if kek is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported key version {payload.keyVersion}.",
        )

    # Decode base64 fields.
    data_iv = _b64d(payload.dataIv)
    wrapped_key_iv = _b64d(payload.wrappedKeyIv)
    wrapped_key_with_tag = _b64d(payload.wrappedKey)
    ciphertext = _b64d(payload.ciphertext)
    auth_tag = _b64d(payload.authTag)

    # Structural validation.
    if len(data_iv) != 12 or len(wrapped_key_iv) != 12:
        raise HTTPException(status_code=400, detail="Malformed IV length.")
    if len(auth_tag) != 16:
        raise HTTPException(status_code=400, detail="Malformed authentication tag.")
    if len(wrapped_key_with_tag) < 16 + 32:
        raise HTTPException(status_code=400, detail="Malformed wrapped key.")
    if len(ciphertext) == 0:
        raise HTTPException(status_code=400, detail="Empty ciphertext.")

    # Envelope size ceiling.
    total = (
        len(ciphertext)
        + len(auth_tag)
        + len(wrapped_key_with_tag)
        + len(data_iv)
        + len(wrapped_key_iv)
    )
    if total > MAX_ENVELOPE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Encrypted payload exceeds size limit.",
        )

    aad = _aad_v2(uid, payload.keyVersion)

    # 1. Unwrap DEK.
    try:
        dek = AESGCM(kek).decrypt(wrapped_key_iv, wrapped_key_with_tag, aad)
    except Exception:
        raise HTTPException(status_code=400, detail="Unable to decrypt payload.")

    # 2. Decrypt ciphertext (recombine ciphertext + tag for GCM).
    try:
        plaintext_bytes = AESGCM(dek).decrypt(data_iv, ciphertext + auth_tag, aad)
    except Exception:
        raise HTTPException(status_code=400, detail="Unable to decrypt payload.")

    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Decrypted data is not valid UTF-8.")

    return DecryptResponse(plaintext=plaintext, ownerUid=uid)


# ---------------------------------------------------------------------------
# Legacy v2 (snake_case) backward-compatible decrypt endpoint.
# ---------------------------------------------------------------------------

class _LegacyEnvelope(BaseModel):
    format: str
    version: int
    cipher: str
    key_mode: str
    owner_uid: str
    created_at: Optional[int] = None
    ciphertext_iv: str
    ciphertext_ct: str
    wrapped_key_iv: str
    wrapped_key_ct: str


class _LegacyDecryptRequest(BaseModel):
    envelope: _LegacyEnvelope


def _aad_v2_legacy_snake(owner_uid: str) -> bytes:
    return f"MRK-PHANTOM|v{PAYLOAD_VERSION}|{owner_uid}".encode("utf-8")


@app.post("/v1/decrypt/legacy", response_model=DecryptResponse)
def decrypt_legacy(
    body: _LegacyDecryptRequest,
    user: Dict[str, Any] = Depends(verify_firebase_token),
) -> DecryptResponse:
    """Backward-compatible decrypt for earlier snake_case envelopes."""
    uid: str = user["uid"]
    _enforce_rate_limit(_DECRYPT_LIMITER, uid)

    env = body.envelope
    if (
        env.format != PAYLOAD_FORMAT
        or env.version != PAYLOAD_VERSION
        or env.cipher != PAYLOAD_CIPHER
        or env.key_mode != PAYLOAD_KEY_MODE
    ):
        raise HTTPException(status_code=400, detail="Unsupported or malformed payload.")
    if env.owner_uid != uid:
        raise HTTPException(status_code=403, detail="You do not own this payload.")

    # Legacy payloads used key version 1 by convention.
    kek = MASTER_KEYS.get(1) or MASTER_KEYS.get(CURRENT_KEY_VERSION)
    if kek is None:
        raise HTTPException(status_code=400, detail="Legacy key version unavailable.")

    ct_iv = _b64d(env.ciphertext_iv)
    ct_with_tag = _b64d(env.ciphertext_ct)
    wrap_iv = _b64d(env.wrapped_key_iv)
    wrapped_key_with_tag = _b64d(env.wrapped_key_ct)

    if len(ct_iv) != 12 or len(wrap_iv) != 12:
        raise HTTPException(status_code=400, detail="Malformed IV length.")

    aad = _aad_v2_legacy_snake(uid)

    try:
        dek = AESGCM(kek).decrypt(wrap_iv, wrapped_key_with_tag, aad)
    except Exception:
        raise HTTPException(status_code=400, detail="Unable to decrypt payload.")

    try:
        plaintext_bytes = AESGCM(dek).decrypt(ct_iv, ct_with_tag, aad)
    except Exception:
        raise HTTPException(status_code=400, detail="Unable to decrypt payload.")

    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Decrypted data is not valid UTF-8.")

    return DecryptResponse(plaintext=plaintext, ownerUid=uid)


# ---------------------------------------------------------------------------
# Error handlers — never leak internals
# ---------------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail},
        headers=exc.headers or None,
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    _request: Request, exc: RequestValidationError
):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": "Invalid request body."},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request: Request, exc: Exception):
    # Logged server-side, generic to client.
    logger.exception("Unhandled server error")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error."},
    )