"""Authentication, Authorization, Step-Up Verification, Rate Limiting & Lockout.

Implements Addendum A2:
- Google OAuth 2.0 ID token verification with exact OWNER_EMAIL allowlist
- Short-lived Access JWT (15m) + revocable SHA-256 hashed Refresh Token (7d)
- Step-up verification (fresh Google re-authentication within 5 minutes)
- Scoped Machine Token (constant-time hash comparison, rotatable without redeploy)
- Dev-only bypass (DEV_OWNER_TOKEN, strictly blocked in ENV=prod)
- Login lockout and sliding-window rate limiting
- Full audit logging of all auth events
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Deque, Dict, Optional

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.audit import append_audit_log
from core.config import Settings, load_settings
from db.database import get_db
from db.models import AuthLockoutRecord, RefreshTokenRecord


MACHINE_ALLOWED_SCOPES = frozenset(
    {
        "read:status",
        "read:health",
        "create:low_tier_task",
        "execute:kill_switch",
    }
)

OWNER_ALL_SCOPES = frozenset(
    {
        "read:status",
        "read:health",
        "read:all",
        "write:tasks",
        "create:low_tier_task",
        "execute:kill_switch",
        "execute:resume",
        "write:agents",
        "write:approvals",
        "write:charter",
        "write:limits",
        "write:autonomy",
    }
)


@dataclass
class AuthPrincipal:
    """Authenticated caller identity and security context."""

    actor: str
    principal_type: str  # "owner" | "machine"
    email: Optional[str]
    scopes: frozenset[str]
    authenticated_at: int
    step_up_at: Optional[int]
    is_dev_bypass: bool = False

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "read:all" in self.scopes and scope.startswith("read:")

    def has_fresh_step_up(self, max_age_seconds: int = 300, now_ts: Optional[int] = None) -> bool:
        if self.principal_type != "owner" or self.step_up_at is None:
            return False
        now = now_ts if now_ts is not None else int(time.time())
        return 0 <= (now - self.step_up_at) <= max_age_seconds


# --- RFC 7519 HS256 JWT Encoding & Decoding (Constant-time signature verification) ---


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode((segment + padding).encode("ascii"))


def encode_jwt(payload: Dict[str, Any], secret: str) -> str:
    """Create an HS256-signed JWT."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_jwt(token: str, secret: str, now_ts: Optional[int] = None) -> Dict[str, Any]:
    """Verify and decode an HS256-signed JWT using constant-time comparison."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT format")
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        provided_sig = _b64url_decode(sig_b64)
    except Exception as exc:
        raise ValueError("Invalid JWT encoding") from exc

    if header.get("alg") != "HS256":
        raise ValueError("Unsupported JWT algorithm")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise ValueError("Invalid JWT signature")

    now = now_ts if now_ts is not None else int(time.time())
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or now >= int(exp):
        raise ValueError("Token has expired")

    return payload


def hash_token(raw_token: str) -> str:
    """Compute SHA-256 hex digest of a raw secret token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


# --- Pluggable Google ID Token Verifier ---

GoogleVerifierFn = Callable[[str, str], Dict[str, Any]]
_CUSTOM_GOOGLE_VERIFIER: Optional[GoogleVerifierFn] = None


def set_google_id_token_verifier(verifier: Optional[GoogleVerifierFn]) -> None:
    """Override the Google ID token verifier (used in tests or custom environments)."""
    global _CUSTOM_GOOGLE_VERIFIER
    _CUSTOM_GOOGLE_VERIFIER = verifier


def verify_google_id_token(id_token_str: str, expected_client_id: str) -> Dict[str, Any]:
    """Verify a Google OAuth 2.0 ID token (signature, audience, expiry, email_verified)."""
    if _CUSTOM_GOOGLE_VERIFIER is not None:
        claims = _CUSTOM_GOOGLE_VERIFIER(id_token_str, expected_client_id)
    else:
        try:
            from google.auth.transport import requests as google_requests
            from google.oauth2 import id_token as google_id_token

            claims = google_id_token.verify_oauth2_token(
                id_token_str,
                google_requests.Request(),
                audience=expected_client_id,
            )
        except ImportError as exc:
            raise ValueError("google-auth library is required for live Google ID token verification") from exc
        except Exception as exc:
            raise ValueError(f"Google ID token verification failed: {exc}") from exc

    aud = claims.get("aud")
    if aud != expected_client_id:
        raise ValueError("Google ID token audience mismatch")

    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or int(time.time()) >= int(exp):
        raise ValueError("Google ID token has expired")

    if claims.get("email_verified") is not True:
        raise ValueError("Google account email is not verified")

    email = str(claims.get("email", "")).strip().lower()
    if not email:
        raise ValueError("Google ID token missing email claim")

    return claims


# --- Rate Limiting & Lockout ---


class SlidingWindowRateLimiter:
    """In-memory sliding-window rate limiter keyed by client identifier and bucket."""

    def __init__(self) -> None:
        self._events: Dict[str, Deque[float]] = defaultdict(deque)

    def check_and_record(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.monotonic()
        dq = self._events[key]
        while dq and (now - dq[0]) > window_seconds:
            dq.popleft()
        if len(dq) >= limit:
            return False
        dq.append(now)
        return True

    def reset(self) -> None:
        self._events.clear()


RATE_LIMITER = SlidingWindowRateLimiter()


def check_lockout(session: Session, actor_key: str, settings: Settings) -> None:
    """Raise HTTP 429 if the actor_key is currently locked out due to repeated auth failures."""
    record = session.get(AuthLockoutRecord, actor_key)
    if not record or not record.locked_until:
        return
    now = datetime.now(timezone.utc)
    locked_until = record.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    if now < locked_until:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account/IP temporarily locked due to repeated failed authentication attempts.",
        )


def record_auth_failure(session: Session, actor_key: str, settings: Settings) -> AuthLockoutRecord:
    """Increment failure count and engage lockout if threshold is reached."""
    now = datetime.now(timezone.utc)
    record = session.get(AuthLockoutRecord, actor_key)
    if not record:
        record = AuthLockoutRecord(
            actor_key=actor_key,
            failed_attempts=1,
            first_failed_at=now,
            locked_until=None,
            updated_at=now,
        )
        session.add(record)
    else:
        first_failed = record.first_failed_at
        if first_failed.tzinfo is None:
            first_failed = first_failed.replace(tzinfo=timezone.utc)
        if (now - first_failed).total_seconds() > settings.auth_lockout_window_seconds:
            record.failed_attempts = 1
            record.first_failed_at = now
            record.locked_until = None
        else:
            record.failed_attempts += 1
        record.updated_at = now

    if record.failed_attempts >= settings.auth_lockout_threshold:
        record.locked_until = now + timedelta(seconds=settings.auth_lockout_window_seconds)

    session.flush()
    return record


def clear_auth_failures(session: Session, actor_key: str) -> None:
    """Reset failed login counter after a successful authentication."""
    record = session.get(AuthLockoutRecord, actor_key)
    if record:
        record.failed_attempts = 0
        record.locked_until = None
        session.flush()


# --- Token Issuance, Refresh, Revocation, and Step-Up ---


def issue_owner_tokens(
    session: Session,
    *,
    owner_email: str,
    settings: Settings,
    is_step_up: bool = True,
) -> Dict[str, Any]:
    """Issue a short-lived access JWT (15 min) and a revocable hashed refresh token (7 days)."""
    now_ts = int(time.time())
    now_dt = datetime.fromtimestamp(now_ts, tz=timezone.utc)
    access_exp = now_ts + settings.access_token_ttl_seconds
    step_up_at = now_ts if is_step_up else None

    access_payload = {
        "sub": f"owner:{owner_email}",
        "email": owner_email,
        "role": "chairman",
        "iat": now_ts,
        "exp": access_exp,
        "step_up_at": step_up_at,
        "jti": secrets.token_hex(12),
    }
    access_token = encode_jwt(access_payload, settings.jwt_signing_key)

    raw_refresh_token = f"rt_{secrets.token_urlsafe(36)}"
    refresh_hash = hash_token(raw_refresh_token)
    refresh_expires_dt = now_dt + timedelta(seconds=settings.refresh_token_ttl_seconds)

    refresh_record = RefreshTokenRecord(
        token_hash=refresh_hash,
        owner_email=owner_email,
        issued_at=now_dt,
        expires_at=refresh_expires_dt,
        revoked=False,
    )
    session.add(refresh_record)
    session.flush()

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh_token,
        "token_type": "Bearer",
        "expires_in": settings.access_token_ttl_seconds,
        "step_up_verified_until": (
            datetime.fromtimestamp(now_ts + settings.step_up_max_age_seconds, tz=timezone.utc).isoformat()
            if is_step_up
            else None
        ),
    }


def login_with_google_id_token(
    session: Session,
    *,
    id_token_str: str,
    client_ip: str = "unknown",
    is_step_up_flow: bool = False,
    settings: Optional[Settings] = None,
) -> Dict[str, Any]:
    """Verify Google ID token, enforce exact OWNER_EMAIL match, issue tokens, and audit-log."""
    cfg = settings or load_settings()
    actor_key = f"ip:{client_ip}"

    if not RATE_LIMITER.check_and_record(f"login:{client_ip}", cfg.rate_limit_login_per_minute, 60):
        append_audit_log(
            session,
            actor=actor_key,
            action="auth.rate_limited",
            target="auth/google",
            outcome="DENIED",
            why="Login rate limit exceeded",
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login requests. Please retry in a minute.",
        )

    check_lockout(session, actor_key, cfg)

    try:
        claims = verify_google_id_token(id_token_str, cfg.google_client_id)
    except ValueError as exc:
        record_auth_failure(session, actor_key, cfg)
        append_audit_log(
            session,
            actor=actor_key,
            action="auth.login_failed",
            target="auth/google",
            outcome="DENIED",
            why=str(exc),
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Google ID token: {exc}",
        ) from exc

    email = str(claims.get("email", "")).strip().lower()
    if not hmac.compare_digest(email.encode("utf-8"), cfg.owner_email.encode("utf-8")):
        record_auth_failure(session, actor_key, cfg)
        append_audit_log(
            session,
            actor=f"unauthorized:{email}",
            action="auth.non_owner_rejected",
            target="auth/google",
            outcome="DENIED",
            why=f"Google account '{email}' is not the authorized owner",
            details={"client_ip": client_ip, "attempted_email": email},
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Google account is not the authorized Chairman.",
        )

    clear_auth_failures(session, actor_key)
    bundle = issue_owner_tokens(session, owner_email=email, settings=cfg, is_step_up=True)
    append_audit_log(
        session,
        actor=f"owner:{email}",
        action="auth.step_up_verified" if is_step_up_flow else "auth.login_success",
        target="auth/google",
        outcome="SUCCESS",
        why="Google OAuth 2.0 ID token verified for single owner",
        details={"client_ip": client_ip, "step_up": True},
    )
    session.commit()
    return bundle


def refresh_access_token(
    session: Session,
    *,
    raw_refresh_token: str,
    client_ip: str = "unknown",
    settings: Optional[Settings] = None,
) -> Dict[str, Any]:
    """Exchange a valid, unrevoked refresh token for a rotated access + refresh token pair.

    Note: Refreshed access tokens do NOT carry fresh step-up verification; step-up
    requires a fresh Google ID token within the last 5 minutes.
    """
    cfg = settings or load_settings()
    token_hash = hash_token(raw_refresh_token)
    record = session.scalar(
        select(RefreshTokenRecord).where(RefreshTokenRecord.token_hash == token_hash)
    )
    now_dt = datetime.now(timezone.utc)

    if not record or record.revoked:
        append_audit_log(
            session,
            actor=f"ip:{client_ip}",
            action="auth.refresh_failed",
            target="auth/refresh",
            outcome="DENIED",
            why="Refresh token is invalid or revoked",
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is invalid or has been revoked.",
        )

    expires_at = record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if now_dt >= expires_at:
        record.revoked = True
        record.revoked_at = now_dt
        append_audit_log(
            session,
            actor=f"owner:{record.owner_email}",
            action="auth.refresh_expired",
            target="auth/refresh",
            outcome="DENIED",
            why="Refresh token has expired",
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired.",
        )

    # Rotate refresh token (revoke old, issue new without step-up)
    record.revoked = True
    record.revoked_at = now_dt
    bundle = issue_owner_tokens(
        session,
        owner_email=record.owner_email,
        settings=cfg,
        is_step_up=False,
    )
    append_audit_log(
        session,
        actor=f"owner:{record.owner_email}",
        action="auth.token_refreshed",
        target="auth/refresh",
        outcome="SUCCESS",
        why="Refresh token rotated and new access token issued",
        details={"client_ip": client_ip},
    )
    session.commit()
    return bundle


def revoke_refresh_token(
    session: Session,
    *,
    raw_refresh_token: str,
    actor: str,
) -> None:
    """Explicitly revoke a refresh token."""
    token_hash = hash_token(raw_refresh_token)
    record = session.scalar(
        select(RefreshTokenRecord).where(RefreshTokenRecord.token_hash == token_hash)
    )
    if record and not record.revoked:
        record.revoked = True
        record.revoked_at = datetime.now(timezone.utc)
        append_audit_log(
            session,
            actor=actor,
            action="auth.token_revoked",
            target="auth/revoke",
            outcome="SUCCESS",
            why="Refresh token explicitly revoked",
        )
        session.commit()


# --- Request Authentication & Scope Enforcement ---


def extract_bearer_token(request: Request) -> str:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization Bearer header.",
        )
    token = auth_header[len("Bearer ") :].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty Bearer token.",
        )
    return token


def authenticate_bearer_token(
    token: str,
    session: Session,
    settings: Optional[Settings] = None,
) -> AuthPrincipal:
    """Authenticate a Bearer token as Owner JWT, Scoped Machine Token, or Dev Bypass."""
    cfg = settings or load_settings()

    # 1. Check Scoped Machine Token (hashed constant-time comparison, rotatable via env)
    if cfg.machine_api_token_hash:
        candidate_hash = hash_token(token)
        if hmac.compare_digest(candidate_hash, cfg.machine_api_token_hash):
            return AuthPrincipal(
                actor="machine:automation",
                principal_type="machine",
                email=None,
                scopes=MACHINE_ALLOWED_SCOPES,
                authenticated_at=int(time.time()),
                step_up_at=None,
                is_dev_bypass=False,
            )

    # 2. Check DEV_OWNER_TOKEN bypass (ONLY when ENV=dev or ENV=test; strictly blocked in prod)
    if cfg.is_dev_or_test and not cfg.is_prod and cfg.dev_owner_token:
        if hmac.compare_digest(token.encode("utf-8"), cfg.dev_owner_token.encode("utf-8")):
            now_ts = int(time.time())
            return AuthPrincipal(
                actor=f"owner:{cfg.owner_email}",
                principal_type="owner",
                email=cfg.owner_email,
                scopes=OWNER_ALL_SCOPES,
                authenticated_at=now_ts,
                step_up_at=now_ts,
                is_dev_bypass=True,
            )

    # 3. Verify Owner JWT
    try:
        payload = decode_jwt(token, cfg.jwt_signing_key)
    except ValueError as exc:
        append_audit_log(
            session,
            actor="anonymous",
            action="auth.token_rejected",
            target="bearer_jwt",
            outcome="DENIED",
            why=str(exc),
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
        ) from exc

    email = str(payload.get("email", "")).strip().lower()
    if not email or not hmac.compare_digest(email.encode("utf-8"), cfg.owner_email.encode("utf-8")):
        append_audit_log(
            session,
            actor=f"unauthorized:{email or 'unknown'}",
            action="auth.jwt_owner_mismatch",
            target="bearer_jwt",
            outcome="DENIED",
            why="JWT email claim does not match configured OWNER_EMAIL",
        )
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token subject is not the authorized owner.",
        )

    step_up_raw = payload.get("step_up_at")
    step_up_at = int(step_up_raw) if isinstance(step_up_raw, (int, float)) else None
    iat = int(payload.get("iat", int(time.time())))

    return AuthPrincipal(
        actor=f"owner:{email}",
        principal_type="owner",
        email=email,
        scopes=OWNER_ALL_SCOPES,
        authenticated_at=iat,
        step_up_at=step_up_at,
        is_dev_bypass=False,
    )


def get_current_principal(
    request: Request,
    session: Session = Depends(get_db),
) -> AuthPrincipal:
    """FastAPI dependency returning the authenticated caller principal."""
    cfg = load_settings()
    if cfg.enforce_https:
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        if proto != "https" and request.url.hostname not in ("localhost", "127.0.0.1", "testserver"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="HTTPS is required for all API requests.",
            )

    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        client_ip = request.client.host if request.client else "unknown"
        if not RATE_LIMITER.check_and_record(
            f"write:{client_ip}", cfg.rate_limit_write_per_minute, 60
        ):
            append_audit_log(
                session,
                actor=f"ip:{client_ip}",
                action="security.write_rate_limited",
                target=request.url.path,
                outcome="DENIED",
                why="Write endpoint rate limit exceeded",
            )
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for write endpoints.",
            )

    token = extract_bearer_token(request)
    return authenticate_bearer_token(token, session, cfg)


def require_scope(required_scope: str, *, require_step_up: bool = False):
    """FastAPI dependency factory enforcing scope and optional 5-minute step-up verification."""

    def _dependency(
        request: Request,
        principal: AuthPrincipal = Depends(get_current_principal),
        session: Session = Depends(get_db),
    ) -> AuthPrincipal:
        cfg = load_settings()
        if not principal.has_scope(required_scope):
            append_audit_log(
                session,
                actor=principal.actor,
                action="auth.permission_denied",
                target=request.url.path,
                outcome="DENIED",
                why=f"Principal '{principal.principal_type}' lacks required scope '{required_scope}'",
                details={"required_scope": required_scope, "principal_type": principal.principal_type},
            )
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: scope '{required_scope}' is required.",
            )

        if require_step_up and not principal.has_fresh_step_up(cfg.step_up_max_age_seconds):
            append_audit_log(
                session,
                actor=principal.actor,
                action="auth.step_up_required",
                target=request.url.path,
                outcome="DENIED",
                why="Action requires fresh Google step-up re-authentication within the last 5 minutes",
                details={"required_scope": required_scope},
            )
            session.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Step-up verification required: please re-authenticate with Google Sign-In within the last 5 minutes.",
            )

        return principal

    return _dependency
