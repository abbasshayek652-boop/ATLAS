"""Append-Only Tamper-Evident Audit Logging Service.

Rules:
- Every decision, action, login, token refresh, step-up, permission denial,
  approval, veto, and error is written to the append-only audit log.
- Entries are cryptographically linked via SHA-256 hash chaining (prev_hash -> entry_hash).
- No secret, token, password, or private key is ever written to the audit log.
- Any attempt to modify or delete an AuditLog row raises AuditTamperError.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from db.models import AuditLog, AuditTamperError

GENESIS_HASH = "0" * 64

SENSITIVE_KEYS = {
    "password",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "gemini_api_key",
    "jwt_signing_key",
    "machine_api_token",
    "dev_owner_token",
    "authorization",
    "private_key",
}


def sanitize_details(data: Any) -> Any:
    """Recursively redact any secret or token fields before persisting to logs."""
    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            key_lower = str(k).lower()
            if key_lower in SENSITIVE_KEYS or any(
                s in key_lower for s in ("secret", "token", "api_key", "password", "private_key")
            ):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = sanitize_details(v)
        return cleaned
    if isinstance(data, list):
        return [sanitize_details(item) for item in data]
    return data


def compute_entry_hash(
    *,
    event_id: str,
    timestamp_iso: str,
    actor: str,
    action: str,
    target: str,
    tier: Optional[str],
    outcome: str,
    why: str,
    details_json: str,
    prev_hash: str,
) -> str:
    """Compute deterministic SHA-256 hash over the canonical audit record."""
    canonical = json.dumps(
        {
            "event_id": event_id,
            "timestamp": timestamp_iso,
            "actor": actor,
            "action": action,
            "target": target,
            "tier": tier,
            "outcome": outcome,
            "why": why,
            "details_json": details_json,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append_audit_log(
    session: Session,
    *,
    actor: str,
    action: str,
    target: str,
    outcome: str,
    why: str,
    tier: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """Append a new tamper-evident entry to the audit log."""
    last_entry = session.scalar(select(AuditLog).order_by(desc(AuditLog.id)).limit(1))
    prev_hash = last_entry.entry_hash if last_entry else GENESIS_HASH

    event_id = f"aud_{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)
    timestamp_iso = now.isoformat()
    safe_details = sanitize_details(details or {})
    details_json = json.dumps(safe_details, sort_keys=True, default=str)

    entry_hash = compute_entry_hash(
        event_id=event_id,
        timestamp_iso=timestamp_iso,
        actor=actor,
        action=action,
        target=target,
        tier=tier,
        outcome=outcome,
        why=why,
        details_json=details_json,
        prev_hash=prev_hash,
    )

    record = AuditLog(
        event_id=event_id,
        timestamp=now,
        actor=actor,
        action=action,
        target=target,
        tier=tier,
        outcome=outcome,
        why=why,
        details_json=details_json,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    session.add(record)
    session.flush()
    return record


def verify_audit_chain(session: Session) -> Dict[str, Any]:
    """Verify the cryptographic hash chain across all audit log entries."""
    entries: List[AuditLog] = list(
        session.scalars(select(AuditLog).order_by(AuditLog.id.asc())).all()
    )
    expected_prev = GENESIS_HASH
    for idx, entry in enumerate(entries):
        if entry.prev_hash != expected_prev:
            return {
                "valid": False,
                "checked_count": idx + 1,
                "broken_at_id": entry.id,
                " broken_event_id": entry.event_id,
                "reason": "prev_hash mismatch",
            }
        ts = entry.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        recomputed = compute_entry_hash(
            event_id=entry.event_id,
            timestamp_iso=ts.isoformat(),
            actor=entry.actor,
            action=entry.action,
            target=entry.target,
            tier=entry.tier,
            outcome=entry.outcome,
            why=entry.why,
            details_json=entry.details_json,
            prev_hash=entry.prev_hash,
        )
        if recomputed != entry.entry_hash:
            return {
                "valid": False,
                "checked_count": idx + 1,
                "broken_at_id": entry.id,
                "broken_event_id": entry.event_id,
                "reason": "entry_hash mismatch",
            }
        expected_prev = entry.entry_hash

    return {
        "valid": True,
        "checked_count": len(entries),
        "head_hash": expected_prev,
    }


def list_audit_logs(
    session: Session,
    *,
    actor: Optional[str] = None,
    action: Optional[str] = None,
    outcome: Optional[str] = None,
    tier: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """Query read-only audit logs with optional filters."""
    stmt = select(AuditLog).order_by(desc(AuditLog.id))
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if tier is not None:
        stmt = stmt.where(AuditLog.tier == tier)

    stmt = stmt.limit(min(max(limit, 1), 500)).offset(max(offset, 0))
    rows = session.scalars(stmt).all()
    results = []
    for r in rows:
        ts = r.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        results.append(
            {
                "id": r.id,
                "event_id": r.event_id,
                "timestamp": ts.isoformat(),
                "actor": r.actor,
                "action": r.action,
                "target": r.target,
                "tier": r.tier,
                "outcome": r.outcome,
                "why": r.why,
                "details": json.loads(r.details_json) if r.details_json else {},
                "prev_hash": r.prev_hash,
                "entry_hash": r.entry_hash,
            }
        )
    return results


__all__ = [
    "AuditTamperError",
    "GENESIS_HASH",
    "append_audit_log",
    "compute_entry_hash",
    "list_audit_logs",
    "sanitize_details",
    "verify_audit_chain",
]
