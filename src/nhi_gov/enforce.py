"""Automated expiration and remediation policy.

``plan_actions`` turns audit findings into concrete actions. Only changes that
are safe to automate are marked ``automatic``; anything needing a human
(missing owner, unjustified privilege) becomes an owner notification.

``apply_actions`` performs the automatic ones against the inventory and records
every step in an audit log. It is a dry run unless ``apply=True``, and it never
touches identities tagged ``nhi:protected=true`` (e.g. break-glass accounts).

Because this repo works on exported inventories, "applying" updates the
inventory snapshot. A live connector would make the same changes through the
Microsoft Graph API (``addPassword`` / ``removePassword``, ``accountEnabled``)
or the host's account tooling.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from .audit import AuditResult
from .models import Credential, Identity, format_time
from .policy import Policy

# rule -> (action kind, automatic?)
ACTION_FOR_RULE = {
    "NHI-001": ("rotate_credential", True),
    "NHI-002": ("shorten_expiry", True),
    "NHI-006": ("remove_expired_credential", True),
    "NHI-004": ("disable_identity", True),       # only if policy.auto_disable_stale
    "NHI-007": ("revoke_credentials", True),
    "NHI-003": ("notify_owner", False),
    "NHI-005": ("notify_owner", False),
    "NHI-008": ("notify_owner", False),
    "NHI-009": ("notify_owner", False),
}


@dataclass
class Action:
    kind: str
    identity_id: str
    identity_name: str
    rule: str
    reason: str
    automatic: bool
    credential_id: Optional[str] = None
    skipped_reason: Optional[str] = None
    result: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def plan_actions(audit: AuditResult, policy: Policy) -> list[Action]:
    actions: list[Action] = []
    for r in audit.results:
        identity = r.identity
        t = policy.for_environment(identity.environment)
        planned: set[tuple[str, Optional[str]]] = set()
        # If this run will disable the identity, issuing it fresh credentials makes
        # no sense: revoke what it has instead of rotating or shortening.
        disabling = (not identity.protected and t.auto_disable_stale
                     and any(f.rule == "NHI-004" for f in r.findings))
        for f in r.findings:
            kind, automatic = ACTION_FOR_RULE[f.rule]
            if disabling and kind in {"rotate_credential", "shorten_expiry"}:
                kind = "revoke_credentials"
            # A credential that is both too old and too long-lived only needs rotating.
            if kind == "shorten_expiry" and ("rotate_credential", f.credential_id) in planned:
                continue
            key = (kind, None if kind == "revoke_credentials" else
                   f.rule if kind == "notify_owner" else f.credential_id)
            if key in planned:
                continue
            planned.add(key)
            cred = None if kind == "revoke_credentials" else f.credential_id
            action = Action(kind, identity.id, identity.name, f.rule, f.message, automatic, cred)
            if identity.protected and automatic:
                action.automatic = False
                action.skipped_reason = "identity is tagged nhi:protected (review manually)"
            elif kind == "disable_identity" and not t.auto_disable_stale:
                action.automatic = False
                action.skipped_reason = "auto_disable_stale is off for this environment"
            actions.append(action)
    return actions


def _find_credential(identity: Identity, cred_id: Optional[str]) -> Optional[Credential]:
    return next((c for c in identity.credentials if c.id == cred_id), None)


def _execute(action: Action, identity: Identity, policy: Policy, now: datetime) -> str:
    t = policy.for_environment(identity.environment)
    if action.kind == "rotate_credential":
        old = _find_credential(identity, action.credential_id)
        if old is None:
            return "credential no longer present"
        if old.kind == "password":
            old.created_at = now
            old.expires_at = now + timedelta(days=t.max_credential_age_days)
            return f"password reset; next rotation due {old.expires_at.date()}"
        new = Credential(id=secrets.token_hex(16), kind=old.kind, name=f"{old.name or old.kind} (rotated)",
                         created_at=now, expires_at=now + timedelta(days=t.max_credential_age_days))
        identity.credentials.append(new)
        overlap_end = now + timedelta(days=t.rotation_overlap_days)
        if old.expires_at is None or old.expires_at > overlap_end:
            old.expires_at = overlap_end
        return f"issued {new.id[:8]} (expires {new.expires_at.date()}); old credential now expires {old.expires_at.date()}"
    if action.kind == "shorten_expiry":
        cred = _find_credential(identity, action.credential_id)
        if cred is None:
            return "credential no longer present"
        start = cred.created_at or now
        cap = max(start + timedelta(days=t.max_credential_lifetime_days), now + timedelta(days=t.rotation_overlap_days))
        if cred.expires_at is None or cred.expires_at > cap:
            cred.expires_at = cap
        return f"expiry set to {cred.expires_at.date()}"
    if action.kind == "remove_expired_credential":
        before = len(identity.credentials)
        identity.credentials = [c for c in identity.credentials if c.id != action.credential_id]
        return "removed" if len(identity.credentials) < before else "credential no longer present"
    if action.kind == "disable_identity":
        identity.enabled = False
        return "identity disabled"
    if action.kind == "revoke_credentials":
        # Graph: removePassword / removeKey. Local passwords can't be removed, so a
        # disabled local account keeps its (now unusable) password.
        keep = [c for c in identity.credentials if c.kind == "password"]
        removed = len(identity.credentials) - len(keep)
        identity.credentials = keep
        return f"removed {removed} credential(s)"
    return "no automatic step"


def apply_actions(actions: list[Action], identities: list[Identity], policy: Policy, now: datetime,
                  apply: bool = False, log_path: Optional[str | Path] = None) -> list[Action]:
    by_id = {i.id: i for i in identities}
    for action in actions:
        if not action.automatic:
            action.result = action.skipped_reason or "owner notified (manual follow-up)"
        elif not apply:
            action.result = "dry run: would apply"
        else:
            action.result = _execute(action, by_id[action.identity_id], policy, now)
    if log_path:
        path = Path(log_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            for a in actions:
                f.write(json.dumps({"at": format_time(now), "applied": apply and a.automatic, **a.to_dict()}) + "\n")
    return actions


def save_inventory_snapshot(identities: list[Identity], path: str | Path) -> None:
    """After --apply: the updated inventory, in the engine's own JSON format."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps([i.to_dict() for i in identities], indent=2), encoding="utf-8")
