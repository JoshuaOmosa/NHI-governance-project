"""The audit: run every rule against every identity and score the result."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Optional

from .models import Credential, Identity
from .policy import Policy, Thresholds

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


@dataclass
class Finding:
    rule: str
    severity: str           # high | medium | low
    identity_id: str
    message: str
    credential_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    check: Callable[[Identity, Thresholds, datetime], Iterable[tuple[str, Optional[str]]]]


def is_retiring(c: Credential, i: Identity, t: Thresholds, now: datetime) -> bool:
    """A credential mid-rotation: it expires within the overlap window and a newer
    credential of the same kind already exists to replace it. Works for any source,
    because it only looks at dates."""
    left = c.days_until_expiry(now)
    if left is None or left > t.rotation_overlap_days or c.created_at is None:
        return False
    return any(o is not c and o.kind == c.kind and o.created_at and o.created_at > c.created_at
               and not o.is_expired(now) for o in i.credentials)


def current_credentials(i: Identity, t: Thresholds, now: datetime) -> list[Credential]:
    """Active credentials that aren't on their way out."""
    return [c for c in i.active_credentials(now) if not is_retiring(c, i, t, now)]


def _rotation_overdue(i: Identity, t: Thresholds, now: datetime):
    for c in current_credentials(i, t, now):
        age = c.age_days(now)
        if age is not None and age > t.max_credential_age_days:
            yield f"{_describe(c)} is {age} days old (rotate every {t.max_credential_age_days})", c.id


def _expired_attached(i: Identity, t: Thresholds, now: datetime):
    for c in i.credentials:
        if c.is_expired(now) and c.kind != "password":
            yield f"{_describe(c)} expired {abs(c.days_until_expiry(now))} days ago but is still attached", c.id


def _expiring_soon(i: Identity, t: Thresholds, now: datetime):
    for c in current_credentials(i, t, now):
        left = c.days_until_expiry(now)
        if left is not None and left <= t.expiry_warning_days:
            yield f"{_describe(c)} expires in {left} days", c.id


def _too_long_lived(i: Identity, t: Thresholds, now: datetime):
    for c in current_credentials(i, t, now):
        life = c.lifetime_days()
        if c.expires_at is None:
            yield f"{_describe(c)} never expires", c.id
        elif life is not None and life > t.max_credential_lifetime_days:
            yield f"{_describe(c)} was issued for {life} days (max {t.max_credential_lifetime_days})", c.id


def _stale(i: Identity, t: Thresholds, now: datetime):
    if not i.enabled:
        return
    if i.last_used_at is not None:
        idle = (now - i.last_used_at).days
        if idle > t.stale_after_days:
            yield f"not used for {idle} days (stale after {t.stale_after_days})", None
    elif i.created_at is not None and (now - i.created_at).days > t.never_used_grace_days:
        yield f"never used, created {(now - i.created_at).days} days ago", None


def _no_owner(i: Identity, t: Thresholds, now: datetime):
    if t.require_owner and not [o for o in i.owners if o]:
        yield "has no accountable owner", None


def _unjustified_privilege(i: Identity, t: Thresholds, now: datetime):
    privileged = sorted({r for r in i.roles if r in t.privileged_roles})
    if privileged and not i.tags.get(t.justification_tag):
        yield f"holds privileged role(s) {', '.join(privileged)} without a '{t.justification_tag}' tag", None


def _too_many_credentials(i: Identity, t: Thresholds, now: datetime):
    n = len(current_credentials(i, t, now))
    if n > t.max_active_credentials:
        yield f"has {n} active credentials (max {t.max_active_credentials})", None


def _disabled_with_live_credentials(i: Identity, t: Thresholds, now: datetime):
    live = [c for c in i.active_credentials(now) if c.kind != "password"]
    if not i.enabled and live:
        yield f"is disabled but still has {len(live)} valid credential(s)", None


RULES: list[Rule] = [
    Rule("NHI-001", "Credential rotation overdue", "high", _rotation_overdue),
    Rule("NHI-002", "Long-lived or non-expiring credential", "high", _too_long_lived),
    Rule("NHI-003", "Privileged role without justification", "high", _unjustified_privilege),
    Rule("NHI-004", "Stale identity (unused)", "medium", _stale),
    Rule("NHI-005", "No accountable owner", "medium", _no_owner),
    Rule("NHI-006", "Expired credential still attached", "medium", _expired_attached),
    Rule("NHI-007", "Disabled identity with valid credentials", "medium", _disabled_with_live_credentials),
    Rule("NHI-008", "Credential expiring soon", "low", _expiring_soon),
    Rule("NHI-009", "Too many active credentials", "low", _too_many_credentials),
]
RULES_BY_ID = {r.id: r for r in RULES}


def _describe(c: Credential) -> str:
    """'secret 'prod-2026Q3' (3f9c1e2a)' for cloud credentials, 'password' for local ones."""
    if c.kind == "password":
        return "password"
    name = f" '{c.name}'" if c.name else ""
    return f"{c.kind}{name} ({c.id[:8]})"


@dataclass
class IdentityResult:
    identity: Identity
    findings: list[Finding] = field(default_factory=list)

    @property
    def status(self) -> str:
        worst = max((SEVERITY_ORDER[f.severity] for f in self.findings), default=0)
        return {0: "compliant", 1: "warning"}.get(worst, "non_compliant")


@dataclass
class AuditResult:
    as_of: datetime
    results: list[IdentityResult]

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    def count(self, status: str) -> int:
        return sum(1 for r in self.results if r.status == status)

    @property
    def compliance_rate(self) -> float:
        total = len(self.results)
        return round(100 * self.count("compliant") / total, 1) if total else 100.0

    def worst_severity(self) -> Optional[str]:
        return max((f.severity for f in self.findings), key=SEVERITY_ORDER.get, default=None)


def run_audit(identities: list[Identity], policy: Policy, now: datetime) -> AuditResult:
    results: list[IdentityResult] = []
    for identity in identities:
        t = policy.for_environment(identity.environment)
        result = IdentityResult(identity)
        for rule in RULES:
            for message, cred_id in rule.check(identity, t, now):
                result.findings.append(Finding(rule.id, rule.severity, identity.id, message, cred_id))
        results.append(result)
    results.sort(key=lambda r: (-max((SEVERITY_ORDER[f.severity] for f in r.findings), default=0), r.identity.name))
    return AuditResult(as_of=now, results=results)
