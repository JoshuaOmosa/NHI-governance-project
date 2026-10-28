"""The common shape every inventory source is mapped into.

Azure AD service principals, local service accounts and anything added later
all become ``Identity`` objects, so the policy engine only has to understand
one model.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def parse_time(value: Optional[str]) -> Optional[datetime]:
    """ISO 8601 -> aware UTC datetime. Accepts a trailing 'Z' and plain dates."""
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_time(value: Optional[datetime]) -> Optional[str]:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if value else None


@dataclass
class Credential:
    id: str
    kind: str                         # "secret" | "certificate" | "password" | "key"
    created_at: Optional[datetime]
    expires_at: Optional[datetime]    # None means it never expires
    name: Optional[str] = None

    def age_days(self, now: datetime) -> Optional[int]:
        return (now - self.created_at).days if self.created_at else None

    def lifetime_days(self) -> Optional[int]:
        if self.created_at and self.expires_at:
            return (self.expires_at - self.created_at).days
        return None

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and self.expires_at <= now

    def days_until_expiry(self, now: datetime) -> Optional[int]:
        return (self.expires_at - now).days if self.expires_at else None


@dataclass
class Identity:
    id: str
    name: str
    kind: str                         # "service_principal" | "local_service_account"
    provider: str                     # "azure_ad" | "local"
    environment: str = "unknown"      # "prod" | "dev" | ... (from tags)
    enabled: bool = True
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    owners: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    credentials: list[Credential] = field(default_factory=list)
    source: str = ""                  # where it came from (tenant, host)

    @property
    def protected(self) -> bool:
        """Break-glass and similar accounts are reported on but never auto-changed."""
        return self.tags.get("nhi:protected", "").lower() == "true"

    def active_credentials(self, now: datetime) -> list[Credential]:
        return [c for c in self.credentials if not c.is_expired(now)]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for key in ("created_at", "last_used_at"):
            d[key] = format_time(getattr(self, key))
        d["credentials"] = [
            {**asdict(c), "created_at": format_time(c.created_at), "expires_at": format_time(c.expires_at)}
            for c in self.credentials
        ]
        return d


def parse_tags(raw: list[str] | dict[str, str] | None) -> dict[str, str]:
    """Azure AD tags are a list of strings. 'env=prod' becomes {'env': 'prod'};
    a bare tag like 'HideApp' becomes {'HideApp': 'true'}."""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    tags: dict[str, str] = {}
    for item in raw:
        key, sep, value = str(item).partition("=")
        tags[key.strip()] = value.strip() if sep else "true"
    return tags
