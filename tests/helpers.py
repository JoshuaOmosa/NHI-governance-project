from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests import _path  # noqa: F401
from nhi_gov.models import Credential, Identity
from nhi_gov.policy import Policy, Thresholds

ROOT = Path(__file__).resolve().parents[1]
AZURE = ROOT / "sample_data" / "azure_ad_export.json"
LOCAL = ROOT / "sample_data" / "local_accounts.json"
POLICY = ROOT / "policies" / "default.json"
NOW = datetime(2026, 10, 23, 6, 0, tzinfo=timezone.utc)


def days_ago(n: float) -> datetime:
    return NOW - timedelta(days=n)


def days_ahead(n: float) -> datetime:
    return NOW + timedelta(days=n)


def secret(cid="s1", age=10, lifetime=180, name=None, kind="secret") -> Credential:
    created = days_ago(age)
    return Credential(id=cid, kind=kind, name=name, created_at=created,
                      expires_at=None if lifetime is None else created + timedelta(days=lifetime))


def identity(**kw) -> Identity:
    """A healthy identity by default; override what a test needs."""
    base = dict(id="azure_ad:x", name="x", kind="service_principal", provider="azure_ad",
                environment="prod", enabled=True, created_at=days_ago(400), last_used_at=days_ago(1),
                owners=["owner@example.com"], roles=[], tags={}, credentials=[secret()])
    base.update(kw)
    return Identity(**base)


def policy(**overrides) -> Policy:
    return Policy(defaults=Thresholds(privileged_roles=("Administrators",), **overrides))
