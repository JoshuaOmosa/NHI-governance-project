"""Governance policy: the thresholds the audit enforces, loaded from JSON.

Settings can be overridden per environment, so production can be stricter:

    {"defaults": {"max_credential_age_days": 180, ...},
     "environments": {"prod": {"max_credential_age_days": 90}}}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Thresholds:
    max_credential_age_days: int = 90          # rotate secrets/passwords at least this often
    max_credential_lifetime_days: int = 365    # no credential may be issued for longer
    expiry_warning_days: int = 30              # warn this long before a credential expires
    stale_after_days: int = 90                 # unused this long = stale
    never_used_grace_days: int = 30            # new identities get this long before "never used" counts
    max_active_credentials: int = 2            # one current + one during rotation overlap
    require_owner: bool = True
    privileged_roles: tuple[str, ...] = ()     # roles that need a justification tag
    justification_tag: str = "nhi:justification"
    auto_disable_stale: bool = True            # enforcement may disable stale identities
    rotation_overlap_days: int = 7             # old credential stays valid this long after rotation


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    defaults: Thresholds = field(default_factory=Thresholds)
    environments: dict[str, Thresholds] = field(default_factory=dict)

    def for_environment(self, env: str) -> Thresholds:
        return self.environments.get(env, self.defaults)


_FIELDS = {f.name: f for f in fields(Thresholds)}


def _thresholds(raw: dict[str, Any], base: Thresholds, where: str) -> Thresholds:
    values = {name: getattr(base, name) for name in _FIELDS}
    for key, value in raw.items():
        if key not in _FIELDS:
            raise PolicyError(f"{where}: unknown setting {key!r}")
        default = values[key]
        if isinstance(default, bool):
            if not isinstance(value, bool):
                raise PolicyError(f"{where}.{key} must be true or false")
        elif isinstance(default, int):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise PolicyError(f"{where}.{key} must be a whole number >= 0")
        elif isinstance(default, tuple):
            if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
                raise PolicyError(f"{where}.{key} must be a list of strings")
            value = tuple(value)
        elif not isinstance(value, str):
            raise PolicyError(f"{where}.{key} must be a string")
        values[key] = value
    t = Thresholds(**values)
    if t.max_credential_age_days > t.max_credential_lifetime_days:
        raise PolicyError(f"{where}: max_credential_age_days can't exceed max_credential_lifetime_days")
    return t


def parse_policy(data: dict[str, Any]) -> Policy:
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")
    defaults = _thresholds(data.get("defaults", {}), Thresholds(), "defaults")
    envs = {
        name: _thresholds(raw, defaults, f"environments.{name}")
        for name, raw in (data.get("environments") or {}).items()
    }
    return Policy(defaults=defaults, environments=envs)


def load_policy(path: str | Path) -> Policy:
    try:
        return parse_policy(json.loads(Path(path).read_text(encoding="utf-8")))
    except json.JSONDecodeError as e:
        raise PolicyError(f"{path}: invalid JSON ({e})") from None
