"""The engine's own inventory format, as written by ``enforce --apply``.

Re-auditing a snapshot confirms the remediation actually fixed the findings.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Credential, Identity, parse_time


def load_snapshot(path: str | Path) -> list[Identity]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    identities: list[Identity] = []
    for raw in data:
        creds = [Credential(id=c["id"], kind=c["kind"], name=c.get("name"),
                            created_at=parse_time(c.get("created_at")), expires_at=parse_time(c.get("expires_at")))
                 for c in raw.get("credentials", [])]
        identities.append(Identity(
            id=raw["id"], name=raw["name"], kind=raw["kind"], provider=raw["provider"],
            environment=raw.get("environment", "unknown"), enabled=bool(raw.get("enabled", True)),
            created_at=parse_time(raw.get("created_at")), last_used_at=parse_time(raw.get("last_used_at")),
            owners=list(raw.get("owners", [])), roles=list(raw.get("roles", [])),
            tags=dict(raw.get("tags", {})), credentials=creds, source=raw.get("source", ""),
        ))
    return identities
