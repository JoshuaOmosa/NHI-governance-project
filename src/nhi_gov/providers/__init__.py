"""Inventory sources. Each one turns its own export format into Identity objects."""

from __future__ import annotations

from pathlib import Path

from ..models import Identity
from .azure_ad import load_azure_ad_export
from .local_accounts import load_local_accounts_export
from .snapshot import load_snapshot

LOADERS = {
    "azure_ad": load_azure_ad_export,
    "local": load_local_accounts_export,
    "snapshot": load_snapshot,
}


def load_inventory(sources: list[tuple[str, str | Path]]) -> list[Identity]:
    """Load and combine several sources, e.g. [('azure_ad', 'tenant.json'), ('local', 'hosts.json')]."""
    identities: list[Identity] = []
    seen: set[str] = set()
    for kind, path in sources:
        if kind not in LOADERS:
            raise ValueError(f"unknown source type {kind!r} (choose from {sorted(LOADERS)})")
        for identity in LOADERS[kind](path):
            if identity.id in seen:
                raise ValueError(f"duplicate identity id {identity.id!r} across sources")
            seen.add(identity.id)
            identities.append(identity)
    return identities
