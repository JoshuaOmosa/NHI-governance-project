"""Local service accounts on servers (Windows or Linux), from a per-host export.

Expected shape (one entry per host)::

    {"hosts": [{"hostname": "build-01", "os": "windows", "accounts": [{
        "name": "svc_backup", "enabled": true, "created": "...",
        "password_last_set": "...", "password_expires": "..." | null,
        "last_logon": "..." | null, "groups": ["Administrators"],
        "owner": "ops@example.com", "tags": {"env": "prod"}}]}]}

On Windows this comes from ``Get-LocalUser`` (``PasswordLastSet``,
``PasswordExpires``, ``LastLogon``) plus group membership; on Linux from
``/etc/passwd``, ``chage -l`` and ``lastlog``.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import Credential, Identity, parse_tags, parse_time


def load_local_accounts_export(path: str | Path) -> list[Identity]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    identities: list[Identity] = []
    for host in data.get("hosts", []):
        hostname = host["hostname"]
        for acct in host.get("accounts", []):
            tags = parse_tags(acct.get("tags"))
            password = Credential(
                id=f"{hostname}:{acct['name']}:password",
                kind="password",
                created_at=parse_time(acct.get("password_last_set")),
                expires_at=parse_time(acct.get("password_expires")),
            )
            identities.append(Identity(
                id=f"local:{hostname}:{acct['name']}",
                name=f"{acct['name']}@{hostname}",
                kind="local_service_account",
                provider="local",
                environment=tags.get("env", host.get("env", "unknown")),
                enabled=bool(acct.get("enabled", True)),
                created_at=parse_time(acct.get("created")),
                last_used_at=parse_time(acct.get("last_logon")),
                owners=[acct["owner"]] if acct.get("owner") else [],
                roles=list(acct.get("groups", [])),
                tags=tags,
                credentials=[password],
                source=f"host {hostname} ({host.get('os', 'unknown')})",
            ))
    return identities
