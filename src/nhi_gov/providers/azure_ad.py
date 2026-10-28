"""Azure AD (Microsoft Entra ID) service principals from a Graph-shaped export.

The export mirrors what these Microsoft Graph calls return, combined in one file:

* ``GET /servicePrincipals``  -> ``servicePrincipals`` (enabled, tags, owners, app roles)
* ``GET /applications``       -> ``applications`` (``passwordCredentials`` = client
  secrets, ``keyCredentials`` = certificates), joined to the principal by ``appId``
* ``GET /reports/servicePrincipalSignInActivities`` -> ``signInActivities``
  (``lastSignInActivity.lastSignInDateTime``), also joined by ``appId``

Reading an export keeps the engine runnable offline and in CI. A live Graph
connector would produce the same three lists.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Credential, Identity, parse_tags, parse_time


def _credentials(app: dict[str, Any]) -> list[Credential]:
    creds: list[Credential] = []
    for raw in app.get("passwordCredentials") or []:
        creds.append(Credential(
            id=raw["keyId"], kind="secret", name=raw.get("displayName"),
            created_at=parse_time(raw.get("startDateTime")), expires_at=parse_time(raw.get("endDateTime")),
        ))
    for raw in app.get("keyCredentials") or []:
        creds.append(Credential(
            id=raw["keyId"], kind="certificate", name=raw.get("displayName"),
            created_at=parse_time(raw.get("startDateTime")), expires_at=parse_time(raw.get("endDateTime")),
        ))
    return creds


def load_azure_ad_export(path: str | Path) -> list[Identity]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    tenant = data.get("tenantId", "unknown-tenant")
    apps = {a["appId"]: a for a in data.get("applications", [])}
    sign_ins = {
        s["appId"]: parse_time((s.get("lastSignInActivity") or {}).get("lastSignInDateTime"))
        for s in data.get("signInActivities", [])
    }

    identities: list[Identity] = []
    for sp in data.get("servicePrincipals", []):
        tags = parse_tags(sp.get("tags"))
        app = apps.get(sp.get("appId"), {})
        identities.append(Identity(
            id=f"azure_ad:{sp['id']}",
            name=sp.get("displayName") or sp["id"],
            kind="service_principal",
            provider="azure_ad",
            environment=tags.get("env", "unknown"),
            enabled=bool(sp.get("accountEnabled", True)),
            created_at=parse_time(sp.get("createdDateTime") or app.get("createdDateTime")),
            last_used_at=sign_ins.get(sp.get("appId")),
            owners=[o.get("userPrincipalName") or o.get("id") for o in sp.get("owners") or []],
            roles=[r.get("roleName") or r.get("appRoleId") for r in sp.get("appRoleAssignments") or []],
            tags=tags,
            credentials=_credentials(app),
            source=f"tenant {tenant}",
        ))
    return identities
