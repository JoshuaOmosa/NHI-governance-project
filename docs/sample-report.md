# Non-Human Identity Compliance Report

As of **2026-10-23** · 12 identities (8 azure_ad, 4 local)

| Compliant | Warning | Non-compliant | Compliance rate |
|---:|---:|---:|---:|
| 4 | 1 | 7 | **33.3%** |

## Findings by rule

| Rule | Severity | Title | Count |
|---|---|---|---:|
| NHI-001 | high | Credential rotation overdue | 4 |
| NHI-002 | high | Long-lived or non-expiring credential | 2 |
| NHI-003 | high | Privileged role without justification | 2 |
| NHI-004 | medium | Stale identity (unused) | 3 |
| NHI-005 | medium | No accountable owner | 2 |
| NHI-006 | medium | Expired credential still attached | 1 |
| NHI-007 | medium | Disabled identity with valid credentials | 1 |
| NHI-008 | low | Credential expiring soon | 1 |

## Identities

| Identity | Type | Env | Status | Last used | Owner | Findings |
|---|---|---|---|---|---|---|
| breakglass-automation | service principal | prod | non-compliant | 2026-03-01 | security@contoso.example | **NHI-001** secret 'breakglass' (14aa4e71) is 264 days old (rotate every 90)<br>**NHI-004** not used for 236 days (stale after 90) |
| data-sync | service principal | dev | non-compliant | 2026-10-20 | data-eng@contoso.example | **NHI-001** secret 'sync-a' (6bad6be2) is 205 days old (rotate every 180)<br>**NHI-006** secret 'sync-old' (7dabe929) expired 145 days ago but is still attached |
| legacy-reporting | service principal | prod | non-compliant | 2026-05-01 | — | **NHI-001** secret 'do-not-delete' (f3f49249) is 712 days old (rotate every 90)<br>**NHI-002** secret 'do-not-delete' (f3f49249) was issued for 27444 days (max 365)<br>**NHI-004** not used for 175 days (stale after 90)<br>**NHI-005** has no accountable owner |
| monitoring-agent | service principal | prod | non-compliant | 2026-10-23 | sre@contoso.example | **NHI-003** holds privileged role(s) Directory.ReadWrite.All without a 'nhi:justification' tag |
| svc_backup@build-01 | local service account | prod | non-compliant | 2026-10-22 | ops@contoso.example | **NHI-001** password is 326 days old (rotate every 90)<br>**NHI-002** password never expires<br>**NHI-003** holds privileged role(s) Administrators without a 'nhi:justification' tag |
| deploy@web-02 | local service account | dev | non-compliant | 2026-06-10 | — | **NHI-004** not used for 134 days (stale after 120)<br>**NHI-005** has no accountable owner |
| old-poc | service principal | dev | non-compliant | never | innovation@contoso.example | **NHI-007** is disabled but still has 1 valid credential(s) |
| ci-deployer | service principal | prod | warning | 2026-10-23 | platform@contoso.example | **NHI-008** certificate 'deployer-cert' (e5121482) expires in 17 days |
| new-integration | service principal | dev | compliant | never | partners@contoso.example | none |
| payments-api | service principal | prod | compliant | 2026-10-22 | payments-team@contoso.example | none |
| svc_metrics@web-02 | local service account | dev | compliant | 2026-10-23 | sre@contoso.example | none |
| svc_sql@build-01 | local service account | prod | compliant | 2026-10-23 | dba@contoso.example | none |

## Expiring in the next 30 days

| Days left | Identity | Credential | Expires |
|---:|---|---|---|
| 17 | ci-deployer | certificate | 2026-11-10 |

## Remediation plan

| Action | Identity | Rule | Automatic | Result |
|---|---|---|---|---|
| rotate credential | breakglass-automation | NHI-001 | no | identity is tagged nhi:protected (review manually) |
| disable identity | breakglass-automation | NHI-004 | no | identity is tagged nhi:protected (review manually) |
| rotate credential | data-sync | NHI-001 | yes | dry run: would apply |
| remove expired credential | data-sync | NHI-006 | yes | dry run: would apply |
| revoke credentials | legacy-reporting | NHI-001 | yes | dry run: would apply |
| disable identity | legacy-reporting | NHI-004 | yes | dry run: would apply |
| notify owner | legacy-reporting | NHI-005 | no | owner notified (manual follow-up) |
| notify owner | monitoring-agent | NHI-003 | no | owner notified (manual follow-up) |
| rotate credential | svc_backup@build-01 | NHI-001 | yes | dry run: would apply |
| notify owner | svc_backup@build-01 | NHI-003 | no | owner notified (manual follow-up) |
| disable identity | deploy@web-02 | NHI-004 | yes | dry run: would apply |
| notify owner | deploy@web-02 | NHI-005 | no | owner notified (manual follow-up) |
| revoke credentials | old-poc | NHI-007 | yes | dry run: would apply |
| notify owner | ci-deployer | NHI-008 | no | owner notified (manual follow-up) |

---

Rules: NHI-001 Credential rotation overdue (high); NHI-002 Long-lived or non-expiring credential (high); NHI-003 Privileged role without justification (high); NHI-004 Stale identity (unused) (medium); NHI-005 No accountable owner (medium); NHI-006 Expired credential still attached (medium); NHI-007 Disabled identity with valid credentials (medium); NHI-008 Credential expiring soon (low); NHI-009 Too many active credentials (low)
