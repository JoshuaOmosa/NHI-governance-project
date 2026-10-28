"""Compliance output: Markdown report, self-contained HTML dashboard, JSON."""

from __future__ import annotations

import html
import json
from collections import Counter
from typing import Any, Optional

from .audit import RULES, SEVERITY_ORDER, AuditResult
from .enforce import Action
from .models import format_time


def _upcoming_expirations(audit: AuditResult, days: int = 30) -> list[tuple[int, str, str, str]]:
    rows = []
    for r in audit.results:
        for c in r.identity.active_credentials(audit.as_of):
            left = c.days_until_expiry(audit.as_of)
            if left is not None and left <= days:
                rows.append((left, r.identity.name, c.kind, c.expires_at.date().isoformat()))
    return sorted(rows)


def to_json(audit: AuditResult, actions: Optional[list[Action]] = None) -> str:
    data: dict[str, Any] = {
        "as_of": format_time(audit.as_of),
        "summary": summary(audit),
        "identities": [
            {"identity": r.identity.to_dict(), "status": r.status, "findings": [f.to_dict() for f in r.findings]}
            for r in audit.results
        ],
    }
    if actions is not None:
        data["actions"] = [a.to_dict() for a in actions]
    return json.dumps(data, indent=2)


def summary(audit: AuditResult) -> dict[str, Any]:
    sev = Counter(f.severity for f in audit.findings)
    return {
        "identities": len(audit.results),
        "compliant": audit.count("compliant"),
        "warning": audit.count("warning"),
        "non_compliant": audit.count("non_compliant"),
        "compliance_rate": audit.compliance_rate,
        "findings": {s: sev.get(s, 0) for s in ("high", "medium", "low")},
        "by_rule": dict(sorted(Counter(f.rule for f in audit.findings).items())),
        "by_provider": dict(Counter(r.identity.provider for r in audit.results)),
    }


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def to_markdown(audit: AuditResult, actions: Optional[list[Action]] = None) -> str:
    s = summary(audit)
    out = [
        "# Non-Human Identity Compliance Report",
        "",
        f"As of **{audit.as_of.date().isoformat()}** · {s['identities']} identities "
        f"({', '.join(f'{n} {p}' for p, n in s['by_provider'].items())})",
        "",
        "| Compliant | Warning | Non-compliant | Compliance rate |",
        "|---:|---:|---:|---:|",
        f"| {s['compliant']} | {s['warning']} | {s['non_compliant']} | **{s['compliance_rate']}%** |",
        "",
        "## Findings by rule",
        "",
        "| Rule | Severity | Title | Count |",
        "|---|---|---|---:|",
    ]
    for rule in RULES:
        n = s["by_rule"].get(rule.id, 0)
        if n:
            out.append(f"| {rule.id} | {rule.severity} | {rule.title} | {n} |")
    if not s["by_rule"]:
        out.append("| - | - | No findings | 0 |")

    out += ["", "## Identities", "",
            "| Identity | Type | Env | Status | Last used | Owner | Findings |",
            "|---|---|---|---|---|---|---|"]
    for r in audit.results:
        i = r.identity
        last = i.last_used_at.date().isoformat() if i.last_used_at else "never"
        findings = "<br>".join(f"**{f.rule}** {_md_escape(f.message)}" for f in r.findings) or "none"
        out.append(f"| {_md_escape(i.name)} | {i.kind.replace('_', ' ')} | {i.environment} | {r.status.replace('_', '-')} "
                   f"| {last} | {_md_escape(', '.join(i.owners) or '—')} | {findings} |")

    upcoming = _upcoming_expirations(audit)
    out += ["", "## Expiring in the next 30 days", ""]
    if upcoming:
        out += ["| Days left | Identity | Credential | Expires |", "|---:|---|---|---|"]
        out += [f"| {d} | {_md_escape(n)} | {k} | {e} |" for d, n, k, e in upcoming]
    else:
        out.append("Nothing expires in the next 30 days.")

    if actions is not None:
        out += ["", "## Remediation plan", "",
                "| Action | Identity | Rule | Automatic | Result |", "|---|---|---|---|---|"]
        for a in actions:
            out.append(f"| {a.kind.replace('_', ' ')} | {_md_escape(a.identity_name)} | {a.rule} "
                       f"| {'yes' if a.automatic else 'no'} | {_md_escape(a.result or '')} |")
    out += ["", "---", "", "Rules: " + "; ".join(f"{r.id} {r.title} ({r.severity})" for r in RULES), ""]
    return "\n".join(out)


_CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2433;--muted:#5b6475;--line:#e2e6ec;
--ok:#1f8a4c;--warn:#b26a00;--bad:#c0392b;--accent:#1f5fa8}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b1f27;--ink:#e6e9ef;--muted:#9aa3b2;--line:#2a303b}}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 "Segoe UI",system-ui,sans-serif;background:var(--bg);color:var(--ink)}
main{max-width:1100px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 10px}
.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}.card b{display:block;font-size:26px}
.ok b{color:var(--ok)}.warn b{color:var(--warn)}.bad b{color:var(--bad)}
.bar{display:flex;height:12px;border-radius:6px;overflow:hidden;margin-top:14px;background:var(--line)}
.bar span{display:block}.s-ok{background:var(--ok)}.s-warn{background:var(--warn)}.s-bad{background:var(--bad)}
.tablewrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600}tr:last-child td{border-bottom:none}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}
.nowrap{white-space:nowrap}
.p-compliant,.p-low{background:var(--ok)}.p-warning,.p-medium{background:var(--warn)}.p-non_compliant,.p-high{background:var(--bad)}
.f{margin:2px 0}.f code{font-size:12px}
"""


def to_html(audit: AuditResult, actions: Optional[list[Action]] = None) -> str:
    e = html.escape
    s = summary(audit)
    total = max(s["identities"], 1)
    pct = {k: round(100 * s[k] / total, 1) for k in ("compliant", "warning", "non_compliant")}
    rows = []
    for r in audit.results:
        i = r.identity
        findings = "".join(
            f'<div class="f"><span class="pill p-{f.severity}">{f.severity}</span> <code>{f.rule}</code> {e(f.message)}</div>'
            for f in r.findings) or '<span class="muted">none</span>'
        rows.append(
            f"<tr><td><b>{e(i.name)}</b><br><span class='muted'>{e(i.kind.replace('_', ' '))} · {e(i.source)}</span></td>"
            f"<td>{e(i.environment)}</td><td><span class='pill p-{r.status}'>{e(r.status.replace('_', '-'))}</span></td>"
            f"<td class='nowrap'>{e(i.last_used_at.date().isoformat()) if i.last_used_at else 'never'}</td>"
            f"<td>{e(', '.join(i.owners) or '—')}</td><td>{findings}</td></tr>")
    rule_rows = "".join(
        f"<tr><td><code>{r.id}</code></td><td><span class='pill p-{r.severity}'>{r.severity}</span></td>"
        f"<td>{e(r.title)}</td><td>{s['by_rule'].get(r.id, 0)}</td></tr>" for r in RULES)
    upcoming = "".join(f"<tr><td>{d}</td><td>{e(n)}</td><td>{e(k)}</td><td>{e(x)}</td></tr>"
                       for d, n, k, x in _upcoming_expirations(audit)) or \
        "<tr><td colspan='4' class='muted'>Nothing expires in the next 30 days.</td></tr>"
    action_html = ""
    if actions is not None:
        arows = "".join(
            f"<tr><td>{e(a.kind.replace('_', ' '))}</td><td>{e(a.identity_name)}</td><td><code>{a.rule}</code></td>"
            f"<td>{'yes' if a.automatic else 'no'}</td><td>{e(a.result or '')}</td></tr>" for a in actions)
        action_html = ("<h2>Remediation plan</h2><div class='tablewrap'><table><tr><th>Action</th><th>Identity</th>"
                       f"<th>Rule</th><th>Automatic</th><th>Result</th></tr>{arows}</table></div>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NHI Compliance Dashboard</title><style>{_CSS}</style></head><body><main>
<h1>Non-Human Identity Compliance</h1>
<div class="muted">As of {e(audit.as_of.date().isoformat())} · {s['identities']} identities ·
{e(', '.join(f'{n} {p}' for p, n in s['by_provider'].items()))}</div>
<div class="cards">
<div class="card"><span class="muted">Compliance rate</span><b>{s['compliance_rate']}%</b></div>
<div class="card ok"><span class="muted">Compliant</span><b>{s['compliant']}</b></div>
<div class="card warn"><span class="muted">Warning</span><b>{s['warning']}</b></div>
<div class="card bad"><span class="muted">Non-compliant</span><b>{s['non_compliant']}</b></div>
<div class="card bad"><span class="muted">High findings</span><b>{s['findings']['high']}</b></div>
</div>
<div class="bar" title="compliant / warning / non-compliant">
<span class="s-ok" style="width:{pct['compliant']}%"></span><span class="s-warn" style="width:{pct['warning']}%"></span>
<span class="s-bad" style="width:{pct['non_compliant']}%"></span></div>
<h2>Identities</h2><div class="tablewrap"><table>
<tr><th>Identity</th><th>Env</th><th>Status</th><th>Last used</th><th>Owner</th><th>Findings</th></tr>
{''.join(rows)}</table></div>
<h2>Rules</h2><div class="tablewrap"><table><tr><th>Rule</th><th>Severity</th><th>Title</th><th>Findings</th></tr>{rule_rows}</table></div>
<h2>Expiring in the next 30 days</h2><div class="tablewrap"><table>
<tr><th>Days left</th><th>Identity</th><th>Credential</th><th>Expires</th></tr>{upcoming}</table></div>
{action_html}
</main></body></html>
"""


FORMATS = {"md": to_markdown, "html": to_html, "json": to_json}


def fails_threshold(audit: AuditResult, fail_on: Optional[str]) -> bool:
    """True if any finding is at or above ``fail_on`` (for CI gating)."""
    if not fail_on:
        return False
    worst = audit.worst_severity()
    return worst is not None and SEVERITY_ORDER[worst] >= SEVERITY_ORDER[fail_on]
