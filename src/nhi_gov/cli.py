"""Command line.

    python -m nhi_gov audit   --azure sample_data/azure_ad_export.json --local sample_data/local_accounts.json
    python -m nhi_gov report  --azure ... --local ... --format html --out output/dashboard.html
    python -m nhi_gov enforce --azure ... --local ...            # dry run: shows the plan
    python -m nhi_gov enforce --azure ... --local ... --apply    # applies safe actions, writes snapshot + log

Common options: --policy policies/default.json, --as-of 2026-10-23, --fail-on high|medium|low
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .audit import run_audit
from .enforce import apply_actions, plan_actions, save_inventory_snapshot
from .models import parse_time
from .policy import PolicyError, load_policy
from .providers import load_inventory
from .report import FORMATS, fails_threshold, summary


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--azure", action="append", default=[], metavar="FILE", help="Azure AD (Graph) export JSON")
    p.add_argument("--local", action="append", default=[], metavar="FILE", help="local service accounts export JSON")
    p.add_argument("--snapshot-in", action="append", default=[], metavar="FILE",
                   help="inventory snapshot written by enforce --apply (to verify remediation)")
    p.add_argument("--policy", default="policies/default.json", help="policy JSON (default: %(default)s)")
    p.add_argument("--as-of", help="evaluate as of this date/time (ISO 8601); default: now")
    p.add_argument("--fail-on", choices=["high", "medium", "low"], help="exit 3 if any finding is this severe or worse")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="nhi_gov", description="Non-human identity lifecycle governance")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("audit", help="print a summary and the non-compliant identities")
    _common(a)

    r = sub.add_parser("report", help="write a compliance report")
    _common(r)
    r.add_argument("--format", choices=sorted(FORMATS), default="md")
    r.add_argument("--out", help="output file (default: stdout)")
    r.add_argument("--with-plan", action="store_true", help="include the remediation plan")

    e = sub.add_parser("enforce", help="plan (and optionally apply) automated remediation")
    _common(e)
    e.add_argument("--apply", action="store_true", help="actually apply automatic actions (default: dry run)")
    e.add_argument("--log", default="output/enforcement-log.jsonl", help="append an audit log here")
    e.add_argument("--snapshot", default="output/inventory-after.json", help="where --apply writes the updated inventory")

    args = parser.parse_args(argv)
    sources = ([("azure_ad", f) for f in args.azure] + [("local", f) for f in args.local]
               + [("snapshot", f) for f in args.snapshot_in])
    if not sources:
        parser.error("give at least one --azure, --local or --snapshot-in inventory file")
    try:
        policy = load_policy(args.policy)
        identities = load_inventory(sources)
        now = parse_time(args.as_of) if args.as_of else datetime.now(timezone.utc)
    except (PolicyError, ValueError, OSError, KeyError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    audit = run_audit(identities, policy, now)

    if args.command == "audit":
        s = summary(audit)
        print(f"As of {now.date()}: {s['identities']} identities, {s['compliance_rate']}% compliant "
              f"({s['compliant']} compliant, {s['warning']} warning, {s['non_compliant']} non-compliant)")
        print(f"Findings: {s['findings']['high']} high, {s['findings']['medium']} medium, {s['findings']['low']} low")
        for res in audit.results:
            if res.findings:
                print(f"\n[{res.status.upper()}] {res.identity.name} ({res.identity.environment})")
                for f in res.findings:
                    print(f"  {f.severity:<6} {f.rule}  {f.message}")

    elif args.command == "report":
        actions = None
        if args.with_plan:
            actions = apply_actions(plan_actions(audit, policy), identities, policy, now, apply=False)
        text = FORMATS[args.format](audit, actions)
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(text, encoding="utf-8")
            print(f"Wrote {args.out}")
        else:
            sys.stdout.write(text)

    else:  # enforce
        actions = apply_actions(plan_actions(audit, policy), identities, policy, now,
                                apply=args.apply, log_path=args.log)
        mode = "APPLY" if args.apply else "DRY RUN"
        print(f"{mode}: {len(actions)} actions ({sum(a.automatic for a in actions)} automatic, "
              f"{sum(not a.automatic for a in actions)} for owners)")
        for act in actions:
            flag = "auto" if act.automatic else "manual"
            print(f"  [{flag:<6}] {act.kind:<26} {act.identity_name:<34} {act.result}")
        if args.apply:
            save_inventory_snapshot(identities, args.snapshot)
            print(f"\nUpdated inventory written to {args.snapshot}; log appended to {args.log}")
            return 0  # findings were remediated; re-run audit on the snapshot to verify

    return 3 if fails_threshold(audit, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
