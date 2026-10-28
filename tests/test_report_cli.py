import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from tests.helpers import AZURE, LOCAL, NOW, POLICY, identity, policy
from nhi_gov import cli
from nhi_gov.audit import run_audit
from nhi_gov.report import fails_threshold, to_html, to_json, to_markdown

AS_OF = "2026-10-23T06:00:00Z"
SOURCES = ["--azure", str(AZURE), "--local", str(LOCAL), "--policy", str(POLICY), "--as-of", AS_OF]


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class ReportTests(unittest.TestCase):
    def test_markdown_sections(self):
        audit = run_audit([identity(owners=[])], policy(), NOW)
        md = to_markdown(audit)
        for heading in ["# Non-Human Identity Compliance Report", "## Findings by rule", "## Identities",
                        "## Expiring in the next 30 days"]:
            self.assertIn(heading, md)
        self.assertIn("NHI-005", md)

    def test_html_escapes_untrusted_names(self):
        audit = run_audit([identity(name="<script>alert(1)</script>")], policy(), NOW)
        page = to_html(audit)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_json_is_valid(self):
        data = json.loads(to_json(run_audit([identity()], policy(), NOW)))
        self.assertEqual(data["summary"]["compliant"], 1)

    def test_fail_threshold(self):
        audit = run_audit([identity(owners=[])], policy(), NOW)   # one medium finding
        self.assertTrue(fails_threshold(audit, "medium"))
        self.assertTrue(fails_threshold(audit, "low"))
        self.assertFalse(fails_threshold(audit, "high"))
        self.assertFalse(fails_threshold(audit, None))


class CliTests(unittest.TestCase):
    def test_audit_summary(self):
        code, out, _ = run_cli("audit", *SOURCES)
        self.assertEqual(code, 0)
        self.assertIn("12 identities, 33.3% compliant", out)

    def test_fail_on_high_exits_3(self):
        self.assertEqual(run_cli("audit", *SOURCES, "--fail-on", "high")[0], 3)

    def test_report_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            for fmt in ("md", "html", "json"):
                out = Path(tmp) / f"r.{fmt}"
                code, _, _ = run_cli("report", *SOURCES, "--format", fmt, "--with-plan", "--out", str(out))
                self.assertEqual(code, 0)
                self.assertGreater(out.stat().st_size, 500)
            self.assertIn("Remediation plan", (Path(tmp) / "r.md").read_text(encoding="utf-8"))

    def test_enforce_dry_run_then_apply(self):
        with tempfile.TemporaryDirectory() as tmp:
            log, snap = Path(tmp) / "log.jsonl", Path(tmp) / "after.json"
            code, out, _ = run_cli("enforce", *SOURCES, "--log", str(log), "--snapshot", str(snap))
            self.assertEqual(code, 0)
            self.assertIn("DRY RUN", out)
            self.assertFalse(snap.exists())
            code, out, _ = run_cli("enforce", *SOURCES, "--apply", "--log", str(log), "--snapshot", str(snap))
            self.assertIn("APPLY", out)
            code, out, _ = run_cli("audit", "--snapshot-in", str(snap), "--policy", str(POLICY), "--as-of", AS_OF)
            self.assertIn("50.0% compliant", out)

    def test_errors(self):
        self.assertEqual(run_cli("audit")[0], 2)                                     # no sources
        self.assertEqual(run_cli("audit", "--azure", "missing.json", "--policy", str(POLICY))[0], 2)
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "p.json"
            bad.write_text('{"defaults": {"nope": 1}}', encoding="utf-8")
            code, _, err = run_cli("audit", "--azure", str(AZURE), "--policy", str(bad))
            self.assertEqual(code, 2)
            self.assertIn("unknown setting", err)


if __name__ == "__main__":
    unittest.main()
