import json
import tempfile
import unittest
from pathlib import Path

from tests.helpers import AZURE, LOCAL, NOW, POLICY, days_ago, identity, policy, secret
from nhi_gov.audit import run_audit
from nhi_gov.enforce import apply_actions, plan_actions
from nhi_gov.models import Credential
from nhi_gov.policy import load_policy
from nhi_gov.providers import load_inventory


def plan(idents, pol=None):
    pol = pol or policy()
    return plan_actions(run_audit(idents, pol, NOW), pol), pol


class PlanTests(unittest.TestCase):
    def test_rotation_planned_for_old_secret(self):
        actions, _ = plan([identity(credentials=[secret(age=120, lifetime=300)])])
        self.assertEqual([(a.kind, a.automatic) for a in actions], [("rotate_credential", True)])

    def test_rotate_wins_over_shorten_for_same_credential(self):
        actions, _ = plan([identity(credentials=[secret(age=120, lifetime=None)])])
        self.assertEqual([a.kind for a in actions], ["rotate_credential"])

    def test_human_issues_become_notifications(self):
        actions, _ = plan([identity(owners=[], roles=["Administrators"])])
        self.assertTrue(actions)
        self.assertTrue(all(a.kind == "notify_owner" and not a.automatic for a in actions))

    def test_protected_identity_never_automatic(self):
        actions, _ = plan([identity(tags={"nhi:protected": "true"}, last_used_at=days_ago(300),
                                    credentials=[secret(age=200, lifetime=365)])])
        self.assertTrue(actions)
        self.assertFalse(any(a.automatic for a in actions))
        self.assertTrue(all("protected" in a.skipped_reason for a in actions))

    def test_disabling_replaces_rotation_with_revocation(self):
        actions, _ = plan([identity(last_used_at=days_ago(200), credentials=[secret(age=120, lifetime=300)])])
        self.assertEqual(sorted(a.kind for a in actions), ["disable_identity", "revoke_credentials"])

    def test_auto_disable_can_be_turned_off(self):
        actions, _ = plan([identity(last_used_at=days_ago(200))], policy(auto_disable_stale=False))
        self.assertEqual([(a.kind, a.automatic) for a in actions], [("disable_identity", False)])


class ApplyTests(unittest.TestCase):
    def test_dry_run_changes_nothing(self):
        ident = identity(credentials=[secret(age=120, lifetime=300)])
        before = ident.to_dict()
        actions, pol = plan([ident])
        apply_actions(actions, [ident], pol, NOW, apply=False)
        self.assertEqual(ident.to_dict(), before)
        self.assertEqual(actions[0].result, "dry run: would apply")

    def test_rotation_issues_new_credential_and_retires_old(self):
        old = secret("old", age=120, lifetime=300)
        ident = identity(credentials=[old])
        actions, pol = plan([ident])
        apply_actions(actions, [ident], pol, NOW, apply=True)
        self.assertEqual(len(ident.credentials), 2)
        new = ident.credentials[1]
        self.assertEqual((new.created_at, new.lifetime_days()), (NOW, pol.defaults.max_credential_age_days))
        self.assertEqual((old.expires_at - NOW).days, pol.defaults.rotation_overlap_days)
        self.assertEqual(run_audit([ident], pol, NOW).results[0].status, "compliant")

    def test_password_rotation_resets_in_place(self):
        pw = Credential("h:svc:password", "password", days_ago(200), None)
        ident = identity(kind="local_service_account", provider="local", credentials=[pw])
        actions, pol = plan([ident])
        apply_actions(actions, [ident], pol, NOW, apply=True)
        self.assertEqual(len(ident.credentials), 1)
        self.assertEqual(pw.created_at, NOW)
        self.assertIsNotNone(pw.expires_at)

    def test_shorten_expiry_caps_lifetime(self):
        ident = identity(credentials=[secret(age=10, lifetime=1000)])
        actions, pol = plan([ident])
        self.assertEqual([a.kind for a in actions], ["shorten_expiry"])
        apply_actions(actions, [ident], pol, NOW, apply=True)
        self.assertEqual(ident.credentials[0].lifetime_days(), pol.defaults.max_credential_lifetime_days)

    def test_revoke_removes_cloud_credentials(self):
        ident = identity(enabled=False, credentials=[secret("a"), secret("b")])
        actions, pol = plan([ident])
        apply_actions(actions, [ident], pol, NOW, apply=True)
        self.assertEqual(ident.credentials, [])
        self.assertEqual(run_audit([ident], pol, NOW).results[0].findings, [])

    def test_log_written(self):
        ident = identity(credentials=[secret(age=120, lifetime=300)])
        actions, pol = plan([ident])
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "log.jsonl"
            apply_actions(actions, [ident], pol, NOW, apply=True, log_path=log)
            entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(entries[0]["kind"], "rotate_credential")
        self.assertTrue(entries[0]["applied"])


class EndToEndTests(unittest.TestCase):
    def test_apply_then_reaudit_leaves_only_human_work(self):
        pol = load_policy(POLICY)
        idents = load_inventory([("azure_ad", AZURE), ("local", LOCAL)])
        apply_actions(plan_actions(run_audit(idents, pol, NOW), pol), idents, pol, NOW, apply=True)
        after = run_audit(idents, pol, NOW)
        remaining = {f.rule for f in after.findings}
        self.assertEqual(remaining, {"NHI-001", "NHI-003", "NHI-004", "NHI-005", "NHI-008"})
        # The only automatic-type findings left belong to the protected break-glass identity.
        auto_rules = {"NHI-001", "NHI-002", "NHI-004", "NHI-006", "NHI-007"}
        leftover = {r.identity.name for r in after.results if any(f.rule in auto_rules for f in r.findings)}
        self.assertEqual(leftover, {"breakglass-automation"})
        self.assertEqual(after.compliance_rate, 50.0)


if __name__ == "__main__":
    unittest.main()
