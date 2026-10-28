import unittest
from collections import Counter

from tests.helpers import AZURE, LOCAL, NOW, POLICY, days_ago, days_ahead, identity, policy, secret
from nhi_gov.audit import run_audit
from nhi_gov.models import Credential
from nhi_gov.policy import PolicyError, load_policy, parse_policy
from nhi_gov.providers import load_inventory


def rules_for(ident, pol=None):
    res = run_audit([ident], pol or policy(), NOW).results[0]
    return sorted(f.rule for f in res.findings), res.status


class RuleTests(unittest.TestCase):
    def test_healthy_identity_is_compliant(self):
        self.assertEqual(rules_for(identity()), ([], "compliant"))

    def test_rotation_overdue(self):
        self.assertIn("NHI-001", rules_for(identity(credentials=[secret(age=100, lifetime=300)]))[0])
        self.assertNotIn("NHI-001", rules_for(identity(credentials=[secret(age=80, lifetime=300)]))[0])

    def test_never_expiring_and_overlong(self):
        self.assertIn("NHI-002", rules_for(identity(credentials=[secret(lifetime=None)]))[0])
        self.assertIn("NHI-002", rules_for(identity(credentials=[secret(lifetime=730)]))[0])
        self.assertNotIn("NHI-002", rules_for(identity(credentials=[secret(lifetime=365)]))[0])

    def test_privileged_needs_justification(self):
        self.assertIn("NHI-003", rules_for(identity(roles=["Administrators"]))[0])
        self.assertNotIn("NHI-003", rules_for(identity(roles=["Administrators"], tags={"nhi:justification": "CHG-1"}))[0])
        self.assertNotIn("NHI-003", rules_for(identity(roles=["Readers"]))[0])

    def test_stale_and_never_used(self):
        self.assertIn("NHI-004", rules_for(identity(last_used_at=days_ago(91)))[0])
        self.assertNotIn("NHI-004", rules_for(identity(last_used_at=days_ago(89)))[0])
        self.assertIn("NHI-004", rules_for(identity(last_used_at=None, created_at=days_ago(31)))[0])
        self.assertNotIn("NHI-004", rules_for(identity(last_used_at=None, created_at=days_ago(5)))[0])
        self.assertNotIn("NHI-004", rules_for(identity(last_used_at=days_ago(400), enabled=False, credentials=[]))[0])

    def test_owner_required(self):
        self.assertIn("NHI-005", rules_for(identity(owners=[]))[0])
        self.assertNotIn("NHI-005", rules_for(identity(owners=[]), policy(require_owner=False))[0])

    def test_expired_credential_still_attached(self):
        expired = Credential("old", "secret", days_ago(200), days_ago(10))
        self.assertIn("NHI-006", rules_for(identity(credentials=[secret(), expired]))[0])

    def test_disabled_with_live_credentials(self):
        self.assertIn("NHI-007", rules_for(identity(enabled=False))[0])
        self.assertNotIn("NHI-007", rules_for(identity(enabled=False, credentials=[]))[0])

    def test_expiring_soon_is_only_a_warning(self):
        ident = identity(credentials=[Credential("c", "certificate", days_ago(60), days_ahead(10))])
        self.assertEqual(rules_for(ident), (["NHI-008"], "warning"))

    def test_too_many_credentials(self):
        ident = identity(credentials=[secret("a"), secret("b"), secret("c")])
        self.assertIn("NHI-009", rules_for(ident)[0])


class RotationOverlapTests(unittest.TestCase):
    """A credential mid-rotation (expires within the overlap, newer one exists) is not a violation."""

    def test_retiring_credential_ignored(self):
        old = Credential("old", "secret", days_ago(200), days_ahead(5))   # would be NHI-001 + NHI-008
        new = secret("new", age=0)
        self.assertEqual(rules_for(identity(credentials=[old, new])), ([], "compliant"))

    def test_without_replacement_it_still_counts(self):
        old = Credential("old", "secret", days_ago(200), days_ahead(5))
        self.assertIn("NHI-001", rules_for(identity(credentials=[old]))[0])


class PolicyTests(unittest.TestCase):
    def test_environment_override_inherits_defaults(self):
        pol = load_policy(POLICY)
        self.assertEqual(pol.for_environment("prod").max_credential_age_days, 90)
        self.assertEqual(pol.for_environment("prod").stale_after_days, 90)
        self.assertEqual(pol.for_environment("dev").max_credential_age_days, 180)
        self.assertEqual(pol.for_environment("dev").stale_after_days, 120)
        self.assertEqual(pol.for_environment("staging").max_credential_age_days, 180)

    def test_validation(self):
        for bad in [{"defaults": {"nope": 1}}, {"defaults": {"stale_after_days": -1}},
                    {"defaults": {"require_owner": "yes"}}, {"defaults": {"privileged_roles": "Admins"}},
                    {"defaults": {"max_credential_age_days": 400, "max_credential_lifetime_days": 365}}, []]:
            with self.assertRaises(PolicyError, msg=repr(bad)):
                parse_policy(bad)


class SampleInventoryTests(unittest.TestCase):
    """The sample data plants one or more problems per identity; check each is caught."""

    @classmethod
    def setUpClass(cls):
        cls.audit = run_audit(load_inventory([("azure_ad", AZURE), ("local", LOCAL)]), load_policy(POLICY), NOW)
        cls.rules = {r.identity.name: sorted(f.rule for f in r.findings) for r in cls.audit.results}

    def test_summary(self):
        self.assertEqual((self.audit.count("compliant"), self.audit.count("warning"), self.audit.count("non_compliant")), (4, 1, 7))
        self.assertEqual(Counter(f.severity for f in self.audit.findings), {"high": 8, "medium": 7, "low": 1})
        self.assertEqual(self.audit.compliance_rate, 33.3)

    def test_each_planted_problem(self):
        expected = {
            "legacy-reporting": ["NHI-001", "NHI-002", "NHI-004", "NHI-005"],
            "svc_backup@build-01": ["NHI-001", "NHI-002", "NHI-003"],
            "data-sync": ["NHI-001", "NHI-006"],
            "breakglass-automation": ["NHI-001", "NHI-004"],
            "monitoring-agent": ["NHI-003"],
            "deploy@web-02": ["NHI-004", "NHI-005"],
            "old-poc": ["NHI-007"],
            "ci-deployer": ["NHI-008"],
            "payments-api": [], "new-integration": [], "svc_sql@build-01": [], "svc_metrics@web-02": [],
        }
        self.assertEqual(self.rules, expected)

    def test_results_sorted_worst_first(self):
        self.assertEqual(self.audit.results[-1].status, "compliant")
        self.assertEqual(self.audit.results[0].status, "non_compliant")


if __name__ == "__main__":
    unittest.main()
