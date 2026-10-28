import json
import tempfile
import unittest
from pathlib import Path

from tests.helpers import AZURE, LOCAL, NOW
from nhi_gov.enforce import save_inventory_snapshot
from nhi_gov.models import parse_tags, parse_time
from nhi_gov.providers import load_inventory


class ParsingTests(unittest.TestCase):
    def test_parse_time(self):
        self.assertEqual(parse_time("2026-10-23T06:00:00Z"), NOW)
        self.assertEqual(parse_time("2026-10-23T09:00:00+03:00"), NOW)
        self.assertEqual(parse_time("2026-10-23").date().isoformat(), "2026-10-23")
        self.assertIsNone(parse_time(None))
        self.assertIsNone(parse_time(""))

    def test_parse_tags(self):
        self.assertEqual(parse_tags(["env=prod", "HideApp", "nhi:justification=CHG-1 a=b"]),
                         {"env": "prod", "HideApp": "true", "nhi:justification": "CHG-1 a=b"})
        self.assertEqual(parse_tags({"env": "dev"}), {"env": "dev"})
        self.assertEqual(parse_tags(None), {})


class AzureAdTests(unittest.TestCase):
    def setUp(self):
        self.by_name = {i.name: i for i in load_inventory([("azure_ad", AZURE)])}

    def test_all_principals_loaded(self):
        self.assertEqual(len(self.by_name), 8)

    def test_secrets_and_certificates_joined_by_app_id(self):
        self.assertEqual([c.kind for c in self.by_name["data-sync"].credentials], ["secret"] * 3)
        self.assertEqual([c.kind for c in self.by_name["ci-deployer"].credentials], ["certificate"])

    def test_sign_in_activity_and_owners(self):
        pay = self.by_name["payments-api"]
        self.assertEqual(pay.last_used_at.date().isoformat(), "2026-10-22")
        self.assertEqual(pay.owners, ["payments-team@contoso.example"])
        self.assertIsNone(self.by_name["old-poc"].last_used_at)   # no sign-in record

    def test_tags_drive_environment_and_protection(self):
        self.assertEqual(self.by_name["data-sync"].environment, "dev")
        self.assertTrue(self.by_name["breakglass-automation"].protected)
        self.assertFalse(self.by_name["payments-api"].protected)

    def test_disabled_flag(self):
        self.assertFalse(self.by_name["old-poc"].enabled)


class LocalAccountTests(unittest.TestCase):
    def test_accounts_become_identities_with_a_password_credential(self):
        ids = {i.name: i for i in load_inventory([("local", LOCAL)])}
        self.assertEqual(sorted(ids), ["deploy@web-02", "svc_backup@build-01", "svc_metrics@web-02", "svc_sql@build-01"])
        backup = ids["svc_backup@build-01"]
        self.assertEqual(backup.environment, "prod")          # from the host
        self.assertEqual(backup.roles, ["Administrators", "Backup Operators"])
        self.assertIsNone(backup.credentials[0].expires_at)    # password never expires
        self.assertEqual(ids["deploy@web-02"].tags["nhi:justification"], "INF-311 deploys systemd units")


class CombinedInventoryTests(unittest.TestCase):
    def test_sources_combine(self):
        self.assertEqual(len(load_inventory([("azure_ad", AZURE), ("local", LOCAL)])), 12)

    def test_duplicate_ids_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            load_inventory([("azure_ad", AZURE), ("azure_ad", AZURE)])

    def test_unknown_source_rejected(self):
        with self.assertRaises(ValueError):
            load_inventory([("aws", AZURE)])

    def test_snapshot_round_trip(self):
        original = load_inventory([("azure_ad", AZURE), ("local", LOCAL)])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snap.json"
            save_inventory_snapshot(original, path)
            json.loads(path.read_text(encoding="utf-8"))
            restored = load_inventory([("snapshot", path)])
        self.assertEqual([i.to_dict() for i in restored], [i.to_dict() for i in original])


if __name__ == "__main__":
    unittest.main()
