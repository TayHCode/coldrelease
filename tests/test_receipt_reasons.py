import json
from pathlib import Path
import subprocess
import sys
import unittest

import test_release_check as fixtures

ROOT = Path(__file__).resolve().parents[1]
INVALID = {"outcome": "INCOMPLETE", "reasons": ["receipt-invalid"], "mismatched": []}


class ReceiptReasonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = fixtures.AuditTests()
        cls.fx.setUp()
        cls.addClassCleanup(cls.fx.doCleanups)
        cls.export = cls.fx.root / "export"
        code, _, _ = cls.fx.run_cli("--verify", "--export", str(cls.export))
        assert code == 0
        cls.receipt = next((cls.fx.root / "reports").rglob("receipt.json"))

    def run_cli(self, *args):
        result = subprocess.run([sys.executable, str(ROOT / "release_check.py"), *args],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def validate(self, receipt, export):
        return self.run_cli("--denylist", str(self.fx.denylist), "--verify", "--validate-receipt", str(receipt), str(export))

    def assert_rejected(self, result, reason, private, stdout=INVALID):
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout), stdout)
        self.assertEqual(result.stderr.splitlines(), [reason])
        for value in private:
            self.assertNotIn(value, result.stdout + result.stderr)

    def bad_receipt(self, name, content):
        path = self.fx.root / name
        if content is not None:
            path.write_text(content)
        return path

    def test_receipt_file_missing(self):
        path = self.bad_receipt("PrivateMissing.json", None)
        self.assert_rejected(self.validate(path, self.export), "receipt file does not exist or cannot be read",
                             [str(path), path.name])

    def test_receipt_is_folder(self):
        path = self.fx.root / "PrivateReceiptFolder"
        path.mkdir()
        self.assert_rejected(self.validate(path, self.export), "receipt file does not exist or cannot be read",
                             [str(path), path.name])

    def test_receipt_not_json(self):
        path = self.bad_receipt("PrivateNotJson.json", "SecretValue not json")
        self.assert_rejected(self.validate(path, self.export), "receipt file is not valid JSON",
                             [str(path), path.name, "SecretValue"])

    def test_receipt_missing_fields(self):
        path = self.bad_receipt("PrivateEmpty.json", "{}")
        keys = "bindings, created_at, export_head, export_tree, outcome, reasons, receipt_sha256, schema_version"
        self.assert_rejected(self.validate(path, self.export), "receipt is missing required fields: " + keys,
                             [str(path), path.name])

    def test_receipt_missing_one_field_names_only_that_key(self):
        receipt = json.loads(self.receipt.read_text())
        del receipt["export_tree"]
        receipt["outcome"] = "SecretOutcome"
        path = self.bad_receipt("PrivatePartial.json", json.dumps(receipt))
        self.assert_rejected(self.validate(path, self.export), "receipt is missing required fields: export_tree",
                             [str(path), path.name, "SecretOutcome"])

    def test_receipt_tampered(self):
        receipt = json.loads(self.receipt.read_text())
        receipt["outcome"] = "FAIL"
        path = self.bad_receipt("PrivateTampered.json", json.dumps(receipt))
        self.assert_rejected(self.validate(path, self.export), "receipt fields are malformed or do not match its checksum",
                             [str(path), path.name])

    def assert_export_rejected(self, result, private):
        stale = {"outcome": "INCOMPLETE", "reasons": ["receipt-stale"],
                 "mismatched": ["inventory", "recipe", "scanners"]}
        self.assert_rejected(result, "export folder does not exist or is not a folder", private, stale)

    def test_export_folder_missing(self):
        missing = self.fx.root / "PrivateNoExport"
        self.assert_export_rejected(self.validate(self.receipt, missing), [str(missing), missing.name])

    def test_export_path_is_file(self):
        path = self.bad_receipt("PrivateExportFile", "x")
        self.assert_export_rejected(self.validate(self.receipt, path), [str(path), path.name])

    def test_valid_receipt_prints_no_reason(self):
        result = self.validate(self.receipt, self.export)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["outcome"], "PASS")
        self.assertEqual(result.stderr, "")

    def assert_destination_exists(self, dest):
        result = self.run_cli(str(self.fx.repo), "--denylist", str(self.fx.denylist),
                              "--reports", str(self.fx.root / "reports-exists"), "--export", str(dest))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr.splitlines(),
                         ["export destination already exists; choose a new path",
                          '{"outcome":"INCOMPLETE","ready":false,"error":"export-destination-exists"}'])
        for value in (str(dest), dest.name):
            self.assertNotIn(value, result.stdout + result.stderr)

    def test_export_destination_is_file(self):
        path = self.bad_receipt("PrivateDestFile", "keep")
        self.assert_destination_exists(path)
        self.assertEqual(path.read_text(), "keep")

    def test_export_destination_is_folder(self):
        path = self.fx.root / "PrivateDestFolder"
        path.mkdir()
        self.assert_destination_exists(path)

    def test_new_export_destination_unchanged(self):
        dest = self.fx.root / "fresh-export"
        result = self.run_cli(str(self.fx.repo), "--denylist", str(self.fx.denylist),
                              "--reports", str(self.fx.root / "reports-fresh"), "--verify", "--export", str(dest))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertTrue(dest.is_dir())


if __name__ == "__main__":
    unittest.main()
