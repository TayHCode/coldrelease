from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow
import test_release_check as fixtures

NAMES = ("COLDRELEASE_DENYLIST", "COLDRELEASE_REPORTS", "RELEASE_CHECK_DENYLIST", "RELEASE_CHECK_REPORTS")
DENYLIST_NOTICE = "RELEASE_CHECK_DENYLIST is deprecated; set COLDRELEASE_DENYLIST instead"
REPORTS_NOTICE = "RELEASE_CHECK_REPORTS is deprecated; set COLDRELEASE_REPORTS instead"
RECEIPT_0_1_0 = Path(__file__).resolve().parent / "fixtures" / "receipt-0.1.0.json"


class ColdreleaseNamesTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.home = self.fx.root / "home"
        self.home.mkdir()

    def audit(self, *extra, **names):
        env = {k: v for k, v in os.environ.items() if k not in NAMES}
        env.update(HOME=str(self.home), **{k: str(v) for k, v in names.items()})
        return subprocess.run([sys.executable, rc.__file__, str(self.fx.repo), *extra],
                              capture_output=True, text=True, env=env, timeout=120)

    def reports_in(self, root):
        return sorted(Path(root).rglob("report.json"))

    def test_new_names_set_denylist_and_reports_without_notice(self):
        reports = self.fx.root / "new-reports"
        result = self.audit(COLDRELEASE_DENYLIST=self.fx.denylist, COLDRELEASE_REPORTS=reports)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(len(self.reports_in(reports)), 1)
        self.assertNotIn("deprecated", result.stderr)

    def test_old_names_still_work_and_print_one_notice_each(self):
        legacy = self.home / ".local/state/release-check"
        result = self.audit(RELEASE_CHECK_DENYLIST=self.fx.denylist, RELEASE_CHECK_REPORTS=legacy)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(len(self.reports_in(legacy)), 1)
        self.assertFalse((self.home / ".local/state/coldrelease").exists())
        lines = result.stderr.splitlines()
        self.assertEqual(lines[:2], [DENYLIST_NOTICE, REPORTS_NOTICE])
        self.assertEqual(lines.count(DENYLIST_NOTICE), 1)
        self.assertEqual(lines.count(REPORTS_NOTICE), 1)
        reports = self.fx.root / "flag-reports"
        flagged = self.audit("--denylist", str(self.fx.denylist), "--reports", str(reports),
                             RELEASE_CHECK_DENYLIST=self.fx.root / "missing.json", RELEASE_CHECK_REPORTS=self.fx.root / "old")
        self.assertEqual((flagged.returncode, flagged.stderr), (2, ""))
        self.assertEqual(len(self.reports_in(reports)), 1)

    def test_new_name_wins_over_old_name(self):
        reports, legacy = self.fx.root / "new-reports", self.fx.root / "old-reports"
        result = self.audit(COLDRELEASE_DENYLIST=self.fx.denylist, RELEASE_CHECK_DENYLIST=self.fx.root / "missing.json",
                            COLDRELEASE_REPORTS=reports, RELEASE_CHECK_REPORTS=legacy)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(len(self.reports_in(reports)), 1)
        self.assertFalse(legacy.exists())
        self.assertNotIn("deprecated", result.stderr)

    def test_default_reports_dir_is_coldrelease_and_old_dir_is_kept(self):
        legacy = self.home / ".local/state/release-check/repo/20261101T000000.000000Z"
        legacy.mkdir(parents=True)
        (legacy / "report.json").write_text('{"kept": true}\n')
        result = self.audit(COLDRELEASE_DENYLIST=self.fx.denylist)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        report = self.home.resolve() / ".local/state/coldrelease" / json.loads(result.stdout)["report"]
        self.assertTrue(report.is_file())
        self.assertEqual(result.stderr.splitlines(), ["report: " + str(report)])
        self.assertEqual(self.reports_in(self.home / ".local/state/release-check"), [legacy / "report.json"])
        self.assertEqual((legacy / "report.json").read_text(), '{"kept": true}\n')

    def preflight(self, **names):
        xdg_dir = self.fx.root / "xdg_dir"
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"XDG_CACHE_HOME": str(xdg_dir)}), redirect_stdout(out), redirect_stderr(err):
            for name in NAMES:
                os.environ.pop(name, None)
            os.environ.update({k: str(v) for k, v in names.items()})
            code = rc.main(["preflight", str(self.fx.repo), "--run", "names"])
        return code, json.loads(out.getvalue()), err.getvalue(), xdg_dir

    def test_workflow_reads_both_denylist_names_and_caches_under_coldrelease(self):
        code, result, err, xdg_dir = self.preflight(COLDRELEASE_DENYLIST=self.fx.denylist)
        self.assertEqual((code, result["outcome"]), (0, "PASS"), err)
        self.assertNotIn("deprecated", err)
        self.assertEqual(len(list((xdg_dir / "coldrelease" / "preflight-v1").glob("*.json"))), 1)
        self.assertFalse((xdg_dir / "release-check").exists())
        code, result, err, _ = self.preflight(RELEASE_CHECK_DENYLIST=self.fx.denylist)
        self.assertEqual((code, result["outcome"]), (0, "PASS"), err)
        self.assertEqual(err.splitlines().count(DENYLIST_NOTICE), 1)

    def validate_0_1_0_receipt(self, denylist, name="COLDRELEASE_DENYLIST"):
        out, err = io.StringIO(), io.StringIO()
        with patch.dict(os.environ), redirect_stdout(out), redirect_stderr(err):
            for key in NAMES:
                os.environ.pop(key, None)
            os.environ[name] = str(denylist)
            code = rc.main(["--validate-receipt", str(RECEIPT_0_1_0), str(self.fx.repo), "--verify"])
        return code, json.loads(out.getvalue()), err.getvalue()

    def test_either_manifest_name_is_read_and_identical_copies_are_fine(self):
        legacy = self.fx.repo / "release-check.json"
        data = json.loads(legacy.read_text())
        self.assertEqual(rc.manifest_for(self.fx.repo, None)["checks"], data["checks"])
        current = self.fx.repo / "coldrelease.json"
        current.write_bytes(legacy.read_bytes())
        self.assertEqual(rc.manifest_for(self.fx.repo, None)["checks"], data["checks"])
        legacy.unlink()
        current.write_text(json.dumps({**data, "checks": [{"role": "tests", "argv": ["python", "-c", "print(2)"]}]}))
        self.assertEqual(rc.manifest_for(self.fx.repo, None)["checks"][0]["argv"][-1], "print(2)")

    def test_two_different_manifests_stop_the_run_naming_both(self):
        legacy = self.fx.repo / "release-check.json"
        (self.fx.repo / "coldrelease.json").write_text(legacy.read_text().replace("print(1)", "print(2)"))
        with self.assertRaises(rc.AuditError) as caught:
            rc.manifest_for(self.fx.repo, None)
        self.assertEqual(str(caught.exception), "manifest-conflict")
        self.assertIn("coldrelease.json and release-check.json", caught.exception.detail)
        with self.assertRaisesRegex(rc.AuditError, "manifest-conflict"):
            rc.manifest_for(self.fx.repo, legacy)
        result = self.audit(COLDRELEASE_DENYLIST=self.fx.denylist)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest-conflict", result.stdout + result.stderr)
        self.assertIn("coldrelease.json and release-check.json", result.stdout + result.stderr)
        self.assertEqual(self.reports_in(self.home), [])

    def test_0_1_0_receipt_still_validates(self):
        for name in ("COLDRELEASE_DENYLIST", "RELEASE_CHECK_DENYLIST"):
            with self.subTest(name=name):
                code, result, err = self.validate_0_1_0_receipt(self.fx.denylist, name)
                self.assertEqual(code, 2, err)
                self.assertEqual(result, {"outcome": "INCOMPLETE", "reasons": ["receipt-stale"],
                                          "mismatched": ["inventory", "scanners"]})
                self.assertNotIn("malformed", err)
        other = self.fx.root / "other-terms.json"
        other.write_text('["OtherName"]')
        _, result, _ = self.validate_0_1_0_receipt(other)
        self.assertEqual(result["mismatched"], ["inventory", "policy", "scanners"])


if __name__ == "__main__":
    unittest.main()
