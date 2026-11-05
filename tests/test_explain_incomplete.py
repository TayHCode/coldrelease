import errno
import json
import os
import subprocess
import unittest
from unittest.mock import patch

import release_check as rc
from tests import test_release_check as fixtures
from tests.test_strict_receipt import cli


class ExplainIncompleteTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def audit(self, repo):
        out, err = fixtures.io.StringIO(), fixtures.io.StringIO()
        with fixtures.redirect_stdout(out), fixtures.redirect_stderr(err):
            code = rc.main([str(repo), "--denylist", str(self.fx.denylist), "--reports", str(self.fx.root / "reports")])
        return code, out.getvalue(), err.getvalue()

    def test_subdirectory_of_another_repository_is_incomplete(self):
        sub = self.fx.repo / "sub"
        sub.mkdir()
        (sub / "a.txt").write_text("untracked")
        code, out, err = self.audit(sub)
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        lines = err.splitlines()
        self.assertEqual(lines[0], "repository path is inside another Git repository; pass its top-level folder")
        self.assertEqual(json.loads(lines[1]), {"outcome": "INCOMPLETE", "ready": False, "error": "not-repository-root"})
        self.assertFalse((self.fx.root / "reports").exists())

    def test_repository_root_with_trailing_space_is_audited(self):
        spaced = self.fx.root / "repo "
        self.fx.repo.rename(spaced)
        code, out, err = self.audit(spaced)
        self.assertNotIn("not-repository-root", err)
        self.assertIn('"outcome"', out)

    def test_repository_root_with_non_utf8_name_is_audited(self):
        odd = self.fx.root / os.fsdecode(b"repo-\xff")
        self.fx.repo.rename(odd)
        code, out, err = self.audit(odd)
        self.assertNotIn("not-repository-root", err)
        self.assertNotIn("UnicodeDecodeError", err)
        self.assertIn('"outcome"', out)

    def test_workflow_rejects_subdirectory_of_another_repository(self):
        sub = self.fx.repo / "sub"
        sub.mkdir()
        (sub / "a.txt").write_text("untracked")
        out, err = fixtures.io.StringIO(), fixtures.io.StringIO()
        with fixtures.redirect_stdout(out), fixtures.redirect_stderr(err):
            code = rc.main(["preflight", str(sub), "--denylist", str(self.fx.denylist)])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["reasons"], ["repository-root-required"])

    def test_unexpected_failure_names_class_and_errno_without_paths(self):
        failure = OSError(errno.EACCES, "SecretMessage", "/secret/path")
        with patch.object(rc.Scanner, "tree", side_effect=failure):
            code, out, err = self.audit(self.fx.repo)
        self.assertEqual(code, 2)
        lines = err.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0]), {"outcome": "INCOMPLETE", "ready": False, "error": "audit-incomplete", "detail": "PermissionError (EACCES)"})
        for private in ("/secret/path", "SecretMessage"):
            self.assertNotIn(private, out + err)

    def test_unexpected_git_failure_names_the_subcommand(self):
        failure = subprocess.CalledProcessError(128, ["git", "-C", "/secret/path", "cat-file", "-p", "SecretObject"])
        with patch.object(rc.Scanner, "tree", side_effect=failure):
            code, out, err = self.audit(self.fx.repo)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(err)["detail"], "CalledProcessError (git cat-file failed)")
        for private in ("/secret/path", "SecretObject"):
            self.assertNotIn(private, out + err)

    def test_unexpected_workflow_failure_names_class_and_errno_without_paths(self):
        failure = OSError(errno.EACCES, "SecretMessage", "/secret/path")
        out, err = fixtures.io.StringIO(), fixtures.io.StringIO()
        with patch.object(rc, "copy_tree", side_effect=failure), fixtures.redirect_stdout(out), fixtures.redirect_stderr(err):
            code = rc.main(["preflight", str(self.fx.repo), "--denylist", str(self.fx.denylist)])
        self.assertEqual(code, 2)
        result = json.loads(out.getvalue())
        self.assertEqual((result["reasons"], result.get("detail")), (["workflow-incomplete"], "PermissionError (EACCES)"))
        for private in ("/secret/path", "SecretMessage"):
            self.assertNotIn(private, out.getvalue() + err.getvalue())

    def test_stale_receipt_policy_mismatch_names_the_flags_to_repeat(self):
        export = self.fx.root / "export"
        code, _, _ = self.fx.run_cli("--verify", "--private-repo", "owner/x", "--export", str(export))
        self.assertEqual(code, 0)
        receipt = next((self.fx.root / "reports").rglob("receipt.json"))
        code, out, err = cli(["--validate-receipt", str(receipt), str(export), "--denylist", str(self.fx.denylist), "--verify"])
        self.assertEqual(code, 2)
        result = json.loads(out)
        self.assertEqual(result["reasons"], ["receipt-stale"])
        self.assertEqual(result["mismatched"], ["policy"])
        self.assertEqual(err.splitlines(), ["policy changed: pass the same --denylist, --private-repo, --verify and --timeout used for the export"])


if __name__ == "__main__":
    unittest.main()
