import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import release_workflow as workflow
import test_release_check as fixtures

ROOT = Path(__file__).resolve().parents[1]
REASON = "reports folder cannot be created or written; pass --reports a writable folder"


class ReportsDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def invoke(self, script, path):
        args = [str(self.fx.repo), "--denylist", str(self.fx.denylist)]
        if script == "release_check.py":
            args += ["--reports", str(path)]
        else:
            args = ["preflight", *args, "--run", path.name]
        result = subprocess.run([sys.executable, str(ROOT / script), *args],
                                capture_output=True, text=True)
        self.assertNotIn("Traceback", result.stderr)
        for private in (str(path), path.name, str(self.fx.repo), str(self.fx.denylist)):
            self.assertNotIn(private, result.stdout + result.stderr)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        value = json.loads(result.stdout)
        self.assertEqual(value["outcome"], "INCOMPLETE")
        self.assertFalse(value["ready"])
        if script == "release_check.py":
            self.assertEqual(value["error"], "reports-unwritable")
            self.assertEqual(value["detail"], REASON)
            self.assertEqual(result.stderr.splitlines(), [REASON])
        else:
            self.assertEqual(value["reasons"], ["workflow-incomplete"])
            self.assertEqual(result.stderr, "")

    def test_reports_path_is_file(self):
        path = self.fx.root / "private-reports-file"
        path.write_text("preserve")
        self.invoke("release_check.py", path)
        self.assertEqual(path.read_text(), "preserve")

    def test_reports_folder_is_unwritable(self):
        path = self.fx.root / "private-reports-folder"
        path.mkdir()
        path.chmod(0o500)
        self.addCleanup(path.chmod, 0o700)
        if os.access(path, os.W_OK):
            self.skipTest("current user can write despite mode 0500")
        self.invoke("release_check.py", path)

    def test_workflow_run_is_file_without_traceback(self):
        path = workflow.run_directory(self.fx.repo, "private-run-file")
        path.parent.mkdir(parents=True)
        path.write_text("preserve")
        self.invoke("release_workflow.py", path)
        self.assertEqual(path.read_text(), "preserve")

    def test_workflow_run_is_unwritable_without_traceback(self):
        path = workflow.run_directory(self.fx.repo, "private-run-folder")
        path.mkdir(parents=True)
        path.chmod(0o500)
        self.addCleanup(path.chmod, 0o700)
        if os.access(path, os.W_OK):
            self.skipTest("current user can write despite mode 0500")
        self.invoke("release_workflow.py", path)
