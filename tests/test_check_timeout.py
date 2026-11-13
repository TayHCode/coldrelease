from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import release_check as rc
import release_workflow as workflow
import test_release_check as fixtures



class CheckTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        self.repo = self.testbed.repo

    def set_check(self, seconds=5, **fields):
        argv = ["python", "-c", f"import time;time.sleep({seconds})"]
        manifest = {**self.testbed.manifest, "checks": [{"role": "tests", "argv": argv, **fields}]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.testbed.commit("Set the tests check")

    def workflow(self, command, run, *extra):
        process = subprocess.run([sys.executable, rc.__file__, command, str(self.repo), "--denylist", str(self.testbed.denylist),
                                  "--run", run, *extra], capture_output=True, text=True)
        return process.returncode, json.loads(process.stdout), process.stderr

    def export(self, run):
        code, result, _ = self.workflow("plan", run)
        self.assertEqual((code, result["outcome"]), (0, "PASS"), result)
        return self.workflow("export", run, "--verify")

    def test_check_over_its_manifest_timeout_fails_export_and_a_larger_budget_passes(self):
        self.set_check(timeout=2)
        code, result, err = self.export("short")
        self.assertEqual((code, result["outcome"]), (1, "FAIL"), result)
        run = workflow.run_directory(self.repo, "short")
        attempt = run / "attempts" / workflow.read_json(run / "export.json")["attempt"]
        report = workflow.read_json(attempt / "report.json")
        self.assertIn("command-timeout", report["reasons"])
        self.assertEqual(report["verification"]["commands"][-1]["exit_code"], 124)
        self.assertIn('quality: command-timeout in release-check.json; the tests command exceeded its 2s limit '
                      '("timeout" in release-check.json)', err)

        self.set_check(timeout=10)
        code, result, err = self.export("long")
        self.assertEqual((code, result["outcome"], err), (0, "PASS", ""), result)
        long_run = workflow.run_directory(self.repo, "long")
        receipt = workflow.read_json(long_run / "attempts" / workflow.read_json(long_run / "export.json")["attempt"] / "receipt.json")
        self.assertNotEqual(receipt["bindings"]["recipe"], workflow.read_json(attempt / "receipt.json")["bindings"]["recipe"])

    def test_cli_timeout_still_bounds_checks_without_a_manifest_timeout(self):
        self.set_check(seconds=60)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = rc.main([str(self.repo), "--denylist", str(self.testbed.denylist), "--reports", str(self.testbed.root / "reports"),
                            "--verify", "--timeout", "20"])
        self.assertEqual(code, 1, out.getvalue())
        self.assertIn("quality: command-timeout in release-check.json; the tests command exceeded its 20s limit (--timeout)", err.getvalue())

    def test_invalid_manifest_timeouts_are_rejected(self):
        for value in (0, -1, 2.5, "2", True, None):
            with self.subTest(value=value):
                self.set_check(timeout=value)
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    code = rc.main([str(self.repo), "--denylist", str(self.testbed.denylist), "--reports", str(self.testbed.root / "reports")])
                self.assertEqual((code, out.getvalue()), (2, ""))
                error = json.loads(err.getvalue())
                self.assertEqual(error["error"], "manifest-schema")
                self.assertEqual(error["detail"], "checks timeout must be a whole number of seconds greater than 0")

    def test_timeout_kills_the_child_when_killpg_is_denied(self):
        with tempfile.TemporaryDirectory() as tempdir:
            pid_file = Path(tempdir) / "pid"
            argv = [sys.executable, "-c", f"import os,time;open({str(pid_file)!r},'w').write(str(os.getpid()));time.sleep(60)"]
            with mock.patch.object(rc.os, "killpg", side_effect=PermissionError):
                try:
                    code, _ = rc.command(argv, Path(tempdir), dict(os.environ), 2)
                except PermissionError:
                    self.fail("a denied killpg escaped the timeout instead of killing the child")
            self.assertEqual(code, 124)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)

    def test_requirements_list_the_timeout_key(self):
        self.assertIn('optional "timeout"', rc.requirements_text())


if __name__ == "__main__":
    unittest.main()
