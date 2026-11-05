import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release_workflow


class InvalidArgumentsTests(unittest.TestCase):
    def run_cli(self, args, reason, script="release_check.py"):
        env = os.environ.copy()
        env.pop("RELEASE_CHECK_DENYLIST", None)
        result = subprocess.run(
            [sys.executable, script, *args],
            cwd=Path(__file__).resolve().parents[1], env=env,
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        lines = result.stderr.splitlines()
        self.assertEqual(lines[0], '{"ready":false,"error":"invalid-arguments"}')
        self.assertEqual(lines[1:], [reason])
        return result

    def test_workflow_missing_arguments(self):
        for args, reason in (([], "missing command and repo; see --help"),
                             (["preflight"], "missing repo; see --help")):
            with self.subTest(args=args):
                self.run_cli(args, reason, script="release_workflow.py")

    def test_workflow_unknown_command(self):
        secret = "ghp_" + "x" * 36
        for command in ("bogus", secret):
            with self.subTest(command=command):
                result = self.run_cli(
                    [command, "/tmp"],
                    "unknown command; use one of: preflight, plan, check, export, approve, publish",
                    script="release_workflow.py",
                )
                self.assertNotIn(command, result.stdout + result.stderr)

    def test_workflow_valid_command(self):
        with patch.object(release_workflow, "workflow", return_value={"outcome": "PASS"}) as workflow, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release_workflow.main(["preflight", "/tmp"]), 0)
        self.assertEqual(workflow.call_args.args[0].command, "preflight")
        self.assertEqual(workflow.call_args.args[0].repo, Path("/tmp"))

    def test_missing_denylist(self):
        self.run_cli([".", "--reports", "/tmp/private-reports"],
                     "pass --denylist or set RELEASE_CHECK_DENYLIST")

    def test_missing_repository_path(self):
        with tempfile.TemporaryDirectory() as root:
            for path in (str(Path(root) / "private-missing-repository"),
                         str(Path(root) / ("private-" + "x" * 256)),
                         "~release-check-nonexistent-private-user/repo"):
                with self.subTest(path=path):
                    result = self.run_cli(
                        ["--reports", root, path],
                        "repository path does not exist or is not a directory")
                    self.assertNotIn(path, result.stdout + result.stderr)

    def test_missing_denylist_path(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / "private-missing-denylist")
            repo = Path(root) / "repo"
            repo.mkdir()
            env = os.environ.copy()
            env.pop("RELEASE_CHECK_DENYLIST", None)
            result = subprocess.run(
                [sys.executable, "release_check.py", "--denylist", path, str(repo)],
                cwd=Path(__file__).resolve().parents[1], env=env,
                capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertNotIn(path, result.stdout + result.stderr)
            self.assertEqual(result.stderr.splitlines(), [
                "denylist file does not exist or cannot be read",
                '{"outcome":"INCOMPLETE","ready":false,"error":"audit-incomplete","detail":"FileNotFoundError (ENOENT)"}'])

    def test_workflow_missing_repository_path(self):
        with tempfile.TemporaryDirectory() as root:
            for name in ("private-missing-repository", "private-" + "x" * 256):
                with self.subTest(name=name):
                    path = str(Path(root) / name)
                    result = subprocess.run(
                        [sys.executable, "release_workflow.py", "preflight", path],
                        cwd=Path(__file__).resolve().parents[1],
                        capture_output=True, text=True)
                    self.assertEqual(result.returncode, 2)
                    self.assertNotIn(path, result.stdout + result.stderr)
                    self.assertEqual(json.loads(result.stdout), {
                        "outcome": "INCOMPLETE", "ready": False,
                        "reasons": ["git-read-failed"], "notice": release_workflow.NOTICE})
                    self.assertEqual(result.stderr.splitlines(), [
                        "repository path does not exist or is not a directory"])

    def test_unknown_option(self):
        for prefix in (["."], ["plan", "."]):
            with self.subTest(prefix=prefix):
                self.run_cli([*prefix, "--unknown"], "unknown option or extra argument; see --help")

    def test_missing_option_value(self):
        for prefix in (["."], ["plan", "."]):
            with self.subTest(prefix=prefix):
                self.run_cli([*prefix, "--manifest"], "missing value for --manifest")

    def test_secret_value_is_never_echoed(self):
        secret = "ghp_" + "x" * 36
        for prefix in (["."], ["plan", "."]):
            with self.subTest(prefix=prefix):
                result = self.run_cli([*prefix, "--token=" + secret],
                                      "unknown option or extra argument; see --help")
                self.assertNotIn(secret, result.stdout + result.stderr)

    def test_invalid_timeout(self):
        reason = "--timeout must be a whole number of seconds greater than 0"
        for prefix in (["."], *([command, "."] for command in release_workflow.COMMANDS)):
            for value in ("abc", "0", "-5", "1.5", "ghp_" + "x" * 36):
                with self.subTest(prefix=prefix, value=value):
                    result = self.run_cli([*prefix, "--timeout", value], reason)
                    if value.startswith("ghp_"):
                        self.assertNotIn(value, result.stdout + result.stderr)

    def test_valid_timeout(self):
        result = subprocess.run(
            [sys.executable, "release_check.py", "--requirements", "--timeout", "1"],
            cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("manifest", result.stdout)
        self.assertEqual(result.stderr, "")
        with patch.object(release_workflow, "workflow", return_value={"outcome": "PASS"}) as workflow, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(release_workflow.main(["plan", ".", "--timeout", "42"]), 0)
        self.assertEqual(workflow.call_args.args[0].timeout, 42)

    def test_unhandled_errors_use_safe_fallback(self):
        secret = "/private/operator-path"
        self.run_cli(["plan", ".", "--scanner", secret], "see --help")


if __name__ == "__main__":
    unittest.main()
