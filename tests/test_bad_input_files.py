import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

import release_workflow
import test_release_check as fixtures

ROOT = Path(__file__).resolve().parents[1]
SHAPE = "denylist must be a JSON list, {terms: [...]} or {categories: ...}"
NO_GIT = "repository path is not a git repository"
NO_DIR = "repository path does not exist or is not a directory"


class BadInputFilesTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.root = self.fx.root

    def run_script(self, script, repo=None, denylist=None, manifest=None):
        fx = self.fx
        args = [str(repo or fx.repo), "--denylist", str(denylist or fx.denylist)]
        if manifest:
            args += ["--manifest", str(manifest)]
        if script == "release_workflow.py":
            args = ["preflight", *args]
        else:
            args += ["--reports", str(self.root / "reports")]
        env = os.environ.copy()
        env.pop("RELEASE_CHECK_DENYLIST", None)
        result = subprocess.run([sys.executable, script, *args], cwd=ROOT, env=env, capture_output=True, text=True)
        for private in (str(repo or fx.repo), str(denylist or fx.denylist), str(manifest or ""), "PrivateTerm", "private-name"):
            if private:
                self.assertNotIn(private, result.stdout + result.stderr)
        return result

    def check(self, script, result, reason, error, detail=None):
        self.assertEqual(result.returncode, 2)
        if script == "release_check.py":
            self.assertEqual(result.stdout, "")
            expected = {"outcome": "INCOMPLETE", "ready": False, "error": error}
            if detail:
                expected["detail"] = detail
            self.assertEqual(result.stderr.splitlines(), [reason, json.dumps(expected, separators=(",", ":"))])
        else:
            expected = {"outcome": "INCOMPLETE", "ready": False,
                        "reasons": ["workflow-incomplete" if error == "audit-incomplete" else error],
                        "notice": release_workflow.NOTICE}
            if detail:
                expected["detail"] = detail
            self.assertEqual(json.loads(result.stdout), expected)
            self.assertEqual(result.stderr.splitlines(), [reason])

    def denylist(self, name, text):
        path = self.root / f"private-name-{name}"
        path.write_text(text)
        return path

    def test_bad_denylists_say_why(self):
        cases = {
            "empty.txt": ("", "denylist file is empty", "denylist-schema"),
            "empty.json": ("", "denylist file is empty", "audit-incomplete", "JSONDecodeError"),
            "comments.txt": ("# PrivateTerm\n", "denylist has no terms", "denylist-schema"),
            "no-terms.json": ("[]", "denylist has no terms", "denylist-schema"),
            "object.json": ('{"PrivateTerm": 1}', SHAPE, "denylist-schema"),
            "category.json": ('{"categories": {"x": "PrivateTerm"}}', SHAPE, "denylist-schema"),
            "blank.json": ('["PrivateTerm", " "]', "denylist has a blank or non-text term", "denylist-schema"),
            "number.json": ('["PrivateTerm", 3]', "denylist has a blank or non-text term", "denylist-schema"),
            "broken.json": ('["PrivateTerm", ', "denylist file is not valid JSON", "audit-incomplete", "JSONDecodeError"),
        }
        for script in ("release_check.py", "release_workflow.py"):
            for name, (text, reason, error, *detail) in cases.items():
                with self.subTest(script=script, name=name):
                    result = self.run_script(script, denylist=self.denylist(name, text))
                    self.check(script, result, reason, error, *detail)

    def test_broken_manifest_says_why(self):
        manifest = self.denylist("manifest.json", '{"exclude": [PrivateTerm')
        for script in ("release_check.py", "release_workflow.py"):
            with self.subTest(script=script):
                result = self.run_script(script, manifest=manifest)
                self.check(script, result, "manifest file is not valid JSON", "audit-incomplete", "JSONDecodeError")

    def test_missing_explicit_manifest_stops_the_run(self):
        missing = self.root / "private-name-missing-manifest.json"
        for script in ("release_check.py", "release_workflow.py"):
            with self.subTest(script=script):
                result = self.run_script(script, manifest=missing)
                self.check(script, result, "manifest file does not exist or cannot be read", "audit-incomplete", "FileNotFoundError (ENOENT)")
                self.assertNotIn("Traceback", result.stderr)
        self.assertFalse((self.root / "reports").exists())

    def test_missing_default_manifest_is_still_optional(self):
        (self.fx.repo / "release-check.json").unlink()
        for script in ("release_check.py", "release_workflow.py"):
            with self.subTest(script=script):
                result = self.run_script(script)
                self.assertNotIn("manifest file", result.stderr)
                self.assertIn(self.outcome(result.stdout)["outcome"], {"PASS", "FAIL", "INCOMPLETE"})
                self.assertNotEqual(result.stdout, "")

    def outcome(self, stdout):
        summary = json.loads(stdout)
        return {k: summary[k] for k in ("outcome", "ready") if k in summary}

    def test_unreadable_manifest_says_why(self):
        directory = self.root / "private-name-manifest-dir"
        directory.mkdir()
        for script in ("release_check.py", "release_workflow.py"):
            with self.subTest(script=script):
                result = self.run_script(script, manifest=directory)
                self.check(script, result, "manifest file does not exist or cannot be read", "audit-incomplete", "IsADirectoryError (EISDIR)")

    def test_bad_repository_paths_say_why(self):
        not_git = self.root / "private-name-not-git"
        not_git.mkdir()
        a_file = self.root / "private-name-file"
        a_file.write_text("x")
        cases = ((not_git, NO_GIT), (a_file, NO_DIR), (self.root / "private-name-missing", NO_DIR))
        for script in ("release_check.py", "release_workflow.py"):
            for path, reason in cases:
                with self.subTest(script=script, path=path.name):
                    result = self.run_script(script, repo=path)
                    self.check(script, result, reason, "git-read-failed")


if __name__ == "__main__":
    unittest.main()
