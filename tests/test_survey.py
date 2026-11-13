from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
import shutil
import subprocess
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
import test_release_check as fixtures


class FakeGitHub:
    def __init__(self, sources):
        self.sources = sources
        self.owners = []

    def repositories(self, owner, timeout):
        self.owners.append(owner)
        return list(self.sources)

    def url(self, name):
        return self.sources[name]


def redacted(path):
    return "[path-" + hashlib.sha256(str(path).encode()).hexdigest()[:16] + "]"


class SurveyTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        self.root = self.testbed.root
        self.passing = self.testbed.repo
        self.failing = self.root / "failing"
        subprocess.run(["git", "clone", "-q", str(self.passing), str(self.failing)], check=True, capture_output=True)
        (self.failing / "SECURITY.md").unlink()
        shutil.rmtree(self.failing / ".github")
        for args in (("add", "-A"), ("-c", "user.name=Testbed", "-c", "user.email=testbed", "commit", "-q", "-m", "Drift")):
            subprocess.run(["git", "-C", str(self.failing), *args], check=True, capture_output=True)

    def cli(self, *argv):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            code = rc.main(["survey", *argv, "--denylist", str(self.testbed.denylist)])
        return code, output.getvalue()

    def snapshot(self, repo):
        return (rc.git(repo, "rev-parse", "HEAD"), rc.git(repo, "status", "--porcelain", "--untracked-files=all"),
                rc.git(repo, "for-each-ref"))

    def test_list_file_preflights_each_source_and_prints_a_readiness_table(self):
        listing = self.root / "repos.txt"
        hidden = self.root / "HiddenPerson"
        passing, failing, missing = hidden / "passing", hidden / "failing", hidden / "absent"
        shutil.copytree(self.passing, passing, symlinks=True)
        shutil.copytree(self.failing, failing, symlinks=True)
        listing.write_text(f"# synthetic portfolio\n{passing}\n\n  {failing}  \n{missing}\n")
        before = [self.snapshot(repo) for repo in (passing, failing)]
        code, output = self.cli(str(listing))
        self.assertEqual(code, 1, output)
        self.assertEqual(output.splitlines(), [
            "| Repository | Outcome | Top blockers by category | Missing documents |",
            "| --- | --- | --- | --- |",
            f"| {redacted(passing)} | PASS | none | none |",
            f"| {redacted(failing)} | FAIL | quality 2 | SECURITY.md, .github/ISSUE_TEMPLATE |",
            f"| {redacted(missing)} | INCOMPLETE | git-read-failed | none |",
            workflow.NOTICE,
        ])
        self.assertEqual([self.snapshot(repo) for repo in (passing, failing)], before)
        state = self.root / "state"
        self.assertTrue(list(state.rglob("preflight-*.json")))
        self.assertFalse([p for p in state.rglob("*") if p.name in {"export.json", "approval.json", "attempts", "publication.json"}])

    def test_owner_pattern_lists_repositories_with_github(self):
        (self.root / "synthetic-owner").mkdir()
        shutil.copytree(self.failing, self.root / "synthetic-owner" / "ready")
        github = FakeGitHub({"synthetic-owner/ready": str(self.passing)})
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.root)
        with patch.object(workflow, "GITHUB", github):
            code, output = self.cli("synthetic-owner/*")
        self.assertEqual((code, github.owners), (0, ["synthetic-owner"]), output)
        self.assertEqual(output.splitlines()[2], "| synthetic-owner/ready | PASS | none | none |")

    def test_run_is_rejected(self):
        listing = self.root / "repos.txt"
        listing.write_text(f"{self.passing}\n")
        code, output = self.cli(str(listing), "--run", "shared")
        self.assertEqual((code, json.loads(output)["reasons"]), (2, ["run-selection"]))
        self.assertFalse(list((self.root / "state").rglob("preflight-*.json")))

    def test_repository_labels_are_redacted(self):
        listing = self.root / "repos.txt"
        private = self.root / "HiddenPerson-repo"
        credential = "ssh://synthetic:" + "pw" + "@example.invalid/x.git"
        listing.write_text(f"{private}\n{credential}\n")
        code, output = self.cli(str(listing))
        self.assertEqual(code, 2, output)
        self.assertNotIn("HiddenPerson", output)
        self.assertNotIn("synthetic:pw", output)
        rows = output.splitlines()[2:4]
        self.assertTrue(all(row.startswith("| [path-") for row in rows), rows)

    def test_empty_survey_is_incomplete(self):
        listing = self.root / "repos.txt"
        listing.write_text("# nothing yet\n")
        code, output = self.cli(str(listing))
        self.assertEqual((code, json.loads(output)["reasons"]), (2, ["survey-empty"]))

    def test_table_cells_cannot_break_rows(self):
        table = workflow.survey_table([{"repository": "a|b\nc", "outcome": "PASS", "findings": [], "reasons": []}])
        self.assertEqual(table.splitlines()[2], "| a\\|b\\nc | PASS | none | none |")

    def test_github_listing_is_validated(self):
        def gh(stdout, returncode=0):
            return patch.object(workflow.GitHub, "gh", return_value=subprocess.CompletedProcess([], returncode, stdout, b""))
        with gh(b"synthetic-owner/one\nSynthetic-Owner/two\n") as call:
            self.assertEqual(workflow.GITHUB.repositories("synthetic-owner", 5), ["synthetic-owner/one", "Synthetic-Owner/two"])
        self.assertEqual(call.call_args.args[:4], (5, "repo", "list", "synthetic-owner"))
        for stdout, returncode, reason in ((b"other-owner/one\n", 0, "github-unreadable"), (b"synthetic-owner/../x\n", 0, "github-unreadable"),
                                           (b"", 1, "github-unreadable"),
                                           ("".join(f"synthetic-owner/r{i}\n" for i in range(1000)).encode(), 0, "survey-limit")):
            with self.subTest(reason=reason, returncode=returncode), gh(stdout, returncode):
                with self.assertRaisesRegex(rc.AuditError, reason):
                    workflow.GITHUB.repositories("synthetic-owner", 5)


if __name__ == "__main__":
    unittest.main()
