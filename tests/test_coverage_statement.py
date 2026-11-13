from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_check as rc


class CoverageStatementTests(unittest.TestCase):
    def setUp(self):
        tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(tempdir.cleanup)
        self.root = Path(tempdir.name)
        self.repo = self.root / "repo"
        (self.repo / "notes").mkdir(parents=True)
        self.denylist = self.root / "terms.json"
        self.denylist.write_text(json.dumps(["HiddenPerson"]))
        shutil.copyfile(Path(rc.__file__).with_name("LICENSE"), self.repo / "LICENSE")
        (self.repo / "README.md").write_text("# Testbed\n## Limitations\nSynthetic only.\n")
        (self.repo / ".env").write_text("testbed settings\n")
        (self.repo / "notes/draft.txt").write_text("draft\n")
        (self.repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        (self.repo / "extra.txt").write_text("extra\n")
        self.manifest = {"exclude": ["notes"], "approvals": [], "quickstart": [], "checks": []}
        (self.repo / "release-check.json").write_text(json.dumps(self.manifest))
        self.git("init", "-q", "-b", "main")
        self.git("add", "-A")
        self.git("-c", "user.name=Testbed", "-c", "user.email=testbed", "commit", "-q", "-m", "Testbed")
        self.git("branch", "side")

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True)

    def test_report_states_coverage_exclusions_media_and_refs(self):
        allowlist = ["LICENSE", "README.md", "logo.png", "release-check.json"]
        report = rc.audit(self.repo, ["HiddenPerson"], self.manifest, [], False, self.root, 30, allowlist=allowlist)
        coverage = report["coverage"]
        self.assertEqual(set(coverage), {"categories", "excluded_paths", "media_pending_review", "history_refs", "residual_risk"})
        statuses = {c["category"]: c["status"] for c in coverage["categories"]}
        self.assertEqual(statuses["application security"], "not run")
        self.assertEqual(statuses["OCR"], "not supported")
        self.assertEqual(statuses["secrets"], "checked")
        self.assertEqual(statuses["verification"], "not run")
        self.assertEqual(coverage["excluded_paths"], {"default": [".env"], "manifest": ["notes/draft.txt"], "allowlist": ["extra.txt"]})
        self.assertIn({"scope": "tree", "path": "logo.png"}, coverage["media_pending_review"])
        self.assertEqual(coverage["history_refs"], ["refs/heads/main", "refs/heads/side", "HEAD", "reflogs"])

    def test_requested_verification_that_runs_nothing_is_not_checked(self):
        report = rc.audit(self.repo, ["HiddenPerson"], self.manifest, [], True, self.root, 30)
        statuses = {c["category"]: c["status"] for c in report["coverage"]["categories"]}
        self.assertEqual((statuses["verification"], statuses["dependencies"]), ("not run", "not run"))

    def test_verification_that_stopped_early_is_failed_not_checked(self):
        stopped = {"status": "blocked", "commands": [{"role": "quickstart", "exit": 1}], "dependencies": None}
        with patch.object(rc, "verify", return_value=stopped):
            report = rc.audit(self.repo, ["HiddenPerson"], self.manifest, [], True, self.root, 30)
        statuses = {c["category"]: c["status"] for c in report["coverage"]["categories"]}
        self.assertEqual(statuses["verification"], "failed")

    def test_legacy_export_keeps_source_manifest_exclusions(self):
        manifest = {**self.manifest, "exclude": ["notes", "release-check.json"]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.git("-c", "user.name=Testbed", "-c", "user.email=testbed", "commit", "-qam", "Exclude the manifest")
        reports = self.root / "reports"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc.main([str(self.repo), "--denylist", str(self.denylist), "--reports", str(reports), "--export", str(self.root / "export")])
        excluded = json.loads(next(reports.rglob("report.json")).read_text())["export"]["coverage"]["excluded_paths"]
        self.assertEqual(excluded["manifest"], ["notes/draft.txt", "release-check.json"])

    def test_unresolved_coverage_gap_makes_secret_and_personal_scans_incomplete(self):
        (self.repo / "link").symlink_to("README.md")
        report = rc.audit(self.repo, ["HiddenPerson"], self.manifest, [], False, self.root, 30)
        statuses = {c["category"]: c["status"] for c in report["coverage"]["categories"]}
        self.assertEqual((statuses["secrets"], statuses["personal data"]), ("incomplete", "incomplete"))

    def test_allowlisted_file_is_never_reported_as_excluded(self):
        allowlist = ["LICENSE", "README.md", "notes/draft.txt"]
        report = rc.audit(self.repo, ["HiddenPerson"], self.manifest, [], False, self.root, 30, allowlist=allowlist)
        excluded = report["coverage"]["excluded_paths"]
        self.assertNotIn("notes/draft.txt", excluded["manifest"] + excluded["allowlist"])

    def test_incomplete_audit_report_still_has_coverage(self):
        reports = self.root / "reports"
        with patch.object(rc.Scanner, "tree", side_effect=OSError("boom")), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(rc.main([str(self.repo), "--denylist", str(self.denylist), "--reports", str(reports)]), 2)
        coverage = json.loads(next(reports.rglob("report.json")).read_text())["coverage"]
        self.assertEqual(set(coverage), {"categories", "excluded_paths", "media_pending_review", "history_refs", "residual_risk"})
        self.assertEqual(coverage["categories"][0]["status"], "not run")
        self.assertIn("## Coverage", next(reports.rglob("report.md")).read_text())

    def test_markdown_report_renders_coverage(self):
        reports = self.root / "reports"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc.main([str(self.repo), "--denylist", str(self.denylist), "--reports", str(reports)])
        markdown = next(reports.rglob("report.md")).read_text()
        self.assertIn("## Coverage", markdown)
        self.assertIn("| application security | not run |", markdown)
        self.assertIn("| OCR | not supported |", markdown)
        self.assertIn("Excluded by default rules: .env", markdown)
        self.assertIn("Excluded by release-check.json: notes/draft.txt", markdown)
        self.assertIn("Media pending review: history logo.png, tree logo.png", markdown)
        self.assertIn("History refs scanned: refs/heads/main, refs/heads/side, HEAD, reflogs", markdown)


if __name__ == "__main__":
    unittest.main()
