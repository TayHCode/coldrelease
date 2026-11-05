from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
from tests import test_release_check as fixtures


class PublishedTargetTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.repo = self.fixture.repo
        self.remote = self.fixture.root / "published.git"
        rc.git(self.repo, "clone", "--bare", str(self.repo), str(self.remote))
        self.head = self.fixture.git("rev-parse", "HEAD").decode().strip()
        self.tree = self.fixture.git("rev-parse", "HEAD^{tree}").decode().strip()
        self.reports = self.fixture.root / "final-reports"

    def argv(self, *extra):
        return [str(self.repo), "--denylist", str(self.fixture.denylist),
                "--reports", str(self.reports), "--verify", "--published-target",
                str(self.remote), "refs/heads/main", *extra]

    def cli(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = rc.main(self.argv(*extra))
        return code, out.getvalue(), err.getvalue()

    def assert_incomplete(self, result, reason):
        code, out, err = result
        self.assertEqual(code, 2, out + err)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err), {"outcome": "INCOMPLETE", "ready": False, "error": reason})
        for report in self.reports.rglob("report.json"):
            self.assertEqual(json.loads(report.read_text())["outcome"], "INCOMPLETE")

    def advance_remote(self, *, same_tree=False):
        if not same_tree:
            (self.repo / "latest.txt").write_text("Latest published content.\n")
            self.fixture.git("add", "latest.txt")
        self.fixture.git("commit", "-q", "--allow-empty", "-m", "New published export")
        head = self.fixture.git("rev-parse", "HEAD").decode().strip()
        self.fixture.git("push", str(self.remote), "HEAD:refs/heads/main")
        self.fixture.git("checkout", "-q", "--detach", self.head)
        return head

    def test_stale_export_is_rejected_before_scan_even_with_cached_ref(self):
        latest = self.advance_remote()
        self.assertNotEqual(latest, self.head)
        self.fixture.git("update-ref", "refs/remotes/published/main", self.head)
        with patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.cli(), "published-target-stale")
        audit.assert_not_called()
        self.assertFalse(self.reports.exists())

    def test_same_tree_at_a_different_published_commit_is_stale(self):
        latest = self.advance_remote(same_tree=True)
        self.assertEqual(rc.git(self.remote, "rev-parse", latest + "^{tree}").decode().strip(), self.tree)
        with patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.cli(), "published-target-stale")
        audit.assert_not_called()

    def test_missing_unavailable_and_invalid_refs_fail_before_scan(self):
        for target, ref, reason in (
            (self.remote, "refs/heads/missing", "published-ref-missing"),
            (self.fixture.root / "unavailable.git", "refs/heads/main", "published-ref-unavailable"),
            (self.remote, "main", "published-target-invalid"),
            (self.remote, "refs/heads/*", "published-target-invalid"),
            (self.remote, "refs/tags/release", "published-target-invalid"),
        ):
            with self.subTest(reason=reason, ref=ref), patch.object(rc, "audit") as audit:
                self.assert_incomplete(self.cli("--published-target", str(target), ref), reason)
            audit.assert_not_called()
        self.assertFalse(self.reports.exists())

    def test_malformed_published_ref_response_cannot_pass(self):
        git = rc.git
        for response in (b"not-an-object\trefs/heads/main\n",
                         self.head.encode() + b"\trefs/heads/other\n",
                         (self.head.encode() + b"\trefs/heads/main\n") * 2):
            def read(repo, *args, **kwargs):
                return response if args[0] == "ls-remote" else git(repo, *args, **kwargs)

            with self.subTest(response=response), patch.object(rc, "git", side_effect=read), patch.object(rc, "audit") as audit:
                self.assert_incomplete(self.cli(), "published-ref-invalid")
            audit.assert_not_called()

    def test_published_ref_timeout_is_incomplete_and_uses_requested_timeout(self):
        git = rc.git

        def read(repo, *args, **kwargs):
            if args[0] == "ls-remote":
                self.assertEqual(kwargs["timeout"], 7)
                raise subprocess.TimeoutExpired("git", 7, stderr=b"HiddenPerson")
            return git(repo, *args, **kwargs)

        with patch.object(rc, "git", side_effect=read), patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.cli("--timeout", "7"), "published-ref-unavailable")
        audit.assert_not_called()

    def test_dirty_tracked_untracked_and_ignored_files_fail_before_scan(self):
        tracked = self.repo / "README.md"
        original = tracked.read_bytes()
        for path, content in ((tracked, original + b"Changed\n"),
                              (self.repo / "untracked.txt", b"Extra\n"),
                              (self.repo / "ignored.txt", b"Ignored\n")):
            with self.subTest(path=path.name):
                if path.name == "ignored.txt":
                    (self.repo / ".git/info/exclude").write_text("ignored.txt\n")
                path.write_bytes(content)
                try:
                    with patch.object(rc, "audit") as audit:
                        self.assert_incomplete(self.cli(), "published-target-dirty")
                    audit.assert_not_called()
                finally:
                    if path == tracked:
                        path.write_bytes(original)
                    else:
                        path.unlink()

    def test_subdirectory_cannot_claim_the_root_head(self):
        self.repo = self.repo / "tests"
        with patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.cli(), "published-target-not-root")
        audit.assert_not_called()

    def test_index_flags_cannot_hide_uncommitted_content(self):
        original = (self.repo / "README.md").read_bytes()
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                self.fixture.git("update-index", flag, "README.md")
                (self.repo / "README.md").write_text("Uncommitted content.\n")
                self.assertEqual(self.fixture.git("status", "--porcelain"), b"")
                with patch.object(rc, "audit") as audit:
                    self.assert_incomplete(self.cli(), "published-target-dirty")
                audit.assert_not_called()
                (self.repo / "README.md").write_bytes(original)
                self.fixture.git("update-index", flag.replace("--", "--no-", 1), "README.md")

    def test_replacement_refs_cannot_hide_published_content(self):
        safe = self.head
        (self.repo / "published.txt").write_text("Actual published content.\n")
        self.fixture.commit("Publish a different tree")
        self.fixture.git("push", str(self.remote), "HEAD:refs/heads/main")
        published = self.fixture.git("rev-parse", "HEAD").decode().strip()
        self.fixture.git("replace", published, safe)
        self.fixture.git("read-tree", "--reset", "-u", "HEAD")
        self.assertEqual(self.fixture.git("status", "--porcelain"), b"")
        self.assertFalse((self.repo / "published.txt").exists())
        with patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.cli(), "published-target-replacements")
        audit.assert_not_called()

    def test_grafts_cannot_hide_published_parent_history(self):
        self.fixture.git("commit", "-q", "--allow-empty", "-m", "Published child")
        self.fixture.git("push", str(self.remote), "HEAD:refs/heads/main")
        published = self.fixture.git("rev-parse", "HEAD").decode().strip()
        (self.repo / ".git/info/grafts").write_text(published + "\n")
        self.assertEqual(self.fixture.git("status", "--porcelain"), b"")
        self.assertEqual(self.fixture.git("rev-list", "--count", "HEAD").strip(), b"1")
        self.assertEqual(rc.git(self.remote, "rev-list", "--count", "refs/heads/main").strip(), b"2")
        with patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.cli(), "published-target-grafts")
        audit.assert_not_called()

    def test_filemode_config_cannot_hide_executable_change(self):
        self.fixture.git("config", "core.filemode", "false")
        path = self.repo / "README.md"
        path.chmod(path.stat().st_mode | 0o111)
        self.assertEqual(self.fixture.git("status", "--porcelain"), b"")
        with patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.cli(), "published-target-dirty")
        audit.assert_not_called()

    def test_published_target_always_runs_static_checks_without_cache(self):
        workflow.preflight(self.repo, self.fixture.manifest, self.fixture.terms, [], use_cache=True)
        with patch.object(workflow, "preflight_cache_key", side_effect=AssertionError("final gate used cache")):
            with patch.object(rc, "license_audit", wraps=rc.license_audit) as audit:
                with patch.object(rc, "verify", return_value={"status": "pass", "commands": []}):
                    code, output, error = self.cli()
        self.assertEqual(code, 0, output + error)
        self.assertEqual(json.loads(output)["outcome"], "PASS")
        self.assertEqual(audit.call_count, 1)

    def test_matching_published_export_passes_real_cli_and_records_binding(self):
        result = subprocess.run([sys.executable, "-B", rc.__file__, *self.argv()],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["outcome"], "PASS")
        self.assertTrue(summary["ready"])
        binding = summary["published_target"]
        self.assertEqual(binding, {"head": self.head, "tree": self.tree,
                                   "inventory": rc.inventory_digest(self.repo)})
        report = json.loads((self.reports / summary["report"]).read_text())
        self.assertEqual(report["published_target"], binding)
        self.assertEqual(report["verification"]["status"], "pass")
        self.assertEqual(result.stderr, "")
        self.assertNotIn(str(self.remote), result.stdout)

    def test_unavailable_remote_real_cli_is_private_and_incomplete(self):
        result = subprocess.run([sys.executable, "-B", rc.__file__, *self.argv(
            "--published-target", str(self.fixture.root / "HiddenPerson.git"), "refs/heads/main")],
            capture_output=True, text=True)
        self.assert_incomplete((result.returncode, result.stdout, result.stderr), "published-ref-unavailable")
        self.assertNotIn("HiddenPerson", result.stdout + result.stderr)

    def test_remote_move_during_scan_cannot_pass(self):
        audit = rc.audit

        def scan_then_move(*args, **kwargs):
            report = audit(*args, **kwargs)
            self.advance_remote()
            return report

        with patch.object(rc, "audit", side_effect=scan_then_move), patch.object(rc, "verify", return_value={
            "status": "pass", "commands": [], "dependencies": {"blocked": 0}
        }):
            self.assert_incomplete(self.cli(), "published-target-stale")
        report = json.loads(next(self.reports.rglob("report.json")).read_text())
        self.assertFalse(report["ready"])

    def test_candidate_mutation_during_scan_cannot_pass(self):
        audit = rc.audit

        def scan_then_mutate(*args, **kwargs):
            report = audit(*args, **kwargs)
            self.fixture.git("config", "fixture.changed", "true")
            return report

        with patch.object(rc, "audit", side_effect=scan_then_mutate), patch.object(rc, "verify", return_value={
            "status": "pass", "commands": [], "dependencies": {"blocked": 0}
        }):
            self.assert_incomplete(self.cli(), "published-target-mutated")

    def test_ref_disappearing_during_scan_cannot_pass(self):
        audit = rc.audit

        def scan_then_remove_ref(*args, **kwargs):
            report = audit(*args, **kwargs)
            rc.git(self.remote, "update-ref", "-d", "refs/heads/main")
            return report

        with patch.object(rc, "audit", side_effect=scan_then_remove_ref), patch.object(rc, "verify", return_value={
            "status": "pass", "commands": [], "dependencies": {"blocked": 0}
        }):
            self.assert_incomplete(self.cli(), "published-ref-missing")

    def test_matching_head_does_not_bypass_scan_findings(self):
        (self.repo / "blocked.txt").write_text("HiddenPerson\n")
        self.fixture.commit("Synthetic finding")
        self.fixture.git("push", str(self.remote), "HEAD:refs/heads/main")
        with patch.object(rc, "verify", return_value={
            "status": "pass", "commands": [], "dependencies": {"blocked": 0}
        }):
            code, out, err = self.cli()
        self.assertEqual(code, 1, out + err)
        self.assertEqual(json.loads(out)["outcome"], "FAIL")
        report = json.loads(next(self.reports.rglob("report.json")).read_text())
        self.assertIn("denylist", report["reasons"])

    def test_guard_requires_verification_and_cannot_export_or_validate_old_receipt(self):
        without_verify = self.argv()
        without_verify.remove("--verify")
        for argv in (without_verify,
                     self.argv("--export", str(self.fixture.root / "new-export")),
                     self.argv("--validate-receipt", str(self.fixture.root / "old.json"), str(self.repo))):
            with self.subTest(argv=argv), patch.object(rc, "audit") as audit:
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    rc.main(argv)
                self.assertEqual(raised.exception.code, 2)
            audit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
