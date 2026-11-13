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
import release_workflow as workflow
from tests import test_release_check as fixtures


class PublishedTargetTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        self.repo = self.testbed.repo
        self.remote = self.testbed.root / "published.git"
        rc.git(self.repo, "clone", "--bare", str(self.repo), str(self.remote))
        self.head = self.testbed.git("rev-parse", "HEAD").decode().strip()
        self.tree = self.testbed.git("rev-parse", "HEAD^{tree}").decode().strip()
        self.reports = self.testbed.root / "final-reports"

    def argv(self, *extra):
        return [str(self.repo), "--denylist", str(self.testbed.denylist),
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
            self.testbed.git("add", "latest.txt")
        self.testbed.git("commit", "-q", "--allow-empty", "-m", "New published export")
        head = self.testbed.git("rev-parse", "HEAD").decode().strip()
        self.testbed.git("push", str(self.remote), "HEAD:refs/heads/main")
        self.testbed.git("checkout", "-q", "--detach", self.head)
        return head

    def test_stale_export_is_rejected_before_scan_even_with_cached_ref(self):
        latest = self.advance_remote()
        self.assertNotEqual(latest, self.head)
        self.testbed.git("update-ref", "refs/remotes/published/main", self.head)
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
            (self.testbed.root / "unavailable.git", "refs/heads/main", "published-ref-unavailable"),
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
                self.testbed.git("update-index", flag, "README.md")
                (self.repo / "README.md").write_text("Uncommitted content.\n")
                self.assertEqual(self.testbed.git("status", "--porcelain"), b"")
                with patch.object(rc, "audit") as audit:
                    self.assert_incomplete(self.cli(), "published-target-dirty")
                audit.assert_not_called()
                (self.repo / "README.md").write_bytes(original)
                self.testbed.git("update-index", flag.replace("--", "--no-", 1), "README.md")

    def test_replacement_refs_cannot_hide_published_content(self):
        safe = self.head
        (self.repo / "published.txt").write_text("Actual published content.\n")
        self.testbed.commit("Publish a different tree")
        self.testbed.git("push", str(self.remote), "HEAD:refs/heads/main")
        published = self.testbed.git("rev-parse", "HEAD").decode().strip()
        self.testbed.git("replace", published, safe)
        self.testbed.git("read-tree", "--reset", "-u", "HEAD")
        self.assertEqual(self.testbed.git("status", "--porcelain"), b"")
        self.assertFalse((self.repo / "published.txt").exists())
        with patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.cli(), "published-target-replacements")
        audit.assert_not_called()

    def test_grafts_cannot_hide_published_parent_history(self):
        self.testbed.git("commit", "-q", "--allow-empty", "-m", "Published child")
        self.testbed.git("push", str(self.remote), "HEAD:refs/heads/main")
        published = self.testbed.git("rev-parse", "HEAD").decode().strip()
        (self.repo / ".git/info/grafts").write_text(published + "\n")
        self.assertEqual(self.testbed.git("status", "--porcelain"), b"")
        self.assertEqual(self.testbed.git("rev-list", "--count", "HEAD").strip(), b"1")
        self.assertEqual(rc.git(self.remote, "rev-list", "--count", "refs/heads/main").strip(), b"2")
        with patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.cli(), "published-target-grafts")
        audit.assert_not_called()

    def test_filemode_config_cannot_hide_executable_change(self):
        self.testbed.git("config", "core.filemode", "false")
        path = self.repo / "README.md"
        path.chmod(path.stat().st_mode | 0o111)
        self.assertEqual(self.testbed.git("status", "--porcelain"), b"")
        with patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.cli(), "published-target-dirty")
        audit.assert_not_called()

    def test_published_target_always_runs_static_checks_without_cache(self):
        workflow.preflight(self.repo, self.testbed.manifest, self.testbed.terms, [], use_cache=True)
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
                                   "inventory": rc.inventory_digest(self.repo), "tags": []})
        report = json.loads((self.reports / summary["report"]).read_text())
        self.assertEqual(report["published_target"], binding)
        self.assertEqual(report["verification"]["status"], "pass")
        self.assertEqual(result.stderr, "")
        self.assertNotIn(str(self.remote), result.stdout)

    def test_unavailable_remote_real_cli_is_private_and_incomplete(self):
        result = subprocess.run([sys.executable, "-B", rc.__file__, *self.argv(
            "--published-target", str(self.testbed.root / "HiddenPerson.git"), "refs/heads/main")],
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
            self.testbed.git("config", "testbed.changed", "true")
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

    def test_github_managed_pull_refs_pass_both_guards(self):
        git = rc.git
        target = "https://github.com/example/project.git"

        def read(repo, *args, **kwargs):
            return target.encode() + b"\n" if "--get-url" in args else git(repo, *(str(self.remote) if arg == target else arg for arg in args), **kwargs)

        for ref in ("refs/pull/1/head", "refs/pull/2/merge"):
            with self.subTest(ref=ref):
                self.testbed.git("push", str(self.remote), self.unexported_commit() + ":" + ref)
                with patch.object(rc, "git", side_effect=read):
                    code, out, err = self.cli("--published-target", target, "refs/heads/main")
                self.assertEqual(code, 0, out + err)
                self.assertEqual(json.loads(out)["outcome"], "PASS")
                with patch.object(rc, "git", side_effect=read):
                    self.assertEqual(workflow.public_head(self.repo, target, "refs/heads/main", 30, False), self.head)

    def test_pull_refs_on_other_targets_are_rejected(self):
        git = rc.git
        for ref in ("refs/pull/1/head", "refs/pull/2/merge"):
            self.testbed.git("push", str(self.remote), self.unexported_commit() + ":" + ref)
        for target in (str(self.remote), "https://gitlab.com/example/project.git", "https://github.com.evil.example/a/b", 'https://github.com' '@evil.example/a/b'):
            def read(repo, *args, **kwargs):
                return target.encode() + b"\n" if "--get-url" in args else git(repo, *(str(self.remote) if arg == target else arg for arg in args), **kwargs)

            with self.subTest(target=target), patch.object(rc, "git", side_effect=read):
                self.assertEqual(workflow.public_head(self.repo, target, "refs/heads/main", 30, False), self.head)
                code, out, err = self.cli("--published-target", target, "refs/heads/main")
                self.assertEqual(code, 1, out + err)
                self.assertEqual(json.loads(err)["error"], "published-extra-refs")

    def test_other_target_rewritten_to_github_rejects_pull_refs(self):
        git = rc.git
        self.testbed.git("push", str(self.remote), self.unexported_commit() + ":refs/pull/1/head")
        for target in (str(self.remote), "https://gitlab.com/example/project.git"):
            def read(repo, *args, **kwargs):
                if "--get-url" in args:
                    return b"https://github.com/example/project.git\n"
                return git(repo, *(str(self.remote) if arg == target else arg for arg in args), **kwargs)

            with self.subTest(target=target), patch.object(rc, "git", side_effect=read):
                self.assertEqual(workflow.public_head(self.repo, target, "refs/heads/main", 30, False), self.head)
                code, out, err = self.cli("--published-target", target, "refs/heads/main")
                self.assertEqual(code, 1, out + err)
                self.assertEqual(json.loads(err)["error"], "published-extra-refs")

    def test_github_url_rewritten_to_local_target_rejects_pull_refs(self):
        target = "https://github.com/example/project.git"
        self.testbed.git("push", str(self.remote), self.unexported_commit() + ":refs/pull/1/head")
        self.testbed.git("config", "url." + str(self.remote) + ".insteadOf", target)
        self.assertEqual(workflow.public_head(self.repo, target, "refs/heads/main", 30, False), self.head)
        code, out, err = self.cli("--published-target", target, "refs/heads/main")
        self.assertEqual(code, 1, out + err)
        self.assertEqual(json.loads(err)["error"], "published-extra-refs")

    def github_gate(self, response, exit_code=0, rewritten=False):
        bin_dir = self.testbed.root / "fake-bin"
        bin_dir.mkdir(exist_ok=True)
        calls = self.testbed.root / "gh-calls"
        (bin_dir / "response.json").write_text(response if isinstance(response, str) else json.dumps(response))
        (bin_dir / "gh").write_text('#!/bin/sh\necho "$@" >> %s\ncat %s\nexit %d\n'
                                    % (calls, bin_dir / "response.json", exit_code))
        (bin_dir / "gh").chmod(0o700)
        target = "https://github.com/example/project.git"
        git = rc.git

        def read(repo, *args, **kwargs):
            return target.encode() + b"\n" if "--get-url" in args else git(repo, *(str(self.remote) if arg == target else arg for arg in args), **kwargs)

        if rewritten:
            self.testbed.git("config", "url." + str(self.remote) + ".insteadOf", target)
        with patch.dict("os.environ", {"PATH": str(bin_dir) + os.pathsep + os.environ["PATH"]}), \
                patch.object(rc, "git", side_effect=git if rewritten else read):
            code, out, err = self.cli("--published-target", target, "refs/heads/main")
        self.assertEqual((code, err), (0, ""), out + err)
        summary = json.loads(out)
        self.assertEqual(summary["outcome"], "PASS")
        if rewritten:
            self.assertFalse(calls.exists())
        else:
            self.assertEqual(calls.read_text(), "api --hostname github.com --method GET repos/example/project\n")
        report = json.loads((self.reports / summary["report"]).read_text())
        self.assertEqual(report["github_settings"], summary["github_settings"])
        return summary["github_settings"]

    def test_github_target_reports_enabled_security_settings_without_warnings(self):
        settings = {name: {"status": "enabled"} for name in rc.GITHUB_SECURITY_SETTINGS}
        self.assertEqual(self.github_gate({"security_and_analysis": settings}),
                         {"settings": {name: "enabled" for name in rc.GITHUB_SECURITY_SETTINGS}, "warnings": []})

    def test_github_target_warns_about_disabled_security_settings_without_changing_the_outcome(self):
        settings = {name: {"status": "disabled"} for name in rc.GITHUB_SECURITY_SETTINGS}
        settings["secret_scanning"] = {"status": "enabled"}
        block = self.github_gate({"security_and_analysis": settings})
        self.assertEqual(block["settings"]["secret_scanning"], "enabled")
        self.assertEqual(block["warnings"], [name + " is disabled" for name in rc.GITHUB_SECURITY_SETTINGS
                                             if name != "secret_scanning"])

    def test_recorded_github_response_reports_every_setting(self):
        recorded = {"security_and_analysis": {
            "dependabot_security_updates": {"status": "disabled"}, "secret_scanning": {"status": "disabled"},
            "secret_scanning_non_provider_patterns": {"status": "disabled"},
            "secret_scanning_push_protection": {"status": "disabled"},
            "secret_scanning_validity_checks": {"status": "disabled"}}}
        self.assertEqual(self.github_gate(recorded),
                         {"settings": {name: "disabled" for name in rc.GITHUB_SECURITY_SETTINGS},
                          "warnings": [name + " is disabled" for name in rc.GITHUB_SECURITY_SETTINGS]})

    def test_rewritten_github_target_is_not_queried(self):
        settings = {name: {"status": "enabled"} for name in rc.GITHUB_SECURITY_SETTINGS}
        self.assertEqual(self.github_gate({"security_and_analysis": settings}, rewritten=True),
                         {"warnings": ["repository security settings are unreadable with gh api; check them on GitHub"]})

    def test_settings_github_omits_are_reported_absent(self):
        block = self.github_gate({"security_and_analysis": {"secret_scanning": {"status": "enabled"}}})
        self.assertEqual(block["warnings"], [name + " is absent" for name in rc.GITHUB_SECURITY_SETTINGS
                                             if name != "secret_scanning"])

    def test_unreadable_github_settings_warn_without_changing_the_outcome(self):
        for response, exit_code in (({"message": "Not Found"}, 1), ({"name": "project"}, 0),
                                    ({"security_and_analysis": {"secret_scanning": {"status": "on"}}}, 0),
                                    ({"security_and_analysis": {"secret_scanning": "enabled"}}, 0),
                                    ({"security_and_analysis": {"secret_scanning": None}}, 0),
                                    ("[" * 100000 + "]" * 100000, 0)):
            with self.subTest(response=response):
                block = self.github_gate(response, exit_code)
                (self.testbed.root / "gh-calls").unlink()
                self.assertEqual(block, {"warnings": ["repository security settings are unreadable with gh api; "
                                                      "check them on GitHub"]})

    def test_non_github_target_has_no_settings_block(self):
        code, out, err = self.cli()
        self.assertEqual(code, 0, out + err)
        self.assertNotIn("github_settings", json.loads(out))

    def test_final_gate_carries_the_settings_block(self):
        block = {"settings": {"secret_scanning": "disabled"}, "warnings": ["secret_scanning is disabled"]}

        def gate(argv):
            print(json.dumps({"outcome": "PASS", "report": "r/report.json", "github_settings": block}))
            return 0

        args = workflow.argparse.Namespace(ref="refs/heads/main", timeout=30, use_git_credentials=False,
                                           denylist=self.testbed.denylist, private_repo=[])
        with patch.object(rc, "git"), patch.object(rc, "main", side_effect=gate):
            result = workflow.final_gate(args, self.testbed.root, "https://github.com/example/project",
                                         self.testbed.root / "manifest.json", self.head, self.tree)
        self.assertEqual(result, {"outcome": "PASS", "report": "r/report.json", "github_settings": block})

    def test_pull_refs_preserve_head_and_extra_ref_rejection(self):
        git = rc.git
        target = "https://github.com/example/project.git"

        def read(repo, *args, **kwargs):
            return target.encode() + b"\n" if "--get-url" in args else git(repo, *(str(self.remote) if arg == target else arg for arg in args), **kwargs)

        with patch.object(rc, "git", side_effect=read):
            private = self.unexported_commit()
            self.testbed.git("push", str(self.remote), private + ":refs/pull/1/head")
            for ref in ("refs/heads/extra", "refs/tags/extra", "refs/pull/1/other", "refs/pull/x/head", "refs/other/head"):
                with self.subTest(ref=ref):
                    rc.git(self.remote, "update-ref", ref, private)
                    self.assertEqual(workflow.public_head(self.repo, target, "refs/heads/main", 30, False), self.head)
                    code, out, err = self.cli("--published-target", target, "refs/heads/main")
                    self.assertEqual(code, 1, out + err)
                    self.assertEqual(json.loads(err)["error"], "published-extra-refs")
                    rc.git(self.remote, "update-ref", "-d", ref)
            rc.git(self.remote, "update-ref", "--no-deref", "HEAD", private)
            self.assertEqual(workflow.public_head(self.repo, target, "refs/heads/main", 30, False), self.head)
            code, out, err = self.cli("--published-target", target, "refs/heads/main")
            self.assertEqual(code, 1, out + err)
            self.assertEqual(json.loads(err)["error"], "published-extra-refs")

    def unexported_commit(self):
        return self.testbed.git("commit-tree", self.tree, "-p", self.head, "-m", "Unexported private work").decode().strip()

    def test_side_branch_or_tag_on_target_fails_real_cli_before_scan(self):
        for ref in ("refs/heads/wip-private-history", "refs/tags/private"):
            with self.subTest(ref=ref):
                self.testbed.git("push", str(self.remote), self.unexported_commit() + ":" + ref)
                result = subprocess.run([sys.executable, "-B", rc.__file__, *self.argv()],
                                        capture_output=True, text=True)
                rc.git(self.remote, "update-ref", "-d", ref)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(json.loads(result.stderr),
                                 {"outcome": "FAIL", "ready": False, "error": "published-extra-refs"})
                self.assertFalse(self.reports.exists())

    def test_release_tag_at_published_head_passes_real_cli_and_is_reported(self):
        self.testbed.git("push", str(self.remote), self.head + ":refs/tags/v0.2.0")
        result = subprocess.run([sys.executable, "-B", rc.__file__, *self.argv()], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["outcome"], "PASS")
        self.assertEqual(summary["published_target"]["tags"], ["refs/tags/v0.2.0"])

    def test_other_extra_refs_still_fail_with_a_release_tag(self):
        self.testbed.git("push", str(self.remote), self.head + ":refs/tags/v0.2.0")
        self.testbed.git("tag", "-a", "-m", "Annotated release", "annotated", self.head)
        for ref, source in (("refs/tags/private", self.unexported_commit()), ("refs/heads/release", self.head),
                            ("refs/tags/annotated", "refs/tags/annotated"), ("refs/tags/HiddenPerson", self.head)):
            with self.subTest(ref=ref):
                self.testbed.git("push", str(self.remote), source + ":" + ref)
                code, out, err = self.cli()
                rc.git(self.remote, "update-ref", "-d", ref)
                self.assertEqual(code, 1, out + err)
                self.assertEqual(json.loads(err)["error"], "published-extra-refs")
                self.assertNotIn("HiddenPerson", out + err)

    def test_older_release_tag_on_published_history_passes_real_cli(self):
        self.testbed.git("push", str(self.remote), self.head + ":refs/tags/v0.2.0")
        latest = self.advance_remote()
        self.testbed.git("checkout", "-q", "--detach", latest)
        result = subprocess.run([sys.executable, "-B", rc.__file__, *self.argv()], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(summary["outcome"], "PASS")
        self.assertEqual(summary["published_target"]["head"], latest)
        self.assertEqual(summary["published_target"]["tags"], ["refs/tags/v0.2.0"])

    def test_tags_off_published_history_annotated_or_private_still_fail_after_a_release(self):
        latest = self.advance_remote()
        self.testbed.git("checkout", "-q", "--detach", latest)
        self.testbed.git("tag", "-a", "-m", "Annotated release", "annotated", self.head)
        for ref, source in (("refs/tags/private", self.unexported_commit()), ("refs/heads/release", self.head),
                            ("refs/tags/annotated", "refs/tags/annotated"), ("refs/tags/HiddenPerson", self.head)):
            with self.subTest(ref=ref):
                self.testbed.git("push", str(self.remote), source + ":" + ref)
                code, out, err = self.cli()
                rc.git(self.remote, "update-ref", "-d", ref)
                self.assertEqual(code, 1, out + err)
                self.assertEqual(json.loads(err)["error"], "published-extra-refs")
                self.assertNotIn("HiddenPerson", out + err)

    def test_detached_target_head_at_private_history_fails_real_cli_before_scan(self):
        rc.git(self.remote, "update-ref", "--no-deref", "HEAD", fixtures.private_root_commit(self.remote))
        clone = self.testbed.root / "branch-clone"
        rc.git(self.repo, "clone", "-q", "--branch", "main", str(self.remote), str(clone))
        argv = [str(clone), *self.argv()[1:]]
        result = subprocess.run([sys.executable, "-B", rc.__file__, *argv], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(json.loads(result.stderr), {"outcome": "FAIL", "ready": False, "error": "published-extra-refs"})
        self.assertFalse(self.reports.exists())

    def test_target_head_detached_during_scan_fails(self):
        audit = rc.audit
        private = fixtures.private_root_commit(self.remote)

        def scan_then_detach_head(*args, **kwargs):
            report = audit(*args, **kwargs)
            rc.git(self.remote, "update-ref", "--no-deref", "HEAD", private)
            return report

        self.assertEqual(rc.git(self.remote, "symbolic-ref", "HEAD").decode().strip(), "refs/heads/main")
        with patch.object(rc, "audit", side_effect=scan_then_detach_head), patch.object(rc, "verify", return_value={
            "status": "pass", "commands": [], "dependencies": {"blocked": 0}
        }):
            code, out, err = self.cli()
        self.assertEqual(code, 1, out + err)
        self.assertEqual(json.loads(err), {"outcome": "FAIL", "ready": False, "error": "published-extra-refs"})
        self.assertFalse(json.loads(next(self.reports.rglob("report.json")).read_text())["ready"])

    def test_extra_ref_pushed_during_scan_fails(self):
        audit = rc.audit
        private = self.unexported_commit()

        def scan_then_push_side_branch(*args, **kwargs):
            report = audit(*args, **kwargs)
            self.testbed.git("push", str(self.remote), private + ":refs/heads/wip-private-history")
            return report

        with patch.object(rc, "audit", side_effect=scan_then_push_side_branch), patch.object(rc, "verify", return_value={
            "status": "pass", "commands": [], "dependencies": {"blocked": 0}
        }):
            code, out, err = self.cli()
        self.assertEqual(code, 1, out + err)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err), {"outcome": "FAIL", "ready": False, "error": "published-extra-refs"})
        report = json.loads(next(self.reports.rglob("report.json")).read_text())
        self.assertFalse(report["ready"])

    def test_matching_head_does_not_bypass_scan_findings(self):
        (self.repo / "blocked.txt").write_text("HiddenPerson\n")
        self.testbed.commit("Synthetic finding")
        self.testbed.git("push", str(self.remote), "HEAD:refs/heads/main")
        with patch.object(rc, "verify", return_value={
            "status": "pass", "commands": [], "dependencies": {"blocked": 0}
        }):
            code, out, err = self.cli()
        self.assertEqual(code, 1, out + err)
        self.assertEqual(json.loads(out)["outcome"], "FAIL")
        report = json.loads(next(self.reports.rglob("report.json")).read_text())
        self.assertIn("denylist", report["reasons"])

    def bound(self, head, tree, *extra):
        try:
            return self.cli("--expected-export", head, tree, *extra)
        except SystemExit as exit:
            self.fail("--expected-export is not accepted (exit %s)" % exit.code)

    def assert_receipt_mismatch(self, result):
        code, out, err = result
        self.assertEqual((code, out), (1, ""), err)
        failure = json.loads(err)
        self.assertEqual((failure["outcome"], failure["ready"], failure["error"]), ("FAIL", False, "published-receipt-mismatch"))
        self.assertFalse(any(json.loads(r.read_text())["outcome"] == "PASS" for r in self.reports.rglob("report.json")))

    def test_expected_export_matching_the_target_passes_and_records_it(self):
        with patch.object(rc, "verify", return_value={"status": "pass", "commands": [], "dependencies": {"blocked": 0}}):
            code, out, err = self.bound(self.head, self.tree)
        self.assertEqual(code, 0, out + err)
        summary = json.loads(out)
        self.assertEqual((summary["outcome"], summary["published_target"]["head"], summary["published_target"]["tree"]),
                         ("PASS", self.head, self.tree))

    def test_expected_export_rejects_another_commit_or_tree_before_scan(self):
        other = "0" * 40
        for head, tree in ((other, self.tree), (self.head, other), (other, other)):
            with self.subTest(head=head, tree=tree), patch.object(rc, "audit") as audit:
                self.assert_receipt_mismatch(self.bound(head, tree))
            audit.assert_not_called()
        self.assertFalse(self.reports.exists())
        without_target = [str(self.repo), "--denylist", str(self.testbed.denylist), "--reports", str(self.reports),
                          "--verify", "--expected-export", self.head, self.tree]
        result = subprocess.run([sys.executable, "-B", rc.__file__, *without_target], capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout), (2, ""), result.stderr)
        self.assertIn('"error":"invalid-arguments"', result.stderr)
        self.assertFalse(self.reports.exists())

    def test_same_tree_at_a_replacement_commit_cannot_pass_as_the_signed_export(self):
        latest = self.advance_remote(same_tree=True)
        self.testbed.git("checkout", "-q", "--detach", latest)
        self.assertEqual(self.testbed.git("rev-parse", "HEAD^{tree}").decode().strip(), self.tree)
        with patch.object(rc, "audit") as audit:
            self.assert_receipt_mismatch(self.bound(self.head, self.tree))
        audit.assert_not_called()

    def test_malformed_expected_export_is_incomplete_before_scan(self):
        for head, tree in ((self.head.upper(), self.tree), (self.head, self.tree[:39]), (self.head, "z" * 40),
                           (self.head + "\n", self.tree), ("", self.tree)):
            with self.subTest(head=head, tree=tree), patch.object(rc, "audit") as audit:
                self.assert_incomplete(self.bound(head, tree), "published-target-invalid")
            audit.assert_not_called()

    def test_expected_export_unavailable_or_moving_target_cannot_pass(self):
        with patch.object(rc, "audit") as audit:
            self.assert_incomplete(self.bound(self.head, self.tree, "--published-target",
                                              str(self.testbed.root / "unavailable.git"), "refs/heads/main"),
                                   "published-ref-unavailable")
        audit.assert_not_called()
        audit = rc.audit

        def scan_then_move(*args, **kwargs):
            report = audit(*args, **kwargs)
            self.advance_remote()
            return report

        with patch.object(rc, "audit", side_effect=scan_then_move), patch.object(rc, "verify", return_value={
            "status": "pass", "commands": [], "dependencies": {"blocked": 0}
        }):
            self.assert_incomplete(self.bound(self.head, self.tree), "published-target-stale")

    def test_guard_requires_verification_and_cannot_export_or_validate_old_receipt(self):
        without_verify = self.argv()
        without_verify.remove("--verify")
        for argv in (without_verify,
                     self.argv("--export", str(self.testbed.root / "new-export")),
                     self.argv("--validate-receipt", str(self.testbed.root / "old.json"), str(self.repo))):
            with self.subTest(argv=argv), patch.object(rc, "audit") as audit:
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    rc.main(argv)
                self.assertEqual(raised.exception.code, 2)
            audit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
