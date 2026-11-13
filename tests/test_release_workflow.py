from contextlib import ExitStack, redirect_stderr, redirect_stdout
import fcntl
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile

import release_check as rc
import release_workflow as workflow
import test_release_check as fixtures


OSV_ADVISORY = {
    "schema_version": "1.6.0", "id": "GHSA-462w-v97r-4m45", "modified": "2024-09-24T21:03:59Z",
    "aliases": ["CVE-2019-10906", "PYSEC-2019-217"], "summary": "Jinja2 sandbox escape via string formatting",
    "database_specific": {"severity": "HIGH"},
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"}],
    "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]}]}],
}


def verified(*args, **kwargs):
    return {"status": "pass", "commands": [], "dependencies": {"blocked": 0}}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        self.root = self.testbed.root
        self.repo = self.testbed.repo
        self.remote = self.root / "public.git"
        self.home = self.root / "owner-home"
        (self.home / ".coldlocker").mkdir(parents=True)
        self.reference = self.home / ".coldlocker" / "release-denylist.sha256"
        self.reference.write_text(rc.sha256(self.testbed.denylist.read_bytes()) + "\n")
        environ = patch.dict(os.environ, {"HOME": str(self.home), "XDG_STATE_HOME": str(workflow.runs_root().parents[1])})
        environ.start()
        self.addCleanup(environ.stop)
        subprocess.run(["git", "init", "-q", "--bare", str(self.remote)], check=True, capture_output=True)
        self.run = workflow.run_directory(self.repo, "first")

    def cli(self, command, *extra, run="first", real=False):
        args = [command, str(self.repo), "--denylist", str(self.testbed.denylist), "--run", run, *extra]
        if real:
            process = subprocess.run([sys.executable, rc.__file__, *args], capture_output=True, text=True)
            if process.returncode != 1 and command == "approve":
                self.assertIn("Approved ", process.stderr)
            elif process.returncode != 1:
                self.assertEqual(process.stderr, "")
            else:
                self.assertIn("personal: denylist in leak.txt; remove or replace", process.stderr)
                self.assertNotIn("HiddenPerson", process.stderr)
            return process.returncode, json.loads(process.stdout)
        output = io.StringIO()
        with redirect_stdout(output):
            code = rc.main(args)
        return code, json.loads(output.getvalue())

    def assert_status(self, result, status, reason=None):
        code, value = result
        self.assertEqual(value["outcome"], status, value)
        self.assertEqual(code, {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[status], value)
        if reason:
            self.assertIn(reason, value["reasons"])
        self.assertEqual(value["notice"], workflow.NOTICE)
        return value

    def target_flags(self, target=None, ref="refs/heads/main"):
        return ["--verify", "--target", str(target or self.remote), "--ref", ref]

    def push(self, check=True, run=None):
        run = run or self.run
        return subprocess.run(workflow.push_command(run, workflow.read_json(run / "approval.json")),
                              capture_output=True, check=check)

    def export(self, scanners=("gitleaks",), run="first", fake=True):
        flags = [flag for name in scanners for flag in ("--scanner", name)]
        with ExitStack() as stack:
            if fake:
                stack.enter_context(patch.object(workflow, "scan_export", side_effect=self.passing_scan))
                stack.enter_context(patch.object(workflow.shutil, "which", return_value=None))
            self.assert_status(self.cli("plan", *flags, run=run), "PASS")
            with patch.object(rc, "verify", side_effect=verified):
                self.assert_status(self.cli("export", "--verify", run=run), "PASS")
        directory = workflow.run_directory(self.repo, run)
        return directory / "attempts" / workflow.read_json(directory / "export.json")["attempt"]

    def prepare(self):
        return self.assert_status(self.cli("approve", *self.target_flags()), "PASS")

    def remote_head(self, ref="refs/heads/main"):
        return rc.git(self.repo, "ls-remote", "--refs", str(self.remote), ref).decode().strip().split("\t")[0]

    def fake_gitleaks(self):
        folder = self.root / "scanner-bin"
        folder.mkdir()
        binary = folder / "gitleaks"
        binary.write_text('#!' + sys.executable + '\nimport pathlib, sys\nargs = sys.argv[1:]\n'
                          'if args == ["version"]:\n print("8.24.0"); sys.exit(0)\n'
                          'if args == ["git", "--help"]:\n print("--config --gitleaks-ignore-path --ignore-gitleaks-allow --redact '
                          '--no-banner --exit-code --report-format --report-path --log-opts"); sys.exit(0)\n'
                          'pathlib.Path(args[args.index("--report-path") + 1]).write_text("[]")\n')
        binary.chmod(0o700)
        return patch.dict(os.environ, {"PATH": str(folder) + os.pathsep + os.environ["PATH"]})

    def test_cli_unsafe_repaired_blocked_then_guarded_push_and_publish(self):
        self.enterContext(self.fake_gitleaks())
        leak = self.repo / "leak.txt"
        leak.write_text("Hidden" + "Person")
        self.testbed.commit("Unsafe synthetic testbed")
        self.assert_status(self.cli("preflight", real=True), "PASS")
        self.assert_status(self.cli("plan", "--scanner", "gitleaks", real=True), "PASS")
        self.assert_status(self.cli("check", "--verify", real=True), "FAIL")
        leak.write_text("Public testbed\n")
        self.testbed.commit("Repair testbed")
        self.assert_status(self.cli("check", "--verify", real=True), "PASS")
        exported = self.assert_status(self.cli("export", "--verify", real=True), "PASS")
        self.assertEqual(exported["scanners"], [{"name": "gitleaks", "outcome": "PASS"}])
        approval = self.assert_status(self.cli("approve", *self.target_flags(), real=True), "PASS")
        self.assertEqual(approval["outstanding_findings"], 0)
        self.assert_status(self.cli("publish", *self.target_flags(), real=True), "INCOMPLETE", "release-not-pushed")
        self.assertEqual(self.remote_head(), "")
        self.push()
        self.assert_status(self.cli("publish", *self.target_flags(), real=True), "PASS")
        record = workflow.read_json(self.run / "published.json")
        self.assertEqual(self.remote_head(), record["export_head"])
        self.assertEqual(rc.git(self.repo, "--git-dir=" + str(self.remote), "rev-list", "--count", record["export_head"]).strip(), b"1")
        for report in self.run.rglob("report.json"):
            self.assertNotIn("HiddenPerson", report.read_text())
        self.assertEqual(len(list(self.run.parent.iterdir())), 1)

    def test_verification_workspace_is_outside_the_source_repository(self):
        probe = "import os,subprocess,sys;sys.exit(subprocess.run(['git','-C',os.environ['TMPDIR'],'rev-parse','--show-toplevel'],capture_output=True).returncode == 0)"
        manifest = {**self.testbed.manifest, "checks": [{"role": "tests", "argv": ["python", "-c", probe]}]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.testbed.commit("Probe enclosing repository")
        self.assert_status(self.cli("plan"), "PASS")
        self.assert_status(self.cli("check", "--verify", real=True), "PASS")

    def test_check_prints_fingerprint_upgrade_hint_on_stderr(self):
        upgrade = {"kind": "npm-source-declarations-review", "path": "package.json",
                   "legacy_fingerprint": "0" * 16, "fingerprint": "1" * 16}
        real_audit = rc.audit
        def audit_with_upgrade(*args, **kwargs):
            return {**real_audit(*args, **kwargs), "fingerprint_upgrades": [upgrade]}
        with patch.object(rc, "audit", side_effect=audit_with_upgrade), patch.object(rc, "verify", side_effect=verified):
            self.assert_status(self.cli("preflight"), "PASS")
            self.assert_status(self.cli("plan"), "PASS")
            errors = io.StringIO()
            with redirect_stderr(errors):
                self.assert_status(self.cli("check", "--verify"), "PASS")
        self.assertEqual(errors.getvalue(), rc.fingerprint_upgrade_hint([{"fingerprint_upgrades": [upgrade]}]) + "\n")

    def test_final_workflow_gates_ignore_preflight_cache(self):
        with patch.dict(os.environ, {"XDG_CACHE_HOME": str(self.root / "cache")}):
            self.assert_status(self.cli("preflight"), "PASS")
            with patch.object(workflow, "preflight_cache_key", side_effect=AssertionError("final gate used cache")):
                with patch.object(rc, "verify", side_effect=verified):
                    self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")
                    self.assert_status(self.cli("check", "--verify"), "PASS")
                    with patch.object(workflow, "scan_export", side_effect=self.passing_scan):
                        self.assert_status(self.cli("export", "--verify"), "PASS")
                    self.prepare()
                    self.push()
                    self.assert_status(self.cli("publish", *self.target_flags()), "PASS")
                self.assertTrue(self.remote_head())

    def test_preflight_fails_license_and_plan_stops(self):
        (self.repo / "LICENSE").write_text("License undecided\n")
        self.assert_status(self.cli("preflight"), "FAIL")
        self.assert_status(self.cli("plan", run="blocked"), "INCOMPLETE", "preflight-not-pass")
        self.assertFalse((workflow.run_directory(self.repo, "blocked") / "public-export.txt").exists())

    def test_plan_never_grows_allowlist_and_rejects_untracked_forbidden_and_symlink(self):
        (self.repo / "AGENTS.md").write_text("Local instructions")
        self.testbed.commit("Local agent notes")
        self.assert_status(self.cli("plan"), "PASS")
        path = self.run / "public-export.txt"
        original = path.read_text()
        self.assertNotIn("AGENTS.md", original)
        (self.repo / "new.txt").write_text("Public testbed")
        self.testbed.commit("Add new public file")
        with patch.object(rc, "verify", side_effect=verified):
            value = self.assert_status(self.cli("check", "--verify"), "PASS")
        candidate = self.run / "attempts" / value["attempt"] / "export"
        self.assertFalse((candidate / "new.txt").exists())
        self.assertEqual(path.read_text(), original)
        for rel in ("AGENTS.md", "untracked.txt", "../outside"):
            path.write_text(original + rel + "\n")
            self.assert_status(self.cli("export", "--verify"), "INCOMPLETE", "allowlist-path")
        path.write_text(original)
        (self.repo / "README.md").unlink()
        (self.repo / "README.md").symlink_to(self.root / "outside")
        self.assert_status(self.cli("export", "--verify"), "INCOMPLETE", "allowlist-file")

    def test_stale_receipt_blocks_publish(self):
        attempt = self.export()
        self.prepare()
        (attempt / "export/README.md").write_text("Changed after approval")
        self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "receipt-stale")
        self.assertEqual(self.remote_head(), "")

    def test_check_and_export_refuse_uncommitted_allowlisted_changes(self):
        self.assert_status(self.cli("plan"), "PASS")
        readme = self.repo / "README.md"
        committed = readme.read_bytes()
        readme.write_bytes(committed + b"Uncommitted line\n")
        with patch.object(rc, "verify", side_effect=verified):
            self.assert_status(self.cli("check", "--verify"), "INCOMPLETE", "source-dirty")
            self.assert_status(self.cli("export", "--verify"), "INCOMPLETE", "source-dirty")
            self.testbed.git("add", "README.md")
            self.assert_status(self.cli("export", "--verify"), "INCOMPLETE", "source-dirty")
            readme.write_bytes(committed)
            self.assert_status(self.cli("export", "--verify"), "INCOMPLETE", "source-dirty")
            self.testbed.git("reset", "-q", "README.md")
            readme.chmod(0o755)
            self.assert_status(self.cli("export", "--verify"), "INCOMPLETE", "source-dirty")
            readme.chmod(0o644)
            stamped = self.repo / "stamped.txt"
            (self.repo / ".gitattributes").write_text("stamped.txt ident\n")
            stamped.write_bytes(b"$Id: committed text $\n")
            self.testbed.commit("Add an ident file")
            stamped.write_bytes(b"$Id: edited by hand $\n")
            self.assertEqual(rc.git(self.repo, "status", "--porcelain", "--untracked-files=no"), b"")
            self.assert_status(self.cli("plan", run="ident"), "PASS")
            self.assert_status(self.cli("export", "--verify", run="ident"), "INCOMPLETE", "source-dirty")
        self.assertFalse((self.run / "export.json").exists())

    def test_receipt_and_approval_bind_the_source_commit_and_exports_repeat_the_tree(self):
        first = self.export()
        with patch.object(rc, "verify", side_effect=verified), self.fake_gitleaks():
            self.assert_status(self.cli("export", "--verify"), "PASS")
        second = self.run / "attempts" / workflow.read_json(self.run / "export.json")["attempt"]
        self.assertNotEqual(first, second)
        receipts = [workflow.read_json(attempt / "receipt.json") for attempt in (first, second)]
        source = {"source_head": rc.git(self.repo, "rev-parse", "HEAD").decode().strip(),
                  "source_tree": rc.git(self.repo, "rev-parse", "HEAD^{tree}").decode().strip()}
        for receipt in receipts:
            self.assertEqual({k: receipt[k] for k in source}, source)
        self.assertEqual(receipts[0]["export_tree"], receipts[1]["export_tree"])
        self.prepare()
        record = workflow.read_json(self.run / "approval.json")
        self.assertEqual({k: record[k] for k in source}, source)
        self.push()
        self.assert_status(self.cli("publish", *self.target_flags()), "PASS")

    def latest_attempt(self, prefix):
        return max(self.run.joinpath("attempts").glob(prefix + "-*"), key=lambda path: path.stat().st_mtime_ns)

    def evidence(self, attempt):
        path = attempt / "verify-evidence.json"
        if not path.is_file():
            self.fail("the attempt has no verify-evidence.json")
        return workflow.read_json(path)

    def test_export_emits_functional_evidence_bound_to_the_export_commit(self):
        self.testbed.git("remote", "add", "origin", "https://github.com/example/project.git")
        self.assert_status(self.cli("plan"), "PASS")
        self.assert_status(self.cli("export", "--verify"), "PASS")
        attempt = self.latest_attempt("export")
        receipt = workflow.read_json(attempt / "receipt.json")
        evidence = self.evidence(attempt)
        self.assertEqual(evidence["repo"], {"name": "example/project", "commit": receipt["export_head"]})
        self.assertEqual(rc.git(attempt / "export", "rev-parse", receipt["export_head"] + "^{tree}").decode().strip(), receipt["export_tree"])
        self.assertEqual(evidence["outcome"], "pass")
        self.assertNotIn("failure", evidence)
        self.assertEqual([(s["step"], s["command"], s["status"]) for s in evidence["steps"]],
                         [("quickstart 1", "python -c 'print(1)'", "pass"),
                          ("tests 2", "python -m unittest discover -s tests -q", "pass")])
        self.assertEqual(evidence["procedure"]["commands"], [s["command"] for s in evidence["steps"]])
        self.assertEqual(evidence["artifacts"][0]["path"], "receipt.json")
        self.assertEqual(evidence["artifacts"][0]["sha256"], rc.sha256((attempt / "receipt.json").read_bytes()))

    def test_failed_check_evidence_never_claims_pass_and_leaves_the_safety_verdict_alone(self):
        self.testbed.git("remote", "add", "origin", "git@github.com:example/project.git")
        manifest = {**self.testbed.manifest, "checks": [{"role": "tests", "argv": ["python", "-c", "import sys;sys.exit(3)"]}]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.testbed.commit("Failing tests")
        self.assert_status(self.cli("plan"), "PASS")
        self.assert_status(self.cli("check", "--verify"), "FAIL")
        attempt = self.latest_attempt("check")
        evidence = self.evidence(attempt)
        self.assertEqual(evidence["outcome"], "fail")
        self.assertEqual(evidence["failure"], {"class": "product", "cause": "test_failure", "detail": "command-failed"})
        self.assertEqual(evidence["steps"][-1]["status"], "fail")
        self.assertEqual(evidence["steps"][-1]["failing_excerpt"], "exit 3")
        self.assertEqual(workflow.read_json(attempt / "receipt.json")["outcome"], "FAIL")

    def test_unverified_evidence_is_incomplete_and_unnamed_sources_write_none(self):
        self.assert_status(self.cli("plan"), "PASS")
        self.assert_status(self.cli("export", "--verify"), "PASS")
        self.assertFalse((self.latest_attempt("export") / "verify-evidence.json").exists())
        self.testbed.git("remote", "add", "origin", "https://github.com/example/project")
        with patch.object(rc, "verify", side_effect=verified):
            self.assert_status(self.cli("export", "--verify"), "PASS")
        evidence = self.evidence(self.latest_attempt("export"))
        self.assertEqual((evidence["outcome"], evidence["steps"], evidence["failure"]["cause"]), ("incomplete", [], "empty_run"))

    def test_passing_commands_with_a_post_install_block_are_not_pass_evidence(self):
        self.testbed.git("remote", "add", "origin", "https://github.com/example/project.git")
        def not_installed(repo, report_dir, scanner, manifest, timeout, **kwargs):
            scanner.add("verification", "quality", "project-not-installed", "pyproject.toml")
            return {"status": "pass", "dependencies": {"blocked": 0},
                    "commands": [{"step": 1, "role": "quickstart", "exit_code": 0, "output_fingerprint": "0"}]}
        self.assert_status(self.cli("plan"), "PASS")
        with patch.object(rc, "verify", side_effect=not_installed):
            self.cli("check", "--verify")
        evidence = self.evidence(self.latest_attempt("check"))
        self.assertEqual(evidence["outcome"], "incomplete")
        self.assertEqual(evidence["failure"], {"class": "harness", "cause": "unknown", "detail": "project-not-installed"})

    def export_path_review(self, relative, **changes):
        return {"scope": "tree", "kind": "export-path-review", "path": relative,
                "source_sha256": rc.sha256((self.repo / relative).read_bytes()),
                "reason": "Reviewed this exact synthetic public instruction file.", **changes}

    def test_export_path_review_selects_only_the_exact_file_and_expires(self):
        (self.repo / "AGENTS.md").write_text("Public product instructions\n")
        (self.repo / "CLAUDE.md").write_text("Public product instructions\n")
        manifest = {**self.testbed.manifest, "approvals": [self.export_path_review("AGENTS.md")]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.testbed.commit("Review one public instruction file")
        self.assert_status(self.cli("plan"), "PASS")
        paths = (self.run / "public-export.txt").read_text().splitlines()
        self.assertIn("AGENTS.md", paths)
        self.assertNotIn("CLAUDE.md", paths)
        (self.run / "public-export.txt").write_text("\n".join(paths + ["CLAUDE.md"]) + "\n")
        self.assert_status(self.cli("check", "--verify"), "INCOMPLETE", "allowlist-path")
        (self.run / "public-export.txt").write_text("\n".join(paths) + "\n")
        checked = self.assert_status(self.cli("check", "--verify", real=True), "PASS")
        coverage = workflow.read_json(self.run / "attempts" / checked["attempt"] / "report.json")["coverage"]
        self.assertIn("CLAUDE.md", coverage["excluded_paths"]["allowlist"])
        self.assertNotIn("AGENTS.md", coverage["excluded_paths"]["allowlist"])
        (self.repo / "AGENTS.md").write_text("Changed instructions\n")
        self.assert_status(self.cli("export", "--verify"), "INCOMPLETE", "allowlist-path")

    def test_export_path_review_rejects_globs_wrong_digests_and_missing_reasons(self):
        (self.repo / "AGENTS.md").write_text("Public product instructions\n")
        self.testbed.commit("Add public instructions")
        self.run.mkdir(parents=True)
        paths = workflow.proposed_paths(self.repo, self.testbed.manifest) + ["AGENTS.md"]
        (self.run / "public-export.txt").write_text("\n".join(paths) + "\n")
        for changes in ({"path": "AGENTS*"}, {"source_sha256": "0" * 64},
                        {"reason": ""}, {"scope": "history"}, {"source_sha256": None}):
            with self.subTest(changes=changes):
                manifest = {**self.testbed.manifest,
                            "approvals": [self.export_path_review("AGENTS.md", **changes)]}
                (self.repo / "release-check.json").write_text(json.dumps(manifest))
                self.assert_status(self.cli("plan"), "INCOMPLETE", "allowlist-path")

    def test_export_path_triage_is_applied_before_plan_check_and_approve(self):
        (self.repo / "AGENTS.md").write_text("Public product instructions\n")
        self.testbed.commit("Add public instructions")
        self.run.mkdir(parents=True)
        review = self.export_path_review("AGENTS.md")
        (self.run / "triage.json").write_text(json.dumps([
            {**review, "file_sha256": review["source_sha256"]}]))
        attempt = self.export()
        self.assertEqual((attempt / "export/AGENTS.md").read_text(), "Public product instructions\n")
        self.prepare()
        self.assertIn("AGENTS.md", workflow.read_json(self.run / "approval.json")["allowlist"])

    def test_export_path_review_never_waives_privacy_or_secrets(self):
        for number, content in enumerate(("Hidden" + "Person", "ghp_" + "a" * 30)):
            with self.subTest(number=number):
                (self.repo / "AGENTS.md").write_text(content)
                manifest = {**self.testbed.manifest, "approvals": [self.export_path_review("AGENTS.md")]}
                (self.repo / "release-check.json").write_text(json.dumps(manifest))
                self.testbed.commit("Review synthetic sensitive bytes")
                run = "sensitive" + str(number)
                self.assert_status(self.cli("plan", run=run), "PASS")
                with patch.object(rc, "verify", side_effect=verified), redirect_stderr(io.StringIO()):
                    result = self.assert_status(self.cli("check", "--verify", run=run), "FAIL")
                attempt = workflow.run_directory(self.repo, run) / "attempts" / result["attempt"]
                report = workflow.read_json(attempt / "report.json")
                self.assertTrue(any(not f["reviewed"] and f["kind"] == ("denylist" if number == 0 else "github-token")
                                    for f in report["findings"]))

    def test_export_path_review_cannot_admit_untracked_excluded_or_symlink_files(self):
        for path in ("AGENTS.md", ".env"):
            (self.repo / path).write_text("Public testbed\n")
        manifest = {**self.testbed.manifest,
                    "approvals": [self.export_path_review(path) for path in ("AGENTS.md", ".env")]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.run.mkdir(parents=True)
        original = workflow.proposed_paths(self.repo, self.testbed.manifest)
        for path in ("AGENTS.md", ".env", "../outside"):
            (self.run / "public-export.txt").write_text("\n".join(original + [path]) + "\n")
            self.assert_status(self.cli("plan"), "INCOMPLETE", "allowlist-path")
        self.testbed.commit("Track public instructions")
        (self.run / "public-export.txt").write_text("\n".join(original + [".env"]) + "\n")
        self.assert_status(self.cli("plan"), "INCOMPLETE", "allowlist-path")
        (self.run / "public-export.txt").write_text("\n".join(original + ["AGENTS.md"]) + "\n")
        (self.repo / "AGENTS.md").unlink()
        (self.repo / "AGENTS.md").symlink_to(self.repo / "README.md")
        self.assert_status(self.cli("plan"), "INCOMPLETE", "allowlist-file")

    def test_export_path_review_rechecks_the_actual_staged_bytes(self):
        (self.repo / "AGENTS.md").write_text("Reviewed public instructions\n")
        manifest = {**self.testbed.manifest, "approvals": [self.export_path_review("AGENTS.md")]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.testbed.commit("Review public instructions")
        original_copy = rc.copy_tree
        def copy_then_change(repo, target, *args, **kwargs):
            original_copy(repo, target, *args, **kwargs)
            (target / "AGENTS.md").write_text("Unreviewed replacement\n")
        with patch.object(rc, "copy_tree", side_effect=copy_then_change):
            self.assert_status(self.cli("plan"), "INCOMPLETE", "allowlist-path")

    def test_export_path_review_rejects_git_normalized_committed_bytes(self):
        (self.repo / ".gitattributes").write_text("AGENTS.md text\n")
        (self.repo / "AGENTS.md").write_bytes(b"Public instructions\r\n")
        manifest = {**self.testbed.manifest, "approvals": [self.export_path_review("AGENTS.md")]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.testbed.commit("Review source before Git normalization")
        self.assertEqual(rc.git(self.repo, "show", "HEAD:AGENTS.md"), b"Public instructions\n")
        self.assert_status(self.cli("plan"), "PASS")
        self.assert_status(self.cli("export", "--verify"), "INCOMPLETE", "allowlist-path")

    def test_approved_scanner_selection_cannot_be_removed_from_mutable_plan(self):
        attempt = self.export(("gitleaks",))
        self.prepare()
        self.push()
        (self.run / "plan.json").write_text('{"scanners":[]}')
        (attempt / "scanners.json").write_text('[]')
        self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "scanner-selection")
        self.assertFalse((self.run / "published.json").exists())

    def test_scanner_digest_and_head_must_match_the_approval(self):
        attempt = self.export(("gitleaks",))
        scanners = next(c for c in workflow.read_json(attempt / "report.json")["coverage"]["categories"]
                        if c["category"] == "external scanners")
        self.assertEqual(scanners["status"], "run after this report")
        self.assertIn("gitleaks", scanners["detail"])
        self.prepare()
        self.push()
        results = workflow.read_json(attempt / "scanners.json")
        results[0]["output_sha256"] = "b" * 64
        (attempt / "scanners.json").write_text(json.dumps(results))
        self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "approval-scanners")
        results[0]["export_head"] = "a" * 40
        (attempt / "scanners.json").write_text(json.dumps(results))
        self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "scanner-not-pass")
        self.assertFalse((self.run / "published.json").exists())

    def publish_with_listing(self, listing_text):
        self.export()
        self.prepare()
        self.push()
        listing = self.root / "listing.txt"
        if listing_text is not None:
            listing.write_text(listing_text)
        errors = io.StringIO()
        with redirect_stderr(errors):
            value = self.assert_status(self.cli("publish", *self.target_flags(), "--listing-source", str(listing)), "PASS")
        return value, errors.getvalue()

    def test_publish_reminds_when_the_repository_is_not_listed(self):
        value, errors = self.publish_with_listing("other-tool\npublic-tool\n")
        self.assertIn("Published public, but it is not in the listing source", value["reminder"])
        self.assertIn(value["reminder"], errors)

    def test_publish_is_silent_when_the_repository_is_listed(self):
        value, errors = self.publish_with_listing("other-tool\n{'slug': 'Public'}\n")
        self.assertNotIn("reminder", value)
        self.assertNotIn("listing", errors)

    def test_publish_reminds_when_the_listing_source_cannot_be_read(self):
        value, errors = self.publish_with_listing(None)
        self.assertIn("listing source could not be read", value["reminder"])
        self.assertIn(value["reminder"], errors)

    def test_target_ref_and_new_ref_lease(self):
        attempt = self.export()
        self.prepare()
        self.push()
        other = self.root / "other.git"
        subprocess.run(["git", "init", "-q", "--bare", str(other)], check=True, capture_output=True)
        self.assert_status(self.cli("publish", *self.target_flags(other)), "INCOMPLETE", "approval-target")
        self.assert_status(self.cli("publish", *self.target_flags(ref="refs/heads/other")), "INCOMPLETE", "approval-ref")
        rc.git(self.repo, "push", "--force", str(self.remote), "HEAD:refs/heads/main")
        old = self.remote_head()
        self.assert_status(self.cli("publish", *self.target_flags()), "FAIL", "target-moved")
        self.assertEqual(self.remote_head(), old)
        self.assertNotEqual(old, workflow.read_json(attempt / "receipt.json")["export_head"])

    def test_other_target_refs_do_not_block_approve_or_publish(self):
        self.export()
        for ref in ("refs/heads/ci/coldbox", "refs/heads/release-v0.1.1", "refs/tags/v0.1.1"):
            rc.git(self.repo, "push", str(self.remote), "HEAD:" + ref)
        approved = self.prepare()
        self.assertIsNone(workflow.read_json(self.run / "approval.json")["expected_public_head"])
        self.push()
        self.assertEqual(self.remote_head(), approved["release_head"])
        self.assert_status(self.cli("publish", *self.target_flags()), "PASS")

    def test_a_detached_target_head_does_not_block_approve_or_publish(self):
        private = fixtures.private_root_commit(self.remote)
        rc.git(self.remote, "update-ref", "--no-deref", "HEAD", private)
        self.export()
        self.prepare()
        self.push()
        self.assert_status(self.cli("publish", *self.target_flags()), "PASS")
        self.assertEqual(rc.git(self.repo, "ls-remote", str(self.remote), "HEAD").decode().split("\t")[0], private)

    def public_history(self, *messages):
        work = self.root / "public-work"
        if not work.exists():
            rc.git(self.root, "clone", "-q", str(self.remote), str(work))
        for message in messages:
            (work / "README.md").write_text(message + "\n")
            rc.git(work, "add", "README.md")
            rc.git(work, "-c", "user.name=Release Export", "-c", "user.email=release-export", "-c", "commit.gpgsign=false",
                   "commit", "-q", "-m", message)
        rc.git(work, "push", "-q", str(self.remote), "HEAD:refs/heads/main")
        return self.remote_head()

    def published(self):
        return workflow.read_json(self.run / "published.json")

    def remote_git(self, *args):
        return rc.git(self.repo, "--git-dir=" + str(self.remote), *args).decode().split()

    def test_publish_appends_the_export_tree_on_the_signed_public_head(self):
        old = self.public_history("Earlier public release")
        attempt = self.export()
        receipt = workflow.read_json(attempt / "receipt.json")
        self.prepare()
        self.push()
        value = self.assert_status(self.cli("publish", *self.target_flags()), "PASS")
        head = self.remote_head()
        self.assertEqual(value["published_head"], head)
        self.assertNotEqual(head, receipt["export_head"])
        self.assertEqual(self.remote_git("rev-list", "--parents", "-n", "1", head), [head, old])
        self.assertEqual(self.remote_git("rev-parse", head + "^{tree}"), [receipt["export_tree"]])
        self.assertEqual(self.published(), {"export_head": receipt["export_head"], "receipt_sha256": receipt["receipt_sha256"],
                                            "parent": old, "published_head": head})

    def test_appended_release_reaches_only_public_history(self):
        old = self.public_history("First public release", "Second public release")
        self.export()
        self.prepare()
        self.push()
        self.assert_status(self.cli("publish", *self.target_flags()), "PASS")
        public = self.remote_git("rev-list", "--all")
        self.assertEqual(public[1:], rc.git(self.root / "public-work", "rev-list", old).decode().split())
        private = self.testbed.git("rev-list", "--all").decode().split()
        self.assertTrue(private)
        self.assertFalse(set(private) & set(public))
        for commit in private:
            with self.assertRaises(rc.AuditError):
                rc.git(self.repo, "--git-dir=" + str(self.remote), "cat-file", "-e", commit)

    def test_first_publication_is_a_parentless_lease_push_and_publish_never_pushes(self):
        attempt = self.export()
        self.prepare()
        record = workflow.read_json(self.run / "approval.json")
        command = workflow.push_command(self.run, record)
        self.assertEqual(command[3:], ["push", "--force-with-lease=refs/heads/main:", "public",
                                       record["release_head"] + ":refs/heads/main"])
        self.push()
        original = rc.git
        pushes = []
        def git(repo, *args, **kwargs):
            if "push" in args:
                pushes.append(args)
            return original(repo, *args, **kwargs)
        with patch.object(rc, "git", side_effect=git):
            self.assert_status(self.cli("publish", *self.target_flags()), "PASS")
        self.assertEqual(pushes, [])
        head = workflow.read_json(attempt / "receipt.json")["export_head"]
        self.assertEqual(self.remote_head(), head)
        self.assertEqual(self.remote_git("rev-list", "--parents", head), [head])
        self.assertEqual(self.published().get("parent", "missing"), None)

    def test_a_public_head_that_moved_after_approval_stops_the_push_and_publish(self):
        self.public_history("Earlier public release")
        self.export()
        self.prepare()
        moved = self.public_history("Another public release")
        self.assertNotEqual(self.push(check=False).returncode, 0)
        self.assertEqual(self.remote_head(), moved)
        self.assert_status(self.cli("publish", *self.target_flags()), "FAIL", "target-moved")
        self.assertFalse((self.run / "published.json").exists())


    def test_publish_records_a_first_publication_and_runs_once(self):
        receipt = workflow.read_json(self.export() / "receipt.json")
        self.prepare()
        self.push()
        value = self.assert_status(self.cli("publish", *self.target_flags()), "PASS")
        self.assertEqual(value["published_head"], receipt["export_head"])
        self.assertEqual(self.published(), {"export_head": receipt["export_head"], "receipt_sha256": receipt["receipt_sha256"],
                                            "parent": None, "published_head": receipt["export_head"]})
        self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "already-published")

    def test_append_push_is_a_fast_forward_whose_only_parent_is_the_expected_head(self):
        old = self.public_history("Earlier public release")
        receipt = workflow.read_json(self.export() / "receipt.json")
        self.prepare()
        record = workflow.read_json(self.run / "approval.json")
        self.assertEqual(record["expected_public_head"], old)
        self.assertEqual(workflow.push_command(self.run, record)[4], "--force-with-lease=refs/heads/main:" + old)
        self.push()
        landed = self.remote_head()
        self.assertEqual(landed, record["release_head"])
        self.assertEqual(self.remote_git("rev-list", "--parents", "-n", "1", landed), [landed, old])
        self.assertEqual(self.remote_git("rev-parse", landed + "^{tree}"), [receipt["export_tree"]])
        self.assert_status(self.cli("publish", *self.target_flags()), "PASS")
        self.assertEqual(self.published(), {"export_head": receipt["export_head"], "receipt_sha256": receipt["receipt_sha256"],
                                            "parent": old, "published_head": landed})

    def test_interrupted_marker_writes_leave_no_partial_marker(self):
        receipt = workflow.read_json(self.export() / "receipt.json")
        original = rc.canonical_json
        def disk_full_on(key):
            def canonical_json(value):
                if isinstance(value, dict) and key in value:
                    raise OSError(28, "No space left on device")
                return original(value)
            return patch.object(rc, "canonical_json", side_effect=canonical_json)
        with disk_full_on("expected_public_head"):
            self.assert_status(self.cli("approve", *self.target_flags()), "INCOMPLETE", "workflow-incomplete")
        self.assertFalse((self.run / "approval.json").exists())
        self.prepare()
        self.push()
        def fsync(fd):
            if Path(os.readlink("/proc/self/fd/%d" % fd)).name.startswith(".published.json."):
                raise OSError(28, "No space left on device")
            return original_fsync(fd)
        original_fsync = os.fsync
        with patch.object(workflow.os, "fsync", side_effect=fsync):
            self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "workflow-incomplete")
        self.assertFalse((self.run / "published.json").exists())
        self.assertEqual(self.remote_head(), receipt["export_head"])
        self.assert_status(self.cli("publish", *self.target_flags()), "PASS")
        self.assertEqual(self.published()["published_head"], receipt["export_head"])
        self.assertEqual([p.name for p in self.run.iterdir() if p.name.startswith(".")], [])

    def test_publish_never_passes_when_the_public_head_cannot_be_read(self):
        self.public_history("Earlier public release")
        self.export()
        self.prepare()
        self.push()
        original = rc.git
        def git(repo, *args, **kwargs):
            if "ls-remote" in args:
                raise rc.AuditError("git-read-failed")
            return original(repo, *args, **kwargs)
        with patch.object(rc, "git", side_effect=git):
            self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "git-read-failed")
        hidden = self.root / "public-offline.git"
        self.remote.rename(hidden)
        self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "git-read-failed")
        hidden.rename(self.remote)
        self.assertFalse((self.run / "published.json").exists())

    def test_remote_race_before_the_first_push_is_stopped_by_the_lease(self):
        self.export()
        self.prepare()
        rc.git(self.repo, "push", str(self.remote), "HEAD:refs/heads/main")
        raced = self.remote_head()
        self.assertNotEqual(self.push(check=False).returncode, 0)
        self.assertEqual(self.remote_head(), raced)
        self.assert_status(self.cli("publish", *self.target_flags()), "FAIL", "target-moved")

    def test_signer_flags_are_gone(self):
        self.export()
        for flags in (["--identity", "owner"], ["--allowed-signers", str(self.root / "signers")],
                      ["--key", str(self.root / "key")], ["--scanner-waiver"]):
            with self.subTest(flags=flags), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.cli("approve", *self.target_flags(), *flags)
        self.assertFalse((self.run / "approval.json").exists())

    def test_policy_changes_and_unverified_exports_cannot_be_approved(self):
        self.export()
        self.assert_status(self.cli("approve", *[f for f in self.target_flags() if f != "--verify"]), "INCOMPLETE", "receipt-stale")
        self.assert_status(self.cli("approve", *self.target_flags(), "--timeout", "301"), "INCOMPLETE", "receipt-stale")
        self.testbed.denylist.write_bytes(self.testbed.denylist.read_bytes() + b"\n")
        self.reference.write_text(rc.sha256(self.testbed.denylist.read_bytes()) + "\n")
        self.assert_status(self.cli("approve", *self.target_flags()), "INCOMPLETE", "receipt-stale")

    def test_byte_bound_triage_carries_across_runs_and_expires_on_change(self):
        text = ('Public contact: help' + '@example.org\n')
        (self.repo / "contact.txt").write_text(text)
        self.testbed.commit("Add documented synthetic contact")
        self.assert_status(self.cli("plan"), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            first = self.assert_status(self.cli("check", "--verify"), "FAIL")
            report = workflow.read_json(self.run / "attempts" / first["attempt"] / "report.json")
            triage = [{**{k: f[k] for k in ("scope", "kind", "path", "fingerprint")},
                       "file_sha256": rc.sha256(text.encode())} for f in report["findings"] if f["kind"] == "email"]
            (self.run / "triage.json").write_text(json.dumps(triage))
            self.assert_status(self.cli("check", "--verify"), "PASS")
            self.assert_status(self.cli("plan", run="second"), "PASS")
            second = self.run.parent / "second"
            self.assertEqual(workflow.read_json(second / "triage.json"), triage)
            self.assert_status(self.cli("check", "--verify", run="second"), "PASS")
            (self.repo / "contact.txt").write_text(text + "Changed bytes\n")
            self.testbed.commit("Change documented contact")
            self.assert_status(self.cli("check", "--verify", run="second"), "FAIL")

    def review(self, answers):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(sys, "stdin", io.StringIO(answers)), redirect_stdout(output), redirect_stderr(errors):
            code = rc.main(["review", str(self.repo), "--run", "first"])
        return code, json.loads(output.getvalue()), errors.getvalue()

    def test_review_records_approve_exclude_and_fix_decisions_for_the_next_check(self):
        addresses = {name: name.split(".")[0] + "@example.org" for name in ("contact.txt", "extra.txt", "draft.txt")}
        for name, address in addresses.items():
            (self.repo / name).write_text("Contact: " + address + "\n" + ("Again: " + address + "\n" if name == "contact.txt" else ""))
        self.testbed.commit("Add synthetic contacts")
        self.assert_status(self.cli("plan"), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            first = self.assert_status(self.cli("check", "--verify"), "FAIL")
        report = workflow.read_json(self.run / "attempts" / first["attempt"] / "report.json")
        unresolved = sorted((f for f in report["findings"] if not f["reviewed"]),
                            key=lambda f: (f["path"], f["line"], f["scope"], f["kind"]))
        self.assertEqual({f["path"] for f in unresolved}, set(addresses))
        replies = {"contact.txt": "a\nVerified public support address.\n", "extra.txt": "e\n", "draft.txt": "x\nf\n"}
        earlier = next(f for f in unresolved if f["path"] == "extra.txt")
        (self.run / "triage.json").write_text(json.dumps([{"decision": "fix", "line": earlier["line"], **{
            k: earlier[k] for k in ("scope", "kind", "path", "fingerprint")}}]))
        answers, seen = "", set()
        for finding in unresolved:
            key = "extra.txt" if finding["path"] == "extra.txt" else tuple(finding[k] for k in ("scope", "kind", "path", "fingerprint"))
            if key not in seen:
                seen.add(key)
                answers += replies[finding["path"]]
        self.assertLess(len(seen), len(unresolved))
        code, value, errors = self.review(answers)
        self.assert_status((code, value), "PASS")
        for finding in unresolved:
            self.assertIn(f"{finding['path']}:{finding['line']} {finding['kind']}", errors)
        for address in addresses.values():
            self.assertNotIn(address, errors + json.dumps(value))
        triage = workflow.read_json(self.run / "triage.json")
        self.assertEqual({(item["decision"], item["path"]) for item in triage},
                         {("approve", "contact.txt"), ("exclude", "extra.txt"), ("fix", "draft.txt")})
        self.assertTrue(all(item["file_sha256"] == rc.sha256((self.repo / "contact.txt").read_bytes())
                            and item["reason"] == "Verified public support address."
                            for item in triage if item["decision"] == "approve"))
        self.assertNotIn("extra.txt", workflow.paths_for(self.repo, self.run, self.testbed.manifest))
        with patch.object(rc, "verify", side_effect=verified):
            second = self.assert_status(self.cli("check", "--verify"), "FAIL")
        report = workflow.read_json(self.run / "attempts" / second["attempt"] / "report.json")
        self.assertEqual({f["path"] for f in report["findings"] if not f["reviewed"]}, {"draft.txt"})
        self.assertTrue(any(f["reviewed"] and f["path"] == "contact.txt" for f in report["findings"]))
        self.assertFalse(any(f["path"] == "extra.txt" for f in report["findings"]))
        code, value, errors = self.review("f\n" * len(unresolved))
        self.assert_status((code, value), "PASS")
        self.assertEqual(value["pending"], 0)
        self.assertIn("draft.txt:1 email (recorded: fix, still unresolved)", errors)
        self.assertNotIn("extra.txt", errors)
        self.assertEqual(len(workflow.read_json(self.run / "triage.json")), len(triage))
        (self.run / "triage.json").write_text(json.dumps([*triage, {"decision": "ignore", "path": "draft.txt"}]))
        self.assert_status(self.review("")[:2], "INCOMPLETE", "triage-schema")
        (self.run / "triage.json").write_text(json.dumps(triage))
        (self.repo / "draft.txt").write_text("Contact: see the README\n")
        self.testbed.commit("Fix the draft contact")
        with patch.object(rc, "verify", side_effect=verified):
            self.assert_status(self.cli("check", "--verify"), "PASS")
        self.assert_status(self.cli("plan", run="second"), "PASS")
        self.assertNotIn("extra.txt", (self.run.parent / "second" / "public-export.txt").read_text().splitlines())

    def test_plan_applies_inherited_exclusions_to_an_existing_allowlist(self):
        package = {"name": "testbed", "version": "1.0.0", "license": "MIT", "dependencies": {"example": "^1.0.0"}}
        lock = {"lockfileVersion": 3, "name": "testbed", "version": "1.0.0", "packages": {
            "": package, "node_modules/example": {"version": "1.0.0", "license": "MIT",
                "resolved": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
                "integrity": "sha512-" + "A" * 86 + "=="}}}
        (self.repo / "package.json").write_text(json.dumps(package))
        (self.repo / "package-lock.json").write_text(json.dumps(lock))
        self.testbed.commit("Add source dependency declarations")
        self.assert_status(self.cli("preflight"), "FAIL")
        listed = workflow.proposed_paths(self.repo, self.testbed.manifest)
        self.assertIn("package.json", listed)
        exclusions = [{"decision": "exclude", "path": name} for name in ("package.json", "package-lock.json")]
        self.run.mkdir(parents=True, exist_ok=True)
        (self.run / "public-export.txt").write_text("".join(p + "\n" for p in listed))
        (self.run / "plan.json").write_text(json.dumps({"scanners": []}))
        (self.run / "triage.json").write_text(json.dumps(exclusions))
        second = workflow.run_directory(self.repo, "second")
        second.mkdir(parents=True)
        (second / "public-export.txt").write_text("".join(p + "\n" for p in listed))
        self.assert_status(self.cli("plan", run="second"), "PASS")
        self.assertEqual(workflow.read_json(second / "triage.json"), exclusions)
        self.assertNotIn("package.json", workflow.paths_for(self.repo, second, self.testbed.manifest))

    def test_exclusion_recorded_after_approval_blocks_publish(self):
        (self.repo / "notes.txt").write_text("Public notes\n")
        self.testbed.commit("Add public notes")
        attempt = self.export()
        self.assertIn("notes.txt", workflow.read_json(attempt / "allowlist.json"))
        self.prepare()
        self.push()
        triage = workflow.read_json(self.run / "triage.json")
        (self.run / "triage.json").write_text(json.dumps([*triage, {"decision": "exclude", "path": "notes.txt"}]))
        self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "allowlist-changed")
        self.assertFalse((self.run / "published.json").exists())

    def test_allowlist_diff_since_published_approval(self):
        self.export()
        self.prepare()
        self.push()
        self.assert_status(self.cli("publish", *self.target_flags()), "PASS")
        (self.repo / "new.txt").write_text("Public testbed")
        self.testbed.commit("Add public file")
        self.export(run="second")
        record = self.assert_status(self.cli("approve", *self.target_flags(), run="second"), "PASS")
        self.assertEqual(record["allowlist_diff"], {"added": ["new.txt"], "removed": []})

    def passing_scan(self, attempt, name, receipt, timeout, repo):
        return {"name": name, "outcome": "PASS", "version": "synthetic", "output_sha256": "a" * 64,
                "export_head": receipt["export_head"], "export_tree": receipt["export_tree"]}

    def test_approval_requires_a_passing_secret_scanner(self):
        self.export(("osv-scanner",))
        self.assert_status(self.cli("approve", *self.target_flags()), "INCOMPLETE", "scanners-required")
        self.assertFalse((self.run / "approval.json").exists())
        self.assertEqual(list(workflow.guard_records_root().glob("*/*")), [])
        self.export(("gitleaks",), run="second")
        approved = self.assert_status(self.cli("approve", *self.target_flags(), run="second"), "PASS")
        self.assertNotIn("scanner_waiver", approved)
        self.assertEqual([s["name"] for s in approved["scanners"]], ["gitleaks"])

    def test_an_edited_record_without_a_secret_scanner_does_not_publish(self):
        self.export()
        self.prepare()
        self.push()
        approval = self.run / "approval.json"
        record = workflow.read_json(approval)
        for scanners in ([], [{"name": "osv-scanner", "result_sha256": "a" * 64}]):
            approval.write_text(json.dumps({**record, "scanners": scanners}))
            self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE")
        approval.write_text(json.dumps({**record, "scanner_waiver": True}))
        self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "approval-invalid")
        self.assertFalse((self.run / "published.json").exists())

    def test_selected_missing_scanner_blocks_approval(self):
        self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")
        with patch.object(rc, "verify", side_effect=verified), patch.object(workflow.shutil, "which", return_value=None):
            result = self.assert_status(self.cli("export", "--verify"), "INCOMPLETE")
        self.assertEqual(result["scanners"], [{"name": "gitleaks", "outcome": "INCOMPLETE"}])
        self.assert_status(self.cli("approve", *self.target_flags()), "INCOMPLETE", "scanner-not-pass")

    def test_changed_recipe_blocks_approval(self):
        self.export()
        manifest = self.repo / "release-check.json"
        obj = json.loads(manifest.read_text())
        obj["exclude"] = ["unrelated-file"]
        manifest.write_text(json.dumps(obj))
        self.assert_status(self.cli("approve", *self.target_flags()), "INCOMPLETE", "recipe-changed")

    def test_historical_attribution_must_survive_allowlist(self):
        (self.repo / "NOTICE").write_text("Required upstream attribution")
        self.testbed.commit("Add attribution")
        self.testbed.git("rm", "NOTICE")
        self.testbed.git("commit", "-q", "-m", "Remove attribution")
        self.assert_status(self.cli("plan"), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            result = self.assert_status(self.cli("export", "--verify"), "FAIL")
        report = workflow.read_json(self.run / "attempts" / result["attempt"] / "report.json")
        self.assertIn("historical-attribution-missing", report["reasons"])
        self.assert_status(self.cli("approve", *self.target_flags()), "INCOMPLETE", "historical-attribution-missing")

    def test_adapter_scans_receipt_commit_and_discards_raw_findings(self):
        attempt = self.export()
        receipt = workflow.read_json(attempt / "receipt.json")
        (attempt / "export/README.md").write_text("Mutable working tree excluded from scanner input")
        binary = self.root / "gitleaks"
        script = """import json, pathlib, subprocess, sys
args = sys.argv[1:]
if args == ['version']:
    print('synthetic-scanner-version')
    sys.exit(0)
clone = pathlib.Path(args[1])
assert clone != pathlib.Path(EXPORT)
assert subprocess.check_output(['git', '-C', str(clone), 'rev-parse', 'HEAD']).decode().strip() == HEAD
assert 'Mutable working tree' not in (clone / 'README.md').read_text()
assert '--ignore-gitleaks-allow' in args
assert '--config' in args
report = pathlib.Path(args[args.index('--report-path') + 1])
report.write_text('[{"Secret":"testbed-only-sensitive-marker"}]')
sys.exit(1)
"""
        binary.write_text('#!' + sys.executable + '\n' + 'EXPORT = ' + repr(str(attempt / 'export')) + '\nHEAD = ' + repr(receipt['export_head']) + '\n' + script)
        binary.chmod(0o700)
        with patch.object(workflow.shutil, "which", return_value=str(binary)):
            result = workflow.scan_export(attempt, "gitleaks", receipt, 300, self.repo)
        self.assertEqual(result["outcome"], "FAIL")
        self.assertEqual(result["export_head"], receipt["export_head"])
        self.assertEqual(result["version"], "synthetic-scanner-version")
        self.assertNotIn("testbed-only-sensitive-marker", json.dumps(result))
        self.assertFalse(any(p.name.startswith("scanner-") for p in self.root.iterdir()))

    def test_trufflehog_requires_completion_and_rejects_error_or_findings(self):
        attempt = self.export()
        receipt = workflow.read_json(attempt / "receipt.json")
        binary = self.root / "trufflehog"
        for rows, code, expected in [
            ([{"msg": "started scanning"}], 0, "INCOMPLETE"),
            ([{"msg": "finished scanning"}, {"level": "error", "msg": "synthetic error"}], 0, "INCOMPLETE"),
            ([{"msg": "finished scanning"}], 2, "INCOMPLETE"),
            ([{"msg": "finished scanning"}], 0, "PASS"),
            ([{"msg": "finished scanning"}, {"DetectorName": "Synthetic", "Raw": "testbed-only-sensitive-marker"}], 183, "FAIL"),
        ]:
            with self.subTest(expected=expected, code=code, rows=rows):
                binary.write_text('#!' + sys.executable + '\nimport json, sys\n'
                                  'if sys.argv[1:] == ["--version"]:\n print("synthetic-version"); sys.exit(0)\n'
                                  'assert "--no-verification" in sys.argv and "--fail-on-scan-errors" in sys.argv\n'
                                  'assert "--no-ignore-tag" in sys.argv\n'
                                  'rows = ' + repr(rows) + '\n'
                                  'for row in rows: print(json.dumps(row))\n'
                                  'sys.exit(' + str(code) + ')\n')
                binary.chmod(0o700)
                with patch.object(workflow.shutil, "which", return_value=str(binary)):
                    result = workflow.scan_export(attempt, "trufflehog", receipt, 300, self.repo)
                self.assertEqual(result["outcome"], expected)
                self.assertNotIn("testbed-only-sensitive-marker", json.dumps(result))

    def test_scanner_timeout_is_incomplete(self):
        attempt = self.export()
        receipt = workflow.read_json(attempt / "receipt.json")
        binary = self.root / "gitleaks"
        binary.write_text('#!' + sys.executable + '\nimport sys, time\n'
                          'if sys.argv[1:] == ["version"]: print("synthetic-version"); sys.exit(0)\n'
                          'time.sleep(10)\n')
        binary.chmod(0o700)
        with patch.object(workflow.shutil, "which", return_value=str(binary)):
            result = workflow.scan_export(attempt, "gitleaks", receipt, 1, self.repo)
        self.assertEqual(result["outcome"], "INCOMPLETE")

    def fake_trufflehog(self, body):
        binary = self.root / "trufflehog"
        binary.write_text('#!' + sys.executable + '\nimport json, sys, time\n'
                          'if sys.argv[1:] == ["--version"]:\n print("synthetic-version"); sys.exit(0)\n' + body)
        binary.chmod(0o700)
        return binary

    def test_plan_rejects_trufflehog_without_required_flags(self):
        old_help = "".join("      --[no-]" + flag + "\n" for flag in
                           ("json", "no-verification", "no-verification-cache", "no-color", "no-update", "fail", "fail-on-scan-errors"))
        old_help += "      --branch=BRANCH\n      --[no-]no-ignore-tags-cache\n"
        binary = self.fake_trufflehog("print(" + repr(old_help) + ")\n")
        with patch.object(workflow.shutil, "which", return_value=str(binary)):
            result = self.assert_status(self.cli("plan", "--scanner", "trufflehog"), "INCOMPLETE", "scanner-unsupported")
            self.assertEqual(result.get("detail"), "trufflehog lacks --no-ignore-tag")
            self.assertFalse((self.run / "plan.json").exists())
            self.fake_trufflehog("print(" + repr(old_help + "      --[no-]no-ignore-tag\n") + ")\n")
            self.assert_status(self.cli("plan", "--scanner", "trufflehog"), "PASS")

    def test_scanner_results_record_why_they_are_not_pass(self):
        stderr = io.StringIO()
        with patch.object(workflow.shutil, "which", return_value=None):
            self.assert_status(self.cli("plan", "--scanner", "gitleaks", "--scanner", "trufflehog"), "PASS")
            with patch.object(rc, "verify", side_effect=verified), redirect_stderr(stderr):
                exported = self.assert_status(self.cli("export", "--verify"), "INCOMPLETE")
        attempt = self.run / "attempts" / exported["attempt"]
        results = workflow.read_json(attempt / "scanners.json")
        self.assertEqual([(r["name"], r["outcome"], r.get("reason")) for r in results],
                         [("gitleaks", "INCOMPLETE", "scanner-missing"), ("trufflehog", "INCOMPLETE", "scanner-missing")])
        self.assertIn("scanner: trufflehog INCOMPLETE (scanner-missing)", stderr.getvalue())
        with redirect_stderr(io.StringIO()):
            refused = self.cli("approve", *self.target_flags())
        self.assert_status(refused, "INCOMPLETE", "scanner-not-pass")
        self.assertFalse((self.run / "approval.json").exists())
        receipt = workflow.read_json(attempt / "receipt.json")
        finished = 'print(json.dumps({"msg": "finished scanning"}))\n'
        for body, timeout, expected in [
            ('print("trufflehog: error: unknown long flag --no-ignore-tag"); sys.exit(1)\n', 300, ("INCOMPLETE", "scanner-exit-code")),
            ("time.sleep(10)\n", 1, ("INCOMPLETE", "scanner-timeout")),
            (finished + 'print(json.dumps({"DetectorName": "Synthetic"})); sys.exit(183)\n', 300, ("FAIL", "scanner-findings")),
            (finished, 300, ("PASS", None)),
        ]:
            with self.subTest(expected=expected):
                binary = self.fake_trufflehog(body)
                with patch.object(workflow.shutil, "which", return_value=str(binary)):
                    result = workflow.scan_export(attempt, "trufflehog", receipt, timeout, self.repo)
                self.assertEqual((result["outcome"], result.get("reason")), expected)

    def fake_osv(self, body):
        binary = self.root / "osv-scanner"
        binary.write_text('#!' + sys.executable + '\nimport json, pathlib, sys\nargs = sys.argv[1:]\n'
                          'if args == ["--version"]:\n print("osv-scanner version: 9.9.9\\ncommit: synthetic"); sys.exit(0)\n'
                          'assert args[:2] == ["scan", "source"] and "--allow-no-lockfiles" in args\n'
                          'assert pathlib.Path(args[args.index("--config") + 1]).read_text() == ""\n'
                          'output, clone = pathlib.Path(args[args.index("--output-file") + 1]), args[-1]\n' + body)
        binary.chmod(0o700)
        return binary

    def osv_report(self, max_severity="8.6", label="HIGH", events=({"introduced": "0"}, {"fixed": "2.10.1"})):
        vulnerability = {"id": OSV_ADVISORY["id"], "aliases": OSV_ADVISORY["aliases"],
                         "database_specific": {"severity": label},
                         "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"},
                                       "ranges": [{"type": "ECOSYSTEM", "events": list(events)}]}]}
        return {"results": [{"source": {"path": "CLONE/requirements.txt", "type": "lockfile"}, "packages": [{
            "package": {"name": "jinja2", "version": "2.10", "ecosystem": "PyPI"},
            "groups": [{"ids": [OSV_ADVISORY["id"]], "aliases": OSV_ADVISORY["aliases"], "max_severity": max_severity}],
            "vulnerabilities": [vulnerability]}]}]}

    def osv_body(self, report, code):
        return ('output.write_text(' + repr(json.dumps(report)) + '.replace("CLONE", clone))\n'
                'sys.exit(' + str(code) + ')\n')

    def test_osv_scanner_blocks_only_fixable_critical_or_high_advisories(self):
        attempt = self.export()
        receipt = workflow.read_json(attempt / "receipt.json")
        unfixed = ({"introduced": "0"},)
        for report, code, expected in [
            (self.osv_report(), 1, ("FAIL", "scanner-findings", True)),
            (self.osv_report(max_severity="9.8", label=""), 1, ("FAIL", "scanner-findings", True)),
            (self.osv_report(max_severity="", label="CRITICAL"), 1, ("FAIL", "scanner-findings", True)),
            (self.osv_report(events=unfixed), 1, ("PASS", None, False)),
            (self.osv_report(max_severity="5.3", label="MODERATE"), 1, ("PASS", None, False)),
            ({"results": []}, 0, ("PASS", None, None)),
            ({"results": []}, 1, ("INCOMPLETE", "scanner-exit-code", None)),
            ({"results": [{"source": {"path": "/elsewhere/requirements.txt"}, "packages": []}]}, 0, ("INCOMPLETE", "scanner-report", None)),
            ({"results": "invalid"}, 0, ("INCOMPLETE", "scanner-report", None)),
            ({"results": [{**self.osv_report()["results"][0], "packages": [{**self.osv_report()["results"][0]["packages"][0], "groups": []}]}]},
             1, ("INCOMPLETE", "scanner-report", None)),
        ]:
            with self.subTest(expected=expected, report=report):
                binary = self.fake_osv(self.osv_body(report, code))
                with patch.object(workflow.shutil, "which", return_value=str(binary)):
                    result = workflow.scan_export(attempt, "osv-scanner", receipt, 300, self.repo)
                self.assertEqual((result["outcome"], result.get("reason")), expected[:2])
                self.assertEqual(result["version"], "osv-scanner version: 9.9.9")
                if expected[2] is not None:
                    [advisory] = result["advisories"]
                    self.assertEqual((advisory["ids"], advisory["package"], advisory["version"], advisory["path"], advisory["blocking"]),
                                     ([OSV_ADVISORY["id"]], "jinja2", "2.10", "requirements.txt", expected[2]))

    def test_osv_scanner_missing_tool_or_database_is_incomplete(self):
        attempt = self.export()
        receipt = workflow.read_json(attempt / "receipt.json")
        old = self.fake_osv(self.osv_body({"results": []}, 0)).read_text().replace("9.9.9", "2.5.0")
        (self.root / "osv-scanner").write_text(old)
        with patch.object(workflow.shutil, "which", return_value=str(self.root / "osv-scanner")):
            self.assertEqual(workflow.scan_export(attempt, "osv-scanner", receipt, 300, self.repo)["reason"], "scanner-version")
        with patch.object(workflow.shutil, "which", return_value=None):
            self.assertEqual(workflow.scan_export(attempt, "osv-scanner", receipt, 300, self.repo)["reason"], "scanner-missing")
        offline = self.fake_osv('import os\nassert "--offline-vulnerabilities" in args\n'
                                'assert os.path.isabs(os.environ["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"])\n'
                                'print("could not load db for PyPI ecosystem: unable to fetch OSV database: '
                                'no offline version of the OSV database is available"); sys.exit(127)\n')
        for database in (self.root / "absent-db", self.root, Path(os.path.relpath(self.root))):
            with self.subTest(database=database), patch.object(workflow.shutil, "which", return_value=str(offline)), \
                    patch.dict(os.environ, {"COLDRELEASE_OSV_DB": str(database)}):
                result = workflow.scan_export(attempt, "osv-scanner", receipt, 300, self.repo)
            self.assertEqual((result["outcome"], result["reason"], result["database"]),
                             ("INCOMPLETE", "scanner-database-missing", "offline"))

    @unittest.skipUnless(shutil.which("osv-scanner"), "osv-scanner is not installed")
    def test_real_osv_scanner_offline_database_blocks_pinned_vulnerable_package(self):
        database = self.root / "osv-db"
        (database / "osv-scalibr/PyPI").mkdir(parents=True)
        with zipfile.ZipFile(database / "osv-scalibr/PyPI/all.zip", "w") as archive:
            archive.writestr(OSV_ADVISORY["id"] + ".json", json.dumps(OSV_ADVISORY))
        (self.repo / "requirements.txt").write_text("jinja2==2.10\n")
        (self.repo / "osv-scanner.toml").write_text('[[IgnoredVulns]]\nid = "' + OSV_ADVISORY["id"] + '"\n'
                                                    '[[PackageOverrides]]\nname = "jinja2"\necosystem = "PyPI"\nignore = true\n')
        self.testbed.commit("Pin a package with a known advisory")
        stderr = io.StringIO()
        with patch.dict(os.environ, {"COLDRELEASE_OSV_DB": str(database)}):
            self.assert_status(self.cli("plan", "--scanner", "osv-scanner"), "PASS")
            with patch.object(rc, "verify", side_effect=verified), redirect_stderr(stderr):
                exported = self.assert_status(self.cli("export", "--verify"), "FAIL")
        self.assertEqual(exported["scanners"], [{"name": "osv-scanner", "outcome": "FAIL"}])
        [result] = workflow.read_json(self.run / "attempts" / exported["attempt"] / "scanners.json")
        self.assertEqual((result["database"], [a["ids"] for a in result["advisories"] if a["blocking"]]),
                         ("offline", [[OSV_ADVISORY["id"]]]))
        self.assertIn(OSV_ADVISORY["id"], stderr.getvalue())
        self.assert_status(self.cli("approve", *self.target_flags()), "INCOMPLETE", "scanner-not-pass")

    def fake_bandit(self, report, code, version="1.9.4"):
        binary = self.root / "bandit"
        binary.write_text('#!' + sys.executable + '\nimport json, pathlib, sys\nargs = sys.argv[1:]\n'
                          'if args == ["--version"]:\n print("bandit ' + version + '\\n  python version = 3"); sys.exit(0)\n'
                          'if args == ["--help"]:\n print("--recursive --ini --ignore-nosec --quiet --format --output"); sys.exit(0)\n'
                          'assert "--ignore-nosec" in args and "--recursive" in args\n'
                          'assert pathlib.Path(args[args.index("--ini") + 1]).read_text() == "[bandit]\\n"\n'
                          'output, clone = pathlib.Path(args[args.index("--output") + 1]), args[-1]\n'
                          'output.write_text(' + repr(report if isinstance(report, str) else json.dumps(report)) + '.replace("CLONE", clone))\n'
                          'sys.exit(' + str(code) + ')\n')
        binary.chmod(0o700)
        return binary

    def bandit_report(self, **overrides):
        row = {"filename": "CLONE/app.py", "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true",
               "line_number": 8, "issue_severity": "HIGH", "issue_confidence": "HIGH", "code": "subprocess.run(command, shell=True)"}
        return {"errors": [], "results": [{**row, **overrides}]}

    def which_bandit(self, binary):
        real = shutil.which
        return patch.object(workflow.shutil, "which", side_effect=lambda name, *a, **k: str(binary) if name == "bandit" else real(name, *a, **k))

    def test_bandit_findings_are_recorded_report_only(self):
        attempt = self.export()
        receipt = workflow.read_json(attempt / "receipt.json")
        for report, code, expected in [
            (self.bandit_report(), 1, ("PASS", None, 1)),
            ({"errors": [], "results": []}, 0, ("PASS", None, 0)),
            ({"errors": [], "results": []}, 1, ("INCOMPLETE", "scanner-exit-code", None)),
            ({"errors": [{"filename": "CLONE/py2.py", "reason": "syntax error"}], "results": []}, 0, ("INCOMPLETE", "scanner-error", None)),
            (self.bandit_report(filename="/elsewhere/app.py"), 1, ("INCOMPLETE", "scanner-report", None)),
            (self.bandit_report(issue_severity="SEVERE"), 1, ("INCOMPLETE", "scanner-report", None)),
            (self.bandit_report(line_number="8"), 1, ("INCOMPLETE", "scanner-report", None)),
            (self.bandit_report(issue_severity=["HIGH"]), 1, ("INCOMPLETE", "scanner-report", None)),
            (self.bandit_report(issue_confidence={"HIGH": 1}), 1, ("INCOMPLETE", "scanner-report", None)),
            ("not json", 0, ("INCOMPLETE", "scanner-report", None)),
            ({"results": []}, 0, ("INCOMPLETE", "scanner-report", None)),
            ({"errors": [], "results": "invalid"}, 0, ("INCOMPLETE", "scanner-report", None)),
        ]:
            with self.subTest(expected=expected, report=report), self.which_bandit(self.fake_bandit(report, code)):
                result = workflow.scan_export(attempt, "bandit", receipt, 300, self.repo)
            self.assertEqual((result["outcome"], result.get("reason")), expected[:2])
            self.assertEqual(result["version"], "bandit 1.9.4")
            if expected[2] is not None:
                self.assertEqual(len(result["findings"]), expected[2])
        with self.which_bandit(self.fake_bandit(self.bandit_report(), 1)):
            [finding] = workflow.scan_export(attempt, "bandit", receipt, 300, self.repo)["findings"]
        self.assertEqual(finding, {"test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true", "path": "app.py",
                                   "line": 8, "severity": "HIGH", "confidence": "HIGH"})
        with self.which_bandit(self.fake_bandit(self.bandit_report(), 1, version="1.7.10")):
            self.assertEqual(workflow.scan_export(attempt, "bandit", receipt, 300, self.repo)["reason"], "scanner-version")
        with patch.object(workflow.shutil, "which", return_value=None):
            self.assertEqual(workflow.scan_export(attempt, "bandit", receipt, 300, self.repo)["reason"], "scanner-missing")

    def test_export_with_bandit_reports_findings_and_still_approves(self):
        stderr = io.StringIO()
        with self.fake_gitleaks(), self.which_bandit(self.fake_bandit(self.bandit_report(), 1)), redirect_stderr(stderr):
            attempt = self.export(("bandit", "gitleaks"), fake=False)
        self.assertIn("appsec: bandit reported 1 findings in @export (B602); report only", stderr.getvalue())
        [result] = [r for r in workflow.read_json(attempt / "scanners.json") if r["name"] == "bandit"]
        self.assertEqual((result["outcome"], [f["test_id"] for f in result["findings"]]), ("PASS", ["B602"]))
        appsec = next(c for c in workflow.read_json(attempt / "report.json")["coverage"]["categories"]
                      if c["category"] == "application security")
        self.assertEqual(appsec["status"], "run after this report")
        self.prepare()
        [binding] = [b for b in workflow.read_json(self.run / "approval.json")["scanners"] if b["name"] == "bandit"]
        self.assertEqual(binding["result_sha256"], rc.sha256(rc.canonical_json(result)))

    @unittest.skipUnless(shutil.which("bandit"), "bandit is not installed")
    def test_real_bandit_reports_insecure_patterns_despite_suppressions(self):
        (self.repo / "app.py").write_text(
            "import subprocess\nimport sys\n\nimport requests\n\n\n"
            "def run(command):\n    return subprocess.run(command, shell=True)\n\n\n"
            "def fetch(url):\n    return requests.get(url, verify=False, timeout=5)  # nosec\n\n\n"
            "run(sys.argv[1])\n")
        (self.repo / ".bandit").write_text("[bandit]\nskips = B602,B501\n")
        self.testbed.commit("Add insecure patterns")
        stderr = io.StringIO()
        self.assert_status(self.cli("plan", "--scanner", "bandit"), "PASS")
        with patch.object(rc, "verify", side_effect=verified), redirect_stderr(stderr):
            exported = self.assert_status(self.cli("export", "--verify"), "PASS")
        self.assertEqual(exported["scanners"], [{"name": "bandit", "outcome": "PASS"}])
        attempt = self.run / "attempts" / exported["attempt"]
        self.assertTrue((attempt / "export" / ".bandit").is_file())
        [result] = workflow.read_json(attempt / "scanners.json")
        found = {(f["test_id"], f["path"], f["line"], f["severity"]) for f in result["findings"]}
        self.assertLessEqual({("B602", "app.py", 8, "HIGH"), ("B501", "app.py", 12, "HIGH")}, found)
        self.assertIn("B501", stderr.getvalue())
        self.assertIn("B602", stderr.getvalue())
        self.prepare()

    def test_record_edits_and_remote_alias_changes_are_rejected(self):
        self.export()
        self.prepare()
        self.push()
        approval = self.run / "approval.json"
        raw = approval.read_bytes()
        try:
            record = json.loads(raw)
            record["scanners"] = [{"name": "gitleaks", "result_sha256": "a" * 64}]
            approval.write_text(json.dumps(record))
            self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "approval-scanners")
        finally:
            approval.write_bytes(raw)
        self.testbed.git("remote", "add", "public", str(self.remote))
        flags = self.target_flags()
        flags[flags.index(str(self.remote))] = "public"
        self.testbed.git("remote", "set-url", "--push", "public", str(self.root / "wrong.git"))
        self.assert_status(self.cli("publish", *flags), "INCOMPLETE", "approval-target")
        self.assertFalse((self.run / "published.json").exists())

    def test_hash_prefixed_tracked_filename_is_an_exact_allowlist_entry(self):
        (self.repo / "#public.txt").write_text("Public testbed")
        self.testbed.commit("Add unusual public filename")
        attempt = self.export()
        self.assertEqual((attempt / "export/#public.txt").read_text(), "Public testbed")

    def test_private_run_id_is_redacted_in_output(self):
        result = self.assert_status(self.cli("preflight", run="HiddenPerson"), "PASS")
        self.assertNotIn("HiddenPerson", json.dumps(result))
        self.assertTrue(result["run"].startswith("[path-"))

    def test_the_push_sends_the_receipt_head_when_the_source_head_moves_after_approval(self):
        attempt = self.export()
        receipt_head = workflow.read_json(attempt / "receipt.json")["export_head"]
        self.prepare()
        (self.repo / "later.txt").write_text("Later\n")
        self.testbed.commit("Move mutable HEAD")
        self.push()
        self.assertEqual(self.remote_head(), receipt_head)

    def test_agent_state_notes_are_excluded_without_excluding_application_source(self):
        (self.repo / "STATE_private.md").write_text("Local agent state")
        (self.repo / "state.py").write_text("value = 4\n")
        self.testbed.commit("Separate app source from agent notes")
        attempt = self.export()
        self.assertEqual((attempt / "export/state.py").read_text(), "value = 4\n")
        self.assertFalse((attempt / "export/STATE_private.md").exists())

    def test_unplanned_tracked_symlinks_do_not_block_planned_snapshot(self):
        (self.repo / "before-link").symlink_to("README.md")
        self.testbed.git("add", "before-link")
        self.testbed.git("commit", "-q", "-m", "Add unsupported source link")
        self.assert_status(self.cli("plan"), "PASS")
        self.assertNotIn("before-link", (self.run / "public-export.txt").read_text().splitlines())
        (self.repo / "after-link").symlink_to("README.md")
        self.testbed.git("add", "after-link")
        self.testbed.git("commit", "-q", "-m", "Add unplanned source link")
        with patch.object(rc, "verify", side_effect=verified):
            self.assert_status(self.cli("check", "--verify"), "PASS")
            self.assert_status(self.cli("export", "--verify"), "PASS")
        (self.run / "public-export.txt").write_text((self.run / "public-export.txt").read_text() + "after-link\n")
        self.assert_status(self.cli("check", "--verify"), "INCOMPLETE", "allowlist-file")

    def test_cli_legacy_audit_accepts_repository_named_check(self):
        target = self.root / "check"
        self.repo.rename(target)
        process = subprocess.run([sys.executable, rc.__file__, "check", "--denylist", str(self.testbed.denylist),
                                  "--reports", str(self.root / "legacy-reports"), "--verify"],
                                 cwd=self.root, capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(json.loads(process.stdout)["outcome"], "PASS")

    def test_dependency_triage_clears_preflight_and_carries_to_next_plan(self):
        package = {"name": "testbed", "version": "1.0.0", "license": "MIT", "dependencies": {"example": "^1.0.0"}}
        lock = {"lockfileVersion": 3, "name": "testbed", "version": "1.0.0", "packages": {
            "": package, "node_modules/example": {"version": "1.0.0", "license": "MIT",
                "resolved": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
                "integrity": "sha512-" + "A" * 86 + "=="}}}
        (self.repo / "package.json").write_text(json.dumps(package))
        (self.repo / "package-lock.json").write_text(json.dumps(lock))
        self.testbed.commit("Add source dependency declarations")
        preflight = self.assert_status(self.cli("preflight"), "FAIL")
        finding = next(f for f in preflight["findings"] if f["kind"] == "npm-source-declarations-review")
        review = {**{k: finding[k] for k in ("scope", "kind", "path", "fingerprint")},
                  "reason": "Reviewed exact source and dependency declarations.",
                  "file_sha256": rc.sha256((self.repo / "package.json").read_bytes())}
        (self.run / "triage.json").write_text(json.dumps([review]))
        self.assert_status(self.cli("plan"), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            self.assert_status(self.cli("check", "--verify"), "PASS")
            self.assert_status(self.cli("export", "--verify"), "PASS")
            self.assert_status(self.cli("plan", run="second"), "PASS")
            self.assert_status(self.cli("check", "--verify", run="second"), "PASS")
        (self.repo / "package.json").write_text(json.dumps(package) + "\n")
        self.assert_status(self.cli("check", "--verify"), "INCOMPLETE", "preflight-not-pass")

    def test_shallow_source_cannot_skip_historical_attribution(self):
        (self.repo / "NOTICE").write_text("Required historical attribution\n")
        self.testbed.commit("Add historical attribution")
        self.testbed.git("rm", "NOTICE")
        self.testbed.git("commit", "-q", "-m", "Remove attribution from current tree")
        shallow = self.root / "shallow"
        subprocess.run(["git", "clone", "--quiet", "--depth", "1", self.repo.as_uri(), str(shallow)],
                       check=True, capture_output=True)
        self.repo = shallow
        self.assertEqual(rc.git(shallow, "rev-parse", "--is-shallow-repository").strip(), b"true")
        self.assert_status(self.cli("preflight"), "INCOMPLETE", "source-shallow")
        self.assert_status(self.cli("plan"), "INCOMPLETE", "source-shallow")

    def test_interrupted_previous_plan_does_not_block_new_runs(self):
        runs = self.run.parent
        for name, plan_written in (("interrupted-allowlist", False), ("interrupted-triage", True)):
            previous = runs / name
            previous.mkdir(parents=True)
            (previous / "public-export.txt").write_text("README.md\n")
            if plan_written:
                (previous / "plan.json").write_text('{"scanners":[]}')
        result = self.assert_status(self.cli("plan"), "PASS")
        self.assertIn("README.md", result["allowlist_diff"]["added"])
        self.assertEqual(workflow.read_json(self.run / "triage.json"), [])

    def test_source_url_rewrite_cannot_split_destination_lookup_and_push(self):
        attempt = self.export()
        redirected = self.root / "redirected.git"
        subprocess.run(["git", "init", "-q", "--bare", str(redirected)], check=True, capture_output=True)
        self.testbed.git("config", "url." + str(redirected) + ".insteadOf", str(self.remote))
        self.prepare()
        self.push()
        self.assert_status(self.cli("publish", *self.target_flags()), "PASS")
        export = attempt / "export"
        head = workflow.read_json(attempt / "receipt.json")["export_head"]
        self.assertEqual(rc.git(export, "ls-remote", "--refs", str(self.remote), "refs/heads/main").decode().split("\t")[0], head)
        self.assertEqual(rc.git(export, "ls-remote", "--refs", str(redirected)), b"")

    def test_initial_allowlist_can_exclude_unsupported_private_ecosystem(self):
        (self.repo / "Cargo.toml").write_text('[package]\nname = "private-part"\nversion = "0.1.0"\n')
        self.testbed.commit("Add unrelated private ecosystem")
        self.assert_status(self.cli("preflight"), "INCOMPLETE")
        selected = [p for p in workflow.proposed_paths(self.repo, self.testbed.manifest) if p != "Cargo.toml"]
        (self.run / "public-export.txt").write_text("".join(p + "\n" for p in selected))
        self.assert_status(self.cli("plan"), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            result = self.assert_status(self.cli("export", "--verify"), "PASS")
        self.assertFalse((self.run / "attempts" / result["attempt"] / "export/Cargo.toml").exists())

    def test_destination_timeout_is_incomplete_and_releases_run_lock(self):
        self.export()
        original = subprocess.run
        def stall_lookup(argv, **kwargs):
            if "ls-remote" in argv:
                self.assertEqual(kwargs.get("timeout"), 300)
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return original(argv, **kwargs)
        with patch.object(rc.subprocess, "run", side_effect=stall_lookup):
            self.assert_status(self.cli("approve", *self.target_flags()), "INCOMPLETE", "workflow-incomplete")
        self.assertFalse((self.run / ".lock").exists())
        self.prepare()
        self.push()
        with patch.object(rc.subprocess, "run", side_effect=stall_lookup):
            self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "workflow-incomplete")
        self.assertFalse((self.run / ".lock").exists())
        self.assertFalse((self.run / "published.json").exists())

    def test_files_left_by_a_dead_process_do_not_strand_the_run(self):
        self.run.mkdir(parents=True)
        (self.run / ".lock").touch()
        (self.run / ".plan.json.half-written").write_text("{")
        self.assert_status(self.cli("plan"), "PASS")
        self.assertFalse((self.run / ".lock").exists())
        with (self.run / ".lock").open("w") as live:
            fcntl.flock(live, fcntl.LOCK_EX)
            self.assert_status(self.cli("preflight"), "INCOMPLETE", "run-locked")
        self.assert_status(self.cli("preflight"), "PASS")

    def test_run_state_defaults_to_the_private_user_state_folder(self):
        home = self.root / "home"
        with patch.dict(os.environ, {"HOME": str(home), "XDG_STATE_HOME": "relative/state"}):
            self.assert_status(self.cli("preflight"), "PASS")
            run = workflow.run_directory(self.repo, "first")
        runs = home / ".local/state/coldrelease/runs"
        self.assertEqual(run.parent.parent, runs)
        self.assertTrue(run.parent.name.startswith("repo-"))
        self.assertEqual([p.name for p in run.iterdir()][0][:10], "preflight-")
        for folder in (run, run.parent, runs, runs.parent):
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700, folder)
        self.assertFalse((self.repo / ".coldrelease").exists())

    def test_run_state_folder_name_stays_short_for_a_long_source_name(self):
        long_repo = self.root / ("r" * 250)
        self.repo.rename(long_repo)
        self.repo = self.testbed.repo = long_repo
        self.assert_status(self.cli("preflight"), "PASS")
        source_id = workflow.run_directory(long_repo, "first").parent.name
        self.assertEqual(source_id, "r" * 64 + "-" + rc.sha256(os.fsencode(long_repo))[:12])

    def test_run_state_inside_the_source_is_refused(self):
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(self.repo / "state")}):
            self.assert_status(self.cli("preflight"), "INCOMPLETE", "run-state-inside-source")
        self.assertFalse((self.repo / "state").exists())

    def test_legacy_source_run_is_still_read_and_used_as_a_baseline(self):
        self.assert_status(self.cli("plan"), "PASS")
        legacy = self.repo / ".coldrelease/runs/first"
        legacy.parent.mkdir(parents=True)
        self.run.rename(legacy)
        self.assertEqual(workflow.run_directory(self.repo, "first"), legacy)
        with patch.object(rc, "verify", side_effect=verified):
            exported = self.assert_status(self.cli("export", "--verify"), "PASS")
        self.assertTrue((legacy / "attempts" / exported["attempt"] / "receipt.json").is_file())
        (self.repo / "NEW.md").write_text("New public file\n")
        self.testbed.commit("Add a file")
        planned = self.assert_status(self.cli("plan", run="second"), "PASS")
        self.assertEqual(planned["allowlist_diff"], {"added": ["NEW.md"], "removed": []})
        self.assertFalse(workflow.run_directory(self.repo, "second").is_relative_to(self.repo))

    def test_prune_removes_only_unbound_attempts_of_one_run(self):
        with patch.object(rc, "verify", side_effect=verified), patch.object(workflow, "scan_export", side_effect=self.passing_scan):
            self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")
            checked = self.assert_status(self.cli("check", "--verify"), "PASS")["attempt"]
            first = self.assert_status(self.cli("export", "--verify"), "PASS")["attempt"]
            approved = self.assert_status(self.cli("export", "--verify"), "PASS")["attempt"]
            self.prepare()
            self.push()
            current = self.assert_status(self.cli("export", "--verify"), "PASS")["attempt"]
            self.assert_status(self.cli("plan", run="other"), "PASS")
            other = self.assert_status(self.cli("check", "--verify", run="other"), "PASS")["attempt"]
        attempts = self.run / "attempts"
        protected = {approved, current}

        def prune(keep):
            output = io.StringIO()
            with redirect_stdout(output):
                code = rc.main(["prune", str(self.repo), "--run", "first", "--keep", str(keep)])
            return code, json.loads(output.getvalue())

        removed = self.assert_status(prune(1), "PASS")
        self.assertEqual(removed["removed"], [checked])
        self.assertEqual({p.name for p in attempts.iterdir()}, protected | {first})
        removed = self.assert_status(prune(0), "PASS")
        self.assertEqual((removed["removed"], set(removed["kept"])), ([first], protected))
        self.assertEqual({p.name for p in attempts.iterdir()}, protected)
        for name in ("approval.json", "plan.json", "public-export.txt"):
            self.assertTrue((self.run / name).is_file(), name)
        self.assertTrue((attempts / approved / "receipt.json").is_file())
        self.assertTrue((workflow.run_directory(self.repo, "other") / "attempts" / other).is_dir())
        self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "approval-receipt")

    def test_prune_requires_a_run_and_a_valid_keep_count(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = rc.main(["prune", str(self.repo), "--run", "first"])
        self.assert_status((code, json.loads(output.getvalue())), "INCOMPLETE", "keep-required")
        self.assert_status(self.cli("preflight", "--keep", "1"), "INCOMPLETE", "keep-selection")
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            rc.main(["prune", str(self.repo), "--run", "first", "--keep", "-1"])
        output = io.StringIO()
        with redirect_stdout(output):
            code = rc.main(["prune", str(self.repo), "--run", "first", "--keep", "0"])
        self.assert_status((code, json.loads(output.getvalue())), "INCOMPLETE", "run-missing")


if __name__ == "__main__":
    unittest.main()
