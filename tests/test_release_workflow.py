from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
import test_release_check as fixtures


def verified(*args, **kwargs):
    return {"status": "pass", "commands": [], "dependencies": {"blocked": 0}}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.repo = self.fixture.repo
        self.key = self.root / "synthetic-key"
        self.trust = self.root / "allowed-signers"
        self.remote = self.root / "public.git"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(self.key)], check=True, capture_output=True)
        self.trust.write_text("synthetic-owner " + self.key.with_suffix(".pub").read_text())
        self.trust.chmod(0o400)
        subprocess.run(["git", "init", "-q", "--bare", str(self.remote)], check=True, capture_output=True)
        self.run = self.repo / ".coldrelease/runs/first"

    def cli(self, command, *extra, run="first", real=False):
        args = [command, str(self.repo), "--denylist", str(self.fixture.denylist), "--run", run, *extra]
        if real:
            process = subprocess.run([sys.executable, rc.__file__, *args], capture_output=True, text=True)
            if process.returncode != 1:
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

    def trust_flags(self, target=None, ref="refs/heads/main"):
        return ["--verify", "--identity", "synthetic-owner", "--allowed-signers", str(self.trust),
                "--target", str(target or self.remote), "--ref", ref]

    def sign(self):
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", workflow.NAMESPACE,
                        str(self.run / "approval.json")], check=True, capture_output=True)

    def export(self, scanners=()):
        flags = [flag for name in scanners for flag in ("--scanner", name)]
        self.assert_status(self.cli("plan", *flags), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            self.assert_status(self.cli("export", "--verify"), "PASS")
        attempt = self.run / "attempts" / workflow.read_json(self.run / "export.json")["attempt"]
        return attempt

    def prepare(self):
        self.assert_status(self.cli("approve", *self.trust_flags()), "PASS")
        self.assertFalse((self.run / "approval.json.sig").exists())

    def remote_head(self, ref="refs/heads/main"):
        return rc.git(self.repo, "ls-remote", "--refs", str(self.remote), ref).decode().strip().split("\t")[0]

    def test_cli_unsafe_repaired_unsigned_blocked_then_signed_local_publish(self):
        leak = self.repo / "leak.txt"
        leak.write_text("Hidden" + "Person")
        self.fixture.commit("Unsafe synthetic fixture")
        self.assert_status(self.cli("preflight", real=True), "PASS")
        self.assert_status(self.cli("plan", real=True), "PASS")
        self.assert_status(self.cli("check", "--verify", real=True), "FAIL")
        leak.write_text("Public fixture\n")
        self.fixture.commit("Repair fixture")
        self.assert_status(self.cli("check", "--verify", real=True), "PASS")
        exported = self.assert_status(self.cli("export", "--verify", real=True), "PASS")
        self.assertEqual(exported["scanners"], [])
        approval = self.assert_status(self.cli("approve", *self.trust_flags(), real=True), "PASS")
        self.assertEqual(approval["outstanding_findings"], 0)
        self.assert_status(self.cli("publish", *self.trust_flags(), real=True), "INCOMPLETE", "approval-unsigned")
        self.assertEqual(self.remote_head(), "")
        self.sign()
        self.assert_status(self.cli("publish", *self.trust_flags(), real=True), "PASS")
        record = workflow.read_json(self.run / "published.json")
        self.assertEqual(self.remote_head(), record["export_head"])
        self.assertEqual(rc.git(self.repo, "--git-dir=" + str(self.remote), "rev-list", "--count", record["export_head"]).strip(), b"1")
        for report in self.run.rglob("report.json"):
            self.assertNotIn("HiddenPerson", report.read_text())
        self.assertEqual(len(list(self.run.parent.iterdir())), 1)

    def test_verification_workspace_is_outside_the_source_repository(self):
        probe = "import os,subprocess,sys;sys.exit(subprocess.run(['git','-C',os.environ['TMPDIR'],'rev-parse','--show-toplevel'],capture_output=True).returncode == 0)"
        manifest = {**self.fixture.manifest, "checks": [{"role": "tests", "argv": ["python", "-c", probe]}]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.fixture.commit("Probe enclosing repository")
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
                    self.assert_status(self.cli("plan"), "PASS")
                    self.assert_status(self.cli("check", "--verify"), "PASS")
                    self.assert_status(self.cli("export", "--verify"), "PASS")
                    self.prepare()
                    self.sign()
                    self.assert_status(self.cli("publish", *self.trust_flags()), "PASS")
                self.assertTrue(self.remote_head())

    def test_preflight_fails_license_and_plan_stops(self):
        (self.repo / "LICENSE").write_text("License undecided\n")
        self.assert_status(self.cli("preflight"), "FAIL")
        self.assert_status(self.cli("plan", run="blocked"), "INCOMPLETE", "preflight-not-pass")
        self.assertFalse((self.repo / ".coldrelease/runs/blocked/public-export.txt").exists())

    def test_plan_never_grows_allowlist_and_rejects_untracked_forbidden_and_symlink(self):
        (self.repo / "AGENTS.md").write_text("Local instructions")
        self.fixture.commit("Local agent notes")
        self.assert_status(self.cli("plan"), "PASS")
        path = self.run / "public-export.txt"
        original = path.read_text()
        self.assertNotIn("AGENTS.md", original)
        (self.repo / "new.txt").write_text("Public fixture")
        self.fixture.commit("Add new public file")
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

    def test_stale_receipt_blocks_signed_publish(self):
        attempt = self.export()
        self.prepare()
        self.sign()
        (attempt / "export/README.md").write_text("Changed after approval")
        self.assert_status(self.cli("publish", *self.trust_flags()), "INCOMPLETE", "receipt-stale")
        self.assertEqual(self.remote_head(), "")

    def export_path_review(self, relative, **changes):
        return {"scope": "tree", "kind": "export-path-review", "path": relative,
                "source_sha256": rc.sha256((self.repo / relative).read_bytes()),
                "reason": "Reviewed this exact synthetic public instruction file.", **changes}

    def test_export_path_review_selects_only_the_exact_file_and_expires(self):
        (self.repo / "AGENTS.md").write_text("Public product instructions\n")
        (self.repo / "CLAUDE.md").write_text("Public product instructions\n")
        manifest = {**self.fixture.manifest, "approvals": [self.export_path_review("AGENTS.md")]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.fixture.commit("Review one public instruction file")
        self.assert_status(self.cli("plan"), "PASS")
        paths = (self.run / "public-export.txt").read_text().splitlines()
        self.assertIn("AGENTS.md", paths)
        self.assertNotIn("CLAUDE.md", paths)
        (self.run / "public-export.txt").write_text("\n".join(paths + ["CLAUDE.md"]) + "\n")
        self.assert_status(self.cli("check", "--verify"), "INCOMPLETE", "allowlist-path")
        (self.run / "public-export.txt").write_text("\n".join(paths) + "\n")
        self.assert_status(self.cli("check", "--verify", real=True), "PASS")
        (self.repo / "AGENTS.md").write_text("Changed instructions\n")
        self.assert_status(self.cli("export", "--verify"), "INCOMPLETE", "allowlist-path")

    def test_export_path_review_rejects_globs_wrong_digests_and_missing_reasons(self):
        (self.repo / "AGENTS.md").write_text("Public product instructions\n")
        self.fixture.commit("Add public instructions")
        self.run.mkdir(parents=True)
        paths = workflow.proposed_paths(self.repo, self.fixture.manifest) + ["AGENTS.md"]
        (self.run / "public-export.txt").write_text("\n".join(paths) + "\n")
        for changes in ({"path": "AGENTS*"}, {"source_sha256": "0" * 64},
                        {"reason": ""}, {"scope": "history"}, {"source_sha256": None}):
            with self.subTest(changes=changes):
                manifest = {**self.fixture.manifest,
                            "approvals": [self.export_path_review("AGENTS.md", **changes)]}
                (self.repo / "release-check.json").write_text(json.dumps(manifest))
                self.assert_status(self.cli("plan"), "INCOMPLETE", "allowlist-path")

    def test_export_path_triage_is_applied_before_plan_check_and_approve(self):
        (self.repo / "AGENTS.md").write_text("Public product instructions\n")
        self.fixture.commit("Add public instructions")
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
                manifest = {**self.fixture.manifest, "approvals": [self.export_path_review("AGENTS.md")]}
                (self.repo / "release-check.json").write_text(json.dumps(manifest))
                self.fixture.commit("Review synthetic sensitive bytes")
                run = "sensitive" + str(number)
                self.assert_status(self.cli("plan", run=run), "PASS")
                with patch.object(rc, "verify", side_effect=verified), redirect_stderr(io.StringIO()):
                    result = self.assert_status(self.cli("check", "--verify", run=run), "FAIL")
                attempt = self.repo / ".coldrelease/runs" / run / "attempts" / result["attempt"]
                report = workflow.read_json(attempt / "report.json")
                self.assertTrue(any(not f["reviewed"] and f["kind"] == ("denylist" if number == 0 else "github-token")
                                    for f in report["findings"]))

    def test_export_path_review_cannot_admit_untracked_excluded_or_symlink_files(self):
        for path in ("AGENTS.md", ".env"):
            (self.repo / path).write_text("Public fixture\n")
        manifest = {**self.fixture.manifest,
                    "approvals": [self.export_path_review(path) for path in ("AGENTS.md", ".env")]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.run.mkdir(parents=True)
        original = workflow.proposed_paths(self.repo, self.fixture.manifest)
        for path in ("AGENTS.md", ".env", "../outside"):
            (self.run / "public-export.txt").write_text("\n".join(original + [path]) + "\n")
            self.assert_status(self.cli("plan"), "INCOMPLETE", "allowlist-path")
        self.fixture.commit("Track public instructions")
        (self.run / "public-export.txt").write_text("\n".join(original + [".env"]) + "\n")
        self.assert_status(self.cli("plan"), "INCOMPLETE", "allowlist-path")
        (self.run / "public-export.txt").write_text("\n".join(original + ["AGENTS.md"]) + "\n")
        (self.repo / "AGENTS.md").unlink()
        (self.repo / "AGENTS.md").symlink_to(self.repo / "README.md")
        self.assert_status(self.cli("plan"), "INCOMPLETE", "allowlist-file")

    def test_export_path_review_rechecks_the_actual_staged_bytes(self):
        (self.repo / "AGENTS.md").write_text("Reviewed public instructions\n")
        manifest = {**self.fixture.manifest, "approvals": [self.export_path_review("AGENTS.md")]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.fixture.commit("Review public instructions")
        original_copy = rc.copy_tree
        def copy_then_change(repo, target, *args, **kwargs):
            original_copy(repo, target, *args, **kwargs)
            (target / "AGENTS.md").write_text("Unreviewed replacement\n")
        with patch.object(rc, "copy_tree", side_effect=copy_then_change):
            self.assert_status(self.cli("plan"), "INCOMPLETE", "allowlist-path")

    def test_export_path_review_rejects_git_normalized_committed_bytes(self):
        (self.repo / ".gitattributes").write_text("AGENTS.md text\n")
        (self.repo / "AGENTS.md").write_bytes(b"Public instructions\r\n")
        manifest = {**self.fixture.manifest, "approvals": [self.export_path_review("AGENTS.md")]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.fixture.commit("Review source before Git normalization")
        self.assertEqual(rc.git(self.repo, "show", "HEAD:AGENTS.md"), b"Public instructions\n")
        self.assert_status(self.cli("plan"), "PASS")
        self.assert_status(self.cli("export", "--verify"), "INCOMPLETE", "allowlist-path")

    def test_signed_scanner_selection_cannot_be_removed_from_mutable_plan(self):
        result = {"name": "gitleaks", "outcome": "PASS", "version": "synthetic", "output_sha256": "a" * 64}
        def scan(attempt, name, receipt, timeout, repo):
            return {**result, "export_head": receipt["export_head"], "export_tree": receipt["export_tree"]}
        with patch.object(workflow, "scan_export", side_effect=scan):
            attempt = self.export(("gitleaks",))
        self.prepare()
        self.sign()
        (self.run / "plan.json").write_text('{"scanners":[]}')
        (attempt / "scanners.json").write_text('[]')
        self.assert_status(self.cli("publish", *self.trust_flags()), "INCOMPLETE", "scanner-selection")
        self.assertEqual(self.remote_head(), "")

    def test_scanner_digest_and_head_must_match_signed_record(self):
        def scan(attempt, name, receipt, timeout, repo):
            return {"name": name, "outcome": "PASS", "version": "synthetic", "output_sha256": "a" * 64,
                    "export_head": receipt["export_head"], "export_tree": receipt["export_tree"]}
        with patch.object(workflow, "scan_export", side_effect=scan):
            attempt = self.export(("gitleaks",))
        self.prepare()
        self.sign()
        results = workflow.read_json(attempt / "scanners.json")
        results[0]["output_sha256"] = "b" * 64
        (attempt / "scanners.json").write_text(json.dumps(results))
        self.assert_status(self.cli("publish", *self.trust_flags()), "INCOMPLETE", "approval-scanners")
        results[0]["export_head"] = "a" * 40
        (attempt / "scanners.json").write_text(json.dumps(results))
        self.assert_status(self.cli("publish", *self.trust_flags()), "INCOMPLETE", "scanner-not-pass")
        self.assertEqual(self.remote_head(), "")

    def test_target_ref_and_new_ref_lease(self):
        attempt = self.export()
        self.prepare()
        self.sign()
        other = self.root / "other.git"
        subprocess.run(["git", "init", "-q", "--bare", str(other)], check=True, capture_output=True)
        self.assert_status(self.cli("publish", *self.trust_flags(other)), "INCOMPLETE", "approval-target")
        self.assert_status(self.cli("publish", *self.trust_flags(ref="refs/heads/other")), "INCOMPLETE", "approval-ref")
        rc.git(self.repo, "push", str(self.remote), "HEAD:refs/heads/main")
        old = self.remote_head()
        self.assert_status(self.cli("publish", *self.trust_flags()), "INCOMPLETE", "target-moved")
        self.assertEqual(self.remote_head(), old)
        self.assertNotEqual(old, workflow.read_json(attempt / "receipt.json")["export_head"])

    def test_existing_ref_replacement_uses_lease_and_exact_receipt_commit(self):
        rc.git(self.repo, "push", str(self.remote), "HEAD:refs/heads/main")
        attempt = self.export()
        old = self.remote_head()
        self.prepare()
        self.sign()
        self.assertEqual(workflow.read_json(self.run / "approval.json")["expected_public_head"], old)
        self.assert_status(self.cli("publish", *self.trust_flags()), "PASS")
        self.assertEqual(self.remote_head(), workflow.read_json(attempt / "receipt.json")["export_head"])

    def test_remote_race_is_stopped_by_git_lease(self):
        self.export()
        self.prepare()
        self.sign()
        original = rc.git
        raced = []
        def git(repo, *args, **kwargs):
            if "push" in args and "--porcelain" in args:
                original(self.repo, "push", str(self.remote), "HEAD:refs/heads/main")
                raced.append(True)
            return original(repo, *args, **kwargs)
        with patch.object(rc, "git", side_effect=git):
            self.assert_status(self.cli("publish", *self.trust_flags()), "INCOMPLETE", "git-read-failed")
        self.assertEqual(raced, [True])
        self.assertEqual(self.remote_head(), self.fixture.git("rev-parse", "HEAD").decode().strip())

    def test_untrusted_signature_and_trust_file_inside_source_are_rejected(self):
        self.export()
        self.prepare()
        self.sign()
        self.trust.chmod(0o600)
        self.trust.write_text("other " + self.key.with_suffix(".pub").read_text())
        self.trust.chmod(0o400)
        self.assert_status(self.cli("publish", *self.trust_flags()), "INCOMPLETE", "approval-signature")
        inside = self.repo / "allowed-signers"
        inside.write_bytes(self.trust.read_bytes())
        self.assert_status(self.cli("publish", *self.trust_flags(), "--allowed-signers", str(inside)), "INCOMPLETE", "allowed-signers-location")
        self.assertEqual(self.remote_head(), "")

    def test_policy_changes_and_unverified_exports_cannot_be_approved(self):
        self.export()
        self.assert_status(self.cli("approve", *[f for f in self.trust_flags() if f != "--verify"]), "INCOMPLETE", "receipt-stale")
        self.assert_status(self.cli("approve", *self.trust_flags(), "--timeout", "301"), "INCOMPLETE", "receipt-stale")
        self.fixture.denylist.write_bytes(self.fixture.denylist.read_bytes() + b"\n")
        self.assert_status(self.cli("approve", *self.trust_flags()), "INCOMPLETE", "receipt-stale")

    def test_byte_bound_triage_carries_across_runs_and_expires_on_change(self):
        text = ('Public contact: help' + '@example.org\n')
        (self.repo / "contact.txt").write_text(text)
        self.fixture.commit("Add documented synthetic contact")
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
            self.assert_status(self.cli("check", "--verify", run="second"), "FAIL")

    def test_allowlist_diff_since_verified_approval(self):
        self.export()
        self.prepare()
        self.sign()
        (self.repo / "new.txt").write_text("Public fixture")
        self.fixture.commit("Add public file")
        self.assert_status(self.cli("plan", run="second"), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            self.assert_status(self.cli("export", "--verify", run="second"), "PASS")
        record = self.assert_status(self.cli("approve", *self.trust_flags(), run="second"), "PASS")
        self.assertEqual(record["allowlist_diff"], {"added": ["new.txt"], "removed": []})

    def test_selected_missing_scanner_blocks_approval(self):
        self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")
        with patch.object(rc, "verify", side_effect=verified), patch.object(workflow.shutil, "which", return_value=None):
            result = self.assert_status(self.cli("export", "--verify"), "INCOMPLETE")
        self.assertEqual(result["scanners"], [{"name": "gitleaks", "outcome": "INCOMPLETE"}])
        self.assert_status(self.cli("approve", *self.trust_flags()), "INCOMPLETE", "scanner-not-pass")

    def test_writable_trust_and_changed_recipe_block_approval(self):
        self.export()
        self.trust.chmod(0o600)
        self.assert_status(self.cli("approve", *self.trust_flags()), "INCOMPLETE", "allowed-signers-writable")
        self.trust.chmod(0o400)
        manifest = self.repo / "release-check.json"
        obj = json.loads(manifest.read_text())
        obj["exclude"] = ["unrelated-file"]
        manifest.write_text(json.dumps(obj))
        self.assert_status(self.cli("approve", *self.trust_flags()), "INCOMPLETE", "recipe-changed")

    def test_historical_attribution_must_survive_allowlist(self):
        (self.repo / "NOTICE").write_text("Required upstream attribution")
        self.fixture.commit("Add attribution")
        self.fixture.git("rm", "NOTICE")
        self.fixture.git("commit", "-q", "-m", "Remove attribution")
        self.assert_status(self.cli("plan"), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            result = self.assert_status(self.cli("export", "--verify"), "FAIL")
        report = workflow.read_json(self.run / "attempts" / result["attempt"] / "report.json")
        self.assertIn("historical-attribution-missing", report["reasons"])
        self.assert_status(self.cli("approve", *self.trust_flags()), "INCOMPLETE", "historical-attribution-missing")

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
report.write_text('[{"Secret":"fixture-only-sensitive-marker"}]')
sys.exit(1)
"""
        binary.write_text('#!' + sys.executable + '\n' + 'EXPORT = ' + repr(str(attempt / 'export')) + '\nHEAD = ' + repr(receipt['export_head']) + '\n' + script)
        binary.chmod(0o700)
        with patch.object(workflow.shutil, "which", return_value=str(binary)):
            result = workflow.scan_export(attempt, "gitleaks", receipt, 300, self.repo)
        self.assertEqual(result["outcome"], "FAIL")
        self.assertEqual(result["export_head"], receipt["export_head"])
        self.assertEqual(result["version"], "synthetic-scanner-version")
        self.assertNotIn("fixture-only-sensitive-marker", json.dumps(result))
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
            ([{"msg": "finished scanning"}, {"DetectorName": "Synthetic", "Raw": "fixture-only-sensitive-marker"}], 183, "FAIL"),
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
                self.assertNotIn("fixture-only-sensitive-marker", json.dumps(result))

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

    def test_signed_record_edits_and_remote_alias_changes_are_rejected(self):
        self.export()
        self.prepare()
        self.sign()
        approval = self.run / "approval.json"
        raw = approval.read_bytes()
        try:
            record = json.loads(raw)
            record["scanners"] = [{"name": "gitleaks", "result_sha256": "a" * 64}]
            approval.write_text(json.dumps(record))
            self.assert_status(self.cli("publish", *self.trust_flags()), "INCOMPLETE", "approval-signature")
        finally:
            approval.write_bytes(raw)
        self.fixture.git("remote", "add", "public", str(self.remote))
        flags = self.trust_flags()
        flags[flags.index(str(self.remote))] = "public"
        self.fixture.git("remote", "set-url", "--push", "public", str(self.root / "wrong.git"))
        self.assert_status(self.cli("publish", *flags), "INCOMPLETE", "approval-target")
        self.assertEqual(self.remote_head(), "")

    def test_hash_prefixed_tracked_filename_is_an_exact_allowlist_entry(self):
        (self.repo / "#public.txt").write_text("Public fixture")
        self.fixture.commit("Add unusual public filename")
        attempt = self.export()
        self.assertEqual((attempt / "export/#public.txt").read_text(), "Public fixture")

    def test_publish_consumes_the_exact_bytes_verified_by_ssh(self):
        self.export()
        self.prepare()
        self.sign()
        other = self.root / "other.git"
        subprocess.run(["git", "init", "-q", "--bare", str(other)], check=True, capture_output=True)
        original = subprocess.run
        def replaced(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv[:3] == ["ssh-keygen", "-Y", "verify"] and result.returncode == 0:
                record = workflow.read_json(self.run / "approval.json")
                record["target"] = str(other)
                (self.run / "approval.json").write_text(json.dumps(record))
            return result
        with patch.object(workflow.subprocess, "run", side_effect=replaced):
            self.assert_status(self.cli("publish", *self.trust_flags(other)), "INCOMPLETE", "approval-target")
        self.assertEqual(rc.git(self.repo, "ls-remote", "--refs", str(other)), b"")
        self.assertEqual(self.remote_head(), "")

    def test_private_run_id_is_redacted_in_output(self):
        result = self.assert_status(self.cli("preflight", run="HiddenPerson"), "PASS")
        self.assertNotIn("HiddenPerson", json.dumps(result))
        self.assertTrue(result["run"].startswith("[path-"))

    def test_publish_pushes_receipt_head_when_head_moves_after_final_validation(self):
        attempt = self.export()
        receipt_head = workflow.read_json(attempt / "receipt.json")["export_head"]
        self.prepare()
        self.sign()
        original = rc.git
        moved = []
        def git(repo, *args, **kwargs):
            if "push" in args and "--porcelain" in args:
                original(repo, "-c", "user.name=Synthetic", "-c", "user.email=fixture", "-c", "commit.gpgsign=false",
                         "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "Move mutable HEAD")
                moved.append(original(repo, "rev-parse", "HEAD").decode().strip())
            return original(repo, *args, **kwargs)
        with patch.object(rc, "git", side_effect=git):
            self.assert_status(self.cli("publish", *self.trust_flags()), "PASS")
        self.assertEqual(len(moved), 1)
        self.assertNotEqual(moved[0], receipt_head)
        self.assertEqual(self.remote_head(), receipt_head)

    def test_agent_state_notes_are_excluded_without_excluding_application_source(self):
        (self.repo / "STATE_private.md").write_text("Local agent state")
        (self.repo / "state.py").write_text("value = 4\n")
        self.fixture.commit("Separate app source from agent notes")
        attempt = self.export()
        self.assertEqual((attempt / "export/state.py").read_text(), "value = 4\n")
        self.assertFalse((attempt / "export/STATE_private.md").exists())

    def test_unplanned_tracked_symlinks_do_not_block_planned_snapshot(self):
        (self.repo / "before-link").symlink_to("README.md")
        self.fixture.git("add", "before-link")
        self.fixture.git("commit", "-q", "-m", "Add unsupported source link")
        self.assert_status(self.cli("plan"), "PASS")
        self.assertNotIn("before-link", (self.run / "public-export.txt").read_text().splitlines())
        (self.repo / "after-link").symlink_to("README.md")
        self.fixture.git("add", "after-link")
        self.fixture.git("commit", "-q", "-m", "Add unplanned source link")
        with patch.object(rc, "verify", side_effect=verified):
            self.assert_status(self.cli("check", "--verify"), "PASS")
            self.assert_status(self.cli("export", "--verify"), "PASS")
        (self.run / "public-export.txt").write_text((self.run / "public-export.txt").read_text() + "after-link\n")
        self.assert_status(self.cli("check", "--verify"), "INCOMPLETE", "allowlist-file")

    def test_cli_legacy_audit_accepts_repository_named_check(self):
        target = self.root / "check"
        self.repo.rename(target)
        process = subprocess.run([sys.executable, rc.__file__, "check", "--denylist", str(self.fixture.denylist),
                                  "--reports", str(self.root / "legacy-reports"), "--verify"],
                                 cwd=self.root, capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(json.loads(process.stdout)["outcome"], "PASS")

    def test_dependency_triage_clears_preflight_and_carries_to_next_plan(self):
        package = {"name": "fixture", "version": "1.0.0", "license": "MIT", "dependencies": {"example": "^1.0.0"}}
        lock = {"lockfileVersion": 3, "name": "fixture", "version": "1.0.0", "packages": {
            "": package, "node_modules/example": {"version": "1.0.0", "license": "MIT",
                "resolved": "https://registry.npmjs.org/example/-/example-1.0.0.tgz",
                "integrity": "sha512-" + "A" * 86 + "=="}}}
        (self.repo / "package.json").write_text(json.dumps(package))
        (self.repo / "package-lock.json").write_text(json.dumps(lock))
        self.fixture.commit("Add source dependency declarations")
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
        self.fixture.commit("Add historical attribution")
        self.fixture.git("rm", "NOTICE")
        self.fixture.git("commit", "-q", "-m", "Remove attribution from current tree")
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
        self.fixture.git("config", "url." + str(redirected) + ".insteadOf", str(self.remote))
        self.prepare()
        self.sign()
        self.assert_status(self.cli("publish", *self.trust_flags()), "PASS")
        export = attempt / "export"
        head = workflow.read_json(attempt / "receipt.json")["export_head"]
        self.assertEqual(rc.git(export, "ls-remote", "--refs", str(self.remote), "refs/heads/main").decode().split("\t")[0], head)
        self.assertEqual(rc.git(export, "ls-remote", "--refs", str(redirected)), b"")

    def test_initial_allowlist_can_exclude_unsupported_private_ecosystem(self):
        (self.repo / "Cargo.toml").write_text('[package]\nname = "private-part"\nversion = "0.1.0"\n')
        self.fixture.commit("Add unrelated private ecosystem")
        self.assert_status(self.cli("preflight"), "INCOMPLETE")
        selected = [p for p in workflow.proposed_paths(self.repo, self.fixture.manifest) if p != "Cargo.toml"]
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
            self.assert_status(self.cli("approve", *self.trust_flags()), "INCOMPLETE", "workflow-incomplete")
        self.assertFalse((self.run / ".lock").exists())
        self.prepare()
        self.sign()
        def stall_push(argv, **kwargs):
            if "push" in argv and "--porcelain" in argv:
                self.assertEqual(kwargs.get("timeout"), 300)
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            return original(argv, **kwargs)
        with patch.object(rc.subprocess, "run", side_effect=stall_push):
            self.assert_status(self.cli("publish", *self.trust_flags()), "INCOMPLETE", "workflow-incomplete")
        self.assertFalse((self.run / ".lock").exists())
        self.assertEqual(self.remote_head(), "")


if __name__ == "__main__":
    unittest.main()
