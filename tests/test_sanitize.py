from contextlib import redirect_stdout
import io
import json
import subprocess
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
import test_release_check as fixtures
from test_metadata_scan import TERM, jpeg, tiff


def verified(*args, **kwargs):
    return {"status": "pass", "commands": [], "dependencies": {"blocked": 0}}


class SanitizeTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        self.repo = self.testbed.repo
        self.run = workflow.run_directory(self.repo, "first")

    def cli(self, command, *extra):
        output = io.StringIO()
        with redirect_stdout(output):
            code = rc.main([command, str(self.repo), "--denylist", str(self.testbed.denylist), "--run", "first", *extra])
        return code, json.loads(output.getvalue())

    def assert_status(self, result, status, reason=None):
        code, value = result
        self.assertEqual(value["outcome"], status, value)
        self.assertEqual(code, {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[status], value)
        if reason:
            self.assertIn(reason, value["reasons"])
        return value

    def transforms(self, items):
        self.run.mkdir(parents=True, exist_ok=True)
        (self.run / "transforms.json").write_text(json.dumps(items))

    def source_state(self):
        status = self.testbed.git("status", "--porcelain", "--untracked-files=all", "--ignored")
        hashes = {p.relative_to(self.repo).as_posix(): rc.sha256(p.read_bytes())
                  for p in sorted(self.repo.rglob("*")) if p.is_file()}
        return status, hashes

    def unsafe_source(self, *plan):
        (self.repo / "docs").mkdir()
        (self.repo / "docs/guide.md").write_text("Guide by HiddenPerson.\n")
        (self.repo / "notes").mkdir()
        (self.repo / "notes/draft.txt").write_text("Draft for HiddenPerson\n")
        self.testbed.commit("Unsafe synthetic testbed")
        (self.repo / ".env").write_text("API_TOKEN=abc123SECRETvalue\nexport DEBUG = 1\n")
        self.assert_status(self.cli("preflight"), "PASS")
        self.assert_status(self.cli("plan", *plan), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            checked = self.assert_status(self.cli("check", "--verify"), "FAIL")
        findings = workflow.read_json(self.run / "attempts" / checked["attempt"] / "report.json")["findings"]
        self.assertEqual({f["path"] for f in findings if not f["reviewed"]}, {"docs/guide.md", "notes/draft.txt"})
        fingerprint = next(f["fingerprint"] for f in findings if f["path"] == "docs/guide.md" and f["kind"] == "denylist")
        self.transforms([{"op": "drop", "path": "notes/draft.txt"},
                         {"op": "replace", "path": "docs/guide.md", "fingerprint": fingerprint, "placeholder": "[author]"},
                         {"op": "env-example"}])

    def sanitized_export(self):
        self.unsafe_source()
        before = self.source_state()
        sanitized = self.assert_status(self.cli("sanitize"), "PASS")
        self.assertEqual([c["op"] for c in sanitized["changes"]], ["drop", "replace", "env-example"])
        self.assertEqual(self.source_state(), before)
        self.assert_status(self.cli("preflight"), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            self.assert_status(self.cli("check", "--verify"), "PASS")
            self.assert_status(self.cli("export", "--verify"), "PASS")
        self.assertEqual(self.source_state(), before)
        return self.run / "attempts" / workflow.read_json(self.run / "export.json")["attempt"]

    def test_export_passes_when_transforms_are_the_only_fixes_and_the_source_is_untouched(self):
        attempt = self.sanitized_export()
        export = attempt / "export"
        self.assertEqual((export / "docs/guide.md").read_text(), "Guide by [author].\n")
        self.assertFalse((export / "notes").exists())
        self.assertEqual((export / ".env.example").read_text(), "API_TOKEN=\nDEBUG=\n")
        self.assertIn(".env.example", workflow.read_json(attempt / "allowlist.json"))
        self.assertEqual((self.repo / "docs/guide.md").read_text(), "Guide by HiddenPerson.\n")
        self.assertTrue((self.repo / "notes/draft.txt").is_file())
        receipt = workflow.read_json(attempt / "receipt.json")
        self.assertEqual(receipt["source_head"], self.testbed.git("rev-parse", "HEAD").decode().strip())
        changes = workflow.read_json(attempt / "changes.json")
        self.assertEqual(changes, workflow.read_json(self.run / "changes.json"))
        self.assertEqual([(c["op"], c["path"]) for c in changes["changes"]],
                         [("drop", "notes/draft.txt"), ("replace", "docs/guide.md"), ("env-example", ".env.example")])
        self.assertEqual(changes["changes"][2]["keys"], ["API_TOKEN", "DEBUG"])
        for path in (attempt / "changes.json", *(self.run / "candidate").rglob("*")):
            if path.is_file():
                self.assertNotIn(b"abc123SECRETvalue", path.read_bytes())
                self.assertNotIn(b"HiddenPerson", path.read_bytes())

    def test_strip_metadata_clears_the_exif_author_in_the_candidate_only(self):
        photo = jpeg(tiff({0x013B: TERM}, {0x9C9D: TERM}))
        (self.repo / "photo.jpg").write_bytes(photo)
        self.testbed.commit("Photo testbed")
        self.assert_status(self.cli("preflight"), "PASS")
        self.assert_status(self.cli("plan"), "PASS")

        def unreviewed(status):
            with patch.object(rc, "verify", side_effect=verified):
                checked = self.assert_status(self.cli("check", "--verify"), status)
            report = workflow.read_json(self.run / "attempts" / checked["attempt"] / "report.json")
            return {(f["kind"], f["path"]) for f in report["findings"] if not f["reviewed"]}

        self.assertIn(("denylist", "photo.jpg!metadata"), unreviewed("FAIL"))
        self.transforms([{"op": "strip-metadata", "path": "photo.jpg"}])
        before = self.source_state()
        sanitized = self.assert_status(self.cli("sanitize"), "PASS")
        self.assertEqual([(c["op"], c["path"]) for c in sanitized["changes"]], [("strip-metadata", "photo.jpg")])
        self.assertEqual(self.source_state(), before)
        self.assertEqual((self.repo / "photo.jpg").read_bytes(), photo)
        self.assert_status(self.cli("preflight"), "PASS")
        self.assertEqual(unreviewed("INCOMPLETE"), {("manual-review", "photo.jpg")})

    def test_strip_metadata_and_add_in_one_plan_share_the_protection_rule(self):
        (self.repo / "NOTICE.jpg").write_bytes(jpeg(tiff({0x013B: TERM}, {0x9C9D: TERM})))
        self.testbed.commit("Protected photo testbed")
        plan = [{"op": "strip-metadata", "path": "NOTICE.jpg"}, {"op": "drop", "path": "LICENSE"},
                {"op": "add", "template": "ISC", "holder": "2026 Testbed Contributors"}]
        for unapproved in (0, 2):
            with self.subTest(unapproved=plan[unapproved]["op"]):
                self.transforms([{**item, **({} if i == unapproved else {"approve_protected": True})} for i, item in enumerate(plan)])
                self.assert_status(self.cli("sanitize"), "INCOMPLETE", "transform-protected")
                self.assertFalse((self.run / "changes.json").exists())
        self.transforms([{**item, "approve_protected": True} for item in plan])
        self.assert_status(self.cli("sanitize"), "PASS")
        changes = workflow.read_json(self.run / "changes.json")["changes"]
        self.assertEqual([(c["op"], c["path"], c.get("approved_protected")) for c in changes],
                         [("strip-metadata", "NOTICE.jpg", True), ("drop", "LICENSE", True), ("add", "LICENSE", True)])
        for change in (changes[0], changes[2]):
            self.assertEqual(rc.sha256((self.run / "candidate" / change["path"]).read_bytes()), change["after_sha256"])
        self.assertEqual(rc.root_licence((self.run / "candidate/LICENSE").read_text()), "ISC")

    def test_approval_binds_the_changes_and_publish_refuses_other_changes(self):
        home = self.testbed.root / "owner-home"
        (home / ".coldlocker").mkdir(parents=True)
        (home / ".coldlocker/release-denylist.sha256").write_text(rc.sha256(self.testbed.denylist.read_bytes()) + "\n")
        self.enterContext(patch.dict("os.environ", {"HOME": str(home)}))

        def scanned(attempt, name, receipt, timeout, repo):
            return {"name": name, "outcome": "PASS", "version": "synthetic", "output_sha256": "a" * 64,
                    "export_head": receipt["export_head"], "export_tree": receipt["export_tree"]}
        with patch.object(workflow, "scan_export", side_effect=scanned), patch.object(workflow.shutil, "which", return_value=None):
            self.unsafe_source("--scanner", "gitleaks")
            self.assert_status(self.cli("sanitize"), "PASS")
            with patch.object(rc, "verify", side_effect=verified):
                self.assert_status(self.cli("check", "--verify"), "PASS")
                self.assert_status(self.cli("export", "--verify"), "PASS")
        attempt = self.run / "attempts" / workflow.read_json(self.run / "export.json")["attempt"]
        remote = self.testbed.root / "public.git"
        subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True, capture_output=True)
        flags = ["--verify", "--target", str(remote)]
        self.assert_status(self.cli("approve", *flags), "PASS")
        record = workflow.read_json(self.run / "approval.json")
        self.assertEqual(record["changes_sha256"], rc.sha256((attempt / "changes.json").read_bytes()))
        subprocess.run(workflow.push_command(self.run, record), check=True, capture_output=True)
        approved = (attempt / "changes.json").read_bytes()
        (attempt / "changes.json").write_bytes(approved.replace(b"[author]", b"[editor]"))
        self.assert_status(self.cli("publish", *flags), "INCOMPLETE", "approval-changes")
        self.assertFalse((self.run / "published.json").exists())
        (attempt / "changes.json").write_bytes(approved)
        self.assert_status(self.cli("publish", *flags), "PASS")

    def test_candidate_must_match_its_transforms_and_its_recorded_tree(self):
        self.unsafe_source()
        self.assert_status(self.cli("sanitize"), "PASS")
        (self.run / "candidate/docs/guide.md").write_text("Guide by HiddenPerson.\n")
        self.assert_status(self.cli("preflight"), "INCOMPLETE", "candidate-changed")
        self.assert_status(self.cli("sanitize"), "PASS")
        self.assert_status(self.cli("preflight"), "PASS")
        self.transforms([{"op": "drop", "path": "notes/draft.txt"}])
        self.assert_status(self.cli("preflight"), "INCOMPLETE", "candidate-stale")
        (self.run / "changes.json").unlink()
        self.assert_status(self.cli("preflight"), "INCOMPLETE", "candidate-incomplete")

    def test_protected_and_check_files_need_explicit_approval(self):
        (self.repo / "AUTHORS").write_text("Testbed contributors\n")
        self.testbed.commit("Add authors")
        before = self.source_state()
        cases = [([{"op": "drop", "path": "LICENSE"}], "transform-protected"),
                 ([{"op": "drop", "path": "AUTHORS"}], "transform-protected"),
                 ([{"op": "drop", "path": "README.md"}], "transform-protected"),
                 ([{"op": "drop", "path": "tests/test_testbed.py"}], "transform-protected"),
                 ([{"op": "replace", "path": "CONTRIBUTING.md", "fingerprint": "0" * 16, "placeholder": "x"}], "transform-not-found"),
                 ([{"op": "drop", "path": "missing.txt"}], "transform-path"),
                 ([{"op": "strip-metadata", "path": "CONTRIBUTING.md"}], "transform-not-image"),
                 ([{"op": "env-example"}], "env-keys-missing"),
                 ([{"op": "drop", "path": "SECURITY.md", "approve_protected": False}], "transforms-schema"),
                 ([], "transforms-schema")]
        for items, reason in cases:
            with self.subTest(items=items):
                self.transforms(items)
                self.assert_status(self.cli("sanitize"), "INCOMPLETE", reason)
                self.assertFalse((self.run / "candidate").exists())
                self.assertFalse((self.run / "changes.json").exists())
        self.transforms([{"op": "drop", "path": "LICENSE", "approve_protected": True}])
        self.assert_status(self.cli("sanitize"), "PASS")
        self.assertEqual(workflow.read_json(self.run / "changes.json")["changes"][0]["approved_protected"], True)
        self.assertEqual(self.source_state(), before)

    def test_a_check_added_after_sanitize_needs_the_transform_approved(self):
        self.transforms([{"op": "drop", "path": "SECURITY.md"}])
        self.assert_status(self.cli("sanitize"), "PASS")
        paths = workflow.read_json(self.run / "changes.json")["source_paths"]
        self.assertEqual(workflow.scan_target(self.repo, self.run, paths, self.testbed.manifest)[0], self.run / "candidate")
        manifest = {**self.testbed.manifest, "checks": [{"role": "lint", "argv": ["python", "-c", "print(1)", "SECURITY.md"]}]}
        with self.assertRaises(rc.AuditError) as caught:
            workflow.scan_target(self.repo, self.run, paths, manifest)
        self.assertEqual(str(caught.exception), "transform-protected")

    def test_env_example_keeps_the_keys_of_an_existing_env_example(self):
        (self.repo / ".env.example").write_text("API_TOKEN=\n")
        self.transforms([{"op": "env-example"}])
        self.assert_status(self.cli("sanitize"), "PASS")
        self.assertEqual((self.run / "candidate/.env.example").read_text(), "API_TOKEN=\n")

    def test_a_file_named_in_a_check_option_is_protected(self):
        manifest = {**self.testbed.manifest, "checks": [{"role": "tests", "argv": ["pytest", "--config=tests/settings.ini"]}]}
        self.assertTrue(workflow.named_in_checks(manifest, "tests/settings.ini"))
        self.assertFalse(workflow.named_in_checks(manifest, "tests/other.ini"))

    def test_only_a_blank_env_example_escapes_the_credential_file_rule(self):
        for raw, flagged in ((b"API_TOKEN=\nDEBUG=\n", False), (b"API_TOKEN=value\n", True), (b"# note\nAPI_TOKEN=\n", True)):
            with self.subTest(raw=raw):
                scanner = rc.Scanner([])
                scanner.file(raw, "tree", ".env.example")
                self.assertEqual(any(f["kind"] == "credential-file" for f in scanner.findings), flagged)
        for path in (".env", "private/.env.example", "settings/.env.example"):
            with self.subTest(path=path):
                scanner = rc.Scanner([])
                scanner.file(b"API_TOKEN=\n", "tree", path)
                self.assertTrue(any(f["kind"] == "credential-file" for f in scanner.findings))

    def test_a_blank_env_example_outside_the_root_stays_forbidden(self):
        (self.repo / "private").mkdir()
        (self.repo / "private/.env.example").write_text("API_TOKEN=\n")
        self.testbed.commit("Nested env example")
        with self.assertRaises(rc.AuditError) as caught:
            workflow.validate_paths(self.repo, ["README.md", "private/.env.example"], self.testbed.manifest)
        self.assertEqual(str(caught.exception), "allowlist-path")

    def test_sanitize_refuses_a_legacy_run_inside_the_source(self):
        legacy = workflow.legacy_root(self.repo) / "first"
        legacy.mkdir(parents=True)
        (legacy / ".lock").write_text("")
        (legacy / "transforms.json").write_text(json.dumps([{"op": "drop", "path": "SECURITY.md"}]))
        before = sorted(p.relative_to(legacy).as_posix() for p in legacy.rglob("*"))
        self.assert_status(self.cli("sanitize"), "INCOMPLETE", "run-state-inside-source")
        self.assertEqual(sorted(p.relative_to(legacy).as_posix() for p in legacy.rglob("*")), before)

    def test_add_writes_chosen_templates_into_the_candidate_and_changes_json(self):
        self.testbed.git("rm", "-q", "CONTRIBUTING.md", "SECURITY.md", ".github/ISSUE_TEMPLATE/bug.yml")
        self.testbed.git("commit", "-q", "-m", "Remove documents")
        before = self.source_state()
        self.transforms([{"op": "drop", "path": "LICENSE", "approve_protected": True},
                         {"op": "add", "template": "Apache-2.0", "approve_protected": True},
                         {"op": "add", "template": "CONTRIBUTING"},
                         {"op": "add", "template": "SECURITY"},
                         {"op": "add", "template": "issue-template"}])
        self.assert_status(self.cli("sanitize"), "PASS")
        changes = workflow.read_json(self.run / "changes.json")["changes"]
        self.assertEqual([(c["op"], c["path"], c.get("template")) for c in changes],
                         [("drop", "LICENSE", None), ("add", "LICENSE", "Apache-2.0"),
                          ("add", "CONTRIBUTING.md", "CONTRIBUTING"), ("add", "SECURITY.md", "SECURITY"),
                          ("add", ".github/ISSUE_TEMPLATE/bug_report.md", "issue-template")])
        candidate = self.run / "candidate"
        for change in changes[1:]:
            self.assertEqual(rc.sha256((candidate / change["path"]).read_bytes()), change["after_sha256"])
        self.assertEqual(rc.root_licence((candidate / "LICENSE").read_text()), "Apache-2.0")
        self.assertEqual(self.source_state(), before)
        self.assert_status(self.cli("preflight"), "PASS")
        self.assert_status(self.cli("plan"), "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            checked = self.assert_status(self.cli("check", "--verify"), "PASS")
        report = workflow.read_json(self.run / "attempts" / checked["attempt"] / "report.json")
        self.assertEqual(report["license"]["identifier"], "Apache-2.0")

    def test_add_licence_with_a_holder(self):
        self.transforms([{"op": "drop", "path": "LICENSE", "approve_protected": True},
                         {"op": "add", "template": "BSD-3-Clause", "holder": "2026 Testbed Contributors", "approve_protected": True}])
        self.assert_status(self.cli("sanitize"), "PASS")
        change = workflow.read_json(self.run / "changes.json")["changes"][1]
        self.assertEqual(change["holder"], "2026 Testbed Contributors")
        self.assertEqual(rc.root_licence((self.run / "candidate/LICENSE").read_text()), "BSD-3-Clause")

    def test_add_rejects_bad_templates(self):
        drop = {"op": "drop", "path": "LICENSE", "approve_protected": True}
        cases = [([{"op": "add", "template": "GPL-3.0"}], "transforms-schema"),
                 ([{"op": "add", "template": "CONTRIBUTING", "path": "x"}], "transforms-schema"),
                 ([{"op": "add", "template": "CONTRIBUTING", "holder": "2026 A"}], "transforms-schema"),
                 ([{"op": "drop", "path": "SECURITY.md", "holder": "2026 A"}], "transforms-schema"),
                 ([drop, {"op": "add", "template": "MIT", "approve_protected": True}], "transforms-schema"),
                 ([drop, {"op": "add", "template": "MIT", "holder": "a\nb", "approve_protected": True}], "transforms-schema"),
                 ([drop, {"op": "add", "template": "MIT", "holder": "2026 lowercase holder; not a notice", "approve_protected": True}], "transform-holder"),
                 ([{"op": "add", "template": "MIT", "holder": "2026 A"}], "transform-protected"),
                 ([{"op": "add", "template": "MIT", "holder": "2026 A", "approve_protected": True}], "transform-path"),
                 ([{"op": "add", "template": "SECURITY"}], "transform-path")]
        for items, reason in cases:
            with self.subTest(items=items):
                self.transforms(items)
                self.assert_status(self.cli("sanitize"), "INCOMPLETE", reason)
                self.assertFalse((self.run / "changes.json").exists())


if __name__ == "__main__":
    unittest.main()
