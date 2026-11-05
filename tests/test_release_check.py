from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from unittest.mock import patch

import release_check as rc


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.denylist = self.root / "terms.json"
        self.denylist.write_text(json.dumps({"categories": {"family": {"placeholder": "private", "terms": ["HiddenPerson"]}}}))
        self.terms = rc.load_terms(self.denylist)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Fixture contributors")
        self.git("config", "user.email", "fixture")
        shutil.copyfile(Path(rc.__file__).with_name("LICENSE"), self.repo / "LICENSE")
        (self.repo / "README.md").write_text("# Fixture\n## Honest limitations\nSynthetic only.\npython -c 'print(1)'\n")
        (self.repo / "CONTRIBUTING.md").write_text("Run tests.")
        (self.repo / "SECURITY.md").write_text("Private reporting.")
        (self.repo / ".github/ISSUE_TEMPLATE").mkdir(parents=True)
        (self.repo / ".github/ISSUE_TEMPLATE/bug.yml").write_text("name: bug\n")
        (self.repo / "tests").mkdir()
        (self.repo / "tests/test_fixture.py").write_text("import unittest\nclass T(unittest.TestCase):\n def test_ok(self): self.assertEqual(2 + 2, 4)\n")
        self.manifest = {"exclude": [], "approvals": [], "quickstart": [{"file": "README.md", "line": 4, "argv": ["python", "-c", "print(1)"]}], "checks": [{"role": "tests", "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-q"]}]}
        (self.repo / "release-check.json").write_text(json.dumps(self.manifest))
        self.commit("Initial fixture")

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.repo), *args], check=True, capture_output=True).stdout

    def commit(self, message):
        files = [str(p.relative_to(self.repo)) for p in self.repo.rglob("*") if p.is_file() and ".git" not in p.relative_to(self.repo).parts]
        self.git("add", "--", *files)
        self.git("commit", "-q", "-m", message)

    def scan(self):
        scanner = rc.Scanner(self.terms)
        scanner.tree(self.repo)
        scanner.history(self.repo)
        return scanner

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = rc.main([str(self.repo), "--denylist", str(self.denylist), "--reports", str(self.root / "reports"), *args])
        return code, out.getvalue(), err.getvalue()

    def test_audit_error_reason_is_reported_and_stays_incomplete(self):
        code, out, err = self.run_cli("--reports", str(self.repo / "out"))
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err), {"outcome": "INCOMPLETE", "ready": False, "error": "reports-inside-source"})

    def test_unexpected_failure_reports_only_generic_error(self):
        with patch.object(rc, "manifest_for", side_effect=KeyError("PrivateDetail")):
            code, out, err = self.run_cli()
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(err), {"outcome": "INCOMPLETE", "ready": False, "error": "audit-incomplete", "detail": "KeyError"})
        self.assertNotIn("PrivateDetail", err)

    def test_short_aliases_detect_words_and_filenames_not_digest_substrings(self):
        scanner=rc.Scanner(['z07'])
        scanner.text(b'sha256:abcz07def https://files.pythonhosted.org/abz07cd/wheel.whl', 'tree', 'uv.lock')
        self.assertEqual(scanner.findings, [])
        scanner.text(b'z07\nZ07.example.test\n/units/tool-z07-9222.service', 'tree', 'config')
        self.assertEqual(len(scanner.findings), 3)
        scanner.file(b'', 'tree', 'tool-z07.service')
        self.assertTrue(any(f['kind']=='denylist' and f['path'].startswith('[path-') for f in scanner.findings))

    def test_full_history_names_metadata_and_case_insensitive_terms(self):
        (self.repo / "HIDDENPERSON.txt").write_text("hiddenperson\n")
        self.git("config", "user.name", "HiddenPerson")
        self.commit("Decided with hiddenperson")
        self.git("rm", "--", "HIDDENPERSON.txt")
        self.git("commit", "-q", "-m", "Remove file")
        scanner = self.scan()
        findings = [f for f in scanner.findings if f["kind"] == "denylist"]
        self.assertTrue(any(f["scope"] == "metadata" for f in findings))
        self.assertTrue(any(f["scope"] == "history" for f in findings))
        self.assertFalse(any(f["scope"] == "tree" for f in findings))
        raw = json.dumps(scanner.findings)
        self.assertNotIn("hiddenperson", raw.lower())
        self.assertTrue(all(f["term_index"] == 0 for f in findings))
        self.assertTrue(any(f["path"].startswith("[path-") for f in findings))

    def test_other_branch_and_deleted_blob(self):
        self.git("checkout", "-q", "-b", "old")
        (self.repo / "old.txt").write_text("HiddenPerson")
        self.commit("Old")
        self.git("checkout", "-q", "main")
        self.assertTrue(any(f["kind"] == "denylist" and f["scope"] == "history" for f in self.scan().findings))

    def test_builtin_network_and_personal_detectors(self):
        raw = ("demo@" + ('example.org\n+1 555-' + '123-4567\n192.0.2.1\n2001:db8::1\n100.64.3.4\nnode.ts.' + 'net\n/hom' + 'e/fakeuser/data\n' + 'C:\\Us' + 'ers\\fakeuser\\data\nnode.' + 'internal\nbuild-' + '07\nhttps://github.com/fake/' + 'private-repo\n')).encode()
        scanner = rc.Scanner(self.terms, ["fake/private-repo"])
        scanner.file(raw, "tree", "text.txt")
        kinds = {f["kind"] for f in scanner.findings}
        self.assertTrue({"email", "phone", "ipv4", "ipv6", "tailnet-ip", "tailnet-host", "home-path", "internal-host", "private-repo-url"} <= kinds)
        self.assertNotIn("fakeuser", json.dumps(scanner.findings))

    def test_github_noreply_emails_only(self):
        allowed = ("216775752+TayHCode@users.noreply.github.com", "1+some-login@users.noreply.github.com",
                   "noreply@github.com")
        blocked = (('pers' + ('on@e' + 'xample.org')), ('logi' + ('n@us' + 'ers.noreply.github.com')), ('1+lo' + ('gin@' + 'github.com')),
                   ('1+lo' + ('gin@' + 'users.noreply.github.com.evil.org')), ('nore' + ('ply@' + 'github.com.evil.org')),
                   ('othe' + ('r@gi' + 'thub.com')), ('nore' + ('ply+' + ('tag@' + 'github.com'))), ('id+l' + ('ogin' + '@users.noreply.github.com')),
                   ('1+ba' + ('d_lo' + 'gin' + '@users.noreply.github.com')), ('1+-l' + ('ogin' + '@users.noreply.github.com')),
                   ("first'nore" + ('ply@' + 'github.com')), ('first!nore' + ('ply@' + 'github.com')), ('first@nore' + ('ply@' + 'github.com')),
                   ('"nore' + ('ply@' + 'github.com"@example.org')), ('"nore' + ('ply@' + 'github.com extra"@example.org')),
                   "1+" + "a" * 40 + "@users.noreply.github.com")
        for email in allowed + blocked:
            with self.subTest(email=email):
                scanner = rc.Scanner([])
                scanner.text(f"Author: Fixture <{email}>\n".encode(), "metadata", "commit")
                self.assertEqual(len([f for f in scanner.findings if f["kind"] == "email"]),
                                 0 if email in allowed else 1)
        scanner = rc.Scanner(["TayHCode"])
        scanner.text(allowed[0].encode(), "tree", "README.md")
        self.assertTrue(any(f["kind"] == "denylist" for f in scanner.findings))
        self.git("config", "user.email", allowed[0])
        self.git("commit", "-q", "--allow-empty", "-m", "Noreply metadata")
        self.assertFalse(any(f["kind"] == "email" for f in self.scan().findings))

    def test_encoding_names_are_not_internal_hosts(self):
        for encoding in ("UTF-16", "utf-8", "utf-32", "ISO-8859-1", "iso-88",
                         "UCS-02", "cp-12", "latin-1", "latin-12"):
            with self.subTest(encoding=encoding):
                scanner = rc.Scanner(self.terms)
                scanner.file(f"Text encoding: {encoding}\n".encode(), "tree", "encodings.txt")
                self.assertEqual(scanner.findings, [])

    def test_internal_host_aliases_are_flagged(self):
        for alias in (('build' + '-07'), ('Build' + '-07'), ('desk' + '-02'), ('store' + '-03'), ('lab' + '-04')):
            with self.subTest(alias=alias):
                scanner = rc.Scanner(self.terms)
                scanner.file(alias.encode(), "tree", "hosts.txt")
                aliases = [f for f in scanner.findings if f["kind"] == "internal-host"]
                self.assertEqual([f["fingerprint"] for f in aliases], [rc.fingerprint(alias)])

    def test_secrets_values_never_reach_output_or_reports(self):
        secret = "gh" + "p_" + "Ab2C3d4E5f6G7h8I9j0K" + "lmNOPqRsTuvWxYz"
        (self.repo / "secret.txt").write_text("key=" + secret)
        self.commit("Test")
        code, out, err = self.run_cli("--scrub-plan")
        self.assertEqual(code, 1)
        self.assertNotIn(secret, out + err)
        reports = list((self.root / "reports").rglob("report.*"))
        self.assertEqual(len(reports), 2)
        for p in reports:
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertEqual(p.parent.stat().st_mode & 0o777, 0o700)
            self.assertNotIn(secret, p.read_text())
        report = json.loads(next(p for p in reports if p.suffix == ".json").read_text())
        self.assertGreater(report["counts"]["secrets"], 0)
        self.assertTrue(any(f["line"] == 1 and f["kind"] == "github-token" for f in report["findings"]))

    def test_utf16_terms_are_not_skipped(self):
        scanner = rc.Scanner(self.terms)
        scanner.file("HiddenPerson".encode("utf-16"), "tree", "wide.txt")
        self.assertTrue(any(f["kind"] == "denylist" for f in scanner.findings))

    def test_specific_review_cannot_waive_denylist_or_secret(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(b"HiddenPerson", "tree", "data.txt")
        finding = scanner.findings[0]
        approve = {k: finding[k] for k in ("scope", "kind", "path", "fingerprint")}
        repeat = rc.Scanner(self.terms, approvals=[approve])
        repeat.file(b"HiddenPerson", "tree", "data.txt")
        self.assertFalse(repeat.findings[0]["reviewed"])
        repeat = rc.Scanner(self.terms)
        repeat.file((b'demo' + b'@example.org'), "tree", "text.txt")
        hit = next(f for f in repeat.findings if f["kind"] == "email")
        repeat = rc.Scanner(self.terms, approvals=[hit])
        repeat.file((b'demo' + b'@example.org'), "tree", "text.txt")
        repeat.file((b'demo' + b'@example.org'), "tree", "other.txt")
        self.assertEqual(sum(f["reviewed"] for f in repeat.findings), 1)

    def test_private_filename_and_ipv6_filename_are_fingerprinted(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(b"fixture", "tree", "HiddenPerson.txt")
        self.assertTrue(all(f["path"].startswith("[path-") for f in scanner.findings))
        self.assertTrue(scanner.safe_path(('2001' + ':db8::1.txt')).startswith("[path-"))

    def test_opaque_secret_filename_never_reaches_reports(self):
        value = "Ab3D4e5F6g7H8i9J0kL1m" + "N2oP3qR4sT5uV6wX7yZ8"
        (self.repo / (value + ".txt")).write_text("fixture")
        code, out, err = self.run_cli("--scrub-plan")
        self.assertEqual(code, 1)
        self.assertNotIn(value, out + err)
        for report in (self.root / "reports").rglob("report.*"):
            self.assertNotIn(value, report.read_text())

    def test_untrusted_check_label_cannot_leak_into_reports(self):
        secret = "SyntheticPrivateLabel"
        scanner = rc.Scanner(self.terms)
        manifest = {**self.manifest, "checks": [{"role": secret, "argv": ["python", "-c", "print(1)"]}]}
        with patch.object(rc, "command") as call:
            with self.assertRaises(rc.AuditError):
                rc.verify(self.repo, self.root, scanner, manifest, 10)
        call.assert_not_called()
        self.assertNotIn(secret, json.dumps(scanner.findings))

    def test_malformed_manifest_is_a_safe_incomplete_audit(self):
        (self.repo / "release-check.json").write_text(json.dumps({"checks": ["SyntheticPrivateManifestContent"]}))
        code, out, err = self.run_cli()
        self.assertEqual(code, 2)
        self.assertNotIn("SyntheticPrivateManifestContent", out + err)

    def test_invalid_cli_argument_is_not_printed(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            with self.assertRaises(SystemExit) as caught:
                rc.main([str(self.repo), "--timeout", "SyntheticPrivateArgument"])
        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn("SyntheticPrivateArgument", out.getvalue() + err.getvalue())

    def test_lfs_pointer_blocks_unscanned_content(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(("version https://git-lfs.github.com/" + "spec/v1\noid sha256:" + "a" * 64 + "\nsize 42\n").encode(), "tree", "pointer.txt")
        self.assertTrue(any(f["kind"] == "lfs-content-not-scanned" for f in scanner.findings))

    def test_public_commit_signature_is_not_treated_as_a_secret(self):
        raw = b"tree " + b"a" * 40 + b"\nauthor Fixture <fixture> 1 +0000\ncommitter Fixture <fixture> 1 +0000\ngpgsig BEGIN SIGNATURE\n random-public-signature\n\nMessage HiddenPerson\n"
        filtered = rc.commit_text(raw)
        self.assertIn(b"author Fixture", filtered)
        self.assertIn(b"Message HiddenPerson", filtered)
        self.assertNotIn(b"random-public-signature", filtered)

    def test_versions_and_classifier_punctuation_are_not_network_addresses(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(b'attrs-26.1.0\n2026-03-19T14:22:25Z\n"License :: OSI Approved :: MIT License"\nPath.home()\n', "tree", "metadata.txt")
        self.assertEqual(scanner.findings, [])

    def test_entropy_and_key_formats_cannot_be_approved(self):
        value = "Ab3D4e5F6g7H8i9J0kL1m" + "N2oP3qR4sT5uV6wX7yZ8"
        scanner = rc.Scanner(self.terms)
        scanner.file(value.encode(), "tree", "random.txt")
        self.assertTrue(any(f["kind"] == "entropy" for f in scanner.findings))
        repeat = rc.Scanner(self.terms, approvals=scanner.findings)
        repeat.file(value.encode(), "tree", "random.txt")
        self.assertTrue(all(not f["reviewed"] for f in repeat.findings))

    def test_compressed_and_binary_files_require_review(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(b"binary\0bytes", "tree", "archive.zip")
        self.assertTrue(any(f["kind"] == "binary-review" for f in scanner.findings))

    def test_export_flattens_history_and_excludes_config_without_source_write(self):
        (self.repo / "old.txt").write_text("HiddenPerson")
        self.commit("Private history")
        self.git("rm", "--", "old.txt")
        self.git("commit", "-q", "-m", "Remove")
        (self.repo / ".env").write_text("fixture config")
        before = self.git("status", "--porcelain")
        scanner = rc.Scanner(self.terms)
        target = self.root / "export"
        rc.copy_tree(self.repo, target, self.manifest, scanner)
        self.assertFalse((target / ".env").exists())
        self.assertEqual(before, self.git("status", "--porcelain"))
        self.assertEqual(rc.git(target, "rev-list", "--count", "HEAD").strip(), b"1")
        self.assertEqual(rc.git(target, "remote").strip(), b"")
        clean = rc.Scanner(self.terms)
        clean.tree(target)
        clean.history(target)
        self.assertEqual(clean.findings, [])

    def test_export_refuses_existing_destination(self):
        target = self.root / "export"
        target.mkdir()
        (target / "keep").write_text("preserve")
        with self.assertRaises(rc.AuditError):
            rc.copy_tree(self.repo, target, self.manifest, rc.Scanner(self.terms))
        self.assertEqual((target / "keep").read_text(), "preserve")

    def test_symlink_is_not_followed_or_copied(self):
        outside = self.root / "outside"
        outside.write_text("HiddenPerson")
        (self.repo / "linked").symlink_to(outside)
        scanner = self.scan()
        self.assertTrue(any(f["kind"] == "symlink" for f in scanner.findings))
        target = self.root / "export"
        rc.copy_tree(self.repo, target, self.manifest, scanner)
        self.assertFalse((target / "linked").exists())

    def test_media_is_reviewed_by_exact_fingerprint(self):
        scanner = rc.Scanner(self.terms)
        scanner.file(b"image fixture", "tree", "image.png")
        self.assertTrue(any(f["category"] == "media" for f in scanner.findings))

    def test_license_text_and_protected_attribution(self):
        scanner = rc.Scanner(self.terms)
        self.assertEqual(rc.license_audit(self.repo, scanner, self.manifest)["status"], "pass")
        manifest = {**self.manifest, "exclude": ["LICENSE"]}
        rc.license_audit(self.repo, scanner, manifest)
        self.assertTrue(any(f["kind"] == "excluded-attribution" for f in scanner.findings))
        (self.repo / "LICENSE").write_text("MIT License\nPermission is hereby granted to do something else.")
        self.assertEqual(rc.license_audit(self.repo, scanner, self.manifest)["status"], "blocked")

    def test_historical_notice_cannot_be_removed_from_export(self):
        (self.repo / "NOTICE").write_text("Upstream attribution fixture.")
        self.commit("Add attribution")
        self.git("rm", "--", "NOTICE")
        self.git("commit", "-q", "-m", "Remove notice")
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "export"))
        self.assertEqual(code, 1, out + err)
        report = json.loads(next((self.root / "reports").rglob("report.json")).read_text())
        self.assertFalse(report["export"]["ready"])
        self.assertTrue(any(f["kind"] == "historical-attribution-missing" for f in report["export"]["findings"]))

    def test_changed_notice_blocks_but_added_notice_context_preserves_attribution(self):
        (self.repo / "NOTICE").write_text("Upstream attribution fixture.\n")
        self.commit("Add attribution")
        (self.repo / "NOTICE").write_text("New context.\nUpstream attribution fixture.\n")
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "good-export"))
        self.assertEqual(code, 0, out + err)
        (self.repo / "NOTICE").write_text("Different attribution.\n")
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "bad-export"))
        self.assertEqual(code, 1, out + err)
        report = json.loads(sorted((self.root / "reports").rglob("report.json"))[-1].read_text())
        self.assertTrue(any(f["kind"] == "historical-attribution-changed" for f in report["export"]["findings"]))

    def test_shallow_history_blocks_coverage(self):
        shallow = self.root / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth=1", self.repo.as_uri(), str(shallow)], check=True, capture_output=True)
        scanner = rc.Scanner(self.terms)
        scanner.history(shallow)
        self.assertTrue(any(f["kind"] == "shallow-history" for f in scanner.findings))

    def test_denylist_inside_source_is_refused_with_no_content(self):
        path = self.repo / "list.json"
        path.write_text('["HiddenPerson"]')
        code, out, err = self.run_cli("--denylist", str(path))
        self.assertEqual(code, 2)
        self.assertNotIn("HiddenPerson", out + err)

    def test_dependency_unknown_and_incompatible_licenses_block(self):
        package = {"name": "fixture", "version": "1", "expression": "GPL-3.0-only", "license": None, "classifiers": [], "license_files": [{"path": "LICENSE", "hash": "f" * 64}]}
        scanner = rc.Scanner(self.terms)
        result = rc.dependency_audit(json.dumps([package]).encode(), self.repo, scanner, self.manifest)
        self.assertEqual(result["blocked"], 1)
        package["expression"] = "MIT"
        result = rc.dependency_audit(json.dumps([package]).encode(), self.repo, rc.Scanner(self.terms), self.manifest)
        self.assertEqual(result["blocked"], 1)  # Empty shipped evidence remains unknown.
        package["license_files"] = []
        result = rc.dependency_audit(json.dumps([package]).encode(), self.repo, rc.Scanner(self.terms), self.manifest)
        self.assertEqual(result["blocked"], 0)

    def test_quickstart_mismatch_never_runs(self):
        scanner = rc.Scanner(self.terms)
        with patch.object(rc, "command") as call:
            result = rc.verify(self.repo, self.root, scanner, {**self.manifest, "quickstart": [{"file": "README.md", "line": 4, "argv": ["python", "-c", "print(2)"]}]}, 10)
        self.assertEqual(result["status"], "blocked")
        call.assert_not_called()

    def test_clean_clone_quickstart_and_tests_run_without_inherited_credentials(self):
        scanner = rc.Scanner(self.terms)
        with patch.dict(os.environ, {"GITHUB_TOKEN": "never-inherit-fixture"}):
            result = rc.verify(self.repo, self.root, scanner, self.manifest, 30)
        self.assertEqual(result["status"], "pass", scanner.findings)
        self.assertEqual([r["exit_code"] for r in result["commands"]], [0, 0])
        environment = rc.safe_environment(self.root / "home", self.root / "bin")
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertEqual(Path(environment["TMPDIR"]), self.root / "home/tmp")
        self.assertEqual(Path(environment["TMPDIR"]).stat().st_mode & 0o777, 0o700)

    def test_verify_commands_cannot_discover_a_repository_above_the_workspace(self):
        self.git("-C", str(self.root), "init", "-q")
        scratch = self.root / ".scratch"
        scratch.mkdir()
        probe = ("import os,subprocess,sys\n"
                 "found = lambda cwd: subprocess.run(['git', 'rev-parse', '--git-dir'], cwd=cwd, capture_output=True).returncode == 0\n"
                 "sys.exit(0 if found('.') and not found(os.environ['TMPDIR']) else 1)")
        manifest = {**self.manifest, "checks": [{"role": "tests", "argv": ["python", "-c", probe]}]}
        scanner = rc.Scanner(self.terms)
        with patch.object(rc.tempfile, "tempdir", str(scratch)):
            result = rc.verify(self.repo, self.root, scanner, manifest, 30)
        self.assertEqual(result["status"], "pass", scanner.findings)

    def test_verify_refuses_when_every_temporary_folder_is_inside_a_repository(self):
        bare = self.root / "bare.git"
        self.git("init", "-q", "--bare", str(bare))
        unwritable = self.root / "unwritable"
        unwritable.mkdir()
        writable = lambda path, mode: Path(path) != unwritable
        with patch.object(rc.tempfile, "tempdir", str(bare / "objects")), patch.object(rc, "TEMP_FALLBACKS", (str(unwritable),), create=True), \
                patch.object(rc.os, "access", side_effect=writable):
            with self.assertRaises(rc.AuditError) as caught:
                rc.verify(self.repo, self.root, rc.Scanner(self.terms), self.manifest, 30)
        self.assertEqual(str(caught.exception), "verify-workspace-in-repository")

    def test_command_failure_output_is_only_fingerprinted(self):
        scanner = rc.Scanner(self.terms)
        secret = "SyntheticPrivateFailureText"
        manifest = {**self.manifest, "checks": [{"role": "tests", "argv": ["python", "-c", f"import sys;print('{secret}');sys.exit(3)"]}]}
        result = rc.verify(self.repo, self.root, scanner, manifest, 30)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["commands"][-1]["exit_code"], 3)
        self.assertNotIn(secret, json.dumps(result) + json.dumps(scanner.findings))

    def test_command_timeout_kills_process_and_blocks(self):
        code, output = rc.command([sys.executable, "-c", "import time;time.sleep(30)"], self.repo, rc.safe_environment(self.root / "home", Path(sys.executable).parent), 1)
        self.assertEqual(code, 124)

    def test_incomplete_scan_still_saves_safe_failure_report(self):
        with patch.object(rc.Scanner, "tree", side_effect=OSError("private-exception-detail")):
            code, out, err = self.run_cli()
        self.assertEqual(code, 2)
        report = next((self.root / "reports").rglob("report.json")).read_text()
        self.assertNotIn("private-exception-detail", report + out + err)
        self.assertEqual(json.loads(report)["counts"], {"coverage": 1})

    def test_cli_export_ready_with_private_history_and_zero_export_findings(self):
        (self.repo / "old.txt").write_text("HiddenPerson")
        self.commit("Private history")
        self.git("rm", "--", "old.txt")
        self.git("commit", "-q", "-m", "Remove")
        code, out, err = self.run_cli("--verify", "--export", str(self.root / "export"))
        self.assertEqual(code, 0, out + err)
        report = json.loads(next((self.root / "reports").rglob("report.json")).read_text())
        self.assertFalse(report["ready"])
        self.assertTrue(report["export"]["ready"])
        self.assertEqual(report["export"]["counts"], {})

    def test_requirements_listing_tracks_enforced_rules(self):
        text = rc.requirements_text()
        for name in rc.REQUIRED_DOCUMENTS:
            path = self.repo / name
            original = path.read_bytes()
            path.unlink()
            scanner = rc.Scanner(self.terms)
            rc.quality_audit(self.repo, scanner, self.manifest)
            self.assertTrue(any(f["kind"] == "missing-document" and f["path"] == name for f in scanner.findings))
            self.assertIn(name, text)
            path.write_bytes(original)
        for heading in rc.README_HEADINGS:
            (self.repo / "README.md").write_text("# Fixture\n## Honest " + heading.title() + "\n")
            scanner = rc.Scanner(self.terms)
            rc.quality_audit(self.repo, scanner, self.manifest)
            self.assertFalse(any(f["kind"] == "missing-limitations" for f in scanner.findings))
            self.assertIn(heading, text)
        with patch.object(rc, "REQUIRED_DOCUMENTS", ("EXTRA.md",)), patch.object(rc, "README_HEADINGS", ("changed heading",)), patch.object(rc, "ISSUE_TEMPLATE_GLOBS", ("*.changed",)), patch.object(rc, "TEST_GLOB", "changed*.py"), patch.object(rc, "ROOT_LICENSE_FILES", ("CHANGED-LICENSE",)):
            changed = rc.requirements_text()
            scanner = rc.Scanner(self.terms)
            rc.quality_audit(self.repo, scanner, self.manifest)
            rc.license_audit(self.repo, scanner, self.manifest)
            self.assertIn("EXTRA.md", changed)
            self.assertIn("changed heading", changed)
            self.assertIn("*.changed", changed)
            self.assertIn("changed*.py", changed)
            self.assertIn("CHANGED-LICENSE", changed)
            self.assertTrue({"missing-document", "missing-limitations", "missing-issue-templates", "missing-tests", "missing-license"} <= {f["kind"] for f in scanner.findings})

    def test_quality_audit_ignores_untracked_files(self):
        for rel in ("CONTRIBUTING.md", ".github/ISSUE_TEMPLATE/bug.yml", "tests/test_fixture.py"):
            self.git("rm", "-q", "--cached", "--", rel)
        scanner = rc.Scanner(self.terms)
        rc.quality_audit(self.repo, scanner, self.manifest)
        found = {(f["kind"], f["path"]) for f in scanner.findings}
        self.assertEqual(found, {("missing-document", "CONTRIBUTING.md"), ("missing-issue-templates", rc.ISSUE_TEMPLATE_DIR), ("missing-tests", rc.TEST_DIR)})

    def test_venv_missing_ensurepip_has_actionable_versioned_message(self):
        scanner = rc.Scanner(self.terms)
        with patch.object(rc, "command", return_value=(1, b"The virtual environment was not created successfully because ensurepip is not available.")):
            result = rc.verify(self.repo, self.root, scanner, self.manifest, 10)
        self.assertEqual(result["status"], "blocked")
        hit = next(f for f in scanner.findings if f["kind"] == "venv-creation-failed")
        version = f"{sys.version_info.major}.{sys.version_info.minor}"
        self.assertEqual(hit["cause"], "missing-ensurepip")
        self.assertIn("Python " + version, hit["message"])
        self.assertIn("python" + version + "-venv", hit["message"])
        for error in (b"No module named ensurepip", b"No module named 'ensurepip'"):
            self.assertEqual(rc.venv_failure(error, scanner)["cause"], "missing-ensurepip")

    def test_other_venv_failure_has_redacted_error_tail(self):
        scanner = rc.Scanner(self.terms)
        private = str(self.root / "HiddenPerson" / "env")
        output = ("Earlier diagnostic\nPermission denied: " + private + "\nFinal failure").encode()
        with patch.object(rc, "command", return_value=(1, output)):
            result = rc.verify(self.repo, self.root, scanner, self.manifest, 10)
        self.assertEqual(result["status"], "blocked")
        hit = next(f for f in scanner.findings if f["kind"] == "venv-creation-failed")
        self.assertEqual(hit["cause"], "other-venv-error")
        self.assertIn("Permission denied", hit["error_tail"])
        self.assertIn("Final failure", hit["error_tail"])
        self.assertNotIn(private, json.dumps(hit))
        self.assertNotIn("HiddenPerson", json.dumps(hit))
        self.assertNotIn("support is missing", hit["message"])
        self.assertEqual(rc.venv_failure(b"ensurepip returned non-zero exit status 1", scanner)["cause"], "other-venv-error")

    def test_venv_real_wrapped_missing_ensurepip_diagnostic(self):
        # Captured from Python 3.14 -m venv with a scratch stdlib lacking ensurepip;
        # only the machine path was replaced with a neutral fixture path.
        output = (Path(__file__).parent / "fixtures/venv-missing-ensurepip.txt").read_bytes()
        self.assertIn(b"ensurepip is not\navailable.", output)
        hit = rc.venv_failure(output, rc.Scanner(self.terms))
        self.assertEqual(hit["cause"], "missing-ensurepip")
        self.assertIn("venv support is missing", hit["message"])
        self.assertIn("on other systems install or enable", hit["message"])
        self.assertEqual(rc.venv_failure(b"ensurepip\t is\nnot\tavailable.", rc.Scanner(self.terms))["cause"], "missing-ensurepip")

    def test_venv_error_tail_preserves_slash_words_and_redacts_absolute_paths(self):
        paths = [str(self.root / "env"), "/neutral/env/bin/python3", "C:\\neutral\\env", "D:/neutral/env"]
        for path in paths:
            with self.subTest(path=path):
                output = ("Debian/Ubuntu read/write support failed: '" + path + "'\nRetry Debian/Ubuntu").encode()
                hit = rc.venv_failure(output, rc.Scanner(self.terms))
                self.assertEqual(hit["cause"], "other-venv-error")
                self.assertEqual(hit["error_tail"].count("Debian/Ubuntu"), 2)
                self.assertIn("read/write", hit["error_tail"])
                self.assertNotIn(path, hit["error_tail"])
                self.assertIn("[redacted]", hit["error_tail"])

    def test_verify_cli_with_real_interpreter_missing_ensurepip(self):
        # Copy the interpreter and stdlib, omitting ensurepip; never change the host.
        home = self.root / "python-home"
        (home / "bin").mkdir(parents=True)
        interpreter = home / "bin/python3"
        shutil.copy2(sys.executable, interpreter)
        stdlib = home / sys.platlibdir / ("python" + sysconfig.get_python_version())
        shutil.copytree(sysconfig.get_path("stdlib"), stdlib,
                        ignore=shutil.ignore_patterns("ensurepip", "site-packages", "dist-packages", "__pycache__"))
        environment = rc.safe_environment(self.root / "home", Path("/usr/bin"))
        version = f"{sys.version_info.major}.{sys.version_info.minor}"
        expected = f"Python {version} venv support is missing (ensurepip). On Debian/Ubuntu install python{version}-venv; on other systems install or enable the Python {version} venv/ensurepip support, then retry."

        def run_failure(name):
            reports = self.root / name
            result = subprocess.run([str(interpreter), str(Path(rc.__file__).resolve()), str(self.repo),
                                     "--denylist", str(self.denylist), "--reports", str(reports), "--verify"],
                                    env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            report = json.loads(next(reports.rglob("report.json")).read_text())
            self.assertEqual(report["verification"]["status"], "blocked")
            return next(f for f in report["findings"] if f["kind"] == "venv-creation-failed")

        hit = run_failure("real-missing-reports")
        self.assertEqual(hit["cause"], "missing-ensurepip")
        self.assertEqual(hit["message"], expected)

        # Change only the scratch diagnostic wording to prove the import probe
        # finds the actual condition even without a recognizable error message.
        venv_main = stdlib / "venv/__main__.py"
        original = venv_main.read_text()
        venv_main.write_text("import contextlib, io, sys, venv\n"
                             "try:\n"
                             " with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):\n"
                             "  venv.EnvBuilder(with_pip=True).create(sys.argv[1])\n"
                             "except (Exception, SystemExit):\n"
                             " print('Bootstrap support could not be loaded.')\n"
                             " sys.exit(1)\n")
        hit = run_failure("changed-wording-reports")
        self.assertEqual(hit["cause"], "missing-ensurepip")
        self.assertEqual(hit["message"], expected)

        venv_main.write_text(original)

        # An installed ensurepip that crashes is an unrelated bootstrap failure.
        (stdlib / "ensurepip").mkdir()
        (stdlib / "ensurepip/__init__.py").write_text("")
        (stdlib / "ensurepip/__main__.py").write_text("raise RuntimeError('Synthetic bootstrap failure')\n")
        hit = run_failure("other-failure-reports")
        self.assertEqual(hit["cause"], "other-venv-error")
        self.assertIn("does not identify missing ensurepip", hit["message"])
        self.assertIn("error_tail", hit)
        self.assertNotIn(str(self.root), hit["error_tail"])

        # Missing dependencies inside ensurepip must not mean ensurepip is absent.
        (stdlib / "ensurepip/__init__.py").write_text("import synthetic_missing_bootstrap_dependency\n")
        hit = run_failure("internal-import-failure-reports")
        self.assertEqual(hit["cause"], "other-venv-error")

    def test_reviewed_dependency_is_reported_and_no_longer_blocks(self):
        package = {"name": "fixture", "version": "1", "expression": "GPLv3", "license": None, "classifiers": [], "license_files": [{"path": "LICENSE", "hash": "f" * 64, "text": "SPDX-License-Identifier: GPL-3.0-only"}]}
        raw = json.dumps([package]).encode()
        scanner = rc.Scanner(self.terms)
        rc.dependency_audit(raw, self.repo, scanner, self.manifest)
        manifest = {**self.manifest, "approvals": [{**scanner.findings[0], "reason": "Reviewed exact evidence."}]}
        def verification(repo, report_dir, scanner, manifest, timeout, *, tool_exclusions=(), workspace_dir=None):
            deps = rc.dependency_audit(raw, repo, scanner, manifest)
            return {"status": "pass" if not deps["blocked"] else "blocked", "commands": [], "dependencies": deps}
        with patch.object(rc, "verify", side_effect=verification):
            report = rc.audit(self.repo, self.terms, manifest, [], True, self.root, 10)
        self.assertTrue(report["ready"], report["findings"])
        self.assertEqual(report["reviewed_count"], 1)
        self.assertTrue(next(f for f in report["findings"] if f["kind"] == "dependency-license-review")["reviewed"])


if __name__ == "__main__":
    unittest.main()
