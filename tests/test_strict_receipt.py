from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import stat
import subprocess
import unittest
from unittest.mock import patch

import release_check as rc
from tests import test_release_check as fixtures


def cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = rc.main(argv)
    return code, out.getvalue(), err.getvalue()


def verified(*args, **kwargs):
    return {"status": "pass", "commands": [], "dependencies": {"blocked": 0}}


class StrictReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clean = fixtures.AuditTests()
        cls.clean.setUp()
        cls.addClassCleanup(cls.clean.doCleanups)
        cls.export = cls.clean.root / "export"
        cls.clean_result = cls.clean.run_cli("--verify", "--export", str(cls.export))
        cls.report_path = next((cls.clean.root / "reports").rglob("report.json"))
        cls.receipt_path = cls.report_path.with_name("receipt.json")
        cls.receipt_bytes = cls.receipt_path.read_bytes()

    def setUp(self):
        self.fixture = fixtures.AuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def validate(self, extra=(), path=None):
        return cli(["--validate-receipt", str(path or self.receipt_path), str(self.export),
                    "--denylist", str(self.clean.denylist), "--verify", *extra])

    def result(self, run, status, reason=None, mismatched=None):
        code, out, err = run
        self.assertEqual(code, {"PASS": 0, "FAIL": 1, "INCOMPLETE": 2}[status], out + err)
        summary = json.loads(out)
        self.assertEqual(summary["outcome"], status)
        if reason:
            self.assertIn(reason, summary["reasons"])
        if mismatched is not None:
            self.assertEqual(summary["mismatched"], mismatched)
        return summary

    def report(self):
        return json.loads(sorted((self.fixture.root / "reports").rglob("report.json"))[-1].read_text())

    def test_clean_export_and_read_only_validation(self):
        summary = self.result(self.clean_result, "PASS")
        report = json.loads(self.report_path.read_text())
        self.assertEqual(summary["export_outcome"], "PASS")
        for audit in (report, report["export"]):
            self.assertEqual(audit["outcome"], "PASS")
            self.assertEqual(audit["reasons"], [])
            self.assertTrue(audit["ready"])
        self.assertFalse((self.export / "receipt.json").exists())
        self.assertEqual(self.receipt_path.stat().st_mode & 0o777, 0o600)
        receipt = json.loads(self.receipt_bytes)
        self.assertEqual(set(receipt), {"schema_version", "outcome", "reasons", "created_at",
                                      "export_head", "export_tree", "bindings", "receipt_sha256"})
        self.assertEqual(self.receipt_bytes, rc.canonical_json(receipt) + b"\n")
        self.assertNotIn(str(self.clean.root), self.receipt_bytes.decode())
        self.assertNotIn("HiddenPerson", self.receipt_bytes.decode())
        inventory = rc.inventory_digest(self.export)
        audit = rc.audit(self.export, self.clean.terms, self.clean.manifest, [],
                         True, self.fixture.root, 300)
        self.assertEqual(audit["outcome"], "PASS")
        self.assertEqual(rc.inventory_digest(self.export), inventory)
        reports = self.clean.root / "must-not-exist"
        with patch.object(rc, "audit") as audit, patch.object(rc, "verify") as verify:
            self.result(self.validate(["--reports", str(reports)]), "PASS", mismatched=[])
        audit.assert_not_called()
        verify.assert_not_called()
        self.assertFalse(reports.exists())

    def test_leaks_fail_and_never_escape(self):
        for marker, reason in (("ghp_" + "Ab12" * 9, "github-token"), ("HiddenPerson", "denylist")):
            with self.subTest(reason=reason):
                (self.fixture.repo / "leak.txt").write_text(marker)
                self.fixture.commit("Synthetic fixture")
                target = self.fixture.root / reason
                with patch.object(rc, "verify", side_effect=verified):
                    run = self.fixture.run_cli("--verify", "--export", str(target))
                self.result(run, "FAIL")
                report = self.report()
                self.assertEqual(report["outcome"], "FAIL")
                self.assertIn(reason, report["reasons"])
                self.assertEqual(report["export"]["outcome"], "FAIL")
                self.assertIn(reason, report["export"]["reasons"])
                self.assertFalse(report["ready"])
                for path in (self.fixture.root / "reports").rglob("*"):
                    if path.is_file():
                        self.assertNotIn(marker, path.read_text())
                self.assertNotIn(marker, run[1] + run[2])
                receipt = sorted((self.fixture.root / "reports").rglob("receipt.json"))[-1]
                args = ["--validate-receipt", str(receipt), str(target), "--denylist", str(self.fixture.denylist), "--verify"]
                self.result(cli(args), "FAIL", reason, [])

    def test_coverage_gaps_are_incomplete(self):
        self.result(self.fixture.run_cli(), "INCOMPLETE")
        report = self.report()
        self.assertEqual(report["reasons"], ["verification-not-passed", "verification-not-run"])
        self.assertFalse(report["ready"])
        self.assertEqual({f["kind"] for f in report["findings"]}, {"verification-not-run"})
        (self.fixture.repo / "link").symlink_to("README.md")
        with patch.object(rc, "verify", side_effect=verified):
            run = self.fixture.run_cli("--verify", "--export", str(self.fixture.root / "export"))
        self.result(run, "INCOMPLETE")
        export = self.report()["export"]
        self.assertEqual(export["outcome"], "INCOMPLETE")
        self.assertEqual(export["reasons"], ["unsupported-file"])
        self.assertFalse(export["ready"])
        self.assertTrue(all(f["category"] == "coverage" for f in export["findings"]))
        receipt = next((self.fixture.root / "reports").rglob("receipt.json"))
        self.result(cli(["--validate-receipt", str(receipt), str(self.fixture.root / "export"),
                         "--denylist", str(self.fixture.denylist), "--verify"]),
                    "INCOMPLETE", "unsupported-file", [])

    def test_unknown_license_and_empty_accounting_cannot_pass(self):
        for patcher, reason in ((patch.object(rc, "license_audit", return_value={"status": "unknown"}), "license-not-passed"),
                                (patch.object(rc.Scanner, "history"), "empty-history"),
                                (patch.object(rc.Scanner, "tree"), "empty-tree")):
            with self.subTest(reason=reason), patcher, patch.object(rc, "verify", side_effect=verified):
                self.result(self.fixture.run_cli("--verify"), "INCOMPLETE")
                report = self.report()
                self.assertEqual(report["outcome"], "INCOMPLETE")
                self.assertIn(reason, report["reasons"])
                self.assertFalse(report["ready"])
                self.assertEqual(report["findings"], [])

    def test_readme_command_contradicting_manifest_fails(self):
        self.fixture.manifest["quickstart"][0]["argv"] = ["python", "-c", "print(2)"]
        (self.fixture.repo / "release-check.json").write_text(json.dumps(self.fixture.manifest))
        self.fixture.commit("Contradict README")
        code, out, err = self.fixture.run_cli("--verify")
        self.assertEqual(code, 1, out + err)
        self.assertEqual(json.loads(out)["outcome"], "FAIL")
        self.assertIn("quickstart-document-mismatch", self.report()["reasons"])

    def test_unsupported_dependency_coverage_is_incomplete(self):
        (self.fixture.repo / "Cargo.toml").write_text("")
        with patch.object(rc, "verify", side_effect=verified):
            self.result(self.fixture.run_cli("--verify"), "INCOMPLETE")
        self.assertEqual(self.report()["reasons"], ["dependency-ecosystem-manual-review"])

    def test_fail_dominates_and_retains_incomplete_reasons(self):
        (self.fixture.repo / "leak.txt").write_text("HiddenPerson")
        self.result(self.fixture.run_cli(), "FAIL")
        report = self.report()
        self.assertEqual(report["reasons"], ["denylist", "verification-not-passed", "verification-not-run"])
        self.assertFalse(report["ready"])

    def test_verification_cannot_certify_a_mutated_candidate(self):
        target = self.fixture.root / "export"
        payload = (f"from pathlib import Path; target = Path(bytes.fromhex('{bytes(target).hex()}').decode()); "
                   "(target / 'late.txt').write_text('Hidden' + 'Person')")
        self.fixture.manifest["checks"].append({"role": "tests", "argv": ["python", "-c", payload]})
        (self.fixture.repo / "release-check.json").write_text(json.dumps(self.fixture.manifest))
        self.fixture.commit("Add candidate mutation check")
        code, out, err = self.fixture.run_cli("--verify", "--export", str(target))
        self.assertEqual(code, 1, out + err)
        self.assertEqual((target / "late.txt").read_text(), "HiddenPerson")
        summary = json.loads(out)
        self.assertEqual(summary["export_outcome"], "FAIL")
        self.assertFalse(summary["export_ready"])
        report = self.report()["export"]
        self.assertEqual(report["outcome"], "FAIL")
        self.assertEqual(report["reasons"], ["candidate-mutated"])
        self.assertFalse(report["ready"])
        receipt = next((self.fixture.root / "reports").rglob("receipt.json"))
        self.result(cli(["--validate-receipt", str(receipt), str(target),
                         "--denylist", str(self.fixture.denylist), "--verify"]),
                    "FAIL", "candidate-mutated", [])

    def test_git_metadata_mutations_invalidate_inventory(self):
        config = self.export / ".git/config"
        original = config.read_bytes()
        hook = self.export / ".git/hooks/receipt-test"
        blob = b"Unreferenced receipt fixture\n"
        oid = subprocess.run(["git", "hash-object", "--stdin"], input=blob,
                             capture_output=True, check=True).stdout.decode().strip()
        object_path = self.export / ".git/objects" / oid[:2] / oid[2:]
        prefix_existed = object_path.parent.exists()

        def add_hook():
            hook.write_text("#!/bin/sh\nexit 0\n")
            hook.chmod(0o700)

        def add_blob():
            subprocess.run(["git", "-C", str(self.export), "hash-object", "-w", "--stdin"],
                           input=blob, capture_output=True, check=True)

        def remove_blob():
            object_path.unlink()
            if not prefix_existed:
                object_path.parent.rmdir()

        mutations = [
            ("config", lambda: config.write_bytes(original + b"\n# receipt fixture\n"),
             lambda: config.write_bytes(original)),
            ("hook", add_hook, hook.unlink),
            ("unreferenced-object", add_blob, remove_blob),
        ]
        for name, mutate, restore in mutations:
            with self.subTest(name=name):
                try:
                    mutate()
                    self.result(self.validate(), "INCOMPLETE", "receipt-stale", ["inventory"])
                finally:
                    restore()
                self.result(self.validate(), "PASS", mismatched=[])

    def test_empty_directory_invalidates_inventory(self):
        path = self.export / "empty"
        try:
            path.mkdir()
            self.result(self.validate(), "INCOMPLETE", "receipt-stale", ["inventory"])
        finally:
            path.rmdir()
        self.result(self.validate(), "PASS", mismatched=[])

    def test_full_permission_bits_invalidate_inventory(self):
        for path, mode in ((self.export / "README.md", 0o666),
                           (self.export / "tests", 0o777), (self.export, 0o777)):
            with self.subTest(path=path.relative_to(self.export).as_posix()):
                original = stat.S_IMODE(path.stat().st_mode)
                try:
                    path.chmod(mode)
                    self.result(self.validate(), "INCOMPLETE", "receipt-stale", ["inventory"])
                finally:
                    path.chmod(original)
                self.result(self.validate(), "PASS", mismatched=[])

    def test_media_review_is_incomplete_but_leaks_still_fail(self):
        (self.fixture.repo / "photo.png").write_bytes(b"image fixture")
        with patch.object(rc, "verify", side_effect=verified):
            self.result(self.fixture.run_cli("--verify"), "INCOMPLETE")
            self.assertEqual(self.report()["reasons"], ["manual-review"])
            self.assertFalse(self.report()["ready"])
            (self.fixture.repo / "leak.txt").write_text("HiddenPerson")
            self.result(self.fixture.run_cli("--verify"), "FAIL")
            self.assertEqual(self.report()["reasons"], ["denylist", "manual-review"])

    def test_oversized_receipts_are_invalid_without_traceback(self):
        path = self.fixture.root / "oversized.json"
        with path.open("wb") as handle:
            handle.truncate(2 * 1024 * 1024)
        with patch.object(rc.json, "loads", wraps=rc.json.loads) as loads:
            run = self.validate(path=path)
        loads.assert_not_called()
        self.result(run, "INCOMPLETE", "receipt-invalid", [])
        self.assertEqual(run[2], "receipt file is too large\n")
        with patch.object(rc.os, "fstat", return_value=type("Stat", (), {"st_size": 0})()), patch.object(
                rc.json, "loads", wraps=rc.json.loads) as loads:
            run = self.validate(path=path)
        loads.assert_not_called()
        self.result(run, "INCOMPLETE", "receipt-invalid", [])
        self.assertEqual(run[2], "receipt file is too large\n")
        with patch.object(rc.json, "loads", side_effect=MemoryError):
            run = self.validate()
        self.result(run, "INCOMPLETE", "receipt-invalid", [])
        self.assertEqual(run[2], "receipt file is too large or too deeply nested\n")

    def test_export_mutations_invalidate_inventory(self):
        path = self.export / "README.md"
        original, mode = path.read_bytes(), path.stat().st_mode
        mutations = [
            (lambda: path.write_bytes(b"!" + original[1:]), lambda: path.write_bytes(original)),
            (lambda: path.chmod(mode | 0o111), lambda: path.chmod(mode)),
            (lambda: (self.export / "extra").write_text("extra"), lambda: (self.export / "extra").unlink()),
            (lambda: rc.git(self.export, "update-ref", "refs/tags/extra", "HEAD"),
             lambda: rc.git(self.export, "update-ref", "-d", "refs/tags/extra")),
            (lambda: path.rename(self.export / "renamed"), lambda: (self.export / "renamed").rename(path)),
            (lambda: (self.export / ".env").write_text("ignored"), lambda: (self.export / ".env").unlink()),
            (lambda: (self.export / "link").symlink_to("README.md"), lambda: (self.export / "link").unlink()),
        ]
        for index, (mutate, restore) in enumerate(mutations):
            with self.subTest(index=index):
                try:
                    mutate()
                    self.result(self.validate(), "INCOMPLETE", "receipt-stale", ["inventory"])
                finally:
                    restore()
                self.result(self.validate(), "PASS", mismatched=[])

    def test_recipe_policy_and_scanner_mutations(self):
        manifest = self.export / "release-check.json"
        original = manifest.read_bytes()
        try:
            obj = json.loads(original)
            obj["exclude"] = ["extra"]
            manifest.write_text(json.dumps(obj))
            self.result(self.validate(), "INCOMPLETE", "receipt-stale", ["inventory", "recipe"])
        finally:
            manifest.write_bytes(original)
        try:
            manifest.write_text("{")
            self.result(self.validate(), "INCOMPLETE", "receipt-stale", ["inventory", "recipe"])
        finally:
            manifest.write_bytes(original)
        external = self.fixture.root / "manifest.json"
        external.write_text(json.dumps(obj))
        self.result(self.validate(["--manifest", str(external)]), "INCOMPLETE", "receipt-stale", ["recipe"])
        denylist = self.clean.denylist.read_bytes()
        try:
            self.clean.denylist.write_bytes(denylist + b"\n")
            self.result(self.validate(), "INCOMPLETE", "receipt-stale", ["policy"])
        finally:
            self.clean.denylist.write_bytes(denylist)
        for flags in (["--timeout", "301"], ["--private-repo", "synthetic/private"]):
            self.result(self.validate(flags), "INCOMPLETE", "receipt-stale", ["policy"])
        with patch.object(rc, "VERSION", "synthetic"):
            self.result(self.validate(), "INCOMPLETE", "receipt-stale", ["scanners"])
        real_sha256 = rc.sha256
        scanner_bytes = Path(rc.__file__).read_bytes()
        with patch.object(rc, "sha256", side_effect=lambda raw: "0" * 64 if raw == scanner_bytes else real_sha256(raw)):
            self.result(self.validate(), "INCOMPLETE", "receipt-stale", ["scanners"])
        self.result(self.validate(), "PASS", mismatched=[])

    def test_invalid_receipts(self):
        receipt = json.loads(self.receipt_bytes)
        unknown = {**receipt, "schema_version": 2}
        unknown["receipt_sha256"] = rc.sha256(rc.canonical_json({k: v for k, v in unknown.items() if k != "receipt_sha256"}))
        variants = [b"[]", b"{", b'{"schema_version":1,"schema_version":1}',
                    rc.canonical_json({**receipt, "outcome": "FAIL"}), rc.canonical_json(unknown)]
        path = self.fixture.root / "invalid.json"
        for raw in variants:
            with self.subTest(raw=raw[:35]):
                path.write_bytes(raw)
                result = self.result(self.validate(path=path), "INCOMPLETE", "receipt-invalid", [])
                self.assertEqual(result["reasons"], ["receipt-invalid"])

    def test_reports_cannot_be_inside_export(self):
        target = self.fixture.root / "export"
        run = self.fixture.run_cli("--export", str(target), "--reports", str(target / "reports"))
        self.assertEqual(run[0], 2)
        self.assertEqual(json.loads(run[2])["outcome"], "INCOMPLETE")
        self.assertFalse(target.exists())

    def test_fallback_report_is_incomplete(self):
        with patch.object(rc, "audit", side_effect=rc.AuditError("synthetic")):
            run = self.fixture.run_cli()
        self.assertEqual(run[0], 2)
        report = self.report()
        self.assertEqual(report["outcome"], "INCOMPLETE")
        self.assertIn("audit-incomplete", report["reasons"])
        self.assertFalse(report["ready"])

    def test_leak_assertion_detects_ignored_findings(self):
        (self.fixture.repo / "leak.txt").write_text("ghp_" + "Ab12" * 9)
        real_outcome = rc.outcome
        with patch.object(rc, "verify", side_effect=verified), patch.object(
                rc, "outcome", side_effect=lambda report: real_outcome({**report, "findings": []})):
            run = self.fixture.run_cli("--verify")
        with self.assertRaises(AssertionError):
            self.result(run, "FAIL")
        self.result(run, "PASS")


if __name__ == "__main__":
    unittest.main()
