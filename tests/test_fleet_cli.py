import json
import os
import unittest

import release_check as rc
import test_release_check as fixtures
from fleet_policy import COLD, COLD_SUBCOMMANDS, FLEET_PATTERNS, add_fleet_pack

FLEET_LINES = (
    "Pick a reviewer with `" + COLD + " model get reviewer`.",
    "CI runs `python3 /opt/coldstack/" + COLD + " verify --ci`.",
    "Merge with `" + COLD + " review owner/repo PR --builder-model model --merge`.",
)
NEUTRAL_LINES = (
    "Run `coldrelease verify SOURCE --run ID` before you publish.",
    "Run `python3 release_check.py . --verify --export ../out`.",
    "A " + COLD + " start is slower than a warm one.",
    "Use coldstack review notes for context.",
)


def fleet_findings(findings):
    return [f for f in findings if f["kind"] == "fleet-cli"]


class FleetCliScannerTests(unittest.TestCase):
    def test_fleet_commands_block_with_file_and_line_and_neutral_examples_stay_clean(self):
        text = ("# Notes\n" + "\n".join(FLEET_LINES) + "\n" + "\n".join(NEUTRAL_LINES) + "\n").encode()
        for scope in ("tree", "history"):
            with self.subTest(scope=scope):
                scanner = rc.Scanner(FLEET_PATTERNS)
                scanner.text(text, scope, "rules/model-routing.md")
                found = scanner.findings
                self.assertEqual([(f["kind"], f["scope"], f["path"], f["line"], f["category"], f["reviewed"]) for f in found],
                                 [("fleet-cli", scope, "rules/model-routing.md", line, "personal", False) for line in (2, 3, 4)])
                self.assertEqual(rc.outcome({"findings": scanner.findings})["outcome"], "FAIL")


    def test_every_subcommand_separator_encoding_and_approval_path(self):
        for command in COLD_SUBCOMMANDS:
            for prefix, gap in (("", " "), ("/opt/coldstack/", "\t"), ("~/.local/bin/", "  "), ("./", "\u00a0")):
                value = COLD + gap + command
                with self.subTest(command=command, prefix=prefix, gap=repr(gap)):
                    scanner = rc.Scanner(FLEET_PATTERNS)
                    scanner.text(("$ " + prefix + value + " --help\n").encode(), "tree", "README.md")
                    self.assertEqual([(f["kind"], f["fingerprint"]) for f in scanner.findings], [("fleet-cli", rc.fingerprint(value))])
        scanner = rc.Scanner(FLEET_PATTERNS)
        scanner.text((COLD + " check L13\n").encode("utf-16"), "tree", "notes.txt")
        self.assertIn(rc.fingerprint(COLD + " check"), {f["fingerprint"] for f in fleet_findings(scanner.findings)})
        for source, line in (("Use `" + COLD + "\nmodel get reviewer`.\n", 1), ("x\nRun " + COLD + "\r\n   verify --ci\n", 2),
                             ("a\n" + COLD + "\u2028gate\n", 2)):
            with self.subTest(wrapped=source):
                scanner = rc.Scanner(FLEET_PATTERNS)
                scanner.text(source.encode(), "tree", "README.md")
                self.assertEqual([(f["kind"], f["line"]) for f in scanner.findings], [("fleet-cli", line)])
        line = "Run `" + COLD + " doctor`.\n"
        approval = {"scope": "tree", "kind": "fleet-cli", "path": "README.md", "fingerprint": rc.fingerprint(COLD + " doctor")}
        for approvals, reviewed in (([approval], True), ([dict(approval, fingerprint=rc.fingerprint(COLD + " gate"))], False),
                                    ([dict(approval, path="OTHER.md")], False), ([], False)):
            with self.subTest(approvals=approvals):
                scanner = rc.Scanner(FLEET_PATTERNS, approvals=approvals)
                scanner.text(line.encode(), "tree", "README.md")
                self.assertEqual([(f["kind"], f["reviewed"]) for f in scanner.findings], [("fleet-cli", reviewed)])
                self.assertEqual(rc.outcome({"findings": scanner.findings})["outcome"] == "FAIL", not reviewed)

    def test_side_branch_deleted_blob_commit_message_filename_and_symlink_block(self):
        fx = fixtures.AuditTests()
        fx.setUp()
        self.addCleanup(fx.doCleanups)
        add_fleet_pack(fx)
        fx.git("checkout", "-q", "-b", "side")
        (fx.repo / "old.md").write_text("Run " + COLD + " stalled first.\n")
        fx.commit("Side notes")
        fx.git("rm", "-q", "--", "old.md")
        fx.git("commit", "-q", "-m", "Drop notes")
        fx.git("checkout", "-q", "main")
        fx.git("branch", "-q", "-D", "side")
        (fx.repo / "docs").mkdir()
        (fx.repo / ("docs/" + COLD + " usage.md")).write_text("Notes.\n")
        os.symlink(COLD + " launch", fx.repo / "launcher")
        fx.git("add", "--", "launcher")
        fx.commit("Then " + COLD + " gate before merge")
        found = {(f["scope"], f["fingerprint"]) for f in fleet_findings(fx.scan().findings)}
        for scope, value in (("history", "stalled"), ("metadata", "gate"), ("tree", "usage"), ("history", "usage"),
                             ("tree", "launch"), ("history", "launch")):
            self.assertIn((scope, rc.fingerprint(COLD + " " + value)), found)


class FleetCliExportTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        add_fleet_pack(self.fx)

    def test_export_with_fleet_commands_fails_without_pass_receipt(self):
        readme = self.fx.repo / "README.md"
        readme.write_text(readme.read_text() + FLEET_LINES[0] + "\n" + "\n".join(NEUTRAL_LINES) + "\n")
        (self.fx.repo / "rules").mkdir()
        (self.fx.repo / "rules/coldbox-verification.md").write_text("# Verify\n" + FLEET_LINES[1] + "\n" + FLEET_LINES[2] + "\n"
                                                                     + "Then `" + COLD + "\ngate` before merging.\n")
        self.fx.commit("Add fleet notes")
        code, out, err = self.fx.run_cli("--verify", "--export", str(self.fx.root / "export"))
        self.assertEqual(code, 1, out + err)
        report = json.loads(next((self.fx.root / "reports").rglob("report.json")).read_text())
        export = report["export"]
        self.assertEqual(export["outcome"], "FAIL")
        self.assertIn("fleet-cli", export["reasons"])
        locations = {(f["scope"], f["path"], f["line"]) for f in fleet_findings(export["findings"])}
        self.assertEqual({(scope, path, line) for scope in ("tree", "history")
                          for path, line in (("README.md", 5), ("rules/coldbox-verification.md", 2), ("rules/coldbox-verification.md", 3),
                                                         ("rules/coldbox-verification.md", 4))},
                         locations)
        self.assertFalse([f for f in export["findings"] if f["path"] == "README.md" and f["line"] > 5])
        receipt = json.loads(next((self.fx.root / "reports").rglob("receipt.json")).read_text())
        self.assertEqual(receipt["outcome"], "FAIL")
        self.assertIn("fleet-cli", receipt["reasons"])


if __name__ == "__main__":
    unittest.main()
