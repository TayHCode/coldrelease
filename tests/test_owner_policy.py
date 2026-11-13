import json
import unittest

import release_check as rc
import test_release_check as fixtures
from fleet_policy import COLD, FLEET_PATTERNS, add_fleet_pack

STRANGER_NOTES = ("Run `" + COLD + " check` on your laptop, then `" + COLD + " verify`.\n"
                  "Our " + "Gr" + "ok Bot answers questions.\n")


class OwnerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        (self.fx.repo / "NOTES.md").write_text(STRANGER_NOTES)
        self.fx.commit("Add notes")

    def test_built_in_detectors_are_generic(self):
        scanner = rc.Scanner([])
        scanner.text(STRANGER_NOTES.encode(), "tree", "NOTES.md")
        self.assertEqual(scanner.findings, [])
        self.assertFalse({"fleet-cli", "fleet-reference"} & set(rc.PATTERNS))

    def test_stranger_repo_mentioning_the_words_passes_without_the_pack(self):
        code, out, err = self.fx.run_cli("--verify")
        self.assertEqual((code, json.loads(out)["outcome"]), (0, "PASS"), out + err)

    def test_owner_pack_in_the_denylist_blocks_the_same_repo(self):
        add_fleet_pack(self.fx)
        code, out, err = self.fx.run_cli("--verify")
        result = json.loads(out)
        self.assertEqual((code, result["outcome"]), (1, "FAIL"), out + err)
        report = json.loads(next((self.fx.root / "reports").rglob("report.json")).read_text())
        found = {(f["kind"], f["scope"], f["line"]) for f in report["findings"] if f["path"] == "NOTES.md"}
        self.assertEqual(found, {(kind, scope, line) for scope in ("tree", "history")
                                 for kind, line in (("fleet-cli", 1), ("fleet-reference", 2))})
        self.assertEqual(sum(f["kind"] == "fleet-cli" and f["scope"] == "tree" for f in report["findings"]), 2)
        self.assertEqual(rc.load_terms(self.fx.denylist), ["HiddenPerson", *FLEET_PATTERNS])

    def test_approval_reason_naming_an_owner_pattern_match_is_rejected(self):
        rule = {"kind": "owner-rule", "pattern": "secret"}
        probe = rc.Scanner([rule])
        probe.text(b"secret\n", "tree", "NOTES.md")
        approval = {key: probe.findings[0][key] for key in ("scope", "kind", "path", "fingerprint", "source_sha256", "line")}
        approval["classification"] = "false-positive"
        for reason, reported in (("Public name, reviewed.", ["Public name, reviewed."]), ("The secret is public.", [None])):
            with self.subTest(reason=reason):
                scanner = rc.Scanner([rule], approvals=[{**approval, "reason": reason}])
                scanner.text(b"secret\n", "tree", "NOTES.md")
                self.assertEqual([f.get("reason") for f in scanner.findings], reported)
                self.assertEqual([f["reviewed"] for f in scanner.findings], [reported != [None]])

    def test_multiline_owner_pattern_is_redacted_from_paths_and_diagnostics(self):
        scanner = rc.Scanner([{"kind": "owner-rule", "pattern": "^secret$"}])
        self.assertNotIn("secret", scanner.safe_path("folder/\nsecret\n/file"))
        failure = rc.venv_failure(b"error\nsecret\nend", scanner)
        self.assertNotIn("secret", failure["error_tail"])

    def test_patterns_that_depend_on_a_line_break_block_at_their_first_line(self):
        for pattern in ("secret\\n", "secret(?=\\nproject)", "^secret$"):
            with self.subTest(pattern=pattern):
                scanner = rc.Scanner([{"kind": "owner-rule", "pattern": pattern}])
                scanner.text(b"x\nsecret\nproject\n", "tree", "NOTES.md")
                self.assertEqual([(f["kind"], f["line"]) for f in scanner.findings], [("owner-rule", 2)])


if __name__ == "__main__":
    unittest.main()
