import json
import subprocess
import sys
import unittest

import release_check as rc
import release_workflow as workflow
import test_release_check as fixtures
from fleet_policy import add_fleet_pack

BOT = "Grok" + " Bot"


class GrokBotReferenceTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        add_fleet_pack(self.testbed)
        self.repo = self.testbed.repo

    def fleet_findings(self, scanner):
        return [f for f in scanner.findings if f["kind"] == "fleet-reference"]

    def test_bot_name_variants_block_at_the_exact_line_and_neutral_names_stay_clean(self):
        neutral = rc.Scanner(self.testbed.terms)
        neutral.text(b"Grok is a model.\nA Discord bot and a chatbot.\nWe grokked the robot docs.\n", "tree", "README.md")
        self.assertEqual(neutral.findings, [])
        for name in (BOT, BOT.lower(), BOT.upper(), "Grok" + "-Bot", "Grok" + "Bot", "grok" + "_bot", "Grok" + " Bots"):
            with self.subTest(name=name):
                scanner = rc.Scanner(self.testbed.terms)
                scanner.text(f"# Tool\n\nConnect {name} first.\n".encode(), "tree", "README.md")
                found = self.fleet_findings(scanner)
                self.assertEqual([(f["category"], f["path"], f["line"], f["reviewed"]) for f in found],
                                 [("personal", "README.md", 3, False)])

    def test_name_wrapped_across_lines_blocks_at_its_first_line(self):
        for gap in ("\n", " \r\n  "):
            with self.subTest(gap=gap):
                scanner = rc.Scanner(self.testbed.terms)
                scanner.text(f"# Tool\nConnect Grok{gap}Bot first.\n".encode(), "tree", "README.md")
                self.assertEqual([(f["path"], f["line"], f["reviewed"]) for f in self.fleet_findings(scanner)],
                                 [("README.md", 2, False)])

    def test_history_only_reference_fails_the_audit(self):
        readme = self.repo / "README.md"
        original = readme.read_text()
        readme.write_text(original.replace("Synthetic only.\n", f"Synthetic only.\nSee {BOT}.\n"))
        self.testbed.commit("Mention the bot")
        readme.write_text(original)
        self.testbed.commit("Remove the bot")

        scanner = self.testbed.scan()
        self.assertEqual({(f["scope"], f["path"], f["line"]) for f in self.fleet_findings(scanner)}, {("history", "README.md", 4)})
        code, out, _ = self.testbed.run_cli()
        self.assertEqual((code, json.loads(out)["outcome"]), (1, "FAIL"), out)

    def workflow(self, command, run, *extra):
        process = subprocess.run([sys.executable, rc.__file__, command, str(self.repo), "--denylist", str(self.testbed.denylist),
                                  "--run", run, *extra], capture_output=True, text=True)
        return process.returncode, json.loads(process.stdout)

    def test_standard_export_fails_without_a_denylist_term(self):
        self.assertNotIn("grok", json.dumps([t for t in self.testbed.terms if isinstance(t, str)]).lower())
        readme = self.repo / "README.md"
        readme.write_text(readme.read_text() + f"{BOT}: follow docs/setup.md\n")
        self.testbed.commit("Mention the bot")
        code, result = self.workflow("plan", "bot")
        self.assertEqual((code, result["outcome"]), (0, "PASS"), result)
        code, result = self.workflow("export", "bot", "--verify")
        self.assertEqual((code, result["outcome"]), (1, "FAIL"), result)
        run = workflow.run_directory(self.repo, "bot")
        attempt = run / "attempts" / workflow.read_json(run / "export.json")["attempt"]
        report = workflow.read_json(attempt / "report.json")
        found = {(f["scope"], f["path"], f["line"]) for f in report["findings"] if f["kind"] == "fleet-reference"}
        self.assertEqual(found, {("tree", "README.md", 5), ("history", "README.md", 5)})
        self.assertEqual(workflow.read_json(attempt / "receipt.json")["outcome"], "FAIL")


if __name__ == "__main__":
    unittest.main()
