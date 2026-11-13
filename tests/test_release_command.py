from contextlib import redirect_stderr, redirect_stdout
import io
import json
import shlex
import subprocess
import sys
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
from tests import test_release_workflow as flows


class ReleaseCommandTests(unittest.TestCase):
    def setUp(self):
        self.flow = flows.WorkflowTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        self.enterContext(self.flow.fake_gitleaks())
        self.run_dir = self.flow.run

    def argv(self, *extra):
        return ["release", str(self.flow.repo), "--denylist", str(self.flow.testbed.denylist), "--run", "first",
                *self.flow.target_flags(), "--scanner", "gitleaks", *extra]

    def release(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), patch.object(rc, "verify", side_effect=flows.verified):
            code = rc.main(self.argv(*extra))
        return code, json.loads(out.getvalue()), err.getvalue()

    def assert_awaits_push(self, result):
        code, value, err = result
        self.assertEqual((code, value["outcome"], value["reasons"]), (2, "INCOMPLETE", ["release-not-pushed"]), value)
        self.assertIn("push --force-with-lease=refs/heads/main:", value["detail"])
        self.assertEqual(self.flow.remote_head(), "")
        self.assertFalse((self.run_dir / "published.json").exists())

    def test_cli_release_stops_at_the_guarded_push_then_records_and_gates_it(self):
        process = subprocess.run([sys.executable, rc.__file__, *self.argv()], stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True)
        self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
        for stage in ("preflight", "plan", "export", "approve"):
            self.assertIn("release: %s PASS" % stage, process.stderr)
        self.assert_awaits_push((2, json.loads(process.stdout), process.stderr))
        self.flow.push()
        process = subprocess.run([sys.executable, rc.__file__, *self.argv()], stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        result = json.loads(process.stdout)
        self.assertEqual((result["outcome"], result["published_head"], result["final_gate"]["outcome"]),
                         ("PASS", self.flow.remote_head(), "PASS"), result)
        self.assertIn("release: publish PASS", process.stderr)
        self.assertIn("Next: make the target public", process.stderr)
        self.assertFalse(list(self.run_dir.glob("*.sig")))

    def test_release_with_a_finding_stops_at_triage_with_fail_and_pushes_nothing(self):
        (self.flow.repo / "leak.txt").write_text("Hidden" + "Person\n")
        self.flow.testbed.commit("Unsafe synthetic testbed")
        code, result, err = self.release()
        self.assertEqual((code, result["outcome"]), (1, "FAIL"), result)
        self.assertEqual(result["next"], shlex.join(["coldrelease", "review", str(self.flow.repo), "--run", "first"])
                         + ", then rerun this release command")
        self.assertIn("Next: " + result["next"], err)
        self.assertNotIn("HiddenPerson", err + json.dumps(result))
        self.assertEqual(self.flow.remote_head(), "")
        self.assertFalse((self.run_dir / "approval.json").exists())

    def test_release_records_a_resumed_runs_preflight_blocker_for_triage(self):
        self.flow.cli("plan", "--scanner", "gitleaks")
        readme = self.flow.repo / "README.md"
        readme.write_text(readme.read_text().replace("## Honest limitations", "## Notes"))
        self.flow.testbed.commit("Drop a required heading after plan")
        code, result, err = self.release()
        self.assertEqual((code, result["outcome"]), (1, "FAIL"), result)
        self.assertTrue(result["next"].startswith(shlex.join(["coldrelease", "review", str(self.flow.repo)])), result)
        self.assertEqual(len(list(self.run_dir.glob("preflight-*.json"))), 1)
        self.assertNotIn("release: export", err)
        self.assertEqual(self.flow.remote_head(), "")

    def test_release_continues_from_the_recorded_state(self):
        self.assert_awaits_push(self.release())
        self.flow.push()
        code, result, err = self.release()
        self.assertEqual((code, result["outcome"]), (0, "PASS"), result)
        self.assertEqual(err.count("release: "), 2, err)
        self.assertIn("release: publish PASS\nrelease: final-gate PASS", err)
        self.assertEqual(self.flow.remote_head(), result["published_head"])
        code, again, err = self.release()
        self.assertEqual((code, again["final_gate"]["outcome"], again["published_head"]),
                         (0, "PASS", result["published_head"]), again)
        self.assertEqual(err.count("release: "), 1, err)
        self.assertIn("release: final-gate PASS", err)
        self.assertEqual(self.flow.remote_head(), result["published_head"])

    def test_release_rerun_reports_a_failing_final_gate(self):
        self.release()
        self.flow.push()
        code, result, err = self.release()
        self.assertEqual((code, result["outcome"]), (0, "PASS"), result)
        with patch.object(workflow, "final_gate", return_value={"outcome": "FAIL", "report": None}):
            code, again, err = self.release()
        self.assertEqual((code, again["outcome"], again["reasons"]), (1, "FAIL", ["final-gate-not-pass"]), again)
        self.assertTrue(again["next"].startswith("do not make the target public"), again)

    def test_release_exports_again_when_the_source_moved_after_a_passing_export(self):
        self.flow.export()
        (self.flow.repo / "README.md").write_text((self.flow.repo / "README.md").read_text() + "Fixed-line-marker\n")
        self.flow.testbed.commit("Fix after export")
        result = self.release()
        self.assertIn("release: export PASS", result[2])
        self.assert_awaits_push(result)
        self.flow.push()
        code, result, err = self.release()
        self.assertEqual((code, result["outcome"]), (0, "PASS"), result)
        published = self.flow.remote_git("show", result["published_head"] + ":README.md")
        self.assertIn("Fixed-line-marker", "\n".join(published))

    def test_release_refuses_an_approval_of_an_older_source(self):
        self.flow.export()
        self.flow.prepare()
        (self.flow.repo / "README.md").write_text((self.flow.repo / "README.md").read_text() + "Fixed-line-marker\n")
        self.flow.testbed.commit("Fix after approve")
        code, result, err = self.release()
        self.assertEqual((code, result["outcome"], result["reasons"]), (2, "INCOMPLETE", ["source-changed"]), result)
        self.assertEqual(self.flow.remote_head(), "")

    def test_release_points_a_scanner_failure_at_scanners_json_not_review(self):
        def scan(attempt, name, receipt, timeout, repo):
            return {"name": name, "outcome": "FAIL", "version": "synthetic", "output_sha256": "a" * 64,
                    "export_head": receipt["export_head"], "export_tree": receipt["export_tree"]}
        with patch.object(workflow, "scan_export", side_effect=scan), patch.object(workflow, "require_supported_flags"):
            code, result, err = self.release()
        self.assertEqual((code, result["outcome"]), (1, "FAIL"), result)
        self.assertIn("scanners.json in attempt " + result["attempt"], result["next"])
        self.assertNotIn("coldrelease review", result["next"])
        self.assertEqual(self.flow.remote_head(), "")
        self.assertFalse((self.run_dir / "approval.json").exists())

    def test_release_records_a_run_approved_and_pushed_outside_it(self):
        self.flow.export()
        self.flow.prepare()
        self.flow.push()
        code, result, err = self.release()
        self.assertEqual((code, result["outcome"], result["final_gate"]["outcome"]), (0, "PASS", "PASS"), result)
        self.assertIn("release: publish PASS", err)
        self.assertEqual(self.flow.remote_head(), result["published_head"])

    def test_release_stops_at_a_proposed_recipe_and_continues_once_accepted(self):
        repo = self.flow.repo
        (repo / "release-check.json").write_text(json.dumps({"exclude": [], "approvals": []}))
        (repo / "pyproject.toml").write_text('[project]\nname = "testbed"\nversion = "0"\n')
        (repo / "README.md").write_text((repo / "README.md").read_text() + "```\npython -m pip install .\n```\n")
        self.flow.testbed.commit("Drop the recipe")
        code, result, err = self.release()
        proposal, accepted = self.run_dir / "proposed-release-check.json", self.run_dir / "release-check.json"
        self.assertEqual((code, result["outcome"], result["reasons"]), (2, "INCOMPLETE", ["recipe-not-accepted"]), result)
        self.assertEqual(result["next"], "review " + str(proposal) + ", accept it with "
                         + shlex.join(["mv", str(proposal), str(accepted)]) + ", then rerun this release command")
        proposal.rename(accepted)
        self.assert_awaits_push(self.release())
        self.flow.push()
        code, result, err = self.release()
        self.assertEqual((code, result["outcome"]), (0, "PASS"), result)
        self.assertEqual(self.flow.remote_head(), result["published_head"])

    def test_release_refuses_missing_decision_inputs_before_any_stage(self):
        for flag, width, reason in (("--scanner", 2, "scanners-required"), ("--verify", 1, "verification-not-authorized"),
                                    ("--target", 2, "approval-target-required")):
            argv = self.argv()
            index = argv.index(flag)
            del argv[index:index + width]
            with self.subTest(drop=flag), redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
                self.assertEqual(rc.main(argv), 2)
                self.assertEqual(json.loads(out.getvalue())["reasons"], [reason])
        for flag in ("--key", "--identity", "--allowed-signers", "--scanner-waiver"):
            with self.subTest(removed=flag), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                rc.main(self.argv(flag, *(() if flag == "--scanner-waiver" else (str(self.flow.root / "x"),))))
        self.assertFalse(self.run_dir.exists())


if __name__ == "__main__":
    unittest.main()
