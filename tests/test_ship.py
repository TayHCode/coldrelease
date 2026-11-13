from contextlib import redirect_stderr, redirect_stdout
import io
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
from tests import test_release_workflow as flows

FLIP = ' --visibility public --accept-visibility' '-change-consequences'


def failed_verification(*args, **kwargs):
    return {"status": "fail", "commands": [], "dependencies": {"blocked": 0}}


class ShipTests(unittest.TestCase):
    def setUp(self):
        self.flow = flows.WorkflowTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        self.run_dir = self.flow.run

    def argv(self, *extra, target=None):
        return ["ship", str(self.flow.repo), "--denylist", str(self.flow.testbed.denylist), "--run", "first",
                *self.flow.target_flags(target), *extra]

    def ship(self, *extra, target=None, verify=flows.verified, argv=None):
        out, err = io.StringIO(), io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(err), patch.object(rc, "verify", side_effect=verify):
                code = rc.main(argv or self.argv(*extra, target=target))
        except SystemExit as exit:
            self.fail("ship is not a command (exit %s): %s" % (exit.code, err.getvalue()))
        return code, json.loads(out.getvalue()), err.getvalue()

    def export_head(self, attempt):
        return workflow.read_json(attempt / "receipt.json")["export_head"]

    def approved(self):
        attempt = self.flow.export()
        self.flow.prepare()
        return attempt

    def pushed(self):
        attempt = self.approved()
        self.flow.push()
        return attempt

    def assert_refused(self, result, reason):
        code, value, err = result
        self.assertEqual((code, value["outcome"], value["reasons"]), (2, "INCOMPLETE", [reason]), value)
        self.assertNotIn("gh repo edit", err + json.dumps(value))
        self.assertFalse((self.run_dir / "published.json").exists())

    def test_cli_ship_records_the_guarded_push_and_gates_the_target_without_flipping_it(self):
        target_dir = self.flow.root / "home"
        target_dir.mkdir()
        target = target_dir / "public.git"
        self.flow.remote.rename(target)
        self.flow.remote = target
        attempt = self.pushed()
        process = subprocess.run([sys.executable, rc.__file__, *self.argv()], stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        result = json.loads(process.stdout)
        head = self.export_head(attempt)
        self.assertEqual((result["outcome"], result["published_head"], result["final_gate"]["outcome"]),
                         ("PASS", head, "PASS"), result)
        self.assertEqual(self.flow.remote_head(), head)
        self.assertEqual(rc.git(self.flow.repo, "--git-dir=" + str(self.flow.remote), "rev-list", "--count", head).strip(), b"1")
        self.assertNotIn(str(target), process.stderr)
        report = self.run_dir / "final-gate" / result["final_gate"]["report"]
        gate = json.loads(report.read_text())
        self.assertEqual((gate["outcome"], gate["published_target"]["head"]), ("PASS", head))
        self.assertEqual(result["next"], "make the target public with its host, then run coldrelease confirm-public on this run")
        self.assertIn("Next: " + result["next"], process.stderr)
        self.assertTrue((self.run_dir / "published.json").is_file())

    def test_preflight_to_ship_leaves_the_source_byte_identical(self):
        repo = self.flow.repo
        (repo / "untracked-notes.txt").write_text("local only\n")

        def snapshot():
            return {path.relative_to(repo).as_posix(): (path.lstat().st_mode, path.read_bytes() if path.is_file() else None)
                    for path in sorted(repo.rglob("*"))}

        before = snapshot()
        self.assertEqual(self.flow.cli("preflight")[1]["outcome"], "PASS")
        self.pushed()
        code, result, err = self.ship()
        self.assertEqual((code, result["outcome"]), (0, "PASS"), err)
        self.assertEqual(snapshot(), before)
        self.assertFalse(self.run_dir.is_relative_to(repo))
        self.assertEqual(self.run_dir.stat().st_mode & 0o777, 0o700)

    def test_ship_appends_to_public_history_and_gates_the_release_commit(self):
        old = self.flow.public_history("Earlier public release")
        attempt = self.pushed()
        code, result, err = self.ship()
        head = self.flow.remote_head()
        receipt = workflow.read_json(attempt / "receipt.json")
        self.assertEqual((code, result["outcome"], result["published_head"], result["final_gate"]["outcome"]),
                         (0, "PASS", head, "PASS"), result)
        self.assertEqual(self.flow.remote_git("rev-list", "--parents", "-n", "1", head), [head, old])
        gate = json.loads((self.run_dir / "final-gate" / result["final_gate"]["report"]).read_text())
        self.assertEqual((gate["outcome"], gate["published_target"]["head"], gate["published_target"]["tree"]),
                         ("PASS", head, receipt["export_tree"]))

    def test_ship_prints_the_exact_github_flip_line(self):
        flip = getattr(workflow, "flip_command", lambda target: None)
        for target in ("https://github.com/example/project.git", "https://github.com/example/project",
                       'git@git' 'hub.com:example/project.git', 'ssh://git@git' 'hub.com/example/project.git'):
            with self.subTest(target=target):
                self.assertEqual(flip(target), "gh repo edit example/project" + FLIP)
        for target in ("https://gitlab.com/example/project.git", "/srv/git/project.git",
                       "https://github.com/example/project/extra", "https://github.com.evil/example/project"):
            with self.subTest(target=target):
                self.assertFalse(flip(target))

    def test_ship_before_the_guarded_push_refuses_and_pushes_nothing(self):
        self.approved()
        code, value, err = self.ship()
        self.assert_refused((code, value, err), "release-not-pushed")
        self.assertIn("push --force-with-lease=refs/heads/main:", err + json.dumps(value))
        self.assertEqual(self.flow.remote_head(), "")

    def test_ship_refuses_when_approval_is_missing_or_already_published(self):
        self.flow.export()
        self.assert_refused(self.ship(), "approval-missing")
        self.flow.prepare()
        self.flow.push()
        self.assertEqual(self.ship()[1]["outcome"], "PASS")
        code, value, err = self.ship()
        self.assertEqual((code, value["reasons"]), (2, ["already-published"]), value)

    def test_ship_refuses_a_stale_approval(self):
        self.approved()
        with patch.object(rc, "verify", side_effect=flows.verified), self.flow.fake_gitleaks():
            self.flow.assert_status(self.flow.cli("export", "--verify"), "PASS")
        self.assert_refused(self.ship(), "approval-receipt")
        self.assertEqual(self.flow.remote_head(), "")

    def test_other_target_refs_do_not_block_ship_but_a_moved_target_fails(self):
        self.approved()
        rc.git(self.flow.repo, "push", str(self.flow.remote), "HEAD:refs/tags/private")
        self.assert_refused(self.ship(), "release-not-pushed")
        rc.git(self.flow.remote, "update-ref", "-d", "refs/tags/private")
        rc.git(self.flow.repo, "push", str(self.flow.remote), "HEAD:refs/heads/main")
        code, value, err = self.ship()
        self.assertEqual((code, value["outcome"], value["reasons"]), (1, "FAIL", ["target-moved"]), value)
        self.assertFalse((self.run_dir / "published.json").exists())

    def test_ship_and_publish_take_no_key(self):
        self.pushed()
        for command in ("ship", "publish"):
            with self.subTest(command=command), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.flow.cli(command, *self.flow.target_flags(), "--key", str(self.flow.root / "key"))
        self.assertFalse((self.run_dir / "published.json").exists())

    def test_final_gate_keeps_the_runs_byte_bound_reviews(self):
        text = "Public contact: help" + "@example.org\n"
        (self.flow.repo / "contact.txt").write_text(text)
        self.flow.testbed.commit("Add documented synthetic contact")
        self.enterContext(patch.object(workflow, "scan_export", side_effect=self.flow.passing_scan))
        self.enterContext(patch.object(workflow.shutil, "which", return_value=None))
        self.flow.assert_status(self.flow.cli("plan", "--scanner", "gitleaks"), "PASS")
        with patch.object(rc, "verify", side_effect=flows.verified):
            check = self.flow.assert_status(self.flow.cli("check", "--verify"), "FAIL")
            report = workflow.read_json(self.run_dir / "attempts" / check["attempt"] / "report.json")
            triage = [{**{k: f[k] for k in ("scope", "kind", "path", "fingerprint")}, "file_sha256": rc.sha256(text.encode())}
                      for f in report["findings"] if f["kind"] == "email"]
            self.assertTrue(triage)
            (self.run_dir / "triage.json").write_text(json.dumps(triage))
            self.flow.assert_status(self.flow.cli("export", "--verify"), "PASS")
        self.flow.prepare()
        self.flow.push()
        code, value, err = self.ship()
        self.assertEqual((code, value["outcome"], value["final_gate"]["outcome"]), (0, "PASS", "PASS"), value)

    def test_ship_refuses_a_target_tree_swapped_after_readback(self):
        attempt = self.pushed()
        approved = workflow.read_json(attempt / "receipt.json")
        swap = self.flow.root / "other-writer"
        real_final_gate = workflow.final_gate

        def swap_then_gate(*args, **kwargs):
            rc.git(self.flow.root, "clone", "-q", "--branch", "main", str(self.flow.remote), str(swap))
            author = rc.git(swap, "log", "-1", "--format=%an%n%ae").decode().split("\n")
            (swap / "NOTICE.txt").write_text("Replacement content.\n")
            rc.git(swap, "add", "NOTICE.txt")
            rc.git(swap, "-c", "user.name=" + author[0], "-c", "user.email=" + author[1],
                   "commit", "-q", "-m", "Replacement export")
            rc.git(swap, "push", "-q", "origin", "HEAD:refs/heads/main")
            return real_final_gate(*args, **kwargs)

        with patch.object(workflow, "final_gate", side_effect=swap_then_gate):
            code, value, err = self.ship()
        swapped = rc.git(swap, "rev-parse", "HEAD", "HEAD^{tree}").decode().split()
        self.assertNotEqual(swapped, [approved["export_head"], approved["export_tree"]])
        self.assertEqual(self.flow.remote_head(), swapped[0])
        self.assertEqual((code, value["outcome"], value["final_gate"]["outcome"], value.get("reasons")),
                         (1, "FAIL", "FAIL", ["final-gate-not-pass"]), value)
        self.assertIn('"error":"published-receipt-mismatch"', err)
        self.assertTrue(value["next"].startswith("do not make the target public"), value)
        self.assertNotIn("gh repo edit", err + json.dumps(value))
        self.assertNotIn("make the target public with its host", err + json.dumps(value))

    def test_failed_final_gate_withholds_the_flip(self):
        attempt = self.pushed()
        code, value, err = self.ship(verify=failed_verification)
        self.assertEqual((code, value["outcome"], value["reasons"]), (2, "INCOMPLETE", ["final-gate-not-pass"]), value)
        self.assertEqual((value["published_head"], value["final_gate"]["outcome"]), (self.export_head(attempt), "INCOMPLETE"))
        self.assertEqual(self.flow.remote_head(), self.export_head(attempt))
        self.assertTrue(value["next"].startswith("do not make the target public"), value)
        self.assertNotIn("gh repo edit", err + json.dumps(value))


if __name__ == "__main__":
    unittest.main()
