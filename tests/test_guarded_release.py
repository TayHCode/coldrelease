from contextlib import redirect_stderr
from datetime import datetime, timedelta
import io
import json
import os
import shlex
import shutil
import subprocess
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
from tests import test_release_workflow as base


class GuardedReleaseTests(unittest.TestCase):
    def setUp(self):
        self.w = base.WorkflowTests()
        self.w.setUp()
        self.addCleanup(self.w.doCleanups)
        self.run = self.w.run
        self.guards = self.w.home / ".coldlocker" / "guards.json"

    def approve(self, *extra, target=None):
        errors = io.StringIO()
        with redirect_stderr(errors):
            result = self.w.cli("approve", *self.w.target_flags(target), *extra)
        return result, errors.getvalue()

    def test_approve_without_identity_records_the_release_and_names_the_denylist(self):
        attempt = self.w.export()
        result, summary = self.approve()
        value = self.w.assert_status(result, "PASS")
        record = workflow.read_json(self.run / "approval.json")
        receipt = workflow.read_json(attempt / "receipt.json")
        self.assertEqual(record["receipt_sha256"], receipt["receipt_sha256"])
        self.assertEqual((record["target"], record["ref"], record["expected_public_head"], record["release_head"]),
                         (str(self.w.remote), "refs/heads/main", None, receipt["export_head"]))
        denylist = self.w.testbed.denylist
        terms = rc.load_terms(denylist)
        self.assertEqual(record["denylist"], {"path": str(denylist), "sha256": rc.sha256(denylist.read_bytes()),
                                              "terms": sum(not isinstance(t, dict) for t in terms),
                                              "patterns": sum(isinstance(t, dict) for t in terms)})
        self.assertEqual(value["denylist"], record["denylist"])
        for text in (record["denylist"]["path"], record["denylist"]["sha256"], receipt["export_head"]):
            self.assertIn(text, summary)
        self.assertFalse({"identity", "signature", "scanner_waiver"} & set(record))
        self.assertEqual(sorted(p.name for p in self.run.glob("approval.json*")), ["approval.json"])
        self.assertEqual(value["push"], workflow.push_command(self.run, record))

    def test_approve_names_the_denylist_when_paths_are_redacted(self):
        self.w.export()
        with patch.object(rc.Scanner, "safe_path", lambda scanner, path: "[path-redacted]"):
            result, summary = self.approve()
        value = self.w.assert_status(result, "PASS")
        denylist = workflow.read_json(self.run / "approval.json")["denylist"]
        self.assertEqual(value["denylist"], denylist)
        self.assertIn("; denylist %s sha256 %s, 1 terms, 0 patterns; receipt valid until" % (denylist["path"], denylist["sha256"]), summary)

    def test_approve_keeps_the_denylist_summary_when_paths_are_only_escaped(self):
        self.w.export()
        with patch.object(rc.Scanner, "safe_path", lambda scanner, path: path.replace("terms.json", "terms[tab].json")):
            result, summary = self.approve()
        self.w.assert_status(result, "PASS")
        denylist = workflow.read_json(self.run / "approval.json")["denylist"]
        escaped = denylist["path"].replace("terms.json", "terms[tab].json")
        self.assertIn("; denylist %s sha256 %s, 1 terms, 0 patterns; receipt valid until" % (escaped, denylist["sha256"]), summary)

    def test_push_instructions_stay_runnable_when_paths_are_redacted(self):
        self.w.export()
        with patch.object(rc.Scanner, "safe_path", lambda scanner, path: "[path-redacted]"):
            value = self.w.assert_status(self.approve()[0], "PASS")
            push = workflow.push_command(self.run, workflow.read_json(self.run / "approval.json"))
            self.assertEqual((value["push"], value["next"]), (push, shlex.join(push)))
            refused = self.w.assert_status(self.w.cli("publish", *self.w.target_flags()), "INCOMPLETE", "release-not-pushed")
        self.assertEqual(refused["detail"], "run the guarded push first: " + shlex.join(push))

    def test_owner_no_or_an_unreadable_guards_file_stops_approve(self):
        self.w.export()
        for text in ('{"default": {"public_push": false}}', "{not json", '{"unknown": 1}'):
            with self.subTest(guards=text):
                self.guards.write_text(text)
                self.w.assert_status(self.approve()[0], "INCOMPLETE", "owner-public-push-no")
                self.assertFalse((self.run / "approval.json").exists())
                self.assertFalse((self.run / "release.git").exists())

    def test_a_noncanonical_github_target_is_refused_before_any_lookup(self):
        self.w.export()
        with patch.object(workflow.GITHUB, "gh", side_effect=AssertionError("gh was called")):
            for target in ("https://user:@github.com/example/project.git", "https://GitHub.com/example/project",
                           "https://github.com/example/project/", "https://www.github.com/example/project.git"):
                with self.subTest(target=target):
                    self.w.assert_status(self.approve(target=target)[0], "INCOMPLETE", "target-invalid")
        self.assertFalse((self.run / "approval.json").exists())
        self.assertFalse((self.run / "release.git").exists())

    def test_an_owner_no_while_approve_runs_writes_nothing(self):
        self.w.export()
        staged = workflow.stage_release

        def owner_says_no(*args):
            self.guards.write_text('{"default": {"public_push": false}}')
            return staged(*args)
        with patch.object(workflow, "stage_release", side_effect=owner_says_no):
            self.w.assert_status(self.approve()[0], "INCOMPLETE", "owner-public-push-no")
        self.assertFalse((self.run / "approval.json").exists())

    def test_a_failed_run_approval_write_writes_no_guard_record(self):
        self.w.export()
        (self.run / "approval.json").symlink_to(self.w.root / "missing")
        with patch.object(workflow, "write_guard_record", wraps=workflow.write_guard_record) as guard:
            self.w.assert_status(self.approve()[0], "INCOMPLETE", "approval-exists")
        guard.assert_not_called()

    def test_a_failed_guard_record_write_leaves_no_approval(self):
        self.w.export()
        with patch.object(workflow, "write_guard_record", side_effect=OSError("disk full")):
            try:
                result = self.approve()[0]
                self.assertNotEqual(result[1]["outcome"], "PASS", result)
            except OSError:
                pass
        self.assertFalse((self.run / "approval.json").exists())
        self.w.assert_status(self.approve()[0], "PASS")

    def guard_record(self, attempt):
        target, head = "https://github.com/example/project.git", "a" * 40
        folder = workflow.guard_records_root() / "example__project" / head
        return folder, lambda: workflow.write_guard_record(target, head, {"release_head": head}, attempt)

    def test_a_temp_cleanup_failure_after_linking_still_reports_the_written_record(self):
        folder, write = self.guard_record(self.w.export())
        unlink = os.unlink

        def refuse_temp(path, *args, **kwargs):
            if os.path.basename(path).startswith("."):
                raise PermissionError(path)
            return unlink(path, *args, **kwargs)
        with patch.object(workflow.os, "unlink", side_effect=refuse_temp):
            self.assertEqual(write(), folder)
        self.assertEqual(workflow.read_json(folder / "approval.json"), {"release_head": "a" * 40})
        self.assertTrue((folder / "receipt.json").is_file())

    def test_a_failed_guard_record_write_never_removes_an_existing_record(self):
        folder, write = self.guard_record(self.w.export())
        write()
        before = {p.name: p.read_bytes() for p in folder.iterdir()}
        with patch.object(workflow.tempfile, "mkstemp", side_effect=OSError("no space")), self.assertRaises(OSError):
            write()
        self.assertEqual({p.name: p.read_bytes() for p in folder.iterdir()}, before)

    def test_owner_no_after_approval_stops_publish(self):
        self.w.export()
        self.w.prepare()
        self.w.push()
        self.guards.write_text('{"default": {"public_push": false}}')
        self.w.assert_status(self.w.cli("publish", *self.w.target_flags()), "INCOMPLETE", "owner-public-push-no")
        self.assertFalse((self.run / "published.json").exists())

    def test_a_missing_or_different_reference_denylist_fails_clearly(self):
        self.w.export()
        cases = [(None, "denylist-reference-missing"), ("not a hash\n", "denylist-reference-invalid"),
                 ("a" * 64 + "\n", "denylist-not-reference")]
        for text, reason in cases:
            with self.subTest(reason=reason):
                self.w.reference.unlink(missing_ok=True)
                if text is not None:
                    self.w.reference.write_text(text)
                result, explained = self.approve()
                self.w.assert_status(result, "INCOMPLETE", reason)
                self.assertNotIn("receipt-stale", result[1]["reasons"])
                self.assertIn(str(self.w.reference), explained)
                self.assertFalse((self.run / "approval.json").exists())

    def test_a_receipt_older_than_seven_days_is_refused(self):
        self.w.export()
        class Later(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.now(tz) + timedelta(days=7, minutes=1)
        with patch.object(workflow, "datetime", Later, create=True):
            self.w.assert_status(self.approve()[0], "INCOMPLETE", "receipt-expired")
        self.assertFalse((self.run / "approval.json").exists())

    def test_admin_enforced_required_checks_refuse_with_both_ways_out(self):
        self.w.export()
        target = "https://github.com/synthetic-owner/public-demo"
        calls = []
        def gh(timeout, *argv):
            calls.append(argv)
            if argv[-1].endswith("/protection"):
                body = {"enforce_admins": {"enabled": True}, "required_status_checks": {"contexts": ["verify"]}}
            else:
                body = []
            return subprocess.CompletedProcess(argv, 0, json.dumps(body).encode(), b"")
        with patch.object(workflow.GITHUB, "gh", side_effect=gh):
            result, explained = self.approve(target=target)
        self.w.assert_status(result, "INCOMPLETE", "target-requires-checks")
        self.assertIn("verify", explained)
        self.assertIn("Do not allow bypassing the above settings", explained)
        self.assertIn("remove the required check", explained)
        self.assertEqual(calls[0][-1], "repos/synthetic-owner/public-demo/branches/main/protection")
        self.assertFalse((self.run / "approval.json").exists())

    def test_approve_on_another_host_rechecks_the_copied_run_without_reverifying(self):
        receipt = workflow.read_json(self.w.export() / "receipt.json")
        state = workflow.runs_root().parents[1]
        other = self.w.root / "compute-host-state"
        shutil.copytree(state / "coldrelease", other / "coldrelease", symlinks=True)
        shutil.rmtree(state / "coldrelease")
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(other)}), \
                patch.object(rc, "verify", side_effect=AssertionError("approve re-ran verification")):
            run = workflow.run_directory(self.w.repo, "first")
            self.assertTrue(str(run).startswith(str(other)))
            self.w.assert_status(self.approve()[0], "PASS")
            record = workflow.read_json(run / "approval.json")
        self.assertEqual(record["receipt_sha256"], receipt["receipt_sha256"])
        self.assertEqual(subprocess.run(workflow.push_command(run, record), capture_output=True).returncode, 0)
        self.assertEqual(self.w.remote_head(), record["release_head"])

    def test_the_lease_push_is_a_fast_forward_that_cannot_move_the_ref_elsewhere(self):
        old = self.w.public_history("Earlier public release")
        self.w.export()
        self.w.prepare()
        record = workflow.read_json(self.run / "approval.json")
        release = record["release_head"]
        release_git = self.run / "release.git"
        self.assertEqual(rc.git(release_git, "rev-list", "--parents", "-n", "1", release).decode().split(), [release, old])
        moved = self.w.public_history("Another public release")
        self.assertNotEqual(self.w.push(check=False).returncode, 0)
        self.assertEqual(self.w.remote_head(), moved)
        rc.git(self.w.remote, "update-ref", "refs/heads/main", old)
        self.w.push()
        self.assertEqual(self.w.remote_head(), release)
        self.assertEqual(self.w.remote_git("merge-base", "--is-ancestor", old, release), [])


if __name__ == "__main__":
    unittest.main()
