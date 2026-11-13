from contextlib import redirect_stderr, redirect_stdout
import io
import json
import shlex
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
from tests import test_private_http_target as http


class ConfirmPublicTests(unittest.TestCase):
    def setUp(self):
        self.http = http.PrivateHttpTargetTests()
        self.http.setUp()
        self.addCleanup(self.http.doCleanups)
        self.flow = self.http.flow
        self.bare = self.http.project_root / "private.git"
        self.run_dir = self.flow.run
        self.marker = self.run_dir / "public-verified.json"

    def main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), patch.object(rc, "verify", side_effect=http.flows.verified):
            code = rc.main(argv)
        return code, json.loads(out.getvalue()), err.getvalue()

    def confirm(self, *extra):
        return self.main(["confirm-public", str(self.flow.repo), "--run", "first",
                          "--denylist", str(self.flow.testbed.denylist), *extra])

    def status(self):
        return self.main(["status", str(self.flow.repo), "--run", "first", "--denylist", str(self.flow.testbed.denylist),
                          "--json"])[1]

    def remote_head(self):
        return rc.git(self.bare, "rev-parse", "refs/heads/main").decode().strip()

    def publish_and_flip(self):
        attempt = self.flow.export()
        flags = self.http.flags()
        self.flow.assert_status(self.flow.cli("approve", *flags), "PASS")
        self.http.push()
        self.flow.assert_status(self.flow.cli("publish", *flags), "PASS")
        self.private_authorization = self.http.server.expected_authorization
        self.http.server.expected_authorization = None
        return workflow.read_json(attempt / "receipt.json")

    def move_target(self):
        swap = self.flow.root / "other-writer"
        rc.git(self.flow.root, "clone", "-q", "--branch", "main", str(self.bare), str(swap))
        author = rc.git(swap, "log", "-1", "--format=%an%n%ae").decode().split("\n")
        (swap / "NOTICE.txt").write_text("Replacement content.\n")
        rc.git(swap, "add", "NOTICE.txt")
        rc.git(swap, "-c", "user.name=" + author[0], "-c", "user.email=" + author[1], "commit", "-q", "-m", "Replacement export")
        rc.git(swap, "push", "-q", "origin", "HEAD:refs/heads/main")

    def test_confirm_public_gates_the_public_target_and_records_public_verified(self):
        receipt = self.publish_and_flip()
        head = self.remote_head()
        self.assertEqual(self.status()["state"], "published")
        code, result, err = self.confirm()
        self.assertEqual((code, result["outcome"], result["state"], result["published_head"]),
                         (0, "PASS", "public-verified", head), err)
        report = json.loads((self.run_dir / "public-gate" / result["public_gate"]["report"]).read_text())
        self.assertEqual((report["outcome"], report["published_target"]["head"], report["published_target"]["tree"]),
                         ("PASS", head, receipt["export_tree"]))
        marker = workflow.read_json(self.marker)
        self.assertEqual((marker["published_head"], marker["export_tree"], marker["receipt_sha256"]),
                         (head, receipt["export_tree"], receipt["receipt_sha256"]))
        value = self.status()
        self.assertEqual((value["state"], value["published_head"]), ("public-verified", head), value)
        self.assertEqual(shlex.split(value["next"])[1], "confirm-public")

    def test_target_moved_between_the_gate_and_the_flip_fails_published_receipt_mismatch(self):
        self.publish_and_flip()
        self.assertEqual(self.confirm()[0], 0)
        self.move_target()
        code, result, err = self.confirm()
        self.assertEqual((code, result["outcome"], result["reasons"]), (1, "FAIL", ["published-receipt-mismatch"]), err)
        self.assertNotIn("state", result)
        self.assertFalse(self.marker.exists())
        self.assertEqual(self.status()["state"], "published")

    def test_a_private_target_readable_through_netrc_is_not_public(self):
        self.publish_and_flip()
        self.http.server.expected_authorization = self.private_authorization
        host = self.http.origin.removeprefix("http://").split(":")[0]
        (self.http.home / ".netrc").write_text("machine %s login synthetic password %s\n" % (host, http.SECRET))
        code, result, err = self.confirm()
        self.assertEqual((code, result["reasons"]), (2, ["published-clone-failed"]), err)
        self.assertFalse(self.marker.exists())

    def test_confirm_public_refusals_never_leave_an_earlier_marker(self):
        code, result, _ = self.confirm()
        self.assertEqual((code, result["reasons"]), (2, ["not-published"]))
        self.publish_and_flip()
        for extra, reason in ((["--use-git-credentials"], "git-credentials-selection"),):
            with self.subTest(reason=reason):
                self.assertEqual(self.confirm()[0], 0)
                self.assertTrue(self.marker.exists())
                code, result, _ = self.confirm(*extra)
                self.assertEqual((code, result["outcome"], result["reasons"]), (2, "INCOMPLETE", [reason]), result)
                self.assertFalse(self.marker.exists())
                self.assertEqual(self.status()["state"], "published")

    def test_confirm_public_runs_only_with_the_approved_policy(self):
        self.publish_and_flip()
        weaker = self.flow.root / "weaker-terms.json"
        weaker.write_text(json.dumps({"categories": {"family": {"placeholder": "private", "terms": ["OtherName"]}}}))
        for extra in (["--denylist", str(weaker)], ["--private-repo", "example/other"], ["--timeout", "301"]):
            with self.subTest(extra=extra):
                self.assertEqual(self.confirm()[0], 0)
                code, result, _ = self.confirm(*extra)
                self.assertEqual((code, result["outcome"], result["reasons"]), (2, "INCOMPLETE", ["receipt-stale"]), result)
                self.assertFalse(self.marker.exists())
        manifest = self.run_dir / "attempts" / workflow.read_json(self.run_dir / "export.json")["attempt"] / "manifest.json"
        manifest.write_text(json.dumps({**workflow.read_json(manifest), "exclude": ["docs/"]}))
        code, result, _ = self.confirm()
        self.assertEqual((code, result["outcome"]), (2, "INCOMPLETE"), result)
        self.assertFalse(self.marker.exists())

    def test_the_public_check_reads_only_anonymous_https(self):
        for target in ("git@github.com:example/project.git", "ssh://git@github.com/example/project.git",
                       "https://github.com/example/project"):
            with self.subTest(target=target):
                self.assertEqual(workflow.anonymous_url(target), "https://github.com/example/project.git")
        self.assertEqual(workflow.anonymous_url("https://gitlab.example/group/project.git"),
                         "https://gitlab.example/group/project.git")
        for target in ("git@gitlab.example:group/project.git", "ssh://git@gitlab.example/group/project.git",
                       "https://user@gitlab.example/group/project.git", "file:///srv/git/project.git",
                       "/srv/git/project.git"):
            with self.subTest(target=target), self.assertRaises(rc.AuditError) as refused:
                workflow.anonymous_url(target)
            self.assertEqual(str(refused.exception), "public-url-unknown")

    def test_a_local_path_target_cannot_be_confirmed_public(self):
        self.flow.export()
        self.flow.prepare()
        self.flow.push()
        self.flow.assert_status(self.flow.cli("publish", *self.flow.target_flags()), "PASS")
        code, result, _ = self.confirm()
        self.assertEqual((code, result["reasons"]), (2, ["public-url-unknown"]))
        self.assertFalse(self.marker.exists())

    def test_gate_error_reads_a_failure_printed_on_stdout(self):
        self.assertEqual(workflow.gate_error('report: x\n{"outcome":"INCOMPLETE","error":"reports-unwritable"}'),
                         "reports-unwritable")


if __name__ == "__main__":
    unittest.main()
