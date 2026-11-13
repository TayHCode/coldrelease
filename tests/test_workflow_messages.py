from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import release_check as rc
import test_release_check as fixtures
import test_release_workflow as flows

STUB_PREFIX = "only if this text is meant to be public, such as the copyright holder's name, add "
STUB_SUFFIX = ' to "approvals" in release-check.json and write in "reason" why it is public'


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err), patch.object(rc, "verify", side_effect=flows.verified):
        code = rc.main(argv)
    return code, out.getvalue(), err.getvalue()


class ApprovalExistsTests(unittest.TestCase):
    def setUp(self):
        self.flow = flows.WorkflowTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)

    def test_second_approve_says_approval_exists_and_keeps_the_gate(self):
        flow = self.flow
        flow.export()
        flow.prepare()
        record = (flow.run / "approval.json").read_bytes()
        code, value = flow.cli("approve", *flow.target_flags())
        self.assertEqual((code, value["outcome"], value["reasons"]), (2, "INCOMPLETE", ["approval-exists"]), value)
        self.assertEqual((flow.run / "approval.json").read_bytes(), record)
        flow.assert_status(flow.cli("publish", *flow.target_flags()), "INCOMPLETE", "release-not-pushed")
        self.assertEqual(flow.remote_head(), "")
        flow.push()
        code, value = flow.cli("approve", *flow.target_flags())
        self.assertEqual((code, value["reasons"]), (2, ["approval-exists"]), value)
        self.assertEqual((flow.run / "approval.json").read_bytes(), record)
        flow.assert_status(flow.cli("publish", *flow.target_flags()), "PASS")

class ReportPathTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def cli(self, *extra, home):
        env = {k: v for k, v in os.environ.items() if k not in {"RELEASE_CHECK_REPORTS", "COLDRELEASE_REPORTS"}}
        env["HOME"] = str(home)
        return subprocess.run([sys.executable, rc.__file__, str(self.fx.repo), "--denylist", str(self.fx.denylist), *extra],
                              capture_output=True, text=True, env=env, timeout=120)

    def test_run_without_reports_prints_the_absolute_report_path(self):
        home = self.fx.root / "home"
        home.mkdir()
        result = self.cli(home=home)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        locator = json.loads(result.stdout)["report"]
        self.assertFalse(Path(locator).is_absolute())
        report = home.resolve() / ".local/state/coldrelease" / locator
        self.assertTrue(report.is_file())
        self.assertEqual(result.stderr.splitlines(), ["report: " + str(report)])
        named = self.cli("--reports", str(self.fx.root / "reports"), home=home)
        self.assertEqual((named.returncode, named.stderr), (2, ""))
        private_home = self.fx.root / "HiddenPerson"
        private_home.mkdir()
        private = self.cli(home=private_home)
        self.assertEqual(private.returncode, 2, private.stdout + private.stderr)
        self.assertNotIn("HiddenPerson", private.stdout + private.stderr)
        self.assertRegex(private.stderr, r"\Areport: \[path-[0-9a-f]{16}\]\n\Z")

    def test_report_path_with_a_recognized_secret_is_redacted(self):
        home = self.fx.root / "home"
        home.mkdir()
        token = "ghp_" + 'A1b2C3d4E5f6G7h8I9' 'j0K1l2M3n4O5p6Q7r8'
        env = {k: v for k, v in os.environ.items() if k not in {"RELEASE_CHECK_REPORTS", "COLDRELEASE_REPORTS"}}
        env.update(HOME=str(home), COLDRELEASE_REPORTS=str(self.fx.root / token))
        result = subprocess.run([sys.executable, rc.__file__, str(self.fx.repo), "--denylist", str(self.fx.denylist)],
                                capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertRegex(result.stderr, r"\Areport: \[path-[0-9a-f]{16}\]\n\Z")


class DenylistApprovalHintTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        (self.fx.repo / "notes.txt").write_text("HiddenPerson\n")
        self.fx.commit("Add synthetic finding")
        self.reports = self.fx.root / "reports"

    def audit(self):
        code, out, err = run_cli([str(self.fx.repo), "--denylist", str(self.fx.denylist), "--reports", str(self.reports), "--verify"])
        summary = json.loads(out.splitlines()[0])
        return code, json.loads((self.reports / summary["report"]).read_text()), err

    def stubs(self, err):
        lines = [line for line in err.splitlines() if line.startswith("personal: denylist in ")]
        for line in lines:
            self.assertIn("remove or replace the private data, including affected history (see README); " + STUB_PREFIX, line)
            self.assertTrue(line.endswith(STUB_SUFFIX), line)
        return [json.loads(line.split(STUB_PREFIX, 1)[1].removesuffix(STUB_SUFFIX)) for line in lines]

    def tree_finding(self, report):
        return next(f for f in report["findings"] if f["kind"] == "denylist" and f["scope"] == "tree")

    def test_denylist_findings_print_the_exact_approvals_stub(self):
        code, report, err = self.audit()
        self.assertEqual(code, 1)
        self.assertNotIn("HiddenPerson", err)
        self.assertEqual(len(err.splitlines()), 2)
        findings = [f for f in report["findings"] if f["kind"] == "denylist"]
        stubs = self.stubs(err)
        self.assertEqual(stubs, [{"scope": f["scope"], "kind": "denylist", "path": f["path"],
                                  "fingerprint": f["fingerprint"], "reason": ""} for f in findings])
        tree = next(stub for stub in stubs if stub["scope"] == "tree")
        manifest = {**self.fx.manifest, "approvals": [tree]}
        (self.fx.repo / "release-check.json").write_text(json.dumps(manifest))
        self.fx.commit("Paste the stub unchanged")
        code, report, err = self.audit()
        self.assertEqual(code, 1)
        self.assertFalse(self.tree_finding(report)["reviewed"])
        manifest["approvals"] = [{**tree, "reason": "Verified public attribution."}]
        (self.fx.repo / "release-check.json").write_text(json.dumps(manifest))
        self.fx.commit("Record the review")
        code, report, err = self.audit()
        self.assertEqual(code, 1)
        self.assertTrue(self.tree_finding(report)["reviewed"])

    def test_secret_findings_never_print_an_approvals_stub(self):
        (self.fx.repo / "notes.txt").write_text("ordinary\n")
        (self.fx.repo / "key.txt").write_text("AKIA" + "ABCDEFGHIJKLMNOP\n")
        self.fx.commit("Add synthetic secret")
        code, report, err = self.audit()
        self.assertEqual(code, 1)
        secrets = [line for line in err.splitlines() if line.startswith("secrets: ")]
        self.assertTrue(secrets, err)
        for line in secrets:
            self.assertNotIn("approvals", line)
        self.assertEqual(len(self.stubs(err)), 1)


class PublishedCloneEmptyTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)

    def test_final_gate_on_a_clone_without_checkout_says_published_clone_empty(self):
        target = self.fx.root / "published.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "other", str(target)], check=True, capture_output=True)
        self.fx.git("push", "-q", str(target), "HEAD:refs/heads/main")
        clone = self.fx.root / "clone"
        subprocess.run(["git", "clone", "-q", str(target), str(clone)], check=True, capture_output=True)
        self.assertEqual(list(clone.iterdir()), [clone / ".git"])
        reports = self.fx.root / "reports"
        with patch.object(rc, "audit") as audit:
            code, out, err = run_cli([str(clone), "--denylist", str(self.fx.denylist), "--reports", str(reports), "--verify",
                                      "--published-target", str(target), "refs/heads/main"])
        audit.assert_not_called()
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(json.loads(err), {"outcome": "INCOMPLETE", "ready": False, "error": "published-clone-empty",
                                           "detail": "the clone has no checked-out commit; clone the published branch with "
                                                     "git clone --branch <branch>"})
        self.assertFalse(reports.exists())


if __name__ == "__main__":
    unittest.main()
