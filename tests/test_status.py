from contextlib import redirect_stderr, redirect_stdout
import io
import json
import shlex
import subprocess
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
from tests import test_release_workflow as flows

EFFECTS = {"publish", "ship", "push", "gh", "--visibility"}


def failed_verification(*args, **kwargs):
    return {"status": "fail", "commands": [], "dependencies": {"blocked": 0}}


class StatusTests(unittest.TestCase):
    def setUp(self):
        self.flow = flows.WorkflowTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        self.run_dir = self.flow.run

    def status(self, *extra, as_json=True, run="first"):
        argv = ["status", str(self.flow.repo), "--run", run, "--denylist", str(self.flow.testbed.denylist),
                *extra, *(["--json"] if as_json else [])]
        out = io.StringIO()
        try:
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = rc.main(argv)
        except SystemExit as exit:
            self.fail("status is not a command (exit %s)" % exit.code)
        return code, json.loads(out.getvalue()) if as_json else out.getvalue()

    def state(self, *extra):
        code, value = self.status(*extra)
        self.assertEqual((code, value["outcome"]), (0, "PASS"), value)
        return value

    def run_printed(self, line):
        argv = shlex.split(line)
        self.assertEqual(argv[0], "coldrelease", line)
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()), patch.object(rc, "verify", side_effect=flows.verified):
            code = rc.main(argv[1:])
        return code, json.loads(out.getvalue().splitlines()[0])

    def snapshot(self):
        root = workflow.state_root(self.flow.repo)
        return {str(p): (p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None) for p in root.rglob("*")} if root.exists() else None

    def assert_read_only(self, *extra):
        before = self.snapshot()
        value = self.state(*extra)
        self.assertEqual(self.snapshot(), before)
        return value

    def publish(self):
        self.flow.prepare()
        self.flow.push()
        self.flow.assert_status(self.flow.cli("publish", *self.flow.target_flags()), "PASS")

    def test_status_names_each_state_and_its_exact_next_command(self):
        self.enterContext(self.flow.fake_gitleaks())
        repo = str(self.flow.repo)
        denylist = str(self.flow.testbed.denylist)
        new = self.assert_read_only()
        self.assertEqual((new["state"], new["next"]), ("new", shlex.join(
            ["coldrelease", "preflight", repo, "--run", "first", "--denylist", denylist])))
        self.assertFalse(self.run_dir.exists())
        for state, command, extra in (("new", "preflight", ""), ("preflighted", "plan", " --scanner gitleaks"),
                                      ("planned", "export", "")):
            value = self.assert_read_only()
            self.assertEqual(value["state"], state, value)
            self.assertEqual(shlex.split(value["next"])[1], command, value)
            self.assertEqual(self.run_printed(value["next"] + extra)[1]["outcome"], "PASS", value)
        exported = self.assert_read_only("--target", str(self.flow.remote))
        self.assertEqual(exported["state"], "exported", exported)
        self.assertEqual(exported["next"], shlex.join(
            ["coldrelease", "approve", repo, "--run", "first", "--denylist", denylist, "--verify",
             "--target", str(self.flow.remote), "--ref", "refs/heads/main"]))
        self.assertEqual(self.run_printed(exported["next"])[1]["outcome"], "PASS")

        record = workflow.read_json(self.run_dir / "approval.json")
        approved = self.assert_read_only()
        push = shlex.join(workflow.push_command(self.run_dir, record))
        self.assertEqual((approved["state"], approved["next"], approved["then"]), ("approved", push, shlex.join(
            ["coldrelease", "publish", repo, "--run", "first", "--denylist", denylist, "--verify",
             "--target", str(self.flow.remote), "--ref", "refs/heads/main"])))
        code, text = self.status(as_json=False)
        self.assertEqual((code, text.splitlines()), (0, ["approved", "next: " + push, "then: " + approved["then"]]))
        self.assertEqual(self.flow.remote_head(), "")
        subprocess.run(shlex.split(approved["next"]), check=True, capture_output=True)
        self.assertEqual(self.run_printed(approved["then"])[1]["outcome"], "PASS")
        head = workflow.read_json(self.run_dir / "published.json")["export_head"]
        self.assertEqual(self.flow.remote_head(), head)

        code, text = self.status(as_json=False)
        lines = text.splitlines()
        self.assertEqual((code, lines[0]), (0, "published " + head))
        published = self.state()
        self.assertEqual((published["state"], published["published_head"]), ("published", head))
        self.assertEqual(lines[1], "next: " + published["next"])
        clone = self.flow.root / "published-clone"
        fetch, gate = published["next"].replace("PUBLISHED_CLONE", str(clone)).split(" && ")
        subprocess.run(shlex.split(fetch), check=True, capture_output=True)
        code, report = self.run_printed(gate)
        self.assertEqual((code, report["outcome"]), (0, "PASS"), report)
        self.assertIn("--published-target", shlex.split(gate))

    def test_exported_without_a_secret_scanner_points_to_a_scanned_run_that_approves(self):
        self.flow.export(("osv-scanner",))
        exported = self.assert_read_only("--target", str(self.flow.remote))
        self.assertEqual((exported["state"], exported["reasons"]), ("exported", ["scanners-required"]), exported)
        self.assertEqual(shlex.split(exported["next"])[-6:],
                         ["--scanner", "gitleaks", "--scanner", "osv-scanner", "--scanner", "trufflehog"])
        self.flow.assert_status(self.flow.cli("approve", *self.flow.target_flags()), "INCOMPLETE", "scanners-required")
        self.assertFalse((self.run_dir / "approval.json").exists())
        scanned = (patch.object(workflow, "scan_export", side_effect=self.flow.passing_scan),
                   patch.object(workflow.shutil, "which", return_value=None))
        with scanned[0], scanned[1]:
            self.assertEqual(self.run_printed(exported["next"].replace("NEW_RUN", "second"))[1]["outcome"], "PASS")
            with patch.object(rc, "verify", side_effect=flows.verified):
                self.flow.assert_status(self.flow.cli("export", "--verify", run="second"), "PASS")
        code, second = self.status("--target", str(self.flow.remote), run="second")
        self.assertEqual((code, second["state"], second.get("reasons")), (0, "exported", None), second)
        self.assertEqual(shlex.split(second["next"])[1], "approve")
        self.assertEqual(self.run_printed(second["next"])[1]["outcome"], "PASS")

        record = workflow.run_directory(self.flow.repo, "second") / "approval.json"
        edited = workflow.read_json(record)
        record.write_text(json.dumps({**edited, "scanners": [r for r in edited["scanners"] if r["name"] == "osv-scanner"]}))
        code, stale = self.status(run="second")
        self.assertEqual((code, stale["state"], stale["reasons"]), (0, "approval-stale", ["scanners-required"]), stale)
        self.assertFalse(EFFECTS & set(shlex.split(stale["next"])), stale)

    def test_only_a_current_approval_prints_the_push(self):
        seen = []

        def check(*extra):
            value = self.state(*extra)
            seen.append(value["state"])
            if value["state"] != "approved":
                self.assertFalse(EFFECTS & set(shlex.split(value["next"])), value)
            return value

        check()
        self.flow.assert_status(self.flow.cli("plan", "--scanner", "gitleaks"), "PASS")
        check()
        with patch.object(workflow, "scan_export", side_effect=self.flow.passing_scan), \
                patch.object(workflow.shutil, "which", return_value=None):
            with patch.object(rc, "verify", side_effect=failed_verification):
                self.flow.cli("export", "--verify")
            self.assertEqual(check()["state"], "export-not-pass")
            with patch.object(rc, "verify", side_effect=flows.verified):
                self.flow.assert_status(self.flow.cli("export", "--verify"), "PASS")
            check("--target", str(self.flow.remote))
            self.flow.prepare()
            approved = check()
            self.assertEqual(shlex.split(approved["next"])[3:5], ["push", "--force-with-lease=refs/heads/main:"])
            self.assertNotIn("--force", shlex.split(approved["next"]))
            with patch.object(rc, "verify", side_effect=flows.verified):
                self.flow.assert_status(self.flow.cli("export", "--verify"), "PASS")
            check()
        self.assertEqual(seen, ["new", "planned", "export-not-pass", "exported", "approved", "approval-stale"])
        self.assertEqual(self.flow.remote_head(), "")

    def test_published_state_survives_a_later_export_of_the_same_run(self):
        published_attempt = self.flow.export()
        self.publish()
        head = workflow.read_json(self.run_dir / "published.json")["export_head"]
        with patch.object(rc, "verify", side_effect=failed_verification):
            self.flow.cli("export", "--verify")
        self.assertNotEqual(workflow.export_attempt(self.run_dir), published_attempt)
        value = self.state()
        self.assertEqual((value["state"], value.get("published_head")), ("published", head), value)
        gate = shlex.split(value["next"].split(" && ")[1])
        self.assertEqual(gate[gate.index("--manifest") + 1], str(published_attempt / "manifest.json"))
        receipt = workflow.read_json(published_attempt / "receipt.json")
        self.assertIn("--expected-export", gate, gate)
        self.assertEqual(gate[gate.index("--expected-export") + 1:][:2], [receipt["export_head"], receipt["export_tree"]])

    def test_published_state_gates_the_appended_release_commit(self):
        old = self.flow.public_history("Earlier public release")
        attempt = self.flow.export()
        self.publish()
        head = self.flow.remote_head()
        receipt = workflow.read_json(attempt / "receipt.json")
        value = self.state()
        self.assertEqual(value.get("published_head"), head, value)
        self.assertEqual(self.flow.remote_git("rev-list", "--parents", "-n", "1", head), [head, old])
        clone = self.flow.root / "published-clone"
        fetch, gate = value["next"].replace("PUBLISHED_CLONE", str(clone)).split(" && ")
        argv = shlex.split(gate)
        self.assertEqual(argv[argv.index("--expected-export") + 1:][:2], [head, receipt["export_tree"]])
        subprocess.run(shlex.split(fetch), check=True, capture_output=True)
        code, report = self.run_printed(gate)
        self.assertEqual((code, report["outcome"]), (0, "PASS"), report)
        path = self.run_dir / "published.json"
        for field, forged in (("published_head", "0" * 40), ("parent", None)):
            with self.subTest(field=field):
                original = path.read_bytes()
                path.write_text(json.dumps({**json.loads(original), field: forged}))
                code, value = self.status()
                self.assertEqual((code, value["outcome"], value.get("reasons")), (2, "INCOMPLETE", ["receipt-invalid"]), value)
                path.write_bytes(original)
        original = path.read_bytes()
        path.write_text(json.dumps({key: value for key, value in json.loads(original).items()
                                    if key not in {"published_head", "parent"}}))
        self.assertEqual(self.state().get("published_head"), head)
        path.write_bytes(original)

    def test_published_final_gate_refuses_a_target_swapped_after_publish(self):
        attempt = self.flow.export()
        self.publish()
        receipt = workflow.read_json(attempt / "receipt.json")
        swap = self.flow.root / "other-writer"
        rc.git(self.flow.root, "clone", "-q", "--branch", "main", str(self.flow.remote), str(swap))
        author = rc.git(swap, "log", "-1", "--format=%an%n%ae").decode().split("\n")
        (swap / "NOTICE.txt").write_text("Replacement content.\n")
        rc.git(swap, "add", "NOTICE.txt")
        rc.git(swap, "-c", "user.name=" + author[0], "-c", "user.email=" + author[1], "commit", "-q", "-m", "Replacement export")
        rc.git(swap, "push", "-q", "origin", "HEAD:refs/heads/main")
        self.assertNotEqual(self.flow.remote_head(), receipt["export_head"])

        clone = self.flow.root / "published-clone"
        fetch, gate = self.state()["next"].replace("PUBLISHED_CLONE", str(clone)).split(" && ")
        subprocess.run(shlex.split(fetch), check=True, capture_output=True)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err), patch.object(rc, "verify", side_effect=flows.verified):
            code = rc.main(shlex.split(gate)[1:])
        self.assertEqual((code, out.getvalue()), (1, ""), err.getvalue())
        self.assertEqual(json.loads(err.getvalue())["error"], "published-receipt-mismatch")

    def test_published_state_refuses_a_receipt_edited_without_its_digest(self):
        attempt = self.flow.export()
        self.publish()
        path = attempt / "receipt.json"
        original = path.read_bytes()
        for field in ("export_head", "export_tree"):
            with self.subTest(field=field):
                receipt = json.loads(original)
                receipt[field] = "0" * 40
                path.write_text(json.dumps(receipt))
                code, value = self.status()
                self.assertEqual((code, value["outcome"], value.get("reasons")), (2, "INCOMPLETE", ["receipt-invalid"]), value)
                self.assertNotIn("next", value)
                path.write_bytes(original)
        self.assertEqual(self.state()["state"], "published")

    def test_published_state_refuses_a_rehashed_receipt_whose_tree_is_not_the_export(self):
        attempt = self.flow.export()
        self.publish()
        files = {name: path.read_bytes() for name, path in (
            ("receipt", attempt / "receipt.json"), ("approval", self.run_dir / "approval.json"),
            ("published", self.run_dir / "published.json"))}
        receipt = json.loads(files["receipt"])
        receipt["export_tree"] = "0" * 40
        receipt["receipt_sha256"] = rc.sha256(rc.canonical_json({k: v for k, v in receipt.items() if k != "receipt_sha256"}))
        (attempt / "receipt.json").write_text(json.dumps(receipt))
        for name in ("approval", "published"):
            record = json.loads(files[name])
            record["receipt_sha256"] = receipt["receipt_sha256"]
            (self.run_dir / (name + ".json")).write_text(json.dumps(record))
        code, value = self.status()
        self.assertEqual((code, value["outcome"], value.get("reasons")), (2, "INCOMPLETE", ["export-ancestry"]), value)
        self.assertNotIn("next", value)
        (attempt / "receipt.json").write_bytes(files["receipt"])
        (self.run_dir / "approval.json").write_bytes(files["approval"])
        (self.run_dir / "published.json").write_bytes(files["published"])

        receipt_path = attempt / "receipt.json"
        receipt_path.unlink()
        code, value = self.status()
        self.assertEqual((code, value["outcome"], value.get("reasons")), (2, "INCOMPLETE", ["workflow-incomplete"]), value)
        self.assertNotIn("next", value)
        receipt_path.write_bytes(files["receipt"])
        self.assertEqual(self.state()["state"], "published")

    def test_status_needs_a_run_and_only_status_takes_json(self):
        code, value = self.status("--run", "")
        self.assertEqual((code, value["reasons"]), (2, ["run-required"]), value)
        code, value = self.flow.cli("plan", "--json")
        self.assertEqual((code, value["reasons"]), (2, ["json-selection"]), value)
        self.assertFalse(self.run_dir.exists())


if __name__ == "__main__":
    unittest.main()
