import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

import release_check as rc
import release_workflow as workflow
import test_release_check as fixtures

FAKE = Path(__file__).resolve().parent / "fixtures" / "exec_fake.py"
IN_FAKE_VM = ("import os, sys; sys.exit(0 if '/vms/cbx-' in os.getcwd() and 'LEAKED_BY_THE_CALLER' not in os.environ "
              "and 'PYTHONPATH' not in os.environ and os.environ['HOME'].endswith('/home') and os.environ.get('GIT_CONFIG_NOSYSTEM') == '1' "
              "and os.environ.get('GIT_CONFIG_GLOBAL') == os.devnull and os.environ.get('GIT_TERMINAL_PROMPT') == '0' else 3)")


class VerifyBackendTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        self.repo = self.testbed.repo
        state = tempfile.TemporaryDirectory()
        self.addCleanup(state.cleanup)
        self.state = Path(state.name)
        self.env = {**os.environ, "COLD_EXEC_FAKE_STATE": str(self.state),
                    "COLDRELEASE_COLDBOX": shlex.join([sys.executable, str(FAKE)])}

    def workflow(self, command, run, *extra, env=None):
        process = subprocess.run([sys.executable, rc.__file__, command, str(self.repo), "--denylist", str(self.testbed.denylist),
                                  "--run", run, *extra], capture_output=True, text=True, env=env or self.env)
        return process.returncode, json.loads(process.stdout), process.stderr

    def export(self, run, *extra, env=None):
        code, result, _ = self.workflow("plan", run, env=env)
        self.assertEqual((code, result["outcome"]), (0, "PASS"), result)
        code, result, err = self.workflow("export", run, "--verify", *extra, env=env)
        attempt = workflow.run_directory(self.repo, run) / "attempts" / result["attempt"]
        return code, result, err, workflow.read_json(attempt / "report.json"), workflow.read_json(attempt / "receipt.json")

    def require_fake_vm(self):
        manifest = {**self.testbed.manifest, "checks": [*self.testbed.manifest["checks"],
                                                        {"role": "tests", "argv": ["python", "-c", IN_FAKE_VM]}]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        self.testbed.commit("Require the fake VM")

    def test_coldbox_backend_runs_the_checks_in_a_vm_and_records_image_and_log_digest(self):
        self.require_fake_vm()
        env = {**self.env, "LEAKED_BY_THE_CALLER": "1", "PYTHONPATH": str(self.state)}
        code, result, err, report, receipt = self.export("box", "--verify-backend", "coldbox", env=env)
        self.assertEqual((code, result["outcome"]), (0, "PASS"), (report["reasons"], report["findings"], err))
        self.assertEqual([c["exit_code"] for c in report["verification"]["commands"]], [0, 0, 0])
        environment = receipt["verification_environment"]
        self.assertEqual(environment, report["verification"]["environment"])
        self.assertEqual((environment["backend"], environment["interface"]), ("coldbox", "cold.exec/v0"))
        self.assertTrue(environment["image"])
        self.assertRegex(environment["log_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(list((self.state / "vms").iterdir()), [])
        attempt = workflow.run_directory(self.repo, "box") / "attempts" / result["attempt"]
        validated = rc.validate_receipt(attempt / "receipt.json", attempt / "export", self.receipt_args(attempt / "manifest.json"))
        self.assertEqual(validated["outcome"], "PASS", validated)

    def test_host_backend_is_unchanged_and_fails_the_vm_only_check(self):
        self.require_fake_vm()
        code, result, _, report, receipt = self.export("host")
        self.assertEqual((code, result["outcome"]), (1, "FAIL"), result)
        self.assertIn("command-failed", report["reasons"])
        self.assertNotIn("environment", report["verification"])
        self.assertNotIn("verification_environment", receipt)

    def test_unreachable_coldbox_is_incomplete_and_runs_nothing_on_the_host(self):
        env = {**self.env, "COLDRELEASE_COLDBOX": str(self.state / "missing-coldbox")}
        code, result, err, report, receipt = self.export("down", "--verify-backend", "coldbox", env=env)
        self.assertEqual((code, result["outcome"]), (2, "INCOMPLETE"), result)
        self.assertIn("verify-backend-unavailable", report["reasons"])
        self.assertEqual(report["verification"]["commands"], [])
        self.assertEqual(receipt["verification_environment"], {"backend": "coldbox", "unavailable": "coldbox-not-found"})
        self.assertIn("--allow-host-fallback", err)

    def backend_script(self, name, body):
        script = self.state / name
        script.write_text("#!/bin/sh\n" + body)
        script.chmod(0o755)
        return {**self.env, "COLDRELEASE_COLDBOX": str(script)}

    def test_busy_coldbox_falls_back_to_the_host_only_with_the_flag(self):
        env = self.backend_script("busy-coldbox", "[ \"$1\" = version ] && echo '{\"interface\": \"cold.exec/v0\"}' && exit 0\nexit 75\n")
        code, result, _, report, _ = self.export("busy", "--verify-backend", "coldbox", env=env)
        self.assertEqual((code, result["outcome"]), (2, "INCOMPLETE"), result)
        self.assertEqual(report["verification"]["commands"], [])
        self.assertEqual(report["verification"]["environment"]["unavailable"], "coldbox-busy")

        code, result, err, report, receipt = self.export("fallback", "--verify-backend", "coldbox", "--allow-host-fallback", env=env)
        self.assertEqual((code, result["outcome"]), (0, "PASS"), (result, err))
        self.assertEqual([c["exit_code"] for c in report["verification"]["commands"]], [0, 0])
        self.assertEqual(receipt["verification_environment"],
                         {"backend": "host", "requested": "coldbox", "fallback": "coldbox-busy"})
        self.assertIn("running it on this host because --allow-host-fallback was given", err)

    def test_wrong_interface_is_refused(self):
        env = self.backend_script("old-coldbox", "echo '{\"interface\": \"cold.exec/v9\"}'\n")
        code, result, _, report, _ = self.export("old", "--verify-backend", "coldbox", env=env)
        self.assertEqual((code, result["outcome"]), (2, "INCOMPLETE"), result)
        self.assertEqual(report["verification"]["environment"]["unavailable"], "coldbox-interface")

    def test_backend_flags_are_rejected_where_they_do_not_apply(self):
        code, result, _ = self.workflow("plan", "flags", "--verify-backend", "coldbox")
        self.assertEqual((code, result["reasons"]), (2, ["verify-backend-selection"]))
        code, result, _ = self.workflow("plan", "flags", "--allow-host-fallback")
        self.assertEqual((code, result["reasons"]), (2, ["host-fallback-selection"]))
        for extra in (["--verify-backend", "coldbox"], ["--verify", "--allow-host-fallback"]):
            process = subprocess.run([sys.executable, rc.__file__, str(self.repo), "--denylist", str(self.testbed.denylist), *extra],
                                     capture_output=True, text=True, env=self.env)
            self.assertEqual((process.returncode, json.loads(process.stderr.splitlines()[0])["error"]), (2, "invalid-arguments"))

    def receipt_args(self, manifest=None):
        return argparse.Namespace(denylist=self.testbed.denylist, private_repo=[], verify=True, timeout=300, manifest=manifest)

    def test_receipt_validation_rejects_a_malformed_environment(self):
        directory = self.state / "receipt"
        directory.mkdir()
        good = {"backend": "coldbox", "interface": "cold.exec/v0", "image": "Ubuntu 26.04 LTS", "log_sha256": "d" * 64}
        cases = {
            "complete": (good, True),
            "unavailable": ({"backend": "coldbox", "unavailable": "coldbox-busy"}, True),
            "fallback": ({"backend": "host", "requested": "coldbox", "fallback": "coldbox-not-found"}, True),
            "backend only": ({"backend": "coldbox"}, False),
            "other backend": ({**good, "backend": "elsewhere"}, False),
            "other interface": ({**good, "interface": "cold.exec/v9"}, False),
            "empty image": ({**good, "image": ""}, False),
            "short digest": ({**good, "log_sha256": "d" * 63}, False),
            "extra field": ({**good, "note": "x"}, False),
            "fallback without reason": ({"backend": "host", "requested": "coldbox", "fallback": ""}, False),
            "not an object": (["coldbox"], False),
        }
        for label, (environment, valid) in cases.items():
            body = {"schema_version": 1, "outcome": "PASS", "reasons": [], "created_at": "x", "export_head": "a" * 40,
                    "export_tree": "b" * 40, "bindings": {k: "c" * 64 for k in ("inventory", "recipe", "policy", "scanners")},
                    "verification_environment": environment}
            body["receipt_sha256"] = rc.sha256(rc.canonical_json(body))
            (directory / "receipt.json").write_bytes(rc.canonical_json(body))
            reasons = rc.validate_receipt(directory / "receipt.json", directory, self.receipt_args())["reasons"]
            self.assertEqual(reasons != ["receipt-invalid"], valid, label)

    def test_log_digest_covers_output_beyond_the_report_limit(self):
        digest = rc.hashlib.sha256()
        code, output = rc.command([sys.executable, "-c", "import sys; sys.stdout.write('x' * (9 * 1024 * 1024))"],
                                  self.state, dict(os.environ), 60, digest=digest)
        self.assertEqual((code, len(output)), (0, 8 * 1024 * 1024))
        self.assertEqual(digest.hexdigest(), rc.sha256(b"x" * (9 * 1024 * 1024)))

if __name__ == "__main__":
    unittest.main()
