import json
import os
import subprocess
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
from tests import test_release_workflow as flows

NAME = "example/fresh"


class CreateRefusedTests(unittest.TestCase):
    def setUp(self):
        self.flow = flows.WorkflowTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)

    def test_create_is_refused_on_every_command_and_calls_nothing(self):
        self.flow.export()
        with patch.object(workflow.GITHUB, "gh", side_effect=AssertionError("gh was called")):
            for command, extra in (("approve", ["--verify"]), ("ship", ["--verify"]), ("publish", ["--verify"]), ("check", [])):
                with self.subTest(command=command):
                    self.flow.assert_status(self.flow.cli(command, *extra, "--create", NAME), "INCOMPLETE", "create-not-supported")
        self.assertFalse((self.flow.run / "approval.json").exists())
        self.assertEqual(self.flow.remote_head(), "")


class GhAdapterTests(unittest.TestCase):
    def setUp(self):
        self.flow = flows.WorkflowTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        self.bin = self.flow.root / "bin"
        self.bin.mkdir()
        self.log = self.flow.root / "gh.log"
        path = patch.dict(os.environ, {"PATH": str(self.bin) + os.pathsep + os.environ["PATH"], "GH_HOST": "ghe.example"})
        path.start()
        self.addCleanup(path.stop)

    def fake(self, protection, rules, protection_code=0, rules_code=0):
        gh = self.bin / "gh"
        gh.write_text("#!/bin/sh\nprintf '%%s %%s\\n' \"$GH_HOST\" \"$*\" >> %s\n"
                      "case \"$*\" in\n"
                      "  *protection) printf '%%s' '%s'; [ %d = 0 ] || printf 'gh: Branch not protected (HTTP 404)' >&2; exit %d;;\n"
                      "  *) printf '%%s' '%s'; exit %d;;\n"
                      "esac\n" % (self.log, json.dumps(protection), protection_code, protection_code, json.dumps(rules), rules_code))
        gh.chmod(0o700)

    def calls(self):
        return self.log.read_text().splitlines()

    def test_required_checks_count_only_when_they_bind_admins(self):
        rules = [{"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "ruleset-check"}]}},
                 {"type": "deletion"}]
        for enforced, expected in ((True, ["ruleset-check", "verify"]), (False, ["ruleset-check"])):
            with self.subTest(enforced=enforced):
                self.fake({"enforce_admins": {"enabled": enforced}, "required_status_checks": {"contexts": ["verify"]}}, rules)
                self.assertEqual(workflow.GitHub().admin_required_checks(NAME, "release/v1", 5), expected)
        self.assertEqual(self.calls()[:2], [
            "github.com api --hostname github.com --method GET repos/example/fresh/branches/release%2Fv1/protection",
            "github.com api --hostname github.com --method GET repos/example/fresh/rules/branches/release%2Fv1"])

    def test_an_unprotected_branch_has_no_required_checks_and_other_failures_refuse(self):
        self.fake({}, [], protection_code=1)
        self.assertEqual(workflow.GitHub().admin_required_checks(NAME, "main", 5), [])
        self.fake({}, [], rules_code=1)
        with self.assertRaises(rc.AuditError) as refused:
            workflow.GitHub().admin_required_checks(NAME, "main", 5)
        self.assertEqual(str(refused.exception), "github-unreadable")

    def test_visibility_reads_the_repository_and_refuses_anything_but_public_or_private(self):
        for output, expected in (("private", "PRIVATE"), ("public", "PUBLIC")):
            with self.subTest(output=output), patch.object(workflow.GITHUB, "gh",
                    return_value=subprocess.CompletedProcess([], 0, output.encode() + b"\n", b"")) as gh:
                self.assertEqual(workflow.GITHUB.visibility(NAME, 5), expected)
                self.assertEqual(gh.call_args[0][1:], ("api", "--hostname", "github.com", "--method", "GET",
                                                       "repos/example/fresh", "--jq", ".visibility"))
        for code, output, reason in ((0, "internal", "target-visibility"), (1, "", "github-unreadable")):
            with self.subTest(output=output), patch.object(workflow.GITHUB, "gh",
                    return_value=subprocess.CompletedProcess([], code, output.encode(), b"")), \
                    self.assertRaises(rc.AuditError) as refused:
                workflow.GITHUB.visibility(NAME, 5)
            self.assertEqual(str(refused.exception), reason)


if __name__ == "__main__":
    unittest.main()
