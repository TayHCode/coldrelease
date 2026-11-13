from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
import test_release_check as fixtures


def verified(*args, **kwargs):
    return {"status": "pass", "commands": [], "dependencies": {"blocked": 0}}


class RemoteSourceTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        self.root = self.testbed.root
        self.remote = self.root / "origin.git"
        self.testbed.git("branch", "side")
        self.testbed.git("tag", "v1")
        subprocess.run(["git", "clone", "-q", "--bare", str(self.testbed.repo), str(self.remote)], check=True, capture_output=True)
        self.pushed = self.root / "push-attempted"
        for hook in ("pre-receive", "update", "post-update"):
            path = self.remote / "hooks" / hook
            path.write_text("#!/bin/sh\ntouch '%s'\nexit 1\n" % self.pushed)
            path.chmod(0o755)
        self.url = "file://" + str(self.remote)
        home = self.root / "owner-home"
        (home / ".coldlocker").mkdir(parents=True)
        (home / ".coldlocker/release-denylist.sha256").write_text(rc.sha256(self.testbed.denylist.read_bytes()) + "\n")
        self.enterContext(patch.dict("os.environ", {"HOME": str(home)}))

    def remote_refs(self):
        rows = subprocess.run(["git", "--git-dir", str(self.remote), "for-each-ref", "--format=%(refname) %(objectname)"],
                              check=True, capture_output=True, text=True).stdout.splitlines()
        return dict(row.split(" ", 1) for row in rows)

    def cli(self, command, *extra, source=None):
        output = io.StringIO()
        with redirect_stdout(output):
            code = rc.main([command, source or self.url, "--denylist", str(self.testbed.denylist), *extra])
        return code, json.loads(output.getvalue())

    def test_preflight_clones_a_mirror_records_refs_and_continues_without_writing_the_remote(self):
        before = self.remote_refs()
        self.assertEqual(set(before), {"refs/heads/main", "refs/heads/side", "refs/tags/v1"})
        code, result = self.cli("preflight", "--run", "first")
        self.assertEqual((code, result["outcome"]), (0, "PASS"), result)
        self.assertEqual(result["run"], "first")
        checkout = workflow.source_repository(self.url, "first")
        run = workflow.run_directory(checkout, "first")
        self.assertEqual(run, checkout.parent)
        record = workflow.read_json(run / "source.json")
        self.assertEqual(record, {"schema_version": 1, "url": self.url, "refs": before})
        self.assertEqual(rc.git(run / "mirror.git", "rev-parse", "--is-bare-repository").strip(), b"true")
        self.assertEqual(rc.git(checkout, "rev-parse", "HEAD").decode().strip(), before["refs/heads/main"])
        self.assertEqual(rc.git(checkout, "rev-parse", "--is-shallow-repository").strip(), b"false")
        self.assertFalse(run.is_relative_to(self.testbed.repo))
        self.assertEqual(self.cli("plan", "--run", "first")[1]["outcome"], "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            code, result = self.cli("export", "--run", "first", "--verify")
        self.assertEqual((code, result["outcome"]), (0, "PASS"), result)
        for source, target in ((None, self.url), (None, str(self.remote)), (None, self.url + "/"), (None, "origin"),
                               (None, str(run / "mirror.git")), (str(checkout), self.url), (str(checkout), str(self.remote))):
            with self.subTest(source=source, target=target):
                code, result = self.cli("approve", "--run", "first", "--verify", "--target", target, source=source)
                self.assertEqual((code, result["reasons"]), (2, ["target-is-source"]), result)
        self.assertFalse((run / "approval.json").exists())
        output = io.StringIO()
        with redirect_stdout(output):
            rc.main(["status", self.url, "--run", "first", "--denylist", str(self.testbed.denylist), "--json"])
        status = json.loads(output.getvalue())
        self.assertEqual(status["reasons"], ["scanners-required"])
        steps = status["next"].split(" && ")
        self.assertEqual([step.split()[1:3] for step in steps], [["preflight", self.url], ["plan", self.url]])
        self.assertTrue(all("--run NEW_RUN" in step for step in steps))
        self.assertEqual(self.cli("preflight", "--run", "first")[1]["outcome"], "PASS")
        self.assertEqual(workflow.read_json(run / "source.json"), record)
        self.assertEqual(self.remote_refs(), before)
        self.assertFalse(self.pushed.exists())

    def test_checkout_path_runs_name_evidence_from_the_cloned_url(self):
        self.assertEqual(self.cli("preflight", "--run", "first")[1]["outcome"], "PASS")
        checkout = workflow.source_repository(self.url, "first")
        cloned = checkout.parent / "source.json"
        cloned.write_text(json.dumps({**workflow.read_json(cloned), "url": "https://github.com/example/project.git"}))
        self.assertEqual(self.cli("plan", "--run", "first", source=str(checkout))[1]["outcome"], "PASS")
        with patch.object(rc, "verify", side_effect=verified):
            self.assertEqual(self.cli("export", "--run", "first", "--verify", source=str(checkout))[1]["outcome"], "PASS")
        attempt = checkout.parent / "attempts" / workflow.read_json(checkout.parent / "export.json")["attempt"]
        self.assertTrue((attempt / "verify-evidence.json").is_file())
        self.assertEqual(workflow.read_json(attempt / "verify-evidence.json")["repo"]["name"], "example/project")

    def test_use_git_credentials_reaches_the_clone_only_for_remote_preflight(self):
        with patch.object(rc, "global_credential_helpers", return_value=[]) as helpers:
            self.assertEqual(self.cli("preflight", "--run", "first", "--use-git-credentials")[1]["outcome"], "PASS")
        helpers.assert_called()
        code, result = self.cli("preflight", "--run", "local", "--use-git-credentials", source=str(self.testbed.repo))
        self.assertEqual((code, result["reasons"]), (2, ["git-credentials-selection"]))
        code, result = self.cli("plan", "--run", "first", "--use-git-credentials")
        self.assertEqual((code, result["reasons"]), (2, ["git-credentials-selection"]))

    def test_commands_after_preflight_need_the_cloned_run(self):
        code, result = self.cli("plan", "--run", "never")
        self.assertEqual((code, result["reasons"]), (2, ["source-not-cloned"]))

    def test_remote_spec_forms(self):
        self.assertEqual(workflow.remote_url("OWNER/REPO"), "https://github.com/OWNER/REPO.git")
        self.assertEqual(workflow.remote_url("OWNER/REPO.git"), "https://github.com/OWNER/REPO.git")
        for url in ("https://github.com/OWNER/REPO.git", "ssh://git@github.com/OWNER/REPO.git", "git@github.com:OWNER/REPO.git"):
            self.assertEqual(workflow.remote_url(url), url)
        self.assertIsNone(workflow.remote_url(str(self.testbed.repo)))
        self.assertIsNone(workflow.remote_url("."))
        local = self.root / "git@host:path"
        local.mkdir()
        self.assertIsNone(workflow.remote_url(str(local)))
        keys = {workflow.repository_key(url) for url in ("https://github.com/OWNER/REPO.git", "git@github.com:OWNER/REPO.git",
                                                           "ssh://git@github.com:22/OWNER/REPO.git", "https://github.com:443/owner/repo/")}
        self.assertEqual(keys, {"github.com/owner/repo"})
        for url, reason in (("https://user:" + "secret-value@github.com/OWNER/REPO.git", "source-url-credentials"),
                            ("https://secret-value@github.com/OWNER/REPO.git", "source-url-credentials"),
                            ("https://github.com/OWNER/REPO.git?token=secret-value", "source-url-credentials"),
                            ("ssh://git:secret-value@github.com/OWNER/REPO.git", "source-url-credentials"),
                            ("http://github.com/OWNER/REPO.git", "source-url-invalid"),
                            ("https://github.com/OWNER/REPO.git\n", "source-url-invalid")):
            with self.subTest(url=url):
                code, result = self.cli("preflight", "--run", "first", source=url)
                self.assertEqual((code, result["reasons"]), (2, [reason]))
                self.assertNotIn("secret-value", json.dumps(result))

    def test_failed_clone_is_incomplete_and_retried_fresh(self):
        missing = "file://" + str(self.root / "missing.git")
        code, result = self.cli("preflight", "--run", "first", source=missing)
        self.assertEqual((code, result["reasons"]), (2, ["source-clone-failed"]))
        self.assertFalse((workflow.source_repository(missing, "first").parent / "source.json").exists())
        subprocess.run(["git", "clone", "-q", "--bare", str(self.testbed.repo), str(self.root / "missing.git")], check=True, capture_output=True)
        self.assertEqual(self.cli("preflight", "--run", "first", source=missing)[1]["outcome"], "PASS")


if __name__ == "__main__":
    unittest.main()
