import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
from tests import test_release_workflow as flows

TARGET = "https://github.com/Example/Project.git"


class OwnerPublicPushRuleTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.home = Path(temp.name)
        self.guards = self.home / ".coldlocker" / "guards.json"
        self.guards.parent.mkdir()

    def allows(self, target=TARGET):
        rule = getattr(workflow, "owner_allows_public", lambda target: None)
        with patch.dict(os.environ, {"HOME": str(self.home)}):
            return rule(target)

    def write(self, guards):
        self.guards.write_text(guards if isinstance(guards, str) else json.dumps(guards))

    def test_absent_file_allows(self):
        self.assertIs(self.allows(), True)

    def test_default_false_refuses_every_target(self):
        self.write({"default": {"public_push": False}})
        for target in (TARGET, "git@github.com:other/repo.git", "/srv/git/public.git"):
            with self.subTest(target=target):
                self.assertIs(self.allows(target), False)

    def test_per_repo_false_refuses_only_that_repo(self):
        self.write({"repos": {"example/project": {"public_push": False}}})
        self.assertIs(self.allows(), False)
        for target in ("ssh://git@github.com/example/project", "https://git@github.com/example/project.git",
                       "ssh://git@ssh.github.com:443/example/project.git", "https://GitHub.com/example/project/",
                       "github.com:example/project.git"):
            with self.subTest(target=target):
                self.assertIs(self.allows(target), False)
        self.assertIs(self.allows("https://github.com/example/other.git"), True)

    def test_a_target_without_an_owner_repo_refuses_while_any_repo_says_no(self):
        targets = ("git@github-work:example/project.git", "https://github.com/example/project/extra",
                   "https://github.com.example.org/team/repo.git", "/srv/git/public.git")
        self.write({"repos": {"example/project": {"public_push": False}}})
        for target in targets:
            with self.subTest(target=target):
                self.assertIs(self.allows(target), False)
        self.write({"repos": {"example/project": {"public_push": True}}})
        for target in targets:
            with self.subTest(target=target):
                self.assertIs(self.allows(target), True)

    def test_per_repo_true_overrides_default_false(self):
        self.write({"default": {"public_push": False}, "repos": {"Example/Project": {"public_push": True}}})
        self.assertIs(self.allows(), True)
        self.assertIs(self.allows("https://github.com/example/other.git"), False)

    def test_other_switches_leave_the_answer_yes(self):
        self.write({"default": {"keep_going": True}, "repos": {"example/project": {"publication": False}}})
        self.assertIs(self.allows(), True)

    def test_invalid_file_refuses(self):
        for guards in ("{not json", "[]", '{"default": {"public_push": "no"}}', '{"other": {}}',
                       '{"default": {"unknown": true}}', '{"repos": {"not-a-repo": {}}}', '{"repos": []}',
                       '{"repos": {"default": {"public_push": false}}}',
                       '{"default": {"public_push": false, "public_push": true}}'):
            with self.subTest(guards=guards):
                self.write(guards)
                self.assertIs(self.allows(), False)

    def test_symlinked_or_non_file_guards_refuses(self):
        real = self.home / "real.json"
        real.write_text("{}")
        self.guards.symlink_to(real)
        self.assertIs(self.allows(), False)
        self.guards.unlink()
        self.guards.mkdir()
        self.assertIs(self.allows(), False)


class OwnerPublicPushCommandTests(unittest.TestCase):
    def setUp(self):
        self.flow = flows.WorkflowTests()
        self.flow.setUp()
        self.addCleanup(self.flow.doCleanups)
        self.flow.export()
        self.flow.prepare()
        self.flow.push()
        (self.flow.home / ".coldlocker" / "guards.json").write_text('{"default": {"public_push": false}}')

    def test_ship_and_publish_refuse_when_the_owner_says_no_after_the_push(self):
        for command in ("ship", "publish"):
            with self.subTest(command=command), patch.object(rc, "verify", side_effect=flows.verified):
                self.flow.assert_status(self.flow.cli(command, *self.flow.target_flags()), "INCOMPLETE", "owner-public-push-no")
                self.assertFalse((self.flow.run / "published.json").exists())


if __name__ == "__main__":
    unittest.main()
