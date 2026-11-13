import json
import shutil
import unittest
from unittest.mock import patch

import release_check as rc

import release_workflow as workflow
import test_release_workflow as flows

BACKEND = '''import base64, hashlib, zipfile
DIST = "testbed_app-0.1.0.dist-info"
FILES = {"testbed_app.py": b"def main():\\n    print('testbed ok')\\n",
         DIST + "/METADATA": b"Metadata-Version: 2.1\\nName: testbed-app\\nVersion: 0.1.0\\nLicense: MIT\\n",
         DIST + "/WHEEL": b"Wheel-Version: 1.0\\nGenerator: testbed\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n",
         DIST + "/entry_points.txt": b"[console_scripts]\\ntestbed-app = testbed_app:main\\n"}
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name = "testbed_app-0.1.0-py3-none-any.whl"
    record = "".join("%s,sha256=%s,%d\\n" % (path, base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode(), len(data))
                     for path, data in FILES.items()) + DIST + "/RECORD,,\\n"
    with zipfile.ZipFile(wheel_directory + "/" + name, "w") as wheel:
        for path, data in {**FILES, DIST + "/RECORD": record.encode()}.items():
            wheel.writestr(path, data)
    return name
'''


class RecipeProposalTests(unittest.TestCase):
    cli, assert_status, target_flags, push, prepare, fake_gitleaks = (
        flows.WorkflowTests.cli, flows.WorkflowTests.assert_status, flows.WorkflowTests.target_flags,
        flows.WorkflowTests.push, flows.WorkflowTests.prepare, flows.WorkflowTests.fake_gitleaks)

    def setUp(self):
        flows.WorkflowTests.setUp(self)
        self.enterContext(self.fake_gitleaks())
        (self.repo / "release-check.json").unlink()

    def project(self, readme, files):
        (self.repo / "README.md").write_text("# Testbed\n## Honest limitations\nSynthetic only.\n```\n" + readme + "\n```\n")
        for name, text in files.items():
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(text)
        self.testbed.git("rm", "-q", "--cached", "release-check.json")
        self.testbed.commit("Synthetic project without a manifest")

    def python_project(self, readme="python -m pip install .\ntestbed-app", tests=None):
        self.project(readme, {**(tests or {}),
            "testbed_backend.py": BACKEND,
            "pyproject.toml": '[build-system]\nrequires = []\nbuild-backend = "testbed_backend"\nbackend-path = ["."]\n\n'
                              '[project]\nname = "testbed-app"\nversion = "0.1.0"\nlicense = "MIT"\n\n'
                              '[project.scripts]\ntestbed-app = "testbed_app:main"\n'})

    def npm_project(self):
        self.project("npm install", {
            "package.json": json.dumps({"name": "testbed-app", "version": "0.1.0", "license": "MIT",
                                        "scripts": {"test": "node tests/run.js"}}),
            "tests/run.js": "require('assert').strictEqual(2 + 2, 4)\n"})

    def accept_and_publish(self):
        planned = self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")
        self.assertEqual(planned["recipe"], "proposed-release-check.json")
        proposal = self.run / "proposed-release-check.json"
        self.assertFalse((self.repo / "release-check.json").exists())
        self.assert_status(self.cli("check", "--verify", real=True), "INCOMPLETE", "recipe-not-accepted")
        proposal.rename(self.run / "release-check.json")
        self.assert_status(self.cli("export", "--verify", real=True), "PASS")
        self.prepare()
        record = workflow.read_json(self.run / "approval.json")
        self.assertEqual(record["recipe"], workflow.read_json(self.run / "release-check.json"))
        self.push()
        self.assert_status(self.cli("publish", *self.target_flags(), real=True), "PASS")
        self.assertEqual(self.testbed.git("status", "--porcelain", "--untracked-files=no"), b"")
        return record["recipe"]

    def test_python_project_reaches_pass_with_the_accepted_proposal(self):
        self.python_project()
        recipe = self.accept_and_publish()
        self.assertEqual([item["argv"] for item in recipe["quickstart"]],
                         [["python", "-m", "pip", "install", "."], ["testbed-app"]])
        self.assertEqual(recipe["checks"], [{"role": "tests", "argv": ["python", "-m", "unittest", "discover", "-s", "tests", "-q"]}])
        self.assertEqual(recipe["verify_tools"], [])

    @unittest.skipUnless(shutil.which("node") and shutil.which("npm"), "node and npm are required")
    def test_npm_project_reaches_pass_with_the_accepted_proposal(self):
        self.npm_project()
        recipe = self.accept_and_publish()
        self.assertEqual([item["argv"] for item in recipe["quickstart"]], [["npm", "install"]])
        self.assertIn({"role": "tests", "argv": ["npm", "test"]}, recipe["checks"])
        self.assertEqual(recipe["verify_tools"], ["node", "npm"])

    def accepted_check(self, tests, readme="python -m pip install ."):
        self.python_project(readme, tests)
        self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")
        (self.run / "proposed-release-check.json").rename(self.run / "release-check.json")
        code, value = self.cli("check", "--verify")
        self.assertIn(value["outcome"], {"FAIL", "INCOMPLETE"}, value)
        report = workflow.read_json(self.run / "attempts" / value["attempt"] / "report.json")
        self.assertIn(("command-failed", "release-check.json"),
                      [(f["kind"], f["path"]) for f in report["findings"]], report["findings"])
        return workflow.read_json(self.run / "release-check.json")["checks"]

    def write_tests(self, tests):
        shutil.rmtree(self.repo / "tests", ignore_errors=True)
        for name, text in tests.items():
            (self.repo / name).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / name).write_text(text)
        return self.repo

    def proposed_runner(self, tests):
        self.python_project(tests=tests)
        return workflow.propose_recipe(self.repo)["checks"][0]["argv"][2]

    def test_module_level_test_function_goes_to_pytest(self):
        self.assertEqual(self.proposed_runner({"tests/test_plain.py": "def test_plain():\n    assert True\n"}), "pytest")

    def test_unittest_mentioned_only_in_a_comment_goes_to_pytest(self):
        self.assertEqual(self.proposed_runner({"tests/test_testbed.py": "# unittest TestCase\nVALUE = 1\n"}), "pytest")

    def test_unparseable_test_file_goes_to_pytest(self):
        self.assertEqual(self.proposed_runner({"tests/test_broken.py": "def test_(:\n"}), "pytest")

    def test_pure_unittest_suite_runs_its_tests(self):
        failing = "import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertEqual(2 + 2, 5)\n"
        checks = self.accepted_check({"tests/test_testbed.py": failing})
        self.assertEqual(checks[0]["argv"][:3], ["python", "-m", "unittest"])

    def test_pytest_without_pytest_installed_never_passes(self):
        checks = self.accepted_check({"tests/test_plain.py": "def test_plain():\n    assert True\n"})
        self.assertEqual(checks[0]["argv"], ["python", "-m", "pytest", "-q"])

    def test_suite_without_unittest_tests_goes_to_pytest(self):
        self.assertEqual(self.proposed_runner({"tests/test_testbed.py": "VALUE = 1\n"}), "pytest")

    def test_unittest_discover_blind_spots_go_to_pytest(self):
        self.python_project()
        case = "import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        pass\n"
        for name, tests in {
                "folder without __init__": {"tests/unit/test_testbed.py": case},
                "local TestCase": {"tests/test_testbed.py": "class TestCase:\n    pass\nclass T(TestCase):\n    def test_ok(self):\n        pass\n"},
                "async test": {"tests/test_testbed.py": case + "    async def test_async(self):\n        assert False\n"},
                "load_tests": {"tests/test_testbed.py": case + "def load_tests(loader, tests, pattern):\n    return unittest.TestSuite()\n"}}.items():
            with self.subTest(name):
                self.assertEqual(workflow.propose_recipe(self.write_tests(tests))["checks"][0]["argv"][2], "pytest")

    def test_packaged_folders_and_imported_testcase_stay_unittest(self):
        case = "from unittest import TestCase\nclass T(TestCase):\n    def test_ok(self):\n        pass\n"
        self.assertEqual(self.proposed_runner({"tests/unit/__init__.py": "", "tests/unit/test_testbed.py": case}), "unittest")

    def test_makefile_test_target_is_proposed(self):
        (self.repo / "Makefile").write_text("VERSION := 1\ntest:\n\tpython3 -m unittest\n")
        self.assertEqual(workflow.propose_recipe(self.repo)["checks"], [{"role": "tests", "argv": ["make", "test"]}])
        (self.repo / "Makefile").write_text("test := 1\n")
        self.assertEqual(workflow.propose_recipe(self.repo)["checks"], [])

    def test_incomplete_proposal_names_the_file_and_can_be_completed(self):
        self.python_project("echo setup")
        self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "INCOMPLETE", "recipe-proposal-incomplete")
        proposal = workflow.read_json(self.run / "proposed-release-check.json")
        self.assertEqual(proposal["quickstart"], [])
        code, value = self.cli("status", "--json")
        self.assertEqual(value["state"], "recipe-proposed", value)
        (self.repo / "README.md").write_text((self.repo / "README.md").read_text() + "python -m pip install .\n")
        self.testbed.commit("Document the install")
        workflow.write_json(self.run / "release-check.json", {**proposal, "quickstart": [
            {"file": "README.md", "line": 7, "argv": ["python", "-m", "pip", "install", "."]}]})
        self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")

    def test_source_recipe_added_after_plan_still_needs_acceptance(self):
        self.python_project()
        self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")
        (self.repo / "release-check.json").write_text(json.dumps(self.testbed.manifest))
        self.testbed.commit("Add a source manifest")
        self.assert_status(self.cli("check", "--verify"), "INCOMPLETE", "recipe-not-accepted")

    def test_unparseable_project_files_propose_nothing(self):
        (self.repo / "package.json").write_text('{"scripts": {"test": "a", "test": "b"}}')
        (self.repo / "pyproject.toml").write_text("[project\n")
        self.assertEqual(workflow.propose_recipe(self.repo)["verify_tools"], [])

    def test_an_edited_approval_rejects_a_changed_recipe(self):
        self.python_project()
        self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")
        (self.run / "proposed-release-check.json").rename(self.run / "release-check.json")
        with patch.object(rc, "verify", side_effect=flows.verified):
            self.assert_status(self.cli("export", "--verify"), "PASS")
        self.prepare()
        record = workflow.read_json(self.run / "approval.json")
        record["recipe"]["checks"] = []
        (self.run / "approval.json").unlink()
        workflow.write_json(self.run / "approval.json", record)
        self.assert_status(self.cli("publish", *self.target_flags()), "INCOMPLETE", "approval-recipe")

    def test_accepted_recipe_may_not_carry_approvals(self):
        self.python_project()
        self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")
        workflow.write_json(self.run / "release-check.json", {"checks": [], "approvals": []})
        self.assert_status(self.cli("check", "--verify"), "INCOMPLETE", "recipe-schema")

    def test_status_names_the_accept_step(self):
        self.python_project()
        self.assert_status(self.cli("plan", "--scanner", "gitleaks"), "PASS")
        code, value = self.cli("status", "--json")
        self.assertEqual(value["state"], "recipe-proposed", value)
        self.assertIn(str(self.run / "release-check.json"), value["next"])


if __name__ == "__main__":
    unittest.main()
