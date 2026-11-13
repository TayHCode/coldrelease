from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RECIPE = ROOT / ".fleet" / "verify.py"

ADAPTER = """import os, sys, unittest
from pathlib import Path
junit_dir = os.environ.pop("COLD_VERIFY_JUNIT_DIR")
sys.path[0] = os.getcwd()
result = unittest.main(module=None, argv=["python3 -m unittest", *sys.argv[1:]], exit=False).result
Path(junit_dir, sys.argv[-1]).write_text(str(result.testsRun))
sys.exit(0 if result.wasSuccessful() else 1)
"""

SAMPLE = """import unittest
class Sample(unittest.TestCase):
    def test_one(self):
        self.assertTrue({passes})
    def test_two(self):
        pass
"""


@unittest.skipUnless(RECIPE.is_file(), ".fleet/verify.py is not part of the public export")
class FleetVerifyTests(unittest.TestCase):
    def run_recipe(self, passes, adapter):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        shutil.copytree(ROOT / ".fleet", directory / ".fleet")
        (directory / "tests").mkdir()
        (directory / "tests" / "test_sample.py").write_text(SAMPLE.format(passes=passes), encoding="utf-8")
        junit = directory / "junit"
        junit.mkdir()
        env = {key: value for key, value in os.environ.items() if not key.startswith("COLD_VERIFY_")}
        env["COLD_VERIFY_JUNIT_DIR"] = str(junit)
        if adapter:
            (directory / "adapter.py").write_text(ADAPTER, encoding="utf-8")
            env["COLD_VERIFY_UNITTEST"] = str(directory / "adapter.py")
        done = subprocess.run([sys.executable, "-B", str(directory / ".fleet" / "verify.py")], capture_output=True,
                              text=True, env=env, check=False)
        return done, sorted(path.name for path in junit.iterdir())

    def test_each_test_process_runs_through_the_adapter_when_cold_verify_sets_it(self):
        done, reports = self.run_recipe(True, adapter=True)
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertIn("Total: 2 of 2 tests in 2 processes", done.stdout)
        self.assertEqual(reports, ["test_sample.Sample.test_one", "test_sample.Sample.test_two"])

    def test_without_the_adapter_the_recipe_runs_plain_unittest(self):
        done, reports = self.run_recipe(True, adapter=False)
        self.assertEqual(done.returncode, 0, done.stdout)
        self.assertIn("Total: 2 of 2 tests in 2 processes", done.stdout)
        self.assertEqual(reports, [])

    def test_a_failing_test_fails_the_recipe_either_way(self):
        for adapter in (True, False):
            with self.subTest(adapter=adapter):
                done, _ = self.run_recipe(False, adapter=adapter)
                self.assertNotEqual(done.returncode, 0, done.stdout)
                self.assertIn("FAIL: test_sample.Sample.test_one (exit 1, 1 of 1 tests)", done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
