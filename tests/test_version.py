from pathlib import Path
import subprocess
import sys
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


class VersionTests(unittest.TestCase):
    def test_version_flag_prints_pyproject_version(self):
        expected = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
        result = subprocess.run([sys.executable, "release_check.py", "--version"],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, f"coldrelease {expected}\n", ""))


if __name__ == "__main__":
    unittest.main()
