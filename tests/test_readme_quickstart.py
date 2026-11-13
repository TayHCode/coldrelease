import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import release_check as rc

ROOT = Path(rc.__file__).parent


class ReadmeQuickstartTests(unittest.TestCase):
    def quickstart_blocks(self):
        readme = (ROOT / "README.md").read_text()
        start = readme.find("\n## Quickstart\n")
        end = readme.find("\n## Single-command audit\n")
        self.assertTrue(0 <= start < end, "README needs a Quickstart section before the single-command audit")
        blocks = re.findall(r"```sh\n(.*?)```", readme[start:end], re.S)
        self.assertGreaterEqual(len(blocks), 4)
        return blocks

    def test_prerequisites_name_the_debian_packages(self):
        install = self.quickstart_blocks()[0].split()
        for package in ("git", "python3-venv"):
            self.assertIn(package, install)

    def test_demo_blocks_run_verbatim_and_publish_one_commit(self):
        demo, steps = self.quickstart_blocks()[2:4]
        with tempfile.TemporaryDirectory() as tempdir:
            home = Path(tempdir)
            tools = home / "bin"
            tools.mkdir()
            shim = tools / "coldrelease"
            shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{rc.__file__}" "$@"\n')
            shim.chmod(0o755)
            scanner = tools / "gitleaks"
            scanner.write_text('#!' + sys.executable + '\nimport pathlib, sys\nargs = sys.argv[1:]\n'
                               'if args == ["version"]:\n print("8.24.0"); sys.exit(0)\n'
                               'if args == ["git", "--help"]:\n print("--config --gitleaks-ignore-path --ignore-gitleaks-allow '
                               '--redact --no-banner --exit-code --report-format --report-path --log-opts"); sys.exit(0)\n'
                               'pathlib.Path(args[args.index("--report-path") + 1]).write_text("[]")\n')
            scanner.chmod(0o755)
            clone = home / "clone"
            clone.mkdir()
            shutil.copyfile(ROOT / "LICENSE", clone / "LICENSE")
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith(("GIT_", "XDG_", "RELEASE_CHECK_", "COLDRELEASE_"))}
            env.update(HOME=str(home), PATH=str(tools) + os.pathsep + os.environ["PATH"])
            result = subprocess.run(["bash", "-e", "-c", demo + steps], cwd=clone, env=env,
                                    capture_output=True, text=True, timeout=900)
            self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            outcomes = [json.loads(line)["outcome"] for line in result.stdout.splitlines() if line.startswith("{")]
            self.assertEqual(outcomes, ["PASS"] * 5)
            published = subprocess.run(["git", "--git-dir", str(home / "coldrelease-demo-public.git"),
                                        "rev-list", "--count", "main"], capture_output=True, text=True, env=env)
            self.assertEqual(published.stdout.strip(), "1")
            self.assertEqual(len(list((home / ".local/state/coldrelease/runs").glob("*/demo/published.json"))), 1)


if __name__ == "__main__":
    unittest.main()
