import json
import os
from pathlib import Path
import unittest

import release_check as rc
from tests import test_release_check as fixtures


class ForgeNeutralTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        self.repo = self.testbed.repo
        self.testbed.git("rm", "-q", "-r", "--", ".github")
        self.testbed.git("commit", "-q", "-m", "Drop GitHub templates")

    def template_findings(self):
        scanner = rc.Scanner(self.testbed.terms)
        rc.quality_audit(self.repo, scanner, self.testbed.manifest)
        return [f for f in scanner.findings if f["kind"] == "missing-issue-templates"]

    def add(self, rel, text="name: bug\n", track=True):
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if track:
            self.testbed.git("add", "--", rel)
        return path

    def reset_templates(self):
        self.testbed.git("rm", "-q", "-r", "--cached", "--ignore-unmatch", "--", ".gitlab", ".gitea", ".github")
        for name in (".gitlab", ".gitea", ".github"):
            path = self.repo / name
            if path.is_symlink() or path.is_file():
                path.unlink()
            elif path.exists():
                for child in sorted(path.rglob("*"), reverse=True):
                    child.unlink() if child.is_file() or child.is_symlink() else child.rmdir()
                path.rmdir()

    def test_gitlab_and_gitea_issue_templates_pass(self):
        self.assertEqual([f["path"] for f in self.template_findings()], [rc.ISSUE_TEMPLATE_DIR])
        for rel in (".gitlab/issue_templates/bug.md", ".gitea/ISSUE_TEMPLATE/bug.yaml",
                    ".gitea/issue_template/bug.md", ".github/ISSUE_TEMPLATE/bug.yml"):
            with self.subTest(rel=rel):
                self.reset_templates()
                self.add(rel)
                self.assertEqual(self.template_findings(), [])

    def test_issue_template_bypasses_stay_missing(self):
        outside = self.testbed.root / "outside"
        (outside / "issue_templates").mkdir(parents=True)
        (outside / "issue_templates/bug.md").write_text("# bug\n")

        def symlinked_file(rel):
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(outside / "issue_templates/bug.md", path)
            self.testbed.git("add", "--", rel)

        def symlinked_dir():
            os.symlink(outside, self.repo / ".gitlab")
            self.testbed.git("add", "--", ".gitlab")

        cases = {
            "gitlab yaml is not a gitlab template": lambda: self.add(".gitlab/issue_templates/bug.yml"),
            "untracked gitlab template": lambda: self.add(".gitlab/issue_templates/bug.md", track=False),
            "singular gitlab directory": lambda: self.add(".gitlab/issue_template/bug.md"),
            "gitlab template symlink": lambda: symlinked_file(".gitlab/issue_templates/bug.md"),
            "github template symlink": lambda: symlinked_file(".github/ISSUE_TEMPLATE/bug.md"),
            "symlinked gitlab directory": symlinked_dir,
        }
        for name, build in cases.items():
            with self.subTest(name):
                self.reset_templates()
                build()
                self.assertEqual([f["path"] for f in self.template_findings()], [rc.ISSUE_TEMPLATE_DIR])

    def test_requirements_name_every_template_location(self):
        text = rc.requirements_text()
        for location in (".github/ISSUE_TEMPLATE/", ".gitlab/issue_templates/", ".gitea/ISSUE_TEMPLATE/", ".gitea/issue_template/"):
            self.assertIn(location, text)


class AnyHostPrivateRepoTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        self.repo = self.testbed.repo

    def history_only(self, text):
        self.testbed.git("checkout", "-q", "--detach")
        (self.repo / "remote.txt").write_text(text + "\n")
        self.testbed.commit("Add remote")
        blob = self.testbed.git("rev-parse", "HEAD:remote.txt").decode().strip()
        self.testbed.git("checkout", "-q", "main")
        self.assertFalse((self.repo / "remote.txt").exists())
        return blob

    def history_hits(self, flag, blob):
        scanner = rc.Scanner(self.testbed.terms, [flag])
        scanner.history(self.repo)
        return [f for f in scanner.findings if f["kind"] == "private-repo-url" and f["scope"] == "history" and f.get("object") == blob]

    def test_private_repo_on_any_host_matches_every_form(self):
        cases = (
            ("https://gitlab.com/group/sub/proj.git", 'git@git' 'lab.com:group/sub/proj.git'),
            ("https://gitlab.com/group/sub/proj.git/", "see group/sub/proj for details"),
            ('git@code' 'berg.org:o/r.git', "https://codeberg.org/o/r"),
            ('ssh://git@gitea.' 'example.org:2222/team/tool.git', "mirror at https://other.example/team/tool"),
            ("https://github.com/fake/hidden", 'git@git' 'hub.com:fake/hidden.git'),
        )
        for flag, text in cases:
            with self.subTest(flag=flag):
                hits = self.history_hits(flag, self.history_only(text))
                self.assertEqual(len(hits), 1, hits)
                self.assertEqual(hits[0]["path"], "remote.txt")

    def test_cli_report_fails_and_hides_gitlab_label(self):
        self.history_only('origin git@git' 'lab.com:group/sub/proj.git')
        code, out, _ = self.testbed.run_cli("--private-repo", "https://gitlab.com/group/sub/proj.git")
        self.assertNotEqual(code, 0)
        report = json.loads(next((self.testbed.root / "reports").rglob("report.json")).read_text())
        self.assertIn(("history", "private-repo-url"), {(f["scope"], f["kind"]) for f in report["findings"]})
        reports = "".join(p.read_text() for p in (self.testbed.root / "reports").rglob("*") if p.is_file())
        self.assertNotIn("group/sub/proj", reports + out)


if __name__ == "__main__":
    unittest.main()
