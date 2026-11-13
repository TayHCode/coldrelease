import json
import subprocess
import sys
import unittest

import release_check as rc
import test_release_check as fixtures


class SourceIdentityTermTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)
        self.testbed.denylist.write_text(json.dumps(["unrelated-codename"]))

    def commit_as(self, name, email, message):
        self.testbed.git("-c", "user.name=" + name, "-c", "user.email=" + email, "commit", "-q", "--allow-empty", "-m", message)

    def export(self):
        testbed = self.testbed
        result = subprocess.run([sys.executable, rc.__file__, str(testbed.repo), "--denylist", str(testbed.denylist),
                                 "--reports", str(testbed.root / "reports"), "--export", str(testbed.root / "export")],
                                capture_output=True, text=True, timeout=120)
        report_path = testbed.root / "reports" / json.loads(result.stdout.splitlines()[0])["report"]
        reports = report_path.read_text() + report_path.with_suffix(".md").read_text()
        return result, json.loads(report_path.read_text())["export"], reports

    def denylist_paths(self, export_report):
        return sorted({f["path"] for f in export_report["findings"] if f["kind"] == "denylist" and not f["reviewed"]})

    def test_author_name_in_readme_fails_export_without_denylist_entry(self):
        self.commit_as("Quillon Varnet", "quillon@example.invalid", "Work")
        notice = self.testbed.repo / "NOTICE-Quillon Varnet"
        notice.write_text("Attribution.\n")
        self.testbed.commit("Notice")
        self.testbed.git("rm", "-q", "--", notice.name)
        self.testbed.git("commit", "-q", "-m", "Drop notice")
        readme = self.testbed.repo / "README.md"
        readme.write_text(readme.read_text() + "Maintained by Quillon Varnet.\n")
        self.testbed.commit("Credit")
        result, export_report, reports = self.export()
        self.assertEqual(export_report["outcome"], "FAIL", result.stdout + result.stderr)
        self.assertEqual(self.denylist_paths(export_report), ["README.md"])
        self.assertNotIn("quillon", json.dumps(export_report).lower())

    def test_name_inside_export_identity_is_still_a_term(self):
        self.commit_as("Port", "port@example.invalid", "Work")
        readme = self.testbed.repo / "README.md"
        readme.write_text(readme.read_text() + "Ask Port.\n")
        self.testbed.commit("Credit")
        result, export_report, _ = self.export()
        self.assertEqual(self.denylist_paths(export_report), ["README.md"], result.stdout + result.stderr)

    def test_home_path_username_from_history_fails_export(self):
        note = self.testbed.repo / "notes.txt"
        note.write_text("built in /home/zorvek, then in /home/quenbé.\n")
        self.testbed.commit("Notes")
        self.testbed.git("rm", "-q", "--", "notes.txt")
        self.testbed.git("commit", "-q", "-m", "Drop notes")
        readme = self.testbed.repo / "README.md"
        readme.write_text(readme.read_text() + "Ask zorvek.\n")
        contributing = self.testbed.repo / "CONTRIBUTING.md"
        contributing.write_text(contributing.read_text() + " Or quenbé.\n")
        self.testbed.commit("Contact")
        result, export_report, reports = self.export()
        self.assertEqual(self.denylist_paths(export_report), ["CONTRIBUTING.md", "README.md"])
        output = (result.stdout + result.stderr + reports).lower()
        self.assertNotIn("zorvek", output)
        self.assertNotIn("quenb", output)

    def test_generic_identities_do_not_self_trigger(self):
        self.commit_as(*rc.EXPORT_IDENTITY, "Earlier export")
        self.commit_as("GitHub", "noreply@github.com", "Merge from the web")
        self.commit_as("helper[bot]", "1+helper[bot]@users.noreply.github.com", "Bump")
        note = self.testbed.repo / "notes.txt"
        note.write_text("CI ran in /home/runner/work and /home/user/src\n")
        self.testbed.commit("Notes")
        self.testbed.git("rm", "-q", "--", "notes.txt")
        self.testbed.git("commit", "-q", "-m", "Drop notes")
        readme = self.testbed.repo / "README.md"
        readme.write_text(readme.read_text() + "Release Export on GitHub; the runner and the user.\n")
        self.testbed.commit("Words")
        result, export_report, _ = self.export()
        self.assertEqual(self.denylist_paths(export_report), [])
        self.assertNotIn("personal", export_report["counts"], result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
