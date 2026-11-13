import json
import unittest

import release_check as rc
import test_release_check as fixtures


class BarePrivateRepoNameTests(unittest.TestCase):
    def setUp(self):
        self.testbed = fixtures.AuditTests()
        self.testbed.setUp()
        self.addCleanup(self.testbed.doCleanups)

    def test_placeholder_owner_and_bare_name_block_in_tree_and_export_history(self):
        testbed = self.testbed
        (testbed.repo / "notes.txt").write_text(
            'remote = "o/widget-private"\n'
            "Clone widget-private first.\n"
            'public = "o/widget" and https://github.com/testbed-owner/widget\n'
            "Keep this file private; widget-privateer and xwidget-private are other words.\n")
        testbed.commit("Add notes")
        code, out, _ = testbed.run_cli("--private-repo", 'https://github.com/fixtur' 'e-owner/widget-private.git',
                                       "--verify", "--export", str(testbed.root / "export"))
        self.assertEqual(code, 1)
        report = json.loads((testbed.root / "reports" / json.loads(out.splitlines()[0])["report"]).read_text())
        for target in (report, report["export"]):
            hits = {(f["scope"], f["path"], f["line"]) for f in target["findings"] if f["kind"] == "private-repo-url"}
            self.assertEqual(hits, {(scope, "notes.txt", line) for scope in ("tree", "history") for line in (1, 2)})
        self.assertNotIn("widget-private", out + json.dumps(report))

    def test_names_in_filenames_symlinks_commit_metadata_and_deleted_history_block(self):
        testbed = self.testbed
        (testbed.repo / "old.txt").write_text("widget-private\n")
        testbed.commit("Add old notes")
        testbed.git("rm", "-q", "--", "old.txt")
        (testbed.repo / "docs").mkdir()
        (testbed.repo / "docs/widget-private.md").write_text("ordinary\n")
        (testbed.repo / "link").symlink_to("../Widget-Private/settings")
        testbed.git("add", "--", "docs/widget-private.md", "link")
        testbed.git("commit", "-q", "-m", "Import WIDGET-PRIVATE notes")
        code, out, _ = testbed.run_cli("--private-repo", 'git@git' '.example:widget-private.git', "--verify")
        self.assertEqual(code, 1)
        report = json.loads((testbed.root / "reports" / json.loads(out.splitlines()[0])["report"]).read_text())
        hits = [f for f in report["findings"] if f["kind"] == "private-repo-url"]
        self.assertIn(("tree", "link", 1), {(f["scope"], f["path"], f["line"]) for f in hits})
        self.assertTrue(any(f["scope"] == "tree" and f["path"].startswith("[path-") for f in hits))
        self.assertIn(("history", "old.txt", 1), {(f["scope"], f["path"], f["line"]) for f in hits})
        self.assertIn("metadata", {f["scope"] for f in hits})
        self.assertNotIn("widget-private", (out + json.dumps(report)).casefold())

    def test_every_private_repo_form_blocks_the_bare_name(self):
        for repo in ("o/widget-private", 'https://github.com/' 'o/widget-private.git', 'git@git' 'hub.com:o/widget-private.git',
                     'https://github.com/o' '/widget-private.git/',
                     'https://git.example/gr' 'oup/sub/widget-private/', 'git@git' '.example:widget-private.git', "widget-private"):
            for text in (b"clone widget-private", b"WIDGET-PRIVATE.git", b"(widget-private)", b"see o/widget-private",
                         b"group/sub/widget-private"):
                with self.subTest(repo=repo, text=text):
                    scanner = rc.Scanner([], [repo])
                    scanner.text(text, "tree", "notes.txt")
                    self.assertEqual([f["kind"] for f in scanner.findings], ["private-repo-url"])

    def test_bare_name_keeps_paths_out_of_reports(self):
        for repo in ("testbed-owner/widget-private", "widget-private.git", 'https://github.com/' 'widget-private.git/'):
            with self.subTest(repo=repo):
                scanner = rc.Scanner([], [repo])
                scanner.file(b"widget-private\n", "tree", "docs/widget-private.md")
                self.assertTrue(scanner.findings)
                self.assertTrue(all(f["path"].startswith("[path-") for f in scanner.findings))
                diagnostic = rc.venv_failure(b"Error: cannot build widget-private", scanner)
                self.assertNotIn("widget-private", json.dumps(diagnostic).casefold())

    def test_short_bare_name_redacts_only_whole_words(self):
        for repo in ('git@code' 'berg.org:o/r.git', 'git@git' '.example:r.git'):
            with self.subTest(repo=repo):
                scanner = rc.Scanner([], [repo])
                self.assertEqual(scanner.safe_path("remote.txt"), "remote.txt")
                self.assertTrue(scanner.safe_path("r/settings").startswith("[path-"))
                self.assertEqual(rc.venv_failure(b"error: r failed in remote", scanner)["error_tail"], "error: [redacted] failed in remote")

    def test_full_ref_hit_does_not_hide_another_private_name(self):
        cases = ((["o/foo", "p/foo.bar"], b"see o/foo.bar"), (["o/foo.bar", "p/bar.baz"], b"see o/foo.bar.baz"),
                 (["o/bar.baz", "p/bar"], b"see o/bar.baz"), (["o/a.a"], b"see o/a.a.a"))
        for repos, text in cases:
            with self.subTest(repos=repos):
                scanner = rc.Scanner([], repos)
                scanner.text(text, "tree", "notes.txt")
                self.assertEqual(len([f for f in scanner.findings if f["kind"] == "private-repo-url"]), 2)

    def test_host_only_private_repo_url_adds_no_bare_name(self):
        scanner = rc.Scanner([], ['ssh://git@exa' 'mple.org:2222', "o/tool"])
        scanner.text(b"listen on port 2222\nbuild tool", "tree", "notes.txt")
        self.assertEqual([(f["kind"], f["line"]) for f in scanner.findings], [("private-repo-url", 2)])


if __name__ == "__main__":
    unittest.main()
