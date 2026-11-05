import json
import subprocess

import release_check as rc
import unittest

import test_release_check as fixtures


class WorktreeScopeTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixtures.AuditTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        repo = self.fx.repo
        (repo / ".gitignore").write_text("/.worktrees/\n/.scratch/\n")
        self.fx.commit("Ignore working folders")
        (repo / ".worktrees/feature").mkdir(parents=True)
        (repo / ".worktrees/feature/notes.md").write_text("HiddenPerson wrote this\n")
        (repo / ".scratch").mkdir()
        (repo / ".scratch/key.txt").write_text("token = ghp_" + "a" * 36 + "\n")

    def kinds(self):
        return {(f["path"], f["kind"]) for f in self.fx.scan().findings}

    def test_ignored_working_folders_are_not_scanned(self):
        paths = {path for path, _ in self.kinds()}
        self.assertFalse(any(p.startswith((".worktrees", ".scratch")) for p in paths))

    def test_untracked_visible_files_are_still_scanned(self):
        (self.fx.repo / "draft.md").write_text("HiddenPerson\n")
        self.assertIn("draft.md", {path for path, _ in self.kinds()})

    def test_untracked_nested_repository_blocks_instead_of_being_skipped(self):
        nested = self.fx.repo / "vendored"
        nested.mkdir()
        subprocess.run(["git", "init", "-q", str(nested)], check=True)
        self.assertIn(("vendored", "nested-repository"), self.kinds())

    def test_legacy_export_copies_only_visible_files(self):
        target = self.fx.root / "export"
        code, out, err = self.fx.run_cli("--export", str(target))
        self.assertIn("export_outcome", json.loads(out.splitlines()[0]))
        self.assertTrue((target / "README.md").is_file())
        self.assertFalse((target / ".worktrees").exists())
        self.assertFalse((target / ".scratch").exists())


    def symlink_tracked_folder(self):
        outside = self.fx.root / "outside"
        outside.mkdir()
        (outside / "notes.md").write_text("HiddenPerson\n")
        (self.fx.repo / "docs").mkdir()
        (self.fx.repo / "docs/notes.md").write_text("public\n")
        self.fx.git("add", "docs/notes.md")
        self.fx.git("commit", "-qm", "Add docs")
        (self.fx.repo / "docs/notes.md").unlink()
        (self.fx.repo / "docs").rmdir()
        (self.fx.repo / "docs").symlink_to(outside)

    def test_tracked_file_under_symlinked_folder_is_not_read(self):
        self.symlink_tracked_folder()
        kinds = self.kinds()
        self.assertIn(("docs/notes.md", "symlink"), kinds)
        self.assertNotIn(("docs/notes.md", "family"), kinds)

    def test_legacy_export_does_not_follow_symlinked_folder(self):
        self.symlink_tracked_folder()
        target = self.fx.root / "export"
        self.fx.run_cli("--export", str(target))
        self.assertFalse((target / "docs/notes.md").exists())

    def test_ignored_files_do_not_change_npm_source_scope(self):
        before = rc.npm_source_scope(self.fx.repo, self.fx.manifest)
        (self.fx.repo / ".worktrees/feature/node_modules").mkdir(parents=True)
        (self.fx.repo / ".worktrees/feature/node_modules/index.js").write_text("payload\n")
        self.assertIsNotNone(before)
        self.assertEqual(rc.npm_source_scope(self.fx.repo, self.fx.manifest), before)

    def test_unignored_nested_node_modules_keeps_manual_review(self):
        (self.fx.repo / "app/node_modules/pkg").mkdir(parents=True)
        (self.fx.repo / "app/package.json").write_text("{}")
        (self.fx.repo / "app/node_modules/pkg/index.js").write_text("payload\n")
        scanner = rc.Scanner(self.fx.terms)
        rc.license_audit(self.fx.repo, scanner, self.fx.manifest)
        self.assertIn("dependency-ecosystem-manual-review", {f["kind"] for f in scanner.findings})


if __name__ == "__main__":
    unittest.main()
