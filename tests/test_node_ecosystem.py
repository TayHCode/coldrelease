import json
import os
from pathlib import Path
import unittest
from contextlib import chdir
from unittest.mock import patch

import release_check as rc
import test_release_check as fixtures


class NodeEcosystemTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.repo = self.fixture.repo
        self.root = self.fixture.root
        self.manifest = self.fixture.manifest
        self.reports = self.root / "reports"
        self.reports.mkdir()

    def license_audit(self, package):
        (self.repo / "package.json").write_text(json.dumps(package))
        scanner = rc.Scanner(self.fixture.terms)
        result = rc.license_audit(self.repo, scanner, self.manifest)
        return result, scanner.findings

    def test_dependency_free_package_has_no_findings(self):
        for package in ({}, {"dependencies": {}, "devDependencies": {}, "license": "MIT"},
                        {"scripts": {"test": "node --test"}, "bin": "cli.js"}):
            with self.subTest(package=package):
                result, findings = self.license_audit(package)
                self.assertEqual(findings, [])
                self.assertEqual(result["dependencies"], "none (package.json)")

    def test_dependency_fields_keep_manual_review(self):
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
                    "bundledDependencies", "bundleDependencies", "workspaces", "overrides", "resolutions"):
            with self.subTest(key=key):
                result, findings = self.license_audit({key: ["example"]})
                self.assertEqual([f["kind"] for f in findings], ["dependency-ecosystem-manual-review"])
                self.assertEqual(result["dependencies"], "not-verified")

    def test_install_lifecycle_scripts_keep_manual_review(self):
        for name in ("preinstall", "install", "postinstall", "prepare", "prepublish",
                     "prepublishOnly", "prepack", "postpack"):
            with self.subTest(name=name):
                _, findings = self.license_audit({"scripts": {name: "node setup.js"}})
                self.assertEqual([f["kind"] for f in findings], ["dependency-ecosystem-manual-review"])

    def test_fix_nested_dependency_manifests_require_review(self):
        path = self.repo / "app/package.json"
        path.parent.mkdir()
        for spec in ("file:../gpl-package", "git+https://example.invalid/package", "https://example.invalid/package.tgz", "workspace:*", "1"):
            with self.subTest(spec=spec):
                path.write_text(json.dumps({"dependencies": {"example": spec}}))
                _, findings = self.license_audit({})
                self.assertIn(("dependency-ecosystem-manual-review", "app/package.json"),
                              [(f["kind"], f["path"]) for f in findings])
        path.write_text("{")
        _, findings = self.license_audit({})
        self.assertIn("app/package.json", [f["path"] for f in findings])
        path.unlink()
        path.write_bytes(b'\xef\xbb\xbf{"license":"MIT"}')
        hidden = self.repo / ".git/hidden/package.json"
        hidden.parent.mkdir()
        hidden.write_text('{"dependencies":{"example":"file:../gpl"}}')
        _, findings = self.license_audit({})
        self.assertEqual(findings, [])

    def test_fix_nested_json_bom_duplicates_and_symlinks(self):
        path = self.repo / "app/package.json"
        path.parent.mkdir()
        for raw in (b'\xef\xbb\xbf{"dependencies":{"example":"file:../gpl"}}',
                    b'{"dependencies":{"example":"1"},"dependencies":{}}'):
            with self.subTest(raw=raw):
                path.write_bytes(raw)
                _, findings = self.license_audit({})
                self.assertIn("app/package.json", [f["path"] for f in findings])
        path.unlink()
        outside = self.root / "external-package.json"
        outside.write_text("{}")
        path.symlink_to(outside)
        _, findings = self.license_audit({})
        self.assertIn("app/package.json", [f["path"] for f in findings])

    def test_fix_legacy_licenses_always_require_review(self):
        for licenses in ([], [{"type": "GPL-3.0-only"}], None, "MIT"):
            with self.subTest(licenses=licenses):
                _, findings = self.license_audit({"licenses": licenses})
                self.assertTrue(any(f["kind"] in {"dependency-ecosystem-manual-review", "license-metadata-mismatch"}
                                    and f["path"] == "package.json" for f in findings))

    def test_fix_prepare_and_other_lifecycle_variants_require_review(self):
        for name in ("preprepare", "postprepare", "publish", "dependencies", "pretest", "posttest",
                     "preversion", "postshrinkwrap", "preuninstall", "postrestart", "prestart", "poststop",
                     "preprepack", "postpack", "precustom", "postcustom"):
            for value in ("node setup.js", ""):
                with self.subTest(name=name, value=value):
                    _, findings = self.license_audit({"scripts": {name: value}})
                    self.assertEqual([f["kind"] for f in findings], ["dependency-ecosystem-manual-review"])

    def test_fix_implicit_native_install_hooks_require_review(self):
        _, findings = self.license_audit({"gypfile": True})
        self.assertEqual([f["kind"] for f in findings], ["dependency-ecosystem-manual-review"])
        for relative in ("binding.gyp", "nested/binding.gyp"):
            with self.subTest(relative=relative):
                path = self.repo / relative
                path.parent.mkdir(exist_ok=True)
                path.write_text("{}")
                _, findings = self.license_audit({})
                self.assertTrue(any(f["kind"] == "dependency-ecosystem-manual-review" for f in findings))
                path.unlink()

    def test_fix_relative_and_empty_path_entries_cannot_select_tools(self):
        tools = self.repo / "tools"
        tools.mkdir()
        name = "fixture-private-tool"
        marker = self.repo / "original-source-write"
        fake = tools / name
        fake.write_text("#!/bin/sh\necho touched > '" + str(marker) + "'\n")
        fake.chmod(0o700)
        for cwd, path in ((self.repo, "tools"), (tools, "")):
            with self.subTest(path=path):
                scanner = rc.Scanner(self.fixture.terms)
                with chdir(cwd), patch.dict(os.environ, {"PATH": path}), patch.object(rc, "command") as run:
                    result = rc.verify(self.repo, self.reports, scanner,
                                       {**self.manifest, "verify_tools": [name]}, 30)
                self.assertEqual([f["kind"] for f in scanner.findings], ["verify-tool-missing"])
                self.assertEqual(result["status"], "blocked")
                run.assert_not_called()
                self.assertFalse(marker.exists())

    def test_fix_absolute_and_symlink_tools_inside_audit_paths_are_blocked(self):
        reports = self.root / "reports"
        reports.mkdir(exist_ok=True)
        tools = self.root / "caller-bin"
        tools.mkdir()
        for base in (self.repo, reports):
            with self.subTest(base=base.name):
                target = base / "fixture-private-tool"
                target.write_text("#!/bin/sh\nexit 0\n")
                target.chmod(0o700)
                link = tools / target.name
                link.symlink_to(target)
                for entry in (base, tools):
                    scanner = rc.Scanner(self.fixture.terms)
                    with patch.dict(os.environ, {"PATH": str(entry)}), patch.object(rc, "command") as run:
                        result = rc.verify(self.repo, reports, scanner,
                                           {**self.manifest, "verify_tools": [target.name]}, 30)
                    self.assertEqual([f["kind"] for f in scanner.findings], ["verify-tool-missing"])
                    self.assertEqual(result["status"], "blocked")
                    run.assert_not_called()
                link.unlink()

    def test_fix_export_audit_rejects_original_source_and_export_tools(self):
        export = self.root / "export"
        reports = self.root / "reports"
        reports.mkdir(exist_ok=True)
        tools = self.repo / "tools"
        tools.mkdir()
        name = "fixture-private-tool"
        fake = tools / name
        fake.write_text("#!/bin/sh\nexit 0\n")
        fake.chmod(0o700)
        manifest = {**self.manifest, "verify_tools": [name]}
        (self.repo / "release-check.json").write_text(json.dumps(manifest))
        with patch.dict(os.environ, {"PATH": str(tools) + os.pathsep + os.environ["PATH"]}):
            code, out, err = self.fixture.run_cli("--verify", "--export", str(export))
        self.assertEqual(code, 2, out + err)
        report = json.loads(next(reports.rglob("report.json")).read_text())
        for audited in (report, report["export"]):
            self.assertEqual([f["kind"] for f in audited["findings"]], ["verify-tool-missing"])
        scanner = rc.Scanner(self.fixture.terms)
        with patch.dict(os.environ, {"PATH": str(export / "tools")}), patch.object(rc, "command") as run:
            result = rc.verify(self.repo, reports, scanner, manifest, 30, tool_exclusions=(export,))
        self.assertEqual([f["kind"] for f in scanner.findings], ["verify-tool-missing"])
        self.assertEqual(result["status"], "blocked")
        run.assert_not_called()

    def test_root_and_tracked_lockfiles_keep_manual_review(self):
        for name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                     "bun.lock", "bun.lockb"):
            for prefix in ("", "nested/"):
                with self.subTest(name=name, prefix=prefix):
                    path = self.repo / (prefix + name)
                    path.parent.mkdir(exist_ok=True)
                    path.write_text("fixture")
                    if prefix:
                        self.fixture.git("add", "--", prefix + name)
                        path.unlink()
                    _, findings = self.license_audit({})
                    self.assertEqual([f["kind"] for f in findings], ["dependency-ecosystem-manual-review"])
                    if prefix:
                        self.fixture.git("rm", "--cached", "--", prefix + name)
                    else:
                        path.unlink()

    def test_root_and_tracked_node_modules_keep_manual_review(self):
        path = self.repo / "node_modules"
        path.mkdir()
        _, findings = self.license_audit({})
        self.assertEqual([f["kind"] for f in findings], ["dependency-ecosystem-manual-review"])
        path.rmdir()
        path = self.repo / "nested/node_modules/example/index.js"
        path.parent.mkdir(parents=True)
        path.write_text("fixture")
        self.fixture.git("add", "--", "nested/node_modules/example/index.js")
        path.unlink()
        _, findings = self.license_audit({})
        self.assertEqual([f["kind"] for f in findings], ["dependency-ecosystem-manual-review"])

    def test_invalid_duplicate_and_oversized_package_keep_manual_review(self):
        for raw in ('{', '[]', 'null', '{"dependencies":{"example":"1"},"dependencies":{}}',
                    '{"scripts":{"install":"run","install":""}}', '{"x":NaN}',
                    '{"x":"' + 'x' * rc.MAX_METADATA_BYTES + '"}',
                    '[' * 2000 + ']' * 2000):
            with self.subTest(length=len(raw)):
                (self.repo / "package.json").write_text(raw)
                scanner = rc.Scanner(self.fixture.terms)
                rc.license_audit(self.repo, scanner, self.manifest)
                self.assertEqual([f["kind"] for f in scanner.findings], ["dependency-ecosystem-manual-review"])

    def test_package_symlink_cannot_establish_dependency_free_status(self):
        outside = self.root / "outside.json"
        outside.write_text("{}")
        (self.repo / "package.json").symlink_to(outside)
        scanner = rc.Scanner(self.fixture.terms)
        rc.license_audit(self.repo, scanner, self.manifest)
        self.assertEqual([f["kind"] for f in scanner.findings], ["dependency-ecosystem-manual-review"])

    def test_package_license_must_match_detected_identifier(self):
        for declared in ("Apache-2.0", None, ["MIT"], {"type": "MIT"}, 1):
            with self.subTest(declared=declared):
                _, findings = self.license_audit({"license": declared})
                self.assertEqual([(f["kind"], f["path"]) for f in findings],
                                 [("license-metadata-mismatch", "package.json")])
        _, findings = self.license_audit({"dependencies": {"example": "1"}, "license": "Apache-2.0"})
        self.assertEqual({f["kind"] for f in findings},
                         {"license-metadata-mismatch", "dependency-ecosystem-manual-review"})

    def test_other_ecosystems_still_require_manual_review(self):
        for name in ("Cargo.toml", "go.mod", "pom.xml", "Gemfile", "composer.json", "build.gradle",
                     "build.gradle.kts", "Package.swift", "environment.yml", "Pipfile", "setup.py", "setup.cfg", "example.csproj"):
            with self.subTest(name=name):
                (self.repo / name).write_text("")
                _, findings = self.license_audit({})
                self.assertEqual([(f["kind"], f["path"]) for f in findings],
                                 [("dependency-ecosystem-manual-review", name)])
                (self.repo / name).unlink()

    def test_verify_tools_schema(self):
        for tools in (None, "node", {}, [1], ["node", "node"], ["x"] * 9,
                      ["../node"], ["/bin/node"], ["sub/node"], ["sub\\node"],
                      ["."], [".."], [""], ["node --version"], ["node\n"]):
            with self.subTest(tools=tools):
                (self.repo / "release-check.json").write_text(json.dumps({**self.manifest, "verify_tools": tools}))
                with self.assertRaises(rc.AuditError):
                    rc.manifest_for(self.repo, None)
        for tools in ([], ["node"], ["tool-1.0_+", "other"]):
            (self.repo / "release-check.json").write_text(json.dumps({**self.manifest, "verify_tools": tools}))
            self.assertEqual(rc.manifest_for(self.repo, None)["verify_tools"], tools)
        self.assertIn("verify_tools", rc.requirements_text().split("release-check.json keys: ")[1].splitlines()[0])

    def test_verify_tools_invalid_direct_manifest_does_not_run(self):
        with patch.object(rc, "command") as run:
            with self.assertRaises(rc.AuditError):
                rc.verify(self.repo, self.reports, rc.Scanner(self.fixture.terms),
                          {**self.manifest, "verify_tools": ["../escape"]}, 30)
        run.assert_not_called()

    def test_verify_tool_runs_without_inheriting_environment_or_path(self):
        tools = self.root / "caller-bin"
        tools.mkdir()
        fake = tools / "node"
        fake.write_text("#!/bin/sh\n[ \"$1\" = --version ] || exit 1\n"
                        "[ -z \"$CALLER_SECRET\" ] || exit 2\n"
                        "case \":$PATH:\" in *:\"" + str(tools) + "\":*) exit 3;; esac\n"
                        "[ -L \"${PATH%%:*}/node\" ] || exit 4\n"
                        "[ \"$HOME\" != \"" + str(self.root) + "\" ] || exit 5\n"
                        "[ \"$XDG_CONFIG_HOME\" = \"$HOME/config\" ] || exit 6\n"
                        "[ \"$XDG_CACHE_HOME\" = \"$HOME/cache\" ] || exit 7\n"
                        "[ \"$TMPDIR\" = \"$HOME/tmp\" ] || exit 8\n"
                        "command -v undeclared-fixture-tool >/dev/null && exit 9\n"
                        "echo v0.0-fixture\n")
        fake.chmod(0o700)
        extra = tools / "undeclared-fixture-tool"
        extra.write_text("#!/bin/sh\nexit 0\n")
        extra.chmod(0o700)
        manifest = {**self.manifest, "verify_tools": ["node"],
                    "checks": [{"role": "tests", "argv": ["node", "--version"]}]}
        scanner = rc.Scanner(self.fixture.terms)
        with patch.dict(os.environ, {"PATH": "tools" + os.pathsep * 2 + str(tools) + os.pathsep + os.environ["PATH"],
                                     "CALLER_SECRET": "fixture", "HOME": str(self.root)}), patch.object(rc.shutil, "which", side_effect=AssertionError("manual resolution required")):
            result = rc.verify(self.repo, self.reports, scanner, manifest, 30)
        self.assertEqual(result["status"], "pass", scanner.findings)
        self.assertEqual([c["exit_code"] for c in result["commands"]], [0, 0])
        self.assertEqual(result["commands"][-1]["output_fingerprint"], rc.fingerprint(b"v0.0-fixture\n"))

    def test_missing_verify_tool_blocks_before_commands(self):
        scanner = rc.Scanner(self.fixture.terms)
        with patch.object(rc, "command") as run:
            result = rc.verify(self.repo, self.reports, scanner,
                               {**self.manifest, "verify_tools": ["missing-fixture-tool"]}, 30)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["commands"], [])
        self.assertEqual([(f["kind"], f["category"], f["path"]) for f in scanner.findings],
                         [("verify-tool-missing", "quality", "release-check.json")])
        run.assert_not_called()

    def test_verify_tool_must_be_regular_and_executable(self):
        tools = self.root / "caller-bin"
        tools.mkdir()
        candidate = tools / "node"
        for kind in ("directory", "plain", "broken"):
            with self.subTest(kind=kind):
                if kind == "directory":
                    candidate.mkdir()
                elif kind == "plain":
                    candidate.write_text("fixture")
                else:
                    candidate.symlink_to(self.root / "missing")
                scanner = rc.Scanner(self.fixture.terms)
                with patch.dict(os.environ, {"PATH": str(tools)}), patch.object(rc, "command") as run:
                    result = rc.verify(self.repo, self.reports, scanner,
                                       {**self.manifest, "verify_tools": ["node"]}, 30)
                self.assertEqual(result["status"], "blocked")
                self.assertEqual([f["kind"] for f in scanner.findings], ["verify-tool-missing"])
                run.assert_not_called()
                if kind == "directory":
                    candidate.rmdir()
                else:
                    candidate.unlink()

    def test_verify_tool_cannot_replace_venv_symlink(self):
        outside = self.root / "node"
        outside.write_text("preserve")
        outside.chmod(0o700)

        for kind in ("symlink", "regular", "directory"):
            with self.subTest(kind=kind):
                def create_venv(argv, cwd, env, timeout):
                    self.assertEqual(argv[1:3], ["-m", "venv"])
                    bin_dir = Path(argv[-1]) / "bin"
                    bin_dir.mkdir(parents=True)
                    if kind == "symlink":
                        (bin_dir / "node").symlink_to(outside)
                    elif kind == "regular":
                        (bin_dir / "node").write_text("preserve")
                    else:
                        (bin_dir / "node").mkdir()
                    return 0, b""

                scanner = rc.Scanner(self.fixture.terms)
                with patch.dict(os.environ, {"PATH": str(self.root) + os.pathsep + os.environ["PATH"]}), patch.object(rc, "command", side_effect=create_venv) as run:
                    result = rc.verify(self.repo, self.reports, scanner, {**self.manifest, "verify_tools": ["node"]}, 30)
                self.assertEqual(result["status"], "blocked")
                self.assertEqual([f["kind"] for f in scanner.findings], ["verify-tool-missing"])
                self.assertEqual(run.call_count, 1)
                self.assertEqual(outside.read_text(), "preserve")

    def test_fix_bin_directory_symlink_cannot_escape(self):
        tool = self.root / "node"
        tool.write_text("#!/bin/sh\nexit 0\n")
        tool.chmod(0o700)
        escaped = self.root / "escaped-bin"
        escaped.mkdir()

        def create_venv(argv, cwd, env, timeout):
            self.assertEqual(argv[1:3], ["-m", "venv"])
            env_dir = Path(argv[-1])
            env_dir.mkdir()
            (env_dir / "bin").symlink_to(escaped, target_is_directory=True)
            return 0, b""

        scanner = rc.Scanner(self.fixture.terms)
        with patch.dict(os.environ, {"PATH": str(self.root) + os.pathsep + os.environ["PATH"]}), patch.object(rc, "command", side_effect=create_venv) as run:
            result = rc.verify(self.repo, self.reports, scanner, {**self.manifest, "verify_tools": ["node"]}, 30)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual([f["kind"] for f in scanner.findings], ["verify-tool-missing"])
        self.assertEqual(run.call_count, 1)
        self.assertEqual(list(escaped.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
