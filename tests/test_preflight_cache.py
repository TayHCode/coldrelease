from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import release_check as rc
import release_workflow as workflow
import test_release_check as fixtures


class PreflightCacheTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.repo = self.fixture.repo
        self.manifest = self.fixture.manifest
        self.terms = self.fixture.terms
        self.cache_home = self.fixture.root / 'cache'
        environment = patch.dict(os.environ, {'XDG_CACHE_HOME': str(self.cache_home)})
        environment.start()
        self.addCleanup(environment.stop)

    def preflight(self, *, cached=True, **kwargs):
        return workflow.preflight(self.repo, self.manifest, self.terms, [], use_cache=cached, **kwargs)

    def cli(self, *flags):
        output = io.StringIO()
        with redirect_stdout(output):
            code = rc.main(['preflight', str(self.repo), '--run', 'cache-test',
                            '--denylist', str(self.fixture.denylist), *flags])
        return code, json.loads(output.getvalue())

    def test_cached_uncached_pass_and_fail_are_identical(self):
        expected = self.preflight(cached=False)
        self.assertEqual(expected['outcome'], 'PASS')
        self.assertEqual(self.preflight(), expected)
        with patch.object(rc, 'license_audit', side_effect=AssertionError('cache miss')):
            self.assertEqual(self.preflight(), expected)
        (self.repo / 'LICENSE').write_text('Undecided license')
        expected = self.preflight(cached=False)
        self.assertEqual(expected['outcome'], 'FAIL')
        self.assertEqual(self.preflight(), expected)
        with patch.object(rc, 'license_audit', side_effect=AssertionError('cache miss')):
            self.assertEqual(self.preflight(), expected)

    def assert_miss(self, **kwargs):
        with patch.object(rc, 'license_audit', wraps=rc.license_audit) as audit:
            result = self.preflight(**kwargs)
        self.assertEqual(audit.call_count, 1)
        self.assertEqual(result, self.preflight(cached=False, **kwargs))
        return result

    def test_content_change_invalidates_even_with_same_size_and_mtime(self):
        self.preflight()
        path = self.repo / 'README.md'
        original = path.stat()
        path.write_text(path.read_text().replace('limitations', 'constraints'))
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        self.assertEqual(path.stat().st_size, original.st_size)
        result = self.assert_miss()
        self.assertIn('missing-limitations', [f['kind'] for f in result['findings']])

    def test_raw_content_invalidates_despite_git_eol_normalization(self):
        (self.repo / '.gitattributes').write_text('*.md text eol=lf\n')
        self.fixture.commit('Normalize text')
        self.preflight()
        path = self.repo / 'README.md'
        path.write_bytes(path.read_bytes().replace(b'\n', b'\r\n'))
        self.assert_miss()

    def test_denylist_and_private_repo_changes_invalidate(self):
        self.preflight()
        self.terms.append('NewPrivateTerm')
        self.assert_miss()
        with patch.object(rc, 'license_audit', wraps=rc.license_audit) as audit:
            workflow.preflight(self.repo, self.manifest, self.terms, ['owner/private'], use_cache=True)
        self.assertEqual(audit.call_count, 1)

    def test_policy_and_checker_version_changes_invalidate(self):
        self.preflight()
        self.manifest['approvals'].append({'scope': 'tree', 'kind': 'missing-document',
                                           'path': 'SECURITY.md', 'fingerprint': 'synthetic'})
        self.assert_miss()
        with patch.object(rc, 'VERSION', 'new-checker-version'):
            self.assert_miss()

    def test_checker_code_change_invalidates(self):
        checker = self.fixture.root / 'checker.py'
        checker.write_bytes(Path(rc.__file__).read_bytes())
        with patch.object(rc, '__file__', str(checker)):
            self.preflight()
            checker.write_bytes(checker.read_bytes() + b'\n# Changed checker\n')
            self.assert_miss()

    def test_file_mode_and_selection_changes_invalidate(self):
        self.preflight()
        path = self.repo / 'README.md'
        path.chmod(path.stat().st_mode | 0o100)
        self.assert_miss()
        paths = workflow.proposed_paths(self.repo, self.manifest)
        result = self.assert_miss(paths=[p for p in paths if p != 'SECURITY.md'])
        self.assertIn('missing-document', [f['kind'] for f in result['findings']])

    def test_cli_no_cache_and_raw_denylist_and_manifest_changes(self):
        expected = self.cli('--no-cache')
        self.assertEqual(self.cli(), expected)
        with patch.object(rc, 'license_audit', side_effect=AssertionError('cache miss')):
            self.assertEqual(self.cli(), expected)
        for path in (self.fixture.denylist, self.repo / 'release-check.json'):
            path.write_bytes(path.read_bytes() + b'\n')
            with patch.object(rc, 'license_audit', wraps=rc.license_audit) as audit:
                self.assertEqual(self.cli(), expected)
            self.assertEqual(audit.call_count, 1)
        with patch.object(rc, 'license_audit', wraps=rc.license_audit) as audit:
            self.assertEqual(self.cli('--no-cache'), expected)
        self.assertEqual(audit.call_count, 1)

    def test_command_availability_is_rechecked_on_cache_hit(self):
        self.manifest['checks'].append({'role': 'lint', 'argv': ['synthetic-linter']})
        with patch.object(workflow.shutil, 'which', return_value='/usr/bin/tool'):
            self.preflight()
        with patch.object(rc, 'license_audit', side_effect=AssertionError('cache miss')):
            with patch.object(workflow.shutil, 'which', return_value=None):
                with self.assertRaisesRegex(rc.AuditError, 'command-missing'):
                    self.preflight()

    def test_corrupt_or_unavailable_cache_reruns_checks(self):
        expected = self.preflight()
        entry = next(self.cache_home.rglob('*.json'))
        for contents in ('invalid JSON', '{}', '{"data": null}', entry.read_text().replace('"status":"pass"', '"status":"blocked"')):
            entry.write_text(contents)
            self.assertEqual(self.assert_miss(), expected)
        entry.unlink()
        entry.parent.rmdir()
        entry.parent.write_text('not a directory')
        self.assertEqual(self.assert_miss(), expected)

    def test_cache_inside_source_is_disabled_and_never_exported(self):
        other = self.fixture.root / 'other-repo'
        rc.git(self.fixture.root, 'init', '-q', str(other))
        for repository in (self.repo, other):
            with patch.dict(os.environ, {'XDG_CACHE_HOME': str(repository / 'cache')}):
                with patch.object(workflow, 'preflight_cache_key', side_effect=AssertionError('cache used')):
                    self.assertEqual(self.preflight()['outcome'], 'PASS')
            self.assertFalse((repository / 'cache').exists())
        self.preflight()
        entry = next(self.cache_home.rglob('*.json'))
        self.assertEqual(entry.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('HiddenPerson', entry.read_text())
        target = self.fixture.root / 'export'
        rc.copy_tree(self.repo, target, self.manifest, rc.Scanner(self.terms))
        self.assertFalse((target / 'cache').exists())
        self.assertEqual(rc.git(target, 'rev-list', '--count', 'HEAD').strip(), b'1')

    def test_binary_bun_conversion_is_never_cached(self):
        (self.repo / 'bun.lockb').write_bytes(b'not a real lockfile')
        self.fixture.commit('Binary lock fixture')
        with patch.object(workflow, 'preflight_cache_key', side_effect=AssertionError('cache used')):
            self.preflight()
            self.assert_miss()

    def test_batch_staging_preserves_every_literal_filename_and_empty_export(self):
        names = ['space name.txt', 'line\nbreak.txt', ':(glob)*.txt', '-option.txt']
        names += [f'file-{number}.txt' for number in range(250)]
        for name in names:
            (self.repo / name).write_text(name)
        self.fixture.git('--literal-pathspecs', 'add', '--', *names)
        self.fixture.git('commit', '-q', '-m', 'Literal filenames')
        target = self.fixture.root / 'batch-export'
        rc.copy_tree(self.repo, target, self.manifest, rc.Scanner(self.terms))
        exported = {os.fsdecode(path) for path in rc.git(target, 'ls-tree', '-r', '--name-only', '-z', 'HEAD').split(b'\0') if path}
        self.assertTrue(set(names).issubset(exported))
        for name in names:
            self.assertEqual((target / name).read_text(), name)
        empty = self.fixture.root / 'empty-export'
        rc.copy_tree(self.repo, empty, self.manifest, rc.Scanner(self.terms), allowlist=[])
        self.assertEqual(rc.git(empty, 'ls-tree', '-r', '--name-only', 'HEAD'), b'')
        self.assertEqual(rc.git(empty, 'rev-list', '--count', 'HEAD').strip(), b'1')

    def test_runtime_encoding_change_invalidates(self):
        self.preflight()
        with patch.object(workflow.locale, 'getpreferredencoding', return_value='ascii'):
            self.assert_miss()
