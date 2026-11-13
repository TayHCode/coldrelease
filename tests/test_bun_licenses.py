import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_check as rc


class BunLicenseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        shutil.copyfile(Path(rc.__file__).with_name('LICENSE'), self.repo / 'LICENSE')
        self.package = {'name': 'testbed', 'dependencies': {'example': '^1.0.0'}}
        self.integrity = 'sha512-' + 'A' * 86 + '=='
        self.lock = {'lockfileVersion': 1, 'configVersion': 1,
                     'workspaces': {'': copy.deepcopy(self.package)},
                     'packages': {'example': ['example@1.2.3', '', {}, self.integrity]}}
        self.manifest = {'exclude': [], 'approvals': [], 'dependency_licenses': {}}
        self.document('example', '1.2.3')
        self.write()

    def document(self, name, version, text=None):
        relative = f'licenses/{name}/{version}/LICENSE'
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        raw = (text.encode() if text is not None else (self.repo / 'LICENSE').read_bytes())
        path.write_bytes(raw)
        self.manifest['dependency_licenses'][f'npm:{name}@{version}'] = {
            'version': version, 'spdx': 'MIT', 'integrity': self.integrity,
            'path': relative, 'sha256': rc.sha256(raw)}

    def write(self):
        (self.repo / 'package.json').write_text(json.dumps(self.package))
        (self.repo / 'bun.lock').write_text(json.dumps(self.lock))

    def audit(self, approvals=()):
        scanner = rc.Scanner(['PrivateTestbed'], approvals=approvals)
        result = rc.license_audit(self.repo, scanner, self.manifest)
        return result, scanner.findings

    def inventory(self):
        evidence = rc.bun_source_declarations(self.repo, self.repo / 'package.json',
                                               rc.npm_source_scope(self.repo, self.manifest))
        self.assertIsNotNone(evidence)
        self.assertTrue(rc.source_license_documents(self.repo, evidence, self.manifest, required=True))
        return evidence['inventory']

    def approval(self):
        findings = self.audit()[1]
        self.assertEqual([f['kind'] for f in findings], ['bun-source-declarations-review'])
        return {**findings[0], 'reason': 'Reviewed exact source, resolutions and retained license documents.'}

    def incomplete(self, approvals=()):
        result, findings = self.audit(approvals)
        self.assertEqual(result['dependencies'], 'not-verified')
        self.assertEqual([f['kind'] for f in findings], ['dependency-ecosystem-manual-review'])
        self.assertFalse(findings[0]['reviewed'])

    def test_exact_resolution_and_document_require_source_review(self):
        row, = self.inventory()
        self.assertEqual((row['version'], row['license_state']), ('1.2.3', 'accepted'))
        self.assertEqual(row['license_document']['sha256'], rc.sha256((self.repo / 'LICENSE').read_bytes()))
        self.assertEqual(self.audit()[0]['dependencies'], 'not-verified')
        approval = self.approval()
        self.assertEqual(self.audit([approval])[0]['dependencies'], 'pass')
        for reason in ('', ' ', None, 7, 'PrivateTestbed'):
            self.assertFalse(self.audit([{**approval, 'reason': reason}])[1][0]['reviewed'])

    def test_jsonc_and_supported_versions_preserve_strings_and_duplicates(self):
        self.lock['packages']['example'][2]['bin'] = {'tool': 'https://example.invalid/a, } /* literal */'}
        for version in (1, 2):
            for version_flag in (0, 1):
                self.lock.update(lockfileVersion=version, configVersion=version_flag)
                raw = json.dumps(self.lock)
                (self.repo / 'bun.lock').write_text('// comment\n' + raw[:-1] + ', /* comment */ }')
                self.approval()
                self.assertEqual(self.inventory()[0]['bin'], {'tool': 'https://example.invalid/a, } /* literal */'})
        for broken in (raw.replace('"lockfileVersion": 2', '"lockfileVersion": 2, "lockfileVersion": 1'),
                       raw.replace('"configVersion": 1', '"configVersion": NaN'), raw[:-1], '[]'):
            (self.repo / 'bun.lock').write_text(broken)
            self.incomplete()

    def test_invalid_versions_and_resolutions_fail_closed(self):
        for version in ('^1.2.3', 'latest', '1.2', '01.2.3', '1.2.3-01', 'github:user/repo', 'file:../pkg', '1.2.3/path'):
            self.lock['packages']['example'][0] = 'example@' + version
            self.write()
            self.incomplete()
        self.lock['packages']['example'][0] = 'other@1.2.3'
        self.write()
        self.incomplete()

    def test_invalid_shapes_missing_edges_and_unsupported_sources(self):
        original = copy.deepcopy(self.lock)
        changes = [lambda d: d.update(lockfileVersion=True), lambda d: d.update(lockfileVersion=99),
                   lambda d: d.update(configVersion=2), lambda d: d.update(packages=[]),
                   lambda d: d['packages'].clear(), lambda d: d['packages']['example'].__setitem__(3, 'invalid'),
                   lambda d: d['packages']['example'].__setitem__(1, 'https://other.invalid'),
                   lambda d: d['packages']['example'].__setitem__(2, {'dependencies': {'missing': '*'}}),
                   lambda d: d['packages']['example'].__setitem__(2, {'optionalPeers': ['undeclared']}),
                   lambda d: d['packages']['example'].__setitem__(2, {'unknown': True}),
                   lambda d: d['workspaces'].update(other={}), lambda d: d.update(patchedDependencies={}),
                   lambda d: d['workspaces']['']['dependencies'].clear()]
        for change in changes:
            self.lock = copy.deepcopy(original)
            change(self.lock)
            self.write()
            self.incomplete()

    def test_license_document_must_belong_to_the_audited_tree(self):
        entry = self.manifest['dependency_licenses']['npm:example@1.2.3']
        hidden = self.repo / '.git/licenses/example/LICENSE'
        hidden.parent.mkdir(parents=True)
        hidden.write_bytes((self.repo / entry['path']).read_bytes())
        entry['path'] = '.git/licenses/example/LICENSE'
        self.incomplete()

    def test_missing_stale_or_unsafe_document_evidence_stays_incomplete(self):
        key = 'npm:example@1.2.3'
        original = copy.deepcopy(self.manifest['dependency_licenses'][key])
        for field, value in [('version', '1.2.4'), ('integrity', 'wrong'), ('sha256', '0' * 64),
                             ('spdx', None), ('path', '../LICENSE'), ('path', '/LICENSE'), ('path', 'missing/LICENSE')]:
            self.manifest['dependency_licenses'][key] = {**original, field: value}
            self.incomplete()
        self.manifest['dependency_licenses'].clear()
        self.incomplete()
        self.lock['packages']['example'][2]['license'] = 'UNKNOWN'
        self.write()
        self.incomplete()
        self.document('example', '1.2.3')
        document = self.repo / original['path']
        document.unlink()
        document.symlink_to(self.repo / 'LICENSE')
        self.incomplete()

    def test_license_documents_do_not_hide_strong_or_unknown_assertions(self):
        for text, state in [('GNU GENERAL PUBLIC LICENSE\nVersion 3', 'strong'),
                            ('Custom unknown license obligations', 'unknown')]:
            self.document('example', '1.2.3', text)
            self.assertEqual(self.inventory()[0]['license_state'], state)
            self.assertFalse(self.audit()[1][0]['reviewed'])
        self.document('example', '1.2.3')
        self.lock['packages']['example'][2]['license'] = 'GPL-3.0-only'
        self.write()
        self.assertEqual(self.inventory()[0]['license_state'], 'strong')

    def test_busboy_streamsearch_copyright_header_preserves_full_grant_check(self):
        text = (self.repo / 'LICENSE').read_text()
        lines = text.splitlines()
        copyright_index = next(i for i, line in enumerate(lines) if line.startswith('Copyright'))
        lines[copyright_index] = 'Copyright Brian White. All rights reserved.'
        document = '\n'.join(lines)
        self.assertEqual(rc.licence_file_state(document), 'accepted')
        self.assertEqual(rc.licence_file_state(document + '\nGNU GENERAL PUBLIC LICENSE'), 'strong')
        self.assertEqual(rc.licence_file_state(document + '\nAn additional restriction applies.'), 'unknown')
        self.document('example', '1.2.3', document)
        self.assertEqual(self.inventory()[0]['license_state'], 'accepted')

    def test_mdx_documents_retain_unknown_and_restrictive_content(self):
        key = 'npm:example@1.2.3'
        document = self.repo / 'licenses/example/1.2.3/license.mdx'
        for text, expected in [((self.repo / 'LICENSE').read_text(), 'accepted'),
                               ('# License\n<Note>Unrecognized license terms.</Note>', 'unknown'),
                               ('# License\nGNU GENERAL PUBLIC LICENSE\nVersion 3', 'strong')]:
            raw = text.encode()
            document.write_bytes(raw)
            self.manifest['dependency_licenses'][key].update(path=document.relative_to(self.repo).as_posix(), sha256=rc.sha256(raw))
            self.assertEqual(self.inventory()[0]['license_state'], expected)
            result, findings = self.audit()
            self.assertEqual(result['npm_source_reviews'][0]['license_states'], {expected: 1})
            self.assertEqual(findings[0]['kind'], 'bun-source-declarations-review')
            self.assertFalse(findings[0]['reviewed'])

    def test_source_lock_document_and_policy_bytes_invalidate_approval(self):
        approval = self.approval()
        for name in ('package.json', 'bun.lock', 'LICENSE'):
            path = self.repo / name
            raw = path.read_bytes()
            path.write_bytes(raw + b'\n')
            self.assertFalse(self.audit([approval])[1][0]['reviewed'])
            path.write_bytes(raw)
        self.document('example', '1.2.3', (self.repo / 'LICENSE').read_text() + '\n')
        self.assertFalse(self.audit([approval])[1][0]['reviewed'])
        self.manifest['exclude'] = ['other']
        self.assertFalse(self.audit([approval])[1][0]['reviewed'])

    def test_scoped_nested_optional_packages_keep_every_exact_version(self):
        self.lock['packages']['example'][2] = {'dependencies': {'@scope/child': '^2'},
                                             'optionalDependencies': {'platform': '*'},
                                             'peerDependencies': {'absent': '*'}, 'optionalPeers': ['absent']}
        self.lock['packages']['example/@scope/child'] = ['@scope/child@2.3.4', '', {}, self.integrity]
        self.lock['packages']['platform'] = ['platform@3.0.0', '', {'os': 'other', 'cpu': 'arm64'}, self.integrity]
        self.document('@scope/child', '2.3.4')
        self.document('platform', '3.0.0')
        self.write()
        self.assertEqual([(r['path'], r['version']) for r in self.inventory()], [
            ('node_modules/example', '1.2.3'), ('node_modules/example/node_modules/@scope/child', '2.3.4'),
            ('node_modules/platform', '3.0.0')])
        self.approval()

    def test_two_versions_of_one_package_need_separate_document_bindings(self):
        self.lock['packages']['example'][2] = {'dependencies': {'example': '^2'}}
        self.lock['packages']['example/example'] = ['example@2.0.0', '', {}, self.integrity]
        self.write()
        self.incomplete()
        self.document('example', '2.0.0')
        self.assertEqual([row['version'] for row in self.inventory()], ['1.2.3', '2.0.0'])
        self.approval()

    def test_symlink_oversized_and_orphan_lockfiles_fail_closed(self):
        lock = self.repo / 'bun.lock'
        raw = lock.read_bytes()
        lock.unlink()
        lock.symlink_to(self.repo / 'LICENSE')
        self.incomplete()
        lock.unlink()
        lock.write_bytes(b' ' * (rc.MAX_METADATA_BYTES + 1))
        self.incomplete()
        lock.write_bytes(raw)
        (self.repo / 'package.json').unlink()
        self.assertEqual([f['kind'] for f in self.audit()[1]], ['dependency-ecosystem-manual-review'])

    def test_private_metadata_remains_fingerprinted_in_reports(self):
        self.lock['packages']['example'][2]['bin'] = {'tool': 'PrivateTestbed'}
        self.write()
        result, findings = self.audit()
        self.assertEqual(findings[0]['kind'], 'bun-source-declarations-review')
        self.assertNotIn('PrivateTestbed', json.dumps([result, findings]))

    def test_other_locks_or_installed_payload_cannot_use_source_approval(self):
        approval = self.approval()
        for name in ('package-lock.json', 'bun.lockb', 'yarn.lock', 'payload.node', 'node_modules/example/index.js'):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('{}')
            self.incomplete([approval])
            path.unlink()
            if name.startswith('node_modules'):
                path.parent.rmdir()
                path.parent.parent.rmdir()

    def test_npm_missing_labels_can_use_exact_busboy_and_streamsearch_documents(self):
        (self.repo / 'bun.lock').unlink()
        self.package['dependencies'] = {'busboy': '^1.6.0'}
        packages = {'': copy.deepcopy(self.package)}
        for name, version in [('busboy', '1.6.0'), ('streamsearch', '1.1.0')]:
            packages['node_modules/' + name] = {'version': version, 'integrity': self.integrity,
                'resolved': f'https://registry.npmjs.org/{name}/-/{name}-{version}.tgz'}
            self.document(name, version)
        packages['node_modules/busboy']['dependencies'] = {'streamsearch': '^1.1.0'}
        (self.repo / 'package.json').write_text(json.dumps(self.package))
        (self.repo / 'package-lock.json').write_text(json.dumps({'lockfileVersion': 3, 'name': 'testbed', 'packages': packages}))
        result, findings = self.audit()
        self.assertEqual(result['npm_source_reviews'][0]['license_states'], {'accepted': 2})
        self.assertEqual(findings[0]['kind'], 'npm-source-declarations-review')
        self.assertFalse(findings[0]['reviewed'])

    def test_binary_conversion_is_isolated_and_bound_to_original_bytes(self):
        text = (self.repo / 'bun.lock').read_bytes()
        (self.repo / 'bun.lock').unlink()
        binary = self.repo / 'bun.lockb'
        binary.write_bytes(b'testbed binary\0lock')
        real_run = subprocess.run

        def convert(argv, **kwargs):
            if argv[0] == 'git':
                return real_run(argv, **kwargs)
            directory = Path(kwargs['cwd'])
            self.assertNotEqual(directory, self.repo)
            self.assertEqual((directory / 'bun.lockb').read_bytes(), binary.read_bytes())
            self.assertEqual((directory / 'bunfig.toml').read_bytes(), b'')
            self.assertEqual(kwargs['env'], {'PATH': rc.os.defpath})
            for flag in ('--offline', '--ignore-scripts', '--lockfile-only', '--frozen-lockfile'):
                self.assertIn(flag, argv)
            (directory / 'bun.lock').write_bytes(text)
            return subprocess.CompletedProcess(argv, 0)

        with patch.object(rc.shutil, 'which', return_value='/usr/bin/bun'), patch.object(rc.subprocess, 'run', side_effect=convert):
            approval = self.approval()
            self.assertEqual(self.audit([approval])[0]['dependencies'], 'pass')
            binary.write_bytes(binary.read_bytes() + b'changed')
            self.assertFalse(self.audit([approval])[1][0]['reviewed'])
        self.assertEqual(sorted(p.name for p in self.repo.iterdir() if p.name.startswith('bun.')), ['bun.lockb'])

    def test_binary_converter_errors_and_missing_output_fail_closed(self):
        (self.repo / 'bun.lock').unlink()
        (self.repo / 'bun.lockb').write_bytes(b'bad\0binary')
        with patch.object(rc.shutil, 'which', return_value=None):
            self.incomplete()
        real_run = subprocess.run
        def converter(result=None, error=None):
            def run(argv, **kwargs):
                if argv[0] == 'git':
                    return real_run(argv, **kwargs)
                if error:
                    raise error
                return subprocess.CompletedProcess(argv, result)
            return run
        for error in (OSError('PrivateTestbed'), subprocess.TimeoutExpired('bun', 30)):
            with patch.object(rc.shutil, 'which', return_value='/usr/bin/bun'), patch.object(rc.subprocess, 'run', side_effect=converter(error=error)):
                self.incomplete()
        for code in (0, 1):
            with patch.object(rc.shutil, 'which', return_value='/usr/bin/bun'), patch.object(rc.subprocess, 'run', side_effect=converter(result=code)):
                self.incomplete()


if __name__ == '__main__':
    unittest.main()
