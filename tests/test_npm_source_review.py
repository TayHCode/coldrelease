import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

import release_check as rc


class NpmSourceReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.repo)], check=True)
        shutil.copyfile(Path(rc.__file__).with_name('LICENSE'), self.repo / 'LICENSE')
        self.manifest = {'exclude': [], 'approvals': []}
        self.package = {'name': 'testbed', 'version': '1.0.0', 'license': 'MIT',
                        'dependencies': {'example': '^1.0.0'}}
        self.lock = {'lockfileVersion': 3, 'name': 'testbed', 'version': '1.0.0',
                     'packages': {'': copy.deepcopy(self.package), 'node_modules/example': {
                         'version': '1.0.0', 'resolved': 'https://registry.npmjs.org/example/-/example-1.0.0.tgz',
                         'integrity': 'sha512-' + 'A' * 86 + '==', 'license': 'MIT'}}}
        self.write()

    def write(self):
        (self.repo / 'package.json').write_text(json.dumps(self.package))
        (self.repo / 'package-lock.json').write_text(json.dumps(self.lock))

    def audit(self, approvals=()):
        scanner = rc.Scanner(['PrivateTestbed'], approvals=approvals)
        result = rc.license_audit(self.repo, scanner, self.manifest)
        return result, scanner.findings

    def review(self):
        findings = self.audit()[1]
        self.assertEqual([f['kind'] for f in findings], ['npm-source-declarations-review'])
        return {**findings[0], 'reason': 'Reviewed exact source tree, declarations and all license obligations.'}

    def test_exact_review_required_and_blank_invalid(self):
        approval = self.review()
        self.assertNotEqual(approval['fingerprint'], rc.fingerprint(b''))
        self.assertFalse(self.audit()[1][0]['reviewed'])
        for reason in ('', ' ', None, 7, 'PrivateTestbed'):
            self.assertFalse(self.audit([{**approval, 'reason': reason}])[1][0]['reviewed'])
        result, findings = self.audit([approval])
        self.assertTrue(findings[0]['reviewed'])
        self.assertEqual(result['dependencies'], 'pass')
        for field in ('scope', 'kind', 'path', 'fingerprint'):
            self.assertFalse(self.audit([{**approval, field: 'wrong'}])[1][0]['reviewed'])

    def test_byte_and_tree_mutations_invalidate(self):
        approval = self.review()
        for name in ('package.json', 'package-lock.json'):
            path = self.repo / name
            raw = path.read_bytes()
            path.write_bytes(raw + b'\n')
            self.assertFalse(self.audit([approval])[1][0]['reviewed'])
            path.write_bytes(raw)
        (self.repo / 'app.js').write_text('export const value = 1;')
        self.assertFalse(self.audit([approval])[1][0]['reviewed'])

    def test_every_optional_entry_and_license_label_preserved(self):
        for label in ('GPL-3.0-only', 'Other/Proprietary License', 'LicenseRef-Unknown', None, 'LGPL-3.0-or-later'):
            with self.subTest(label=label):
                entry = self.lock['packages']['node_modules/example']
                entry['license'] = label
                entry['optional'] = True
                self.write()
                result, findings = self.audit()
                self.assertEqual(findings[0]['kind'], 'npm-source-declarations-review')
                self.assertFalse(findings[0]['reviewed'])
                inventory = rc.npm_source_declarations(self.repo, self.repo / 'package.json',
                                                       rc.npm_source_scope(self.repo, self.manifest))['inventory']
                self.assertEqual(len(inventory), 1)
                self.assertEqual(inventory[0]['license'], label)
                self.assertTrue(inventory[0]['optional'])
                approval = self.review()
                entry['os'] = ['other-platform']
                self.write()
                self.assertFalse(self.audit([approval])[1][0]['reviewed'])
                del entry['os']

    def test_unsupported_and_incomplete_fail_closed(self):
        original = copy.deepcopy(self.lock)
        changes = [lambda d: d.update(lockfileVersion=2),
                   lambda d: d['packages'].pop('node_modules/example'),
                   lambda d: d['packages'][''].update(dependencies={}),
                   lambda d: d['packages']['node_modules/example'].update(link=True),
                   lambda d: d['packages']['node_modules/example'].update(resolved='git+https://example.invalid/repo'),
                   lambda d: d['packages']['node_modules/example'].pop('integrity'),
                   lambda d: d['packages']['node_modules/example'].update(dependencies={'missing': '1'}),
                   lambda d: d['packages']['node_modules/example'].update(optionalDependencies={'missing': '1'})]
        for change in changes:
            self.lock = copy.deepcopy(original)
            change(self.lock)
            self.write()
            self.assertIn('dependency-ecosystem-manual-review', [f['kind'] for f in self.audit()[1]])
        for raw in ('{', '[]', '{"lockfileVersion":3,"lockfileVersion":3}', '{"x":NaN}'):
            (self.repo / 'package-lock.json').write_text(raw)
            self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')
        (self.repo / 'package-lock.json').unlink()
        self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')

    def test_local_workspace_and_lifecycle_manifests_fail_closed(self):
        for key, value in [('workspaces', ['pkg']), ('dependencies', {'example': 'file:../example'}),
                           ('dependencies', {'example': 'git+https://example.invalid/pkg'}),
                           ('dependencies', {'example': 'workspace:*'}), ('scripts', {'prepare': 'node build.js'})]:
            original = copy.deepcopy(self.package)
            self.package[key] = value
            self.lock['packages'][''] = copy.deepcopy(self.package)
            self.write()
            self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')
            self.package = original

    def test_source_approval_never_clears_installed_or_binary_payload(self):
        approval = self.review()
        for name in ('node_modules/example/index.js', 'payload.node', 'payload.zip', 'dist/bundle.js', 'payload'):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'\x7fELF\x00testbed')
            findings = self.audit([approval])[1]
            self.assertTrue(any(f['kind'] == 'dependency-ecosystem-manual-review' and not f['reviewed'] for f in findings))
            path.unlink()
            while path.parent != self.repo:
                path = path.parent
                path.rmdir()

    def test_old_empty_hash_finding_remains_unapprovable(self):
        scanner = rc.Scanner([])
        hit = scanner.add('tree', 'license', 'dependency-ecosystem-manual-review', 'package.json')
        scanner = rc.Scanner([], approvals=[{**hit, 'reason': 'Reviewed'}])
        self.assertFalse(scanner.add('tree', 'license', hit['kind'], 'package.json')['reviewed'])

    def test_lock_entry_mutations_and_overrides_invalidate(self):
        approval = self.review()
        original = copy.deepcopy(self.lock)
        for field, value in [('version', '1.0.1'), ('license', 'GPL-3.0-only'),
                             ('integrity', 'sha512-' + 'B' * 86 + '=='), ('dev', True),
                             ('optional', True), ('cpu', ['arm64'])]:
            self.lock = copy.deepcopy(original)
            self.lock['packages']['node_modules/example'][field] = value
            self.write()
            self.assertFalse(self.audit([approval])[1][0]['reviewed'])
        self.lock = original
        self.package['overrides'] = {'example': '1.0.0'}
        self.write()
        self.assertFalse(self.audit([approval])[1][0]['reviewed'])

    def test_optional_peer_absence_recorded_and_required_peer_missing_blocks(self):
        entry = self.lock['packages']['node_modules/example']
        entry['peerDependencies'] = {'absent': '*'}
        entry['peerDependenciesMeta'] = {'absent': {'optional': True}}
        self.write()
        self.review()
        evidence = rc.npm_source_declarations(self.repo, self.repo / 'package.json', {})
        self.assertEqual(evidence['edges'][-1], {'from': 'node_modules/example', 'field': 'peerDependencies',
                                              'name': 'absent', 'spec': '*', 'target': None, 'optional_peer': True})
        entry['peerDependenciesMeta']['absent']['optional'] = False
        self.write()
        self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')

    def test_nested_resolution_and_disconnected_optional_inventory(self):
        entries = self.lock['packages']
        entries['node_modules/example']['dependencies'] = {'child': '1'}
        entries['node_modules/example/node_modules/child'] = copy.deepcopy(entries['node_modules/example'])
        del entries['node_modules/example/node_modules/child']['dependencies']
        entries['node_modules/platform'] = {**entries['node_modules/example/node_modules/child'], 'optional': True, 'os': ['other']}
        self.write()
        self.review()
        evidence = rc.npm_source_declarations(self.repo, self.repo / 'package.json', {})
        self.assertEqual(len(evidence['inventory']), 3)
        self.assertEqual(evidence['edges'][-1]['target'], 'node_modules/example/node_modules/child')

    def test_policy_scope_and_manifest_changes_invalidate_but_approvals_do_not(self):
        manifest_file = self.repo / 'release-check.json'
        manifest_file.write_text(json.dumps(self.manifest))
        approval = self.review()
        manifest_file.write_text(json.dumps({**self.manifest, 'approvals': [approval]}))
        self.assertTrue(self.audit([approval])[1][0]['reviewed'])
        self.manifest['exclude'] = ['other']
        self.assertFalse(self.audit([approval])[1][0]['reviewed'])
        self.manifest['exclude'] = []
        manifest_file.write_text(json.dumps({**self.manifest, 'exclude': ['other']}))
        self.assertFalse(self.audit([approval])[1][0]['reviewed'])

    def test_symlinks_duplicate_manifest_and_other_locks_block(self):
        for name in ('package.json', 'package-lock.json'):
            path = self.repo / name
            raw = path.read_bytes()
            outside = self.repo.parent / (self.repo.name + '-outside')
            outside.write_bytes(raw)
            self.addCleanup(outside.unlink, missing_ok=True)
            path.unlink()
            path.symlink_to(outside)
            self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')
            path.unlink()
            path.write_bytes(raw)
        for name in ('yarn.lock', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'bun.lockb'):
            path = self.repo / name
            path.write_text('{}')
            self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')
            path.unlink()
        (self.repo / 'package.json').write_text('{"dependencies":{},"dependencies":{}}')
        self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')

    def test_private_metadata_never_enters_report(self):
        self.package['description'] = 'PrivateTestbed'
        self.lock['packages']['node_modules/example']['funding'] = 'PrivateTestbed'
        self.write()
        result, findings = self.audit()
        self.assertEqual(findings[0]['kind'], 'npm-source-declarations-review')
        self.assertNotIn('PrivateTestbed', json.dumps([result, findings]))

    def test_scope_rejects_unknown_binary_even_without_extension(self):
        (self.repo / 'payload').write_bytes(b'\xff\xfe\x00\x01')
        self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')

    def test_orphan_lock_and_missing_tracked_manifest_stay_incomplete(self):
        (self.repo / 'package.json').unlink()
        findings = self.audit()[1]
        self.assertEqual(findings[0]['kind'], 'dependency-ecosystem-manual-review')
        self.assertFalse(findings[0]['reviewed'])
        self.write()
        subprocess.run(['git', '-C', str(self.repo), 'add', 'package.json'], check=True)
        (self.repo / 'package.json').unlink()
        self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')

    def test_new_review_cannot_clear_other_ecosystem_or_attribution_findings(self):
        (self.repo / 'Cargo.toml').write_text('')
        findings = self.audit()[1]
        approval = {**next(f for f in findings if f['kind'] == 'npm-source-declarations-review'), 'reason': 'Reviewed source.'}
        findings = self.audit([approval])[1]
        self.assertTrue(next(f for f in findings if f['kind'] == 'npm-source-declarations-review')['reviewed'])
        self.assertFalse(next(f for f in findings if f['path'] == 'Cargo.toml')['reviewed'])

    def test_malformed_empty_dependency_map_is_not_dependency_free(self):
        (self.repo / 'package-lock.json').unlink()
        for value in ([], None, '', False):
            self.package['dependencies'] = value
            (self.repo / 'package.json').write_text(json.dumps(self.package))
            self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')

    def test_outcome_blocks_unreviewed_labels_and_binary_scope(self):
        for label in ('GPL-3.0-only', 'Other/Proprietary License', 'LicenseRef-Unknown', None):
            self.lock['packages']['node_modules/example']['license'] = label
            self.write()
            licensing, findings = self.audit()
            report = {'license': licensing, 'findings': findings, 'verification': {'status': 'pass'},
                      'stats': {'tree_files': 3, 'history_commits': 1}}
            self.assertEqual(rc.outcome(report)['outcome'], 'FAIL')
            approval = {**findings[0], 'reason': 'Reviewed this exact source distribution and retained notices.'}
            report['license'], report['findings'] = self.audit([approval])
            self.assertEqual(rc.outcome(report)['outcome'], 'PASS')
            (self.repo / 'payload.node').write_bytes(b'\x7fELF\0testbed')
            report['license'], report['findings'] = self.audit([approval])
            self.assertEqual(rc.outcome(report)['outcome'], 'INCOMPLETE')
            (self.repo / 'payload.node').unlink()

    def test_oversized_lock_and_wrong_top_level_identity_block(self):
        self.lock['name'] = 'different'
        self.write()
        self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')
        (self.repo / 'package-lock.json').write_bytes(b' ' * (rc.MAX_METADATA_BYTES + 1))
        self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')

    def test_permission_change_invalidates_source_scope(self):
        approval = self.review()
        (self.repo / 'package.json').chmod(0o700)
        self.assertFalse(self.audit([approval])[1][0]['reviewed'])

    def set_modes(self, file_mode, dir_mode):
        for root, dirs, files in os.walk(self.repo):
            dirs[:] = [d for d in dirs if d != '.git']
            for name in files:
                (Path(root) / name).chmod(file_mode)
            Path(root).chmod(dir_mode)

    def legacy_review(self):
        review = self.review()
        scope = rc.npm_source_scope(self.repo, self.manifest)
        evidence = rc.npm_source_declarations(self.repo, self.repo / 'package.json', scope)
        files = [{**entry, 'mode': stat.S_IMODE((self.repo / entry['path']).lstat().st_mode)} for entry in scope['files']]
        evidence['distribution_scope'] = {**scope, 'files': files}
        return {**review, 'fingerprint': rc.fingerprint(rc.canonical_json(evidence))}

    def test_review_is_independent_of_umask_modes(self):
        (self.repo / 'src').mkdir()
        (self.repo / 'src' / 'app.js').write_text('export const value = 1;')
        for made, checked in (((0o600, 0o700), (0o664, 0o775)), ((0o664, 0o775), (0o600, 0o700))):
            with self.subTest(made=made, checked=checked):
                self.set_modes(*made)
                approval = self.review()
                self.set_modes(*checked)
                result, findings = self.audit([approval])
                self.assertTrue(findings[0]['reviewed'])
                self.assertEqual(result['dependencies'], 'pass')

    def test_executable_bit_flip_invalidates_review_under_any_umask(self):
        for file_mode, flipped in ((0o600, 0o700), (0o664, 0o775), (0o644, 0o755)):
            with self.subTest(file_mode=file_mode):
                self.set_modes(file_mode, 0o755)
                approval = self.review()
                (self.repo / 'package.json').chmod(flipped)
                self.assertFalse(self.audit([approval])[1][0]['reviewed'])

    def test_legacy_full_mode_review_passes_on_its_original_modes_only(self):
        self.set_modes(0o600, 0o700)
        approval = self.legacy_review()
        self.assertNotEqual(approval['fingerprint'], self.review()['fingerprint'])
        result, findings = self.audit([approval])
        self.assertTrue(findings[0]['reviewed'])
        self.assertEqual(result['dependencies'], 'pass')
        self.set_modes(0o664, 0o775)
        self.assertFalse(self.audit([approval])[1][0]['reviewed'])
        self.set_modes(0o600, 0o700)
        (self.repo / 'package.json').chmod(0o700)
        self.assertFalse(self.audit([approval])[1][0]['reviewed'])

    def upgrade_for(self, approval):
        scanner = rc.Scanner(['PrivateTestbed'], approvals=[approval])
        rc.license_audit(self.repo, scanner, self.manifest)
        return scanner.fingerprint_upgrades

    def test_legacy_matched_review_lists_the_new_fingerprint(self):
        self.set_modes(0o600, 0o700)
        approval = self.legacy_review()
        new = self.review()['fingerprint']
        self.assertEqual(self.upgrade_for(approval), [{
            'kind': 'npm-source-declarations-review', 'path': 'package.json',
            'legacy_fingerprint': approval['fingerprint'], 'fingerprint': new}])

    def test_new_fingerprint_written_into_manifest_passes_under_any_umask(self):
        self.set_modes(0o600, 0o700)
        legacy = self.legacy_review()
        upgraded = {**legacy, 'fingerprint': self.upgrade_for(legacy)[0]['fingerprint']}
        for modes in ((0o600, 0o700), (0o664, 0o775)):
            with self.subTest(modes=modes):
                self.set_modes(*modes)
                scanner = rc.Scanner(['PrivateTestbed'], approvals=[upgraded])
                result = rc.license_audit(self.repo, scanner, self.manifest)
                self.assertTrue(scanner.findings[0]['reviewed'])
                self.assertEqual(result['dependencies'], 'pass')
                self.assertEqual(scanner.fingerprint_upgrades, [])

    def test_new_fingerprint_review_and_unreviewed_finding_list_no_upgrade(self):
        self.assertEqual(self.upgrade_for(self.review()), [])
        scanner = rc.Scanner(['PrivateTestbed'])
        rc.license_audit(self.repo, scanner, self.manifest)
        self.assertEqual(scanner.fingerprint_upgrades, [])

    def test_report_and_hint_carry_the_upgrade(self):
        self.manifest = {**self.manifest, 'quickstart': [], 'checks': []}
        self.set_modes(0o600, 0o700)
        approval = self.legacy_review()
        subprocess.run(['git', '-C', str(self.repo), 'add', '-A'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'user.name=t', '-c', ('user.email=t@ex' + 'ample.com'),
                        'commit', '-qm', 'testbed'], check=True)
        with tempfile.TemporaryDirectory() as reports:
            report = rc.audit(self.repo, ['PrivateTestbed'], {**self.manifest, 'approvals': [approval]}, [], False, Path(reports), 10)
        self.assertEqual([u['legacy_fingerprint'] for u in report['fingerprint_upgrades']], [approval['fingerprint']])
        hint = rc.fingerprint_upgrade_hint([report, report])
        self.assertTrue(hint.startswith('1 source review(s) matched only a legacy fingerprint'))
        self.assertIn('fingerprint_upgrades', hint)
        self.assertIsNone(rc.fingerprint_upgrade_hint([{}]))

    def test_invalid_root_identity_and_package_paths_block(self):
        for key, value in [('name', None), ('version', []), ('name', '../outside')]:
            original = self.package[key]
            self.package[key] = value
            self.lock[key] = value
            self.lock['packages'][''][key] = value
            self.write()
            self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')
            self.package[key] = self.lock[key] = self.lock['packages'][''][key] = original
        self.lock['packages']['node_modules/..'] = self.lock['packages'].pop('node_modules/example')
        self.write()
        self.assertEqual(self.audit()[1][0]['kind'], 'dependency-ecosystem-manual-review')
