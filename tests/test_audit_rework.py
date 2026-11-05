"""Regressions from the independent audit, using offline fake distributions."""
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release_check as rc
import test_release_check as fixtures
from licence_fixtures import genuine

MIT = Path(rc.__file__).with_name('LICENSE').read_text()
GPL = 'GNU GENERAL PUBLIC LICENSE\nVersion 3\n'
GRANT = 'You may redistribute this program under the terms of the GNU General Public License version 3'

class ReworkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.info = self.root / 'fake_dependency-1.dist-info'
        self.info.mkdir()

    def installed(self, expression=None, label=None, classifiers=(), content=None,
                  filename='LICENSE', extra_headers=()):
        # Each case owns a complete installed inventory, including its removals.
        shutil.rmtree(self.info)
        self.info.mkdir()
        headers = ['Metadata-Version: 2.4', 'Name: fake_dependency', 'Version: 1']
        if expression is not None:
            headers.append('License-Expression: ' + expression)
        if label is not None:
            headers.append('License: ' + label)
        headers.extend('Classifier: ' + c for c in classifiers)
        headers.extend(extra_headers)
        (self.info / 'METADATA').write_text('\n'.join(headers) + '\n')
        records = [self.info.name + '/METADATA,,']
        if content is not None:
            (self.info / filename).parent.mkdir(parents=True, exist_ok=True)
            (self.info / filename).write_bytes(content.encode() if isinstance(content, str) else content)
            records.append(self.info.name + '/' + filename + ',,')
        (self.info / 'RECORD').write_text('\n'.join(records) + '\n')
        script = 'import sys\n' + rc.METADATA_SCRIPT.replace('m.distributions()', 'm.distributions(path=[sys.argv[1]])')
        result = subprocess.run([sys.executable, '-c', script, str(self.root)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def audit(self, raw, evidence=None):
        scanner = rc.Scanner(['SyntheticPrivateTerm'])
        result = rc.dependency_audit(raw, self.root, scanner, {'dependency_licenses': evidence or {}})
        return result, scanner.findings

    def dependency_cli(self, evidence=None, *, export=False, root_license=None):
        """Install only our fake dist-info in the real verification venv."""
        fixture = fixtures.AuditTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        if root_license is not None:
            (fixture.repo / 'LICENSE').write_bytes(root_license.encode() if isinstance(root_license, str) else root_license)
        source = 'fixtures/' + self.info.name
        shutil.copytree(self.info, fixture.repo / source)
        install = ("import pathlib, shutil, sysconfig; "
                   "shutil.copytree(" + repr(source) + ", "
                   "pathlib.Path(sysconfig.get_path('purelib')) / " + repr(self.info.name) + ")")
        argv = ['python', '-c', install]
        readme = fixture.repo / 'README.md'
        lines = readme.read_text().splitlines()
        lines[3] = shlex.join(argv)
        readme.write_text('\n'.join(lines) + '\n')
        manifest = {**fixture.manifest, 'quickstart': [{'file': 'README.md', 'line': 4, 'argv': argv}],
                    'dependency_licenses': evidence or {}}
        (fixture.repo / 'release-check.json').write_text(json.dumps(manifest))
        before = {p.relative_to(fixture.repo): p.read_bytes() for p in fixture.repo.rglob('*')
                  if p.is_file() and '.git' not in p.relative_to(fixture.repo).parts}
        process = subprocess.run(
            [sys.executable, rc.__file__, str(fixture.repo), '--denylist', str(fixture.denylist),
             '--reports', str(fixture.root / 'reports'), '--verify',
             *(['--export', str(fixture.root / 'export')] if export else [])],
            capture_output=True, text=True, timeout=60)
        code, out, err = process.returncode, process.stdout, process.stderr
        after = {p.relative_to(fixture.repo): p.read_bytes() for p in fixture.repo.rglob('*')
                 if p.is_file() and '.git' not in p.relative_to(fixture.repo).parts}
        self.assertEqual(after, before, 'Audit wrote to its source repository')
        self.assertNotIn('Traceback', out + err)
        report = json.loads(next((fixture.root / 'reports').rglob('report.json')).read_text())
        return code, report

    def test_v3_r2_cli_permissive_weak_and_unlabelled(self):
        cases = [({'expression': 'MIT'}, 0),
                 ({'label': 'Apache License, Version 2.0'}, 0),
                 ({'classifiers': ['License :: OSI Approved :: BSD License']}, 0),
                 ({'label': 'LGPL-3.0-or-later'}, 0),
                 ({'expression': 'MPL-2.0'}, 0),
                 ({'classifiers': ['License :: OSI Approved :: Eclipse Public License 2.0 (EPL-2.0)']}, 0),
                 ({'content': MIT}, 0),
                 ({'expression': 'GPL-3.0-only'}, 1),
                 ({'expression': 'AGPL-3.0-only'}, 1),
                 ({}, 1)]
        for metadata, expected_exit in cases:
            with self.subTest(metadata=metadata, expected_exit=expected_exit):
                (self.info / 'LICENSE').unlink(missing_ok=True)
                self.installed(**metadata)
                code, report = self.dependency_cli()
                self.assertEqual(code, expected_exit)
                self.assertEqual(report['ready'], expected_exit == 0)
                dependencies = report['verification']['dependencies']
                self.assertEqual(dependencies['blocked'], expected_exit)
                if metadata == {'content': MIT}:
                    self.assertEqual(dependencies['accepted_on_license_file'],
                                     ['@dependency/fake_dependency'])
                if expected_exit == 0:
                    self.assertEqual(report['findings'], [])

    def test_round_3_cli_standard_apache_is_ready(self):
        self.installed(label='Apache-2.0', content=genuine('Apache-2.0'))
        code, report = self.dependency_cli()
        self.assertEqual(code, 0)
        self.assertTrue(report['ready'])

    def test_round_3_cli_legacy_restriction_cannot_report_ready(self):
        self.installed(expression='MIT', label='Elastic License 2.0', content=MIT)
        code, report = self.dependency_cli()
        self.assertEqual(code, 1)
        self.assertFalse(report['ready'])

    def test_round_3_standard_full_texts_and_restrictions(self):
        for identifier in ('Apache-2.0', 'MPL-2.0', 'LGPL-2.1', 'LGPL-3.0', 'BSD-3-Clause'):
            text = genuine(identifier)
            for label in (None, identifier):
                with self.subTest(identifier=identifier, label=label):
                    self.assertEqual(self.audit(self.installed(label=label, content=text))[0]['blocked'], 0)
            for suffix in ('\nRedistribution of this software is prohibited.', '\nG.P.L.', '\nG-\nP-\nL'):
                with self.subTest(identifier=identifier, suffix=suffix):
                    self.assertEqual(self.audit(self.installed(label=identifier, content=text + suffix))[0]['blocked'], 1)

    def test_round_3_independent_restrictive_legacy_fields(self):
        for label in ('Elastic License 2.0', 'BUSL-1.1', 'CC-BY-NC-SA-4.0',
                      'All Rights Reserved', 'Internal use only', 'See https://example.invalid/terms'):
            for metadata in ({'expression': 'MIT'}, {'classifiers': ['License :: OSI Approved :: MIT License']}):
                with self.subTest(label=label, metadata=metadata):
                    self.assertEqual(self.audit(self.installed(label=label, content=MIT, **metadata))[0]['blocked'], 1)

    def test_round_3_digest_evidence_cannot_hide_proprietary_text(self):
        for text in ('All Rights Reserved', 'Internal use only',
                     'All rights reserved. Proprietary. No redistribution.',
                     genuine('BSD-3-Clause') + '\nRedistribution of this software is prohibited.'):
            with self.subTest(text=text[:40]):
                raw = self.installed(expression='MIT', content=text)
                evidence = {'fake-dependency': {'version': '1', 'spdx': 'MIT',
                                                'sha256': hashlib.sha256(text.encode()).hexdigest()}}
                self.assertEqual(self.audit(raw, evidence)[0]['blocked'], 1)

    def test_round_3_collector_retains_second_unknown_or_gpl_file(self):
        texts = ('G-\nP-\nL', 'G.P.L.', 'GРL', 'GNU GENERAL PUBLIC LICENSE'.encode('cp037'), 'see URL')
        for filename in ('LICENSE.extra', 'GPL-3.0.txt', 'licenses/GPL-3.0.txt', 'COPYRIGHT'):
            for content in texts:
                with self.subTest(filename=filename, content=content):
                    self.installed(expression='MIT', content=MIT)
                    path = self.info / filename
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content if isinstance(content, bytes) else content.encode())
                    with (self.info / 'RECORD').open('a') as record:
                        record.write(self.info.name + '/' + filename + ',,\n')
                    script = 'import sys\n' + rc.METADATA_SCRIPT.replace('m.distributions()', 'm.distributions(path=[sys.argv[1]])')
                    raw = subprocess.run([sys.executable, '-c', script, str(self.root)],
                                         check=True, capture_output=True, timeout=5).stdout
                    self.assertIn(filename, [f['path'].split('.dist-info/', 1)[-1] for f in json.loads(raw)[0]['license_files']])
                    self.assertEqual(self.audit(raw)[0]['blocked'], 1)
                    path.unlink()

    def test_round_3_common_labels_and_classifiers(self):
        for label in ('The MIT License (MIT)', 'Apache 2.0', 'Expat', 'MIT/X11',
                      'New BSD License', 'Public Domain', 'CC0 1.0 Universal'):
            with self.subTest(label=label):
                self.assertEqual(self.audit(self.installed(label=label))[0]['blocked'], 0)
        for ending in ('Eclipse Public License 2.0 (EPL-2.0)', 'The Unlicense (Unlicense)',
                       'MIT No Attribution License (MIT-0)', 'Boost Software License 1.0 (BSL-1.0)',
                       'CC0 1.0 Universal (CC0 1.0) Public Domain Dedication'):
            with self.subTest(classifier=ending):
                self.assertEqual(self.audit(self.installed(classifiers=['License :: OSI Approved :: ' + ending]))[0]['blocked'], 0)

    def test_round_3_cli_standard_weak_texts_are_ready(self):
        for identifier in ('MPL-2.0', 'LGPL-2.1', 'LGPL-3.0'):
            with self.subTest(identifier=identifier):
                self.installed(content=genuine(identifier))
                code, report = self.dependency_cli()
                self.assertEqual(code, 0)
                self.assertTrue(report['ready'])

    def test_round_3_cli_second_unknown_file_cannot_report_ready(self):
        self.installed(expression='MIT', content=MIT)
        (self.info / 'COPYRIGHT').write_text('see URL')
        with (self.info / 'RECORD').open('a') as record:
            record.write(self.info.name + '/COPYRIGHT,,\n')
        code, report = self.dependency_cli()
        self.assertEqual(code, 1)
        self.assertFalse(report['ready'])

    def test_finding_1_placeholder_never_erases_strong_label(self):
        for placeholder in ('NOASSERTION', 'UNKNOWN', 'NONE', ' unknown '):
            for strong in ('GPL-3.0-only', 'AGPL-3.0-only'):
                for content in ('', MIT):
                    with self.subTest(placeholder=placeholder, strong=strong, empty=not content):
                        self.assertEqual(self.audit(self.installed(expression=placeholder, label=strong, content=content))[0]['blocked'], 1)

    def test_finding_1_cli_placeholder_cannot_report_ready(self):
        self.installed(expression='NOASSERTION', label='GPL-3.0-only', content='')
        code, report = self.dependency_cli()
        self.assertEqual(code, 1)
        self.assertFalse(report['ready'])
        self.assertEqual(report['verification']['dependencies']['blocked'], 1)
        self.assertTrue(any(f['kind'] == 'dependency-license-review' and not f['reviewed']
                            for f in report['findings']))

    def test_finding_2_whole_label_only(self):
        labels = ('Proprietary, not Mozilla Public License',
                  'Commercial licence replacing the Eclipse Public License',
                  'Lesser General Public License for non-commercial use only; commercial licence required',
                  'SSPL (successor to GNU Lesser General Public License)',
                  'Not MIT License. Permission is hereby granted only to paying customers')
        for label in labels:
            for source in ('expression', 'label'):
                with self.subTest(label=label, source=source):
                    self.assertEqual(self.audit(self.installed(**{source: label}))[0]['blocked'], 1)

    def test_finding_2_exception_branches_require_complete_identifiers(self):
        for label in ('Custom terms WITH LLVM-exception OR MIT',
                      'Proprietary terms WITH LLVM-exception OR MIT',
                      'GPLv3 (commercial use only) OR MIT',
                      'MIT WITH LLVM-exception additional restrictions',
                      'MIT OR Bespoke Mozilla Public License',
                      'Not MIT License. Permission is hereby granted only to paying customers'):
            with self.subTest(label=label):
                self.assertEqual(self.audit(self.installed(expression=label))[0]['blocked'], 1)

    def test_finding_2_cli_proprietary_label_blocks(self):
        self.installed(label='Proprietary, not Mozilla Public License')
        code, report = self.dependency_cli()
        self.assertEqual(code, 1)
        self.assertFalse(report['ready'])
        self.assertEqual(report['verification']['dependencies']['blocked'], 1)

    def test_finding_3_non_licence_files_block(self):
        cases = [('LICENSE', ''), ('LICENSE', '\n \n'), ('LICENSE', 'TODO'),
                 ('LICENSE', bytes(range(32))), ('license.py', MIT),
                 ('license_utils.py', 'pass'), ('copying.py', 'pass'),
                 ('license.html', '<p>MIT License</p>'),
                 ('LICENSE', 'All rights reserved. Proprietary. No redistribution.'),
                 ('LICENSE', 'Server Side Public License')]
        for filename, content in cases:
            with self.subTest(filename=filename, content=repr(content)[:30]):
                self.assertEqual(self.audit(self.installed(content=content, filename=filename))[0]['blocked'], 1)
        self.assertEqual(self.audit(self.installed(content=MIT))[0]['blocked'], 0)

    def test_finding_3_declared_code_and_markup_cannot_establish_acceptance(self):
        for filename in ('license.py', 'license.html', 'license.svg', 'license.sh', 'license.bin'):
            with self.subTest(filename=filename):
                raw = self.installed(content=MIT, filename=filename,
                                     extra_headers=['License-File: ' + filename])
                self.assertEqual(self.audit(raw)[0]['blocked'], 1)
        for text in ('SPDX-License-Identifier: MIT\n' + chr(0),
                     'SPDX-License-Identifier: MIT\n' + chr(1)):
            self.assertEqual(self.audit(self.installed(content=text))[0]['blocked'], 1)

    def test_finding_3_cli_empty_and_proprietary_files_block(self):
        for content in ('', 'All rights reserved. Proprietary. No redistribution.'):
            with self.subTest(content=content):
                self.installed(content=content)
                code, report = self.dependency_cli()
                self.assertEqual(code, 1)
                self.assertFalse(report['ready'])
                self.assertEqual(report['verification']['dependencies']['accepted_on_license_file'], [])

    def test_finding_4_whole_text_and_wide_encodings(self):
        texts = [GPL, 'SPDX-License-Identifier: MIT\n' + GRANT,
                 'Lesser General Public License\n' + GRANT,
                 'GNU Public License version 3', 'GPL_v3']
        for text in texts:
            for encoding in ('utf-8', 'utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be', 'utf-32', 'utf-32-le', 'utf-32-be'):
                with self.subTest(text=text[:35], encoding=encoding):
                    self.assertEqual(self.audit(self.installed(content=text.encode(encoding)))[0]['blocked'], 1)

    def test_finding_4_reference_wording_and_control_bytes_do_not_hide_grants(self):
        for text in ('Lesser General Public License\nSPDX-License-Identifier: MIT\n' + GRANT + ' by reference.',
                     'SPDX-License-Identifier: MIT\n' + GRANT + chr(0),
                     'SPDX-License-Identifier: MIT\n' + GPL + chr(1)):
            with self.subTest(text=text):
                raw = self.installed(content=text)
                result, findings = self.audit(raw)
                self.assertEqual(result['blocked'], 1)
                evidence = {'fake-dependency': {'version': '1', 'spdx': 'MIT',
                                                'sha256': hashlib.sha256(text.encode()).hexdigest()}}
                self.assertEqual(self.audit(raw, evidence)[0]['blocked'], 1)
                self.assertFalse(findings[0]['reviewed'])

    def test_finding_4_cli_wide_gpl_and_misleading_header_block(self):
        for content in (GPL.encode('utf-16'), 'SPDX-License-Identifier: MIT\n' + GRANT):
            with self.subTest(content=content):
                self.installed(content=content)
                code, report = self.dependency_cli()
                self.assertEqual(code, 1)
                self.assertFalse(report['ready'])
                self.assertEqual(report['verification']['dependencies']['blocked'], 1)

    def test_finding_5_classifier_and_text_fallback(self):
        cases = [('Dual License', ['BSD License', 'Apache Software License']),
                 ('Modified BSD License', ['BSD License']), ('Apache 2.0', ['Apache Software License']),
                 (genuine('BSD-3-Clause'), ['BSD License']), ('LGPL v3', ['GNU Library or Lesser General Public License (LGPL)']),
                 ('Expat (MIT/X11)', ['MIT License'])]
        for label, endings in cases:
            raw = self.installed(label=label.splitlines()[0], classifiers=['License :: OSI Approved :: ' + c for c in endings])
            package = json.loads(raw)[0]
            package['license'] = label
            package['licenses'] = [label]
            with self.subTest(label=label[:30]):
                self.assertEqual(self.audit(json.dumps([package]).encode())[0]['blocked'], 0)
        self.assertEqual(self.audit(self.installed(label='Custom terms', content=MIT))[0]['blocked'], 1)
        self.assertEqual(self.audit(self.installed(expression='Apache-2.0 WITH LLVM-exception'))[0]['blocked'], 0)
        self.assertEqual(self.audit(self.installed(expression='EPL-2.0 OR GPL-2.0-only WITH Classpath-exception-2.0'))[0]['blocked'], 0)

    def test_finding_5_full_grant_and_classifier_fallback_preserve_contrary_evidence(self):
        package = json.loads(self.installed())[0]
        package.update(license=MIT, licenses=[MIT])
        self.assertEqual(self.audit(json.dumps([package]).encode())[0]['blocked'], 0)
        for kwargs in ({'label': 'Custom terms', 'classifiers': ['License :: MIT License'], 'content': GPL},
                       {'label': 'Proprietary', 'classifiers': ['License :: MIT License'], 'content': MIT},
                       {'label': 'Custom terms', 'content': 'All rights reserved. Proprietary. No redistribution.'}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.audit(self.installed(**kwargs))[0]['blocked'], 1)

    def test_finding_5_cli_permissive_classifier_recovers_free_text(self):
        self.installed(label='Apache 2.0', classifiers=['License :: OSI Approved :: Apache Software License'], content=MIT)
        code, report = self.dependency_cli()
        self.assertEqual(code, 0)
        self.assertTrue(report['ready'])
        self.assertEqual(report['verification']['dependencies']['blocked'], 0)

    def test_finding_5_legacy_field_preserves_valid_choices(self):
        for label, blocked in (('MIT OR GPL-3.0-only', 0), ('GPL-3.0-only OR MIT', 0),
                               ('MIT AND GPL-3.0-only', 1), ('Apache-2.0 WITH LLVM-exception', 0)):
            with self.subTest(label=label):
                self.assertEqual(self.audit(self.installed(label=label))[0]['blocked'], blocked)

    def test_finding_6_evidence_cannot_hide_gpl_and_review_is_visible(self):
        for label, classifiers in [('Custom terms', []), (None, ['License :: Other/Proprietary License'])]:
            raw = self.installed(label=label, classifiers=classifiers, content=GPL)
            evidence = {'fake-dependency': {'version': '1', 'spdx': 'MIT', 'sha256': hashlib.sha256(GPL.encode()).hexdigest()}}
            result, findings = self.audit(raw, evidence)
            self.assertEqual(result['blocked'], 1)
            self.assertFalse(findings[0]['reviewed'])
        raw = self.installed(label='Custom terms', content='Unrecognised licence terms')
        evidence['fake-dependency']['sha256'] = hashlib.sha256(b'Unrecognised licence terms').hexdigest()
        result, findings = self.audit(raw, evidence)
        self.assertEqual(result['blocked'], 0)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]['reviewed'])
        raw = self.installed(label='Custom terms', content='Unrecognised licence terms', filename='NOTICE')
        self.assertEqual(self.audit(raw, evidence)[0]['blocked'], 1)

    def test_notice_files_cannot_supply_acceptance_or_digest_evidence(self):
        for filename in ('NOTICE', 'NOTICE.txt', 'licenses/NOTICE.md'):
            for label in (None, 'MIT'):
                with self.subTest(filename=filename, label=label):
                    raw = self.installed(label=label, content=MIT, filename=filename,
                                         extra_headers=['License-File: ' + filename])
                    evidence = {'fake-dependency': {'version': '1', 'spdx': 'MIT',
                                'sha256': hashlib.sha256(MIT.encode()).hexdigest()}}
                    result, findings = self.audit(raw, evidence)
                    self.assertEqual(result['blocked'], 1)
                    self.assertEqual(result['accepted_on_license_file'], [])
                    self.assertFalse(findings[0]['reviewed'])
                    scanner = rc.Scanner(['SyntheticPrivateTerm'], approvals=[{
                        **{key: findings[0][key] for key in ('scope', 'kind', 'path', 'fingerprint')},
                        'reason': 'Reviewed this exact attribution and licence evidence.'}])
                    result = rc.dependency_audit(raw, self.root, scanner, {'dependency_licenses': evidence})
                    self.assertEqual(result['blocked'], 0)
                    self.assertTrue(scanner.findings[0]['reviewed'])
        requirements = rc.requirements_text()
        self.assertIn('NOTICE alone is not a licence file', requirements)
        self.assertIn('even if declared by License-File', requirements)
        readme = Path(rc.__file__).with_name('README.md').read_text()
        self.assertIn('NOTICE files are scanned for licence assertions but cannot establish acceptance', readme)

    def test_notice_cli_cannot_accept_unlabelled_package_or_erase_restrictions(self):
        for content in (MIT, GPL, 'Proprietary: internal use only'):
            with self.subTest(content=content.splitlines()[0]):
                self.installed(content=content, filename='NOTICE')
                code, report = self.dependency_cli()
                self.assertEqual(code, 1)
                self.assertFalse(report['ready'])
                self.assertEqual(report['verification']['dependencies']['blocked'], 1)
                self.assertEqual(report['verification']['dependencies']['accepted_on_license_file'], [])
                self.assertTrue(any(f['kind'] == 'dependency-license-review' and not f['reviewed']
                                    for f in report['findings']))

    def test_finding_6_evidence_cannot_weaken_other_blockers(self):
        for kwargs in ({'label': 'GPL-3.0-only', 'content': MIT},
                       {'label': 'Proprietary', 'content': MIT},
                       {'label': 'MIT', 'content': GPL, 'filename': 'license.py',
                        'extra_headers': ['License-File: license.py']}):
            raw = self.installed(**kwargs)
            content = kwargs['content']
            evidence = {'fake-dependency': {'version': '1', 'spdx': 'MIT',
                                            'sha256': hashlib.sha256(content.encode()).hexdigest()}}
            self.assertEqual(self.audit(raw, evidence)[0]['blocked'], 1)
        raw = self.installed(label='MIT', content=MIT)
        for label in ('GPL-3.0-only', 'Proprietary', 'LicenseRef-Unknown'):
            evidence = {'fake-dependency': {'version': '1', 'spdx': label,
                                            'sha256': hashlib.sha256(MIT.encode()).hexdigest()}}
            self.assertEqual(self.audit(raw, evidence)[0]['blocked'], 1)

    def test_finding_6_cli_gpl_cannot_be_erased_and_resolution_is_visible(self):
        evidence = {'fake-dependency': {'version': '1', 'spdx': 'MIT', 'sha256': hashlib.sha256(GPL.encode()).hexdigest()}}
        self.installed(label='Custom terms', content=GPL)
        code, report = self.dependency_cli(evidence)
        self.assertEqual(code, 1)
        self.assertFalse(report['ready'])
        self.assertEqual(report['reviewed_count'], 0)
        text = 'Unrecognised licence terms'
        self.installed(label='Custom terms', content=text)
        evidence['fake-dependency']['sha256'] = hashlib.sha256(text.encode()).hexdigest()
        code, report = self.dependency_cli(evidence)
        self.assertEqual(code, 0)
        self.assertTrue(report['ready'])
        self.assertEqual(report['reviewed_count'], 1)
        hits = [f for f in report['findings'] if f['kind'] == 'dependency-license-review']
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0]['reviewed'])
        self.assertEqual(hits[0]['review_source'], 'dependency_licenses')
        self.assertNotIn(text, json.dumps(report))

    def test_finding_7_paths_with_spaces_redacted(self):
        for path in (str(self.root / 'Example Person' / 'My Reports' / 'venv'),
                     'C:\\Example Person\\My Reports\\venv',
                     '\\\\FixtureShare\\My Reports\\venv'):
            for quote in ("'", '"', ''):
                text = ('Error: Permission denied: ' + quote + path + quote + '\nRetry Debian/Ubuntu').encode()
                hit = rc.venv_failure(text, rc.Scanner(['SyntheticPrivateTerm']))
                self.assertNotIn('Example Person', hit['error_tail'])
                self.assertNotIn('My Reports', hit['error_tail'])
                self.assertIn('Retry Debian/Ubuntu', hit['error_tail'])

    def test_finding_7_embedded_quotes_and_report_serialization(self):
        fixture = fixtures.AuditTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        path = fixture.root / "Example Person's Folder" / 'My Reports' / 'venv'
        output = ("Error: Permission denied: '" + str(path) + "'\nRetry Debian/Ubuntu HiddenPerson").encode()
        with patch.object(rc, 'command', return_value=(1, output)):
            code, out, err = fixture.run_cli('--verify')
        self.assertEqual(code, 2)
        self.assertNotIn('Traceback', out + err)
        for report_path in (fixture.root / 'reports').rglob('report.*'):
            text = report_path.read_text()
            for fragment in ('Example Person', 'My Reports', 'HiddenPerson', str(fixture.root)):
                self.assertNotIn(fragment, text)
            self.assertIn('Retry Debian/Ubuntu', text)

    def test_adversarial_metadata_source_combinations(self):
        cases = [({'expression': 'MIT', 'label': 'GPL-3.0-only'}, 1),
                 ({'label': 'MIT', 'content': GPL}, 1),
                 ({'expression': 'MIT', 'content': 'GNU AFFERO GENERAL PUBLIC LICENSE', 'filename': 'COPYING'}, 1),
                 ({'classifiers': ['License :: MIT License'], 'content': GPL}, 1),
                 ({'label': 'MIT', 'classifiers': ['License :: Other/Proprietary License']}, 1),
                 ({'label': 'MIT', 'classifiers': ['License :: Free for non-commercial use']}, 1),
                 ({'label': 'MIT', 'classifiers': ['License :: European Union Public Licence']}, 1),
                 ({'label': 'MIT', 'classifiers': ['license :: gplv3']}, 1),
                 ({'label': 'MIT', 'extra_headers': ['License: GPL-3.0-only']}, 1),
                 ({'expression': 'MIT', 'extra_headers': ['License-Expression: AGPLv3']}, 1),
                 ({'expression': 'GPLv3 OR MIT', 'label': 'GPLv3'}, 1),
                 ({'expression': 'GPLv3 OR MIT'}, 0),
                 ({'expression': 'MIT AND GPLv3'}, 1),
                 ({'expression': 'MIT', 'content': MIT}, 0),
                 ({'label': 'LicenseRef-Unknown'}, 1)]
        for kwargs, blocked in cases:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.audit(self.installed(**kwargs))[0]['blocked'], blocked)

    def test_hostile_metadata_is_bounded(self):
        self.assertEqual(rc.licence_expression('(' * 1100 + 'MIT' + ')' * 1100), 'unknown')
        self.assertEqual(rc.licence_file_state('\n' * 60000), 'unknown')
        raw = self.installed(content='x' * (10 * 1024 * 1024))
        result, findings = self.audit(raw)
        self.assertEqual(result['blocked'], 1)
        self.assertTrue(any(f['kind'] == 'dependency-metadata-limit' for f in findings))
        package = json.loads(self.installed())[0]
        package['name'] = None
        result, findings = self.audit(json.dumps([package]).encode())
        self.assertEqual(result['blocked'], 1)
        self.assertEqual(findings[0]['kind'], 'dependency-metadata-invalid')

    def test_judgement_11_invalid_metadata_fails_plainly(self):
        package = json.loads(self.installed(expression='MIT'))[0]
        for field, value in (('name', None), ('version', 1), ('expression', []),
                             ('licenses', 'MIT'), ('classifiers', [None]), ('license_files', [{}])):
            with self.subTest(field=field):
                result, findings = self.audit(json.dumps([{**package, field: value}]).encode())
                self.assertEqual(result['blocked'], 1)
                self.assertEqual(findings[0]['kind'], 'dependency-metadata-invalid')
                self.assertFalse(findings[0]['reviewed'])
        for raw in (b'null', b'[null]', b'not json', ('[' * 1500 + '0' + ']' * 1500).encode()):
            self.assertEqual(self.audit(raw)[1][0]['kind'], 'dependency-metadata-invalid')
        self.assertEqual(self.audit(b'x' * (rc.MAX_METADATA_BYTES + 1))[1][0]['kind'], 'dependency-metadata-limit')

    def test_judgement_11_cli_missing_name_is_coverage_failure(self):
        self.installed(expression='MIT')
        metadata = self.info / 'METADATA'
        metadata.write_text('\n'.join(line for line in metadata.read_text().splitlines() if not line.startswith('Name:')) + '\n')
        code, report = self.dependency_cli()
        self.assertEqual(code, 2)
        self.assertFalse(report['ready'])
        self.assertTrue(any(f['kind'] == 'dependency-metadata-invalid' for f in report['findings']))

    def test_judgement_12_requirements_example_is_explicit(self):
        text = rc.requirements_text()
        self.assertIn('Example manifest for your own repository', text)
        self.assertIn('adjust file, line and argv', text)

    def test_judgement_13_verify_without_manifest_runs_no_commands(self):
        fixture = fixtures.AuditTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        (fixture.repo / 'release-check.json').unlink()
        with patch.object(rc, 'command') as call:
            code, out, err = fixture.run_cli('--verify')
        call.assert_not_called()
        self.assertEqual(code, 2)
        self.assertNotIn('Traceback', out + err)
        report = json.loads(next((fixture.root / 'reports').rglob('report.json')).read_text())
        kinds = {f['kind'] for f in report['findings']}
        self.assertTrue({'quickstart-not-declared', 'test-command-not-declared', 'verification-not-configured'} <= kinds)

    def bound_evidence(self, content):
        raw = content.encode() if isinstance(content, str) else content
        return {'fake-dependency': {'version': '1', 'spdx': 'MIT',
                                    'sha256': hashlib.sha256(raw).hexdigest()}}

    def test_encoding_gate_decodes_byte_order_before_digest_review(self):
        encodings = ('utf-8', 'utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be',
                     'utf-32', 'utf-32-le', 'utf-32-be')
        for text in ('GPL', 'AGPL', 'GPLv3', MIT):
            contents = [text.encode(encoding) for encoding in encodings]
            contents += [b'\xfe\xff' + text.encode('utf-16-be'),
                         b'\xff\xfe\x00\x00' + text.encode('utf-32-le'),
                         b'\x00\x00\xfe\xff' + text.encode('utf-32-be')]
            for content in contents:
                with self.subTest(text=text[:10], content=content[:16]):
                    raw = self.installed(content=content)
                    self.assertEqual(json.loads(raw)[0]['license_files'][0]['text'], text)
                    result, findings = self.audit(raw, self.bound_evidence(content))
                    self.assertEqual(result['blocked'], 0 if text == MIT else 1)
                    self.assertFalse(any(f['reviewed'] for f in findings))

    def test_encoding_gate_uncertain_files_cannot_be_digest_waived(self):
        for content in (b'\xe9' * 16, b'\x00\x01' * 8, b'\xff\xfeMIT',
                        b'\xef\xbb\xbfMIT\xff', b'\x00\x00\xfe\xff\x00',
                        'GPL'.encode('utf-16-be') + b'\xff'):
            with self.subTest(content=content):
                raw = self.installed(expression='MIT', content=content)
                result, findings = self.audit(raw, self.bound_evidence(content))
                self.assertEqual(result['blocked'], 1)
                self.assertFalse(any(f['reviewed'] for f in findings))

    def test_encoding_gate_cli_gpl_digest_blocks_source_and_export(self):
        for text in ('GPL', 'AGPL', 'GPLv3'):
            content = text.encode('utf-16-be')
            self.installed(content=content)
            code, report = self.dependency_cli(self.bound_evidence(content), export=text == 'GPL')
            with self.subTest(text=text):
                self.assertEqual(code, 1)
                for audit in (report, *([report['export']] if text == 'GPL' else [])):
                    self.assertFalse(audit['ready'])
                    self.assertEqual(audit['reviewed_count'], 0)
                    self.assertEqual(audit['verification']['dependencies']['blocked'], 1)

    def test_root_gate_preserves_non_mit_headings(self):
        fixture = fixtures.AuditTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for heading in ('LGPL-3.0-only', 'MPL-2.0', 'EPL-2.0', 'Apache-2.0', 'MIT-0'):
            with self.subTest(heading=heading):
                (fixture.repo / 'LICENSE').write_text(heading + '\n' + MIT)
                scanner = rc.Scanner(['SyntheticPrivateTerm'])
                result = rc.license_audit(fixture.repo, scanner, fixture.manifest)
                self.assertEqual(result['status'], 'blocked')
                self.assertTrue(any(f['kind'] == 'unrecognized-or-modified-license' for f in scanner.findings))

    def test_root_gate_cli_non_mit_heading_is_reported(self):
        self.installed(expression='MIT', content=MIT)
        code, report = self.dependency_cli(root_license='LGPL-3.0-only\n' + MIT)
        self.assertEqual(code, 1)
        self.assertFalse(report['ready'])
        self.assertEqual(report['license']['status'], 'blocked')
        self.assertTrue(any(f['kind'] == 'unrecognized-or-modified-license' for f in report['findings']))

    def test_root_gate_mit_headings_and_encoded_documents(self):
        fixture = fixtures.AuditTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for heading in ('MIT', 'MIT License', 'The MIT License (MIT)', 'MIT Software License'):
            for encoding in ('utf-8-sig', 'utf-16', 'utf-16-be', 'utf-32'):
                with self.subTest(heading=heading, encoding=encoding):
                    (fixture.repo / 'LICENSE').write_bytes((heading + '\n' + MIT).encode(encoding))
                    scanner = rc.Scanner(['SyntheticPrivateTerm'])
                    self.assertEqual(rc.license_audit(fixture.repo, scanner, fixture.manifest)['status'], 'pass')
        (fixture.repo / 'LICENSE').write_text(MIT)
        for declaration in ('{text = ' + json.dumps('LGPL-3.0-only\n' + MIT) + '}',
                            '{file = "other.txt"}'):
            (fixture.repo / 'other.txt').write_bytes(('LGPL-3.0-only\n' + MIT).encode('utf-16-be'))
            (fixture.repo / 'pyproject.toml').write_text('[project]\nlicense = ' + declaration + '\n')
            scanner = rc.Scanner(['SyntheticPrivateTerm'])
            rc.license_audit(fixture.repo, scanner, fixture.manifest)
            self.assertTrue(any(f['kind'] == 'license-metadata-mismatch' for f in scanner.findings))

    def test_final_gate_parser_failures_preserve_restrictions(self):
        labels = ('GPL-3.0-only AND Custom terms', 'AGPL-3.0-only AND Custom terms',
                  'GNU General Public License version 3',
                  'GPL-3.0-only WITH Classpath-exception-2.0 extra',
                  'GPL-3.0-only OR LicenseRef-Unknown',
                  'LicenseRef-Unknown OR AGPL-3.0-only',
                  'Proprietary AND Custom terms', 'MIT WITH extra proprietary terms',
                  'G\u200bPL-3.0-only AND Custom terms',
                  'GNU Affero General Public Licence version 3',
                  'General Public Licence AND Custom terms',
                  'LicenseRef-Unknown OR General Public Licence',
                  'Elastic License 2.0 extra', 'BUSL-1.1 AND Custom terms',
                  'MIT WITH GPL-3.0-only', 'MIT WITH BUSL-1.1',
                  'LicenseRef-GPL', 'MIT AND LicenseRef-AGPL', 'LicenseRef-Proprietary',
                  'GPL-3.0-only ' + '(' * 65, 'Proprietary ' + 'x' * 8192)
        for label in labels:
            for source in ('expression', 'label', 'classifiers', 'content'):
                with self.subTest(label=label[:60], source=source):
                    content = 'SPDX-License-Identifier: ' + label if source == 'content' else MIT
                    kwargs = {'content': content}
                    if source != 'content':
                        kwargs[source] = ['License :: OSI Approved :: ' + label] if source == 'classifiers' else label
                    result, findings = self.audit(self.installed(**kwargs), self.bound_evidence(content))
                    self.assertEqual(result['blocked'], 1)
                    self.assertTrue(findings)
                    self.assertFalse(any(f['reviewed'] for f in findings))

    def test_final_gate_cli_parser_failures_cannot_be_digest_waived(self):
        cases = [({'expression': label, 'content': MIT}, MIT) for label in
                 ('GPL-3.0-only AND Custom terms', 'AGPL-3.0-only AND Custom terms',
                  'GNU General Public License version 3',
                  'GPL-3.0-only WITH Classpath-exception-2.0 extra',
                  'GPL-3.0-only OR LicenseRef-Unknown', 'Proprietary AND Custom terms')]
        cases += [({'content': 'SPDX-License-Identifier: GPL-3.0-only AND Custom terms'},
                   'SPDX-License-Identifier: GPL-3.0-only AND Custom terms'),
                  ({'classifiers': ['License :: OSI Approved :: GNU General Public License version 3'],
                    'content': MIT}, MIT)]
        for kwargs, content in cases:
            with self.subTest(kwargs=kwargs):
                self.installed(**kwargs)
                code, report = self.dependency_cli(self.bound_evidence(content))
                self.assertEqual(code, 1)
                self.assertFalse(report['ready'])
                self.assertEqual(report['verification']['dependencies']['blocked'], 1)
                self.assertEqual(report['reviewed_count'], 0)

    def test_final_gate_cli_generic_classifier_is_neutral(self):
        for label in ('MIT', 'Apache-2.0', 'BSD-3-Clause', 'LGPL-3.0'):
            with self.subTest(label=label):
                self.installed(label=label, classifiers=['License :: OSI Approved'])
                code, report = self.dependency_cli()
                self.assertEqual(code, 0)
                self.assertTrue(report['ready'])
                self.assertEqual(report['verification']['dependencies']['blocked'], 0)
                self.assertEqual(report['findings'], [])
        for kwargs in ({}, {'label': 'GPLv3'}, {'label': 'Custom terms'},
                       {'label': 'MIT', 'content': GPL}):
            (self.info / 'LICENSE').unlink(missing_ok=True)
            self.assertEqual(self.audit(self.installed(classifiers=['License :: OSI Approved'], **kwargs))[0]['blocked'], 1)

    def test_final_gate_digest_covers_all_unknown_files(self):
        self.installed(label='Custom terms', content=MIT)
        (self.info / 'COPYING').write_text('Unreviewed extra obligations')
        with (self.info / 'RECORD').open('a') as record:
            record.write(self.info.name + '/COPYING,,\n')
        script = 'import sys\n' + rc.METADATA_SCRIPT.replace('m.distributions()', 'm.distributions(path=[sys.argv[1]])')
        raw = subprocess.run([sys.executable, '-c', script, str(self.root)],
                             check=True, capture_output=True).stdout
        self.assertEqual(self.audit(raw, self.bound_evidence(MIT))[0]['blocked'], 1)
        for content in ('', '\n', chr(0), 'SPDX-License-Identifier: MIT\n' + chr(1)):
            with self.subTest(content=repr(content)):
                raw = self.installed(label='Custom terms', content=content)
                self.assertEqual(self.audit(raw, self.bound_evidence(content))[0]['blocked'], 1)

    def test_final_gate_cli_missing_files_and_unbound_unknown_block(self):
        for kind in ('missing-record', 'missing-file', 'unlisted-declaration', 'second-unknown',
                     'unrecorded-licence', 'duplicate-version', 'malformed-header'):
            with self.subTest(kind=kind):
                (self.info / 'COPYING').unlink(missing_ok=True)
                self.installed(expression='MIT', content=MIT,
                               extra_headers=['License-File: absent.txt'] if kind == 'unlisted-declaration' else ())
                if kind == 'missing-record':
                    (self.info / 'RECORD').unlink()
                elif kind == 'missing-file':
                    (self.info / 'LICENSE').unlink()
                elif kind == 'second-unknown':
                    (self.info / 'COPYING').write_text('Unreviewed extra obligations')
                    with (self.info / 'RECORD').open('a') as record:
                        record.write(self.info.name + '/COPYING,,\n')
                elif kind == 'unrecorded-licence':
                    (self.info / 'COPYING').write_text(GPL)
                elif kind == 'duplicate-version':
                    with (self.info / 'METADATA').open('a') as metadata:
                        metadata.write('Version: 2\n')
                elif kind == 'malformed-header':
                    with (self.info / 'METADATA').open('a') as metadata:
                        metadata.write('Invalid header\nLicense-Expression: GPLv3\n')
                code, report = self.dependency_cli(self.bound_evidence(MIT))
                self.assertEqual(code, 1 if kind == 'second-unknown' else 2)
                self.assertFalse(report['ready'])
                self.assertEqual(report['reviewed_count'], 0)

    def test_final_gate_malformed_wide_text_retains_gpl(self):
        for encoding in ('utf-16', 'utf-16-le', 'utf-16-be', 'utf-32', 'utf-32-le', 'utf-32-be'):
            with self.subTest(encoding=encoding):
                content = 'GPL-3.0-only'.encode(encoding) + b'\xff'
                self.assertEqual(self.audit(self.installed(content=content), self.bound_evidence(content))[0]['blocked'], 1)

    def test_final_gate_duplicate_json_and_missing_file_text_block(self):
        package = json.loads(self.installed(expression='GPLv3', content=MIT))[0]
        duplicate = json.dumps([package]).replace('"expression": "GPLv3"', '"expression": "GPLv3", "expression": "MIT"')
        self.assertEqual(self.audit(duplicate.encode(), self.bound_evidence(MIT))[0]['blocked'], 1)
        del package['license_files'][0]['text']
        self.assertEqual(self.audit(json.dumps([package]).encode(), self.bound_evidence(MIT))[1][0]['category'], 'coverage')
        manifest_path = self.root / 'release-check.json'
        manifest_path.write_text('{"dependency_licenses": {"fake-dependency": {"spdx": "GPLv3", "spdx": "MIT"}}}')
        with self.assertRaises((rc.AuditError, ValueError)):
            rc.manifest_for(self.root, None)
        raw = self.installed(label='Custom terms', content=MIT)
        evidence = self.bound_evidence(MIT)
        evidence['fake_dependency'] = {**evidence['fake-dependency'], 'spdx': 'GPLv3'}
        self.assertEqual(self.audit(raw, evidence)[0]['blocked'], 1)

    def test_final_gate_normalized_classifiers_and_corrupt_metadata_block(self):
        for classifier in ('Li\u200bcense :: OSI Approved :: GPLv3',
                           'Ｌicense :: OSI Approved :: AGPLv3'):
            raw = self.installed(expression='MIT', classifiers=[classifier], content=MIT)
            self.assertEqual(self.audit(raw, self.bound_evidence(MIT))[0]['blocked'], 1)
        for field in ('expression', 'license', 'licenses', 'classifiers'):
            package = json.loads(self.installed(expression='MIT', content=MIT))[0]
            package[field] = ['G' + chr(0) + 'PL'] if field in ('licenses', 'classifiers') else 'GPL' + chr(0)
            result, findings = self.audit(json.dumps([package]).encode(), self.bound_evidence(MIT))
            self.assertEqual(result['blocked'], 1)
            self.assertEqual(findings[0]['category'], 'coverage')
            scanner = rc.Scanner(['SyntheticPrivateTerm'], approvals=[{**findings[0], 'reason': 'Reviewed.'}])
            rc.dependency_audit(json.dumps([package]).encode(), self.root, scanner,
                                {'dependency_licenses': self.bound_evidence(MIT)})
            self.assertFalse(scanner.findings[0]['reviewed'])

    def test_final_gate_copyright_normalization_retains_restrictions(self):
        for heading in ('Copyright 2026 GPLv3', 'Copyright 2026 AGPL',
                        'Copyright 2026 Proprietary', 'Copyright 2026 Noncommercial'):
            content = heading + '\n' + MIT
            with self.subTest(heading=heading):
                raw = self.installed(content=content)
                self.assertEqual(self.audit(raw, self.bound_evidence(content))[0]['blocked'], 1)

    def test_final_gate_full_legacy_text_precedes_restriction_fallback(self):
        for identifier in ('BSD-3-Clause', 'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0'):
            package = json.loads(self.installed())[0]
            package.update(license=genuine(identifier), licenses=[genuine(identifier)])
            with self.subTest(identifier=identifier):
                self.assertEqual(self.audit(json.dumps([package]).encode())[0]['blocked'], 0)

    def test_final_gate_limits_cannot_be_digest_or_approval_waived(self):
        for label in ('(' * 65 + 'MIT' + ')' * 65, 'LicenseRef-' + 'x' * 8192):
            for source in ('expression', 'content', 'evidence'):
                content = 'SPDX-License-Identifier: ' + label if source == 'content' else MIT
                raw = self.installed(expression=label if source == 'expression' else 'MIT', content=content)
                evidence = self.bound_evidence(content)
                if source == 'evidence':
                    evidence['fake-dependency']['spdx'] = label
                with self.subTest(source=source, length=len(label)):
                    result, findings = self.audit(raw, evidence)
                    self.assertEqual(result['blocked'], 1)
                    self.assertEqual(findings[0]['kind'], 'dependency-metadata-limit')
                    scanner = rc.Scanner(['SyntheticPrivateTerm'], approvals=[{**findings[0], 'reason': 'Reviewed.'}])
                    rc.dependency_audit(raw, self.root, scanner, {'dependency_licenses': evidence})
                    self.assertFalse(scanner.findings[0]['reviewed'])

    def test_final_gate_root_licences_and_metadata_do_not_drop_restrictions(self):
        fixture = fixtures.AuditTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for text in ('GPL-3.0-only\n' + MIT, 'Proprietary\n' + MIT):
            (fixture.repo / 'LICENSE').write_text(text)
            scanner = rc.Scanner(['SyntheticPrivateTerm'])
            self.assertEqual(rc.license_audit(fixture.repo, scanner, fixture.manifest)['status'], 'blocked')
        (fixture.repo / 'LICENSE').write_text(MIT)
        (fixture.repo / 'COPYING').write_text(GPL)
        scanner = rc.Scanner(['SyntheticPrivateTerm'])
        self.assertEqual(rc.license_audit(fixture.repo, scanner, fixture.manifest)['status'], 'blocked')
        (fixture.repo / 'COPYING').unlink()
        for declaration in ('{text = "GPL-3.0-only"}', '{file = "other.txt"}', '42'):
            (fixture.repo / 'other.txt').write_text(GPL)
            (fixture.repo / 'pyproject.toml').write_text('[project]\nname="fixture"\nlicense=' + declaration + '\n')
            scanner = rc.Scanner(['SyntheticPrivateTerm'])
            rc.license_audit(fixture.repo, scanner, fixture.manifest)
            self.assertTrue(any(f['kind'] == 'license-metadata-mismatch' for f in scanner.findings))


if __name__ == '__main__':
    unittest.main()
