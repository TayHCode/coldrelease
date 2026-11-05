import base64
import hashlib
import json
import unittest

import release_check as rc
import test_release_check as fixtures


class NpmIntegrityTests(unittest.TestCase):
    def sri(self, algorithm='sha512'):
        return algorithm + '-' + base64.b64encode(hashlib.new(algorithm, b'public package fixture 2').digest()).decode()

    def lock(self, value, version=3):
        return {'name': 'fixture', 'lockfileVersion': version,
                'packages': {'': {'name': 'fixture'}, 'node_modules/fixture': {'integrity': value}}}

    def scan(self, raw, path='package-lock.json', terms=()):
        scanner = rc.Scanner(list(terms))
        scanner.file(raw.encode() if isinstance(raw, str) else raw, 'tree', path)
        return scanner.findings

    def test_valid_sri_only_removes_entropy_in_npm_integrity_fields(self):
        value = self.sri()
        self.assertTrue(any(f['kind'] == 'entropy' for f in self.scan(value, 'data.txt')))
        for algorithm in ('sha1', 'sha256', 'sha384', 'sha512'):
            for path in ('package-lock.json', 'app/npm-shrinkwrap.json'):
                with self.subTest(algorithm=algorithm, path=path):
                    self.assertEqual(self.scan(json.dumps(self.lock(self.sri(algorithm))), path), [])

    def test_non_integrity_fields_and_other_paths_still_block(self):
        value = self.sri()
        document = self.lock(value)
        document['packages']['node_modules/fixture']['description'] = value
        self.assertEqual([f['kind'] for f in self.scan(json.dumps(document))], ['entropy'])
        for path in ('data.json', 'tests/test_lock.json', 'package-lock.json.txt'):
            with self.subTest(path=path):
                self.assertTrue(any(f['kind'] == 'entropy' for f in self.scan(json.dumps(self.lock(value)), path)))

    def test_invalid_sri_and_schema_fail_closed(self):
        value = self.sri()
        documents = [self.lock(value, 1), self.lock(value, 2), self.lock(value, True), {'integrity': value},
                     {**self.lock(value), 'packages': [], 'extra': value},
                     {**self.lock(value), 'packages': {'node_modules/fixture': value}},
                     {**self.lock(value), 'extra': {'integrity': value}},
                     self.lock(value[:-1]), self.lock(value + 'A'), self.lock(value.replace('sha512-', 'sha999-')),
                     self.lock(('Ab3D' + ('4e5F' + ('6g7H' + '8i9J0kL1mN2oP3qR4sT5uV6wX7yZ8')))),
                     self.lock(value[:-8])]
        for index, document in enumerate(documents):
            with self.subTest(case=index):
                self.assertTrue(any(f['kind'] == 'entropy' for f in self.scan(json.dumps(document))))
        raw = json.dumps(self.lock(value))
        for broken in (raw[:-1], raw.replace('"lockfileVersion": 3', '"lockfileVersion": 3, "lockfileVersion": 3')):
            self.assertTrue(any(f['kind'] == 'entropy' for f in self.scan(broken)))

    def test_secret_detectors_and_private_terms_still_scan_integrity(self):
        key = 'gh' + 'p_' + ('Ab3D' + ('4e5F' + ('6g7H' + '8i9J0kL1mN2oP3qR4sT5uV6wX7yZ8')))
        password = ('synt' + 'hetic-password-value')
        for value, kind in ((key, 'github-token'), ('api_key=' + password, 'assigned-secret'),
                            ('https://fixture:' + password + '@example.invalid/path', 'credential-url')):
            with self.subTest(kind=kind):
                hit = next(f for f in self.scan(json.dumps(self.lock(value))) if f['kind'] == kind)
                scanner = rc.Scanner([], approvals=[hit])
                scanner.file(json.dumps(self.lock(value)).encode(), 'tree', 'package-lock.json')
                self.assertTrue(all(not f['reviewed'] for f in scanner.findings))
        value = self.sri()
        self.assertTrue(any(f['kind'] == 'denylist' for f in self.scan(json.dumps(self.lock(value)), terms=[value[10:18]])))
        digest = base64.b64encode(bytes(range(64))).decode()
        digest = 'AKIA' + 'A' * 16 + '+' + digest[21:]
        findings = self.scan(json.dumps(self.lock('sha512-' + digest)))
        self.assertTrue(any(f['kind'] == 'aws-key' for f in findings))

    def test_history_and_line_endings_follow_the_same_classification(self):
        raw = json.dumps(self.lock(self.sri()), indent=2)
        for scope in ('tree', 'history'):
            for separator in ('\n', '\r\n', '\r'):
                scanner = rc.Scanner([])
                scanner.file(raw.replace('\n', separator).encode(), scope, 'app/package-lock.json', object_id='fixture')
                self.assertEqual(scanner.findings, [])

    def test_escaped_fields_encoding_and_unknown_locations_fail_closed(self):
        value = self.sri()
        raw = json.dumps(self.lock(value))
        for document in (raw.replace('sha512-', r'\u0073ha512-'),
                         raw.replace('"integrity"', r'"integrit\u0079"'),
                         raw + ' trailing', raw.replace('"name": "fixture"', '"name": NaN', 1)):
            self.assertTrue(any(f['kind'] == 'entropy' for f in self.scan(document)))
        for encoded in (b'\xef\xbb\xbf' + raw.encode(), b'\xff' + raw.encode(), raw.encode('utf-16')):
            self.assertTrue(any(f['kind'] == 'entropy' for f in self.scan(encoded)))
        for location in ('dependencies', 'extra'):
            document = self.lock(value)
            document['packages']['node_modules/fixture'][location] = {'integrity': value}
            self.assertTrue(any(f['kind'] == 'entropy' for f in self.scan(json.dumps(document))))
        raw = raw.replace('"integrity":', '"integrity": "invalid", "integrity":')
        self.assertTrue(any(f['kind'] == 'entropy' for f in self.scan(raw)))

    def test_cli_keeps_node_gate_and_real_secret_controls(self):
        fixture = fixtures.AuditTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        (fixture.repo / 'package.json').write_text('{"dependencies":{"fixture":"1"}}')
        lock = self.lock(self.sri())
        (fixture.repo / 'package-lock.json').write_text(json.dumps(lock))
        code, _, _ = fixture.run_cli()
        self.assertEqual(code, 2)
        report_path = next((fixture.root / 'reports').rglob('report.json'))
        report = json.loads(report_path.read_text())
        self.assertNotIn('entropy', [f['kind'] for f in report['findings']])
        self.assertIn('dependency-ecosystem-manual-review', [f['kind'] for f in report['findings']])
        lock['packages']['node_modules/fixture']['resolved'] = ('https://fixture:synt' + ('heti' + ('c-pa' + ('sswo' + 'rd-value@' + 'example.invalid/package.tgz'))))
        (fixture.repo / 'package-lock.json').write_text(json.dumps(lock))
        code, _, _ = fixture.run_cli()
        self.assertEqual(code, 1)
        reports = [json.loads(path.read_text()) for path in (fixture.root / 'reports').rglob('report.json')]
        self.assertTrue(any(f['kind'] == 'credential-url' and not f['reviewed']
                            for report in reports for f in report['findings']))
