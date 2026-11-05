import unittest

import release_check as rc


class AssignedExpressionTests(unittest.TestCase):
    def scan(self, source, path='config.py', scope='tree'):
        scanner = rc.Scanner([])
        scanner.file(source.encode(), scope, path)
        return [f for f in scanner.findings if f['kind'] == 'assigned-secret']

    def test_python_references_are_not_literal_credentials(self):
        for scope in ('tree', 'history'):
            for expression in ('credentials.value', 'configured_password'):
                with self.subTest(scope=scope, expression=expression):
                    self.assertEqual(self.scan('password = ' + expression, scope=scope), [])
                    self.assertEqual(len(self.scan(('password = "actu' + 'al-password-value"'), scope=scope)), 1)

    def test_only_exact_expression_occurrence_is_classified(self):
        source = ('note = "é"; password = cred' + 'entials.value\npassword = "cred' + 'entials.value"\n# password = cred' + 'entials.value\n')
        self.assertEqual([f['line'] for f in self.scan(source)], [2, 3])

    def test_invalid_python_and_other_file_types_still_block(self):
        for source, path in ((('password = cred' + 'entials.value'), 'config.env'),
                             (('password = cred' + 'entials.value\nif'), 'config.py')):
            with self.subTest(path=path):
                self.assertEqual(len(self.scan(source, path)), 1)

    def test_call_argument_secrets_are_still_scanned(self):
        source = ('password = conf' + 'igure(api_key="actu' + 'al-password-value")')
        findings = self.scan(source)
        self.assertTrue(any(f['fingerprint'] == rc.fingerprint('actual-password-value') for f in findings))

    def test_reference_and_fixture_strings_remain_blocking(self):
        for value in ('secret://credential-name?extra', '${CONFIGURED_PASSWORD}', '<placeholder-password>', 'fixture-password'):
            with self.subTest(value=value):
                self.assertEqual(len(self.scan('password = "' + value + '"')), 1)
        scanner = rc.Scanner([])
        scanner.file((b'url = "https://user:fixt' + (b'ure-' + (b'pass' + (b'word' + b'@example.invalid/path"')))), 'tree', 'test_config.py')
        self.assertTrue(any(f['kind'] == 'credential-url' and not f['reviewed'] for f in scanner.findings))

    def test_secret_valued_calls_with_positional_literals_still_block(self):
        for expression in ('identity("actual-password-value")', 'bytearray(b"actual-password-value")',
                           're.compile(r"^[a-z]+$")'):
            with self.subTest(expression=expression):
                self.assertTrue(self.scan('password = ' + expression))
