import unittest

import release_check as rc


class ResidualFormatTests(unittest.TestCase):
    def scan(self, source, path='config.py', terms=(), scope='tree'):
        scanner = rc.Scanner(list(terms))
        scanner.file(source.encode(), scope, path)
        return scanner.findings

    def secrets(self, source, **kwargs):
        return [f for f in self.scan(source, **kwargs) if f['category'] == 'secrets']

    def test_regex_calls_remain_blocking_without_callee_proof(self):
        source = "import re\nSECRET_KEY = re.compile(r'token|secret|key|password|authorization|credential', re.I)"
        for scope in ('tree', 'history'):
            self.assertTrue(self.secrets(source, scope=scope))
            self.assertTrue(self.secrets(('password = iden' + 'tity("actual-password-value")'), scope=scope))
            self.assertTrue(self.secrets(('password = byte' + 'array(b"actual-password-value")'), scope=scope))

    def test_regex_exemption_rejects_arbitrary_patterns_shadowing_and_invalid_source(self):
        for source in (
            'import re\npassword = re.compile("actual-password-value")',
            'import re\npassword = re.compile(r"^[a-z]+$")',
            ('password = re.c' + 'ompile("token|password")'),
            'import re\nre = identity\npassword = re.compile("token|password")',
            'import re\nre.compile = identity\npassword = re.compile("token|password")',
            'import re\npassword = re.compile("token|password")\nif',
            ('import re\npassword = re.compile("token|password", api_key="actu' + 'al-password-value")'),
            'import re\npassword = re.compile(\n# password = act' + 'ual-password-value\n"token|password")',
        ):
            with self.subTest(source=source):
                self.assertTrue(self.secrets(source))

    def test_pattern_classification_requires_initial_module_declaration(self):
        sources = (
            'import re\nimport review_fixture_patch\npassword = re.compile("token|password")',
            ('import re\nclass Holder(Exception):\n def compile(self, pattern): return "actual-password-value"\ntry:\n raise Holder()\nexcept Holder as re:\n password = re.c' + 'ompile("token|password")'),
            ('import re\nclass Holder:\n def compile(self, pattern): return "actual-password-value"\nmatch Holder():\n case re:\n  password = re.c' + 'ompile("token|password")'),
            'import re\nsetattr(re, "compile", identity)\npassword = re.compile("token|password")',
            ('import re\ndef f():\n password = re.c' + 'ompile("token|password")'),
        )
        for source in sources:
            for scope in ('tree', 'history'):
                with self.subTest(source=source, scope=scope):
                    self.assertTrue(self.secrets(source, scope=scope))

    def test_complete_supported_references_and_exact_placeholder(self):
        for scope in ('tree', 'history'):
            for value in ('secret://existing', '${AGENTLOCKER_SECRET_EXAMPLE}', '<your-password>'):
                with self.subTest(scope=scope, value=value):
                    self.assertEqual(self.secrets('password = "' + value + '"', scope=scope), [])
                    self.assertEqual(self.secrets('args = ["--password=' + value + '"]', scope=scope), [])
                    self.assertTrue(self.secrets(('password = "actu' + 'al-password-value"'), scope=scope))

    def test_known_assertion_prefixes_only_in_expected_operand(self):
        for prefix in (('--password=secr' + 'et://'), ('--password=${AG' + 'ENTLOCKER_SECRET_')):
            with self.subTest(prefix=prefix):
                self.assertEqual(self.secrets('self.assertIn("' + prefix + '", rendered)'), [])
                self.assertTrue(self.secrets('password = "' + prefix + '"'))
                self.assertTrue(self.secrets('self.assertIn(rendered, "' + prefix + '")'))
                self.assertTrue(self.secrets('# self.assertIn("' + prefix + '", rendered)'))

    def test_malformed_escaped_unknown_and_non_source_formats_remain_blocking(self):
        values = ('secret://', 'secret://name?token=extra', 'secret://name/extra',
                  '${AGENTLOCKER_SECRET_EXAMPLE', '${AGENTLOCKER_SECRET_EXAMPLE}suffix',
                  '${CONFIGURED_PASSWORD}', '<placeholder-password>', '<your-password>suffix')
        for value in values:
            with self.subTest(value=value):
                self.assertTrue(self.secrets('password = "' + value + '"'))
        for source, path in (
            (('password = "secr' + 'et://existing"'), 'config.txt'),
            (('password = "secr' + 'et://existing"\nif'), 'config.py'),
            ('password = "sec' + 'ret:\\x2f/existing"', 'config.py'),
            (('password = "secr' + 'et://existing" "suffix"'), 'config.py'),
        ):
            self.assertTrue(self.secrets(source, path=path))

    def test_real_keys_entropy_and_private_terms_inside_references_still_block(self):
        key = 'gh' + 'p_' + ('Ab3D' + '4e5F6g7H8i9J0kL1mN2oP3qR4sT5')
        entropy = ('Ab3D' + ('4e5F' + ('6g7H' + '8i9J0kL1mN2oP3qR4sT5uV6wX7yZ8')))
        for token in (key, entropy, 'AKIA' + 'A' * 16):
            for value in ('secret://' + token, '${AGENTLOCKER_SECRET_' + token + '}'):
                with self.subTest(value=value):
                    self.assertTrue(self.secrets('password = "' + value + '"'))
        findings = self.scan(('password = "secr' + 'et://HiddenFixture"'), terms=['HiddenFixture'])
        self.assertTrue(any(f['kind'] == 'denylist' and not f['reviewed'] for f in findings))

    def test_ts_lookalikes_and_invalid_source_remain_blocking(self):
        for source in (('const text = "return {accessToken:body' + '.access_token}";'),
                       ('/* return {accessToken:body' + '.access_token} */'),
                       ('const pattern = /return {accessToken:body' + '.access_token}/;'),
                       ('function f() { return {accessToken:"body' + '.access_token"}; }'),
                       ('function f() { return {accessToken:body' + '.access_token}; }\nconst = ;')):
            self.assertTrue(self.secrets(source, path='code.ts'))

    def test_negative_assertion_does_not_prove_validator_has_no_credential_use(self):
        source = '''
import unittest
configured = []
def repository_page(value):
    configured.append(value)
    raise ValueError("rejected after use")
class Checks(unittest.TestCase):
    def test_invalid_url(self):
        for invalid in ("https://user:''' + '''password@''' + '''github.com/example/repo",):
            with self.subTest(url=invalid), self.assertRaises(ValueError):
                repository_page(invalid)
'''
        self.assertTrue(any(f['kind'] == 'credential-url' for f in self.secrets(source)))
        namespace = {}
        exec(source, namespace)
        namespace['Checks']('test_invalid_url').test_invalid_url()
        self.assertEqual(namespace['configured'], [('https://user:pass' + ('word' + '@github.com/example/repo'))])
