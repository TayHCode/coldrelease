import unittest

import release_check as rc


class PlaceholderUrlTests(unittest.TestCase):
    def scan(self, source, path='settings.py', scope='tree', terms=()):
        scanner = rc.Scanner(list(terms))
        scanner.file(source.encode(), scope, path)
        return scanner.findings

    def credentials(self, source, **kwargs):
        return [f for f in self.scan(source, **kwargs) if f['kind'] == 'credential-url']

    def test_exact_public_placeholders_in_python_literals(self):
        for scope in ('tree', 'history'):
            for host in ('example.com', 'example.net', 'example.org', 'api.example.test', 'api.example.invalid'):
                for user, password in (('user', 'pass'), ('u', 'p'), ('username', 'password')):
                    with self.subTest(scope=scope, host=host, user=user):
                        self.assertEqual(self.credentials((f'url = "https:' + f'//{user}:{password}@{host}/api"'), scope=scope), [])
                        self.assertEqual(len(self.credentials((f'url = "https:' + f'//{user}:actual-password-value@{host}/api"'), scope=scope)), 1)

    def test_private_and_deceptive_hosts_are_not_placeholders(self):
        for host in (('serv' + ('ice.' + 'internal')), 'localhost', ('127.' + '0.0.1'), 'example.com.attacker.org',
                     'notexample.com', 'example.test.attacker.org', 'example.com.', ('[:' + ':1]')):
            with self.subTest(host=host):
                self.assertEqual(len(self.credentials((f'url = "https:' + f'//user:pass@{host}/api"'))), 1)

    def test_raw_ambiguous_and_encoded_urls_stay_blocking(self):
        for source, path in (
            (('https://user:pass' + '@example.test/api'), 'readme.txt'),
            (('# https://user:pass' + '@example.test/api'), 'settings.py'),
            (('url = "https://user:pass' + '@example.test/api"\nif'), 'settings.py'),
            (('url = "https://user:p%61ss' + '@example.test/api"'), 'settings.py'),
            (('url = "https://user:pass' + '@ex%61mple.test/api"'), 'settings.py'),
            (('url = "https://user:pass' + '@example.test/api%20path"'), 'settings.py'),
            (('url = "https://user:pass' + ('@exam' + ('ple.' + ('test' + '@actual.example.com/api"')))), 'settings.py'),
            (('url = r"https://user:pass' + '@example.test\\@actual.org/api"'), 'settings.py'),
            (('url = "http' + 's://user:pass' + '@example.test/api" "suffix"'), 'settings.py'),
        ):
            with self.subTest(source=source, path=path):
                self.assertTrue(self.credentials(source, path=path))

    def test_later_credentials_keys_and_private_terms_stay_blocking(self):
        source = ('urls = ["https://user:pass' + '@example.test/api","https://user:actu' + ('al-p' + ('assw' + ('ord-' + 'value@' + 'example.test/api"]'))))
        self.assertEqual(len(self.credentials(source)), 1)
        token = 'gh' + 'p_' + ('Ab3D' + '4e5F6g7H8i9J0kL1mN2oP3qR4sT5')
        findings = self.scan(('url = "https://user:pass' + '@' + 'example.test/') + token + '"', terms=['example.test'])
        kinds = {f['kind'] for f in findings}
        self.assertTrue({'github-token', 'denylist'} <= kinds)
        self.assertTrue(all(not f['reviewed'] for f in findings))
