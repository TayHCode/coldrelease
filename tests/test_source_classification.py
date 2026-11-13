import unittest

import release_check as rc


class SourceClassificationTests(unittest.TestCase):
    def scan(self, text, path='module.py', scope='tree', encoding='utf-8', terms=(), repos=()):
        scanner = rc.Scanner(list(terms), private_repos=list(repos))
        scanner.file(text.encode(encoding), scope, path, object_id='testbed')
        return scanner.findings

    def hosts(self, text, **kwargs):
        return [f['line'] for f in self.scan(text, **kwargs) if f['kind'] == 'internal-host']

    def test_attributes_only_at_their_source_occurrences(self):
        for scope in ('tree', 'history'):
            with self.subTest(scope=scope):
                self.assertEqual(self.hosts(('self' + '.home\nself' + '.local\nself.settings' + '.home\n'), scope=scope), [])
                self.assertEqual(self.hosts(('self' + ('.home\n"self' + ('.home"\n# self' + '.home\n'))), scope=scope), [2, 3])
                self.assertEqual(self.hosts(('self' + ('.local; "self' + ('.local" # self' + '.local\n'))), scope=scope), [1])

    def test_unicode_and_line_endings_preserve_offsets(self):
        for separator in ('\n', '\r\n', '\r'):
            text = separator.join((('label = "é雪😀"; self' + '.home'), ('é.l' + 'ocal'), ('"é.l' + 'ocal"'), ('# self' + '.home')))
            with self.subTest(separator=repr(separator)):
                self.assertEqual(self.hosts(text), [3, 4])
        self.assertEqual(self.hosts(('label = "\u2028"; self' + ('.home\n"self' + '.home"'))), [3])

    def test_comments_inside_multiline_attributes_remain_scanned(self):
        self.assertEqual(self.hosts(('(self\n # serv' + ('er.l' + 'ocal\n .home)\n'))), [2])
        self.assertEqual(self.hosts('(self\n .home)\n'), [])

    def test_invalid_python_other_files_and_non_name_roots_still_scan(self):
        for text, path in ((('self' + '.home\nif :'), 'module.py'), (('self' + '.local'), 'module.txt'),
                           (('self' + '.home'), 'module.py.txt'), (('("serv' + ('er.l' + 'ocal").home')), 'module.py')):
            with self.subTest(text=text, path=path):
                self.assertTrue(self.hosts(text, path=path))
        self.assertEqual(self.hosts(('"serv' + ('er.l' + 'ocal"\n# data') + ('base' + '.internal\n'))), [1, 2])

    def test_paths_terms_and_explicit_secrets_are_not_exempt(self):
        self.assertTrue(self.hosts(('self' + '.home'), path=('self' + '.home/settings.py')))
        for encoding in ('utf-8', 'utf-16'):
            findings = self.scan(('self' + '.home\n"/hom' + 'e/testbed/settings"\n"api_key=synt' + 'hetic-password"'),
                                 encoding=encoding, terms=[('self' + '.home')])
            self.assertTrue({'denylist', 'home-path', 'assigned-secret'} <= {f['kind'] for f in findings})
        self.assertTrue(self.hosts(('self' + '.home\n"serv' + ('er.l' + 'ocal"')), encoding='utf-16'))

    def test_private_keyword_uses_only_url_path(self):
        for scope in ('tree', 'history'):
            for encoding in ('utf-8', 'utf-16'):
                for host in ('example.invalid', 'github.com'):
                    with self.subTest(scope=scope, encoding=encoding, host=host):
                        clean = self.scan(f'"https://{host}/public?visibility=private#private"', scope=scope, encoding=encoding)
                        self.assertNotIn('private-repo-url', [f['kind'] for f in clean])
                        private = self.scan((f'"https://{host}/team/' + 'private/repo?visibility=public"'), scope=scope, encoding=encoding)
                        self.assertIn('private-repo-url', [f['kind'] for f in private])
        self.assertNotIn('private-repo-url', [f['kind'] for f in self.scan('"https://example.invalid?next=/private/repo"')])

    def test_internal_known_private_urls_and_query_secrets_still_scan(self):
        for url in (('http' + 's://gitl' + ('ab.i' + 'nternal/team/public')), ('git@' + 'gitl' + ('ab.i' + 'nternal:team/public'))):
            self.assertIn('private-repo-url', [f['kind'] for f in self.scan(repr(url))])
        findings = self.scan('"https://github.com/testbed/hidden?visibility=private"', repos=['testbed/hidden'])
        self.assertIn('private-repo-url', [f['kind'] for f in findings])
        findings = self.scan(('"https://example.invalid/public?private=yes&api_key=synt' + 'hetic-password"'))
        self.assertIn('assigned-secret', [f['kind'] for f in findings])
        self.assertNotIn('private-repo-url', [f['kind'] for f in findings])
        findings = self.scan('"https://example.invalid/public?next=testbed/hidden"', repos=['testbed/hidden'])
        self.assertIn('private-repo-url', [f['kind'] for f in findings])
