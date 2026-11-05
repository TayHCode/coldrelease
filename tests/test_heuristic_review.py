import hashlib
import unittest

import release_check as rc


class HeuristicReviewTests(unittest.TestCase):
    def test_review_binds_the_exact_occurrence(self):
        raw = ((b'password = cred' + b'entials.value; password = cred' + b'entials.value\n') +
               (b'password = cred' + b'entials.value\n'))
        first = rc.Scanner([])
        first.file(raw, 'tree', 'example.ts')
        finding = next(f for f in first.findings if f['kind'] == 'assigned-secret')
        approval = {**finding, 'classification': 'false-positive', 'reason': 'Reviewed only this occurrence.'}
        scanner = rc.Scanner([], approvals=[approval])
        scanner.file(raw, 'tree', 'example.ts')
        self.assertEqual([f['reviewed'] for f in scanner.findings if f['kind'] == 'assigned-secret'],
                         [True, False, False])

    def test_many_matches_hash_the_source_only_once(self):
        from unittest.mock import patch
        raw = (b'password = cred' + b'entials.value\n') * 20
        real_sha256 = hashlib.sha256
        with patch.object(rc.hashlib, 'sha256', wraps=real_sha256) as hashed:
            scanner = rc.Scanner([])
            scanner.file(raw, 'tree', 'example.ts')
        matches = [f for f in scanner.findings if f['kind'] == 'assigned-secret']
        self.assertEqual(len(matches), 20)
        self.assertEqual({f['source_sha256'] for f in matches}, {real_sha256(raw).hexdigest()})
        self.assertEqual(sum(call.args == (raw,) for call in hashed.call_args_list), 1)

    def test_entropy_review_keeps_private_terms_blocking(self):
        import base64
        value = 'sha512-' + base64.b64encode(bytes(range(64))).decode()
        raw = ('checksum = "' + value + '"\nHiddenPerson\n').encode()
        first = rc.Scanner(['HiddenPerson'])
        first.file(raw, 'tree', 'bun.lock')
        finding = next(f for f in first.findings if f['kind'] == 'entropy')
        approval = {**finding, 'classification': 'false-positive', 'reason': 'Reviewed package checksum.'}
        scanner = rc.Scanner(['HiddenPerson'], approvals=[approval])
        scanner.file(raw, 'tree', 'bun.lock')
        self.assertTrue(next(f for f in scanner.findings if f['kind'] == 'entropy')['reviewed'])
        self.assertTrue(any(f['kind'] == 'denylist' and not f['reviewed'] for f in scanner.findings))
        scanner = rc.Scanner([], approvals=[approval])
        scanner.file(raw + b'changed\n', 'tree', 'bun.lock')
        self.assertFalse(next(f for f in scanner.findings if f['kind'] == 'entropy')['reviewed'])

    def test_exact_review_is_bound_to_the_whole_source_file(self):
        raw = (b'password = cred' + b'entials.value\n')
        scanner = rc.Scanner([])
        scanner.file(raw, 'tree', 'example.ts')
        finding, = [f for f in scanner.findings if f['kind'] == 'assigned-secret']
        approval = {key: finding[key] for key in ('scope', 'kind', 'path', 'fingerprint', 'source_sha256', 'line', 'column')}
        approval.update(classification='false-positive', reason='Code member access, not a credential literal.')
        reviewed = rc.Scanner([], approvals=[approval])
        reviewed.file(raw, 'tree', 'example.ts')
        self.assertTrue(next(f for f in reviewed.findings if f['kind'] == 'assigned-secret')['reviewed'])
        for mutation in ({'source_sha256': '0' * 64}, {'classification': None}, {'reason': ''}, {'path': 'other.ts'}):
            scanner = rc.Scanner([], approvals=[{**approval, **mutation}])
            scanner.file(raw, 'tree', 'example.ts')
            self.assertFalse(next(f for f in scanner.findings if f['kind'] == 'assigned-secret')['reviewed'])
        changed = rc.Scanner([], approvals=[approval])
        changed.file(raw + b'// changed\n', 'tree', 'example.ts')
        self.assertFalse(next(f for f in changed.findings if f['kind'] == 'assigned-secret')['reviewed'])

    def test_explicit_secret_shapes_cannot_be_approved(self):
        raw = ('ghp_' + 'Ab1Cd2Ef3Gh4' * 3).encode()
        initial = rc.Scanner([])
        initial.file(raw, 'tree', 'example.ts')
        approvals = [{**f, 'source_sha256': hashlib.sha256(raw).hexdigest(),
                      'classification': 'false-positive', 'reason': 'Not allowed.'}
                     for f in initial.findings]
        scanner = rc.Scanner([], approvals=approvals)
        scanner.file(raw, 'tree', 'example.ts')
        self.assertTrue(any(f['kind'] == 'github-token' and not f['reviewed'] for f in scanner.findings))

    def test_review_reason_cannot_contain_a_private_term(self):
        raw = (b'password = cred' + b'entials.value\n')
        scanner = rc.Scanner([])
        scanner.file(raw, 'tree', 'example.ts')
        approval = {**scanner.findings[0], 'classification': 'false-positive', 'reason': 'HiddenPerson approved.'}
        scanner = rc.Scanner(['HiddenPerson'], approvals=[approval])
        scanner.file(raw, 'tree', 'example.ts')
        self.assertFalse(scanner.findings[0]['reviewed'])
