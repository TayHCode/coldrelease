import unittest

import release_check as rc

RAW = (b'first = "203.' + b'0.113.7"\nsecond = "203.' + b'0.113.8"\n')
REASON = 'Documentation-range address used as an example, not a real host.'


def scan(raw, approvals=(), terms=(), path='example.ts', scope='tree'):
    scanner = rc.Scanner(list(terms), approvals=list(approvals))
    scanner.file(raw, scope, path)
    return scanner


def findings(scanner, kind):
    return [f for f in scanner.findings if f['kind'] == kind]


def approval_for(finding, **changes):
    approval = {key: finding[key] for key in ('scope', 'kind', 'path', 'fingerprint', 'line') if key in finding}
    if 'source_sha256' in finding:
        approval['source_sha256'] = finding['source_sha256']
    approval.update(classification='false-positive', reason=REASON)
    approval.update(changes)
    return {key: value for key, value in approval.items() if value is not None}


class PersonalReviewTests(unittest.TestCase):
    def setUp(self):
        self.first, self.second = findings(scan(RAW), 'ipv4')
        self.approval = approval_for(self.first)

    def test_reviewed_false_positive_clears_only_that_finding(self):
        scanner = scan(RAW, [self.approval])
        self.assertEqual([f['reviewed'] for f in findings(scanner, 'ipv4')], [True, False])
        reviewed = findings(scanner, 'ipv4')[0]
        self.assertEqual(reviewed['reason'], REASON)
        self.assertEqual(reviewed['review_status'], 'accepted as exact-source false positive')

    def test_changed_bytes_invalidate_the_review(self):
        for raw in (RAW + b'unrelated = 1\n', b'\n' + RAW):
            self.assertFalse(any(f['reviewed'] for f in findings(scan(raw, [self.approval]), 'ipv4')))

    def test_review_needs_a_written_reason(self):
        for reason in (None, '', '   ', 5):
            approval = approval_for(self.first, reason=reason)
            if reason is None:
                approval.pop('reason', None)
            self.assertFalse(any(f['reviewed'] for f in findings(scan(RAW, [approval]), 'ipv4')), reason)

    def test_review_must_be_classified_and_bound_to_the_source(self):
        for change in ({'classification': 'accepted'}, {'classification': ''},
                       {'source_sha256': '0' * 64}, {'line': 2}, {'line': 99}):
            approval = approval_for(self.first, **change)
            self.assertFalse(any(f['reviewed'] for f in findings(scan(RAW, [approval]), 'ipv4')), change)
        unbound = approval_for(self.first)
        del unbound['source_sha256']
        self.assertFalse(any(f['reviewed'] for f in findings(scan(RAW, [unbound]), 'ipv4')))

    def test_no_wildcard_or_blanket_suppression(self):
        for change in ({'path': '*'}, {'path': 'example.ts/'}, {'fingerprint': '*'}, {'fingerprint': ''},
                       {'kind': '*'}, {'kind': 'email'}, {'scope': 'history'}, {'scope': '*'}):
            approval = approval_for(self.first, **change)
            self.assertFalse(any(f['reviewed'] for f in scan(RAW, [approval]).findings), change)
        for key in ('path', 'fingerprint', 'kind', 'scope'):
            approval = {k: v for k, v in self.approval.items() if k != key}
            self.assertFalse(any(f['reviewed'] for f in scan(RAW, [approval]).findings), key)

    def test_review_does_not_move_to_another_file(self):
        self.assertFalse(any(f['reviewed'] for f in findings(scan(RAW, [self.approval], path='other.ts'), 'ipv4')))

    def test_genuine_personal_data_stays_flagged(self):
        raw = (b'owner = "HiddenPerson"\nmail = "some' + (b'one@' + b'example.org"\n'))
        first = scan(raw, terms=['HiddenPerson'])
        denylist, = findings(first, 'denylist')
        email, = findings(first, 'email')
        self.assertFalse(denylist['reviewed'] or email['reviewed'])
        bad = [approval_for(denylist, reason='HiddenPerson is fine.'), approval_for(email, reason='')]
        scanner = scan(raw, bad, terms=['HiddenPerson'])
        self.assertFalse(any(f['reviewed'] for f in scanner.findings))
        good = [approval_for(denylist), approval_for(email)]
        scanner = scan(raw, good, terms=['HiddenPerson'])
        self.assertTrue(all(f['reviewed'] for f in scanner.findings if f['category'] == 'personal'))
        self.assertFalse(any(f['reviewed'] for f in scan(raw + b'HiddenPerson2\n', good, terms=['HiddenPerson2']).findings))

    def test_media_review_needs_reason_and_exact_bytes(self):
        raw = b'\x89PNG\r\n\x1a\n\0example'
        first = scan(raw, path='image.png')
        media, = findings(first, 'manual-review')
        approval = approval_for(media)
        self.assertTrue(findings(scan(raw, [approval], path='image.png'), 'manual-review')[0]['reviewed'])
        for bad in (approval_for(media, reason=''), approval_for(media, classification='accepted')):
            self.assertFalse(findings(scan(raw, [bad], path='image.png'), 'manual-review')[0]['reviewed'])
        self.assertFalse(findings(scan(raw + b'x', [approval], path='image.png'), 'manual-review')[0]['reviewed'])
        self.assertFalse(findings(scan(raw, [approval], path='other.png'), 'manual-review')[0]['reviewed'])


if __name__ == '__main__':
    unittest.main()
