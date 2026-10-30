import unittest
from rules import run_analysis, extract_urls
import test_app
import database as db
from evaluation_cases import build_cases


class DetectionTests(unittest.TestCase):
    def test_requests_and_matching_benign_context(self):
        pairs = [
            ('Please confirm your employee ID on this portal.', 'Your employee ID was updated.'),
            ('Transfer payment to our new bank account.', 'Do not transfer payment to a new bank account.'),
            ('Update KYC today or your account will be blocked.', 'Your KYC review is complete.'),
            ('Apna OTP bhejo.', 'Apna OTP mat bhejo.'),
            ('अपना पासवर्ड भेजें।', 'अपना पासवर्ड साझा न करें।'),
        ]
        for request, benign in pairs:
            with self.subTest(request=request):
                self.assertGreaterEqual(run_analysis(request)['score'], 20)
                self.assertEqual(run_analysis(benign)['score'], 0)

    def test_warning_then_separate_request(self):
        self.assertGreaterEqual(run_analysis('OTP mat bhejo; lekin password bhejo')['score'], 20)

    def test_bare_and_disguised_links_preserve_original(self):
        r = run_analysis('See example.com/help and hxxps://paypa1[.]com/login')
        self.assertEqual(len(r['url_reports']), 2)
        u = r['url_reports'][1]
        self.assertEqual(u['raw'], 'hxxps://paypa1[.]com/login')
        self.assertEqual(u['normalized_url'], 'https://paypa1.com/login')
        self.assertTrue(u['normalization_applied'])
        self.assertGreaterEqual(r['score'], 20)

    def test_no_email_version_or_query_false_destinations(self):
        self.assertEqual(extract_urls('Write user@example.co.in version 2.1.0 document.pdf'), [])
        self.assertEqual(len(extract_urls('https://example.com/?next=other.com&email=a@bank.co.in')), 1)
        self.assertEqual(extract_urls('Open www.example.test'), ['www.example.test'])

    def test_parenthesized_dot_and_query_preservation(self):
        u = run_analysis('', 'hxxp://example(.)com/?q=[.]')['url_reports'][0]
        self.assertEqual(u['normalized_url'], 'http://example.com/?q=[.]')

    def test_splits_are_family_disjoint(self):
        dev, heldout = build_cases('dev'), build_cases('heldout')
        self.assertEqual(len(dev) + len(heldout), 320)
        self.assertFalse({r['family'] for r in dev} & {r['family'] for r in heldout})
        self.assertEqual(len({(r['text'], r['url']) for r in dev + heldout}), 320)


class PrivacyTests(unittest.TestCase):
    setUp = test_app.AppTests.setUp
    tearDown = test_app.AppTests.tearDown
    post = test_app.AppTests.post

    def test_default_is_private_in_api_and_ui(self):
        self.assertFalse(self.post({'message':'Hello'}).json['saved'])
        self.assertEqual(db.list_scans(path=self.path)['total'], 0)
        self.assertNotIn('id="save" checked', self.client.get('/').get_data(as_text=True))

    def test_expiry_preserves_unexpired_and_legacy(self):
        old = db.log_scan('legacy', '', 0, 'low', path=self.path)
        saved = self.post({'message':'hello', 'save_history':True, 'retention_days':7}).json['scan_id']
        keep = self.post({'message':'keep', 'save_history':True, 'retention_days':0}).json['scan_id']
        self.assertIsNotNone(db.get_scan(saved, self.path)['expires_at'])
        self.assertIsNone(db.get_scan(keep, self.path)['expires_at'])
        self.assertEqual(self.client.get('/api/history').json['total'], 3)
        with db.connection(self.path) as conn:
            conn.execute("UPDATE scan_history SET expires_at='2000-01-01' WHERE id=?", (saved,))
        self.assertEqual(self.client.get(f'/api/history/{saved}').status_code, 404)
        self.assertEqual(self.client.get('/api/history').json['total'], 2)
        self.assertIsNotNone(db.get_scan(old, self.path))

    def test_retention_validation(self):
        for value in [-1, 1, True, '30', None]:
            self.assertEqual(self.post({'message':'hello', 'retention_days':value}).status_code, 400)
