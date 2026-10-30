import unittest
from rules import run_analysis, compute_risk, parse_url

class RuleTests(unittest.TestCase):
    def test_password_request(self):
        r=run_analysis('Please send me your password.')
        self.assertEqual(r['risk'],'medium')
        self.assertEqual(r['message_findings'][2]['evidence'],'send me your password')

    def test_warning_is_not_request(self):
        r=run_analysis('Your OTP is 123456. Do not share this OTP with anyone.')
        self.assertFalse(r['message_findings'][2]['triggered'])

    def test_request_after_warning(self):
        r=run_analysis('Never share your OTP. Please send me your password.')
        self.assertTrue(r['message_findings'][2]['triggered'])

    def test_embedded_links(self):
        r=run_analysis('Open http://192.168.1.5/login immediately.')
        self.assertTrue(r['has_url']);self.assertEqual(r['url_score'],30)

    def test_multiple_links_deduplicated(self):
        r=run_analysis('https://bit.ly/a https://bit.ly/b https://bit.ly/a')
        self.assertEqual(len(r['url_reports']),2);self.assertEqual(r['url_score'],10)

    def test_brand_deception(self):
        for url in ['https://www.paypa1.com','https://paypal.com.attacker-example.test']:
            self.assertGreaterEqual(run_analysis('',url)['url_score'],20)

    def test_official_subdomains(self):
        for url in ['https://www.paypal.com','https://retail.sbi.co.in']:
            self.assertEqual(run_analysis('',url)['url_score'],0)
        self.assertEqual(parse_url('https://retail.sbi.co.in')['registered_domain'],'sbi.co.in')

    def test_at_symbol(self):
        self.assertEqual(run_analysis('','https://example.com/?email=user@example.com')['score'],0)
        self.assertGreaterEqual(run_analysis('','https://paypal.com@evil.test')['score'],20)

    def test_scheme(self):
        self.assertEqual(run_analysis('','HTTPS://example.com')['score'],0)
        r=run_analysis('','example.com');self.assertEqual(r['score'],0)
        self.assertIsNone(r['url_reports'][0]['protocol'])

    def test_ipv6(self):
        self.assertEqual(run_analysis('','https://[2001:db8::1]')['url_score'],20)

    def test_invalid_urls(self):
        for url in ['http://[bad','https://example.com:99999','javascript://example.com','https://a b.test','https://xn--a.com']:
            with self.assertRaises(ValueError): run_analysis('',url)
        r=run_analysis('Open http://[bad now')
        self.assertFalse(r['analysis_complete'])

    def test_thresholds(self):
        self.assertEqual([compute_risk(x) for x in [19,20,49,50]],['low','medium','medium','high'])

    def test_internationalized(self):
        r=run_analysis('','https://xn--bcher-kva.de')
        self.assertTrue(r['url_findings'][-1]['triggered'])

    def test_message_rules(self):
        r=run_analysis('URGENT!! Dear customer, you have won a free gift. Failure to comply brings a penalty.')
        for id in ['urgency_language','threat_language','generic_greeting','reward_bait','excessive_emphasis']:
            self.assertTrue(next(f for f in r['message_findings'] if f['id']==id)['triggered'])

    def test_link_limit(self):
        with self.assertRaises(ValueError):run_analysis(' '.join(f'https://example.com/{i}' for i in range(11)))

if __name__=='__main__':unittest.main()
