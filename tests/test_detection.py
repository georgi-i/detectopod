"""Offline tests: python -m unittest discover -s tests  (run from the repo root)."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'detection'))
os.environ.setdefault('URLSCAN_API_KEY', 'x')

import detectopod  # noqa: E402
import feedlib  # noqa: E402
import llm_analyzer  # noqa: E402


class FalsePositiveMatching(unittest.TestCase):
    def setUp(self):
        self.fp = feedlib.FalsePositives([
            {'domain': 'tollpass.xyz', 'subdomains': True},
            {'domain': 'exact.top'},
        ])

    def test_subtree(self):
        for d in ['tollpass.xyz', 'www.tollpass.xyz', 'test.tollpass.xyz',
                  'www.ucntbtest.tollpass.xyz', 'A.B.TollPass.xyz.']:
            self.assertIn(d, self.fp)

    def test_exact_only(self):
        self.assertIn('www.exact.top', self.fp)
        self.assertNotIn('sub.exact.top', self.fp)

    def test_unrelated(self):
        self.assertNotIn('tollpass.klgf.cam', self.fp)
        self.assertNotIn('nottollpass.xyz', self.fp)
        self.assertNotIn('xyz', self.fp)


class ScanEndToEnd(unittest.TestCase):
    def test_fp_dev_and_dedupe(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = os.path.join(tmp, 'phishing_feed.json')
            fpf = os.path.join(tmp, 'false_positives.json')
            json.dump([{'domain': 'mvrbg.sbs', 'score': 100}], open(feed, 'w'))
            json.dump([{'domain': 'tollpass.xyz', 'subdomains': True}], open(fpf, 'w'))

            domains = ['test.tollpass.xyz', 'www.dev.tollpass.xyz',   # false positive
                       'dev.tollpass.klgf.cam',                      # dev host
                       'www.mvrbg.sbs',                              # already in feed (www dup)
                       'tollpass.klgf.cam', 'www.tollpass.klgf.cam']  # new, listed twice
            detectopod.query_urlscan = lambda kw, max_results=0: [
                {'domain': d, 'source': 'urlscan.io'} for d in domains]
            detectopod.query_urlscan_recent = lambda **kw: []
            detectopod.OUTPUT_FILE = feed
            feedlib.FALSE_POSITIVES_FILE = fpf
            detectopod.time.sleep = lambda s: None

            detectopod.scan_domains(sources=['urlscan'])

            with open(feed) as f:
                result = json.load(f)
            self.assertEqual([e['domain'] for e in result], ['mvrbg.sbs', 'tollpass.klgf.cam'])
            self.assertEqual(result[1]['keywords'], ['tollpass'])


class LlmParsing(unittest.TestCase):
    a = llm_analyzer.GeminiAnalyzer('k')

    def test_valid(self):
        r = self.a._parse_response('{"threat_level":"high","confidence":"97","decision":"block"}')
        self.assertEqual(r, {'threat_level': 'HIGH', 'decision': 'BLOCK', 'confidence': 97})

    def test_fenced(self):
        r = self.a._parse_response('```json\n{"threat_level":"LOW","confidence":80,"decision":"FALSE_POSITIVE"}\n```')
        self.assertEqual(r['decision'], 'FALSE_POSITIVE')

    def test_unusable(self):
        for bad in ['', 'Based on the provided rules and domain details',
                    '{"threat_level":"HIGH"', '{"threat_level":"HIGH","decision":"MAYBE"}']:
            self.assertIsNone(self.a._parse_response(bad))


if __name__ == '__main__':
    unittest.main()
