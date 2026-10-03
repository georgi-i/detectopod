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
import rules  # noqa: E402


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


class ExtractDomains(unittest.TestCase):
    def test_sources_dedupe_and_url_fallback(self):
        results = [
            {'page': {'domain': 'a.top', 'url': 'http://a.top/x'}, 'task': {'time': 't1'}},
            {'page': {'domain': 'a.top'}},                                  # duplicate
            {'task': {'domain': 'b.top'}},                                  # task fallback
            {'page': {'url': 'https://c.top/login'}},                       # url fallback
            {'page': {}},                                                   # nothing usable
        ]
        out = detectopod.extract_domains(results, set(), 'urlscan.io-.top')
        self.assertEqual([d['domain'] for d in out], ['a.top', 'b.top', 'c.top'])
        self.assertEqual(out[0]['source'], 'urlscan.io-.top')
        self.assertEqual(out[0]['scan_time'], 't1')


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


class RuleBasedTriage(unittest.TestCase):
    def test_certain_phishing(self):
        for d in ['speedy.bg-iw.qpon', 'econt.bg-g63829.cfd', 'econt-bg.an537294.sbs', 'bgpost-bga.life',
                  'mvrbg.cam', 'gav.mvrbg.cam', 'mvr-bg.cfd', 'www.mvrbg.sbs', 'mvr-gov-mk.shop',
                  'e-uslugicye.top', 'tollpass.klgf.cam', 'tollpassapp.top', 'tollpassss.cc',
                  'econt.png4kx.icu']:
            self.assertIsNotNone(rules.rule_based_decision(d), d)

    def test_left_to_the_llm(self):
        for d in ['fxktmvrbgsblq.top',            # mvrbg buried inside a random string
                  'tollpass.online', 'tollpass.icu', 'econt.shop', 'bgpost.one',   # apex domains
                  'speedy-glass.cfd', 'speedy-delivery.online',
                  'test.tollpass.klgf.cam', 'dev.mvrbg.cam',   # dev/test hosts are never auto-blocked
                  'e-uslugi.mvr.bg', 'tollpass.bg', 'mvr.qdoz.cam']:
            self.assertIsNone(rules.rule_based_decision(d), d)

    def test_never_matches_the_reviewed_false_positives(self):
        path = os.path.join(os.path.dirname(__file__), '..', 'feed', 'false_positives.json')
        with open(path) as f:
            for entry in json.load(f):
                self.assertIsNone(rules.rule_based_decision(entry['domain']), entry['domain'])


class FakeResponse:
    def __init__(self, status, body=None, text=''):
        self.status_code, self._body, self.text = status, body, text

    def json(self):
        return self._body


def ok_body(decision='BLOCK'):
    content = json.dumps({'threat_level': 'HIGH', 'confidence': 90, 'indicators': [], 'decision': decision})
    return {'choices': [{'message': {'content': content}, 'finish_reason': 'stop'}]}


class RateLimitHandling(unittest.TestCase):
    def setUp(self):
        self.sleeps = []
        self._sleep, self._post, self._interval = (llm_analyzer.time.sleep, llm_analyzer.requests.post,
                                                   llm_analyzer.MIN_REQUEST_INTERVAL)
        llm_analyzer.time.sleep = self.sleeps.append
        llm_analyzer.MIN_REQUEST_INTERVAL = 0

    def tearDown(self):
        llm_analyzer.time.sleep, llm_analyzer.requests.post = self._sleep, self._post
        llm_analyzer.MIN_REQUEST_INTERVAL = self._interval

    def run_analyzer(self, responses):
        calls = []

        def post(url, headers, json, timeout):
            calls.append(json['model'])
            return responses[len(calls) - 1]
        llm_analyzer.requests.post = post
        return llm_analyzer.GeminiAnalyzer('k').analyze_domain('x.top', 100, [], {}), calls

    def test_429_falls_through_to_the_other_model_without_sleeping(self):
        result, calls = self.run_analyzer([FakeResponse(429, text='quota'), FakeResponse(200, ok_body())])
        self.assertEqual(calls, [llm_analyzer.MODEL, llm_analyzer.MODEL_FALLBACK])
        self.assertEqual(result['model'], llm_analyzer.MODEL_FALLBACK)
        self.assertEqual(self.sleeps, [])

    def test_both_models_limited_cools_down_once_then_gives_up(self):
        result, calls = self.run_analyzer([FakeResponse(429, text='quota')] * 4)
        self.assertIsNone(result)
        self.assertEqual(len(calls), 4)                      # 2 models x 2 rounds
        self.assertEqual(self.sleeps, [llm_analyzer.RATE_LIMIT_COOLDOWN])


class MainWithRules(unittest.TestCase):
    def test_rule_hits_are_free_and_llm_budget_applies_to_the_rest(self):
        with tempfile.TemporaryDirectory() as tmp:
            feed = os.path.join(tmp, 'phishing_feed.json')
            domains = ['mvrbg.cam', 'tollpass.klgf.cam',                      # rules
                       'speedy-delivery.online', 'econt.shop', 'bgpost.one']  # LLM
            with open(feed, 'w') as f:
                json.dump([{'domain': d, 'score': 100, 'detected_at': '2999-01-01T00:00:00'} for d in domains], f)
            with open(os.path.join(tmp, 'false_positives.json'), 'w') as f:
                json.dump([], f)

            asked = []

            def fake(self, domain, score, kw, entry):
                asked.append(domain)
                return {'analysis': '{}', 'model': 'm', 'timestamp': 't', 'threat_level': 'HIGH',
                        'confidence': 9, 'decision': 'BLOCK'}
            original = llm_analyzer.GeminiAnalyzer.analyze_domain
            llm_analyzer.GeminiAnalyzer.analyze_domain = fake
            os.environ['GEMINI_API_KEY'] = 'x'
            argv, sys.argv = sys.argv, ['x', '--days', '400', '--max-analyze', '2', '--feed-file', feed]
            try:
                llm_analyzer.main()
            finally:
                llm_analyzer.GeminiAnalyzer.analyze_domain, sys.argv = original, argv

            self.assertEqual(len(asked), 2)                      # budget of 2 applies to LLM domains only
            with open(feed) as f:
                result = {e['domain']: e.get('llm_analysis') for e in json.load(f)}
            self.assertEqual(result['mvrbg.cam']['model'], 'rule-based')
            self.assertEqual(result['tollpass.klgf.cam']['model'], 'rule-based')
            self.assertEqual(sum(1 for v in result.values() if v is None), 1)   # one left for next run


if __name__ == '__main__':
    unittest.main()
