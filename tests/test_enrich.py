import unittest
from unittest.mock import patch, MagicMock
import urllib.error
import enrich as e

class EnrichmentTests(unittest.TestCase):
    def test_normalize_deduplicate(self):
        r=e.run(['PORTAL[.]lab.test.','portal.lab.test','2001:db8:0::1'],fixtures={})
        self.assertEqual(len(r['indicators']),2)
        self.assertEqual(e.normalize('A'*64),('sha256','a'*64))
    def test_bad_inputs(self):
        for v in ['https://lab.test/?token=secret','person@lab.test','999.1.1.1','-bad.test','x\n.test','']:
            with self.subTest(v=v), self.assertRaises(ValueError): e.normalize(v)
    def test_offline_no_network(self):
        with patch('urllib.request.build_opener',side_effect=AssertionError('network')):
            self.assertEqual(e.run(['192.0.2.10'],fixtures={})['indicators'][0]['results'][0]['status'],'no_fixture')
    def test_vt_request_projection(self):
        def fake(url,headers):
            self.assertEqual(url,'https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8')
            self.assertEqual(headers,{'x-apikey':'test-only'})
            return {'data':{'attributes':{'last_analysis_stats':{'malicious':0},'private':'discard'}}}
        self.assertEqual(e.VirusTotal('test-only',fake).lookup('ip','8.8.8.8'),{'analysis_stats':{'malicious':0}})
    def test_abuse_ipv6(self):
        def fake(url,headers):
            self.assertIn('ipAddress=2606%3A4700%3A4700%3A%3A1111',url)
            self.assertIn('maxAgeInDays=90',url)
            return {'data':{'abuseConfidenceScore':0,'totalReports':0}}
        a=e.AbuseIPDB('test-only',fake)
        self.assertEqual(a.lookup('ip','2606:4700:4700::1111')['total_reports'],0)
        self.assertEqual(a.lookup('domain','lab.test')['status'],'unsupported_type')
    def test_reserved_not_queried(self):
        def forbidden(*a): raise AssertionError('network')
        for v in ['127.0.0.1','192.0.2.1','::1','224.0.0.1','x.test','example.com']:
            r=e.run([v],providers=[e.VirusTotal('test',forbidden)])
            self.assertEqual(r['indicators'][0]['results'][0]['status'],'blocked_nonpublic_or_reserved')
    def test_http_error_redaction(self):
        for code,status in [(401,'unauthorized'),(403,'forbidden'),(404,'not_found'),(429,'rate_limited'),(302,'http_error'),(500,'http_error')]:
            error=urllib.error.HTTPError('https://provider/',code,'SECRET',{},None)
            with patch('urllib.request.OpenerDirector.open',side_effect=error):
                with self.assertRaisesRegex(e.ProviderError,status): e.get_json('https://provider/',{})
    def test_transport_failures(self):
        with patch('urllib.request.OpenerDirector.open',side_effect=TimeoutError('secret')):
            with self.assertRaisesRegex(e.ProviderError,'network_error'): e.get_json('https://provider/',{})
        response=MagicMock(); response.__enter__.return_value.read.return_value=b'not-json'
        with patch('urllib.request.OpenerDirector.open',return_value=response):
            with self.assertRaisesRegex(e.ProviderError,'invalid_json'): e.get_json('https://provider/',{})
    def test_bad_schema_partial_success(self):
        bad=e.VirusTotal('test',lambda *a:{})
        good=e.AbuseIPDB('test',lambda *a:{'data':{'abuseConfidenceScore':4,'totalReports':2}})
        result=e.run(['8.8.8.8'],[bad,good])
        self.assertEqual([x['status'] for x in result['indicators'][0]['results']],['invalid_schema','ok'])
        with self.assertRaises(e.ProviderError):
            e.AbuseIPDB('test',lambda *a:{'data':{'abuseConfidenceScore':101,'totalReports':0}}).lookup('ip','8.8.8.8')
    def test_prevalidate_entire_batch(self):
        with self.assertRaises(ValueError): e.run(['lab.test']*101,fixtures={})
        def forbidden(*a): raise AssertionError('network')
        with self.assertRaises(ValueError): e.run(['8.8.8.8','bad!'],[e.VirusTotal('test',forbidden)])

class CliTests(unittest.TestCase):
    def test_cli_offline_and_live_gate(self):
        import subprocess, sys, json
        from pathlib import Path
        root=Path(__file__).resolve().parents[1]
        command=[sys.executable,str(root/'enrich.py'),str(root/'examples/iocs.txt')]
        result=subprocess.run(command,capture_output=True,text=True,cwd=root)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['mode'],'synthetic_offline')
        result=subprocess.run(command+['--live'],capture_output=True,text=True,cwd=root)
        self.assertEqual(result.returncode,2)
        self.assertIn('live requires',result.stderr)
    def test_vt_all_resource_paths(self):
        for kind,value,path in [('domain','lab.test','domains/lab.test'),('sha256','a'*64,'files/'+'a'*64)]:
            def fake(url,headers):
                self.assertTrue(url.endswith(path))
                return {'data':{'attributes':{'last_analysis_stats':{'undetected':1}}}}
            self.assertEqual(e.VirusTotal('test',fake).lookup(kind,value)['analysis_stats'],{'undetected':1})
    def test_scoped_ipv6_and_idn(self):
        with self.assertRaises(ValueError): e.normalize('2606:4700:4700::1111%secret')
        self.assertEqual(e.normalize('xn--e1afmkfd.xn--p1ai')[0],'domain')
    def test_redirect_not_followed(self):
        import urllib.request
        opener=MagicMock()
        response=MagicMock(); response.__enter__.return_value.read.return_value=b'{}'
        opener.open.return_value=response
        with patch('urllib.request.build_opener',return_value=opener) as builder:
            e.get_json('https://provider/',{'Key':'test-only'})
        handler=builder.call_args.args[0]
        self.assertIsNone(handler.redirect_request(None,None,302,'',{},'https://other/'))
    def test_size_and_schema_limits(self):
        response=MagicMock(); response.__enter__.return_value.read.return_value=b'x'*1_000_001
        with patch('urllib.request.OpenerDirector.open',return_value=response):
            with self.assertRaisesRegex(e.ProviderError,'response_too_large'): e.get_json('https://provider/',{})
        for stats in [None,{},[],{'malicious':-1},{'malicious':True}]:
            with self.assertRaisesRegex(e.ProviderError,'invalid_schema'):
                e.VirusTotal('test',lambda *a:{'data':{'attributes':{'last_analysis_stats':stats}}}).lookup('ip','8.8.8.8')

if __name__=='__main__': unittest.main()
