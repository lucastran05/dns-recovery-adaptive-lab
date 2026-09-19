import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('dns_lab',ROOT/'provisioning/files/dns_lab.py')
lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)

def config(tmp):
    return {'data_dir':tmp,'dns_ip':'10.60.20.53','portal_name':'portal.corp.test.','files_name':'files.corp.test.','zone':'corp.test.','portal_ip':'10.60.20.10','files_ip':'10.60.20.20','rogue_ip':'10.60.40.10','legacy_key_file':tmp+'/legacy.key','recovery_key_file':tmp+'/recovery.key','dns_api':'http://dns','client_api':'http://client','attacker_api':'http://attacker','agent_token':'agent','instructor_token':'instructor','student_user':'analyst','student_password':'password','completion_flag':'TEST_FLAG','node':'test','mode':'admin'}

def response(rc=0,out='',err=''):
    return {'rc':rc,'stdout':out,'stderr':err}

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();lab.CFG.clear();lab.CFG.update(config(self.tmp.name))
    def tearDown(self):self.tmp.cleanup()

    def test_dns_parser_positive_nxdomain_timeout(self):
        out=';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12\n;; flags: qr aa rd; QUERY: 1, ANSWER: 1\nportal.corp.test. 30 IN A 10.60.20.10\n'
        with patch.object(lab,'run',return_value=response(out=out)):
            d=lab.dig('portal.corp.test.');self.assertEqual(d['addresses'],['10.60.20.10']);self.assertTrue(d['authoritative'])
        with patch.object(lab,'run',return_value=response(out=';; status: NXDOMAIN, id: 1\n;; flags: qr aa;')):
            d=lab.dig('files.corp.test.');self.assertEqual(d['rcode'],'NXDOMAIN');self.assertEqual(d['addresses'],[])
        with patch.object(lab,'run',return_value=response(rc=9,out=';; connection timed out')):
            d=lab.dig('files.corp.test.');self.assertIsNone(d['rcode'])

    def test_refusal_is_not_timeout_or_bad_signature(self):
        for stderr,expected in [('update failed: REFUSED',True),('update failed: BADKEY',False),('tsig verify failure',False),('connection timed out',False)]:
            with patch.object(lab,'run',return_value=response(rc=2,err=stderr)):
                r=lab.probe_update(True);self.assertEqual(r['explicit_refused'],expected);self.assertFalse(r['accepted'])

    def test_update_scope_and_keys(self):
        with patch.object(lab,'run',return_value=response()) as runner:
            lab.scenario();args,script=runner.call_args.args
            self.assertIn(lab.CFG['legacy_key_file'],args)
            self.assertIn('server 10.60.20.53 53',script)
            self.assertIn('update add portal.corp.test. 300 A 10.60.40.10',script)
            self.assertIn('update delete files.corp.test. A',script)
            lab.restore();args,script=runner.call_args.args
            self.assertIn(lab.CFG['recovery_key_file'],args)
            self.assertIn('update add files.corp.test. 30 A 10.60.20.20',script)

    def test_policy_rollback(self):
        p=Path(self.tmp.name)
        for n,content in [('active','old'),('secure','new'),('legacy','old')]: (p/n).write_text(content)
        lab.CFG.update(policy_file=str(p/'active'),secure_policy_file=str(p/'secure'),legacy_policy_file=str(p/'legacy'))
        with patch.object(lab,'run',return_value=response(rc=1,err='invalid')):
            self.assertFalse(lab.harden()['ok']);self.assertEqual((p/'active').read_text(),'old')
        with patch.object(lab,'run',side_effect=[response(),response(rc=1),response()]):
            self.assertFalse(lab.harden()['ok']);self.assertEqual((p/'active').read_text(),'old')
        with patch.object(lab,'run',return_value=response()):
            self.assertTrue(lab.harden()['ok']);self.assertEqual((p/'active').read_text(),'new')

    def good_answers(self):
        return {'http://dns/diagnose':(200,{'portal':{'rcode':'NOERROR','authoritative':True,'addresses':['10.60.20.10']},'files':{'rcode':'NOERROR','authoritative':True,'addresses':['10.60.20.20']}}), 'http://client/probe':(200,{'portal_dns':{'rcode':'NOERROR','addresses':['10.60.20.10']},'files_dns':{'rcode':'NOERROR','addresses':['10.60.20.20']},'portal_http':{'ok':True,'data':{'service_id':'NORTHSTAR-INTRANET'}},'files_http':{'ok':True,'data':{'document_id':'NS-HANDBOOK-2026'}}}), 'http://attacker/probe':(200,{'explicit_refused':True,'accepted':False}),'http://dns/probe-authorized':(200,{'accepted':True})}

    def test_checker_pass_and_missing_dependencies(self):
        (Path(self.tmp.name)/'scenario.json').write_text('{}')
        answers=self.good_answers()
        with patch.object(lab,'api',side_effect=lambda url,*a,**k:answers[url]):
            result=lab.check();self.assertTrue(result['passed']);self.assertEqual(len(result['checks']),9);self.assertEqual(result['flag'],'TEST_FLAG')
            for url in answers:
                old=answers[url];answers[url]=(0,{})
                result=lab.check();self.assertFalse(result['passed'],url);self.assertNotIn('flag',result)
                answers[url]=old
            (Path(self.tmp.name)/'scenario.json').unlink()
            self.assertFalse(lab.check()['passed'])

    def test_cache_stale_or_rogue_web_prevents_success(self):
        (Path(self.tmp.name)/'scenario.json').write_text('{}')
        for field,value in [('portal_dns',{'rcode':'NOERROR','addresses':['10.60.40.10']}),('portal_http',{'ok':True,'data':{'service_id':'ROGUE-TRAINING-PAGE'}}),('files_dns',{'rcode':'NXDOMAIN','addresses':[]})]:
            answers=self.good_answers();answers['http://client/probe'][1][field]=value
            with patch.object(lab,'api',side_effect=lambda url,*a,**k:answers[url]):
                r=lab.check();self.assertFalse(r['passed']);self.assertNotIn('flag',r)

    def test_no_fetch_for_unexpected_dns_address(self):
        with patch.object(lab.HTTP,'open') as opener:
            r=lab.fetch_identity('203.0.113.25','portal.corp.test.')
            self.assertFalse(r['ok']);opener.assert_not_called()

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();lab.CFG.clear();lab.CFG.update(config(self.tmp.name))
        self.server=lab.ThreadingHTTPServer(('127.0.0.1',0),lab.Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url='http://127.0.0.1:'+str(self.server.server_port)
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.tmp.cleanup()
    def request(self,path,body=None,auth=None):
        req=urllib.request.Request(self.url+path,data=None if body is None else json.dumps(body).encode(),headers={'Authorization':auth or '', 'Content-Type':'application/json'})
        try:
            with lab.HTTP.open(req,timeout=3) as r:return r.status,r.read()
        except urllib.error.HTTPError as e:return e.code,e.read()
    def test_http_auth_and_instructor_separation(self):
        basic='Basic '+base64.b64encode(b'analyst:password').decode()
        self.assertEqual(self.request('/')[0],401)
        self.assertEqual(self.request('/',auth=basic)[0],200)
        with patch.object(lab,'api') as api:
            self.assertEqual(self.request('/scenario',{},basic)[0],404)
            self.assertEqual(self.request('/reset',{},basic)[0],404)
            api.assert_not_called()
        self.assertEqual(self.request('/restore',{'command':'anything'},basic)[0],400)
    def test_http_diagnose_and_actions(self):
        basic='Basic '+base64.b64encode(b'analyst:password').decode()
        with patch.object(lab,'api',return_value=(200,{'ok':True})) as api:
            status,_=self.request('/harden',{},basic);self.assertEqual(status,200)
            self.assertEqual(api.call_args.args,('http://dns/harden',{},'agent'))
            status,_=self.request('/diagnose',auth=basic);self.assertEqual(status,200)
    def test_unauthorized_agent_request(self):
        lab.CFG['mode']='dns'
        self.assertEqual(self.request('/policy')[0],401)
        self.assertEqual(self.request('/reset',{},'Bearer agent')[0],403)

if __name__=='__main__':unittest.main(verbosity=2)
