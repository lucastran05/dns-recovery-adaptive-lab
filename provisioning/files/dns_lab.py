#!/usr/bin/env python3
"""DNS recovery exercise. Fixed operations against configured sandbox hosts only."""
import argparse
import base64
import fcntl
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CFG = {}
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def run(args, text=None):
    try:
        p = subprocess.run(args, input=text, text=True, capture_output=True, timeout=12)
        return {'rc': p.returncode, 'stdout': p.stdout[-12000:], 'stderr': p.stderr[-2000:]}
    except (OSError, subprocess.TimeoutExpired) as e:
        return {'rc': 124, 'stdout': '', 'stderr': type(e).__name__}


def api(url, body=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        with HTTP.open(request, timeout=45) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as e:
        return e.code, {'error': 'HTTP ' + str(e.code)}
    except (OSError, ValueError, urllib.error.URLError) as e:
        return 0, {'error': type(e).__name__}


def audit(action, result):
    path = Path(CFG['data_dir'])
    path.mkdir(parents=True, exist_ok=True)
    with (path/'actions.jsonl').open('a') as f:
        f.write(json.dumps({'ts': time.time(), 'node': CFG['node'], 'action': action, 'result': result})+'\n')


def dig(name, cached=False):
    server = '127.0.0.1' if cached else CFG['dns_ip']
    port = '5353' if cached else '53'
    result = run(['dig', '@'+server, '-p', port, name, 'A', '+time=2', '+tries=1', '+noall', '+answer', '+comments'])
    output = result['stdout']
    status = re.search(r'status: ([A-Z]+)', output)
    flags = re.search(r'flags: ([^;]+);', output)
    records = []
    for line in output.splitlines():
        pieces = line.split()
        if len(pieces) == 5 and pieces[2:4] == ['IN', 'A']:
            try:
                records.append(str(ipaddress.IPv4Address(pieces[4])))
            except ValueError:
                pass
    return {**result, 'rcode': status[1] if status else None,
            'authoritative': bool(flags and 'aa' in flags[1].split()), 'addresses': records}


def update(key, lines):
    # No user supplied DNS names, addresses, command text or paths reach this call.
    script = 'server '+CFG['dns_ip']+' 53\nzone '+CFG['zone']+'\n'+ '\n'.join(lines)+'\nsend\n'
    result = run(['nsupdate', '-v', '-t', '5', '-k', key], script)
    result['accepted'] = result['rc'] == 0
    result['explicit_refused'] = result['rc'] != 0 and bool(re.search(r'update failed:\s*REFUSED\b', result['stderr']+result['stdout']))
    return result


def probe_update(legacy):
    key = CFG['legacy_key_file'] if legacy else CFG['recovery_key_file']
    name = '_probe.'+CFG['zone']
    label = 'legacy-probe' if legacy else 'recovery-probe'
    return update(key, ['update delete '+name+' TXT', 'update add '+name+' 30 TXT "'+label+'"'])


def restore():
    result = update(CFG['recovery_key_file'], [
        'update delete '+CFG['portal_name']+' A',
        'update add '+CFG['portal_name']+' 30 A '+CFG['portal_ip'],
        'update delete '+CFG['files_name']+' A',
        'update add '+CFG['files_name']+' 30 A '+CFG['files_ip']])
    audit('restore-records', result)
    return result


def harden(enable_legacy=False):
    policy = Path(CFG['policy_file'])
    baseline = Path(CFG['legacy_policy_file'] if enable_legacy else CFG['secure_policy_file']).read_text()
    old = policy.read_text()
    # Serialize writes across HTTP workers and roll back invalid or failed reloads.
    with open(CFG['data_dir']+'/policy.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        old = policy.read_text()
        policy.write_text(baseline)
        checked = run(['named-checkconf'])
        if checked['rc'] != 0:
            policy.write_text(old)
            return {'ok': False, 'validation': checked}
        reloaded = run(['rndc', 'reconfig'])
        if reloaded['rc'] != 0:
            policy.write_text(old)
            run(['rndc', 'reconfig'])
            return {'ok': False, 'reload': reloaded}
    result = {'ok': True, 'legacy_enabled': enable_legacy}
    audit('policy-change', result)
    return result


def scenario():
    result = update(CFG['legacy_key_file'], [
        'update delete '+CFG['portal_name']+' A',
        'update add '+CFG['portal_name']+' 300 A '+CFG['rogue_ip'],
        'update delete '+CFG['files_name']+' A'])
    audit('unauthorized-dns-change', result)
    return result


def fetch_identity(address, hostname, path='/identity.json'):
    # Client probes only the three known lab HTTP nodes, not arbitrary DNS answers.
    if address not in [CFG['portal_ip'], CFG['files_ip'], CFG['rogue_ip']]:
        return {'ok': False, 'error': 'unexpected-address'}
    request = urllib.request.Request('http://'+address+':'+str(CFG.get('http_port', 80))+path, headers={'Host': hostname})
    try:
        with HTTP.open(request, timeout=3) as r:
            data = json.load(r)
            return {'ok': r.status == 200, 'data': data}
    except (OSError, ValueError, urllib.error.URLError) as e:
        return {'ok': False, 'error': type(e).__name__}


def client_probe():
    portal = dig(CFG['portal_name'], cached=True)
    files = dig(CFG['files_name'], cached=True)
    p = fetch_identity(portal['addresses'][0], CFG['portal_name']) if len(portal['addresses']) == 1 else {'ok': False}
    f = fetch_identity(files['addresses'][0], CFG['files_name'], '/handbook.json') if len(files['addresses']) == 1 else {'ok': False}
    return {'portal_dns': portal, 'files_dns': files, 'portal_http': p, 'files_http': f}


def check():
    token = CFG['agent_token']
    ds, dns = api(CFG['dns_api']+'/diagnose', token=token)
    cs, client = api(CFG['client_api']+'/probe', token=token)
    ls, legacy = api(CFG['attacker_api']+'/probe', {}, token)
    rs, recovery = api(CFG['dns_api']+'/probe-authorized', {}, token)
    pd, fd = dns.get('portal', {}), dns.get('files', {})
    cp, cf = client.get('portal_dns', {}), client.get('files_dns', {})
    ph, fh = client.get('portal_http', {}), client.get('files_http', {})
    checks = {
        'incident_initialized': (Path(CFG['data_dir'])/'scenario.json').exists(),
        'authoritative_portal_correct': ds == 200 and pd.get('rcode') == 'NOERROR' and pd.get('authoritative') is True and pd.get('addresses') == [CFG['portal_ip']],
        'authoritative_files_correct': ds == 200 and fd.get('rcode') == 'NOERROR' and fd.get('authoritative') is True and fd.get('addresses') == [CFG['files_ip']],
        'client_cache_portal_correct': cs == 200 and cp.get('rcode') == 'NOERROR' and cp.get('addresses') == [CFG['portal_ip']],
        'client_cache_files_correct': cs == 200 and cf.get('rcode') == 'NOERROR' and cf.get('addresses') == [CFG['files_ip']],
        'portal_identity_correct': cs == 200 and ph.get('ok') is True and ph.get('data', {}).get('service_id') == 'NORTHSTAR-INTRANET',
        'file_service_available': cs == 200 and fh.get('ok') is True and fh.get('data', {}).get('document_id') == 'NS-HANDBOOK-2026',
        'legacy_update_refused': ls == 200 and legacy.get('explicit_refused') is True and legacy.get('accepted') is False,
        'authorized_update_works': rs == 200 and recovery.get('accepted') is True,
    }
    result = {'checks': checks, 'passed': all(checks.values()), 'ts': time.time()}
    if result['passed']:
        result['flag'] = CFG['completion_flag']
    audit('check', result)
    return result


class Handler(BaseHTTPRequestHandler):
    def send(self, status, value, mime='application/json; charset=utf-8'):
        raw = value.encode() if isinstance(value, str) else json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self, key):
        return hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer '+CFG[key])

    def student(self):
        value = base64.b64encode((CFG['student_user']+':'+CFG['student_password']).encode()).decode()
        return hmac.compare_digest(self.headers.get('Authorization', ''), 'Basic '+value)

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 <= size <= 2048:
                return self.send(413, {'error': 'body too large'})
            body = json.loads(self.rfile.read(size) or b'{}')
            if body != {}:
                return self.send(400, {'error': 'This API accepts fixed operations only'})
        except (ValueError, UnicodeDecodeError):
            return self.send(400, {'error': 'invalid JSON'})
        self.dispatch(True)

    def dispatch(self, post):
        try:
            self.route(post)
        except (OSError, ValueError, KeyError) as e:
            self.send(503, {'error': type(e).__name__})

    def route(self, post):
        path = self.path.split('?')[0]
        mode = CFG['mode']
        if path == '/health' and not post:
            return self.send(200, {'ok': True, 'node': CFG['node']})
        instructor = self.authorized('instructor_token')
        if mode == 'admin':
            if path == '/scenario' and post and instructor:
                status, result = api(CFG['attacker_api']+'/scenario', {}, CFG['instructor_token'])
                if status != 200 or not result.get('accepted'):
                    return self.send(409, {'error': 'scenario did not change DNS', 'result': result})
                fs, flush = api(CFG['client_api']+'/flush', {}, CFG['agent_token'])
                ps, probe = api(CFG['client_api']+'/probe', token=CFG['agent_token'])
                ready = fs == 200 and flush.get('rc') == 0 and ps == 200 and probe.get('portal_dns', {}).get('addresses') == [CFG['rogue_ip']] and probe.get('files_dns', {}).get('rcode') == 'NXDOMAIN'
                if ready:
                    (Path(CFG['data_dir'])/'scenario.json').write_text(json.dumps({'started_at':time.time()}))
                return self.send(200 if ready else 503, {'ready':ready, 'update': result, 'flush_status': fs, 'flush':flush, 'probe_status': ps, 'client': probe})
            if path == '/reset' and post and instructor:
                s, d = api(CFG['dns_api']+'/reset', {}, CFG['instructor_token'])
                fs, f = api(CFG['client_api']+'/flush', {}, CFG['agent_token'])
                if s == 200 and fs == 200:
                    marker = Path(CFG['data_dir'])/'scenario.json'
                    if marker.exists():
                        marker.unlink()
                return self.send(200 if s == 200 and fs == 200 else 503, {'dns':d,'flush':f})
            if not self.student():
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Northstar DNS exercise"')
                self.end_headers()
                return
            if path == '/' and not post:
                return self.send(200, PAGE, 'text/html; charset=utf-8')
            if path == '/check' and post:
                return self.send(200, check())
            mapping = {'/diagnose':(CFG['dns_api']+'/diagnose',False), '/evidence':(CFG['dns_api']+'/evidence',False), '/policy':(CFG['dns_api']+'/policy',False), '/client':(CFG['client_api']+'/probe',False), '/restore':(CFG['dns_api']+'/restore',True), '/harden':(CFG['dns_api']+'/harden',True), '/flush':(CFG['client_api']+'/flush',True)}
            if path in mapping and mapping[path][1] == post:
                url, mutates = mapping[path]
                status, result = api(url, {} if mutates else None, CFG['agent_token'])
                return self.send(status or 503, result)
        else:
            if path in ['/scenario','/reset']:
                if not instructor:
                    return self.send(403, {'error': 'instructor only'})
            elif not self.authorized('agent_token'):
                return self.send(401, {'error': 'unauthorized'})
            if mode == 'dns':
                if path == '/diagnose' and not post:
                    return self.send(200, {'portal':dig(CFG['portal_name']), 'files':dig(CFG['files_name'])})
                if path == '/policy' and not post:
                    return self.send(200, {'policy':Path(CFG['policy_file']).read_text()})
                if path == '/evidence' and not post:
                    p = Path(CFG['bind_log'])
                    if not p.exists():
                        return self.send(200, {'lines':[], 'note':'No BIND update log yet'})
                    with p.open('rb') as f:
                        f.seek(max(0, p.stat().st_size-64000))
                        lines=f.read().decode(errors='replace').splitlines()[-150:]
                    return self.send(200, {'source':'native BIND update/security log','lines':lines})
                if path == '/harden' and post:
                    result=harden()
                    return self.send(200 if result['ok'] else 503,result)
                if path == '/restore' and post:
                    result=restore()
                    return self.send(200 if result['accepted'] else 503,result)
                if path == '/probe-authorized' and post:
                    return self.send(200,probe_update(False))
                if path == '/reset' and post:
                    p=harden(True)
                    if not p['ok']:
                        return self.send(503,p)
                    r=restore()
                    return self.send(200 if r['accepted'] else 503,{'policy':p,'restore':r})
            elif mode == 'client':
                if path == '/probe' and not post:
                    return self.send(200,client_probe())
                if path == '/flush' and post:
                    result=run(['systemctl','reload','dns-lab-cache'])
                    if result['rc'] == 0:
                        time.sleep(0.2)
                    return self.send(200 if result['rc']==0 else 503,result)
            elif mode == 'attacker':
                if path == '/probe' and post:
                    return self.send(200,probe_update(True))
                if path == '/scenario' and post:
                    return self.send(200,scenario())
        self.send(404, {'error':'not found'})


PAGE='''<!doctype html><html lang="vi"><meta charset="utf-8"><title>Northstar DNS Recovery</title>
<style>body{font:16px system-ui;background:#f1f5f9;color:#14223a;max-width:1100px;margin:40px auto;padding:16px}button{padding:10px;margin:4px;border:0;border-radius:6px;background:#174c7a;color:white}pre{background:#122235;color:#dbeafe;padding:20px;max-height:65vh;overflow:auto;white-space:pre-wrap}</style>
<h1>Northstar · DNS Recovery</h1><p>Điều tra sự cố tên miền, khôi phục dịch vụ và kiểm tra quyền cập nhật.</p>
<button onclick="go('diagnose')">DNS authoritative</button><button onclick="go('client')">Máy nhân viên</button><button onclick="go('evidence')">BIND evidence</button><button onclick="go('policy')">Update policy</button>
<button onclick="go('harden',true)">Thu hồi legacy key</button><button onclick="go('restore',true)">Khôi phục bản ghi</button><button onclick="go('flush',true)">Xóa cache client</button><button onclick="go('check',true)">Kiểm tra kết quả</button><pre id="out">Chọn bước điều tra.</pre>
<script>async function go(p,w=false){try{let r=await fetch('/'+p,w?{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}:{});document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2)}catch(e){document.getElementById('out').textContent=String(e)}}</script></html>'''


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--config',default='/etc/dns-lab/config.json')
    p.add_argument('command',choices=['serve','scenario'])
    a=p.parse_args()
    CFG.update(json.loads(Path(a.config).read_text()))
    Path(CFG['data_dir']).mkdir(parents=True,exist_ok=True)
    if a.command=='scenario':
        r=scenario();print(json.dumps(r));raise SystemExit(0 if r['accepted'] else 1)
    ThreadingHTTPServer((CFG['bind'],CFG['port']),Handler).serve_forever()

if __name__=='__main__':
    main()
