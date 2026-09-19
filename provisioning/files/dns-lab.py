#!/usr/bin/env python3
import argparse,base64,json,os,sys,urllib.request,urllib.error
from pathlib import Path
p=argparse.ArgumentParser(description='Northstar DNS recovery workbench')
p.add_argument('command',choices=['diagnose','client','evidence','policy','restore','harden','flush','check'])
a=p.parse_args()
c=json.loads(Path(os.environ.get('DNS_LAB_CONFIG',str(Path.home()/'.dns-lab.json'))).read_text())
post=a.command in ['restore','harden','flush','check']
r=urllib.request.Request(c['url']+'/'+a.command,data=b'{}' if post else None,headers={'Content-Type':'application/json','Authorization':'Basic '+base64.b64encode((c['username']+':'+c['password']).encode()).decode()})
try:
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(r,timeout=120) as response:
  result=json.load(response)
 print(json.dumps(result,ensure_ascii=False,indent=2))
 if a.command=='check' and not result.get('passed'):sys.exit(1)
except (urllib.error.URLError,ValueError) as e:
 print('Request failed: '+str(e),file=sys.stderr);sys.exit(2)
