#!/usr/bin/env python3
"""Run before provisioning; updates instructor-owned config and access content."""
import base64,json,secrets,subprocess
from pathlib import Path
import yaml
R=Path(__file__).resolve().parents[1]
p=R/'provisioning/group_vars/all.yml';v=yaml.safe_load(p.read_text());old=v['student_password']
for k in ['student_password','agent_token','instructor_token']:v[k]=secrets.token_urlsafe(32)
for k in ['legacy_secret','recovery_secret']:v[k]=base64.b64encode(secrets.token_bytes(32)).decode()
v['student_password_hash']=subprocess.run(['openssl','passwd','-6','-stdin'],input=v['student_password']+'\n',text=True,capture_output=True,check=True).stdout.strip()
d=json.loads((R/'training.json').read_text())
for phase in d['phases']:
 if phase['phase_type']=='ACCESS':
  for k in ['cloud_content','local_content']:phase[k]=phase[k].replace(old,v['student_password'])
p.write_text(yaml.safe_dump(v,sort_keys=False,allow_unicode=True));p.chmod(0o600)
(R/'training.json').write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
print('Credentials rotated. Read group_vars/all.yml privately and provision the sandbox again.')
