#!/usr/bin/env python3
"""Structural validator; cloud import and named validation are separate gates."""
import ast,base64,ipaddress,json,re
from pathlib import Path
import yaml
R=Path(__file__).resolve().parents[1]
count=0
for p in R.rglob('*.py'):
 ast.parse(p.read_text());count+=1
for p in R.rglob('*.yml'):
 yaml.safe_load(p.read_text());count+=1
t=yaml.safe_load((R/'topology.yml').read_text())
nets={n['name']:ipaddress.ip_network(n['cidr']) for n in t['networks']}
hosts={h['name'] for h in t['hosts']};routers={h['name'] for h in t['routers']}
assert len(hosts)==6 and len(routers)==1
for x in t['net_mappings']+t['router_mappings']:
 assert ipaddress.ip_address(x['ip']) in nets[x['network']]
 assert x.get('host',x.get('router')) in hosts|routers
for g in t['groups']:assert set(g['nodes'])<=hosts|routers
for play in yaml.safe_load((R/'provisioning/playbook.yml').read_text()):
 assert play['hosts'] in {g['name'] for g in t['groups']}
 for role in play['roles']:assert (R/'provisioning/roles'/role/'tasks/main.yml').exists()
v=yaml.safe_load((R/'provisioning/group_vars/all.yml').read_text())
for key in ['legacy_secret','recovery_secret']:assert len(base64.b64decode(v[key],validate=True))==32
assert v['legacy_secret']!=v['recovery_secret']
assert v['agent_token']!=v['instructor_token']
assert v['zone']=='corp.test.'
d=json.loads((R/'training.json').read_text());assert 'levels' not in d
assert [p['order'] for p in d['phases']]==list(range(9))
ph=[p for p in d['phases'] if p['phase_type']=='TRAINING'];assert len(ph)==5
for i,p in enumerate(ph):
 assert len(p['tasks'])==3
 assert [x['order'] for x in p['tasks']]==[0,1,2]
 assert [x['order'] for x in p['decision_matrix']]==list(range(i+1))
 assert all(x['modify_sandbox'] is False for x in p['tasks'])
for r in d['phases'][1]['phase_relations']:
 assert d['phases'][r['phase_order']]['phase_type']=='TRAINING'
 assert all(q < len(d['phases'][1]['questions']) for q in r['question_orders'])
assert ph[0]['tasks'][0]['answer']==v['rogue_ip']
assert ph[2]['tasks'][0]['answer']==v['files_ip']
assert all(task['answer']==v['completion_flag'] for p in ph[-2:] for task in p['tasks'])
secure=(R/'provisioning/templates/policy-secure.conf.j2').read_text()
assert 'grant legacy-ddns' not in secure and 'grant recovery-ddns' in secure
assert 'allow-update' not in (R/'provisioning/templates/named.local.j2').read_text()
print(f'PASS: {count} Python/YAML files, topology, key separation, 5 adaptive phases and 15 variants.')
