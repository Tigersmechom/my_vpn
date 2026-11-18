#!/usr/bin/env python3
"""Add dedicated AWG health peers without restarting services; update private profiles.

Never print or commit the resulting plaintext profiles. Run before publishing feeds.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import shlex
import subprocess
import os
import tempfile

REMOTE = r'''
import hashlib,json,pathlib,re,subprocess,sys
entries=json.loads(sys.argv[1])
def call(args):return subprocess.check_output(args,text=True).strip()
def snapshot():
 allowed=dict(line.split(None,1) for line in call(['awg','show','awg0','allowed-ips']).splitlines())
 psk=dict(line.split(None,1) for line in call(['awg','show','awg0','preshared-keys']).splitlines())
 peers={key:hashlib.sha256((psk[key]+'\n'+allowed[key]).encode()).hexdigest() for key in allowed}
 return {'peers':peers,'xray':call(['systemctl','show','xray','-p','MainPID','--value']),'awg':call(['pgrep','-x','amneziawg-go'])}
before=snapshot();profiles={}
for item in entries:
 device,client=item['device'],item['client']
 if not all(re.fullmatch(r'[A-Za-z0-9_-]{1,32}',s) for s in [device,client]):raise ValueError('invalid device name')
 if not pathlib.Path('/etc/myvpn/awg-devices',device+'.env').exists():
  subprocess.run(['vpnctl','add-awg-device',device,client],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 profiles[device]=json.loads(call(['vpnctl','profile',device]))
after=snapshot()
assert before['xray']==after['xray'] and before['awg']==after['awg'],'Service changed during provisioning'
assert all(after['peers'].get(k)==v for k,v in before['peers'].items()),'Existing peer changed'
print(json.dumps({'profiles':profiles,'old_peers_preserved':len(before['peers']),'total_peers':len(after['peers']),'services_unchanged':True}))
'''


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profiles',type=Path,nargs='+',required=True)
    parser.add_argument('--ssh-key',type=Path,required=True)
    parser.add_argument('--only-missing',action='store_true',help='Preserve existing dedicated health identities')
    args=parser.parse_args();documents={p:json.loads(p.read_text()) for p in args.profiles};plans={}
    for path,root in documents.items():
        servers=[('primary',root)]+[(s['id'],s['profile']) for s in root.get('additionalServers',[])]
        for server_id,base in servers:
            for route_id,p in [('direct',base)]+[(r['id'],r['profile']) for r in base.get('routes',[])]:
                if args.only_missing and 'probeAwg' in p:
                    continue
                host=str(ipaddress.IPv4Address(p.get('exitHost',p['host'])))
                client=p['client'];identity='\n'.join([client,server_id,route_id,p['awg']['serverPublicKey']])
                device='probe-'+client+'-'+hashlib.sha256(identity.encode()).hexdigest()[:12]
                plans.setdefault(host,[]).append({'device':device,'client':client,'profile':p})
    for host,entries in plans.items():
        payload=[{'device':e['device'],'client':e['client']} for e in entries]
        command='python3 -c '+shlex.quote(REMOTE)+' '+shlex.quote(json.dumps(payload))
        result=subprocess.run(['ssh','-i',str(args.ssh_key),'-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=12','root@'+host,command],capture_output=True,text=True,timeout=90)
        if result.returncode:raise RuntimeError('Health peer provisioning failed on '+host+'; credentials withheld')
        response=json.loads(result.stdout)
        for entry in entries:
            original=entry['profile'];generated=response['profiles'][entry['device']]
            assert generated['hy2']['auth']==original['hy2']['auth'] and generated['awg']['serverPublicKey']==original['awg']['serverPublicKey']
            override={k:generated['awg'][k] for k in ['privateKey','presharedKey','address']}
            assert override['privateKey']!=original['awg']['privateKey'] and override['address']!=original['awg']['address']
            original['probeAwg']=override
        print('Dedicated health peers ready on',host,'; existing peers preserved:',response['old_peers_preserved'],'; services unchanged')
    for path,value in documents.items():
        fd, temporary = tempfile.mkstemp(prefix='.probe-next-', dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(value, stream, ensure_ascii=False, indent=2)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


if __name__=='__main__':main()
