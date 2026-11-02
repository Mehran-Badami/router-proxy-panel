"""Exercise routed TCP, verified HTTPS and UDP on isolated Docker networks.

All addresses and credentials are disposable laboratory fixtures. No router,
subscription, host route or public service is used.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

SERVER='198.18.10.3'
LAN='198.19.10.0/24'
IDENTITY='00000000-0000-4000-8000-000000000001'
BODY=b'native-tun-payload-'*65536

def docker(*args,check=True):
    p=subprocess.run(['docker',*args],capture_output=True,text=True,timeout=120)
    if check and p.returncode:raise RuntimeError(p.stderr[-1800:] or p.stdout[-1800:])
    return (p.stdout+p.stderr if args[0]=='logs' else p.stdout).strip()

SERVER_CODE='''import http.server,socket,ssl,subprocess,threading,time
subprocess.run(['ip','address','add','198.18.10.3/32','dev','lo'],check=True)
class H(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def do_GET(self):
  b=b'native-tun-payload-'*65536
  self.send_response(200);self.send_header('Content-Length',str(len(b)));self.send_header('X-Peer',self.client_address[0]);self.end_headers();self.wfile.write(b)
def serve(port,tls=False):
 s=http.server.ThreadingHTTPServer(('0.0.0.0',port),H)
 if tls:
  ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain('/lab/cert.pem','/lab/key.pem');s.socket=ctx.wrap_socket(s.socket,server_side=True)
 s.serve_forever()
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.18.10.3',9005))
 while True:
  b,a=s.recvfrom(65535);print('UDP received',len(b),flush=True);s.sendto(b,a)
for fn,args in ((serve,(8085,)),(serve,(8444,True)),(udp,())):threading.Thread(target=fn,args=args,daemon=True).start()
subprocess.run(['/usr/local/bin/xray','run','-c','/lab/server.json'],check=True)
'''

def certs(folder):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import ipaddress
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME,'RPP isolated laboratory')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
          .not_valid_after(now+datetime.timedelta(days=1))
          .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(SERVER))]),False)
          .sign(key,hashes.SHA256()))
    (folder/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))

def main(image,platform=None):
    prefix='rpp-tun-'+uuid.uuid4().hex[:8]
    gateway,server,client=(prefix+'-'+s for s in ('gateway','server','client'))
    lan=prefix+'-lan'
    platform_args=['--platform',platform] if platform else []
    def execute(name,code):return docker('exec',name,'python','-c',code)
    def ready():
        for _ in range(20):
            try:
                execute(gateway,"import socket;socket.create_connection(('127.0.0.1',1080),1).close()")
                return
            except RuntimeError:time.sleep(.5)
        detail=docker('exec',gateway,'python','-c',"import subprocess;r=subprocess.run(['/usr/local/bin/xray','run','-test','-c','/data/runtime.json'],capture_output=True,text=True);print(r.stdout,r.stderr)",check=False)
        raise RuntimeError('Gateway not ready: '+docker('logs',gateway)+' '+detail)
    def probes(peer):
        result=execute(client,f'''import hashlib,json,socket,ssl,urllib.request
result=[]
for scheme,port in (('http',8085),('https',8444)):
 with urllib.request.urlopen(scheme+'://{SERVER}:'+str(port),context=ssl.create_default_context(cafile='/lab/cert.pem'),timeout=12) as r:
  data=r.read();assert r.headers['X-Peer']=='{peer}',r.headers['X-Peer'];assert hashlib.sha256(data).hexdigest()=='{hashlib.sha256(BODY).hexdigest()}'
  result.append([scheme,len(data)])
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(5)
for n in (1,1200,4096):
 print('UDP test',n,flush=True);b=b'x'*n;s.sendto(b,('{SERVER}',9005));assert s.recv(65535)==b
print(json.dumps(result+[['udp',3]]))
''')
        print(result,flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
            lab=Path(tmp);certs(lab)
            (lab/'server.py').write_text(SERVER_CODE)
            server_cfg={'log':{'loglevel':'error'},'inbounds':[{'port':9443,'protocol':'vless','settings':{'clients':[{'id':IDENTITY}],'decryption':'none'},'streamSettings':{'security':'tls','tlsSettings':{'certificates':[{'certificateFile':'/lab/cert.pem','keyFile':'/lab/key.pem'}]}}}],'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':[SERVER+'/32'],'port':'8085,8444,9005'}]}}]}
            (lab/'server.json').write_text(json.dumps(server_cfg))
            seed=lab/'data';seed.mkdir()
            out={'protocol':'vless','settings':{'vnext':[{'address':SERVER,'port':9443,'users':[{'id':IDENTITY,'encryption':'none'}]}]},'streamSettings':{'security':'tls','tlsSettings':{'serverName':SERVER,'certificates':[{'certificateFile':'/lab/cert.pem','usage':'verify'}]}}}
            (seed/'config.json').write_text(json.dumps({'outbounds':[out]}))
            (seed/'state.json').write_text(json.dumps({'enabled':True,'automatic':False,'selected':'Isolated laboratory'}))
            # Docker --internal filters packets whose destination is outside the
            # bridge subnet before they reach our gateway. Remove each namespace's
            # default route instead so the lab has no path to the Internet.
            docker('network','create','--subnet',LAN,lan)
            docker('run','-d','--name',server,*platform_args,'--network',lan,'--ip','198.19.10.4','--user','0:0','--cap-add=NET_ADMIN','-v',str(lab)+':/lab:ro','--entrypoint','python',image,'/lab/server.py')
            docker('exec',server,'ip','route','del','default')
            out['settings']['vnext'][0]['address']='198.19.10.4'
            docker('create','--name',gateway,*platform_args,'--network',lan,'--ip','198.19.10.2','--user','0:0','--cap-drop=ALL','--cap-add=NET_ADMIN','--cap-add=SETUID','--cap-add=SETGID','--cap-add=CHOWN','--cap-add=FOWNER','--cap-add=DAC_OVERRIDE','--device','/dev/net/tun','--sysctl','net.ipv4.ip_forward=1','--sysctl','net.ipv4.conf.all.rp_filter=2','--sysctl','net.ipv4.conf.default.rp_filter=2','-e','RPP_GATEWAY_MODE=tun','-e','RPP_LAN_CIDRS='+LAN,'-e','ALLOW_SYSTEM_BOOTSTRAP=false','-v',str(seed)+':/data',image)
            docker('cp',str(lab/'cert.pem'),gateway+':/data/lab-ca.crt')
            # The CA is a laboratory-only, generated certificate; use its data path.
            out['streamSettings']['tlsSettings']['certificates'][0]['certificateFile']='/data/lab-ca.crt'
            (seed/'config.json').write_text(json.dumps({'outbounds':[out]}))
            docker('start',gateway);ready()
            docker('exec',gateway,'ip','route','del','default')
            docker('exec',gateway,'ip','route','add',SERVER+'/32','via','198.19.10.4')
            docker('run','-d','--name',client,*platform_args,'--network',lan,'--ip','198.19.10.3','--user','0:0','--cap-add=NET_ADMIN','-v',str(lab)+':/lab:ro','--entrypoint','sleep',image,'600')
            docker('exec',client,'ip','route','del','default')
            docker('exec',client,'ip','route','add',SERVER+'/32','via','198.19.10.2')
            assert 'dev eth0' in docker('exec',gateway,'ip','route','get','198.19.10.3')
            assert 'rpp0' not in docker('exec',gateway,'ip','route','get',SERVER)
            print('Lab HTTP',execute(server,"import urllib.request;print(len(urllib.request.urlopen('http://"+SERVER+":8085',timeout=5).read()))"),flush=True)
            print('Lab SOCKS',docker('exec',gateway,'curl','--proxy','socks5h://127.0.0.1:1080','--fail','--silent','--show-error','--max-time','8','--output','/dev/null','--write-out','%{http_code} %{size_download}','http://'+SERVER+':8085'),flush=True)
            probes(SERVER)
            print(execute(gateway,"""from pathlib import Path
import json,manager
s=Path('/proc/1/status').read_text();assert 'Uid:\\t10001' in s;assert 'CapEff:\\t0000000000000000' in s
c=json.loads(Path('/data/config.json').read_text());assert not any(x.get('protocol')=='tun' for x in manager.config(c['outbounds'][0],test=True)['inbounds'])
stats=json.loads(__import__('subprocess').check_output(['ip','-j','-s','link','show','rpp0']))[0]['stats64'];assert stats['rx']['bytes']>0 and stats['tx']['bytes']>0
print('Unprivileged gateway, isolated probes, packet counters and local route verified')
"""),flush=True)
            # Kill only Xray; manager must recover with the still-open TUN FD.
            docker('exec','--user','10001:10001',gateway,'python','-c',"from pathlib import Path;import os,signal;[os.kill(int(p.name),signal.SIGKILL) for p in Path('/proc').iterdir() if p.name.isdigit() and (p/'comm').exists() and (p/'comm').read_text().strip()=='xray']")
            time.sleep(4);ready();probes(SERVER)
            # Toggle changes routed application traffic, while DoH remains separate.
            for enabled,peer in ((False,'198.19.10.2'),(True,SERVER)):
                execute(gateway,"import json,urllib.request;from pathlib import Path;token=Path('/data/access-token').read_text().strip();r=urllib.request.Request('http://127.0.0.1:8080/api/toggle',data=json.dumps({'enabled':"+str(enabled)+"}).encode(),headers={'Origin':'http://localhost:8080','Cookie':'access='+token});urllib.request.urlopen(r,timeout=10).read()")
                ready();probes(peer)
            docker('restart',gateway);ready()
            docker('exec',gateway,'ip','route','del','default')
            docker('exec',gateway,'ip','route','add',SERVER+'/32','via','198.19.10.4')
            probes(SERVER)
            print('Native TUN smoke passed: routed TCP/HTTPS/UDP, no local loop, UID/capabilities, core recovery, toggle and container restart',flush=True)
    except Exception:
        for name in (gateway,server):
            print(name,docker('logs',name,check=False),flush=True)
        for args in (('rule','show'),('route','show','table','all'),('-s','link','show','rpp0'),('route','get',SERVER,'from','198.19.10.3','iif','eth0')):
            print(docker('exec',gateway,'ip',*args,check=False),flush=True)
        raise
    finally:
        for name in (client,gateway,server):docker('rm','-f',name,check=False)
        docker('network','rm',lan,check=False)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--image',required=True);parser.add_argument('--platform')
    args=parser.parse_args();main(args.image,args.platform)
