"""Isolated container checks; never uses a real subscription or router."""
import argparse
import http.client
import json
import socket
import subprocess
import time
import uuid

def docker(*args):
    result=subprocess.run(['docker',*args],capture_output=True,text=True,timeout=120)
    if result.returncode:raise RuntimeError('Docker command failed: '+result.stderr[-800:])
    return result.stdout.strip()

def main(image,platform=None):
    name='rpp-smoke-'+uuid.uuid4().hex[:10]
    volume=name+'-data'
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    origin='http://127.0.0.1:'+str(port)
    docker('volume','create',volume)
    try:
        args=['run','-d','--name',name,'--cap-drop=ALL','--security-opt=no-new-privileges','-p',f'127.0.0.1:{port}:8080','-e','PUBLIC_ORIGIN='+origin,'-v',volume+':/data']
        if platform:args+=['--platform',platform]
        docker(*args,image)
        def request(path,method='GET',data=None,headers=None):
            conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
            conn.request(method,path,json.dumps(data) if data is not None else None,headers or {})
            response=conn.getresponse();result=response.status,dict(response.getheaders()),response.read();conn.close();return result
        for attempt in range(30):
            try:
                if request('/')[0]==200:break
            except (OSError,http.client.HTTPException):pass
            time.sleep(1)
        else:raise RuntimeError('Panel did not become ready')
        assert request('/api/status')[0]==401
        token=docker('exec',name,'python','/app/manager.py','--print-token')
        assert len(token)>=32
        code,headers,_=request('/api/login','POST',{'key':token},{'Origin':origin})
        assert code==200 and 'Max-Age=' in headers.get('Set-Cookie','')
        auth={'Cookie':'access='+token,'Origin':origin}
        code,_,body=request('/api/status',headers=auth);state=json.loads(body)
        assert code==200 and state['groups']==[] and state['servers']==[] and not state['running']
        assert token.encode() not in body
        assert request('/api/sites')[0]==401
        assert request('/api/setup/check','POST',{}, {'Origin':origin})[0]==401
        code,_,body=request('/api/setup/check','POST',{},auth)
        assert code==200 and json.loads(body)['ready'] is False
        assert request('/api/sites/presets','POST',{}, {**auth,'Origin':'https://other.example'})[0]==403
        code,_,body=request('/api/sites',headers=auth)
        sites=json.loads(body)
        assert code==200 and len(sites['items'])==10 and sites['pending'] and not sites['configured']
        custom={'id':'smoke','name':'Example','enabled':True,'subdomains':True,'domains':['example.com']}
        assert request('/api/sites/save','POST',{'items':[custom]},auth)[0]==200
        code,_,body=request('/api/sites/presets','POST',{},auth)
        assert code==200 and custom in json.loads(body)['items'] and len(json.loads(body)['items'])==11
        assert request('/api/sites/save','POST',{'items':[custom]},auth)[0]==200
        assert request('/api/sites/apply','POST',{},auth)[0]==400
        assert request('/api/toggle','POST',{'enabled':False},{**auth,'Origin':'https://other.example'})[0]==403
        validate="""import json,subprocess,manager as m
for network in ('tcp','ws','xhttp','grpc','httpupgrade'):
 link='vless://00000000-0000-4000-8000-000000000001@203.0.113.9:443?security=tls&sni=example.com&type='+network
 c=m.config(m.parse(link)[0]['outbound'])
 m.save('selftest.json',c)
 subprocess.run([m.CORE,'run','-test','-c','/data/selftest.json'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print('Core configuration matrix passed')
"""
        print(docker('exec',name,'python','-c',validate))
        docker('restart',name)
        for attempt in range(30):
            try:
                if request('/api/status',headers=auth)[0]==200:break
            except (OSError,http.client.HTTPException):pass
            time.sleep(1)
        else:raise RuntimeError('Persistent login did not survive restart')
        assert docker('exec',name,'python','/app/manager.py','--print-token')==token
        assert json.loads(request('/api/sites',headers=auth)[2])['items']==[custom]
        print('Container smoke passed: clean state, authentication, origin checks, core configs, restart persistence')
    finally:
        subprocess.run(['docker','rm','-f',name],capture_output=True)
        subprocess.run(['docker','volume','rm',volume],capture_output=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--image',required=True);parser.add_argument('--platform');args=parser.parse_args();main(args.image,args.platform)
