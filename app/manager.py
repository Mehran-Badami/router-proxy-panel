import base64, copy, hashlib, http.cookies, ipaddress, json, os, secrets, signal, socket, ssl, subprocess, threading, time, urllib.parse, uuid
from safe_fetch import fetch_subscription
from sites import SiteStore, merge_presets
from onboarding import inspect_router
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

os.umask(0o077)
DATA=Path(os.environ.get('APP_DATA','/data')); DATA.mkdir(parents=True,exist_ok=True)
CORE=os.environ.get('XRAY_CORE','/usr/local/bin/xray')
BIND=os.environ.get('BIND_ADDRESS','0.0.0.0')
PORT=int(os.environ.get('PORT','8080'))
ORIGIN=os.environ.get('PUBLIC_ORIGIN','http://localhost:8080').rstrip('/')
if urllib.parse.urlsplit(ORIGIN).scheme not in ('http','https') or not urllib.parse.urlsplit(ORIGIN).netloc:
    raise ValueError('PUBLIC_ORIGIN must be an absolute HTTP(S) origin')
DOH_HOST=os.environ.get('DOH_HOST','dns.google')
DOH_IP=str(ipaddress.ip_address(os.environ.get('DOH_IP','8.8.8.8')))
DOH_PORT=int(os.environ.get('DOH_PORT','8443'))
SOCKS_PORT=int(os.environ.get('SOCKS_PORT','1080'))
TEST_PORT=int(os.environ.get('TEST_PORT','18081'))
SYSTEM_BOOTSTRAP=os.environ.get('ALLOW_SYSTEM_BOOTSTRAP','true').lower()=='true'
COOKIE_AGE=int(os.environ.get('SESSION_DAYS','30'))*86400
PANEL=Path(__file__).with_name('panel.html')
lock=threading.RLock(); proc=None
def read(name, default):
    try: return json.loads((DATA/name).read_text(encoding='utf-8'))
    except (FileNotFoundError, ValueError): return default
def save(name, value):
    p=DATA/(name+'.tmp'); p.write_text(json.dumps(value,ensure_ascii=False),encoding='utf-8'); p.chmod(0o600); p.replace(DATA/name)
site_store=SiteStore(read,save)
site_lock=threading.Lock()
state=read('state.json',{'enabled':True,'selected':'No server selected','automatic':True})
token_path=DATA/'access-token'
if not token_path.exists(): token_path.write_text(secrets.token_urlsafe(24)); token_path.chmod(0o600)
TOKEN=token_path.read_text().strip()
def node_id(node):
    return hashlib.sha256((node.get('group','legacy')+json.dumps(node['outbound'],sort_keys=True)).encode()).hexdigest()[:24]

def normalize(items,group):
    result=[]; seen=set()
    for original in items:
        n=copy.deepcopy(original); server=n['outbound']['settings']['vnext'][0]
        if server['address']=='9.9.9.9' and server['port']==9999: continue
        tls=n['outbound'].get('streamSettings',{}).get('tlsSettings',{})
        if isinstance(tls.get('pinnedPeerCertSha256'),list): tls['pinnedPeerCertSha256']=','.join(tls['pinnedPeerCertSha256'])
        n['group']=group; n['id']=node_id(n)
        if n['id'] not in seen: result.append(n); seen.add(n['id'])
    return result

catalog=read('catalog.json',{'groups':[],'nodes':[],'trash':[]})
groups=catalog['groups']; nodes=catalog['nodes']; trash=catalog.get('trash',[])
def save_catalog(): save('catalog.json',{'groups':groups,'nodes':nodes,'trash':trash})
state.setdefault('automatic',True)
health=read('health.json',{}); scan={'running':False,'message':'','last_switch':state.get('last_switch',0),'last_complete':time.time()}; probe_lock=threading.Lock()
job={'running':False,'message':'','done':0,'total':0}
connectivity={'vpn_ok':None,'checked':0,'message':'در حال بررسی اتصال'}
def secure_outbound(outbound, refresh=False):
    # Persist a verified bootstrap IP so VPN startup never depends on its own DNS.
    out=copy.deepcopy(outbound)
    server=out.get('settings',{}).get('vnext',[{}])[0]
    host=server.get('address','')
    try: ipaddress.ip_address(host); return out
    except ValueError: pass
    cache=read('dns-bootstrap.json',{})
    if refresh or host not in cache:
        try:
            url='https://'+DOH_HOST+'/resolve?'+urllib.parse.urlencode({'name':host,'type':'A'})
            r=subprocess.run(['curl','--noproxy','*','--connect-to',DOH_HOST+':443:127.0.0.1:'+str(DOH_PORT),'--max-time','10','--fail','--silent',url],capture_output=True,timeout=12)
            if r.returncode: raise ValueError('Secure bootstrap query failed')
            result=json.loads(r.stdout)
            addresses=[a['data'] for a in result.get('Answer',[]) if a.get('type')==1 and ipaddress.ip_address(a['data']).is_global]
            if result.get('Status')!=0 or not addresses: raise ValueError('Secure bootstrap has no public address')
            cache[host]={'address':addresses[0],'checked':int(time.time())}; save('dns-bootstrap.json',cache)
        except Exception:
            if host not in cache:
                if not SYSTEM_BOOTSTRAP: raise ValueError('Secure bootstrap unavailable; configure an initial IP or opt into system DNS bootstrap')
                # Family continuity mode: a new subscription must be usable even
                # after the old VPN expires. TLS identity verification is retained.
                try: addresses=[row[4][0] for row in socket.getaddrinfo(host,server.get('port',443),socket.AF_INET,socket.SOCK_STREAM) if ipaddress.ip_address(row[4][0]).is_global]
                except OSError: addresses=[]
                if not addresses: raise ValueError('آدرس معتبر سرور پیدا نشد؛ اتصال قبلی حفظ شد')
                cache[host]={'address':addresses[0],'checked':int(time.time()),'source':'system-fallback'}; save('dns-bootstrap.json',cache)
    # Preserve the original TLS identity when replacing a hostname with an IP.
    tls=out.get('streamSettings',{}).get('tlsSettings')
    if tls is not None and not tls.get('serverName'): tls['serverName']=host
    server['address']=cache[host]['address']
    return out

def config(outbound, enabled=True, test=False, refresh_bootstrap=True):
    secure=secure_outbound(outbound,refresh=test and refresh_bootstrap)
    out=copy.deepcopy(secure) if enabled else {'protocol':'freedom'}
    c={'log':{'loglevel':'error','access':'none'},'inbounds':[{'listen':'127.0.0.1' if test else '0.0.0.0','port':TEST_PORT if test else SOCKS_PORT,'protocol':'socks','settings':{'udp':True}}],'outbounds':[out]}
    if not test:
        c['inbounds'].append({'tag':'secure-doh','listen':'0.0.0.0','port':DOH_PORT,'protocol':'dokodemo-door','settings':{'address':DOH_IP,'port':443,'network':'tcp'}})
        secure['tag']='dns-vpn'; c['outbounds'].append(secure)
        c['routing']={'rules':[{'type':'field','inboundTag':['secure-doh'],'outboundTag':'dns-vpn'}]}
    return c
def stop():
    global proc
    if proc and proc.poll() is None:
        proc.terminate()
        try: proc.wait(5)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait()
    proc=None
def start():
    global proc
    saved=read('config.json',{}).get('outbounds',[])
    if not saved: return
    c=config(saved[0],state['enabled'])
    save('runtime.json',c)
    proc=subprocess.Popen([CORE,'run','-c',str(DATA/'runtime.json')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
def restart():
    stop(); start(); time.sleep(.4)
    if proc is not None and proc.poll() is not None: raise ValueError('Core failed to start')
def test(out, thorough=False, download=False, refresh_bootstrap=True):
    with probe_lock:
        save('test.json',config(out,test=True,refresh_bootstrap=refresh_bootstrap))
        result=subprocess.run([CORE,'run','-test','-c',str(DATA/'test.json')],capture_output=True,timeout=10)
        if result.returncode: raise ValueError('Configuration is not supported by this Xray version')
        p=subprocess.Popen([CORE,'run','-c',str(DATA/'test.json')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            time.sleep(.5)
            latency=check_https(TEST_PORT)
            if thorough:
                check_doh(socks_port=TEST_PORT)
                r=subprocess.run(['curl','--proxy','socks5h://127.0.0.1:'+str(TEST_PORT),'--max-time','25','--max-filesize','2097152','--fail','--silent','https://www.youtube.com/'],capture_output=True,timeout=28)
                if r.returncode or len(r.stdout)<50000 or b'youtube' not in r.stdout.lower(): raise ValueError('Full HTTPS page test failed; current server was preserved')
            if download:
                r=subprocess.run(['curl','--proxy','socks5h://127.0.0.1:'+str(TEST_PORT),'--max-time','25','--max-filesize','2000000','--fail','--silent','--output',os.devnull,'--write-out','%{http_code} %{size_download} %{speed_download}','https://speed.cloudflare.com/__down?bytes=2000000'],capture_output=True,timeout=28)
                values=r.stdout.decode().split()
                if r.returncode or len(values)!=3 or values[0]!='200' or int(float(values[1]))!=2000000: raise ValueError('تست دانلود کامل نشد؛ نتیجه سرعت ثبت نشد')
                return {'latency_ms':round(latency*1000),'mbps':round(float(values[2])*8/1000000,2),'bytes':2000000}
            return latency
        finally:
            p.terminate()
            try: p.wait(3)
            except subprocess.TimeoutExpired: p.kill(); p.wait()

def check_https(port):
    # Small, real HTTPS bodies. Default TLS, certificate verification, no downgrade.
    total=0
    for url,marker in [('https://www.youtube.com/robots.txt',b'User-agent'),('https://web.whatsapp.com/robots.txt',b'User-agent')]:
        r=subprocess.run(['curl','--proxy','socks5h://127.0.0.1:'+str(port),'--max-time','12','--max-filesize','131072','--fail','--silent','--show-error','--write-out','\n__TIMING__%{time_starttransfer}',url],capture_output=True,timeout=15)
        parts=r.stdout.rsplit(b'\n__TIMING__',1)
        if r.returncode or len(parts)!=2 or marker.lower() not in parts[0].lower(): raise ValueError('تست HTTPS ناموفق بود؛ اتصال فعال حفظ شد')
        total+=float(parts[1])
    return round(total/2,3)

def check_doh(socks_port=None):
    route=['--proxy','socks5h://127.0.0.1:'+str(socks_port),'--connect-to',DOH_HOST+':443:'+DOH_IP+':443'] if socks_port else ['--noproxy','*','--connect-to',DOH_HOST+':443:127.0.0.1:'+str(DOH_PORT)]
    result=subprocess.run(['curl',*route,'--max-time','10','--max-filesize','65536','--fail','--silent','https://'+DOH_HOST+'/resolve?name=example.com&type=A'],capture_output=True,timeout=12)
    if result.returncode: raise ValueError('پاسخ DNS امن دریافت نشد')
    answer=json.loads(result.stdout)
    if answer.get('Status')!=0 or not any(a.get('type')==1 and ipaddress.ip_address(a['data']).is_global for a in answer.get('Answer',[])):
        raise ValueError('پاسخ DNS امن معتبر نیست')

def record(node,result=None,error=None,speed=False):
    with lock:
        key=node['id']; item=health.setdefault(key,{})
        if speed and error: item.update(speed_error=str(error),speed_checked=int(time.time()))
        elif error: item.update(ok=False,error=str(error),checked=int(time.time()))
        else:
            item.update(ok=True,checked=int(time.time()),error=None)
            if isinstance(result,dict): item.update(result,speed_checked=int(time.time()),speed_error=None)
            else: item['latency_ms']=round(result*1000)
        save('health.json',health)

def run_job(items,kind):
    try:
        for i,node in enumerate(items):
            job.update(message='آزمایش '+node['name'],done=i)
            try:
                if kind=='apply':
                    result=test(node['outbound'],thorough=True); record(node,result); activate(node,False)
                else: record(node,test(node['outbound'],download=kind=='speed'))
            except Exception as exc: record(node,error=exc,speed=kind=='speed')
            job['done']=i+1
        job['message']='آزمایش تمام شد؛ نتیجه کنار هر سرور نمایش داده شد'
    finally: job['running']=False

def queue_job(items,kind):
    if job['running'] or scan['running']: raise ValueError('یک تست در حال اجراست؛ پس از پایان دوباره امتحان کنید')
    if not items: raise ValueError('سروری انتخاب نشده است')
    job.update(running=True,message='در صف آزمایش…',done=0,total=len(items))
    threading.Thread(target=run_job,args=(copy.deepcopy(items),kind),daemon=True).start()

def activate(node,automatic):
    with lock:
        old=read('config.json',{}); old_state=copy.deepcopy(state)
        save('previous-config.json',old); save('config.json',{'outbounds':[node['outbound']]})
        state.update(selected=node['name'],selected_id=node['id'],automatic=automatic,last_switch=time.time())
        try: restart(); save('state.json',state)
        except Exception: save('config.json',old); state.update(old_state); restart(); raise
        scan['last_switch']=time.time()

def candidate_order(items, current):
    return sorted(items,key=lambda n:(n['outbound']==current,not health.get(n['id'],{}).get('ok',False),health.get(n['id'],{}).get('latency_ms',999999)))

def select_best(force=False):
    with lock:
        if scan['running'] or job['running']: return
        scan.update(running=True,message='در حال بازیابی خودکار اتصال…')
        current=read('config.json',{}).get('outbounds',[{}])[0]
        snapshot=candidate_order(copy.deepcopy(nodes),current)
    try:
        if not force:
            try:
                check_doh()
                if state['enabled']: check_https(SOCKS_PORT)
                connectivity.update(vpn_ok=True,checked=int(time.time()),message='اتصال امن برقرار است')
                scan['message']='سرور فعلی سالم است؛ اتصال حفظ شد'; return
            except Exception: pass
        for i,node in enumerate(snapshot):
            if not state.get('automatic'): return
            if node['outbound']['settings']['vnext'][0]['port']==9999: continue
            scan['message']='بازیابی اتصال؛ آزمایش سرور '+str(i+1)+' از '+str(len(snapshot))
            try:
                score=test(node['outbound'],thorough=True,refresh_bootstrap=False)
                record(node,score)
                with lock:
                    if not state.get('automatic'): return
                    activate(node,True)
                connectivity.update(vpn_ok=True,checked=int(time.time()),message='سرور سالم جایگزین شد')
                scan['message']='اتصال بازیابی شد؛ سرور سالم انتخاب شد'; return
            except Exception as exc: record(node,error=exc)
        connectivity.update(vpn_ok=False,checked=int(time.time()),message='سرور سالم پیدا نشد؛ اعتبار اشتراک را بررسی یا لینک جدید وارد کنید')
        scan['message']='سرور سالم پیدا نشد؛ تلاش خودکار دوباره انجام می‌شود'
    except Exception:
        scan['message']='بازیابی کامل نشد؛ تلاش دوباره انجام می‌شود'
    finally:
        scan['running']=False; scan['last_complete']=time.time()

def monitor():
    failures=0; last_recovery=0
    while True:
        if not read('config.json',{}).get('outbounds'):
            connectivity.update(vpn_ok=None,message='ابتدا یک اشتراک اضافه و سرور را انتخاب کنید')
            time.sleep(10); continue
        if not scan['running'] and not job['running']:
            try:
                check_doh()
                if state['enabled']: check_https(SOCKS_PORT)
                failures=0
                connectivity.update(vpn_ok=True,checked=int(time.time()),message='اتصال امن برقرار است')
            except Exception:
                failures+=1
                connectivity.update(vpn_ok=False,checked=int(time.time()),message='اتصال VPN مشکل دارد؛ تنظیمات مسیر اضطراری روتر را بررسی کنید')
            if state.get('automatic') and failures>=2 and time.time()-last_recovery>=120:
                select_best(force=True); last_recovery=time.time(); failures=0
        time.sleep(45)

def subscription_info(text,headers=None):
    info={'records':[]}
    fields={str(k).lower():str(v) for k,v in (headers or {}).items()}
    raw=fields.get('subscription-userinfo',''); counters={}
    for item in raw.split(';'):
        key,sep,value=item.strip().partition('=')
        if sep and key in ('upload','download','total','expire'):
            try:
                number=int(value)
                if number>=0: counters[key]=number
            except ValueError: pass
    if counters: info['usage']=counters
    if '://' not in text:
        try: text=base64.b64decode(text.strip()+'='*((-len(text.strip()))%4)).decode()
        except Exception: return info
    for line in text.splitlines():
        try:
            u=urllib.parse.urlsplit(line.strip())
            if (u.hostname=='9.9.9.9' and u.port==9999) or u.hostname in ('127.0.0.1','localhost'):
                label=urllib.parse.unquote(u.fragment)[:250]
                if label and label not in info['records']: info['records'].append(label)
        except ValueError: continue
    info['records']=info['records'][:10]
    return info

def parse(text):
    text=text.strip()
    if '://' not in text:
        try: text=base64.b64decode(text+'='*((-len(text))%4)).decode()
        except Exception: raise ValueError('Paste VLESS links or a subscription URL')
    result=[]
    for line in text.splitlines():
        if not line.strip().startswith('vless://'): continue
        u=urllib.parse.urlsplit(line.strip()); uuid.UUID(u.username or '');
        if not u.hostname or not 1 <= (u.port or 443) <= 65535: raise ValueError('Invalid server address or port')
        q=dict(urllib.parse.parse_qsl(u.query)); net=q.get('type','tcp'); sec=q.get('security') or 'none'
        if net not in ('tcp','raw','ws','xhttp','grpc','httpupgrade'): continue
        if q.get('allowInsecure')=='1' or q.get('insecure')=='1': continue
        if sec not in ('tls','reality'): continue
        user={'id':urllib.parse.unquote(u.username or ''),'encryption':q.get('encryption') or 'none'}
        if q.get('flow'): user['flow']=q['flow']
        stream={'network':net,'security':sec}
        if sec=='reality': stream['realitySettings']={'serverName':q.get('sni',''),'password':q.get('pbk',''),'shortId':q.get('sid',''),'fingerprint':q.get('fp') or 'chrome'}
        if sec=='tls':
            tls={'serverName':q.get('sni') or q.get('host') or u.hostname,'fingerprint':q.get('fp') or 'chrome'}
            if q.get('alpn'): tls['alpn']=q['alpn'].split(',')
            if q.get('pcs'): tls['pinnedPeerCertSha256']=q['pcs']
            stream['tlsSettings']=tls
        if net=='ws': stream['wsSettings']={'path':q.get('path','/'),'headers':{'Host':q.get('host') or u.hostname}}
        if net=='xhttp': stream['xhttpSettings']={'path':q.get('path','/'),'host':q.get('host',''),'mode':q.get('mode') or 'auto'}
        if net=='grpc': stream['grpcSettings']={'serviceName':q.get('serviceName','')}
        if net=='httpupgrade': stream['httpupgradeSettings']={'path':q.get('path','/'),'host':q.get('host','')}
        out={'protocol':'vless','settings':{'vnext':[{'address':u.hostname,'port':u.port or 443,'users':[user]}]},'streamSettings':stream}
        result.append({'name':urllib.parse.unquote(u.fragment)[:120] or 'Server '+str(len(result)+1),'outbound':out})
    if not result: raise ValueError('No supported VLESS connections found')
    return result[:100]
class Handler(BaseHTTPRequestHandler):
    login_lock=threading.Lock()
    login_attempts=[]
    def session_cookie(self):
        return 'access='+TOKEN+'; HttpOnly; SameSite=Strict; Path=/; Max-Age='+str(COOKIE_AGE)+('; Secure' if ORIGIN.startswith('https://') else '')
    def end_headers(self):
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        super().end_headers()
    def login(self):
        with self.login_lock:
            now=time.monotonic()
            self.login_attempts[:]=[t for t in self.login_attempts if now-t<60]
            if len(self.login_attempts)>=10: return self.reply(429,{'error':'Too many attempts; wait one minute'})
            self.login_attempts.append(now)
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=256: raise ValueError()
            value=json.loads(self.rfile.read(length)).get('key','')
            if not isinstance(value,str) or not secrets.compare_digest(value,TOKEN): raise ValueError()
        except Exception: return self.reply(401,{'error':'Invalid access key'})
        self.send_response(200); self.send_header('Set-Cookie',self.session_cookie()); self.send_header('Cache-Control','no-store'); self.send_header('Content-Type','application/json'); self.end_headers(); self.wfile.write(b'{"ok":true}')

    def log_message(self,*args): pass
    def reply(self,code,obj):
        body=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(body)
    def authorized(self):
        c=http.cookies.SimpleCookie()
        try: c.load(self.headers.get('Cookie',''))
        except http.cookies.CookieError: return False
        return 'access' in c and secrets.compare_digest(c['access'].value,TOKEN)
    def do_GET(self):
        u=urllib.parse.urlsplit(self.path); key=urllib.parse.parse_qs(u.query).get('key',[''])[0]
        if key and secrets.compare_digest(key,TOKEN):
            self.send_response(303); self.send_header('Set-Cookie',self.session_cookie()); self.send_header('Location','/'); self.send_header('Referrer-Policy','no-referrer'); self.end_headers(); return
        if not self.authorized():
            if u.path=='/':
                body=Path(__file__).with_name('login.html').read_bytes(); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(body); return
            return self.reply(401,{'error':'Open your private management link'})
        if u.path=='/api/sites': return self.reply(200,site_store.status())
        if u.path=='/api/status':
            active=read('config.json',{}).get('outbounds',[{}])[0]
            servers=[{'id':n['id'],'name':n['name'],'group':n['group'],'active':n['outbound']==active,'host':n['outbound']['settings']['vnext'][0]['address'],'health':health.get(n['id'],{}).copy()} for n in nodes]
            return self.reply(200,{'enabled':state['enabled'],'running':proc is not None and proc.poll() is None,'selected':state['selected'],'automatic':state.get('automatic',False),'connectivity':connectivity.copy(),'scan':scan.copy(),'job':job.copy(),'groups':[{'id':g['id'],'name':g['name'],'updatable':bool(g.get('source')),'info':g.get('info',{}),'updated':g.get('updated')} for g in groups],'trash':[{'id':g['id'],'name':g['group']['name']} for g in trash],'servers':servers})
        if u.path!='/': return self.reply(404,{'error':'Not found'})
        self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Referrer-Policy','no-referrer'); self.send_header('X-Frame-Options','DENY'); self.end_headers(); self.wfile.write(PANEL.read_bytes())
    def do_POST(self):
        global nodes,groups,trash
        self.connection.settimeout(25)
        if self.headers.get('Origin')!=ORIGIN: return self.reply(403,{'error':'Origin rejected'})
        if self.path=='/api/login': return self.login()
        if not self.authorized(): return self.reply(401,{'error':'Unauthorized'})
        try:
            length=int(self.headers.get('Content-Length','0'))
            if length<1 or length>262144: raise ValueError('Input too large')
            body=json.loads(self.rfile.read(length))
            if self.path=='/api/setup/check':return self.reply(200,inspect_router())
            if self.path in ('/api/sites/save','/api/sites/apply','/api/sites/rollback','/api/sites/presets'):
                if not site_lock.acquire(blocking=False):return self.reply(409,{'error':'عملیات سایت‌ها در حال اجراست'})
                try:
                    if self.path=='/api/sites/save':site_store.update(body.get('items'))
                    elif self.path=='/api/sites/presets':site_store.update(merge_presets(site_store.state()['items']))
                    else:site_store.apply(restore=self.path.endswith('/rollback'))
                    return self.reply(200,site_store.status())
                finally:site_lock.release()
            with lock:
                if self.path=='/api/toggle':
                    previous=state['enabled']; state['enabled']=bool(body['enabled'])
                    try: restart(); save('state.json',state)
                    except Exception: state['enabled']=previous; restart(); raise
                elif self.path in ('/api/import','/api/update'):
                    if job['running'] or scan['running']: raise ValueError('صبر کنید تست فعلی تمام شود')
                    group=next((g for g in groups if g['id']==body.get('group')),None)
                    if body.get('group') and group is None: raise ValueError('گروه پیدا نشد؛ صفحه را تازه کنید')
                    text=body.get('text','').strip()
                    if self.path=='/api/update':
                        if not group or not group.get('source'): raise ValueError('این گروه لینک اشتراک ندارد؛ لینک‌ها را دوباره وارد کنید')
                        text=group['source']
                    source=text if text.startswith('https://') else ''
                    response_headers={}
                    if text.startswith('https://'):
                        text,response_headers=fetch_subscription(text)
                    parsed=parse(text)
                    if group is None and source: group=next((g for g in groups if g.get('source')==source),None)
                    gid=group['id'] if group else secrets.token_hex(8)
                    added=normalize(parsed,gid)
                    if not added: raise ValueError('هیچ سرور واقعی در این ورودی نبود')
                    label=body.get('name','').strip()[:80] or (group['name'] if group else 'اشتراک '+str(len(groups)+1))
                    replacement={'id':gid,'name':label,'source':source,'info':subscription_info(text,response_headers),'updated':int(time.time())}
                    new_groups=[replacement if g['id']==gid else g for g in groups] if group else groups+[replacement]
                    new_nodes=[n for n in nodes if n['group']!=gid]+added
                    save('catalog.json',{'groups':new_groups,'nodes':new_nodes,'trash':trash}); groups=new_groups; nodes=new_nodes
                elif self.path=='/api/delete':
                    if job['running'] or scan['running']: raise ValueError('صبر کنید تست فعلی تمام شود')
                    group=next((g for g in groups if g['id']==body.get('group')),None)
                    if not group: raise ValueError('گروه پیدا نشد')
                    removed=[n for n in nodes if n['group']==group['id']]
                    new_trash=trash+[{'id':secrets.token_hex(8),'deleted':int(time.time()),'group':group,'nodes':removed}]
                    new_groups=[g for g in groups if g['id']!=group['id']]; new_nodes=[n for n in nodes if n['group']!=group['id']]
                    save('catalog.json',{'groups':new_groups,'nodes':new_nodes,'trash':new_trash});groups=new_groups;nodes=new_nodes;trash=new_trash
                elif self.path=='/api/restore':
                    if job['running'] or scan['running']: raise ValueError('صبر کنید تست فعلی تمام شود')
                    item=next((g for g in trash if g['id']==body.get('id')),None)
                    if not item: raise ValueError('گروه حذف‌شده پیدا نشد')
                    if any(g['id']==item['group']['id'] for g in groups): raise ValueError('این گروه قبلاً وجود دارد')
                    new_groups=groups+[item['group']];new_nodes=nodes+item['nodes'];new_trash=[g for g in trash if g['id']!=item['id']]
                    save('catalog.json',{'groups':new_groups,'nodes':new_nodes,'trash':new_trash});groups=new_groups;nodes=new_nodes;trash=new_trash
                elif self.path=='/api/apply':
                    node=next((n for n in nodes if n['id']==body.get('id')),None)
                    if node is None: raise ValueError('سرور را انتخاب کنید')
                    queue_job([node],'apply')
                elif self.path in ('/api/test','/api/speed'):
                    items=[n for n in nodes if (not body.get('id') or n['id']==body['id']) and (not body.get('group') or n['group']==body['group'])]
                    if self.path=='/api/speed' and (not body.get('id') or len(items)!=1): raise ValueError('برای تست سرعت یک سرور انتخاب کنید')
                    queue_job(items,'speed' if self.path=='/api/speed' else 'test')
                elif self.path=='/api/recover':
                    if job['running'] or scan['running']: raise ValueError('بازیابی یا تست در حال انجام است؛ کمی صبر کنید')
                    state['automatic']=True; state['enabled']=True
                    restart(); save('state.json',state)
                    threading.Thread(target=select_best,kwargs={'force':False},daemon=True).start()
                elif self.path=='/api/automatic':
                    state['automatic']=bool(body['enabled']); save('state.json',state)
                    if state['automatic'] and not scan['running']: threading.Thread(target=select_best,kwargs={'force':False},daemon=True).start()
                else: return self.reply(404,{'error':'Not found'})
            self.reply(200,{'ok':True})
        except Exception as exc:
            safe=str(exc) if isinstance(exc,ValueError) else 'Operation failed; current connection was preserved. Check the link or try another server.'
            self.reply(400,{'error':safe})
def supervise():
    while True:
        time.sleep(3)
        with lock:
            if proc is None or proc.poll() is not None:
                try: start()
                except Exception: pass
if __name__=='__main__':
    import sys
    if '--print-token' in sys.argv:
        print(TOKEN); sys.exit(0)
    def shutdown(signum,frame):
        stop(); raise SystemExit(0)
    signal.signal(signal.SIGTERM,shutdown)
    signal.signal(signal.SIGINT,shutdown)
    try: start()
    except Exception: print('Proxy not started; select a supported server in the panel',flush=True)
    threading.Thread(target=supervise,daemon=True).start()
    threading.Thread(target=monitor,daemon=True).start()
    ThreadingHTTPServer((BIND,PORT),Handler).serve_forever()
