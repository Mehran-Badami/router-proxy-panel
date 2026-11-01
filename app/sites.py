"""Private site preferences and narrowly scoped RouterOS DNS synchronization."""
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import ssl
import urllib.parse

PRESETS = [
    ('youtube', 'YouTube', ['youtube.com','youtu.be','googlevideo.com','ytimg.com','youtubei.googleapis.com','youtube-nocookie.com','youtube.googleapis.com','ggpht.com']),
    ('telegram', 'Telegram', ['telegram.org','t.me','telegram.me','tdesktop.com','telegra.ph','telesco.pe','telegram-cdn.org']),
    ('whatsapp', 'WhatsApp', ['whatsapp.com','whatsapp.net','wa.me']),
    ('instagram', 'Instagram', ['instagram.com','cdninstagram.com','ig.me','fbcdn.net','star.c10r.facebook.com']),
    ('x', 'X', ['x.com','twitter.com','t.co','twimg.com']),
    ('clubhouse', 'Clubhouse', ['clubhouse.com','clubhouseapi.com','joinclubhouse.com','agora.io','sd-rtn.com','rtnsvc.com','rtesvc.com']),
    ('spotify', 'Spotify', ['spotify.com','scdn.co','spotifycdn.com','pscdn.co','spotifycdn.net','spoti.fi','spotify.link','audio-ak-spotify-com.akamaized.net','audio4-ak-spotify-com.akamaized.net','heads-ak-spotify-com.akamaized.net','heads4-ak-spotify-com.akamaized.net','spotify.com.edgesuite.net','spotify.map.fastly.net','spotify.map.fastlylb.net','cdn-spotify-experiments.conductrics.com']),
    ('google-media', 'رسانه‌های مشترک گوگل', ['gstatic.com','googleusercontent.com']),
    ('assistant', 'Google Assistant', ['assistant.google.com','embeddedassistant.googleapis.com','speech.googleapis.com']),
    ('home', 'Google Home', ['home.google.com','googlehome.googleapis.com']),
]
PREFIX='RPP sites: '
PATH='/ip/dns/static'

def routing_names():
    """Allow an existing installation to retain its routing and watchdog names."""
    values=tuple(os.environ.get(key,default) for key,default in (
        ('ROUTEROS_SITE_LIST','rpp-sites'),('ROUTEROS_DNS_FORWARDER','RPP Secure DNS'),
        ('ROUTEROS_ROUTING_TABLE','rpp-proxy')))
    if any(not value.strip() or len(value)>64 or any(ord(c)<32 or ord(c)==127 for c in value) for value in values):
        raise ValueError('نام فهرست، فورواردِر یا جدول مسیر معتبر نیست')
    return values

def defaults():
    return [{'id':key,'name':name,'enabled':key not in ('assistant','home'),
             'subdomains':True,'domains':domains[:]} for key,name,domains in PRESETS]

def domain(value):
    if not isinstance(value,str):raise ValueError('دامنه باید متن باشد')
    value=value.strip().rstrip('.').lower()
    try:value=value.encode('idna').decode('ascii')
    except UnicodeError:raise ValueError('دامنه معتبر نیست') from None
    try:ipaddress.ip_address(value)
    except ValueError:pass
    else:raise ValueError('نام دامنه وارد کنید، نه IP')
    if len(value)>253 or '.' not in value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in value.split('.')):
        raise ValueError('فقط دامنه وارد کنید؛ بدون https، مسیر، فاصله یا ستاره')
    return value

def merge_presets(items):
    items=validate(items)
    by_id={item['id']:item for item in items}
    for preset in defaults():
        if preset['id'] in by_id:
            old=by_id[preset['id']]
            old['domains']=sorted(set(old['domains']+preset['domains']))
        else:items.append(preset)
    return validate(items)

def validate(items):
    if not isinstance(items,list) or len(items)>100:raise ValueError('حداکثر ۱۰۰ گروه سایت مجاز است')
    result=[];ids=set();total=0
    for item in items:
        if not isinstance(item,dict):raise ValueError('ساختار سایت معتبر نیست')
        key=item.get('id','');name=item.get('name','')
        if not isinstance(key,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',key) or key in ids:raise ValueError('شناسهٔ سایت معتبر نیست')
        if not isinstance(name,str) or not 1<=len(name.strip())<=80:raise ValueError('نام سایت لازم است؛ حداکثر ۸۰ حرف')
        if type(item.get('enabled')) is not bool or type(item.get('subdomains')) is not bool:raise ValueError('وضعیت سایت معتبر نیست')
        raw=item.get('domains')
        if not isinstance(raw,list) or not raw or len(raw)>100:raise ValueError('هر گروه باید بین ۱ تا ۱۰۰ دامنه داشته باشد')
        domains=sorted(set(domain(d) for d in raw));total+=len(domains)
        result.append(dict(id=key,name=name.strip(),enabled=item['enabled'],subdomains=item['subdomains'],domains=domains));ids.add(key)
    if total>500:raise ValueError('حداکثر ۵۰۰ دامنه مجاز است')
    return result

def records(items):
    address_list,forwarder,_=routing_names()
    merged={}
    for item in validate(items):
        if item['enabled']:
            for d in item['domains']:merged[d]=merged.get(d,False) or item['subdomains']
    return [dict(name=d,type='FWD',**{'address-list':address_list,'forward-to':forwarder,
            'match-subdomain':'true' if sub else 'false','disabled':'false','comment':PREFIX+d}) for d,sub in sorted(merged.items())]

def revision(items):return hashlib.sha256(json.dumps(validate(items),sort_keys=True).encode()).hexdigest()

class Router:
    def __init__(self):
        u=urllib.parse.urlsplit(os.environ.get('ROUTEROS_URL',''))
        if u.scheme!='https' or not u.hostname or u.username or u.password or u.path not in ('','/') or u.query or u.fragment:
            raise ValueError('ابتدا اتصال HTTPS روتر را در تنظیمات نصب برقرار کنید')
        self.host=u.hostname;self.port=u.port or 443
        user=os.environ.get('ROUTEROS_USER','');password_file=os.environ.get('ROUTEROS_PASSWORD_FILE','')
        if not user or not password_file:raise ValueError('حساب اتصال روتر تنظیم نشده است')
        from pathlib import Path
        password=Path(password_file).read_text().rstrip('\r\n')
        self.auth='Basic '+base64.b64encode((user+':'+password).encode()).decode()
        self.context=ssl.create_default_context(cafile=os.environ.get('ROUTEROS_CA_FILE') or None)

    def request(self,method,path,data=None):
        conn=http.client.HTTPSConnection(self.host,self.port,context=self.context,timeout=10)
        try:
            conn.request(method,'/rest'+path,json.dumps(data) if data is not None else None,
                         {'Authorization':self.auth,'Content-Type':'application/json'})
            response=conn.getresponse();body=response.read(2097153)
            if not 200<=response.status<300 or len(body)>2097152:raise ValueError('درخواست روتر ناموفق بود؛ دسترسی و تنظیمات را بررسی کنید')
            return json.loads(body) if body else None
        except (OSError,http.client.HTTPException,json.JSONDecodeError):
            raise ValueError('ارتباط امن با روتر برقرار نشد؛ گواهی، آدرس و دسترسی را بررسی کنید') from None
        finally:conn.close()

def owned(row):return str(row.get('comment','')).startswith(PREFIX)

def clean(row):
    return {key:row.get(key,'false' if key in ('disabled','match-subdomain') else '') for key in
            ('name','type','address-list','forward-to','match-subdomain','disabled','comment')}

def sync(router, desired):
    """Only touch this feature's DNS records; verify readback. Retry reconciles partial writes."""
    current=router.request('GET',PATH)
    names={r['name'] for r in desired}
    # A manually adopted, unchanged rule can coexist with a historical overlap.
    # Never introduce or expand an overlap, and never exempt regex rules.
    unchanged=[clean(r) for r in current if owned(r)]
    if any(not owned(r) and r.get('disabled','false')=='false' and
           (r.get('regexp') or any(d not in unchanged and (r.get('name')==n or
            (r.get('match-subdomain')=='true' and n.endswith('.'+r.get('name',''))) or
            (d['match-subdomain']=='true' and r.get('name','').endswith('.'+n)))
            for d in desired for n in [d['name']])) for r in current):
        raise ValueError('دامنه با قانون DNS موجود تداخل دارد؛ هیچ تغییری اعمال نشد')
    by_name={}
    for row in current:
        if owned(row):by_name.setdefault(row.get('name'),[]).append(row)
    for row in desired:
        found=by_name.get(row['name'],[])
        if found:
            if clean(found[0])!=row:router.request('PATCH',PATH+'/'+urllib.parse.quote(found[0]['.id'],safe='*'),row)
            for duplicate in found[1:]:router.request('DELETE',PATH+'/'+urllib.parse.quote(duplicate['.id'],safe='*'))
        else:router.request('PUT',PATH,row)
    for row in current:
        if owned(row) and row.get('name') not in names:router.request('DELETE',PATH+'/'+urllib.parse.quote(row['.id'],safe='*'))
    actual=[clean(r) for r in router.request('GET',PATH) if owned(r)]
    if sorted(actual,key=lambda r:r['name'])!=sorted(desired,key=lambda r:r['name']):raise ValueError('تأیید نهایی روتر ناموفق بود؛ وضعیت ممکن است ناقص باشد')

def preflight(router):
    address_list,forwarder,table=routing_names()
    fw=router.request('GET','/ip/dns/forwarders')
    if not any(x.get('name')==forwarder for x in fw):raise ValueError('فورواردِر DNS تنظیم‌شده روی روتر پیدا نشد: '+forwarder)
    rules=router.request('GET','/ip/firewall/mangle')
    if not any(r.get('disabled','false')=='false' and r.get('dst-address-list')==address_list for r in rules):
        raise ValueError('قوانین فهرست مسیر نصب نشده‌اند: '+address_list)
    if not any(r.get('disabled','false')=='false' and r.get('action')=='mark-routing' and r.get('new-routing-mark')==table for r in rules):
        raise ValueError('قانون علامت‌گذاری مسیر نصب نشده است: '+table)
    routes=router.request('GET','/ip/route')
    if not any(r.get('routing-table')==table and r.get('dst-address')=='0.0.0.0/0' and r.get('active')=='true' for r in routes):
        raise ValueError('مسیر فعال تونل پیدا نشد: '+table)
    filters=router.request('GET','/ip/firewall/filter')
    if any(r.get('disabled','false')=='false' and r.get('action')=='fasttrack-connection' and r.get('connection-mark')!='no-mark' for r in filters):
        raise ValueError('ابتدا FastTrack را به اتصال‌های بدون علامت محدود کنید؛ راهنما را بخوانید')

class SiteStore:
    def __init__(self,read,save):self.read=read;self.save=save
    def state(self):return self.read('sites.json',{'items':defaults(),'applied_revision':None,'message':'فهرست اولیه هنوز روی روتر اعمال نشده است'})
    def status(self):
        s=self.state();s['configured']=bool(os.environ.get('ROUTEROS_URL'))
        s['pending']=revision(s['items'])!=s.get('applied_revision') or bool(s.get('route_cleanup'));return s
    def update(self,items):
        s=self.state();s['items']=validate(items);s['message']='ذخیره شد؛ برای ارسال به روتر «اعمال» را بزنید';self.save('sites.json',s)
    def apply(self,restore=False):
        s=self.state();router=Router()
        if not restore:preflight(router)
        before=[clean(r) for r in router.request('GET',PATH) if owned(r)]
        if restore:
            backup=self.read('sites-previous.json',None)
            if backup is None:raise ValueError('نسخهٔ قبلی موجود نیست')
            desired=backup['records']
        else:
            desired=records(s['items'])
            if not s.get('incomplete') and not s.get('route_cleanup'):
                self.save('sites-previous.json',{'records':before})
        cleanup=s.get('route_cleanup') or {'records':[],'addresses':[]}
        for row in before+records([{**item,'enabled':True} for item in s['items']]):
            if row not in cleanup['records']:cleanup['records'].append(row)
        s['route_cleanup']=cleanup
        s['incomplete']=True
        s['applied_revision']=None;s['message']='در حال اعمال؛ در صورت قطع ارتباط نتیجه را دوباره بررسی کنید';self.save('sites.json',s)
        try:
            sync(router,desired)
            s['incomplete']=False
            s['applied_revision']=None if restore else revision(s['items'])
            s['message']='قوانین قبلی بازگردانده شدند؛ فهرست ویرایش‌شده حفظ شد' if restore else 'قوانین DNS اعمال و از روتر بازخوانی شدند؛ اتصال واقعی سایت را آزمایش کنید'
        except Exception:
            s['message']='اعمال کامل تأیید نشد؛ ممکن است بخشی اجرا شده باشد. دوباره اعمال کنید یا بازگردانی را بزنید'
            if not restore:
                try:
                    previous=self.read('sites-previous.json',None)
                    if previous is None:raise ValueError('Missing backup')
                    sync(router,previous['records'])
                    s['incomplete']=False
                    s['message']='اعمال ناموفق بود؛ قوانین قبلی به‌صورت خودکار بازگردانده و تأیید شدند'
                except Exception:
                    s['message']='ارتباط یا اعمال ناموفق بود و بازگردانی خودکار تأیید نشد؛ بکاپ محفوظ است. اتصال روتر را بررسی و بازگردانی را اجرا کنید'
            self.save('sites.json',s)
            raise ValueError(s['message']) from None
        try:
            from site_cleanup import retire,warm
            address_list,_,table=routing_names()
            mark=os.environ.get('ROUTEROS_CONNECTION_MARK',table)
            if not mark.strip():raise ValueError('Connection mark is empty')
            def checkpoint(addresses):
                cleanup['addresses']=addresses;self.save('sites.json',s)
            warmed=warm(router,desired,address_list)
            result=retire(router,cleanup['records'],desired,address_list,mark,cleanup['addresses'],checkpoint)
            result['cached_addresses_restored']=warmed
            s['route_cleanup']=None;s['cleanup_result']=result
            s['message']+='؛ مسیرهای قدیمی پاک‌سازی شدند'
            if result['shared_addresses']:s['message']+='؛ IPهای مشترک با قواعد دیگر حفظ شدند'
        except Exception:
            s['message']='قوانین DNS ثبت شدند؛ پاک‌سازی مسیرهای قدیمی کامل نشد. برای تکمیل دوباره «اعمال» را بزنید'
            self.save('sites.json',s)
            raise ValueError(s['message']) from None
        self.save('sites.json',s)
