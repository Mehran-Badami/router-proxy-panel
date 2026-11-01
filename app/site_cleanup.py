"""Retire only DNS-derived routes owned by the site's selection history."""
import ipaddress
import re
import urllib.parse

ADDRESS_PATH='/ip/firewall/address-list'
CONNECTION_PATH='/ip/firewall/connection'

def covers(host, rules):
    return any(r.get('disabled','false')=='false' and
               (host==r.get('name') or r.get('match-subdomain')=='true' and host.endswith('.'+r.get('name','')))
               for r in rules if r.get('name'))

def origin(row):
    comment=row.get('comment','')
    m=re.fullmatch(r'created for ([a-zA-Z0-9.-]+)\.',comment) or re.fullmatch(r'RPP DNS cache: ([a-zA-Z0-9.-]+)',comment)
    return m[1].lower() if m else None

def network(value):
    try:return ipaddress.ip_network(value,strict=False)
    except ValueError:return None

def ttl_seconds(value):
    if re.fullmatch(r'(?:\d+(?:ms|[wdhms]))+',value):
        units={'w':604800,'d':86400,'h':3600,'m':60,'s':1,'ms':0.001}
        return min(86400,int(sum(int(n)*units[u] for n,u in re.findall(r'(\d+)(ms|[wdhms])',value))))
    m=re.fullmatch(r'(?:(\d+)d)?(\d+):(\d+):(\d+)',value)
    if m:return min(86400,int(m[1] or 0)*86400+int(m[2])*3600+int(m[3])*60+int(m[4]))
    return 0

def warm(router, desired, address_list):
    """Re-enabling a FWD rule does not repopulate routes for already cached answers."""
    rows=router.request('GET',ADDRESS_PATH)
    # RouterOS rejects another row for the same address, even with a new origin.
    protected=[network(r.get('address','')) for r in rows if r.get('list')==address_list and r.get('disabled','false')=='false']
    added=0
    for record in router.request('GET','/ip/dns/cache'):
        host=record.get('name','').lower().rstrip('.')
        if record.get('type')!='A' or not covers(host,desired):continue
        n=network(record.get('data',''));seconds=ttl_seconds(record.get('ttl',''))
        if not n or n.version!=4 or n.prefixlen!=32 or not n.network_address.is_global or seconds<=0:continue
        if any(other and other.version==4 and n.network_address in other for other in protected):continue
        try:router.request('PUT',ADDRESS_PATH,{'list':address_list,'address':str(n.network_address),'timeout':str(seconds)+'s','comment':'RPP DNS cache: '+host})
        except ValueError:
            # A concurrent client DNS lookup may have created this route first.
            live=router.request('GET',ADDRESS_PATH)
            if not any(r.get('list')==address_list and r.get('address')==str(n.network_address) and r.get('disabled','false')=='false' for r in live):raise
        protected.append(n);added+=1
    return added

def retire(router, known, desired, address_list, connection_mark, pending, checkpoint):
    """Persist exact destinations before deletions; a retry completes interrupted cleanup.

    Other origins, static entries, other address lists and other connection marks
    are preserved. Shared addresses retain their route and existing connections.
    """
    active=router.request('GET','/ip/dns/static')
    references=[r for r in active if r.get('address-list')==address_list and r.get('disabled','false')=='false']
    if any(r.get('regexp') for r in references):
        raise ValueError('قانون DNS با الگوی عمومی مانع پاک‌سازی محدود است')
    rows=router.request('GET',ADDRESS_PATH)
    candidates=[r for r in rows if r.get('list')==address_list and r.get('dynamic')=='true'
                and origin(r) and covers(origin(r),known) and not covers(origin(r),desired)
                and not covers(origin(r),references)]
    shared=set()
    for record in router.request('GET','/ip/dns/cache'):
        if record.get('type')=='A' and ttl_seconds(record.get('ttl',''))>0 and covers(record.get('name','').lower().rstrip('.'),desired+references):
            n=network(record.get('data',''))
            if n and n.version==4 and n.prefixlen==32:shared.add(str(n.network_address))
    addresses=set(pending)
    for row in candidates:
        n=network(row.get('address',''))
        if n and n.version==4 and n.prefixlen==32:addresses.add(str(n.network_address))
    candidates=[r for r in candidates if r.get('address') not in shared]
    selected={r['.id'] for r in candidates}
    checkpoint(sorted(addresses))
    for row in candidates:
        router.request('DELETE',ADDRESS_PATH+'/'+urllib.parse.quote(row['.id'],safe='*'))
    remaining=router.request('GET',ADDRESS_PATH)
    if any(r['.id'] in selected for r in remaining):raise ValueError('پاک‌سازی IPهای قدیمی تأیید نشد')
    protected=[network(r.get('address','')) for r in remaining if r.get('list')==address_list and r.get('disabled','false')=='false']
    isolated={a for a in addresses if not any(n and n.version==4 and ipaddress.ip_address(a) in n for n in protected)}
    removed=[]
    if isolated:
        connections=router.request('GET',CONNECTION_PATH)
        for row in connections:
            # Current RouterOS uses separate port fields; older versions append :port.
            dst=row.get('dst-address','')
            if dst not in isolated:dst=dst.rsplit(':',1)[0]
            if row.get('connection-mark')==connection_mark and dst in isolated:
                router.request('DELETE',CONNECTION_PATH+'/'+urllib.parse.quote(row['.id'],safe='*'))
                removed.append(row['.id'])
    return {'addresses_removed':len(candidates),'connections_restarted':len(removed),'shared_addresses':len(addresses-isolated)}
