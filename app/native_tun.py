"""Opt-in IPv4 gateway settings; network setup runs only during container startup."""
import ipaddress
import os
import re

TABLE=1001
PRIORITY=11000
DEVICE='/dev/net/tun'

def settings(environ=None):
    env=os.environ if environ is None else environ
    mode=env.get('RPP_GATEWAY_MODE','off')
    if mode=='off':return None
    if mode!='tun':raise ValueError('RPP_GATEWAY_MODE must be off or tun')
    interface=env.get('RPP_GATEWAY_INTERFACE','eth0')
    name=env.get('RPP_TUN_NAME','rpp0')
    if any(not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,14}',n) or n=='lo' for n in (interface,name)) or interface==name:
        raise ValueError('Invalid gateway or TUN interface name')
    try:mtu=int(env.get('RPP_TUN_MTU','1500'))
    except ValueError:raise ValueError('Invalid TUN MTU') from None
    if not 576<=mtu<=9000:raise ValueError('TUN MTU must be between 576 and 9000')
    raw=env.get('RPP_LAN_CIDRS','').split(',')
    if not 1<=len(raw)<=16 or any(not x.strip() for x in raw):
        raise ValueError('RPP_LAN_CIDRS must explicitly list the client IPv4 networks')
    networks=[]
    for value in raw:
        n=ipaddress.ip_network(value.strip(),strict=True)
        if n.version!=4 or n.prefixlen==0 or n.is_multicast or n.is_loopback or n.is_link_local or n.network_address.is_unspecified:
            raise ValueError('Use explicit unicast client IPv4 networks, not a default route')
        if str(n) not in networks:networks.append(str(n))
    return {'interface':interface,'name':name,'mtu':mtu,'networks':networks}

def inbound():
    s=settings()
    if not s:return None
    # The entrypoint owns addresses/routes. Xray only receives the open TUN FD.
    return {'tag':'rpp-tun','port':0,'protocol':'tun','settings':{'name':s['name'],'mtu':s['mtu']}}

def inherited_fds():
    if not settings():return ()
    try:
        fd=int(os.environ['XRAY_TUN_FD'])
        if fd<3:raise ValueError()
        os.fstat(fd)
    except (KeyError,ValueError,OSError):
        raise ValueError('Gateway startup did not provide an open TUN device') from None
    return (fd,)
