"""Create a TUN in the container namespace, then permanently drop privileges.

Only forwarded IPv4 packets from the declared LAN networks enter table 1001.
Locally originated Xray, panel and bootstrap connections keep the main table.
"""
import ctypes
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

from native_tun import DEVICE,PRIORITY,TABLE,settings

def command(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=10).stdout

def sysctl(path,value):
    target=Path(path)
    if target.read_text().strip()!=value:
        target.write_text(value)

def setup(s):
    import fcntl
    if os.geteuid()!=0:raise ValueError('TUN gateway startup requires user=0:0; the service then drops to 10001')
    # Refuse a reused or host network namespace with conflicting configuration.
    rules=json.loads(command('ip','-j','-4','rule','show'))
    if any(r.get('priority')==PRIORITY or str(r.get('table'))==str(TABLE) for r in rules):
        raise ValueError('Gateway policy table/priority is already in use; use a dedicated container interface')
    routes=json.loads(command('ip','-j','-4','route','show','table','all'))
    if any(str(r.get('table'))==str(TABLE) for r in routes):
        raise ValueError('Gateway route table is already in use')
    links=json.loads(command('ip','-j','link','show'))
    if not any(x['ifname']==s['interface'] for x in links) or any(x['ifname']==s['name'] for x in links):
        raise ValueError('Gateway interface is missing or TUN name is already in use')
    fd=os.open(DEVICE,os.O_RDWR|os.O_NONBLOCK)
    added=[]
    try:
        fcntl.ioctl(fd,0x400454ca,struct.pack('16sH',s['name'].encode(),0x0001|0x1000))
        command('ip','link','set','dev',s['name'],'mtu',str(s['mtu']),'up')
        sysctl('/proc/sys/net/ipv4/ip_forward','1')
        # Loose reverse-path checks support replies from the TUN without disabling validation.
        for name in ('all',s['interface'],s['name']):
            sysctl(str(Path('/proc/sys/net/ipv4/conf',name,'rp_filter')),'2')
        bypass=set(s['networks'])|{'0.0.0.0/8','10.0.0.0/8','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/4','240.0.0.0/4'}
        for network in sorted(bypass):
            command('ip','-4','route','add','throw',network,'table',str(TABLE))
        command('ip','-4','route','add','default','dev',s['name'],'table',str(TABLE))
        for network in s['networks']:
            rule=('priority',str(PRIORITY),'iif',s['interface'],'from',network,'lookup',str(TABLE))
            command('ip','-4','rule','add',*rule);added.append(rule)
        os.set_inheritable(fd,True)
        return fd
    except Exception:
        for rule in reversed(added):
            subprocess.run(['ip','-4','rule','del',*rule],capture_output=True)
        subprocess.run(['ip','-4','route','flush','table',str(TABLE)],capture_output=True)
        os.close(fd)
        raise

def main():
    s=settings()
    if s:
        fd=setup(s)
        data=Path(os.environ.get('APP_DATA','/data'));data.mkdir(parents=True,exist_ok=True)
        os.chown(data,10001,10001);data.chmod(0o700)
        os.environ['XRAY_TUN_FD']=str(fd)
        os.setgroups([]);os.setgid(10001);os.setuid(10001)
        if ctypes.CDLL(None,use_errno=True).prctl(38,1,0,0,0)!=0:
            raise OSError(ctypes.get_errno(),'Cannot set no_new_privs')
        print('Native Xray TUN gateway ready; service UID=10001',flush=True)
    else:
        os.environ.pop('XRAY_TUN_FD',None)
    os.execv(sys.executable,[sys.executable,str(Path(__file__).with_name('manager.py')),*sys.argv[1:]])

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('Gateway startup failed: '+str(exc),file=sys.stderr)
        raise SystemExit(1)
