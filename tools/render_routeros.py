"""Generate reviewed DNS integration scripts; never connects to a router."""
import argparse
import ipaddress
from pathlib import Path

def render(panel_ip, fallback_dns=None):
    panel_ip=str(ipaddress.IPv4Address(panel_ip))
    fallback=[str(ipaddress.IPv4Address(x)) for x in (fallback_dns or [])]
    secure='https://8.8.8.8/dns-query'
    install=f'''# REVIEW BEFORE IMPORT. Back up /ip dns and firewall configuration privately.
# Requires a healthy selected server, trusted CA store and correct router time.
:if ([:len [/ip firewall nat find comment="RPP DoH relay"]]>0) do={{:error "RPP already installed"}}
/ip firewall nat add chain=output protocol=tcp dst-address=8.8.8.8 dst-port=443 action=dst-nat to-addresses={panel_ip} to-ports=8443 comment="RPP DoH relay"
/ip dns forwarders add name="RPP Secure DNS" doh-servers={secure} verify-doh-cert=yes
/ip dns set use-doh-server={secure} verify-doh-cert=yes doh-timeout=15s
/ip dns cache flush
'''
    if fallback:
        servers=','.join(fallback)
        script=f''':local watch [/tool netwatch find name="RPP DNS watchdog"]; :local healthy ([/tool netwatch get $watch status]="up"); :local age ([:timestamp]+[:totime ([/system clock get gmt-offset]."s")]-[/tool netwatch get $watch since]); :if ($healthy && ($age>=30s) && ([/ip dns get use-doh-server]="")) do={{/ip dns forwarders set [find name="RPP Secure DNS"] dns-servers="" doh-servers={secure} verify-doh-cert=yes; /ip dns set use-doh-server={secure} verify-doh-cert=yes; /ip dns cache flush; :log info "RPP: encrypted DNS restored"}}; :if ((!$healthy) && ($age>=1m) && ([/ip dns get use-doh-server]!="")) do={{/ip dns forwarders set [find name="RPP Secure DNS"] doh-servers="" dns-servers={servers}; /ip dns set use-doh-server="" servers={servers}; /ip dns cache flush; :log warning "RPP: ordinary DNS fallback active"}}'''
        install+=f'/tool netwatch add name="RPP DNS watchdog" host=8.8.8.8 type=https-get port=443 check-certificate=yes http-codes=200-399 interval=30s timeout=15s thr-http-time=15s startup-delay=30s test-script={{{script}}}\n'
    rollback='''# STOP automatic changes first, then restore your previously saved DNS settings.
/tool netwatch disable [find name="RPP DNS watchdog"]
# If DNS previously used only standard resolvers, this restores that mode:
/ip dns set use-doh-server=""
/ip firewall nat disable [find comment="RPP DoH relay"]
# Restore original /ip dns servers and any FWD rules from your private backup.
# Do not delete container data; keeping it permits rollback.
/ip dns cache flush
'''
    return install,rollback

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--panel-ip',required=True)
    parser.add_argument('--fallback-dns',nargs='+',help='Explicit opt-in to unencrypted DNS fallback')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    if args.output.resolve().is_relative_to(root):parser.error('Write operator-specific scripts outside the source repository')
    install,rollback=render(args.panel_ip,args.fallback_dns)
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'enable-dns.rsc').write_text(install,encoding='utf-8')
    (args.output/'rollback-dns.rsc').write_text(rollback,encoding='utf-8')
    print('Generated scripts locally. Review before importing; no router was changed.')
