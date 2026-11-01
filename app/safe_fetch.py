"""Bounded HTTPS subscription downloads; no private-network redirects or DNS rebinding."""
import http.client
import ipaddress
import socket
import ssl
import urllib.parse

LIMIT = 262144

def public_addresses(host, port):
    rows = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(row[4][0] for row in rows))
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ValueError('Subscription host must resolve only to public addresses')
    return addresses

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address):
        super().__init__(host, port, timeout=20, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise

def fetch_subscription(url):
    for _ in range(4):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError('Use an HTTPS subscription URL without embedded credentials or fragment')
        port = parsed.port or 443
        addresses = public_addresses(parsed.hostname, port)
        connection = PinnedHTTPS(parsed.hostname, port, addresses[0])
        try:
            path = urllib.parse.urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
            connection.request('GET', path, headers={'User-Agent': 'v2rayN', 'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                destination = response.getheader('Location')
                if not destination:
                    raise ValueError('Subscription redirect has no destination')
                url = urllib.parse.urljoin(url, destination)
                continue
            if response.status != 200:
                raise ValueError('Subscription server did not return HTTP 200')
            body = response.read(LIMIT + 1)
            if len(body) > LIMIT:
                raise ValueError('Subscription exceeds 256 KiB')
            return body.decode('utf-8-sig'), dict(response.getheaders())
        except (OSError, UnicodeError, http.client.HTTPException):
            raise ValueError('Subscription download failed; previous group was preserved') from None
        finally:
            connection.close()
    raise ValueError('Too many subscription redirects')
