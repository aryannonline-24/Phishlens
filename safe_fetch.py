"""Public HTTP(S) fetch with DNS validation and connection IP pinning.

No proxy environment, cookies, auth, decompression or ambient browser state.
Call only within an explicit network workflow, never during offline analysis.
"""
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit, urljoin

LIMIT = 512 * 1024


def public_target(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 for c in url):
        raise ValueError('Invalid inspection URL.')
    p = urlsplit(url)
    if p.scheme not in {'http', 'https'} or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError('Use HTTP(S) without embedded credentials.')
    port = p.port or (443 if p.scheme == 'https' else 80)
    if port not in {80, 443}:
        raise ValueError('Only ports 80 and 443 are allowed.')
    host = p.hostname.encode('idna').decode('ascii')
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = list(dict.fromkeys(answer[4][0] for answer in answers))
    if not ips:
        raise ValueError('No public address found.')
    for value in ips:
        ip = ipaddress.ip_address(value)
        if not ip.is_global or ip.is_multicast or ip.is_reserved or getattr(ip, 'ipv4_mapped', None):
            raise ValueError('Private, reserved, multicast and local network addresses are blocked.')
    return p, host, port, ips[0]


def fetch(url, accept='text/html', redirects=3):
    chain = []
    for hop in range(redirects + 1):
        p, host, port, ip = public_target(url)
        conn = http.client.HTTPConnection(host, port, timeout=5)
        try:
            sock = socket.create_connection((ip, port), timeout=5)
            conn.sock = sock
            if p.scheme == 'https':
                conn.sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            path = p.path or '/'
            if p.query:
                path += '?' + p.query
            conn.request('GET', path, headers={'Accept': accept, 'Accept-Encoding': 'identity', 'User-Agent': 'PhishLens-inspector/1.0'})
            response = conn.getresponse()
            chain.append(dict(url=url, status=response.status))
            if response.status in {301, 302, 303, 307, 308}:
                location = response.getheader('Location')
                if not location or hop == redirects:
                    raise ValueError('Redirect limit exceeded or missing redirect location.')
                url = urljoin(url, location)
                continue
            if response.getheader('Content-Disposition', '').lower().startswith('attachment'):
                raise ValueError('Attachment downloads are blocked.')
            content_type = response.getheader('Content-Type', '').split(';')[0].lower()
            allowed = {'text/html', 'application/xhtml+xml'} if accept == 'text/html' else {'application/json', 'application/rdap+json'}
            if content_type not in allowed:
                raise ValueError('Unsupported response type; only the requested HTML or JSON is read.')
            if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
                raise ValueError('Compressed responses are not inspected.')
            body = response.read(LIMIT + 1)
            if len(body) > LIMIT:
                raise ValueError('Response exceeds 512 KB.')
            return dict(url=url, status=response.status, chain=chain, body=body.decode('utf-8', errors='replace'))
        finally:
            conn.close()
    raise ValueError('Redirect limit exceeded.')
