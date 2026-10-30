"""Explicitly opted-in network integrations, with bounded in-memory caching."""
import hashlib
import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from urllib.parse import urlencode, quote
from rules import parse_url, normalize_url
from safe_fetch import fetch

CACHE = {}
LOCK = threading.Lock()
INSPECTION_LOCK = threading.BoundedSemaphore(1)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def reputation(raw_url):
    url = normalize_url(raw_url)
    parsed = parse_url(url)
    if not parsed or parsed['protocol'] not in {'http', 'https'} or parsed['has_at']:
        raise ValueError('Use an explicit HTTP(S) URL without credentials.')
    key = hashlib.sha256(url.encode()).hexdigest()
    with LOCK:
        cached = CACHE.get(key)
        if cached and time.monotonic() - cached[0] < 900:
            return {**cached[1], 'cached': True}
    result = dict(provider='URLhaus + RDAP', cached=False,
                  warning='Not listed does not mean safe. URLhaus covers known malware URLs, not all phishing.',
                  urlhaus={'status': 'unavailable'}, registration={'status': 'unavailable'})
    auth = os.environ.get('URLHAUS_AUTH_KEY')
    if auth:
        request = Request('https://urlhaus-api.abuse.ch/v1/url/',
                          data=urlencode({'url': url}).encode(), headers={'Auth-Key': auth})
        try:
            opener = build_opener(ProxyHandler({}), NoRedirect())
            with opener.open(request, timeout=8) as response:
                body = response.read(512 * 1024 + 1)
            if len(body) > 512 * 1024:
                raise ValueError('Provider response too large.')
            data = json.loads(body)
            state = data.get('query_status')
            result['urlhaus'] = dict(status='listed' if state == 'ok' else 'not_listed' if state == 'no_results' else 'unavailable',
                                     threat=data.get('threat'), url_status=data.get('url_status'))
        except Exception:
            result['urlhaus'] = {'status': 'unavailable', 'detail': 'Provider lookup failed; no safety conclusion.'}
    else:
        result['urlhaus']['detail'] = 'Configure URLHAUS_AUTH_KEY to enable reputation lookup.'
    try:
        response = fetch('https://rdap.org/domain/' + quote(parsed['registered_domain'], safe=''), accept='application/rdap+json', redirects=2)
        if response['status'] == 200:
            data = json.loads(response['body'])
            result['registration'] = dict(status='available', domain=parsed['registered_domain'],
                                           events=[{'action': e.get('eventAction'), 'date': e.get('eventDate')}
                                                   for e in data.get('events', [])[:20]])
    except Exception:
        result['registration']['detail'] = 'Registration lookup unavailable.'
    with LOCK:
        if len(CACHE) >= 128:
            CACHE.pop(next(iter(CACHE)))
        CACHE[key] = (time.monotonic(), result)
    return result


def inspect(raw_url):
    if os.environ.get('PHISHLENS_ENABLE_INSPECTION') != '1':
        raise ValueError('Website inspection is disabled. Build the worker image and set PHISHLENS_ENABLE_INSPECTION=1.')
    docker = shutil.which('docker')
    if not docker:
        raise ValueError('Docker is required; inspection never falls back to a host process.')
    if not INSPECTION_LOCK.acquire(blocking=False):
        raise ValueError('An inspection is already running. Try again shortly.')
    name = 'phishlens-' + uuid.uuid4().hex
    try:
        command = [docker, 'run', '--rm', '-i', '--pull=never', '--name', name,
                   '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                   '--memory=128m', '--cpus=0.5', '--pids-limit=32', '--user=65534:65534',
                   '--network=bridge', 'phishlens-inspector:1']
        output = subprocess.run(command, input=json.dumps({'url': normalize_url(raw_url)}),
                                capture_output=True, text=True, timeout=30)
        try:
            result = json.loads(output.stdout)
        except ValueError as exc:
            raise ValueError('Inspector unavailable. Verify Docker and build the local worker image.') from exc
        if output.returncode or result.get('error'):
            raise ValueError(result.get('error', 'Inspection failed.'))
        return result
    except subprocess.TimeoutExpired as exc:
        raise ValueError('Inspection exceeded the 30-second limit.') from exc
    finally:
        try:
            subprocess.run([docker, 'rm', '-f', name], capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        finally:
            INSPECTION_LOCK.release()
