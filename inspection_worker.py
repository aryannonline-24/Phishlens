"""Container entrypoint. Static HTML inspection only; no script execution."""
from html.parser import HTMLParser
import json
import sys
from urllib.parse import urljoin, urlsplit
from safe_fetch import fetch


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.password_fields = 0
        self.forms = []
        self.title = ''
        self.in_title = False
        self.refresh = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'input' and a.get('type', '').lower() == 'password':
            self.password_fields += 1
        if tag == 'form':
            self.forms.append(a.get('action', '')[:2048])
        if tag == 'title':
            self.in_title = True
        if tag == 'meta' and a.get('http-equiv', '').lower() == 'refresh':
            self.refresh = True

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title = (self.title + data)[:300]


def inspect_url(url):
    result = fetch(url)
    parser = Page()
    parser.feed(result.pop('body'))
    forms = [urljoin(result['url'], a) for a in parser.forms[:30]]
    return dict(**result, title=parser.title, password_fields=parser.password_fields,
                form_destinations=forms,
                cross_host_forms=[u for u in forms if urlsplit(u).hostname != urlsplit(result['url']).hostname],
                meta_refresh_present=parser.refresh,
                warning='Static HTML only. Scripts and meta-refresh are not executed; forms are not submitted. Login fields alone do not prove phishing.')


if __name__ == '__main__':
    try:
        payload = json.loads(sys.stdin.read(4096))
        print(json.dumps(inspect_url(payload['url'])))
    except Exception as exc:
        print(json.dumps({'error': str(exc)[:300]}))
        sys.exit(1)
