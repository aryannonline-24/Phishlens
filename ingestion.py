"""Bounded offline email and image extraction. Uploaded HTML is never rendered."""
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
import io
import os
import shutil
import json
from pathlib import Path
import subprocess
import tempfile
import re
from urllib.parse import urljoin, urlsplit
from rules import parse_url, MAX_MESSAGE, MAX_URLS, KNOWN_BRANDS

MAX_FILE = 5 * 1024 * 1024


class HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self.forms = [], [], []
        self.anchor = None
        self.hidden = 0
        self.password_fields = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {'script', 'style'}:
            self.hidden += 1
        if tag == 'a':
            self.anchor = {'href': attrs.get('href', '')[:2048], 'text': ''}
        if tag == 'input' and attrs.get('type', '').lower() == 'password':
            self.password_fields += 1
        if tag == 'form':
            self.forms.append(attrs.get('action', '')[:2048])

    def handle_endtag(self, tag):
        if tag in {'script', 'style'}:
            self.hidden = max(0, self.hidden - 1)
        if tag == 'a' and self.anchor:
            self.links.append(self.anchor)
            self.anchor = None
        if tag in {'p', 'div', 'br', 'li'}:
            self.text.append('\n')

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            if self.anchor:
                self.anchor['text'] += data


def domain(address):
    try:
        return parse_url(address)['registered_domain']
    except (ValueError, TypeError):
        return ''


def email_extract(raw):
    if len(raw) > MAX_FILE:
        raise ValueError('Email exceeds 5 MB.')
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    text, links, attachments, findings = [], [], [], []
    for index, part in enumerate(msg.walk()):
        if index >= 100:
            raise ValueError('Email contains too many MIME parts.')
        if part.get_content_disposition() == 'attachment' or part.get_filename():
            attachments.append((part.get_filename() or 'unnamed attachment')[:200])
            continue
        if part.is_multipart() or part.get_content_type() not in {'text/plain', 'text/html'}:
            continue
        body = (part.get_payload(decode=True) or b'').decode(part.get_content_charset() or 'utf-8', errors='replace')
        if part.get_content_type() == 'text/html':
            parser = HTMLText()
            parser.feed(body)
            text.append(' '.join(parser.text))
            links.extend(parser.links)
        else:
            text.append(body)
    senders = getaddresses(msg.get_all('from', []))
    replies = getaddresses(msg.get_all('reply-to', []))
    if len(senders) != 1:
        findings.append(dict(label='Ambiguous From header', evidence=str(senders)))
    if senders and replies and {a.lower() for _, a in senders} != {a.lower() for _, a in replies}:
        findings.append(dict(label='From and Reply-To differ', evidence=f'{senders} → {replies}'))
    for name, address in senders:
        sender_domain = domain(address.rsplit('@', 1)[-1]) if '@' in address else ''
        for brand in KNOWN_BRANDS:
            if sender_domain and sender_domain != brand and re.search(r'\b' + re.escape(brand.split('.')[0]) + r'\b', name, re.I):
                findings.append(dict(label='Brand display name uses a different sender domain', evidence=f'{name} <{address}> (expected brand domain: {brand})'))
    for link in links:
        displayed = link['text'].strip()
        if (re.match(r'^(?:https?://)?[^\s/]+\.[^\s/]+(?:/\S*)?$', displayed, re.I) and domain(displayed)
                and domain(link['href']) and domain(displayed) != domain(link['href'])):
            findings.append(dict(label='Displayed link hides a different domain', evidence=f'{displayed} → {link["href"]}'))
    # Uploaded Authentication-Results can be forged. Do not convert them into
    # SPF/DKIM/DMARC verdicts, even if their authserv-id looks familiar.
    authentication = [str(v)[:2000] for v in msg.get_all('Authentication-Results', [])][:10]
    urls = list(dict.fromkeys(l['href'] for l in links if l['href'].lower().startswith(('http://', 'https://'))))
    content = str(msg.get('subject', '')) + '\n' + '\n'.join(text)
    if len(content) + sum(len(u) + 1 for u in urls) > MAX_MESSAGE or len(urls) > MAX_URLS:
        raise ValueError('Extracted email exceeds message/link limits. Select a smaller message.')
    return dict(kind='email', text=content + '\n' + '\n'.join(urls), findings=findings,
                sender=str(msg.get('from', ''))[:500], reply_to=str(msg.get('reply-to', ''))[:500],
                links=links[:100], attachments=attachments, authentication_headers=authentication,
                warnings=['Email headers are unverified. Authentication-Results in uploaded files are not trusted.',
                          'Attachments are listed but never opened or executed.'])


def image_extract(raw):
    if len(raw) > MAX_FILE:
        raise ValueError('Image exceeds 5 MB.')
    try:
        from PIL import Image
        import cv2
        import numpy as np
    except ImportError as exc:
        raise ValueError('Install requirements-advanced.txt to enable image and QR extraction.') from exc
    Image.MAX_IMAGE_PIXELS = 12_000_000
    try:
        with Image.open(io.BytesIO(raw)) as source:
            if source.format not in {'PNG', 'JPEG', 'WEBP'} or source.width * source.height > 12_000_000:
                raise ValueError('Use a PNG, JPEG or WebP image up to 12 megapixels.')
            img = source.convert('RGB')
    except Exception as exc:
        raise ValueError('Invalid or oversized image; use PNG, JPEG or WebP up to 12 megapixels.') from exc
    qr = cv2.QRCodeDetector()
    array = np.array(img)
    ok, decoded, _, _ = qr.detectAndDecodeMulti(array)
    values = list(dict.fromkeys(v for v in decoded if v)) if ok else []
    if not values:
        value, _, _ = qr.detectAndDecode(array)
        if value:
            values = [value]
    warnings, words, confidence = [], [], []
    engine = None
    try:
        import pytesseract
        executable = os.environ.get('PHISHLENS_TESSERACT') or shutil.which('tesseract')
        if not executable:
            raise RuntimeError('Tesseract executable is not configured.')
        pytesseract.pytesseract.tesseract_cmd = executable
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT, timeout=20,
                                        lang=os.environ.get('PHISHLENS_OCR_LANG', 'eng'))
        for word, score in zip(data['text'], data['conf']):
            if word.strip():
                words.append(word)
                confidence.append(float(score))
        engine = 'Tesseract'
    except (ImportError, RuntimeError, OSError) as exc:
        if os.name == 'nt':
            try:
                with tempfile.TemporaryDirectory(prefix='phishlens-ocr-') as folder:
                    image_path = Path(folder) / 'image.png'
                    preview = img.copy()
                    preview.thumbnail((2400, 2400))
                    preview.save(image_path)
                    output = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                             '-File', str(Path(__file__).with_name('windows_ocr.ps1')), '-ImagePath', str(image_path)],
                                            capture_output=True, text=True, encoding='utf-8-sig', timeout=25)
                    if output.returncode:
                        raise RuntimeError('Windows OCR unavailable.')
                    words = [json.loads(output.stdout)['text']]
                    engine = 'Windows OCR'
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
                warnings.append('OCR unavailable or timed out. Configure Tesseract or install a Windows OCR language; QR decoding still ran.')
        else:
            warnings.append('OCR unavailable or timed out. Configure Tesseract and its language data; QR decoding still ran.')
    content = ' '.join(words) + '\n' + '\n'.join(values)
    if len(content) > MAX_MESSAGE:
        raise ValueError('Extracted image text exceeds 20,000 characters.')
    warnings.append('OCR/QR extraction may omit or misread content. Review extracted text before analysis.')
    return dict(kind='image', text=content.strip(), qr_values=values, ocr_engine=engine,
                ocr_confidence=round(sum(confidence) / len(confidence), 1) if confidence else None,
                warnings=warnings, findings=[])
