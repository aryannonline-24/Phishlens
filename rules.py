"""Offline, explainable phishing indicators. No links are visited."""
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit
import tldextract

RULESET_VERSION = '2.1.0'
EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
KNOWN_SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd'}
KNOWN_BRANDS = {'paypal.com', 'amazon.com', 'google.com', 'microsoft.com',
                'apple.com', 'netflix.com', 'sbi.co.in', 'icicibank.com'}
MAX_MESSAGE = 20000
MAX_URL = 2048
MAX_URLS = 10


def levenshtein(a, b):
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(current[-1] + 1, previous[j] + 1,
                               previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def parse_url(raw_url):
    raw = raw_url.strip()
    if not raw:
        return None
    if len(raw) > MAX_URL or re.search(r'\s', raw):
        raise ValueError('URL is too long or contains whitespace.')
    explicit = bool(re.match(r'^[a-z][a-z0-9+.-]*://', raw, re.I))
    parsed = urlsplit(raw if explicit else '//' + raw)
    if explicit and parsed.scheme.lower() not in {'http', 'https'}:
        raise ValueError('Only HTTP and HTTPS links are supported.')
    host = (parsed.hostname or '').rstrip('.').lower()
    if not host:
        raise ValueError('URL must contain a hostname.')
    try:
        parsed.port  # validate invalid/out-of-range ports
        ascii_host = host.encode('idna').decode('ascii')
        if len(ascii_host) > 253:
            raise ValueError('Hostname is too long.')
        unicode_host = ascii_host.encode('ascii').decode('idna')
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
        if not is_ip and (':' in host or not re.fullmatch(r'[a-z0-9.-]+', ascii_host)
                or any(not label or len(label) > 63 or label.startswith('-')
                       or label.endswith('-') for label in ascii_host.split('.'))):
            raise ValueError('Invalid hostname.')
    except (UnicodeError, ValueError) as exc:
        raise ValueError('Invalid URL hostname or port.') from exc
    ext = EXTRACTOR(ascii_host)
    registered = ext.top_domain_under_public_suffix or ascii_host
    return {'raw': raw, 'protocol': parsed.scheme.lower() if explicit else None,
            'hostname': ascii_host, 'registered_domain': registered,
            'subdomain': ext.subdomain, 'is_ip': is_ip,
            'has_at': parsed.username is not None or parsed.password is not None,
            'unicode_hostname': unicode_host}


def rule(id, label, weight, tip, pattern=None):
    return dict(id=id, label=label, weight=weight, tip=tip, pattern=pattern)

MESSAGE_RULES = [
    rule('urgency_language', 'Urgent or time-pressured wording', 10,
         'Pause and verify the request through an independently obtained contact.',
         r'\b(immediately|urgent(?:ly)?|act now|within 24 hours|expires? (?:today|soon)|account will be (?:suspended|closed|locked))\b'),
    rule('threat_language', 'Threatening consequences', 10,
         'Verify account warnings in the official app or website.',
         r'\b(legal action|account (?:has been |will be )?(?:locked|suspended|terminated|blocked)|penalty|failure to comply)\b'),
    rule('credential_request', 'Request to disclose a password, OTP or PIN', 25,
         'Do not disclose passwords, PINs or verification codes in response to unsolicited messages.'),
    rule('generic_greeting', 'Generic account greeting', 5,
         'A generic greeting is a weak signal. Consider the full message.',
         r'\bdear (?:customer|user|member|sir\s*/?\s*madam|account holder)\b'),
    rule('reward_bait', 'Unexpected prize or reward lure', 10,
         'Verify unexpected rewards before providing information or payment.',
         r"\b(you(?:'ve| have) won|claim your (?:prize|reward|refund)|free gift|congratulations[!, ]+you)\b"),
    rule('excessive_emphasis', 'Repeated exclamations or all-capitals', 5,
         'Emphasis alone does not prove phishing. Look for stronger indicators.'),
]
MESSAGE_RULES += [
    rule('identity_request', 'Request for employee or identity information', 20,
         'Confirm the request with HR or the organisation using a contact you already know.'),
    rule('payment_redirection', 'Request to redirect a payment', 25,
         'Call the payee on a previously verified number before changing payment details.'),
    rule('kyc_pressure', 'KYC request with pressure or sensitive-data collection', 20,
         'Check KYC requirements inside the official banking app or at your branch.'),
]


def request_clauses(text):
    """Exclude warning clauses without discarding separate requests."""
    for clause in re.split(r'[.!?\n;।]+|\bbut\b|लेकिन|\blekin\b', text, flags=re.I):
        if re.search(r"\b(?:do not|don't|never|must not|no need to|will not|won't)\b|"
                     r'\b(?:mat|nahi|nahin)\b|नहीं|मत\s|न\s+कर', clause, re.I):
            continue
        yield clause


def contextual_evidence(text, kind):
    action = r'\b(?:send|share|provide|enter|submit|confirm|upload|verify|reply|bhejo|bheje|batao|karo|karein|do)\b|भेज|बताओ|बताएं|दर्ज|जमा|करें|करो|साझा'
    for clause in request_clauses(text):
        asks = re.search(action, clause, re.I)
        if kind == 'credential_request':
            topic = re.search(r'\b(?:otp|password|pin|passcode|verification code)\b|ओटीपी|पासवर्ड|पिन', clause, re.I)
            # English is handled by the more precise existing rule; this covers
            # Hindi/Hinglish requests where the action follows the secret.
            match = asks and topic and re.search(r'\b(?:bhejo|bheje|batao|karo|karein|do)\b|भेज|बताओ|बताएं|दर्ज|जमा|करें|करो|साझा', clause, re.I)
        elif kind == 'identity_request':
            match = asks and re.search(r'\b(?:employee (?:id|number)|aadhaar|aadhar|pan (?:card|number)|passport|identity document)\b|कर्मचारी.*पहचान|आधार|पैन कार्ड', clause, re.I)
        elif kind == 'payment_redirection':
            match = (re.search(r'\b(?:pay|transfer|send|deposit|remit|bhejo|payment karo)\b|भेज|भुगतान|ट्रांसफर', clause, re.I)
                     and re.search(r'\b(?:new|updated|changed|replacement|alternate|naye|naya)\b|नए|नया|बदले', clause, re.I)
                     and re.search(r'\b(?:account|bank details|upi|beneficiary)\b|खाते|खाता|यूपीआई', clause, re.I))
        else:
            match = (re.search(r'\bkyc\b|केवाईसी', clause, re.I)
                     and re.search(r'\b(?:blocked|suspended|locked|today|immediately|urgent|aadhaar|aadhar|pan|otp|abhi|band)\b|बंद|आज|तुरंत|आधार|ओटीपी', clause, re.I)
                     and (asks or re.search(r'\b(?:update|complete)\b|अपडेट|पूरा', clause, re.I)))
        if match:
            return clause.strip()
    return ''
URL_RULES = [
    rule('ip_address_url', 'Link uses an IP address', 20, 'Verify the destination before entering sensitive information.'),
    rule('at_symbol_in_url', 'URL contains user information before the hostname', 20, 'The destination is the hostname after the user-information component.'),
    rule('url_shortener', 'Shortened link hides its destination', 10, 'Verify the destination through the sender’s official channel.'),
    rule('no_https', 'URL explicitly uses HTTP', 10, 'Avoid entering sensitive information over an unencrypted connection.'),
    rule('excessive_subdomains', 'Long subdomain chain', 10, 'Check the registered domain rather than the first name in the URL.'),
    rule('lookalike_domain', 'Registered domain resembles a known brand', 20, 'Compare the registered domain with the organisation’s official domain.'),
    rule('brand_in_subdomain', 'Brand name appears under an unrelated domain', 20, 'Open the organisation’s official app or type its known website address instead of using this link.'),
    rule('internationalized_domain', 'Internationalized or punycode hostname', 5, 'Internationalized domains can be legitimate. Check for visually deceptive characters.'),
]


def credential_evidence(text):
    secret = r'(?:password|passcode|otp|one[- ]time password|pin(?: number)?|verification code|the code)'
    action = r'(?:send|share|provide|enter|submit|confirm|verify|disclose|tell|give|reply)'
    for sentence in re.split(r'[.!?\n;]+', text):
        # Remove explicit safety-warning clauses, but retain any separate request.
        cleaned = re.sub(r"\b(?:do not|don't|never|must not)\s+(?:ever\s+)?" + action +
                         r'\b[^,]*', '', sentence, flags=re.I)
        match = re.search(r'\b' + action + r'\b[^.!?\n]{0,60}?\b' + secret + r'\b', cleaned, re.I)
        if match:
            return match.group(0)
    return ''


def build_finding(r, evidence=''):
    return {k: r[k] for k in ('id', 'label', 'weight', 'tip')} | {
        'triggered': bool(evidence), 'evidence': evidence,
        'contribution': r['weight'] if evidence else 0}


def compute_risk(score):
    return 'high' if score >= 50 else 'medium' if score >= 20 else 'low'


def extract_urls(text):
    # Consume explicit links first so embedded email addresses/query values are
    # never extracted as additional destinations. Bare domains require a PSL suffix.
    dot = r'(?:\.|\[\.\]|\(\.\))'
    label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    pattern = (r'(?i)(?<![\w@/.-])(?:(?:https?|hxxps?)://[^\s<>"\u201c\u201d]+'
               r'|(?:' + label + dot + r')+[a-z]{2,63}(?::\d+)?(?:[/?#][^\s<>"\u201c\u201d]*)?)')
    urls = []
    for match in re.finditer(pattern, text):
        raw = match.group().rstrip('.,;!?')
        while raw.endswith(')') and raw.count(')') > raw.count('('):
            raw = raw[:-1]
        if not re.match(r'(?i)^(?:(?:https?|hxxps?)://|www\.)', raw):
            try:
                candidate = parse_url(normalize_url(raw))
                if not EXTRACTOR(candidate['hostname']).suffix:
                    continue
            except ValueError:
                continue
        if raw not in urls:
            urls.append(raw)
    return urls


def normalize_url(raw):
    value = re.sub(r'(?i)^hxxp(s?)://', r'http\1://', raw.strip())
    # Only normalize the authority; do not rewrite paths or query parameters.
    parts = re.split(r'([/?#])', value.split('://', 1)[-1], maxsplit=1)
    authority = parts[0].replace('[.]', '.').replace('(.)', '.')
    prefix = value.split('://', 1)[0] + '://' if '://' in value else ''
    return prefix + authority + ''.join(parts[1:])


def analyse_url(raw):
    normalized = normalize_url(raw)
    try:
        url = parse_url(normalized)
    except ValueError as exc:
        return {'raw': raw, 'valid': False, 'error': str(exc), 'score': 0, 'findings': []}
    host, domain = url['hostname'], url['registered_domain']
    conditions = {
        'ip_address_url': url['is_ip'],
        'at_symbol_in_url': url['has_at'],
        'url_shortener': domain in KNOWN_SHORTENERS,
        'no_https': url['protocol'] == 'http',
        'excessive_subdomains': len(url['subdomain'].split('.')) >= 4 if url['subdomain'] else False,
        'lookalike_domain': not url['is_ip'] and any(domain != b and
            len(domain) <= len(b) + 2 and levenshtein(domain, b) <= 2 for b in KNOWN_BRANDS),
        'brand_in_subdomain': any(domain != b and (b in url['subdomain'] or
            b.split('.')[0] in url['subdomain'].split('.')) for b in KNOWN_BRANDS),
        'internationalized_domain': any(label.startswith('xn--') for label in host.split('.')),
    }
    findings = [build_finding(r, host if conditions[r['id']] else '') for r in URL_RULES]
    score = sum(f['contribution'] for f in findings)
    return {**url, 'raw': raw, 'normalized_url': normalized,
            'normalization_applied': normalized != raw.strip(),
            'valid': True, 'score': score, 'risk': compute_risk(score),
            'findings': findings, 'scheme_provided': url['protocol'] is not None}


def run_analysis(text, raw_url=''):
    if not isinstance(text, str) or not isinstance(raw_url, str):
        raise ValueError('Message and URL must be strings.')
    if len(text) > MAX_MESSAGE or len(raw_url) > MAX_URL:
        raise ValueError('Message or URL exceeds the allowed length.')
    normalized = unicodedata.normalize('NFKC', text)
    message_findings = []
    for r in MESSAGE_RULES:
        if r['id'] == 'credential_request':
            evidence = credential_evidence(normalized) or contextual_evidence(normalized, r['id'])
        elif r['id'] in {'identity_request', 'payment_redirection', 'kyc_pressure'}:
            evidence = contextual_evidence(normalized, r['id'])
        elif r['id'] == 'excessive_emphasis':
            caps = re.findall(r'\b[A-Z]{4,}\b', normalized)
            evidence = 'Repeated exclamation marks' if '!!' in normalized else ', '.join(caps) if len(caps) >= 2 else ''
        else:
            match = re.search(r['pattern'], normalized, re.I)
            evidence = match.group() if match else ''
        message_findings.append(build_finding(r, evidence))
    urls = list(dict.fromkeys(([raw_url.strip()] if raw_url.strip() else []) + extract_urls(normalized)))
    if len(urls) > MAX_URLS:
        raise ValueError(f'At most {MAX_URLS} unique URLs are supported per scan.')
    url_reports = [analyse_url(u) for u in urls]
    if raw_url.strip() and not url_reports[0]['valid']:
        raise ValueError(url_reports[0]['error'])
    # Repeated indicators across links contribute once, avoiding link-count inflation.
    url_findings = [build_finding(r, next((f['evidence'] for u in url_reports
        for f in u['findings'] if f['id'] == r['id'] and f['triggered']), '')) for r in URL_RULES]
    message_score = sum(f['contribution'] for f in message_findings)
    url_score = sum(f['contribution'] for f in url_findings)
    score = message_score + url_score
    warnings = ['Heuristic indicators are not a probability of phishing. Low detected risk does not guarantee safety.']
    if any(not u['valid'] for u in url_reports):
        warnings.append('Some embedded URLs could not be analysed. Review the individual URL errors.')
    if any(u.get('valid') and not u['scheme_provided'] for u in url_reports):
        warnings.append('A URL has no scheme. Its use of HTTPS cannot be determined from this input.')
    return dict(score=score, risk=compute_risk(score), message_score=message_score,
        url_score=url_score, message_findings=message_findings, url_findings=url_findings,
        url_reports=url_reports, has_url=bool(urls), ruleset_version=RULESET_VERSION,
        thresholds={'medium': 20, 'high': 50}, warnings=warnings,
        analysis_complete=all(u['valid'] for u in url_reports))
