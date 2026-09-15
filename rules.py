# rules.py
import re
from urllib.parse import urlparse

KNOWN_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"]
KNOWN_BRANDS = ["paypal.com", "amazon.com", "google.com", "microsoft.com",
                "apple.com", "netflix.com", "sbi.co.in", "icicibank.com"]


def levenshtein(a, b):
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        dp[i][0] = i
    for j in range(len(b) + 1):
        dp[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
    return dp[len(a)][len(b)]


def parse_url(raw_url):
    if not raw_url or not raw_url.strip():
        return None
    url = raw_url if raw_url.startswith(("http://", "https://")) else "http://" + raw_url
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    return {
        "raw": raw_url,
        "protocol": parsed.scheme,
        "hostname": hostname,
        "has_at": "@" in raw_url,
        "labels": [p for p in hostname.split(".") if p],
    }


# Every rule shares the same normalized shape:
# id, label, weight, tip, test(ctx) -> bool
MESSAGE_RULES = [
    {
        "id": "urgency_language",
        "label": "Urgent or time-pressured wording",
        "weight": 10,
        "tip": "Scammers create false urgency so you act before thinking. Pause and verify independently.",
        "test": lambda ctx: bool(re.search(
            r"\b(immediately|urgent(ly)?|act now|within 24 hours|expires? (today|soon)|"
            r"account will be (suspended|closed|locked))\b", ctx["text"], re.I)),
    },
    {
        "id": "threat_language",
        "label": "Threatening consequences",
        "weight": 10,
        "tip": "Legitimate organizations rarely threaten legal action or account loss over email/SMS.",
        "test": lambda ctx: bool(re.search(
            r"\b(legal action|account (has been |will be )?(locked|suspended|terminated)|"
            r"penalty|failure to comply)\b", ctx["text"], re.I)),
    },
    {
        "id": "credential_request",
        "label": "Requests a password, OTP, or PIN",
        "weight": 15,
        "tip": "Never share OTPs, passwords, or PINs. No legitimate bank or service will ask for these.",
        "test": lambda ctx: bool(re.search(
            r"\b(otp|one[- ]time password|pin number|verify your (password|account|identity)|"
            r"confirm your (password|details|identity)|share the code)\b", ctx["text"], re.I)),
    },
    {
        "id": "generic_greeting",
        "label": "Generic greeting instead of your name",
        "weight": 5,
        "tip": "Real account-related messages usually address you by name.",
        "test": lambda ctx: bool(re.search(
            r"\bdear (customer|user|member|sir\s*/?\s*madam|account holder)\b", ctx["text"], re.I)),
    },
    {
        "id": "reward_bait",
        "label": "Unexpected prize, refund, or reward",
        "weight": 10,
        "tip": "Unsolicited winnings are a classic lure. If you didn't enter, you didn't win.",
        "test": lambda ctx: bool(re.search(
            r"\b(you('ve| have) won|claim your (prize|reward|refund)|free gift|congratulations you)\b",
            ctx["text"], re.I)),
    },
    {
        "id": "excessive_emphasis",
        "label": "Excessive punctuation or capitalization",
        "weight": 5,
        "tip": "Heavy exclamation marks or all-caps are often used to provoke a rushed reaction.",
        "test": lambda ctx: bool(re.search(r"!{2,}", ctx["text"]))
        or len(re.findall(r"\b[A-Z]{4,}\b", ctx["text"])) >= 2,
    },
]

URL_RULES = [
    {
        "id": "ip_address_url",
        "label": "Link uses a raw IP address instead of a domain",
        "weight": 20,
        "tip": "Legitimate sites almost never link through a bare IP address. Do not click.",
        "test": lambda ctx: bool(ctx["url"]) and bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ctx["url"]["hostname"])),
    },
    {
        "id": "at_symbol_in_url",
        "label": "Link contains an '@' symbol",
        "weight": 20,
        "tip": "Everything before an '@' in a URL is ignored by browsers — a common disguise trick.",
        "test": lambda ctx: bool(ctx["url"]) and ctx["url"]["has_at"],
    },
    {
        "id": "url_shortener",
        "label": "Link uses a URL-shortening service",
        "weight": 10,
        "tip": "Shortened links hide the true destination. Expand before clicking, or avoid it.",
        "test": lambda ctx: bool(ctx["url"]) and ctx["url"]["hostname"].lower() in KNOWN_SHORTENERS,
    },
    {
        "id": "no_https",
        "label": "Link does not use a secure (HTTPS) connection",
        "weight": 10,
        "tip": "Avoid entering information on a page not served over HTTPS.",
        "test": lambda ctx: bool(ctx["url"]) and ctx["url"]["protocol"].lower() != "https",
    },
    {
        "id": "excessive_subdomains",
        "label": "Unusually many subdomains",
        "weight": 10,
        "tip": "A long subdomain chain is often used to bury a fake brand name.",
        "test": lambda ctx: bool(ctx["url"]) and len(ctx["url"]["labels"]) >= 5,
    },
    {
        "id": "lookalike_domain",
        "label": "Domain closely resembles a well-known brand",
        "weight": 20,
        "tip": "Check the spelling carefully — this is close to a real brand but not an exact match.",
        "test": lambda ctx: bool(ctx["url"]) and any(
            levenshtein(ctx["url"]["hostname"].lower(), b) <= 2
            and ctx["url"]["hostname"].lower() != b
            and not ctx["url"]["hostname"].lower().endswith("." + b)
            for b in KNOWN_BRANDS
        ),
    },
]


def compute_risk(score):
    if score >= 50:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def build_finding(rule, triggered):
    return {
        "id": rule["id"],
        "label": rule["label"],
        "weight": rule["weight"],
        "tip": rule["tip"],
        "triggered": triggered,
    }


def run_analysis(text, raw_url):
    ctx = {"text": text or "", "url": parse_url(raw_url)}
    message_findings = [build_finding(r, r["test"](ctx)) for r in MESSAGE_RULES]
    url_findings = [build_finding(r, bool(ctx["url"]) and r["test"](ctx)) for r in URL_RULES]
    all_findings = message_findings + url_findings
    score = sum(f["weight"] for f in all_findings if f["triggered"])
    return {
        "score": score,
        "risk": compute_risk(score),
        "message_findings": message_findings,
        "url_findings": url_findings,
        "has_url": bool(ctx["url"]),
    }