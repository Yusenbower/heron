"""Phishing indicators: each function returns the points one indicator adds."""

import re

from heron.parser import sender_domain

W_KEYWORD = 1
W_IP_LINK = 3
W_PUNYCODE_LINK = 3
W_BRAND_MISMATCH = 3
W_AUTH_FAIL = 2
W_REPLY_TO_MISMATCH = 2

BRANDS = ["paypal", "microsoft", "amazon"]
KEYWORDS = [
    "urgent", "verify", "suspended", "password", "expires", "act now",
    "congratulations", "winner", "claim", "immediately", "gift card",
]

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_IP_URL_RE = re.compile(r"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")


def keyword_score(raw):
    """One point for each pressure keyword found anywhere in the message."""
    low = raw.lower()
    return sum(W_KEYWORD for kw in KEYWORDS if kw in low)


def link_score(raw):
    """Points for links to a bare IP address or to a punycode domain."""
    s = 0
    for url in _URL_RE.findall(raw):
        if _IP_URL_RE.match(url):
            s = s + W_IP_LINK
        if "xn--" in url:
            s = s + W_PUNYCODE_LINK
    return s


def brand_score(frm):
    """Points when the sender name claims a brand but the address is elsewhere."""
    low = frm.lower()
    return sum(
        W_BRAND_MISMATCH
        for brand in BRANDS
        if brand in low and brand + ".com" not in low
    )


def auth_score(raw):
    """Points when SPF or DMARC failed."""
    low = raw.lower()
    if "spf=fail" in low or "dmarc=fail" in low:
        return W_AUTH_FAIL
    return 0


def reply_to_score(frm, reply_to):
    """Points when replies go to a different domain than the sender's."""
    from_domain = sender_domain(frm)
    reply_domain = sender_domain(reply_to)
    if from_domain and reply_domain and from_domain != reply_domain:
        return W_REPLY_TO_MISMATCH
    return 0