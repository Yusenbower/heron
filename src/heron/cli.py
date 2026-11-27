# quick phishing checker for the mail export - L. Garcia, march 2025
import email
from email.utils import parseaddr
import re
import os
import sys
# Points added by each indicator, and the score thresholds of each verdict.
W_KEYWORD = 1
W_IP_LINK = 3
W_PUNYCODE_LINK = 3
W_BRAND_MISMATCH = 3
W_AUTH_FAIL = 2
W_REPLY_TO_MISMATCH = 2
PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3


KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]
BRANDS = ["paypal", "microsoft", "amazon"]

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
IP_URL_RE = re.compile(r"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")


def keyword_score(low):
    return sum(W_KEYWORD for kw in KEYWORDS if kw in low)


def link_score(raw):
    score = 0
    for u in URL_RE.findall(raw):
        if IP_URL_RE.match(u):
            score += W_IP_LINK
        if "xn--" in u:
            score += W_PUNYCODE_LINK
    return score


def brand_score(frm):
    frm_low = frm.lower()
    return sum(
        W_BRAND_MISMATCH
        for brand in BRANDS
        if brand in frm_low and f"{brand}.com" not in frm_low
    )


def auth_score(low):
    return W_AUTH_FAIL if ("spf=fail" in low or "dmarc=fail" in low) else 0


def domain_of(header_value):
    _, addr = parseaddr(header_value)
    _, sep, domain = addr.partition("@")
    return domain.lower() if sep else ""


def reply_to_score(frm, rt):
    d1 = domain_of(frm)
    d2 = domain_of(rt)
    if d1 and d2 and d1 != d2:
        return W_REPLY_TO_MISMATCH
    return 0


def score_email(raw):
    msg = email.message_from_string(raw)
    frm = msg.get("From", "")
    rt = msg.get("Reply-To", "")
    low = raw.lower()
    return (
        keyword_score(low)
        + link_score(raw)
        + brand_score(frm)
        + auth_score(low)
        + reply_to_score(frm, rt)
    )

def verdict_for(score):
    if score >= PHISHING_THRESHOLD:
        return "PHISHING"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "ok"
def check_mail(folder):
    verdicts = []
    for fn in os.listdir(folder):
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder, fn), encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        score = score_email(raw)
        verdicts.append((fn, verdict_for(score), score))
    return verdicts

def report(verdicts):
    print(f"checked {len(verdicts)} mails")
    for fn, verdict, score in verdicts:
        print(f"  {fn} -> {verdict} (score {score})")
    with open("results.txt", "w", encoding="utf-8") as out:
        out.write(str(verdicts))
    flagged = [fn for fn, verdict, _ in verdicts if verdict == "PHISHING"]
    print("flagged:", flagged)

def main(argv: list[str] | None = None) -> int:
    """Run the triage on the folder given on the command line; return the exit code."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m heron <folder-with-eml-files>", file=sys.stderr)
        return 2
    try:
        report(check_mail(args[0]))
    except FileNotFoundError:
        print("error: no such folder:", args[0], file=sys.stderr)
        return 2
    return 0