# quick phishing checker for the mail export - L. Garcia, march 2025

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
DOMAIN_RE = re.compile(r"@([a-zA-Z0-9.-]+)")

def header(raw, name):
    m = re.search(f"{name}: (.*)", raw)
    return m.group(1) if m is not None else ""

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


def reply_to_score(frm, rt):
    if not rt:
        return 0
    m1 = DOMAIN_RE.search(frm)
    m2 = DOMAIN_RE.search(rt)
    if m1 is not None and m2 is not None and m1.group(1) != m2.group(1):
        return W_REPLY_TO_MISMATCH
    return 0


def score_email(raw):
    frm = header(raw, "From")
    rt = header(raw, "Reply-To")
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

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python triage.py <folder-with-eml-files>", file=sys.stderr)
        sys.exit(2)
    try:
        verdicts = check_mail(sys.argv[1])
    except FileNotFoundError:
        print(f"error: folder not found: {sys.argv[1]}", file=sys.stderr)
        sys.exit(1)
    report(verdicts)