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
def header(raw, name):
    m = re.search(f"{name}: (.*)", raw)
    return m.group(1) if m is not None else ""
def check_mail(folder, flagged = None):
    if flagged is None:
        flagged = []
    verdicts = []
    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder, fn), encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        s = 0
        frm = header(raw, "From") or "?"

        low = raw.lower()
        for kw in KEYWORDS:
            if kw in low:
                s = s + W_KEYWORD
        # links that look bad
        urls = re.findall("https?://[^\\s\"'<>]+", raw)
        for u in urls:
            if re.match("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", u):
                s = s + W_IP_LINK
            if "xn--" in u:
                s = s + W_PUNYCODE_LINK
        # sender says paypal/microsoft/amazon but domain is weird
        # sender mentions a known brand but uses another domain
        frm_low = frm.lower()
        for brand in BRANDS:
            if brand in frm_low and f"{brand}.com" not in frm_low:
                s = s + W_BRAND_MISMATCH
        if "spf=fail" in low or "dmarc=fail" in low:
            s = s + W_AUTH_FAIL
        # reply-to different from from
        rt = header(raw, "Reply-To")
        if rt:
            m1 = re.search(r"@([a-zA-Z0-9.-]+)", frm)
            m2 = re.search(r"@([a-zA-Z0-9.-]+)", rt)
            if m1 is not None and m2 is not None and m1.group(1) != m2.group(1):
                s = s + W_REPLY_TO_MISMATCH

        if s >= PHISHING_THRESHOLD:
            verdicts.append((fn, "PHISHING", s))
            flagged.append(fn)
        elif s >= SUSPICIOUS_THRESHOLD:
            verdicts.append((fn, "suspicious", s))
        else:
            verdicts.append((fn, "ok", s))
    print("checked", len(verdicts), "mails")
    for v in verdicts:
        print(" ", v[0], "->", v[1], "(score", str(v[2]) + ")")
    with open("results.txt", "w", encoding="utf-8") as out:
        out.write(str(verdicts))
    print("flagged:", flagged)
    return verdicts

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python triage.py <folder-with-eml-files>", file=sys.stderr)
        sys.exit(2)
    try:
        check_mail(sys.argv[1])
    except FileNotFoundError:
        print(f"error: folder not found: {sys.argv[1]}", file=sys.stderr)
        sys.exit(1)
    check_mail(sys.argv[1])
