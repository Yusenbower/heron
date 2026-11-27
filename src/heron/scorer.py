"""Combine the indicator points into a score and a verdict."""

from heron.features import auth_score, brand_score, keyword_score, link_score, reply_to_score
from heron.models import ParsedEmail

PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3


def score_email(email: ParsedEmail) -> int:
    """Sum the points of every indicator for one parsed message."""
    return (
        keyword_score(email)
        + link_score(email)
        + brand_score(email)
        + auth_score(email)
        + reply_to_score(email)
    )


def verdict_for(score):
    """Map a score to a verdict."""
    if score >= PHISHING_THRESHOLD:
        return "PHISHING"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "ok"