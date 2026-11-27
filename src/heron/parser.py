"""Read the triage-relevant parts of a raw .eml message."""

from email.utils import parseaddr


def sender_domain(header_value):
    """Return the domain of the address in a From/Reply-To value, or None."""
    _, address = parseaddr(header_value)
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower()