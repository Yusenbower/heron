"""The data types of the triage domain."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ParsedEmail:
    """The parts of one message that the indicator checks read."""

    email_id: str
    sender: str
    from_domain: str | None
    reply_to_domain: str | None
    auth_results: str
    text: str
    links: tuple[str, ...]

@dataclass(frozen=True)
class TriageResult:
    """The verdict on one message, with its score."""

    email_id: str
    score: int
    verdict: str