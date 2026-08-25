"""
Time helpers.

`datetime.utcnow()` is deprecated from Python 3.12 and scheduled for removal.
The database columns are naive `DateTime` (UTC by convention), so `utcnow()`
here returns a naive UTC timestamp - a drop-in replacement that keeps the
stored representation identical while staying forward compatible.
"""

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Current UTC time as a naive datetime, matching the DB column type."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utcnow_aware() -> datetime:
    """Current UTC time as a timezone-aware datetime, for API payloads."""
    return datetime.now(timezone.utc)


def to_utc(moment: datetime) -> datetime:
    """Normalise any datetime to naive UTC, so comparisons never mix kinds."""
    if moment.tzinfo is None:
        return moment
    return moment.astimezone(timezone.utc).replace(tzinfo=None)


def utc_from_timestamp(seconds: float) -> datetime:
    """Naive UTC datetime from a Unix timestamp.

    Replaces `datetime.utcfromtimestamp`, which carries the same deprecation
    as `datetime.utcnow`.
    """
    return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(tzinfo=None)
