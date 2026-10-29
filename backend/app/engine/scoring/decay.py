import datetime
from typing import Optional

def ensure_utc(dt: Optional[datetime.datetime]) -> Optional[datetime.datetime]:
    """Ensures a datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)

def calculate_evidence_freshness(
    collected_at: Optional[datetime.datetime],
    max_ttl_hours: int,
    now: Optional[datetime.datetime] = None
) -> float:
    """
    Computes evidence freshness F(t) from 1.0 (freshly collected) down to 0.0 (stale/expired).
    Formula: F(t) = max(0.0, 1.0 - (elapsed_hours / max_ttl_hours))
    Safely handles timezone boundaries, missing timestamps, and future-dated evidence.
    """
    if not collected_at:
        return 0.0

    collected_utc = ensure_utc(collected_at)
    current_utc = ensure_utc(now) or datetime.datetime.now(datetime.timezone.utc)

    # Handle future-dated evidence (clock skew / inconsistent clocks)
    if collected_utc > current_utc:
        # If within 5 minutes skew, treat as 1.0; if large forward drift, treat as untrusted/stale
        skew_seconds = (collected_utc - current_utc).total_seconds()
        if skew_seconds <= 300:
            return 1.0
        return 0.0

    elapsed_seconds = (current_utc - collected_utc).total_seconds()
    elapsed_hours = max(0.0, elapsed_seconds / 3600.0)

    if elapsed_hours >= max_ttl_hours:
        return 0.0

    freshness = 1.0 - (elapsed_hours / float(max_ttl_hours))
    return round(max(0.0, min(1.0, freshness)), 4)
