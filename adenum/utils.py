from datetime import datetime, timezone

# userAccountControl flags (Microsoft docs)
UAC_ACCOUNTDISABLE = 0x2
UAC_DONT_EXPIRE_PASSWORD = 0x10000


def domain_to_base_dn(domain):
    """lab.local -> DC=lab,DC=local"""
    parts = [p.strip() for p in domain.split(".") if p.strip()]
    if not parts:
        raise ValueError("Domain is empty, e.g. lab.local")
    return ",".join(f"DC={p}" for p in parts)


def filetime_to_datetime(value):
    """Windows FILETIME (lastLogonTimestamp) -> datetime, or None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        filetime = int(value)
    except (TypeError, ValueError):
        return None
    if filetime == 0:
        return None
    unix_seconds = (filetime - 116444736000000000) // 10_000_000
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)


def password_never_expires(user_account_control):
    if user_account_control is None:
        return False
    return bool(int(user_account_control) & UAC_DONT_EXPIRE_PASSWORD)


def account_disabled(user_account_control):
    if user_account_control is None:
        return False
    return bool(int(user_account_control) & UAC_ACCOUNTDISABLE)


def is_stale(last_logon, stale_days, now=None):
    """True if the account has not logged in for stale_days, or never logged in."""
    if last_logon is None:
        return True
    now = now or datetime.now(timezone.utc)
    return (now - last_logon).days >= stale_days
