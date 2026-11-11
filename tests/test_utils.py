from datetime import datetime, timezone
from adenum.utils import (domain_to_base_dn, filetime_to_datetime,
                          is_stale, password_never_expires)


def test_domain_to_base_dn():
    assert domain_to_base_dn("lab.local") == "DC=lab,DC=local"


def test_filetime_conversion():
    # 2023-01-01 00:00:00 UTC as a Windows FILETIME
    assert filetime_to_datetime(133170048000000000) == datetime(2023, 1, 1, tzinfo=timezone.utc)
    assert filetime_to_datetime(0) is None
    assert filetime_to_datetime(None) is None


def test_password_never_expires():
    assert password_never_expires(66048) is True   # 512 + 65536
    assert password_never_expires(512) is False


def test_is_stale():
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    now = datetime(2026, 11, 11, tzinfo=timezone.utc)
    assert is_stale(old, 90, now) is True
    assert is_stale(now, 90, now) is False
    assert is_stale(None, 90, now) is True
