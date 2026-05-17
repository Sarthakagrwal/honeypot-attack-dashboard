"""Tests for the GeoIP wrapper's graceful-degradation behaviour.

CI has no ``.mmdb`` file, so these tests verify the wrapper never raises and
always returns the documented all-keys-present dict.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from honeypot import geoip


@pytest.mark.parametrize(
    "private_ip",
    ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.0.1", "::1"],
)
def test_private_ip_degrades_to_none(private_ip: str, tmp_path: Path) -> None:
    """Private/reserved addresses return all-None without consulting any DB."""
    result = geoip.lookup(private_ip, tmp_path / "missing.mmdb")
    assert result == {
        "country": None,
        "country_code": None,
        "latitude": None,
        "longitude": None,
    }


def test_missing_database_degrades_to_none(tmp_path: Path) -> None:
    """A public IP with no .mmdb present returns all-None and does not raise."""
    result = geoip.lookup("8.8.8.8", tmp_path / "nonexistent.mmdb")
    assert result["country"] is None
    assert result["latitude"] is None


def test_invalid_ip_string_degrades(tmp_path: Path) -> None:
    """A non-IP string is treated as un-geolocatable, never raising."""
    result = geoip.lookup("not-an-ip-address", tmp_path / "missing.mmdb")
    assert result["country"] is None


def test_lookup_always_returns_all_keys(tmp_path: Path) -> None:
    """Every lookup result has the four documented keys regardless of outcome."""
    for ip in ("8.8.8.8", "10.0.0.1", "bogus"):
        result = geoip.lookup(ip, tmp_path / "missing.mmdb")
        assert set(result) == {"country", "country_code", "latitude", "longitude"}


def test_lookup_never_raises(tmp_path: Path) -> None:
    """Pathological inputs must not raise — the honeypot must stay up."""
    for ip in ("", "999.999.999.999", "1.2.3", "  ", "0.0.0.0"):
        geoip.lookup(ip, tmp_path / "missing.mmdb")  # no exception expected
