"""Configuration: SPEC §19, acceptance case 42."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from pydantic_settings import SettingsError

from mail_dissect.settings import Settings


def test_defaults_need_no_environment() -> None:
    """SPEC §19: the image starts with no variable set."""
    settings = Settings(_env_file=None)
    assert settings.max_message_bytes == 50 * 1024 * 1024
    assert settings.dissect_timeout_seconds == 60
    assert settings.health_cache_ttl_seconds == 10
    assert settings.unwrappers == []  # empty by default: SPEC §10
    assert settings.tika_url == "" and settings.screenshot_url == ""


def test_a_valid_unwrapper_entry_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "UNWRAPPERS",
        '[{"host_suffix":"Protection.Example.COM","source":"query:url","decoder":"percent"}]',
    )
    rule = Settings(_env_file=None).unwrappers[0]
    assert rule.host_suffix == "protection.example.com"  # matching is case-insensitive
    assert rule.strip_prefix is None


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("not json at all", "malformed JSON"),
        ('[{"host_suffix":"x.example","source":"header:1","decoder":"percent"}]', "unknown source"),
        ('[{"host_suffix":"x.example","source":"query:u","decoder":"rot13"}]', "unknown decoder"),
        ('[{"host_suffix":"x.example","source":"path_segment:x","decoder":"none"}]', "bad index"),
        ('[{"source":"query:u","decoder":"none"}]', "no host_suffix"),
    ],
)
def test_malformed_unwrappers_stop_the_service(
    monkeypatch: pytest.MonkeyPatch, value: str, why: str
) -> None:
    """Test 42: silently ignoring bad configuration would be worse than not starting.

    A wrapper that matches but never unwraps is indistinguishable from one that is simply
    irreversible, so the mistake would hide as normal behaviour (SPEC §10).
    """
    monkeypatch.setenv("UNWRAPPERS", value)
    with pytest.raises((ValidationError, SettingsError)):
        Settings(_env_file=None)


def test_limits_reject_nonsense(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAX_MIME_PARTS", "0")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
