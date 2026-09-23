"""Production must not start with a token-signing key anyone can read.

SECRET_KEY signs every JWT. Its default sits in the public .env.example, so a
production deploy that forgot to set it would accept admin tokens forged by
anyone. These tests build Settings directly; nothing touches a database.
"""

import pytest

from config import MIN_SECRET_KEY_BYTES, PLACEHOLDER_SECRET_KEY, Settings

STRONG = "k" * 64


@pytest.fixture(autouse=True)
def _no_ambient_settings(monkeypatch):
    """Settings read the environment even with _env_file=None.

    CI exports a SECRET_KEY of its own, so the cases that check what happens
    when none is set were reading CI's value and passing only on a machine
    where the variable happened to be absent or the placeholder. Clearing them
    makes the result the same everywhere.
    """
    for name in ("SECRET_KEY", "APP_ENV"):
        monkeypatch.delenv(name, raising=False)


def make(**overrides):
    # _env_file=None: the developer's own .env must not decide the outcome.
    return Settings(_env_file=None, database_url="postgresql://unused", **overrides)


def test_production_refuses_the_placeholder_secret():
    with pytest.raises(ValueError, match="SECRET_KEY is still the placeholder"):
        make(app_env="production", secret_key=PLACEHOLDER_SECRET_KEY)


def test_production_refuses_the_default_when_secret_key_is_never_set():
    with pytest.raises(ValueError, match="SECRET_KEY is still the placeholder"):
        make(app_env="production")


def test_production_refuses_a_short_secret():
    with pytest.raises(ValueError, match=f"at least {MIN_SECRET_KEY_BYTES} bytes"):
        make(app_env="production", secret_key="short-but-not-the-placeholder")


def test_the_length_rule_counts_bytes_not_characters():
    # 16 two-byte characters are 32 bytes: enough, even though only 16 long.
    make(app_env="production", secret_key="é" * 16)
    with pytest.raises(ValueError):
        make(app_env="production", secret_key="é" * 15)


def test_production_accepts_a_strong_secret():
    assert make(app_env="production", secret_key=STRONG).secret_key == STRONG


def test_development_still_runs_on_the_placeholder():
    # A fresh checkout copies .env.example and should start without extra steps.
    assert make(app_env="development").secret_key == PLACEHOLDER_SECRET_KEY
