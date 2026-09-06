from fastpair_mic.fastpair.key_material import (
    FastPairKeyMaterial,
)

import pytest

from fastpair_mic.fastpair.key_material import (
    load_account_key_from_environment,
)

def test_account_key_is_valid_when_16_bytes():
    material = FastPairKeyMaterial(
        account_key=bytes(range(16)),
    )

    assert material.has_account_key()


def test_account_key_is_invalid_when_wrong_length():
    material = FastPairKeyMaterial(
        account_key=b"\x00" * 15,
    )

    assert not material.has_account_key()


def test_missing_account_key():
    material = FastPairKeyMaterial()

    assert not material.has_account_key()


def test_anti_spoofing_private_key_presence():
    material = FastPairKeyMaterial(
        anti_spoofing_private_key=b"test-key",
    )

    assert material.has_anti_spoofing_private_key()




def test_environment_account_key(monkeypatch):
    monkeypatch.setenv(
        "FASTPAIR_ACCOUNT_KEY",
        "000102030405060708090a0b0c0d0e0f",
    )

    key = load_account_key_from_environment()

    assert key == bytes(range(16))


def test_environment_account_key_missing(monkeypatch):
    monkeypatch.delenv(
        "FASTPAIR_ACCOUNT_KEY",
        raising=False,
    )

    assert load_account_key_from_environment() is None


def test_environment_account_key_rejects_bad_length(monkeypatch):
    monkeypatch.setenv(
        "FASTPAIR_ACCOUNT_KEY",
        "0001020304050607",
    )

    with pytest.raises(ValueError):
        load_account_key_from_environment()


def test_environment_account_key_rejects_invalid_hex(monkeypatch):
    monkeypatch.setenv(
        "FASTPAIR_ACCOUNT_KEY",
        "not-a-key",
    )

    with pytest.raises(ValueError):
        load_account_key_from_environment()
