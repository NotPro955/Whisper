import pytest

from fastpair_mic.fastpair.kbp_protocol import (
    KBP_MESSAGE_TYPE_REQUEST,
    KBPRequest,
    build_kbp_request,
    encrypt_kbp_request,
)


PROVIDER = bytes.fromhex("010203040506")
SEEKER = bytes.fromhex("060504030201")
SALT = bytes.fromhex("1011121314151617")


def test_basic_request_is_16_bytes():
    request = build_kbp_request(
        PROVIDER,
        salt=SALT,
    )

    encoded = request.encode()

    assert len(encoded) == 16
    assert encoded[0] == KBP_MESSAGE_TYPE_REQUEST
    assert encoded[1] == 0
    assert encoded[2:8] == PROVIDER
    assert encoded[8:] == SALT


def test_bonding_request_contains_seeker_address():
    request = build_kbp_request(
        PROVIDER,
        seeker_address=SEEKER,
        request_bonding=True,
        salt=SALT,
    )

    encoded = request.encode()

    assert len(encoded) == 16
    assert encoded[0] == 0
    assert encoded[1] & 0x02
    assert encoded[2:8] == PROVIDER
    assert encoded[8:14] == SEEKER
    assert encoded[14:] == SALT[:2]


def test_name_request():
    request = build_kbp_request(
        PROVIDER,
        request_name=True,
        salt=SALT,
    )

    assert request.flags & 0x04


def test_retroactive_account_key_requires_seeker():
    with pytest.raises(ValueError):
        build_kbp_request(
            PROVIDER,
            retroactive_account_key=True,
            salt=SALT,
        )


def test_invalid_provider_address():
    with pytest.raises(ValueError):
        build_kbp_request(
            b"\x00",
            salt=SALT,
        )


def test_invalid_salt():
    with pytest.raises(ValueError):
        build_kbp_request(
            PROVIDER,
            salt=b"\x00",
        )


def test_encryption_returns_one_block():
    request = build_kbp_request(
        PROVIDER,
        salt=SALT,
    )

    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
    )

    encrypted = encrypt_kbp_request(
        request,
        key,
    )

    assert len(encrypted) == 16
    assert encrypted != request.encode()
 
def test_bonding_request_encoding_uses_two_salt_bytes():
    request = build_kbp_request(
        PROVIDER,
        seeker_address=SEEKER,
        request_bonding=True,
        salt=SALT,
    )

    encoded = request.encode()

    assert len(encoded) == 16
    assert encoded[:2] == bytes([
        KBP_MESSAGE_TYPE_REQUEST,
        0x02,
    ])
    assert encoded[2:8] == PROVIDER
    assert encoded[8:14] == SEEKER
    assert encoded[14:16] == SALT[:2]

def test_encryption_rejects_invalid_key_length():
    request = build_kbp_request(
        PROVIDER,
        salt=SALT,
    )

    with pytest.raises(ValueError):
        encrypt_kbp_request(
            request,
            b"\x00" * 15,
        )
