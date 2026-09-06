import pytest

from fastpair_mic.fastpair.crypto import (
    aes_ctr_crypt,
    aes_ecb_encrypt_block,
)


def test_aes_ecb_known_vector():
    # NIST AES-128 test vector.
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
    )

    plaintext = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    expected = bytes.fromhex(
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    )

    assert aes_ecb_encrypt_block(
        key,
        plaintext,
    ) == expected


def test_aes_ecb_rejects_bad_key():
    with pytest.raises(ValueError):
        aes_ecb_encrypt_block(
            b"\x00" * 15,
            b"\x00" * 16,
        )


def test_aes_ecb_rejects_bad_block():
    with pytest.raises(ValueError):
        aes_ecb_encrypt_block(
            b"\x00" * 16,
            b"\x00" * 15,
        )


def test_aes_ctr_round_trip():
    key = bytes(range(16))
    iv = bytes(range(16, 32))
    plaintext = b"Fast Pair test payload"

    encrypted = aes_ctr_crypt(
        key,
        iv,
        plaintext,
    )

    assert encrypted != plaintext

    decrypted = aes_ctr_crypt(
        key,
        iv,
        encrypted,
    )

    assert decrypted == plaintext
 
