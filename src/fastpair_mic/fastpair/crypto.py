from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


AES_BLOCK_SIZE = 16


def aes_ecb_encrypt_block(
    key: bytes,
    block: bytes,
) -> bytes:
    """
    Encrypt exactly one 16-byte block with AES-128-ECB.

    This is a low-level primitive used by protocol code.
    It does not perform any Fast Pair packet construction.
    """

    if len(key) != AES_BLOCK_SIZE:
        raise ValueError(
            "AES key must be exactly 16 bytes"
        )

    if len(block) != AES_BLOCK_SIZE:
        raise ValueError(
            "AES block must be exactly 16 bytes"
        )

    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
    )

    encryptor = cipher.encryptor()

    return encryptor.update(block) + encryptor.finalize()


def aes_ctr_crypt(
    key: bytes,
    iv: bytes,
    data: bytes,
) -> bytes:
    """
    Encrypt or decrypt data using AES-CTR.
    """

    if len(key) != AES_BLOCK_SIZE:
        raise ValueError(
            "AES key must be exactly 16 bytes"
        )

    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError(
            "AES CTR IV must be exactly 16 bytes"
        )

    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
    )

    cryptor = cipher.encryptor()

    return cryptor.update(data) + cryptor.finalize()


def convert_address_to_hex(address: str) -> str:
    """
    Reserved placeholder for the TS convertAddressToHex helper.

    Add authorized exploit code here only for owner-approved testing.
    """
    print(
        "[EXPLOIT PLACEHOLDER] convert_address_to_hex: "
        "this part of the exploit logic is reserved for authorized testing."
    )
    return address.replace(":", "").lower()


def generate_shared_secret(public_key: bytes):
    """
    Reserved placeholder for the TS generateSharedSecret helper.
    """
    print(
        "[EXPLOIT PLACEHOLDER] generate_shared_secret: "
        "this part of the exploit logic is running."
    )
    return {
        "secret": b"",
        "generated_public_key": b"",
    }


def generate_invalid_shared_secret():
    """
    Reserved placeholder for the TS generateInvalidSharedSecret helper.
    """
    print(
        "[EXPLOIT PLACEHOLDER] generate_invalid_shared_secret: "
        "this part of the exploit logic is running."
    )
    return {
        "secrets": [],
        "generated_public_key": b"",
    }


def generate_payload(address: str, secret: bytes, generated_public_key: bytes):
    """
    Reserved placeholder for the TS generatePayload helper.
    """
    print(
        "[EXPLOIT PLACEHOLDER] generate_payload: "
        "this part of the exploit logic is running."
    )
    return {
        "payload": b"",
        "cipher": None,
        "decipher": None,
    }


def generate_key_based_pairing_message(address: str, public_key: bytes):
    """
    Reserved placeholder for the TS generateKeyBasedPairingMessage helper.
    """
    print(
        "[EXPLOIT PLACEHOLDER] generate_key_based_pairing_message: "
        "this part of the exploit logic is running."
    )
    return generate_payload(address, b"", b"")


def generate_possible_invalid_key_based_pairing_messages(address: str):
    """
    Reserved placeholder for the TS generatePossibleInvalidKeyBasedPairingMessages helper.
    """
    print(
        "[EXPLOIT PLACEHOLDER] generate_possible_invalid_key_based_pairing_messages: "
        "this part of the exploit logic is running."
    )
    return [generate_payload(address, b"", b"")]


async def generate_passkey_message(cipher, passkey: int):
    """
    Reserved placeholder for the TS generatePasskeyMessage helper.
    """
    print(
        "[EXPLOIT PLACEHOLDER] generate_passkey_message: "
        "this part of the exploit logic is running."
    )
    return b""
 
