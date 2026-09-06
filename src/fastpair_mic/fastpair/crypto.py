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
 
