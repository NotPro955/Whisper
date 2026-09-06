from dataclasses import dataclass
import secrets

from .crypto import aes_ecb_encrypt_block


KBP_REQUEST_LENGTH = 16
KBP_MESSAGE_TYPE_REQUEST = 0x00


@dataclass(frozen=True)
class KBPRequest:
    """
    Fast Pair Key-Based Pairing raw request.

    The raw request is exactly 16 bytes before AES-128-ECB
    encryption.
    """

    flags: int
    provider_address: bytes
    seeker_address: bytes | None
    salt: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.flags <= 0xFF:
            raise ValueError("flags must fit in one byte")

        if len(self.provider_address) != 6:
            raise ValueError(
                "provider_address must contain exactly 6 bytes"
            )

        if self.seeker_address is not None:
            if len(self.seeker_address) != 6:
                raise ValueError(
                    "seeker_address must contain exactly 6 bytes"
                )

        # A request without a seeker address has 8 bytes
        # available for salt. A request with a seeker
        # address has only 2 bytes available.
        address_required = bool(
            self.flags & 0x02
            or self.flags & 0x08
        )

        required_salt_length = 2 if address_required else 8

        if len(self.salt) < required_salt_length:
            raise ValueError(
                f"salt must contain at least "
                f"{required_salt_length} bytes"
            )

        if address_required and self.seeker_address is None:
            raise ValueError(
                "seeker_address is required by the flags"
            )

    def encode(self) -> bytes:
        """
        Encode the 16-byte raw KBP request.
        """

        data = bytearray()

        data.append(KBP_MESSAGE_TYPE_REQUEST)
        data.append(self.flags)

        data.extend(self.provider_address)

        if self.seeker_address is not None:
            data.extend(self.seeker_address)

        remaining = KBP_REQUEST_LENGTH - len(data)

        if remaining <= 0:
            raise ValueError(
                "No space remains for KBP request salt"
            )

        if len(self.salt) < remaining:
            raise ValueError(
                f"KBP salt must contain at least "
                f"{remaining} bytes; got {len(self.salt)}"
            )

        data.extend(self.salt[:remaining])

        if len(data) != KBP_REQUEST_LENGTH:
            raise ValueError(
                f"KBP request encoded to {len(data)} bytes; "
                f"expected {KBP_REQUEST_LENGTH}"
            )

        return bytes(data)


def build_kbp_request(
    provider_address: bytes,
    *,
    seeker_address: bytes | None = None,
    request_bonding: bool = False,
    request_name: bool = False,
    retroactive_account_key: bool = False,
    salt: bytes | None = None,
) -> KBPRequest:
    """
    Construct a Fast Pair Key-Based Pairing request.

    Without a seeker address:

        type(1) + flags(1) + provider(6) + salt(8) = 16

    With a seeker address:

        type(1) + flags(1) + provider(6)
        + seeker(6) + salt(2) = 16
    """

    flags = 0

    if request_bonding:
        flags |= 0x02

    if request_name:
        flags |= 0x04

    if retroactive_account_key:
        flags |= 0x08

    seeker_required = (
        request_bonding
        or retroactive_account_key
    )

    if seeker_required and seeker_address is None:
        raise ValueError(
            "seeker_address is required for this request"
        )

    salt_length = 2 if seeker_required else 8

    if salt is None:
        salt = secrets.token_bytes(salt_length)
    elif len(salt) < salt_length:
        raise ValueError(
            f"salt must contain at least "
            f"{salt_length} bytes"
        )

    return KBPRequest(
        flags=flags,
        provider_address=provider_address,
        seeker_address=seeker_address,
        salt=salt,
    )


def encrypt_kbp_request(
    request: KBPRequest,
    key: bytes,
) -> bytes:
    """
    Encrypt a raw KBP request with an AES-128 key.

    The key must be exactly 16 bytes.
    No BLE operation is performed here.
    """

    if len(key) != 16:
        raise ValueError(
            "KBP encryption key must be exactly 16 bytes"
        )

    raw = request.encode()

    return aes_ecb_encrypt_block(
        key,
        raw,
    )
