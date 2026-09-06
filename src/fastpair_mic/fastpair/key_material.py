from dataclasses import dataclass
import os


@dataclass(frozen=True)
class FastPairKeyMaterial:
    """
    Cryptographic material supplied by an authorized Fast Pair client.

    Secrets are kept outside the source tree.
    """

    account_key: bytes | None = None
    anti_spoofing_private_key: bytes | None = None

    def has_account_key(self) -> bool:
        return (
            self.account_key is not None
            and len(self.account_key) == 16
        )

    def has_anti_spoofing_private_key(self) -> bool:
        return (
            self.anti_spoofing_private_key is not None
            and len(self.anti_spoofing_private_key) > 0
        )


def load_account_key_from_environment() -> bytes | None:
    """
    Load an Account Key supplied by the user.

    Expected format:
        32 hexadecimal characters

    Returns None when FASTPAIR_ACCOUNT_KEY is not set.
    """

    value = os.environ.get("FASTPAIR_ACCOUNT_KEY")

    if value is None:
        return None

    value = value.strip()

    if not value:
        raise ValueError(
            "FASTPAIR_ACCOUNT_KEY is empty"
        )

    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(
            "FASTPAIR_ACCOUNT_KEY must contain hexadecimal bytes"
        ) from exc

    if len(key) != 16:
        raise ValueError(
            "FASTPAIR_ACCOUNT_KEY must contain exactly 16 bytes"
        )

    return key


def load_key_material() -> FastPairKeyMaterial:
    """
    Load available Fast Pair key material.
    """

    return FastPairKeyMaterial(
        account_key=load_account_key_from_environment(),
    )
