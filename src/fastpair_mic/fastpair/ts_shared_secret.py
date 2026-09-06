"""Reserved TS-derived shared-secret helpers.

These names mirror the TypeScript implementation for the authorized-test workflow.
The functions intentionally do not perform any real exploit behavior.
"""


def convert_address_to_hex(address: str) -> str:
    """Placeholder for the TS convertAddressToHex helper."""
    print(
        "[TS SHARED SECRET PLACEHOLDER] convert_address_to_hex: "
        "this part of the exploit logic is reserved for authorized testing."
    )
    return address.replace(":", "").lower()


def generate_shared_secret(public_key: bytes):
    """Placeholder for the TS generateSharedSecret helper."""
    print(
        "[TS SHARED SECRET PLACEHOLDER] generate_shared_secret: "
        "this part of the exploit logic is running."
    )
    return {
        "secret": b"",
        "generated_public_key": b"",
    }


def generate_invalid_shared_secret():
    """Placeholder for the TS generateInvalidSharedSecret helper."""
    print(
        "[TS SHARED SECRET PLACEHOLDER] generate_invalid_shared_secret: "
        "this part of the exploit logic is running."
    )
    return {
        "secrets": [],
        "generated_public_key": b"",
    }
