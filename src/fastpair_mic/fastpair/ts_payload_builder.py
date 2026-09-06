"""Reserved TS-derived payload builders.

These names mirror the TypeScript implementation and are placed here so the
user-authored code remains intact while the protocol-building logic is isolated
into a dedicated, clearly labeled module.
"""


def generate_payload(address: str, secret: bytes, generated_public_key: bytes):
    """Placeholder for the TS generatePayload helper."""
    print(
        "[TS PAYLOAD PLACEHOLDER] generate_payload: "
        "this part of the exploit logic is running."
    )
    return {
        "payload": b"",
        "cipher": None,
        "decipher": None,
    }


def generate_key_based_pairing_message(address: str, public_key: bytes):
    """Placeholder for the TS generateKeyBasedPairingMessage helper."""
    print(
        "[TS PAYLOAD PLACEHOLDER] generate_key_based_pairing_message: "
        "this part of the exploit logic is running."
    )
    return generate_payload(address, b"", b"")


def generate_possible_invalid_key_based_pairing_messages(address: str):
    """Placeholder for the TS generatePossibleInvalidKeyBasedPairingMessages helper."""
    print(
        "[TS PAYLOAD PLACEHOLDER] generate_possible_invalid_key_based_pairing_messages: "
        "this part of the exploit logic is running."
    )
    return [generate_payload(address, b"", b"")]


async def generate_passkey_message(cipher, passkey: int):
    """Placeholder for the TS generatePasskeyMessage helper."""
    print(
        "[TS PAYLOAD PLACEHOLDER] generate_passkey_message: "
        "this part of the exploit logic is running."
    )
    return b""
