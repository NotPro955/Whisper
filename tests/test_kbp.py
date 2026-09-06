from fastpair_mic.fastpair.capabilities import (
    KEY_BASED_PAIRING_UUID,
    detect_capabilities,
)
from fastpair_mic.fastpair.gatt import (
    GattCharacteristicInfo,
    GattServiceInfo,
)


def test_kbp_characteristic_is_detected():
    services = [
        GattServiceInfo(
            uuid="0000fe2c-0000-1000-8000-00805f9b34fb",
            characteristics=(
                GattCharacteristicInfo(
                    uuid=KEY_BASED_PAIRING_UUID,
                    properties=("write", "notify"),
                ),
            ),
        )
    ]

    capabilities = detect_capabilities(services)

    assert capabilities.fast_pair is True
    assert capabilities.key_based_pairing is True

def test_kbp_client_accepts_encrypted_request():
    from fastpair_mic.fastpair.kbp_protocol import (
        build_kbp_request,
        encrypt_kbp_request,
    )

    provider = bytes.fromhex("010203040506")
    key = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f"
    )

    request = build_kbp_request(
        provider,
        salt=bytes.fromhex("1011121314151617"),
    )

    encrypted = encrypt_kbp_request(
        request,
        key,
    )

    assert len(encrypted) == 16
    assert encrypted != request.encode()
