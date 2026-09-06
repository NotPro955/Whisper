from fastpair_mic.fastpair.capabilities import (
    ACCOUNT_KEY_UUID,
    FAST_PAIR_SERVICE_UUID,
    KEY_BASED_PAIRING_UUID,
    MODEL_ID_UUID,
    PASSKEY_UUID,
    detect_capabilities,
)
from fastpair_mic.fastpair.gatt import (
    GattCharacteristicInfo,
    GattServiceInfo,
)


def test_fast_pair_capabilities():
    characteristics = (
        GattCharacteristicInfo(MODEL_ID_UUID, ("read",)),
        GattCharacteristicInfo(KEY_BASED_PAIRING_UUID, ("write", "notify")),
        GattCharacteristicInfo(PASSKEY_UUID, ("write",)),
        GattCharacteristicInfo(ACCOUNT_KEY_UUID, ("write",)),
    )

    services = [
        GattServiceInfo(
            FAST_PAIR_SERVICE_UUID,
            characteristics,
        )
    ]

    capabilities = detect_capabilities(services)

    assert capabilities.fast_pair is True
    assert capabilities.model_id is True
    assert capabilities.key_based_pairing is True
    assert capabilities.passkey is True
    assert capabilities.account_key is True
