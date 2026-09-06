from fastpair_mic.fastpair.capabilities import (
    FAST_PAIR_SERVICE_UUID,
    KEY_BASED_PAIRING_UUID,
    MODEL_ID_UUID,
    PASSKEY_UUID,
    ACCOUNT_KEY_UUID,
)
from fastpair_mic.fastpair.gatt import (
    GattCharacteristicInfo,
    GattServiceInfo,
)
from fastpair_mic.fastpair.capabilities import detect_capabilities


def test_inspection_capabilities():

    services = [
        GattServiceInfo(
            uuid=FAST_PAIR_SERVICE_UUID,
            characteristics=(
                GattCharacteristicInfo(MODEL_ID_UUID, ("read",)),
                GattCharacteristicInfo(
                    KEY_BASED_PAIRING_UUID,
                    ("write", "notify"),
                ),
                GattCharacteristicInfo(PASSKEY_UUID, ("write",)),
                GattCharacteristicInfo(ACCOUNT_KEY_UUID, ("write",)),
            ),
        )
    ]

    capabilities = detect_capabilities(services)

    assert capabilities.fast_pair
    assert capabilities.model_id
    assert capabilities.key_based_pairing
    assert capabilities.passkey
    assert capabilities.account_key
