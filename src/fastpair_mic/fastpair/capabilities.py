from dataclasses import dataclass

from .gatt import GattServiceInfo


FAST_PAIR_SERVICE_UUID = "0000fe2c-0000-1000-8000-00805f9b34fb"

MODEL_ID_UUID = "fe2c1233-8366-4814-8eb0-01de32100bea"
KEY_BASED_PAIRING_UUID = "fe2c1234-8366-4814-8eb0-01de32100bea"
PASSKEY_UUID = "fe2c1235-8366-4814-8eb0-01de32100bea"
ACCOUNT_KEY_UUID = "fe2c1236-8366-4814-8eb0-01de32100bea"


@dataclass(frozen=True)
class FastPairCapabilities:
    fast_pair: bool
    model_id: bool
    key_based_pairing: bool
    passkey: bool
    account_key: bool


def detect_capabilities(
    services: list[GattServiceInfo],
) -> FastPairCapabilities:
    service_uuids = {service.uuid.lower() for service in services}

    characteristic_uuids = {
        characteristic.uuid.lower()
        for service in services
        for characteristic in service.characteristics
    }

    return FastPairCapabilities(
        fast_pair=FAST_PAIR_SERVICE_UUID in service_uuids,
        model_id=MODEL_ID_UUID in characteristic_uuids,
        key_based_pairing=KEY_BASED_PAIRING_UUID in characteristic_uuids,
        passkey=PASSKEY_UUID in characteristic_uuids,
        account_key=ACCOUNT_KEY_UUID in characteristic_uuids,
    )

