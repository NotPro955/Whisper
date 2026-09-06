from __future__ import annotations

from collections.abc import Callable

from .capabilities import KEY_BASED_PAIRING_UUID
from .gatt import GattClient
from .kbp import KBPClient
import importlib

_protocol_service = importlib.import_module(
    ".fast-pair-service",
    __package__,
)


class AuthorizedFastPairService:
    """BLE adapter for explicitly authorized educational protocol tests."""

    def __init__(self, client: GattClient, properties: tuple[str, ...]) -> None:
        if client.client is None:
            raise RuntimeError("BLE client is not connected")

        self.client = client
        self.transport = KBPClient(
            client.client,
            KEY_BASED_PAIRING_UUID,
            properties,
        )
        self._service = _protocol_service.AbstractFastPairService

    async def test_nonce_reuse(
        self,
        address: str,
        model_id: int,
        log_fn: Callable[[str], None] = print,
    ) -> str:
        device = _TestDevice(address, model_id, self.client)
        service = _NonceReuseService(self.transport, device)
        return await service.test_nonce_reuse(log_fn)

    async def test_invalid_curve(
        self,
        address: str,
        model_id: int,
        log_fn: Callable[[str], None] = print,
    ) -> None:
        device = _TestDevice(address, model_id, self.client)
        service = _InvalidCurveService(self.transport, device)
        await service.test_invalid_curve(log_fn)


class _TestDevice:
    def __init__(self, address: str, model_id: int, client: GattClient) -> None:
        self.address = address
        self.model_id = model_id
        self._client = client

    @property
    def connected(self) -> bool:
        return self._client.connected

    async def connect(self) -> None:
        await self._client.connect()

    async def disconnect(self) -> None:
        await self._client.disconnect()


class _ServiceBase:
    def __init__(self, transport: KBPClient, device: _TestDevice) -> None:
        self.transport = transport
        self.device = device

    async def write_key_based_pairing(self, data: bytes) -> None:
        await self.transport.write(data)


class _NonceReuseService(_ServiceBase, _protocol_service.AbstractFastPairService):
    async def read_model_id_characteristic(self) -> int:
        return self.device.model_id

    async def on_key_based_pairing_notify(self, cb):
        raise NotImplementedError("Notifications are not used by this test")

    async def write_passkey(self, data: bytes) -> None:
        raise NotImplementedError

    async def write_account_key(self, data: bytes) -> None:
        raise NotImplementedError


class _InvalidCurveService(_NonceReuseService):
    pass
