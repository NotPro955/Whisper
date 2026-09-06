import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

try:
    from . import protocol
except ImportError:  # pragma: no cover - support direct script execution
    import protocol

logger = logging.getLogger("FastPairService")
ACCOUNT_KEY = b"\x04" + bytes.fromhex("370beacd6f09e6f70dfe7fc5ad20a9")


class AbstractDevice(ABC):
    address: str
    connected: bool
    model_id: Optional[Any]

    @abstractmethod
    async def connect(self) -> None:
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        pass


class AbstractDeviceManager(ABC):
    @abstractmethod
    async def wait_for_device(self, address: str) -> tuple:
        pass


class AbstractFastPairService(ABC):
    def __init__(self, manager: AbstractDeviceManager, device: AbstractDevice):
        self.manager = manager
        self.device = device

    @abstractmethod
    async def read_model_id_characteristic(self) -> int:
        pass

    @abstractmethod
    async def on_key_based_pairing_notify(self, cb: Callable[[bytes], Any]) -> Callable[[], None]:
        pass

    @abstractmethod
    async def write_key_based_pairing(self, data: bytes) -> None:
        pass

    @abstractmethod
    async def write_passkey(self, data: bytes) -> None:
        pass

    @abstractmethod
    async def write_account_key(self, data: bytes) -> None:
        pass

    async def test_pairing_state_predicate(
        self,
        options: Dict[str, bool],
        log_fn: Callable[[str], None] = print,
    ) -> None:
        """Tests whether the provider correctly enforces bonding state prerequisites."""
        if not self.device.model_id:
            raise RuntimeError("Target device does not have a Model ID.")

        log_fn("Generating key based pairing payload...")
        mock_public_key = bytes.fromhex("0" * 128)
        msg_data = protocol.generate_key_based_pairing_message(self.device.address, mock_public_key)
        payload = msg_data["payload"]
        secret = msg_data["secret"]

        response_future = asyncio.get_running_loop().create_future()

        async def on_notify(buffer: bytes):
            log_fn("🔥 Received response notification")
            if not options.get("bond", False):
                if not response_future.done():
                    response_future.set_result(None)
                return

            try:
                decrypted = protocol.aes_ecb_decrypt_block(secret, buffer[:16])
                raw_addr = decrypted[1:7].hex().upper()
                formatted_addr = ":".join(raw_addr[i:i + 2] for i in range(0, 12, 2))
                log_fn(f"Parsed response address: {formatted_addr}")

                if options.get("write_account_key"):
                    log_fn("Writing account key...")
                    encrypted_account_key = protocol.aes_ecb_encrypt_block(
                        secret,
                        ACCOUNT_KEY[:16],
                    )
                    await self.write_account_key(encrypted_account_key)
                    log_fn("✅ Account key written")

                if not response_future.done():
                    response_future.set_result(None)
            except Exception as exc:  # pragma: no cover - runtime hook path
                if not response_future.done():
                    response_future.set_exception(exc)

        cleanup = await self.on_key_based_pairing_notify(on_notify)
        try:
            log_fn("Writing payload to key based pairing characteristic")
            await self.write_key_based_pairing(payload)
            await asyncio.wait_for(response_future, timeout=10.0)
        finally:
            cleanup()

    async def test_nonce_reuse(self, log_fn: Callable[[str], None] = print) -> str:
        """Tests whether devices properly handle or reject repeated nonces."""
        if not self.device.model_id:
            raise RuntimeError("Target device does not have a Model ID.")

        mock_public_key = bytes.fromhex("0" * 128)
        msg_data = protocol.generate_key_based_pairing_message(self.device.address, mock_public_key)
        payload = msg_data["payload"]

        for i in range(1, 4):
            log_fn(f"Writing payload ({i}/3)...")
            try:
                await self.write_key_based_pairing(payload)
                if i == 2:
                    log_fn("Disconnecting and reconnecting...")
                    await self.device.disconnect()
                    await self.device.connect()
            except Exception as exc:
                log_fn(f"⚠️ Payload write {i} rejected or failed: {exc}")

        return "success"

    async def test_invalid_curve(self, log_fn: Callable[[str], None] = print) -> None:
        """Tests whether devices reject invalid-curve inputs."""
        if not self.device.model_id:
            raise RuntimeError("Target device does not have a Model ID.")

        possible_payloads = protocol.generate_possible_invalid_key_based_pairing_messages(
            self.device.address
        )
        successful_payloads: List[int] = []

        for i, item in enumerate(possible_payloads):
            log_fn(f"Trying payload {i + 1}/{len(possible_payloads)}")
            payload = item["payload"]

            if not self.device.connected:
                log_fn("Device disconnected, reconnecting...")
                await self.device.connect()

            try:
                await self.write_key_based_pairing(payload)
                successful_payloads.append(i)
            except Exception as exc:
                log_fn(f"⚠️ Payload {i + 1} rejected: {exc}")

        if successful_payloads:
            log_fn(f"✅ {len(successful_payloads)}/{len(possible_payloads)} accepted")
        else:
            log_fn("No invalid curve payloads were accepted")
            raise RuntimeError("No payloads were accepted")