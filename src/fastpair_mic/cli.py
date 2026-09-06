import asyncio
from pathlib import Path

from .audio.devices import discover_audio_devices
from .audio.playback import generate_demo_wave
from .bluetooth.bluez import BlueZ, BlueZError
from .bluetooth.pairing import BluetoothPairing, PairingError
from .fastpair.capabilities import (
    KEY_BASED_PAIRING_UUID,
    detect_capabilities,
)
from .fastpair.gatt import GattClient
from .fastpair.authorized_service import AuthorizedFastPairService
from .fastpair.scanner import scan
from .speech.recorder import record


def print_header(title: str) -> None:
    print()
    print("=" * 60)
    print(title)
    print("=" * 60)


def print_separator() -> None:
    print("-" * 60)


def consent_prompt(device) -> bool:
    print_header("AUTHORIZED EDUCATIONAL TEST ONLY")

    print("Target selected:")
    print(f"  Device:  {device.name}")
    print(f"  Address: {device.address}")

    print()
    print("WARNING")
    print("-------")
    print(
        "This program is for educational purposes only and"
        " for testing on a device that you own or that the"
        " owner has explicitly authorized before testing."
    )
    print()
    print(
        "It must never be used on an arbitrary nearby device,"
        " a public device, or any device without permission."
    )
    print()
    print(
        "Whisper Pair will only interact with the single selected"
        " target and will not scan or contact other devices."
    )
    print()
    print(
        "If you do not own this device or do not have explicit"
        " permission, exit immediately now."
    )
    print()
    print(
        'Type exactly "I accept this educational test on an authorized device" '
        "to continue."
    )
    print("Anything else cancels the demonstration.")
    print()

    return (
        input("> ").strip()
        == "I accept this educational test on an authorized device"
    )


def display_devices(devices) -> None:
    print_header("FAST PAIR DEVICES")

    for index, device in enumerate(devices, start=1):
        rssi = (
            f"{device.rssi} dBm"
            if device.rssi is not None
            else "unknown"
        )

        print(f"{index}. {device.name}")
        print(f"   Address:  {device.address}")
        print(f"   RSSI:     {rssi}")
        print(f"   Model ID: 0x{device.model_id:06X}")
        print()


def select_device(devices):
    while True:
        choice = input(
            f"Select a device (1-{len(devices)}, or q to quit): "
        ).strip()

        if choice.lower() == "q":
            return None

        try:
            index = int(choice)
        except ValueError:
            print("Please enter a number or q.")
            continue

        if 1 <= index <= len(devices):
            return devices[index - 1]

        print("Invalid selection.")


async def inspect_fast_pair(device) -> None:
    print_header("FAST PAIR / GATT CONNECTION")

    print(f"Target:  {device.name}")
    print(f"Address: {device.address}")
    print()
    print("Connecting to selected target over BLE GATT...")

    client = GattClient(device.address)

    try:
        await client.connect()

        print("Connected.")

        services = await client.discover()

        capabilities = detect_capabilities(services)

        print_header("GATT / FAST PAIR INSPECTION")

        print(f"Device:   {device.name}")
        print(f"Address:  {device.address}")
        print(f"Model ID: 0x{device.model_id:06X}")
        print()

        print(
            "Fast Pair service:       "
            f"{'YES' if capabilities.fast_pair else 'NO'}"
        )
        print(
            "Model ID characteristic: "
            f"{'YES' if capabilities.model_id else 'NO'}"
        )
        print(
            "Key-Based Pairing:       "
            f"{'YES' if capabilities.key_based_pairing else 'NO'}"
        )
        print(
            "Passkey:                 "
            f"{'YES' if capabilities.passkey else 'NO'}"
        )
        print(
            "Account Key:             "
            f"{'YES' if capabilities.account_key else 'NO'}"
        )

        if capabilities.key_based_pairing:
            kbp_characteristic = next(
                (
                    characteristic
                    for service in services
                    for characteristic in service.characteristics
                    if characteristic.uuid.lower()
                    == KEY_BASED_PAIRING_UUID.lower()
                ),
                None,
            )

            print()
            print("KBP characteristic:")

            if kbp_characteristic is None:
                print("  UUID:          not found")
            else:
                properties = {
                    prop.lower()
                    for prop in kbp_characteristic.properties
                }

                writable = (
                    "write" in properties
                    or "write-without-response" in properties
                )

                notifications = (
                    "notify" in properties
                    or "indicate" in properties
                )

                print(
                    f"  UUID:          "
                    f"{kbp_characteristic.uuid}"
                )
                print(
                    "  Writable:      "
                    f"{'YES' if writable else 'NO'}"
                )
                print(
                    "  Notifications: "
                    f"{'YES' if notifications else 'NO'}"
                )

        print_header("SECURITY ASSESSMENT")

        if capabilities.key_based_pairing:
            print("Fast Pair KBP surface: EXPOSED")
            print()
            print(
                "The device exposes a Fast Pair Key-Based "
                "Pairing security surface."
            )
            print()
            print(
                "Exposure alone does not prove that the device "
                "is vulnerable."
            )
        else:
            print("Fast Pair KBP surface: NOT DETECTED")
            print()
            print(
                "The expected Fast Pair Key-Based Pairing "
                "characteristic was not detected."
            )

        print()
        print("Assessment performed:")
        print("  GATT capability inspection")
        print("  Fast Pair characteristic inspection")
        print("  Protocol metadata inspection")
        print("  Non-destructive testing")
        print()
        print("Authentication bypass:  NOT PERFORMED")
        print("Account-key extraction: NOT PERFORMED")
        print("Account-key modification: NOT PERFORMED")

    finally:
        if client.connected:
            await client.disconnect()

        print()
        print("Fast Pair GATT connection closed.")


async def run_authorized_protocol_test(device) -> None:
    print_header("AUTHORIZED PROTOCOL TEST")
    print("This operation writes test payloads to the selected BLE device.")
    print("Run it only against hardware you own or are explicitly authorized to test.")
    print("It does not write an account key.")
    print()
    print('Type exactly "I understand this writes test payloads to the authorized device" to continue.')

    if input("> ").strip() != "I understand this writes test payloads to the authorized device":
        print("Protocol test cancelled.")
        return

    client = GattClient(device.address)

    try:
        await client.connect()
        services = await client.discover()
        kbp_characteristic = next(
            (
                characteristic
                for service in services
                for characteristic in service.characteristics
                if characteristic.uuid.lower() == KEY_BASED_PAIRING_UUID.lower()
            ),
            None,
        )

        if kbp_characteristic is None:
            print("KBP characteristic was not found.")
            return

        properties = tuple(prop.lower() for prop in kbp_characteristic.properties)
        if not {"write", "write-without-response"}.intersection(properties):
            print("KBP characteristic is not writable.")
            return

        service = AuthorizedFastPairService(client, properties)
        print()
        print("1. Test invalid-curve handling")
        print("2. Test nonce reuse handling")
        print("q. Cancel")
        choice = input("> ").strip().lower()

        if choice == "1":
            await service.test_invalid_curve(
                device.address,
                device.model_id,
            )
        elif choice == "2":
            result = await service.test_nonce_reuse(
                device.address,
                device.model_id,
            )
            print(f"Nonce reuse test finished: {result}")
        else:
            print("Protocol test cancelled.")
    finally:
        if client.connected:
            await client.disconnect()
        print("Protocol test connection closed.")


async def connect_bluetooth(device) -> bool:
    print_header("NORMAL BLUETOOTH / BR/EDR")

    print(f"Target device: {device.name}")
    print(f"Address:       {device.address}")
    print()
    print("Connecting through BlueZ...")
    print()

    bluez = BlueZ()

    try:
        await bluez.connect(device.address)

        print("Connected.")
        print()
        print(
            "The normal Bluetooth connection uses the address "
            "selected from the current discovery result."
        )
        return True

    except BlueZError as exc:
        print()
        print("Normal Bluetooth connection failed.")
        print(f"Reason: {exc}")
        print()
        print(
            "Whisper Pair will not attempt to disconnect, "
            "override, or take over another Bluetooth device."
        )
        return False


async def pair_bluetooth(device) -> bool:
    print_header("BLUETOOTH PAIRING")

    print(f"Target:  {device.name}")
    print(f"Address: {device.address}")
    print()
    print(
        "The selected device requires normal Bluetooth "
        "pairing before audio can be used."
    )
    print()

    pairing = BluetoothPairing()

    try:
        print("Starting authorized Bluetooth pairing...")
        output = await pairing.pair(device.address)

        if output:
            print(output)

        print()
        print("Pairing completed.")

        try:
            trust_output = await pairing.trust(device.address)

            if trust_output:
                print(trust_output)

            print("Device trusted in BlueZ.")

        except PairingError as exc:
            print(f"Trust operation was not completed: {exc}")

        return True

    except PairingError as exc:
        print()
        print("Pairing failed.")
        print(f"Reason: {exc}")
        return False


async def establish_bluetooth_audio_connection(device) -> bool:
    """
    Establish the normal Bluetooth connection.

    The Fast Pair/GATT connection has already been handled separately.
    This stage uses BlueZ and does not perform Fast Pair KBP operations.
    """

    connected = await connect_bluetooth(device)

    if connected:
        return True

    print_header("PAIRING FALLBACK")

    print(
        "The initial normal Bluetooth connection was not "
        "established."
    )
    print()
    print(
        "Whisper Pair can attempt normal user-authorized "
        "Bluetooth pairing for the selected target."
    )
    print()

    choice = input(
        'Type "pair" to attempt pairing, or anything else to stop: '
    ).strip().lower()

    if choice != "pair":
        print("Bluetooth pairing cancelled.")
        return False

    paired = await pair_bluetooth(device)

    if not paired:
        return False

    print()
    print("Retrying normal Bluetooth connection...")

    return await connect_bluetooth(device)


async def inspect_bluetooth_audio(device) -> str | None:
    print_header("BLUETOOTH AUDIO")

    print(f"Target:  {device.name}")
    print(f"Address: {device.address}")
    print()

    try:
        outputs, inputs = await discover_audio_devices()
    except Exception as exc:
        print("PipeWire audio discovery failed.")
        print(f"Reason: {exc}")
        return None

    bluetooth_inputs = [
        audio_device
        for audio_device in inputs
        if audio_device.identifier.startswith("bluez_input.")
    ]

    bluetooth_outputs = [
        audio_device
        for audio_device in outputs
        if audio_device.identifier.startswith("bluez_output.")
    ]

    print("PipeWire audio state:")
    print()

    if bluetooth_outputs:
        print("Bluetooth outputs:")
        for audio_device in bluetooth_outputs:
            print(f"  {audio_device.identifier}")
    else:
        print("Bluetooth outputs: NOT DETECTED")

    print()

    if bluetooth_inputs:
        print("Bluetooth microphone sources:")
        for audio_device in bluetooth_inputs:
            print(f"  {audio_device.identifier}")
    else:
        print("Bluetooth microphone sources: NOT DETECTED")

    print()

    if not bluetooth_inputs:
        print(
            "No bluez_input.* microphone source is currently "
            "available through PipeWire."
        )
        print()
        print(
            "The Bluetooth connection itself does not guarantee "
            "that a microphone profile is available."
        )
        return None

    selected_source = bluetooth_inputs[0].identifier

    print("Bluetooth microphone detected.")
    print(f"Source: {selected_source}")

    return selected_source


async def record_bluetooth_microphone(source: str) -> str | None:
    print_header("BLUETOOTH MICROPHONE")

    print("Target microphone detected.")
    print()
    print(f"Source: {source}")
    print()
    print('Type "q" and press Enter to stop recording.')
    print()

    recordings_dir = Path("recordings")
    recordings_dir.mkdir(parents=True, exist_ok=True)

    output_path = recordings_dir / "whisper_pair_recording.wav"

    try:
        saved_path = await record(str(output_path))

        print()
        print_header("RECORDING COMPLETE")
        print(f"Saved: {saved_path}")

        return saved_path

    except Exception as exc:
        print()
        print_header("RECORDING ERROR")
        print(str(exc))
        return None


async def play_demo_audio_on_bluetooth(device) -> str | None:
    """Generate a local WAV and play it through the selected Bluetooth output."""
    print_header("BLUETOOTH AUDIO PLAYBACK")

    recordings_dir = Path("recordings")
    recordings_dir.mkdir(parents=True, exist_ok=True)
    demo_path = recordings_dir / "demo.wav"

    generated = generate_demo_wave(demo_path)

    print(f"Target:  {device.name}")
    print(f"Address: {device.address}")
    print(f"Demo file: {generated}")
    print()
    print("This stage uses a normal local WAV file and a normal Bluetooth audio output.")
    print("It does not use the Fast Pair Audio Switch exploit path.")
    print()

    try:
        outputs, _ = await discover_audio_devices()
    except Exception as exc:
        print("Could not query PipeWire audio devices.")
        print(f"Reason: {exc}")
        return None

    bluetooth_outputs = [
        audio_device
        for audio_device in outputs
        if audio_device.identifier.startswith("bluez_output.")
    ]

    if not bluetooth_outputs:
        print("No bluez_output.* device is available in PipeWire.")
        return None

    selected_output = bluetooth_outputs[0].identifier
    print(f"Selected output: {selected_output}")
    print()
    print("Playback is a normal local demo tone using the selected Bluetooth output")
    print("through PipeWire.")

    try:
        process = await asyncio.create_subprocess_exec(
            "pw-play",
            "--target",
            selected_output,
            str(generated),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()

        if process.returncode != 0:
            error = stderr.decode(errors="replace").strip()
            print("Demo playback failed.")
            print(error or "pw-play returned a failure code.")
            return None

        print("Demo playback completed.")
        return generated
    except FileNotFoundError:
        print("pw-play was not found. Install pipewire-pulse to play audio.")
        return None


async def async_main() -> None:
    print_header("WHISPER PAIR")

    print("Fast Pair BLE discovery")
    print("Authorized Bluetooth security demonstration")
    print()

    print("Scanning for Fast Pair advertisements...")

    devices = await scan(15)

    if not devices:
        print()
        print("No Fast Pair devices found.")
        return

    display_devices(devices)

    selected = select_device(devices)

    if selected is None:
        print()
        print("Demonstration cancelled.")
        return

    print_header("TARGET SELECTED")

    print(f"Device:  {selected.name}")
    print(f"Address: {selected.address}")
    print(f"Model ID: 0x{selected.model_id:06X}")

    if not consent_prompt(selected):
        print()
        print("Authorization not provided.")
        print("No connection was attempted.")
        return

    print()
    print("Authorization accepted.")
    print()
    print(
        "This is an authorized educational security demonstration for the selected device only."
    )
    print(
        "No other target will be contacted, and the flow stops immediately if the device is not explicitly authorized."
    )

    try:
        await inspect_fast_pair(selected)

    except Exception as exc:
        print()
        print_header("FAST PAIR CONNECTION ERROR")
        print(str(exc))

        print()
        print(
            "Fast Pair inspection could not be completed."
        )

    await run_authorized_protocol_test(selected)

    bluetooth_connected = await establish_bluetooth_audio_connection(
        selected
    )

    if not bluetooth_connected:
        print()
        print_header("DEMONSTRATION STOPPED")
        print(
            "The normal Bluetooth audio connection was not "
            "established."
        )
        return

    source = await inspect_bluetooth_audio(selected)

    if source is None:
        print()
        print_header("AUDIO MICROPHONE UNAVAILABLE")
        print(
            "Bluetooth is connected, but PipeWire did not "
            "expose a Bluetooth microphone source."
        )
        return

    demo_audio = await play_demo_audio_on_bluetooth(selected)

    if demo_audio is None:
        print()
        print_header("PLAYBACK SKIPPED")
        print("The normal Bluetooth output was not available for local audio playback.")
        return

    await record_bluetooth_microphone(source)


def main() -> None:
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print()
        print("Demonstration interrupted by user.")


if __name__ == "__main__":
    main()
