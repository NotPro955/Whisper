from dataclasses import dataclass


@dataclass(frozen=True)
class BluetoothAudioCapabilities:
    """
    Audio capabilities exposed by a Bluetooth device.
    """

    a2dp_sink: bool = False
    hfp: bool = False
    hsp: bool = False
    le_audio: bool = False

    @property
    def has_output(self) -> bool:
        return self.a2dp_sink or self.hfp or self.hsp or self.le_audio

    @property
    def has_microphone(self) -> bool:
        return self.hfp or self.hsp or self.le_audio


def detect_from_uuids(uuids: list[str]) -> BluetoothAudioCapabilities:
    """
    Detect commonly used Bluetooth audio profiles from service UUIDs.

    This is intentionally generic. A device may expose different
    combinations of profiles.
    """

    normalized = {uuid.lower() for uuid in uuids}

    # Bluetooth SIG service UUIDs.
    A2DP_SINK = "0000110b-0000-1000-8000-00805f9b34fb"
    HFP = "0000111e-0000-1000-8000-00805f9b34fb"
    HSP = "00001108-0000-1000-8000-00805f9b34fb"

    # LE Audio uses several services rather than one universal
    # "LE Audio" UUID. We therefore don't claim LE Audio solely
    # from an arbitrary unknown UUID here.
    le_audio = False

    return BluetoothAudioCapabilities(
        a2dp_sink=A2DP_SINK in normalized,
        hfp=HFP in normalized,
        hsp=HSP in normalized,
        le_audio=le_audio,
    )
