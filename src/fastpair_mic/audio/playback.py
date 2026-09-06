from __future__ import annotations

import math
import wave
from dataclasses import dataclass
from pathlib import Path

import numpy as np

try:
    import sounddevice as sd
except (ImportError, OSError):
    sd = None


@dataclass(frozen=True)
class PlaybackConfig:
    device: int | None = None
    sample_rate: int = 48000
    channels: int = 1
    block_size: int = 1024


def generate_demo_wave(
    output_path: str | Path,
    *,
    sample_rate: int = 48000,
    duration_seconds: float = 2.0,
    tone_hz: float = 440.0,
) -> str:
    """Create a small WAV file suitable for a device demo/test signal."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    total_samples = int(sample_rate * duration_seconds)
    sample_data = np.linspace(0, duration_seconds, total_samples, endpoint=False)
    tone = 0.3 * np.sin(2.0 * math.pi * tone_hz * sample_data)
    audio = np.clip(tone, -1.0, 1.0)

    pcm = np.int16(audio * 32767)

    with wave.open(str(path), "wb") as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(pcm.tobytes())

    return str(path)


class Playback:
    """
    Plays audio through an explicitly selected output device.

    This class handles only local audio playback.
    """

    def __init__(
        self,
        config: PlaybackConfig | None = None,
    ) -> None:
        self.config = config or PlaybackConfig()
        self.stream: sd.OutputStream | None = None

    def start(self) -> None:
        if sd is None:
            raise RuntimeError(
                "PortAudio is not available in this environment. "
                "Install the system PortAudio library or run on a desktop audio host."
            )

        if self.stream is not None:
            raise RuntimeError("Playback is already running")

        self.stream = sd.OutputStream(
            device=self.config.device,
            samplerate=self.config.sample_rate,
            channels=self.config.channels,
            blocksize=self.config.block_size,
            dtype="float32",
        )

        self.stream.start()

    def play(self, audio: np.ndarray) -> None:
        if self.stream is None:
            raise RuntimeError("Playback is not running")

        self.stream.write(audio)

    def stop(self) -> None:
        if self.stream is None:
            return

        self.stream.stop()
        self.stream.close()
        self.stream = None

    @property
    def running(self) -> bool:
        return self.stream is not None

    def __enter__(self) -> "Playback":
        self.start()
        return self

    def __exit__(
        self,
        _exc_type,
        _exc_value,
        _traceback,
    ) -> None:
        self.stop()
