from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import sounddevice as sd


@dataclass(frozen=True)
class PlaybackConfig:
    device: int | None = None
    sample_rate: int = 48000
    channels: int = 1
    block_size: int = 1024


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
