import asyncio
import shutil
from pathlib import Path


class RecordingError(RuntimeError):
    """Raised when microphone recording fails."""


class MicrophoneRecorder:
    """
    Records audio from a PipeWire/PulseAudio source.

    Recording is explicitly started by the application.
    This class does not select or connect to Bluetooth devices.
    """

    def __init__(
        self,
        output_path: str | Path = "recording.wav",
    ) -> None:
        self.output_path = Path(output_path)
        self.process: asyncio.subprocess.Process | None = None

    @staticmethod
    def available() -> bool:
        return shutil.which("parecord") is not None

    async def record(
        self,
        source: str | None = None,
    ) -> Path:
        """
        Start recording until stop() is called.
        """

        if not self.available():
            raise RecordingError(
                "parecord was not found. "
                "Install pulseaudio-utils."
            )

        if self.process is not None:
            raise RecordingError(
                "A recording is already running."
            )

        command = [
            "parecord",
            "--file-format=wav",
        ]

        if source:
            command.extend([
                "--device",
                source,
            ])

        command.append(str(self.output_path))

        self.process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        return self.output_path

    async def stop(self) -> Path:
        """
        Stop the current recording.
        """

        if self.process is None:
            raise RecordingError(
                "No recording is currently running."
            )

        self.process.terminate()

        stdout, stderr = await self.process.communicate()

        self.process = None

        if stderr:
            error = stderr.decode(errors="replace").strip()

            if error:
                raise RecordingError(error)

        if not self.output_path.exists():
            raise RecordingError(
                "Recording process ended but the output "
                "file was not created."
            )

        return self.output_path