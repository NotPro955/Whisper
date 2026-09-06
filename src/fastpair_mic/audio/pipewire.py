import asyncio
import shutil


class PipeWireError(RuntimeError):
    """Raised when PipeWire audio discovery fails."""


class PipeWire:
    """
    Small wrapper around Linux audio discovery.

    We use pactl because PipeWire normally provides a
    PulseAudio-compatible interface through pipewire-pulse.

    This class only discovers audio devices. It does not
    record, play audio, or change device settings.
    """

    @staticmethod
    def available() -> bool:
        return shutil.which("pactl") is not None

    async def _run(self, *arguments: str) -> str:
        if not self.available():
            raise PipeWireError(
                "pactl was not found. "
                "Install pipewire-pulse."
            )

        process = await asyncio.create_subprocess_exec(
            "pactl",
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        output = stdout.decode(errors="replace").strip()
        error = stderr.decode(errors="replace").strip()

        if process.returncode != 0:
            raise PipeWireError(
                error or output or
                f"pactl exited with code {process.returncode}"
            )

        return output

    async def list_sinks(self) -> str:
        """Return available audio output devices."""
        return await self._run("list", "short", "sinks")

    async def list_sources(self) -> str:
        """Return available audio input devices."""
        return await self._run("list", "short", "sources")

    async def list_cards(self) -> str:
        """Return Bluetooth/audio cards known to the audio server."""
        return await self._run("list", "short", "cards")
