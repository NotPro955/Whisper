from __future__ import annotations

import asyncio


class AudioMonitorError(RuntimeError):
    """Raised when audio monitoring fails."""


class PipeWireMonitor:
    """
    Explicit audio monitor.

    Audio path:

        selected PipeWire source
                    ↓
               pw-record
                    ↓
               pw-play
                    ↓
        selected PipeWire sink
    """

    def __init__(
        self,
        source: str,
        sink: str,
        *,
        rate: int = 48000,
        channels: int = 1,
    ) -> None:
        if not source:
            raise ValueError("Audio source cannot be empty.")

        if not sink:
            raise ValueError("Audio sink cannot be empty.")

        self.source = source
        self.sink = sink
        self.rate = rate
        self.channels = channels

        self.record_process: (
            asyncio.subprocess.Process | None
        ) = None

        self.play_process: (
            asyncio.subprocess.Process | None
        ) = None

        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self.running:
            raise AudioMonitorError(
                "Audio monitor is already running."
            )

        record_command = [
            "pw-record",
            "--target",
            self.source,
            "--raw",
            "--format",
            "s16",
            "--rate",
            str(self.rate),
            "--channels",
            str(self.channels),
            "-",
        ]

        play_command = [
            "pw-play",
            "--target",
            self.sink,
            "--raw",
            "--format",
            "s16",
            "--rate",
            str(self.rate),
            "--channels",
            str(self.channels),
            "-",
        ]

        try:
            self.record_process = (
                await asyncio.create_subprocess_exec(
                    *record_command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            )

            self.play_process = (
                await asyncio.create_subprocess_exec(
                    *play_command,
                    stdin=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            )

        except FileNotFoundError as exc:
            await self.stop()

            raise AudioMonitorError(
                "pw-record or pw-play was not found."
            ) from exc

        if self.record_process.stdout is None:
            await self.stop()
            raise AudioMonitorError(
                "Could not open PipeWire recording stream."
            )

        if self.play_process.stdin is None:
            await self.stop()
            raise AudioMonitorError(
                "Could not open PipeWire playback stream."
            )

        self._task = asyncio.create_task(
            self._forward_audio()
        )

    async def _forward_audio(self) -> None:
        if self.record_process is None:
            return

        if self.play_process is None:
            return

        if self.record_process.stdout is None:
            return

        if self.play_process.stdin is None:
            return

        try:
            while True:
                data = await self.record_process.stdout.read(4096)

                if not data:
                    break

                self.play_process.stdin.write(data)
                await self.play_process.stdin.drain()

        except (BrokenPipeError, ConnectionResetError):
            pass

    async def stop(self) -> None:
        if self._task is not None:
            if not self._task.done():
                self._task.cancel()

            try:
                await self._task
            except asyncio.CancelledError:
                pass

            self._task = None

        processes = (
            self.record_process,
            self.play_process,
        )

        self.record_process = None
        self.play_process = None

        for process in processes:
            if process is None:
                continue

            if process.returncode is None:
                process.terminate()

        for process in processes:
            if process is None:
                continue

            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=2.0,
                )
            except asyncio.TimeoutError:
                if process.returncode is None:
                    process.kill()

                await process.wait()

    @property
    def running(self) -> bool:
        record = self.record_process
        play = self.play_process

        return (
            record is not None
            and record.returncode is None
            and play is not None
            and play.returncode is None
        )
