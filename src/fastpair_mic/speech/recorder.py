import asyncio
import subprocess
from pathlib import Path


class RecordingError(RuntimeError):
    """Raised when audio recording fails."""


async def _run_command(*arguments: str) -> str:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        error = stderr.decode(errors="replace").strip()
        raise RecordingError(
            error or f"Command failed: {' '.join(arguments)}"
        )

    return stdout.decode(errors="replace")


def list_sources() -> list[str]:
    try:
        result = subprocess.run(
            ["pactl", "list", "short", "sources"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise RecordingError(
            f"Could not query audio sources: {exc}"
        ) from exc

    sources = []

    for line in result.stdout.splitlines():
        parts = line.split()

        if len(parts) >= 2:
            sources.append(parts[1])

    return sources


def find_bluetooth_source() -> str:
    for source in list_sources():
        if source.startswith("bluez_input."):
            return source

    raise RecordingError(
        "No Bluetooth microphone source was found."
    )


async def wait_for_quit() -> None:
    loop = asyncio.get_running_loop()

    while True:
        command = await loop.run_in_executor(
            None,
            input,
        )

        if command.strip().lower() == "q":
            return


async def record(
    output_path: str,
) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    source = find_bluetooth_source()

    print("=" * 60)
    print("WHISPER PAIR AUDIO RECORDING")
    print("=" * 60)
    print()
    print(f"Bluetooth source: {source}")
    print()
    print("Recording...")
    print('Type "q" and press Enter to stop.')
    print()

    command = [
        "parecord",
        "--device",
        source,
        "--file-format=wav",
        str(path),
    ]

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        await wait_for_quit()

    finally:
        if process.returncode is None:
            process.terminate()

        try:
            await asyncio.wait_for(
                process.wait(),
                timeout=3,
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()

    if process.returncode not in (0, -15):
        stderr = await process.stderr.read()

        raise RecordingError(
            "parecord failed: "
            + stderr.decode(errors="replace").strip()
        )

    if not path.exists():
        raise RecordingError(
            f"Recording file was not created: {path}"
        )

    print()
    print(f"Recording saved: {path}")

    return str(path)
