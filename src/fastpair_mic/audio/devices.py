from dataclasses import dataclass

from .pipewire import PipeWire


@dataclass(frozen=True)
class AudioDevice:
    identifier: str
    name: str
    description: str


async def discover_audio_devices() -> tuple[
    list[AudioDevice],
    list[AudioDevice],
]:
    """
    Discover audio outputs and inputs exposed by PipeWire.

    Returns:
        (outputs, inputs)
    """

    pipewire = PipeWire()

    sink_output = await pipewire.list_sinks()
    source_output = await pipewire.list_sources()

    outputs: list[AudioDevice] = []
    inputs: list[AudioDevice] = []

    for line in sink_output.splitlines():
        parts = line.split("\t")

        if len(parts) < 2:
            continue

        identifier = parts[1]

        outputs.append(
            AudioDevice(
                identifier=identifier,
                name=identifier,
                description=line,
            )
        )

    for line in source_output.splitlines():
        parts = line.split("\t")

        if len(parts) < 2:
            continue

        identifier = parts[1]

        inputs.append(
            AudioDevice(
                identifier=identifier,
                name=identifier,
                description=line,
            )
        )

    return outputs, inputs
