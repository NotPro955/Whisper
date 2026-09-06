import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from fastpair_mic.speech.transcriber import transcribe_audio


def test_transcribe_audio_uses_python_api(monkeypatch, tmp_path):
    audio_path = tmp_path / "sample.wav"
    audio_path.write_bytes(b"fake wav data")

    fake_model = SimpleNamespace(
        transcribe=lambda *args, **kwargs: {"text": "hello from whisper"}
    )
    fake_whisper = SimpleNamespace(load_model=lambda _model: fake_model)

    monkeypatch.setitem(sys.modules, "whisper", fake_whisper)

    assert transcribe_audio(audio_path) == "hello from whisper"


def test_transcribe_audio_uses_cli_when_python_api_unavailable(monkeypatch, tmp_path):
    audio_path = tmp_path / "sample.wav"
    audio_path.write_bytes(b"fake wav data")
    text_path = tmp_path / "sample.txt"
    text_path.write_text("cli transcript")

    monkeypatch.setattr(
        "fastpair_mic.speech.transcriber._load_whisper_module",
        lambda: None,
    )
    monkeypatch.setattr(
        "fastpair_mic.speech.transcriber.shutil.which",
        lambda _: "/usr/bin/whisper",
    )

    def fake_run(command, **kwargs):
        assert command[0] == "/usr/bin/whisper"
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert transcribe_audio(audio_path) == "cli transcript"
