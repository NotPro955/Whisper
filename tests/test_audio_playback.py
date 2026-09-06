import wave

from fastpair_mic.audio.playback import generate_demo_wave


def test_generate_demo_wave_creates_wav(tmp_path):
    output_path = tmp_path / "demo.wav"

    generate_demo_wave(output_path)

    assert output_path.exists()

    with wave.open(str(output_path), "rb") as wav_file:
        assert wav_file.getnchannels() == 1
        assert wav_file.getframerate() == 48000
        assert wav_file.getsampwidth() == 2
