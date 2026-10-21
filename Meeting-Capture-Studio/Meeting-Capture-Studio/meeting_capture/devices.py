"""Audio device discovery wrappers for SoundCard."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AudioDevice:
    label: str
    device_id: str
    device: Any

    def __str__(self) -> str:
        return self.label


def discover_audio_devices() -> tuple[list[AudioDevice], list[AudioDevice]]:
    """Return (microphones, system-audio loopbacks); raises useful errors if unavailable."""
    try:
        import soundcard as sc
    except ImportError as exc:
        raise RuntimeError(
            "Audio capture needs SoundCard. Install dependencies with: python -m pip install -r requirements.txt"
        ) from exc

    microphones: list[AudioDevice] = []
    speakers: list[AudioDevice] = []
    try:
        for mic in sc.all_microphones(include_loopback=False):
            name = str(getattr(mic, "name", "Microphone"))
            device_id = str(getattr(mic, "id", name))
            microphones.append(AudioDevice(name, device_id, mic))
    except Exception:
        # Continue so users can still access whichever source the backend exposes.
        pass

    try:
        for speaker in sc.all_speakers():
            name = str(getattr(speaker, "name", "System output"))
            device_id = str(getattr(speaker, "id", name))
            try:
                loopback = sc.get_microphone(id=device_id, include_loopback=True)
                speakers.append(AudioDevice(f"{name} (system audio)", device_id, loopback))
            except Exception:
                # Some backends require the speaker name rather than its ID.
                try:
                    loopback = sc.get_microphone(id=name, include_loopback=True)
                    speakers.append(AudioDevice(f"{name} (system audio)", device_id, loopback))
                except Exception:
                    continue
    except Exception:
        pass

    return microphones, speakers
