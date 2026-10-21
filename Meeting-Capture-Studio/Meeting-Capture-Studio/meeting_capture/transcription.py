"""Optional post-session, local transcription using faster-whisper."""
from __future__ import annotations

from pathlib import Path
from typing import Callable


def transcribe_session(session_dir: Path, report: Callable[[str], None] | None = None) -> list[Path]:
    """Transcribe WAV files in a session folder and write plain-text transcripts locally.

    faster-whisper may download the selected model on first use. Audio files are processed
    locally; this module does not upload audio to a transcription API.
    """
    try:
        from faster_whisper import WhisperModel
    except ImportError as exc:
        raise RuntimeError(
            "Local transcription is optional. Install it with: python -m pip install -r requirements-transcription.txt"
        ) from exc

    wav_files = [p for p in (session_dir / "microphone.wav", session_dir / "system_audio.wav") if p.exists() and p.stat().st_size > 44]
    if not wav_files:
        raise RuntimeError("No recorded WAV files were found in this session.")

    if report:
        report("Loading the local Whisper 'base' model (the first run may download model files).")
    model = WhisperModel("base", device="cpu", compute_type="int8")
    created: list[Path] = []
    for wav in wav_files:
        if report:
            report(f"Transcribing {wav.name} locally…")
        segments, info = model.transcribe(str(wav), vad_filter=True)
        lines: list[str] = [f"Source: {wav.name}", f"Language: {info.language}", "", "Transcript", "----------"]
        for segment in segments:
            lines.append(f"[{segment.start:07.2f}–{segment.end:07.2f}] {segment.text.strip()}")
        target = session_dir / f"transcript_{wav.stem}.txt"
        target.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        created.append(target)
    if report:
        report(f"Saved {len(created)} transcript file(s) in {session_dir}")
    return created
