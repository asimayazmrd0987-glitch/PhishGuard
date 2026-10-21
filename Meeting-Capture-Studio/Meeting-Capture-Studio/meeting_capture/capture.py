"""Threaded local audio and screenshot capture."""
from __future__ import annotations

import json
import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SAMPLE_RATE = 44_100
CHUNK_SECONDS = 0.5


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def slugify(value: str) -> str:
    cleaned = "".join(c.lower() if c.isalnum() else "-" for c in value.strip())
    parts = [part for part in cleaned.split("-") if part]
    return "-".join(parts)[:48] or "meeting"


@dataclass
class CaptureConfig:
    output_root: Path
    session_name: str
    capture_microphone: bool
    capture_system_audio: bool
    capture_screenshots: bool
    screenshot_interval: int
    microphone: Any | None = None
    system_audio: Any | None = None


class CaptureService:
    """Captures selected sources into an obvious, user-initiated local session."""

    def __init__(self, events: queue.Queue | None = None) -> None:
        self.events = events or queue.Queue()
        self.stop_event = threading.Event()
        self.workers: list[threading.Thread] = []
        self.session_dir: Path | None = None
        self.started_monotonic = 0.0
        self.started_at = ""
        self.config: CaptureConfig | None = None
        self._metadata_lock = threading.Lock()
        self._screenshots: list[dict[str, str]] = []
        self._errors: list[str] = []
        self._active = False

    @property
    def active(self) -> bool:
        return self._active

    def start(self, config: CaptureConfig) -> Path:
        if self._active:
            raise RuntimeError("A capture session is already running.")
        if not (config.capture_microphone or config.capture_system_audio or config.capture_screenshots):
            raise ValueError("Choose at least one source to capture.")
        if config.capture_microphone and config.microphone is None:
            raise ValueError("Select an available microphone.")
        if config.capture_system_audio and config.system_audio is None:
            raise ValueError("Select an available system-audio output.")
        if config.capture_screenshots and config.screenshot_interval < 5:
            raise ValueError("Screenshot interval must be at least 5 seconds.")

        if config.capture_screenshots:
            import mss  # noqa: F401 - verify screenshot support when selected
        if config.capture_microphone or config.capture_system_audio:
            import soundcard  # noqa: F401 - verify audio support when selected
            import soundfile  # noqa: F401

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        folder_name = f"{stamp}_{slugify(config.session_name)}"
        session_dir = config.output_root.expanduser().resolve() / folder_name
        session_dir.mkdir(parents=True, exist_ok=False)
        if config.capture_screenshots:
            (session_dir / "screenshots").mkdir()

        self.config = config
        self.session_dir = session_dir
        self.started_at = utc_now_iso()
        self.started_monotonic = time.monotonic()
        self.stop_event = threading.Event()
        self.workers = []
        self._screenshots = []
        self._errors = []
        self._active = True

        metadata = {
            "app": "Meeting Capture Studio",
            "version": "1.0.0",
            "session_name": config.session_name.strip() or "Meeting",
            "started_at": self.started_at,
            "finished_at": None,
            "duration_seconds": None,
            "consent_confirmation_required_by_ui": True,
            "capture_settings": {
                "microphone": config.capture_microphone,
                "system_audio": config.capture_system_audio,
                "screenshots": config.capture_screenshots,
                "screenshot_interval_seconds": config.screenshot_interval if config.capture_screenshots else None,
                "sample_rate_hz": SAMPLE_RATE,
            },
            "files": {},
            "screenshots": [],
            "errors": [],
            "storage": "local_only",
        }
        self._write_metadata(metadata)

        if config.capture_microphone:
            self._spawn_audio_worker("microphone", config.microphone)
        if config.capture_system_audio:
            self._spawn_audio_worker("system_audio", config.system_audio)
        if config.capture_screenshots:
            worker = threading.Thread(target=self._screenshot_loop, name="ScreenshotCapture", daemon=True)
            worker.start()
            self.workers.append(worker)
        self.events.put(("started", str(session_dir)))
        return session_dir

    def _spawn_audio_worker(self, key: str, source: Any) -> None:
        assert self.session_dir is not None
        path = self.session_dir / f"{key}.wav"
        worker = threading.Thread(target=self._audio_loop, args=(key, source, path), name=f"Capture-{key}", daemon=True)
        worker.start()
        self.workers.append(worker)

    def _audio_loop(self, key: str, source: Any, path: Path) -> None:
        try:
            import numpy as np
            import soundfile as sf

            writer = None
            frames_written = 0
            try:
                with source.recorder(samplerate=SAMPLE_RATE) as recorder:
                    while not self.stop_event.is_set():
                        data = recorder.record(numframes=int(SAMPLE_RATE * CHUNK_SECONDS))
                        if data is None or getattr(data, "size", 0) == 0:
                            continue
                        data = np.asarray(data, dtype=np.float32)
                        if data.ndim == 1:
                            data = data.reshape(-1, 1)
                        if writer is None:
                            writer = sf.SoundFile(path, mode="w", samplerate=SAMPLE_RATE,
                                                  channels=int(data.shape[1]), subtype="PCM_16")
                            self.events.put(("source_started", key))
                        writer.write(data)
                        frames_written += int(data.shape[0])
            finally:
                if writer is not None:
                    writer.close()
            if frames_written == 0:
                message = f"No audio frames were captured for {key}; check the selected device and permissions."
                self._record_error(message)
                self.events.put(("warning", message))
            else:
                self.events.put(("source_saved", f"{key}: {frames_written / SAMPLE_RATE:.1f} seconds"))
        except Exception as exc:
            message = f"{key} capture failed: {exc}"
            self._record_error(message)
            self.events.put(("warning", message))

    def _screenshot_loop(self) -> None:
        try:
            import mss
            from mss import tools

            assert self.session_dir is not None
            with mss.mss() as capture:
                monitors = capture.monitors
                if len(monitors) <= 1:
                    raise RuntimeError("No display monitor was detected.")
                monitor = monitors[1]  # primary monitor
                index = 0
                while not self.stop_event.is_set():
                    index += 1
                    now = datetime.now().astimezone()
                    filename = f"screen_{index:04d}_{now.strftime('%Y%m%d_%H%M%S')}.png"
                    path = self.session_dir / "screenshots" / filename
                    shot = capture.grab(monitor)
                    tools.to_png(shot.rgb, shot.size, output=str(path))
                    with self._metadata_lock:
                        self._screenshots.append({"file": f"screenshots/{filename}", "captured_at": now.isoformat(timespec="seconds")})
                    self.events.put(("screenshot", filename))
                    if self.stop_event.wait(self.config.screenshot_interval if self.config else 30):
                        break
        except Exception as exc:
            message = f"Screenshot capture failed: {exc}"
            self._record_error(message)
            self.events.put(("warning", message))

    def _record_error(self, message: str) -> None:
        with self._metadata_lock:
            self._errors.append(message)

    def stop(self) -> None:
        if not self._active:
            return
        self.stop_event.set()
        threading.Thread(target=self._finish_in_background, name="SessionFinalizer", daemon=True).start()

    def _finish_in_background(self) -> None:
        for worker in self.workers:
            worker.join(timeout=10)
        finished_at = utc_now_iso()
        duration = round(max(0.0, time.monotonic() - self.started_monotonic), 2)
        assert self.session_dir is not None
        files: dict[str, str] = {}
        for name in ("microphone.wav", "system_audio.wav"):
            path = self.session_dir / name
            if path.exists() and path.stat().st_size > 44:
                files[name] = f"{path.stat().st_size} bytes"
        try:
            metadata = json.loads((self.session_dir / "session.json").read_text(encoding="utf-8"))
        except Exception:
            metadata = {}
        metadata.update({
            "finished_at": finished_at,
            "duration_seconds": duration,
            "files": files,
            "screenshots": self._screenshots,
            "errors": self._errors,
        })
        self._write_metadata(metadata)
        self._active = False
        self.events.put(("complete", str(self.session_dir)))

    def _write_metadata(self, metadata: dict[str, Any]) -> None:
        assert self.session_dir is not None
        destination = self.session_dir / "session.json"
        temp = destination.with_suffix(".json.tmp")
        temp.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
        temp.replace(destination)
