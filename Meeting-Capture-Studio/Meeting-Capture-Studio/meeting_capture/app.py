"""Tkinter desktop interface for Meeting Capture Studio."""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .capture import CaptureConfig, CaptureService
from .devices import AudioDevice, discover_audio_devices
from .transcription import transcribe_session

APP_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = APP_DIR / "sessions"


class MeetingCaptureApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Meeting Capture Studio")
        self.root.geometry("920x760")
        self.root.minsize(780, 650)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.events: queue.Queue = queue.Queue()
        self.service: CaptureService | None = None
        self.last_session: Path | None = self._find_latest_session()
        self._close_after_finalize = False
        self._transcribing = False
        self.microphones: list[AudioDevice] = []
        self.system_outputs: list[AudioDevice] = []
        self._mic_by_label: dict[str, AudioDevice] = {}
        self._system_by_label: dict[str, AudioDevice] = {}

        self.session_name_var = tk.StringVar(value="Team meeting")
        self.output_dir_var = tk.StringVar(value=str(DEFAULT_OUTPUT))
        self.capture_mic_var = tk.BooleanVar(value=True)
        self.capture_system_var = tk.BooleanVar(value=True)
        self.capture_screen_var = tk.BooleanVar(value=True)
        self.interval_var = tk.StringVar(value="30")
        self.consent_var = tk.BooleanVar(value=False)
        self.mic_choice_var = tk.StringVar(value="")
        self.system_choice_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="● NOT RECORDING")
        self.session_var = tk.StringVar(value=f"Last session: {self.last_session}" if self.last_session else "Last session: none yet")

        self._build_ui()
        self._refresh_devices(initial=True)
        self._poll_events()

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=18)
        outer.pack(fill="both", expand=True)

        title = ttk.Label(outer, text="MEETING CAPTURE STUDIO", font=("Segoe UI", 18, "bold"))
        title.pack(anchor="w")
        ttk.Label(outer, text="Capture selected meeting audio and periodic screen snapshots to local files.",
                  font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 12))

        note = ttk.LabelFrame(outer, text="Important — transparent capture", padding=10)
        note.pack(fill="x", pady=(0, 12))
        ttk.Label(note, text=(
            "Use only when you have permission to record the meeting and capture visible screen content. "
            "The app displays a recording status while active and saves files locally; it does not stream or upload recordings. "
            "Screenshots may include private messages, credentials, or other sensitive information."
        ), wraplength=850, justify="left").pack(anchor="w")

        session = ttk.LabelFrame(outer, text="Session", padding=10)
        session.pack(fill="x", pady=(0, 10))
        ttk.Label(session, text="Session name:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(session, textvariable=self.session_name_var, width=35).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Label(session, text="Save under:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(session, textvariable=self.output_dir_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(session, text="Browse…", command=self._choose_output).grid(row=1, column=2, padx=(8, 0), pady=4)
        session.columnconfigure(1, weight=1)

        sources = ttk.LabelFrame(outer, text="What to capture", padding=10)
        sources.pack(fill="x", pady=(0, 10))
        ttk.Checkbutton(sources, text="Microphone audio", variable=self.capture_mic_var,
                        command=self._update_controls).grid(row=0, column=0, sticky="w", padx=(0, 14), pady=4)
        ttk.Label(sources, text="Microphone:").grid(row=0, column=1, sticky="e", padx=6, pady=4)
        self.mic_combo = ttk.Combobox(sources, textvariable=self.mic_choice_var, state="readonly", width=37)
        self.mic_combo.grid(row=0, column=2, sticky="ew", pady=4)

        ttk.Checkbutton(sources, text="System / meeting audio", variable=self.capture_system_var,
                        command=self._update_controls).grid(row=1, column=0, sticky="w", padx=(0, 14), pady=4)
        ttk.Label(sources, text="Output to loop back:").grid(row=1, column=1, sticky="e", padx=6, pady=4)
        self.system_combo = ttk.Combobox(sources, textvariable=self.system_choice_var, state="readonly", width=37)
        self.system_combo.grid(row=1, column=2, sticky="ew", pady=4)

        ttk.Checkbutton(sources, text="Periodic screen snapshots", variable=self.capture_screen_var,
                        command=self._update_controls).grid(row=2, column=0, sticky="w", padx=(0, 14), pady=4)
        ttk.Label(sources, text="Interval (seconds):").grid(row=2, column=1, sticky="e", padx=6, pady=4)
        self.interval_combo = ttk.Combobox(sources, textvariable=self.interval_var, values=("5", "10", "15", "30", "60", "120"), width=10, state="readonly")
        self.interval_combo.grid(row=2, column=2, sticky="w", pady=4)
        ttk.Button(sources, text="Refresh audio devices", command=self._refresh_devices).grid(row=3, column=2, sticky="e", pady=(6, 0))
        sources.columnconfigure(2, weight=1)

        consent_frame = ttk.LabelFrame(outer, text="Permission confirmation", padding=10)
        consent_frame.pack(fill="x", pady=(0, 10))
        ttk.Checkbutton(consent_frame,
                        text="I have informed the relevant participants and have permission to capture the selected audio and screen content.",
                        variable=self.consent_var, command=self._update_controls).pack(anchor="w")

        status_frame = ttk.Frame(outer)
        status_frame.pack(fill="x", pady=(0, 8))
        self.status_label = ttk.Label(status_frame, textvariable=self.status_var, foreground="#177245", font=("Segoe UI", 11, "bold"))
        self.status_label.pack(side="left")
        ttk.Label(status_frame, textvariable=self.session_var, wraplength=570).pack(side="right")

        buttons = ttk.Frame(outer)
        buttons.pack(fill="x", pady=(0, 10))
        self.start_button = ttk.Button(buttons, text="● Start capture", command=self._start_capture)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="■ Stop and save", command=self._stop_capture, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.open_button = ttk.Button(buttons, text="Open last session folder", command=self._open_last_session,
                                      state="normal" if self.last_session else "disabled")
        self.open_button.pack(side="left", padx=(8, 0))
        self.transcribe_button = ttk.Button(buttons, text="Transcribe locally…", command=self._transcribe_last_session,
                                             state="normal" if self.last_session else "disabled")
        self.transcribe_button.pack(side="left", padx=(8, 0))

        log_frame = ttk.LabelFrame(outer, text="Activity log", padding=8)
        log_frame.pack(fill="both", expand=True)
        self.log = tk.Text(log_frame, height=10, wrap="word", state="disabled", font=("Consolas", 9))
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=scrollbar.set)
        self.log.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self._log("Ready. Choose capture sources, confirm permission, then start a session.")
        self._log("Audio files and screenshots are stored under the selected folder; nothing is uploaded by this app.")
        self._update_controls()

    def _refresh_devices(self, initial: bool = False) -> None:
        try:
            microphones, speakers = discover_audio_devices()
        except Exception as exc:
            microphones, speakers = [], []
            self._log(f"Audio device discovery unavailable: {exc}")
        self.microphones = microphones
        self.system_outputs = speakers
        self._mic_by_label = {device.label: device for device in microphones}
        self._system_by_label = {device.label: device for device in speakers}
        mic_values = list(self._mic_by_label)
        system_values = list(self._system_by_label)
        self.mic_combo.configure(values=mic_values)
        self.system_combo.configure(values=system_values)
        if self.mic_choice_var.get() not in mic_values:
            self.mic_choice_var.set(mic_values[0] if mic_values else "")
        if self.system_choice_var.get() not in system_values:
            self.system_choice_var.set(system_values[0] if system_values else "")
        if not microphones and not speakers:
            self._log("No audio devices listed. On this system, check audio permissions and supported loopback capture.")
        elif not initial:
            self._log(f"Audio devices refreshed: {len(microphones)} microphone(s), {len(speakers)} system output(s).")
        self._update_controls()

    def _choose_output(self) -> None:
        chosen = filedialog.askdirectory(title="Choose local folder for meeting sessions",
                                         initialdir=self.output_dir_var.get() if Path(self.output_dir_var.get()).exists() else str(APP_DIR))
        if chosen:
            self.output_dir_var.set(chosen)

    def _update_controls(self) -> None:
        if self.service and self.service.active:
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            return
        self.start_button.configure(state="normal" if self.consent_var.get() else "disabled")
        self.stop_button.configure(state="disabled")
        self.mic_combo.configure(state="readonly" if self.capture_mic_var.get() else "disabled")
        self.system_combo.configure(state="readonly" if self.capture_system_var.get() else "disabled")
        self.interval_combo.configure(state="readonly" if self.capture_screen_var.get() else "disabled")

    def _start_capture(self) -> None:
        if not self.consent_var.get():
            messagebox.showwarning("Permission required", "Please confirm that you have informed participants and have permission to capture the meeting.")
            return
        use_mic = self.capture_mic_var.get()
        use_system = self.capture_system_var.get()
        use_screen = self.capture_screen_var.get()
        if not (use_mic or use_system or use_screen):
            messagebox.showwarning("Choose a source", "Select at least one source to capture.")
            return
        try:
            interval = int(self.interval_var.get())
            output_root = Path(self.output_dir_var.get()).expanduser()
            output_root.mkdir(parents=True, exist_ok=True)
            config = CaptureConfig(
                output_root=output_root,
                session_name=self.session_name_var.get(),
                capture_microphone=use_mic,
                capture_system_audio=use_system,
                capture_screenshots=use_screen,
                screenshot_interval=interval,
                microphone=self._mic_by_label.get(self.mic_choice_var.get()).device if use_mic and self.mic_choice_var.get() in self._mic_by_label else None,
                system_audio=self._system_by_label.get(self.system_choice_var.get()).device if use_system and self.system_choice_var.get() in self._system_by_label else None,
            )
            self.service = CaptureService(self.events)
            path = self.service.start(config)
            self.last_session = path
            self.status_var.set("● RECORDING — LOCAL CAPTURE ACTIVE")
            self.status_label.configure(foreground="#b42318")
            self.session_var.set(f"Current session: {path}")
            self._log(f"Capture started: {path}")
            self._log("The recording status is visible. Select ‘Stop and save’ when finished.")
            self.start_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.open_button.configure(state="normal")
            self.transcribe_button.configure(state="normal")
            for widget in (self.mic_combo, self.system_combo, self.interval_combo):
                widget.configure(state="disabled")
        except Exception as exc:
            messagebox.showerror("Could not start capture", str(exc))
            self._log(f"Could not start capture: {exc}")
            self.service = None
            self._update_controls()

    def _stop_capture(self) -> None:
        if self.service and self.service.active:
            self.stop_button.configure(state="disabled")
            self.status_var.set("● STOPPING — SAVING SESSION")
            self.status_label.configure(foreground="#9a6700")
            self._log("Stop requested; closing audio files and writing session metadata…")
            self.service.stop()

    def _poll_events(self) -> None:
        try:
            while True:
                kind, message = self.events.get_nowait()
                if kind == "complete":
                    self.last_session = Path(message)
                    self.session_var.set(f"Last session: {self.last_session}")
                    self.status_var.set("● NOT RECORDING")
                    self.status_label.configure(foreground="#177245")
                    self._log(f"Session saved: {message}")
                    self.open_button.configure(state="normal")
                    self.transcribe_button.configure(state="normal")
                    self.service = None
                    self._update_controls()
                    if self._close_after_finalize:
                        self.root.destroy()
                        return
                elif kind == "started":
                    self._log(f"Session folder created: {message}")
                elif kind == "source_started":
                    self._log(f"Audio capture active: {message}")
                elif kind == "source_saved":
                    self._log(f"Saved {message}")
                elif kind == "screenshot":
                    self._log(f"Saved screenshot: {message}")
                elif kind == "warning":
                    self._log(f"WARNING: {message}")
                elif kind == "transcribe_done":
                    self._transcribing = False
                    self.transcribe_button.configure(state="normal")
                    self._log(f"Transcription complete:\n{message}")
                    messagebox.showinfo("Transcription complete", f"Transcript file(s) saved:\n{message}")
                elif kind == "transcribe_error":
                    self._transcribing = False
                    self.transcribe_button.configure(state="normal")
                    self._log(f"Transcription failed: {message}")
                    messagebox.showerror("Transcription failed", message)
                elif kind == "log":
                    self._log(message)
                else:
                    self._log(str(message))
        except queue.Empty:
            pass
        self.root.after(200, self._poll_events)

    def _open_last_session(self) -> None:
        path = self.last_session
        if not path or not path.exists():
            messagebox.showinfo("No session", "No saved session folder is available yet.")
            return
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("Could not open folder", f"Folder path:\n{path}\n\n{exc}")

    def _transcribe_last_session(self) -> None:
        if self._transcribing:
            return
        path = self.last_session
        if not path or not path.exists():
            messagebox.showinfo("No session", "Record and save a session first.")
            return
        if self.service and self.service.active:
            messagebox.showinfo("Session still running", "Stop and save the session before transcribing it.")
            return
        okay = messagebox.askyesno(
            "Optional local transcription",
            "Transcription processes the saved WAV files on this computer. The first use may download the Whisper model files; the recorded audio itself is not uploaded by this app. Continue?",
        )
        if not okay:
            return
        self._transcribing = True
        self.transcribe_button.configure(state="disabled")
        self._log("Starting optional local transcription…")

        def report(message: str) -> None:
            self.events.put(("log", message))

        def worker() -> None:
            try:
                created = transcribe_session(path, report)
                self.events.put(("transcribe_done", "\n".join(str(p) for p in created)))
            except Exception as exc:
                self.events.put(("transcribe_error", str(exc)))

        threading.Thread(target=worker, name="LocalTranscription", daemon=True).start()

    def _log(self, message: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", message.rstrip() + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _find_latest_session(self) -> Path | None:
        try:
            candidates = [p for p in DEFAULT_OUTPUT.iterdir() if p.is_dir() and (p / "session.json").exists()]
            return max(candidates, key=lambda p: p.stat().st_mtime) if candidates else None
        except OSError:
            return None

    def _on_close(self) -> None:
        if self.service and self.service.active:
            if not messagebox.askyesno("Capture is running", "Stop and save the current session before exiting?"):
                return
            self._close_after_finalize = True
            self._stop_capture()
            return
        if self._transcribing:
            if not messagebox.askyesno("Transcription is running", "Close the window while local transcription continues? The task may stop when the app exits."):
                return
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    try:
        # Use native theme where available.
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass
    MeetingCaptureApp(root)
    root.mainloop()

