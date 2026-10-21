# Meeting Capture Studio

A small, local-first desktop app for **user-started, transparent meeting capture**. Select which sources to capture, confirm that you have permission, start a session, and use the visible recording indicator to stop and save it.

> **Consent and privacy:** Use this only when you are allowed to record the meeting and capture screen content. Inform the people involved and follow your workplace, school, and local rules. The app is not designed for covert recording: it has a visible interface and requires an explicit permission confirmation before every session. Screenshots can expose private messages, credentials, or other sensitive content, so check the screen before starting.

## What it does

- **Microphone audio:** records the selected microphone to `microphone.wav`.
- **System / meeting audio:** records audio played through the selected output loopback device to `system_audio.wav`. This is useful for remote participants' voices if your OS and audio device support loopback capture.
- **Periodic screenshots:** takes an image of the primary monitor immediately and then at the chosen interval. It captures still images, not continuous video, and does not perform OCR.
- **Session metadata:** saves `session.json` with start/end times, selected sources, screenshots, output files, and capture warnings.
- **Optional local transcription:** after the session, an optional Whisper-based tool can transcribe saved WAV files and write text transcripts. Audio is processed on your computer by the app; `faster-whisper` may download model files the first time it runs. The audio itself is not sent to a hosted transcription API by this project.

Audio sources are saved separately so microphone and computer output can be reviewed independently. Nothing is automatically uploaded, streamed, or shared by this application.

## What it does not do

- It does not automatically join meetings, bypass meeting-platform recording controls, hide itself, or run as a stealth/background surveillance service.
- It does not currently provide live captions, speaker diarization, AI meeting summaries, action-item extraction, webcam recording, or continuous screen video.
- It does not decide whether a meeting can legally be recorded. You are responsible for permission, notice, and secure handling of the output files.
- Audio loopback availability depends on operating system, audio backend, output device, and permissions.

## Requirements

- Python 3.10 or newer is recommended.
- Windows is the primary target. macOS and Linux may work, but system-audio loopback and screen-capture support vary by audio backend and desktop security settings.
- A display session is required for the GUI and screenshots.

## Setup

### Windows

1. Extract this project to a folder.
2. Open PowerShell or Command Prompt in that folder.
3. Install dependencies:

   ```powershell
   py -m pip install -r requirements.txt
   ```

4. Launch the application:

   ```powershell
   py main.py
   ```

You can also double-click `start_windows.bat`. It installs the core dependencies and launches the app.

### macOS / Linux

Install a Python 3 environment and the system audio libraries required by your distribution, then run:

```bash
python3 -m pip install -r requirements.txt
python3 main.py
```

The `start_unix.sh` script runs those commands. On macOS, allow microphone and screen-recording access when prompted. On Linux, capture support depends on X11/Wayland, PipeWire/PulseAudio, and desktop permissions.

### Optional transcription

After a session has been stopped and saved, click **Transcribe locally…** in the app. To install transcription support manually:

```bash
python -m pip install -r requirements-transcription.txt
```

The first transcription may download the `base` Whisper model, depending on whether it is already cached. The model is run on CPU with an integer-quantized configuration, which reduces resource use but can take time. You can use the app without installing this optional package.

## Using the app

1. Start `main.py`.
2. Give the session a name and select the local folder where sessions should be stored.
3. Select the capture sources:
   - **Microphone audio** for your local microphone.
   - **System / meeting audio** for sound played through an available loopback output.
   - **Periodic screen snapshots** for images of the primary display; choose an interval of at least 5 seconds.
4. Use **Refresh audio devices** if the desired device is missing. Choose the output device that the meeting audio actually plays through.
5. Confirm that you have informed the relevant participants and have permission to capture the selected sources.
6. Click **Start capture**. The visible status changes to `RECORDING — LOCAL CAPTURE ACTIVE`.
7. Click **Stop and save** when the meeting capture is finished. Wait for the app to report that the session was saved.
8. Click **Open last session folder** to view the files. Optional: click **Transcribe locally…** to create a transcript from the WAV files.

## Output layout

Each session gets a timestamped folder underneath the selected output directory:

```text
sessions/
└── 20261021_093000_team-meeting/
    ├── session.json
    ├── microphone.wav          # only if microphone capture was selected and produced audio
    ├── system_audio.wav        # only if system-audio capture was selected and produced audio
    ├── screenshots/            # only if screenshots were selected
    │   ├── screen_0001_....png
    │   └── screen_0002_....png
    ├── transcript_microphone.txt   # optional
    └── transcript_system_audio.txt # optional
```

`session.json` records source settings, times, session duration, generated screenshot names, saved audio files, and capture errors/warnings. The app stores absolute session paths in the activity log, so treat logs and metadata as potentially sensitive too.

## Audio and screenshot behavior

- Audio is saved as WAV at 44.1 kHz. Actual channel count depends on the selected audio device.
- Microphone and system audio are separate tracks. They are not automatically mixed or synchronized into a single video.
- The screenshot option captures the **primary monitor** and stores full-resolution PNG stills. Each screenshot can contain any window or notification visible on that display. Close private pages and disable notifications before capture when appropriate.
- Screenshot capture starts with one image immediately, then waits the configured number of seconds between images.
- Audio device failures are shown in the activity log and recorded in `session.json` where possible. Confirm that the expected WAV file exists and has a non-trivial size before relying on it.

## Troubleshooting

### No microphone appears

- Click **Refresh audio devices**.
- Check the operating system's microphone privacy permissions and make sure another application is not exclusively locking the device.
- Close and reopen the app after changing device or permission settings.

### System audio is silent or not available

- Choose the actual output device that plays the meeting sound, not necessarily the default speakers.
- Confirm that the system volume is not muted and that the meeting app is routed to that output.
- Loopback capture differs by driver and operating system. Bluetooth headsets, virtual devices, remote desktops, and certain privacy-restricted environments may not expose usable loopback audio.
- On Windows, try the output device used by the meeting app and check whether your audio driver supports loopback. On Linux, ensure PipeWire/PulseAudio loopback capture is available.

### Screenshots fail or are blank

- Confirm desktop screenshot permissions and that you are in an interactive desktop session, not a headless shell.
- On macOS, allow screen-recording permission and restart the application.
- On some Linux Wayland sessions, desktop policy can block direct screenshots.

### A WAV file is missing or nearly empty

- Check the activity log and the session's `session.json` for warnings.
- Confirm the source was selected, the correct device was selected, and the operating system granted access.
- Capture a 5–10 second test and play back the file before an important meeting.

### Tkinter is missing

Some minimal Linux Python installs package Tk separately (often named `python3-tk`). Install the Tk package using your distribution's package manager, then retry.

## Development and tests

Core GUI dependencies and capture dependencies are listed in `requirements.txt`. The GUI uses Python's built-in Tkinter. Optional transcription dependencies are separate so users are not required to download a speech-recognition model just to record a session.

Run the basic helper tests with:

```bash
python -m unittest discover -s tests -v
```

Check source syntax with:

```bash
python -m compileall -q main.py meeting_capture tests
```

## Security checklist before every session

- Tell participants that audio and/or screen content will be recorded and obtain the required permission.
- Verify which sources are selected and where files will be saved.
- Close password managers, private chats, sensitive customer records, and unrelated confidential pages before enabling screenshots.
- Turn off screenshots if the screen is not needed.
- After the meeting, review the captures, remove unnecessary sensitive material, and store/share session folders only with authorized people.
- Stop the session explicitly and confirm the app reports that it saved the session.

## Project structure

```text
Meeting-Capture-Studio/
├── main.py
├── requirements.txt
├── requirements-transcription.txt
├── start_windows.bat
├── start_unix.sh
├── meeting_capture/
│   ├── app.py             # Tkinter GUI and visible permission workflow
│   ├── capture.py         # WAV capture, screenshots, session metadata
│   ├── devices.py         # Audio-device discovery
│   └── transcription.py   # Optional post-session local transcription
├── tests/
│   └── test_capture_helpers.py
└── sessions/              # Local captures (ignored by git)
```

## Responsible use

This is a local capture utility for meetings where recording is permitted. It is not intended to record people without their knowledge, bypass platform controls, or monitor a device covertly. Secure the files: audio, screenshots, and transcripts may contain confidential or personal information.
