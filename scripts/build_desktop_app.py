#!/usr/bin/env python3
"""Build the double-click "Sentinel AI Scan" app for the platform this runs on.

    python scripts/build_desktop_app.py            # -> dist/desktop/

macOS produces `Sentinel AI Scan.app` (zipped); Windows produces
`Sentinel-AI-Scan.exe`. PyInstaller cannot cross-build, so each platform is
built on itself: macOS locally, Windows by `.github/workflows/desktop.yml`.

Only two files go in: `sentinel/sdk/discovery.py` and `discovery_app.py`, both
standard library only. The rest of the package is deliberately NOT importable
during the build, so the app cannot grow a dependency (or a network client) by
accident. After building, the packaged app is run twice: `--self-test` scans an
empty temporary folder with no window, and `--smoke-gui` opens the real window,
ticks the boxes, presses Scan and records what the window shows. A build that
cannot do both is not shipped.

THE RESULT IS UNSIGNED. macOS will say the developer cannot be verified and
Windows SmartScreen will warn. Signing needs the owner's Apple Developer ID and
a Windows code-signing certificate; nothing here can stand in for them.
"""
from __future__ import annotations

import hashlib
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = (ROOT / "sentinel/sdk/discovery.py", ROOT / "sentinel/sdk/discovery_app.py")
OUT = ROOT / "dist" / "desktop"


def main() -> int:
    system = platform.system()
    if system not in {"Darwin", "Windows"}:
        print("the desktop app is built for macOS and Windows only", file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as work:
        stage = Path(work) / "src"
        stage.mkdir()
        for source in SOURCES:
            shutil.copy2(source, stage / source.name)
        name = "Sentinel AI Scan" if system == "Darwin" else "Sentinel-AI-Scan"
        command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed", "--name", name,
                   "--distpath", str(Path(work) / "dist"), "--workpath", str(Path(work) / "build"),
                   "--specpath", work, "--paths", str(stage)]
        # universal2: one app for Apple Silicon and Intel Macs (python.org's Python is itself universal).
        command += (["--osx-bundle-identifier", "ai.sentinel.aiscan", "--target-arch", "universal2"]
                    if system == "Darwin" else ["--onefile"])
        subprocess.run(command + [str(stage / "discovery_app.py")], check=True, cwd=work)

        if system == "Darwin":
            app = Path(work) / "dist" / f"{name}.app"
            binary = app / "Contents" / "MacOS" / name
            artifact = OUT / "Sentinel-AI-Scan-macOS.zip"
        else:
            binary = Path(work) / "dist" / f"{name}.exe"
            artifact = OUT / "Sentinel-AI-Scan-Windows.exe"
        check = subprocess.run([str(binary), "--self-test"], capture_output=True, text=True, timeout=120)
        print((check.stdout or check.stderr).strip())
        if check.returncode != 0:
            print("the packaged app failed its self-test; nothing was written", file=sys.stderr)
            return 1
        # The real window: open it, tick, Scan, record what it shows, close. This is the packaged
        # app doing what a person would do, on the machine that built it.
        smoke_file = OUT / f"gui-smoke-{system.lower()}.json"
        smoke_file.unlink(missing_ok=True)
        gui = subprocess.run([str(binary), f"--smoke-gui={smoke_file}"], timeout=120)
        shown = smoke_file.read_text(encoding="utf-8") if smoke_file.exists() else "{}"
        print("window smoke test:", " ".join(shown.split())[:400])
        if gui.returncode != 0 or '"ok": true' not in shown:
            print("the packaged app's window smoke test failed; nothing was written", file=sys.stderr)
            return 1
        artifact.unlink(missing_ok=True)
        if system == "Darwin":
            # ditto keeps the bundle's symlinks and permissions; a plain zip breaks the app.
            subprocess.run(["ditto", "-c", "-k", "--keepParent", str(app), str(artifact)], check=True)
        else:
            shutil.copy2(binary, artifact)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    # newline="\n": a checksum file written with Windows line endings names a file that does not exist
    # when `shasum -c` reads it elsewhere.
    with open(artifact.parent / (artifact.name + ".sha256"), "w", newline="\n") as stream:
        stream.write(f"{digest}  {artifact.name}\n")
    print(f"built {artifact} ({artifact.stat().st_size // 1024} KiB)\nsha256 {digest}\nUNSIGNED: see the note in this script")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
