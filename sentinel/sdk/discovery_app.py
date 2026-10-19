"""Sentinel AI Scan: the consent-based presence scanner behind a window.

The same checks as `sentinel-discover`, for someone who will not open a
terminal. Standard library only (tkinter). Nothing is scanned until the person
ticks at least one category and presses Scan; nothing is sent anywhere, ever --
this module imports no networking code. The report is saved where the person
chooses, as the JSON the console imports and a readable HTML copy.

`--self-test` runs the whole path without a window, against an EMPTY temporary
home, so a packaged build can be proven to start and scan without touching the
machine that built it.
"""
from __future__ import annotations

import json
import os
import platform
import sys
import tempfile
import webbrowser
from pathlib import Path
from uuid import uuid4

try:  # packaged builds carry the module beside this one
    from sentinel.sdk import discovery
except ImportError:  # pragma: no cover - the frozen layout
    import discovery  # type: ignore[no-redef]

APP_NAME = "Sentinel AI Scan"
INTRO = (
    "This finds the AI tools installed on this computer by checking whether files, "
    "applications and commands with known names exist.\n\n"
    "It never opens a file, never runs anything, never reads a key or a password, and "
    "never sends anything anywhere. Nothing leaves this computer unless you share the "
    "report yourself."
)
CATEGORIES = (
    ("config_presence", "AI settings files and folders in my home folder"),
    ("app_presence", "AI applications installed on this computer"),
    ("cli_presence", "AI command-line tools in the usual command folders"),
)
LIMITS = (
    "Not detected: AI used in a web browser, cloud-only assistants, renamed or custom installs. "
    "Found means installed, not used."
)


def run_scan(consent: dict[str, bool], *, home: Path | None = None, system: str | None = None) -> dict:
    """The scan the Scan button performs. Raises ValueError when nothing was approved."""
    if not any(consent.values()):
        raise ValueError("Choose at least one thing to check.")
    report = discovery.discover(
        home=home or Path.home(), system=system or platform.system(), device_id=str(uuid4()),
        config_presence=bool(consent.get("config_presence")), app_presence=bool(consent.get("app_presence")),
        cli_presence=bool(consent.get("cli_presence")))
    return discovery.validate_report(report)


def result_lines(report: dict) -> list[str]:
    """What the window shows after a scan: one line per tool found, or one saying none."""
    found = discovery.summarise(report)
    if not found:
        return ["None of the known AI tools was found by the checks you approved."]
    return [f"{label}  —  {len(probes)} sign{'s' if len(probes) != 1 else ''} found" for label, probes in found]


def save_report(report: dict, folder: Path) -> tuple[Path, Path]:
    """Write the JSON and the HTML side by side under a new name; never overwrite."""
    folder.mkdir(parents=True, exist_ok=True)
    stem = f"sentinel-ai-scan-{report['scanned_at'][:19].replace(':', '').replace('-', '')}-{report['device_id'][:8]}"
    data, page = folder / f"{stem}.json", folder / f"{stem}.html"
    for path, content in ((data, json.dumps(report, indent=2) + "\n"), (page, discovery.render_html(report))):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
    return data, page


def self_test() -> int:
    with tempfile.TemporaryDirectory() as empty:
        report = run_scan({name: True for name, _ in CATEGORIES}, home=Path(empty))
        data, page = save_report(report, Path(empty) / "out")
        ok = data.exists() and page.read_text(encoding="utf-8").startswith("<!doctype html>") and result_lines(report)
    sys.stdout.write(f"{APP_NAME} self-test: {'ok' if ok else 'FAILED'} ({len(report['observations'])} checks)\n")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    arguments = list(argv if argv is not None else sys.argv[1:])
    if "--self-test" in arguments:
        return self_test()
    # `--smoke-gui=<file>`: open the REAL window, tick every box and press Scan the way a person
    # would, write what the window then shows to <file>, and close. A windowed build has no
    # console, so the file and the exit code are the only way to see the outcome.
    smoke = next((a.split("=", 1)[1] for a in arguments if a.startswith("--smoke-gui=")), "")
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title(APP_NAME)
    root.geometry("640x620")
    root.minsize(560, 560)
    frame = ttk.Frame(root, padding=20)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="Find the AI tools on this computer", font=("", 18, "bold")).pack(anchor="w")
    ttk.Label(frame, text=INTRO, wraplength=590, justify="left").pack(anchor="w", pady=(10, 14))
    ttk.Label(frame, text="I agree to check for:", font=("", 13, "bold")).pack(anchor="w")
    choices = {}
    for name, label in CATEGORIES:
        choices[name] = tk.BooleanVar(value=False)  # consent is never pre-ticked
        ttk.Checkbutton(frame, text=label, variable=choices[name]).pack(anchor="w", pady=2)
    buttons = ttk.Frame(frame)
    buttons.pack(anchor="w", pady=(14, 8))
    results = tk.Text(frame, height=12, wrap="word", state="disabled", relief="flat", background=root.cget("background"))
    state: dict = {"report": None}

    def show(lines: list[str]) -> None:
        results.configure(state="normal")
        results.delete("1.0", "end")
        results.insert("1.0", "\n".join(lines))
        results.configure(state="disabled")

    def scan() -> None:
        try:
            state["report"] = run_scan({name: var.get() for name, var in choices.items()})
        except ValueError as exc:
            messagebox.showinfo(APP_NAME, str(exc))
            return
        except OSError:
            messagebox.showerror(APP_NAME, "The scan could not be completed on this computer.")
            return
        show(["Found on this computer:", ""] + ["  " + line for line in result_lines(state["report"])] + ["", LIMITS])
        save_button.state(["!disabled"])

    def save() -> None:
        if state["report"] is None:
            return
        chosen = filedialog.askdirectory(title="Where should the report be saved?", initialdir=str(Path.home() / "Documents"))
        if not chosen:
            return
        try:
            data, page = save_report(state["report"], Path(chosen))
        except OSError:
            messagebox.showerror(APP_NAME, "The report could not be saved there. Choose another folder.")
            return
        webbrowser.open(page.as_uri())
        messagebox.showinfo(APP_NAME, f"Saved:\n{page.name}\n{data.name}\n\nThe .json file is the one a Sentinel console imports.")

    ttk.Button(buttons, text="Scan", command=scan).pack(side="left")
    save_button = ttk.Button(buttons, text="Save report…", command=save)
    save_button.pack(side="left", padx=10)
    save_button.state(["disabled"])
    results.pack(fill="both", expand=True, pady=(6, 0))
    show(["Tick what you agree to check, then press Scan.", "", "The complete list of checked names is in the saved report."])
    outcome = {"code": 0}
    if smoke:
        def press() -> None:
            try:
                unticked = not any(var.get() for var in choices.values())
                for var in choices.values():
                    var.set(True)
                scan()
                shown = results.get("1.0", "end").strip()
                ok = unticked and state["report"] is not None and shown.startswith("Found on this computer:")
                Path(smoke).write_text(json.dumps({
                    "ok": ok, "title": root.title(), "boxes_started_unticked": unticked,
                    "platform": state["report"]["platform"] if state["report"] else None,
                    "checks": len(state["report"]["observations"]) if state["report"] else 0,
                    "states": sorted({o["state"] for o in state["report"]["observations"]}) if state["report"] else [],
                    "window_text": shown[:600]}, indent=2), encoding="utf-8")
                outcome["code"] = 0 if ok else 1
            except Exception as exc:  # noqa: BLE001 - a smoke test reports, it does not raise into Tk
                Path(smoke).write_text(json.dumps({"ok": False, "error": type(exc).__name__}), encoding="utf-8")
                outcome["code"] = 1
            root.after(800, root.destroy)
        root.after(800, press)
    root.mainloop()
    return outcome["code"]


if __name__ == "__main__":
    raise SystemExit(main())
