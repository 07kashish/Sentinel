Sentinel AI Scan for Windows
============================

What it does
  Finds the AI tools installed on this computer by checking whether files,
  folders and commands with known names exist. It never opens a file, never
  runs anything, never reads a key or password, and never sends anything
  anywhere. Nothing leaves this computer unless you share the report yourself.

How to run it
  1. Download Sentinel-AI-Scan-Windows.exe.
  2. Double-click it. Windows SmartScreen will warn, because the app is not yet
     code-signed: click "More info", then "Run anyway".
  3. Tick what you agree to check (nothing is ticked for you), press Scan.
  4. Press "Save report..." and choose a folder. A readable page opens in your
     browser; a .json file is saved beside it.
  5. Send the saved .html page back to whoever asked you to test.

Check the download (optional)
  In PowerShell:  Get-FileHash .\Sentinel-AI-Scan-Windows.exe -Algorithm SHA256
  Compare with the value in Sentinel-AI-Scan-Windows.exe.sha256.

What it cannot see
  AI used in a web browser, cloud-only assistants, renamed or custom installs.
  "Found" means installed, not used.

This is a developer preview. Requires 64-bit Windows 10 or 11. Nothing else
needs to be installed.
