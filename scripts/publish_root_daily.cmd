@echo off
REM ─────────────────────────────────────────────────────────────────────────────
REM  Publish the transparency root once. Intended for a daily scheduled task.
REM
REM  WHY DAILY AND NOT PER EVENT: a later root already proves every earlier one
REM  via a consistency proof, so per-event publication costs ~$16/year instead
REM  of ~$0.002 and buys nothing.
REM
REM  %~dp0 is this script's own directory, so the paths below follow the
REM  repository if it moves. A scheduled task with an absolute path baked in
REM  breaks silently the first time somebody relocates the checkout -- and a
REM  transparency publisher that stopped running is invisible until an auditor
REM  asks why the roots stop.
REM
REM  Credentials and the bucket come from .env, which this script does NOT read
REM  itself -- publish_transparency_root.py loads it, so there is one place
REM  that parses it and one place to look when it is wrong.
REM ─────────────────────────────────────────────────────────────────────────────

setlocal

set "REPO=%~dp0.."
cd /d "%REPO%" || (echo cannot cd to %REPO% & exit /b 1)

set "PYTHONPATH=%REPO%"
REM Which tenants to publish. Required by the script rather than defaulted:
REM enumerating every tenant would publish roots for estates nobody asked
REM about, and each write is irreversible under COMPLIANCE retention.
if "%SENTINEL_PUBLISH_TENANTS%"=="" set "SENTINEL_PUBLISH_TENANTS=acme"

REM Append rather than overwrite. A publisher whose log is truncated on every
REM run cannot answer "when did this last succeed", which is the only question
REM anybody asks it.
if not exist "%REPO%\data" mkdir "%REPO%\data"
echo. >> "%REPO%\data\publish-root.log"
echo ==== %DATE% %TIME% ==== >> "%REPO%\data\publish-root.log"

"C:\Users\pc\AppData\Local\Programs\Python\Python312\python.exe" ^
  "%REPO%\scripts\publish_transparency_root.py" >> "%REPO%\data\publish-root.log" 2>&1

set "CODE=%ERRORLEVEL%"
echo exit=%CODE% >> "%REPO%\data\publish-root.log"

REM The exit code is propagated so Task Scheduler shows a failure rather than
REM a green tick. A scheduled job that always reports success is a job nobody
REM checks.
exit /b %CODE%
