# Try Sentinel — a tester's guide

For someone who has never seen the product and wants to know, in an hour, what it does. Four things you can do, from least to most effort. Every command here was run on 2026-10-03 at the commit that added this file.

**What Sentinel is.** A control point for AI agents: before an agent's tool call changes something, Sentinel decides *allow / needs a human / block* by deterministic policy, records who approved what, and refuses replays. It also keeps an inventory of the agents and AI tools it is told about. It is a developer preview (see `RELEASE_STATUS.md`); nothing here is a production claim.

**What it is not.** It does not watch your screen, read your files, or intercept network traffic. It governs the calls an agent *sends through it*, and it lists the AI tools you *choose to report*.

---

## 1. Look at the live demo (2 minutes, nothing to install)

Open the shared console. It signs you in with a published **read-only** key; you cannot change anything.

```
http://sentinel-proof-557842222.ap-south-1.elb.amazonaws.com/console
```

What to look at: **Agent requests** (two waiting for a human), **Approved vs executed** (what ran against what was approved; one replay refused), **Execution graph** (three detected chains), **Containment** (one agent paused, with a reason and expiry), **Overview → open incident** (the report, with the advisory note), **Pilot setup** (a real device's AI inventory). The data is a seeded sample tenant. The address is plain HTTP, so the console refuses operator sign-in there by design; that is why step 3 runs on your own machine.

## 2. Find the AI tools from a terminal

The scanner is one Python file with no dependencies. Download it from the console (**Pilot setup → Download discovery script**) or use `sentinel/sdk/discovery.py` from a checkout. Requires Python 3.9+ (`python3 --version`).

```bash
python3 sentinel-discover.py --explain
```

That prints the complete list of what would be checked. Then, if you agree:

```bash
python3 sentinel-discover.py --consent --all --output my-device.json --html my-device.html
```

Open `my-device.html` in a browser. Windows: use `py` instead of `python3`; applications are looked for as per-user install folders under your home and commands in the usual per-user command folders (tested with a synthetic home, not on a real Windows machine).

**What it checks, and only this:** whether a file, folder, application or command *with a known name* exists — for Gemini CLI, Antigravity, Claude, Cursor, Codex, Continue, GitHub Copilot, Windsurf, Zed, Aider, Goose, OpenCode, ChatGPT, Perplexity, Ollama, LM Studio, Jan and GPT4All. Three categories, each needing your consent: configuration (`--config-presence`), applications (`--app-presence`, macOS), commands (`--cli-presence`, macOS and Linux).

**What it never does:** open a file, follow a link, run a command, read a key, record a path, a host name or a user name, or send anything anywhere. The report holds a random device ID, a timestamp, the OS family, what you consented to, and `present / not_found / inaccessible / unsupported / not_consented` per check.

**What it cannot see:** AI used in a browser, cloud-only assistants, renamed or custom installs, anything inside a container or VM. *Present* means installed, not used, and says nothing about whether the tool is governed. `tests_arch/test_pilot_onboarding.py` holds the checks that the scanner opens no content, follows no link and runs nothing.

## 3. Run your own Sentinel and see your device in the dashboard (10 minutes)

Needs a checkout and Python 3.12+. The commands below are for macOS and Linux; on **Windows** (PowerShell) use `py -m venv .venv`, then `.venv\Scripts\pip install -e ".[server]"`, then `.venv\Scripts\python scripts\try_sentinel.py --scan --demo`.

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -e ".[server]"
```

```bash
.venv/bin/python scripts/try_sentinel.py --scan --demo
```

The last command creates `.sentinel-trial/` with a SQLite database and four fresh keys, migrates, scans this device (the same consented checks as step 2), imports the report, loads a sample story to click through (`--demo`), and serves the console. It prints the address and the **admin key**. Open `http://127.0.0.1:8000/console`, paste the admin key as the *operator token* (that is all "operator token" means: an API key with a role), and open **Pilot setup** to see your device. `Ctrl-C` stops it; delete `.sentinel-trial/` to remove every trace.

Without `--scan` it only starts the service; you can then import a report by hand under **Pilot setup** (preview → tick consent → import).

## 4. Put one agent action behind it (15 minutes)

With step 3 running, take the `ingest` and `analyst` keys from `.sentinel-trial/keys.env`. Ask Sentinel whether an agent may make a change:

```bash
curl -s http://127.0.0.1:8000/v1/protect/evaluate -H "Authorization: Bearer $INGEST" -H "X-Sentinel-Agent-Id: agent:demo" -H "Content-Type: application/json" -d '{"agentId":"agent:demo","tool":"echo","action":"update","resource":"/protected-change/prod/config/rate-limit","arguments":{"rps":450}}'
```

The answer carries the decision and, when a human is required, an authorization to approve in the console under **Agent requests** (sign in with the analyst key). An approved authorization executes once through `POST /v1/tools/execute`; the second attempt is refused. `scripts/seed_console_demo.py` does this whole journey against any deployment and is the shortest complete example. For real agents: `FIRST_WORKFLOW.md`.

## 5. Optional: the advisory brain

Sentinel's decisions are deterministic. A model can be attached as an **advisor**: it writes a note for the analyst on each incident and approval, labelled `[unverified-model-output]`, and it cannot change a priority or a decision. If you have the Antigravity CLI installed and signed in:

```bash
.venv/bin/python scripts/try_sentinel.py --scan --advisor-cli ~/.local/bin/agy --advisor-model gemini-3.1-pro-high
```

Model names come from `agy models`. Check it answers with `sentinel-advisor-check` (same environment variables as the service; see `.env.example`). Notes take 10–60 seconds each and appear in the incident's report under *Advisory second opinion*. `tests_arch/test_cli_advisor.py` holds the isolation checks: sandboxed, no auto-approved tools, an empty working directory, none of the service's secrets in its environment.

---

## What a tester should not conclude

| You saw | It does not show |
|---|---|
| The scanner listed your AI tools | That those tools are controlled. Inventory is self-reported presence. |
| A change waited for approval | That an agent which *bypasses* Sentinel is stopped. Enforcement applies to calls routed through it. |
| The demo on AWS | Production readiness. One region, single-AZ database, plain HTTP, sample data. |
| An advisory note | A decision. Remove the advisor and every decision is identical. |

Feedback that helps most: which AI tool on your machine the scanner missed, and the first place you did not know what to do next.
