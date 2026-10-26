# Try Sentinel — a tester's guide

For someone who has never seen the product and wants to know, in an hour, what it does. Several things you can do, from least to most effort. Every command here was run on 2026-10-03 at the commit that added this file.

**What Sentinel is.** A control point for AI agents: before an agent's tool call changes something, Sentinel decides *allow / needs a human / block* by deterministic policy, records who approved what, and refuses replays. It also keeps an inventory of the agents and AI tools it is told about. It is a developer preview (see `STATUS.md`); nothing here is a production claim.

**What it is not.** It does not watch your screen, read your files, or intercept network traffic. It governs the calls an agent *sends through it*, and it lists the AI tools you *choose to report*.

---

## 1. Run your own Sentinel (10 minutes)

Needs a checkout and Python 3.12+. The commands below are for macOS and Linux; on **Windows** (PowerShell) use `py -m venv .venv`, then `.venv\Scripts\pip install -e ".[server]"`, then `.venv\Scripts\python scripts\try_sentinel.py`.

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -e ".[server]"
```

```bash
.venv/bin/python scripts/try_sentinel.py
```

The last command creates `.sentinel-trial/` with a SQLite database and four fresh keys, migrates and serves the console. It prints the address and the **admin key**. Open `http://127.0.0.1:8000/console`, paste the admin key as the *operator token* (that is all "operator token" means: an API key with a role), and open **Overview** to see current incidents. `Ctrl-C` stops it; delete `.sentinel-trial/` to remove every trace.

The service starts without sample records; shared demos and seeding are parked. Local device discovery is parked; see [PARKED.md](../PARKED.md).

## 2. Put one agent action behind it (15 minutes)

With step 1 running, take the `ingest` and `analyst` keys from `.sentinel-trial/keys.env`. Ask Sentinel whether an agent may make a change:

```bash
curl -s http://127.0.0.1:8000/v1/protect/evaluate -H "Authorization: Bearer $INGEST" -H "X-Sentinel-Agent-Id: agent:demo" -H "Content-Type: application/json" -d '{"agentId":"agent:demo","tool":"echo","action":"update","resource":"/protected-change/prod/config/rate-limit","arguments":{"rps":450}}'
```

The answer carries the decision and, when a human is required, an authorization to approve in the console under **Agent requests** (sign in with the analyst key). An approved authorization executes once through `POST /v1/tools/execute`; the second attempt is refused. For real agents: `FIRST_WORKFLOW.md`.

## 3. Optional: the advisory brain

Sentinel's decisions are deterministic. A model can be attached as an **advisor**: it writes a note for the analyst on each incident and approval, labelled `[unverified-model-output]`, and it cannot change a priority or a decision. If you have the Antigravity CLI installed and signed in:

```bash
.venv/bin/python scripts/try_sentinel.py --advisor-cli ~/.local/bin/agy --advisor-model gemini-3.1-pro-high
```

Model names come from `agy models`. Configure the advisor through the service environment variables in `.env.example`; the standalone advisor-check CLI was removed in Phase 2. Notes take 10–60 seconds each and appear in the incident's report under *Advisory second opinion*. `tests_arch/test_cli_advisor.py` holds the isolation checks: sandboxed, no auto-approved tools, an empty working directory, none of the service's secrets in its environment.

---

## What a tester should not conclude

| You saw | It does not show |
|---|---|
| A change waited for approval | That an agent which *bypasses* Sentinel is stopped. Enforcement applies to calls routed through it. |
| An advisory note | A decision. Remove the advisor and every decision is identical. |

Feedback that helps most: the agent action you tried to govern and the first place you did not know what to do next.
