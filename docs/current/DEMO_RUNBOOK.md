# Showing and running Sentinel — the owner's runbook

For the person giving the demo. `TRY_SENTINEL.md` is the page you hand to the person *receiving* it. The commands, and the live-approval clicks in Part 3, were performed on 2026-10-03; the Part 2 walk on the shared link follows the console's view names and the seeded data but was not clicked through view by view.

**The one-sentence pitch.** *AI agents now change real systems; Sentinel is the checkpoint between the agent and the change — it decides allow, ask a human, or block, proves who approved what, and shows which AI tools are on your machines.*

**Say this, not more.** Developer preview. Demonstrated on one cloud host. No customer in production. Do not say production-ready, secure, compliant or market-leading; `RELEASE_STATUS.md` is what is actually established.

---

## Part 1 — Five minutes before any demo

1. **Refresh the sample data.** The two "waiting for a human" requests expire after about five minutes by design, so load fresh ones right before you start:

   ```bash
   /Users/lokeshjain/Documents/sentinel_soc-main/sentinel_program_evidence/tooling/refresh_demo.sh
   ```

   It should end with `console: 200 | demo key published: 200 | viewer reads devices: 200`.

2. **Open the console** and leave it on *Overview*:

   ```
   http://sentinel-proof-557842222.ap-south-1.elb.amazonaws.com/console
   ```

3. **Have the two apps ready to send**: `sentinel_program_evidence/2026-10-03-desktop-app/Sentinel-AI-Scan-macOS.zip` and `Sentinel-AI-Scan-Windows.exe`.

4. **If you will approve something live** (Part 3), start the local copy now, because the AWS link is read-only:

   ```bash
   cd /Users/lokeshjain/Documents/sentinel_soc-main/sentinel_soc-main && .venv/bin/python scripts/try_sentinel.py --scan --demo
   ```

   Keep that terminal open; it prints the address and the admin key.

## Part 2 — The ten-minute demo on the shared link (read-only)

| Minute | Click | What to say | What they see |
|---|---|---|---|
| 0–1 | *Overview* | "Every agent action that mattered, by state. Nothing here is a mock-up: it was created through the same API a real agent uses." | Incident counts by state |
| 1–4 | *Agent requests* | "An agent asked to change production. Policy said a human must decide. Each card shows the agent, the resource, why approval is needed, and a digest of the exact parameters — what executes is refused unless it matches that digest." | Two cards waiting, each with a countdown. On this link the Approve and Reject buttons cannot be used (read-only) |
| 4–5 | *Approved vs executed* | "This is the proof: what was approved and what actually ran, side by side. The second attempt with the same approval was refused." | Bound executions; one replay refused |
| 5–6 | *Execution graph* | "Why an incident was raised: the chain of steps, not a score." | The staged-exfiltration chain |
| 6–7 | *Containment* | "One agent is paused, with a reason and an expiry. Its calls are refused until someone lifts it." | `agent:data-cleaner` contained |
| 7–8 | *Overview* → **open incident** → report | "A model writes a second opinion for the analyst. It is labelled unverified and it cannot change the decision — remove it and every decision is identical." | *Advisory second opinion*: `antigravity-cli:gemini-3.1-pro-high` and its note |
| 8–10 | *Pilot setup* | "This is a real laptop's AI inventory — found by an app the owner ran with their consent. Presence only." | One device: Gemini CLI, Antigravity, Claude, Codex, ChatGPT |

**Questions you will get, and the true answers.**

* *Does it stop an agent that ignores it?* No. It governs calls routed through it (SDK, tool gateway, MCP proxy). An agent with its own credentials and a direct path is not stopped; closing that path is a deployment task (network policy, credential custody).
* *Is the AI making the decisions?* No. Decisions are deterministic policy. The model only writes notes.
* *Can I sign in and try approving on this link?* Not on this link: it is plain HTTP, so the console refuses operator sign-in by design. Part 3 shows it live.
* *Is it in production anywhere?* No.

## Part 3 — Showing a live approval (your laptop, 3 minutes)

With the local copy from Part 1 step 4 running:

1. Open `http://127.0.0.1:8000/console`, paste the **admin key** the terminal printed as the *operator token*, and press **Sign in**.
2. *Agent requests* → on a waiting card, type a reason in the box → **Approve**. A "request approved" notice appears and the card leaves the list. (*Approvals* is a different view: it is for remediation proposals on incidents and is normally empty in this sample.)
3. *Approved vs executed* → show the record that binds an approval to its execution.
4. *Pilot setup* → show this laptop's inventory, imported a minute ago.

The requests wait for about five minutes, then show **expired** and can no longer be approved — which is itself worth showing ("an approval nobody gave in time is not an approval"). For new ones, in a second terminal:

```bash
cd /Users/lokeshjain/Documents/sentinel_soc-main/sentinel_soc-main && .venv/bin/python scripts/try_sentinel.py --fresh-requests
```

Then click *Overview* and back to *Agent requests*. Approve promptly: the countdown on a card does not tick down on screen between refreshes.

## Part 4 — Letting them try it themselves

| They are | Send them | They do |
|---|---|---|
| Anyone | The console link | Click around, read-only |
| Mac user | `Sentinel-AI-Scan-macOS.zip` + `TRY_SENTINEL.md` | Unzip, right-click → Open, tick, Scan |
| Windows user | `Sentinel-AI-Scan-Windows.exe` + `TRY_SENTINEL.md` | Run, *More info → Run anyway*, tick, Scan |
| A developer | Repository access + `TRY_SENTINEL.md` | `scripts/try_sentinel.py --scan --demo`, then gate one action (section 4 there) |

Warn them first: both apps are unsigned and the operating system will say so. Ask them to send back the saved `.html` page and to tell you which AI tool the scan missed.

## Part 5 — Running it for a design partner

There are two ways to run Sentinel today. Neither is a production service.

**A. On their laptop or a VM (an afternoon).** `scripts/try_sentinel.py`: one process, SQLite, no TLS. Good for a developer evaluating the API. Not for more than one person.

**B. The AWS stack (`deploy/terraform/aws`).** What the shared link runs: load balancer, two API tasks, PostgreSQL with row-level security, Redis, WAF, encrypted evidence, and the brain host. To stand one up for a partner you need, in this order:

1. A domain and an ACM certificate (OWNER_ACTIONS 11) — without HTTPS nobody can sign in as an operator.
2. Their tenant's API keys in `sentinel/<env>/api-keys` (one per role).
3. `tofu apply` with the image digest and, if the advisor is wanted, the `brain_host` variable; run the schema migration task; roll the service.
4. Their first workflow wired through the gateway — `FIRST_WORKFLOW.md` and `PILOT_KIT.md` are the three-week procedure.

Operating notes that have already cost time: every `tofu apply` on `proof` must pass `-var 'brain_host={enabled=true,instance_type="t4g.small",model="gemini-3.1-pro-high"}'` or the plan destroys the brain host; after any rollout run `sudo systemctl restart sentinel-brain` on that host (Session Manager); the advisor answers as the owner's signed-in Google account and stops if that session ends.

## Part 6 — Before you call it a launch

"Launch" can honestly mean **an invited developer preview**: people you choose get the link, the apps and the guide. That is ready today. A public launch is not, and these are the reasons, in the order they block:

| # | Gap | Why it blocks | Who | Size |
|---|---|---|---|---|
| 1 | No HTTPS on the shared link | Operators cannot sign in; browsers mark the page not secure | Owner: a domain + ACM certificate | An hour |
| 2 | Apps unsigned | macOS and Windows warn on first open; many people will stop there | Owner: Apple Developer ID, Windows certificate | Days (enrolment) |
| 3 | No public download | The repository is private; files are sent by hand | Owner: decide where they are hosted | Hours |
| 4 | Windows app never opened on a real PC | It is built and self-tested only on a hosted runner | Anyone with a Windows machine | Minutes |
| 5 | No sign-up, billing, terms or privacy notice | Nobody can become a customer without you in the loop, and the scanner needs a privacy notice before strangers run it | Owner | Days to weeks |
| 6 | One region, single-AZ database, no on-call | An outage has nobody watching and no failover | Owner | Weeks |
| 7 | No external security test, no customer evidence | The tiers `production_observed` and `externally_verified` in `RELEASE_STATUS.md` are empty | Owner: OWNER_ACTIONS 1, 4, 8, 10 | Weeks to months |
| 8 | The advisor runs on one person's Google account | Usage, quota and continuity depend on that account | Owner: a provider key or a service account | Days |

The accurate external sentence until 1, 2 and 5 are done: **"Invite-only developer preview with tested execution control, demonstrated on one cloud host."**
