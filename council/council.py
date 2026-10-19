"""Three-round AI Product Review Board over the Sentinel repository.

Three independent expert models (Claude Opus 4.8, OpenAI Codex, Antigravity /
Gemini 3.1 Pro) conduct an exhaustive due-diligence review as if deciding whether
to invest $100M. They act as CTOs, founders, product strategists, investors,
security architects, UX leads and AI researchers simultaneously.

Round 1  independent — each seat reviews the repo ALONE, no peer influence, and
                       files a complete due-diligence dossier.
Round 2  debate      — each seat reads the others' dossiers and cross-examines
                       them component by component (problem/evidence/risk/fix).
Round 3  consensus   — each seat gives final scores, votes, and a priority plan;
                       the synthesizer later reconciles these into one verdict.

Seats run in parallel inside a round and sequentially across rounds. Every
transcript is written to council/transcript/ as it lands, so a crashed or
timed-out run resumes instead of re-billing completed seats.

Usage:  py council/council.py [--rounds 3] [--timeout 1800] [--only claude,codex]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from seats import REPO_ROOT, SEATS, UNAVAILABLE, Seat, SeatResult, run_seat  # noqa: E402

COUNCIL_DIR = Path(__file__).resolve().parent
TRANSCRIPT_DIR = COUNCIL_DIR / "transcript"
BRIEF_PATH = COUNCIL_DIR / "brief.md"

# Rebuttal rounds quote peers verbatim; cap so round 3 prompts stay bounded.
PEER_EXCERPT_CHARS = 14000

CHARGE = """You are one independent seat on a world-class PRODUCT REVIEW BOARD. The
other seats are independent models from rival vendors; you do not defer to them and
you are not here to be agreeable. Hold, simultaneously, the perspectives of a CTO, a
repeat startup founder, a product strategist, a Tier-1 VC partner, a security
architect, a senior UX lead, an AI/ML researcher, and a demanding enterprise buyer.

THE MANDATE
You are conducting exhaustive due diligence as if your fund is about to invest $100M
into this product. Your job is NOT to praise it. It is to aggressively challenge every
assumption, find every weakness, surface every hidden opportunity, and describe how to
evolve this into a category-defining, globally competitive company. Be brutally honest;
do not protect the project's feelings. Reward only features and claims that carry real
customer or business value, weighed against engineering feasibility, maintenance cost,
scalability and long-term defensibility.

GLOBAL INTELLIGENCE MODE
Bring your full external knowledge to bear: current market trends, competitors and the
startup landscape, academic and LLM research, engineering/security/UX standards,
cloud/DevOps practice, SaaS and enterprise business models, pricing and GTM, VC
expectations, and regulatory requirements. Review this product against the whole
software ecosystem, not in isolation. The external brief below is evidence to argue
with, not settled fact.

CONTEXT: TWO MORE REMEDIATION PASSES HAVE HAPPENED
This is the EIGHTH review of this repository. The board before you scored it
Overall 38/100 and Investment-readiness 19/100 — up two and down one from the
board before that (36 and 20) — with NO on launching, commercial viability and
Series A, and 2-1 NO on seed. Since that verdict, two further passes (v7 and v8)
have been worked. Section 8 of the brief lists what was claimed to change and
what was deliberately NOT changed.

This does NOT narrow your review. Conduct the FULL independent due diligence
described below -- every lens, from market intelligence through feature
discovery, moats and roadmap -- exactly as if you were seeing this product for
the first time. The remediation history is context that saves you rediscovering
known ground, not a limit on what you examine. A fix list is not a company, and
your job is still to decide whether to put $100M into one.

Two things deserve particular attention. First: did any fix RELOCATE the failure
one layer up rather than close it -- the pattern this codebase has repeated five
times? That is the single most valuable finding available to you. Second:
engineering hygiene improved a great deal while detection, customers and
distribution did not, so be precise about which scores that should move and
which it should not. Improved engineering is not by itself a business.

THE PRODUCT
Sentinel — a Trust & Incident Attestation / agent-observability & policy-enforcement
layer for AI agents (pre-production, honest about its status per its own README). You
must READ THE CODE before judging it. Representative surface (not exhaustive — explore):
  README.md  PILOT_README.md  YC_APPLICATION_NOTES.md
  app/core/lifecycle.py  app/core/repository.py  app/core/config.py  app/core/dlq.py
  api/main.py  api/pipeline.py  api/auth.py  api/rbac.py  api/oidc.py
  app/integrations/  app/storage/  app/attestation/  app/identity/  app/monitoring/
  app/observability/  app/response/  app/tools/  agents/  dashboard/  sentinel_sdk/
  evaluation/  deploy/  tests/  docker-compose.yml
Cite file:line for every code-specific claim. Uncited claims about the code are discounted.

COVER EVERY LENS (do not skip; where a lens does not apply, say so briefly):
- Market intelligence: does this already exist? who are the incumbents and challengers,
  where are they better/worse, what is the defensible wedge, what to borrow, what never
  to copy.
- Gap analysis: the real, unsolved pains in this market (customer, workflow, trust,
  privacy, latency, cost, adoption) and whether Sentinel can credibly solve them.
- Feature discovery: invent features no competitor offers — "the product customers never
  knew they needed" — each with problem, impact, complexity, technical design, AI
  requirement, business value, defensibility.
- Technical architecture: frontend, backend, data model, storage, caching, auth/z,
  encryption, AI/agent orchestration, prompt design, memory, RAG/vector/knowledge-graph,
  queues/workers, observability, testing, CI/CD, deploy, scalability, reliability, cost.
- Security: OWASP (incl. the Agentic ASI top-10), authn/z, secrets, rate limiting, data
  privacy/GDPR/SOC2/ISO, prompt injection, model abuse, data/RAG poisoning, supply chain,
  recovery/DR.
- Performance & scale: bottlenecks from single-node to millions of users and global
  deployment; inference, streaming, DB, cache, network, concurrency.
- AI quality: hallucination, reasoning, accuracy, tool use, planning, autonomy, memory,
  cost, latency, multi-agent collaboration, failure recovery.
- UX / user journey: landing -> onboarding -> auth -> dashboard -> AI interaction -> reports ->
  settings -> notifications -> errors -> help. Find friction.
- Business & investment: MVP/V1/V2/V3 roadmap; pricing, subscription, enterprise
  licensing, API monetization, white-label, partnerships, marketplace, growth loops,
  network effects; would YC / Sequoia / a16z / Accel / Lightspeed / Benchmark invest, and
  the honest reasons why or why not.
- Launch readiness: can it launch today? every blocker, categorized Critical/High/Medium/Low.
- Hidden opportunities & moats: ignored industries/customers, emerging markets, patent-worthy
  ideas, durable moats. Think five years ahead — where do LLMs, agents, regulation and buyer
  expectations go, and how must Sentinel evolve to still win.

RULES OF ENGAGEMENT
- Cite files and line numbers for code claims. Quantify wherever you can.
- Say "I could not verify X" rather than guessing. Distinguish what the code DOES from
  what the docs/README/pitch SAY.
- Every criticism carries: Problem, Evidence, Risk, Solution, Tradeoffs, rough effort,
  Priority. Recommend only what a serious operator would actually build.
- Never reproduce a secret found in the repository. Do not recommend disabling safety
  gates, auth, or human-approval steps.
- You are not a licensed financial advisor; frame investment views as diligence opinion,
  not personal advice.
- Being wrong is recoverable. Being vague is not. Density over length.
"""

FORMAT_R1 = """\
ROUND 1 — INDEPENDENT DUE-DILIGENCE DOSSIER. You have NOT seen the other seats; do
not speculate about them. File your own complete review.

OUTPUT FORMAT — plain markdown, no preamble, no closing pleasantries:

## One-paragraph investment thesis   (would you fund it, at what stage, and the core reason)
## Scores (0-100, one number each, with a half-line justification)
   Engineering | AI/ML | UX | Architecture | Innovation | Security | Scalability | Business | Investment-readiness
## Strengths            (the genuinely strong things, with file:line where it is code)
## Weaknesses & architectural issues   (each: Problem | Evidence file:line | Risk | Fix | rough effort | Priority)
## Market intelligence   (does it exist already? named incumbents/challengers, where better/worse, the wedge)
## Gap analysis          (real unsolved market pains, and whether Sentinel can credibly close them)
## Missing / critical features   (what a serious buyer expects that is absent)
## Feature discovery — 3-5 non-obvious features   (problem | impact | complexity | design | AI need | defensibility)
## Security concerns     (OWASP + agentic ASI, prompt-injection, abuse, privacy, compliance)
## Scalability & performance concerns   (named bottlenecks, single-node -> millions of users)
## AI quality limitations   (hallucination, reasoning, tool use, autonomy, cost, failure recovery)
## Customer experience / UX friction   (walk the journey; name specific friction)
## Monetization & business-model opportunities   (pricing, packaging, API, enterprise, moats, growth loops)
## Launch blockers       (Critical/High/Medium/Low, each with why + impact + fix + effort)
## Hidden opportunities & patent-worthy ideas
## Three things I expect the other seats to get wrong

Target 1600-2400 words. Density over length. Cite file:line for code claims.
"""

FORMAT_R2 = """\
ROUND 2 — CROSS-EXAMINATION & COMPONENT DEBATE. You have now read the other seats'
Round-1 dossiers (quoted below). Debate them component by component. Be constructive,
not repetitive: only raise a point if it changes the decision.

OUTPUT FORMAT — plain markdown:

## Where a peer is right and I was wrong   (name the seat and the point)
## Where a peer is wrong   (quote the claim, then refute with file:line or external evidence)
## Component-by-component contest   (pick the 5-8 components that matter most — e.g. lifecycle/state,
   auth & RBAC, attestation/ledger, detection/eval, agent orchestration, storage/scale, SDK/API,
   dashboard/UX. For EACH: the strongest claim made, my challenge, and the resolved position, with
   Problem | Evidence | Risk | Solution | Tradeoffs | effort | Priority)
## What ALL of us missed entirely
## The single disagreement that most changes the investment decision
## My revised scores   (only the numbers that moved from Round 1, and why)

Attack the reasoning, not the model. If a peer made a claim about a file, open that file
and check before agreeing or disagreeing. Target 1200-1800 words.
"""

FORMAT_R3 = """\
ROUND 3 — FINAL VERDICT & PLAN. The full debate is below. Close it out. These numbers
and votes feed a consensus table, so answer in exactly the formats given.

OUTPUT FORMAT — plain markdown:

## Final position (one paragraph)
## FINAL SCORES — one integer 0-100 each, exactly this format, one per line:
  - OVERALL: n
  - ENGINEERING: n
  - AI: n
  - UX: n
  - ARCHITECTURE: n
  - INNOVATION: n
  - SECURITY: n
  - SCALABILITY: n
  - BUSINESS: n
  - INVESTMENT: n
## VOTES — answer each on its own line, exactly this format:
  - CAN_LAUNCH_TODAY: YES/NO - one line why
  - SAFE_TO_RUN_A_REAL_PILOT: YES/NO - one line why
  - VIABLE_COMMERCIAL_PRODUCT: YES/NO - one line why
  - FUNDABLE_AT_SEED: YES/NO - one line why
  - FUNDABLE_AT_SERIES_A: YES/NO - one line why
  - HAS_A_DEFENSIBLE_MOAT: YES/NO - name it or say none in <=15 words
  - CATEGORY_DEFINING_POTENTIAL: YES/NO - one line why
  - BIGGEST_SINGLE_RISK: <=15 words
## Prioritized plan — top 6 moves in priority order   (each: action | why | rough effort | Impact H/M/L | RICE-style reach/impact/confidence/effort if you can estimate them | Owner)
## Multi-year arc — one line each for 30-day / 90-day / 6-month / 1-year / 3-year / 5-year
   (each line must name the ENGINEERING, AI, BUSINESS and HIRING/OPS move for that horizon)
## What would have to be true for this to be a category-defining $1B+ company
## What I still could not verify
## My dissent from the emerging consensus, if any

Target 1100-1500 words.
"""


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _excerpt(text: str, limit: int = PEER_EXCERPT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "\n\n...[truncated for prompt budget]..."


def build_prompt(seat: Seat, rnd: int, brief: str, prior: dict[int, dict[str, str]]) -> str:
    round_name = {1: "Independent Due Diligence", 2: "Cross-Examination & Debate", 3: "Final Verdict"}
    header = (
        f"# AI Product Review Board — Round {rnd} of 3: {round_name.get(rnd, '')}\n"
        f"# Your seat: {seat.display} ({seat.vendor})\n\n"
        f"{CHARGE}\n\n"
        f"---\n# EXTERNAL INTELLIGENCE BRIEF\n\n{brief}\n\n---\n"
    )
    if rnd == 1:
        return header + FORMAT_R1

    peers = [s for s in SEATS if s.key != seat.key]
    body = [header]

    if rnd == 2:
        body.append("# ROUND 1 DOSSIERS FROM THE OTHER SEATS\n")
        for peer in peers:
            statement = prior.get(1, {}).get(peer.key, "")
            body.append(f"\n## {peer.display} — independent dossier\n\n")
            body.append(_excerpt(statement) if statement else "_(this seat did not report)_\n")
        body.append("\n---\n" + FORMAT_R2)
        return "".join(body)

    body.append("# FULL DEBATE TRANSCRIPT\n")
    for r in (1, 2):
        label = "Independent dossiers" if r == 1 else "Cross-examination"
        body.append(f"\n# Round {r} — {label}\n")
        for s in SEATS:
            text = prior.get(r, {}).get(s.key, "")
            tag = " (YOUR OWN)" if s.key == seat.key else ""
            body.append(f"\n## {s.display}{tag}\n\n")
            body.append(_excerpt(text, 9000) if text else "_(did not report)_\n")
    body.append("\n---\n" + FORMAT_R3)
    return "".join(body)


def run_round(
    rnd: int, seats: list[Seat], brief: str, prior: dict[int, dict[str, str]], timeout: int
) -> dict[str, SeatResult]:
    env_base = dict(os.environ)
    pending: list[Seat] = []
    results: dict[str, SeatResult] = {}

    for seat in seats:
        out_path = TRANSCRIPT_DIR / f"r{rnd}_{seat.key}.md"
        if out_path.exists() and out_path.stat().st_size > 200:
            print(f"  [r{rnd}] {seat.key}: reusing existing transcript", flush=True)
            results[seat.key] = SeatResult(seat.key, True, _read(out_path), 0.0, 0)
        else:
            pending.append(seat)

    if pending:
        print(f"  [r{rnd}] dispatching {len(pending)} seat(s) in parallel...", flush=True)
        with ThreadPoolExecutor(max_workers=len(pending)) as pool:
            futures = {
                pool.submit(
                    run_seat, seat, build_prompt(seat, rnd, brief, prior), timeout, env_base
                ): seat
                for seat in pending
            }
            for future, seat in futures.items():
                result = future.result()
                results[seat.key] = result
                status = "ok" if result.ok else f"FAILED ({result.error[:160]})"
                print(
                    f"  [r{rnd}] {seat.key}: {status} in {result.elapsed_sec:.0f}s "
                    f"({len(result.text)} chars)",
                    flush=True,
                )
                if result.ok:
                    (TRANSCRIPT_DIR / f"r{rnd}_{seat.key}.md").write_text(
                        result.text, encoding="utf-8"
                    )
                else:
                    (TRANSCRIPT_DIR / f"r{rnd}_{seat.key}.ERROR.txt").write_text(
                        result.error, encoding="utf-8"
                    )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Sentinel AI Product Review Board debate.")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=1800, help="per-seat, per-round seconds")
    parser.add_argument("--only", type=str, default="", help="comma-separated seat keys")
    args = parser.parse_args()

    TRANSCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    brief = _read(BRIEF_PATH)
    if not brief:
        print(f"FATAL: research brief missing at {BRIEF_PATH}", file=sys.stderr)
        return 1

    wanted = {k.strip() for k in args.only.split(",") if k.strip()}
    seats = [s for s in SEATS if not wanted or s.key in wanted]

    print(f"Repo:  {REPO_ROOT}")
    print(f"Seats: {', '.join(f'{s.display} [{s.key}]' for s in seats)}")
    for s in UNAVAILABLE:
        print(f"       UNAVAILABLE: {s.display} (needs {s.requires_env})")
    print(f"Rounds: {args.rounds}   per-seat timeout: {args.timeout}s\n")

    prior: dict[int, dict[str, str]] = {}
    summary: dict[str, object] = {
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "repo": str(REPO_ROOT),
        "seats": [
            {"key": s.key, "display": s.display, "vendor": s.vendor, "model": s.model}
            for s in seats
        ],
        "unavailable": [{"key": s.key, "display": s.display, "needs": s.requires_env} for s in UNAVAILABLE],
        "rounds": {},
    }

    for rnd in range(1, args.rounds + 1):
        print(f"=== ROUND {rnd} ===", flush=True)
        results = run_round(rnd, seats, brief, prior, args.timeout)
        prior[rnd] = {k: r.text for k, r in results.items() if r.ok}
        summary["rounds"][str(rnd)] = {  # type: ignore[index]
            k: {"ok": r.ok, "chars": len(r.text), "sec": round(r.elapsed_sec, 1), "err": r.error}
            for k, r in results.items()
        }
        if not prior[rnd]:
            print(f"FATAL: every seat failed in round {rnd}; stopping.", file=sys.stderr)
            break
        print()

    summary["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (TRANSCRIPT_DIR / "run_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    print(f"Transcripts + run_summary.json written to {TRANSCRIPT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
