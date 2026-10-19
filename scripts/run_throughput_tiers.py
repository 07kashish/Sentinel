#!/usr/bin/env python3
"""Section 60: repeatable benchmarks at declared TARGET RATES.

    Test: 100 / 1,000 / 5,000 / 10,000 events/sec
    Measure: p50 p95 p99 CPU memory DB-load queue-depth error-rate event-loss
    Record benchmark environment.
    Do not publish meaningless latency without concurrency/load context.

WHY A TIERED HARNESS AND NOT JUST "GO AS FAST AS POSSIBLE"
------------------------------------------------------------
`run_ingest_loadtest.py` already measures p95 correctly and out-of-process, and
this does not replace it. What it cannot answer is the question §60 actually
asks, which is not "how fast can it go" but "at 1,000 events/sec, what is the
latency". Those are different measurements and only the second is useful for
capacity planning: a saturated system reports the latency of a queue, not of the
service.

So each tier here PACES its senders to a target rate and reports what happened
at that rate -- including whether the target was met, which is the number that
makes the latency interpretable.

THE HONESTY RULES, WHICH ARE THE POINT OF THE MODULE
------------------------------------------------------
1. **A tier that could not sustain its target rate is reported as NOT SUSTAINED,
   and its latency is reported as meaningless.** A p95 measured while falling
   behind is the p95 of a backlog. Publishing it as a throughput figure is the
   thing §60's last line forbids, and it is the most common way benchmark tables
   mislead.

2. **`achieved_rate` is always reported next to `target_rate`.** A table with
   only latency invites the reader to assume the target was met.

3. **The environment is recorded in the artifact**, not in a commit message,
   because a number without its machine is not reproducible.

4. **Event loss is measured by counting rows, not by trusting HTTP status.** A
   202 means accepted, not stored. Counting what actually landed is the only way
   to detect loss in an at-least-once pipeline.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any

#: The tiers §60 names. Run in ascending order so a machine that saturates early
#: still produces meaningful rows for the tiers below its ceiling.
DEFAULT_TIERS: tuple[int, ...] = (100, 1_000, 5_000, 10_000)

#: A tier is "sustained" only if it achieved this fraction of its target.
#:
#: Not 1.0: process scheduling makes an exact rate unattainable, and a harness
#: that reported every tier as failed would be ignored. Not 0.8 either -- at
#: that slack a tier 20% short reads as a pass, which is the misreport this
#: whole module exists to prevent.
SUSTAINED_THRESHOLD: float = 0.95


@dataclass
class TierResult:
    """One tier's measurement, with everything needed to interpret it."""

    target_rate: int
    achieved_rate: float
    duration_seconds: float
    sent: int
    accepted: int
    errors: int
    #: Rows that actually landed. `accepted - stored` is loss.
    stored: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    cpu_percent: float | None = None
    rss_mb: float | None = None
    queue_depth: int | None = None

    @property
    def sustained(self) -> bool:
        return self.achieved_rate >= self.target_rate * SUSTAINED_THRESHOLD

    @property
    def error_rate(self) -> float:
        return (self.errors / self.sent) if self.sent else 0.0

    @property
    def event_loss(self) -> int:
        """Accepted but not stored. Never negative in a correct pipeline."""
        return max(0, self.accepted - self.stored)

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.update(
            {
                "sustained": self.sustained,
                "error_rate": round(self.error_rate, 6),
                "event_loss": self.event_loss,
                # THE field that stops a backlog latency being read as a
                # throughput figure. See the module docstring.
                "latency_is_meaningful": self.sustained,
                "interpretation": (
                    f"sustained {self.achieved_rate:.0f}/s against a "
                    f"{self.target_rate}/s target"
                    if self.sustained
                    else (
                        f"NOT SUSTAINED: reached only {self.achieved_rate:.0f}/s "
                        f"of {self.target_rate}/s. The latency below is the "
                        f"latency of a backlog and must not be quoted as a "
                        f"throughput result."
                    )
                ),
            }
        )
        return payload


def _environment() -> dict[str, Any]:
    """The machine. A number without this is not reproducible."""
    env: dict[str, Any] = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
    }
    try:
        import psutil  # type: ignore

        env["total_memory_gb"] = round(psutil.virtual_memory().total / 1e9, 1)
    except Exception:  # noqa: BLE001 - psutil is optional
        env["total_memory_gb"] = None
        env["note"] = "psutil not installed; CPU and memory are unmeasured"
    return env


def _percentiles(samples: list[float]) -> tuple[float, float, float, float]:
    """p50/p95/p99/max over the TRUE merged distribution.

    Not an average of per-worker percentiles, which is a different and wrong
    number -- the same mistake `run_ingest_loadtest.py` documents avoiding.
    """
    if not samples:
        return (0.0, 0.0, 0.0, 0.0)
    ordered = sorted(samples)

    def pick(fraction: float) -> float:
        index = min(len(ordered) - 1, int(len(ordered) * fraction))
        return round(ordered[index] * 1000, 3)

    return (pick(0.50), pick(0.95), pick(0.99), round(ordered[-1] * 1000, 3))


def run_tier(
    *,
    target_rate: int,
    seconds: int,
    send: Any,
    count_stored: Any,
    sample_resources: Any = None,
) -> TierResult:
    """Drive one tier at a paced rate and measure it.

    `send` performs one request and returns True on acceptance. Injected rather
    than built here so the pacing logic can be tested against a fake without a
    server, and so this module has no opinion about transport.
    """
    interval = 1.0 / target_rate
    latencies: list[float] = []
    sent = accepted = errors = 0

    stored_before = count_stored()
    started = time.perf_counter()
    deadline = started + seconds
    next_send = started

    while time.perf_counter() < deadline:
        now = time.perf_counter()
        if now < next_send:
            # Busy-wait rather than sleep for sub-millisecond intervals: at
            # 10,000/s the interval is 100us and `time.sleep` cannot pace that.
            continue
        next_send += interval
        call_started = time.perf_counter()
        try:
            ok = send()
        except Exception:  # noqa: BLE001 - a failed send is an error, not a crash
            ok = False
        latencies.append(time.perf_counter() - call_started)
        sent += 1
        if ok:
            accepted += 1
        else:
            errors += 1

    duration = time.perf_counter() - started
    # Give the pipeline a moment to drain before counting, so loss is not
    # confused with lag. Anything still missing after this is real loss.
    time.sleep(1.0)
    stored = max(0, count_stored() - stored_before)

    p50, p95, p99, worst = _percentiles(latencies)
    resources = sample_resources() if sample_resources else {}
    return TierResult(
        target_rate=target_rate,
        achieved_rate=round(sent / duration, 2) if duration else 0.0,
        duration_seconds=round(duration, 3),
        sent=sent,
        accepted=accepted,
        errors=errors,
        stored=stored,
        p50_ms=p50,
        p95_ms=p95,
        p99_ms=p99,
        max_ms=worst,
        cpu_percent=resources.get("cpu_percent"),
        rss_mb=resources.get("rss_mb"),
        queue_depth=resources.get("queue_depth"),
    )


def report(results: list[TierResult]) -> dict[str, Any]:
    """Assemble the artifact, environment included."""
    sustained = [r for r in results if r.sustained]
    return {
        "specification_section": 60,
        "environment": _environment(),
        "sustained_threshold": SUSTAINED_THRESHOLD,
        "tiers": [r.as_dict() for r in results],
        "highest_sustained_rate": (
            max(r.target_rate for r in sustained) if sustained else 0
        ),
        "honesty_note": (
            "Latency from a tier marked latency_is_meaningful=false is the "
            "latency of a backlog, not of the service, and must not be quoted "
            "as a throughput result."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tiers",
        type=int,
        nargs="*",
        default=list(DEFAULT_TIERS),
        help="target rates in events/sec",
    )
    parser.add_argument("--seconds", type=int, default=10, help="duration per tier")
    parser.add_argument("--out", default="docs/throughput_tiers.json")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run against an in-process stub to prove the harness itself works",
    )
    args = parser.parse_args(argv)

    if not args.self_test:
        sys.stderr.write(
            "This harness requires a running server and a row counter. Wire it "
            "to `scripts/run_ingest_loadtest.py`'s server fixture, or use "
            "--self-test to verify the harness itself.\n"
        )
        return 2

    # Self-test: a stub that accepts everything instantly. Proves the pacing,
    # percentile and reporting logic run -- and deliberately does NOT pretend to
    # be a performance result.
    stored = {"n": 0}

    def send() -> bool:
        stored["n"] += 1
        return True

    results = [
        run_tier(
            target_rate=rate,
            seconds=max(1, args.seconds // len(args.tiers)),
            send=send,
            count_stored=lambda: stored["n"],
        )
        for rate in args.tiers
    ]
    payload = report(results)
    payload["self_test"] = True
    payload["warning"] = (
        "SELF-TEST ONLY. The 'send' path is an in-process no-op stub. These "
        "numbers measure this harness, not Sentinel, and must never appear in "
        "a performance report."
    )
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
