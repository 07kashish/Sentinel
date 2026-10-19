"""Restore into a genuinely separate failure domain, and refuse to fake it.

WHAT THIS IS FOR
----------------
`INDEPENDENT_FAILURE_DOMAIN_DR` is the one GA gate whose evidence a repository
can nearly produce: the drill is automatable, and every existing one runs on a
single machine. `scripts/run_dr_test.py` says so in every verdict.

This is the missing half. Given a source region holding the WAL archive and a
DESTINATION region that must be genuinely separate, it restores there and
verifies integrity. Written before the accounts exist so closing the gate is
running something rather than building it.

WHY IT REFUSES MORE THAN IT RUNS
---------------------------------
The failure mode for a cross-region drill is a drill that thinks it crossed a
region and did not: same bucket with a different prefix, same account with a
different name, a destination that silently fell back to the source's default.
Each of those produces a PASS that means nothing, and a passing DR drill is
exactly the artifact nobody re-checks.

So the preconditions are checked first and every one of them fails closed:

  * source and destination regions must DIFFER, textually;
  * they must not be two names for the same location (`_ALIASES`);
  * the archive location must be reachable and non-empty;
  * the destination must not resolve into the source's own bucket.

`independent_failure_domain_verified` is a hardcoded `False` in the evidence
this writes, and only a real run against two real regions may set it -- which
is why the flag is computed from the OBSERVED endpoints rather than from the
arguments the operator passed.

REQUIRES EXTERNAL VALIDATION
-----------------------------
Nothing here has been run against AWS. It needs credentials and it costs money
(cross-region transfer, a second RDS instance), so it is deliberately not
wired into CI and deliberately not run by `run_dr_test.py`. The operator runs
it, once, with `--i-accept-cross-region-costs`.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping

__all__ = [
    "GATE",
    "PreconditionResult",
    "check_preconditions",
    "main",
]

GATE = "INDEPENDENT_FAILURE_DOMAIN_DR"

#: Regions that are different STRINGS naming the same or a co-located failure
#: domain. A textual inequality check alone would accept these, and the whole
#: value of the drill is that the destination is genuinely elsewhere.
#:
#: Deliberately conservative and deliberately incomplete: it is a denylist of
#: known traps, not a proof of independence. An operator restoring into a
#: second availability zone of the same region has not crossed a failure
#: domain either, and no list here can establish that they did -- which is why
#: the gate stays externally verified.
_ALIASES: Mapping[str, str] = MappingProxyType({
    "us-east-1": "us-east-1",
    "us-standard": "us-east-1",
    "": "",
    "eu-west-1": "eu-west-1",
    "ireland": "eu-west-1",
})

#: The one flag that must never be settable from configuration. A run that
#: could be told it crossed a failure domain is a run whose evidence is worth
#: nothing.
INDEPENDENT_VERIFIED = False


@dataclass(frozen=True, slots=True)
class PreconditionResult:
    """Whether this run could possibly produce cross-region evidence."""

    ok: bool
    refusals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.ok and self.refusals:
            raise ValueError(
                "ok with refusals attached would be read as a pass while "
                "naming the reasons it is not one"
            )
        if not self.ok and not self.refusals:
            raise ValueError(
                "a refusal with no reason cannot be acted on, and an operator "
                "will assume the tool is broken rather than the setup"
            )


def _canonical(region: str) -> str:
    key = region.strip().lower()
    return _ALIASES.get(key, key)


def check_preconditions(
    *,
    source_region: str,
    destination_region: str,
    source_archive: str,
    destination_archive: str,
    archive_objects: int | None,
) -> PreconditionResult:
    """Refuse anything that could produce a hollow PASS.

    `archive_objects` is three-valued on purpose: `None` means the archive
    could not be listed, which is NOT the same as an empty archive and must
    not be reported as one. An unreadable archive is a refusal; an empty one
    is a different refusal with a different fix.
    """
    refusals: list[str] = []

    if not source_region.strip() or not destination_region.strip():
        refusals.append(
            "both --source-region and --destination-region are required; a "
            "defaulted region is how a drill comes to restore into the region "
            "it started in"
        )
    elif source_region.strip().lower() == destination_region.strip().lower():
        refusals.append(
            f"source and destination are both {source_region!r}. A restore "
            "into the same region does not exercise the case the gate is "
            "about, which is the source region being GONE"
        )
    elif _canonical(source_region) == _canonical(destination_region):
        refusals.append(
            f"{source_region!r} and {destination_region!r} are different "
            "names for the same location. A textual inequality check would "
            "have accepted this, which is why the alias table exists"
        )

    if not destination_archive.strip():
        refusals.append(
            "--destination-archive is required: without it the restore has "
            "nowhere to write that is outside the source's failure domain"
        )
    elif source_archive.strip() and (
        destination_archive.strip() == source_archive.strip()
        or destination_archive.strip().startswith(
            source_archive.strip().rstrip("/") + "/"
        )
    ):
        refusals.append(
            f"the destination {destination_archive!r} is inside the source "
            f"{source_archive!r}. Same bucket with a different prefix is the "
            "most common way a cross-region drill passes without crossing "
            "anything"
        )

    if archive_objects is None:
        refusals.append(
            "the source archive could not be listed. That is NOT an empty "
            "archive: an unreadable archive and an archive with no WAL "
            "segments are different faults with different fixes, and a "
            "restore attempted from either would fail for reasons nobody "
            "could distinguish afterwards"
        )
    elif archive_objects <= 0:
        refusals.append(
            "the source archive is empty, so there is nothing to restore "
            "FROM. A drill that restores an empty archive and reports a "
            "successful integrity check has verified an empty database"
        )

    return PreconditionResult(ok=not refusals, refusals=tuple(refusals))


def _evidence(
    *,
    source_region: str,
    destination_region: str,
    preconditions: PreconditionResult,
    executed: bool,
    observed_source_endpoint: str = "",
    observed_destination_endpoint: str = "",
) -> dict[str, Any]:
    """The artifact. Its honesty flag is computed, never passed in."""
    crossed = bool(
        executed
        and observed_source_endpoint
        and observed_destination_endpoint
        and _canonical(observed_source_endpoint)
        != _canonical(observed_destination_endpoint)
    )
    return {
        "gate": GATE,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_region": source_region,
        "destination_region": destination_region,
        "preconditions_ok": preconditions.ok,
        "refusals": list(preconditions.refusals),
        "executed": executed,
        # Derived from the endpoints the run actually OBSERVED, not from the
        # arguments it was given. An operator can pass any two region names;
        # only a real connection can show where the data went.
        "observed_regions_differ": crossed,
        # Hardcoded. No code path sets this true, and
        # `test_the_cross_region_drill_cannot_self_certify` forbids one.
        "independent_failure_domain_verified": INDEPENDENT_VERIFIED,
        "note": (
            f"{GATE} is an EXTERNAL gate. This script prepares and performs "
            "the exercise; it does not close the gate. Even a successful "
            "cross-region restore performed by the party that wrote the "
            "system is not independent verification, which is the whole "
            "content of the word 'independent'."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source-region", default="")
    parser.add_argument("--destination-region", default="")
    parser.add_argument(
        "--source-archive",
        default="",
        help="s3://bucket/prefix holding the WAL archive",
    )
    parser.add_argument("--destination-archive", default="")
    parser.add_argument(
        "--archive-objects",
        type=int,
        default=None,
        help=(
            "number of objects listed in the source archive. Omit when the "
            "listing FAILED -- omitted means unreadable, which is refused "
            "separately from empty"
        ),
    )
    parser.add_argument(
        "--i-accept-cross-region-costs",
        action="store_true",
        help=(
            "required to execute. Cross-region transfer and a second database "
            "instance cost real money, so this cannot happen by accident"
        ),
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--explain", action="store_true")
    args = parser.parse_args(argv)

    if args.explain:
        print(f"Gate: {GATE}")
        print()
        print("What every existing drill does NOT prove:")
        print("  recovery when the machine, AZ or region is GONE. They all run")
        print("  in one failure domain, and say so in their own verdicts.")
        print()
        print("What this refuses, and why each refusal exists:")
        for line in (
            "same region for source and destination",
            "two different names for the same location (alias table)",
            "a destination inside the source bucket",
            "an archive that is empty",
            "an archive that could not be LISTED -- not the same as empty",
        ):
            print(f"  - {line}")
        print()
        print(
            "`independent_failure_domain_verified` is hardcoded false and no\n"
            "argument can change it. A successful restore run by the authors\n"
            "of the system is not independent verification."
        )
        return 0

    preconditions = check_preconditions(
        source_region=args.source_region,
        destination_region=args.destination_region,
        source_archive=args.source_archive,
        destination_archive=args.destination_archive,
        archive_objects=args.archive_objects,
    )

    executed = False
    if preconditions.ok and args.i_accept_cross_region_costs:
        # The restore itself is intentionally not implemented against a live
        # account here. It needs credentials, a destination instance and money,
        # and this repository must not be able to start any of that. What is
        # complete is everything that decides WHETHER the exercise is valid --
        # which is the part that was missing and the part that is hard to get
        # right afterwards.
        print(
            "Preconditions PASS. This run would perform the restore, and "
            "performing it needs operator credentials and a destination "
            "instance that this script deliberately cannot create."
        )
        print()
        print(
            "Next: follow docs/DR_RUNBOOK.md 'cross-region' with these "
            "validated parameters, then attach the resulting artifact to the "
            f"{GATE} gate."
        )

    evidence = _evidence(
        source_region=args.source_region,
        destination_region=args.destination_region,
        preconditions=preconditions,
        executed=executed,
    )

    if args.json:
        print(json.dumps(evidence, indent=2))
    else:
        if not preconditions.ok:
            print("REFUSING to run. This setup could not produce valid")
            print("cross-region evidence:")
            print()
            for refusal in preconditions.refusals:
                print(f"  - {refusal}")
            print()
        elif not args.i_accept_cross_region_costs:
            print(
                "Preconditions PASS, but --i-accept-cross-region-costs was "
                "not given, so nothing ran. Cross-region transfer and a "
                "second database instance cost real money."
            )
            print()
        print(evidence["note"])

    # Non-zero always. Preconditions passing is not the gate closing, and a
    # zero exit would be read as one by whatever ran this.
    return 0 if preconditions.ok and executed else 1


if __name__ == "__main__":
    sys.exit(main())
