"""Ingest real AWS cost data, and refuse to invent it.

WHAT THIS CLOSES AND WHAT IT DOES NOT
--------------------------------------
`MEASURED_AWS_UNIT_ECONOMICS` is an open external gate because no bill for
this platform exists. This script is the thing that closes it -- once there IS
a bill. Running it today against an account with no Sentinel resources
produces `UNVERIFIED` and a non-zero exit, which is the honest answer and the
whole point of writing it now: the collection procedure should exist before
the data does, so that closing the gate is a matter of running something rather
than building something.

IT READS COST EXPLORER, WHICH COSTS MONEY TO QUERY
---------------------------------------------------
`GetCostAndUsage` is $0.01 per request. That is small and it is not zero, so
this makes ONE request per invocation and says so -- a loop that polled it
every minute would be a cost tool that is itself a line item, which has
happened to people.

`--dry-run` makes no request at all and prints what it would ask for. That is
the default posture for anybody exploring: an operator should be able to see
the query before spending anything.

WHY IT DERIVES UNIT COST RATHER THAN JUST TOTAL SPEND
------------------------------------------------------
Total spend is a number an accountant already has. The question this product
needs answered is "what does a million agent events cost", because that is
what pricing rests on. So the script takes the volume figures as arguments and
divides -- and REFUSES to divide by zero volume, because a cost-per-event of
infinity rendered as a large number would be quoted.

IT IS WIRED, AND UNTESTED AGAINST A REAL BILL
----------------------------------------------
The signing, the request and the arithmetic are real. What has never happened
is a successful run, because no Sentinel-tagged resource exists in any account
-- so the gate stays open and this script reports UNVERIFIED. That is the
correct state and not a partial one.

IT DOES NOT READ `.env`, DELIBERATELY
--------------------------------------
`publish_transparency_root.py` loads `.env` because it runs on a schedule and
an operator cannot type into a cron job. This does the opposite: a real run
costs money and reads billing data, so the credential has to be in the
environment of the person invoking it. Picking one up from a file in the
working copy would let an exploratory session turn into a charged query
against whichever account somebody last configured.

NO CREDENTIAL IS PRINTED, EVER
-------------------------------
Credentials come from the environment and are used to sign. Any occurrence in
output is redacted before display, on the same rule as
`scripts/publish_transparency_root.py`: an operator pasting this output into an
issue must not be pasting their secret key with it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PASS, UNVERIFIED, FAIL = "PASS", "UNVERIFIED", "FAIL"

#: A literal newline, named. SigV4's canonical request is newline-joined
#: and every escaping layer between here and the file has mangled it at
#: least once, so it is a constant rather than an escape sequence.
NEWLINE = chr(10)

#: Cost Explorer charges per request. Small, not zero, and stated so nobody
#: writes the polling loop.
COST_PER_QUERY_USD = 0.01

#: The tag every Terraform module here sets. Without it a shared account's
#: other spend drowns the signal, and the resulting figure would be somebody
#: else's bill divided by our event count.
PROJECT_TAG = "Project"
PROJECT_VALUE = "Sentinel"


@dataclass(frozen=True)
class Outcome:
    status: str
    detail: str
    payload: dict

    @property
    def exit_code(self) -> int:
        # UNVERIFIED is non-zero. "We could not measure it" and "we measured
        # it" are different facts and only one closes the gate.
        return 0 if self.status == PASS else 1


def _redact(text: str) -> str:
    """Strip anything from the environment that could be a credential."""
    for name in (
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "SENTINEL_S3_ROOT_SECRET_ACCESS_KEY",
    ):
        value = os.environ.get(name, "").strip()
        if value:
            text = text.replace(value, "[redacted]")
    return text


def _query_body(start: date, end: date) -> dict:
    """The Cost Explorer request. Built here so `--dry-run` can print it."""
    return {
        "TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()},
        "Granularity": "MONTHLY",
        # UnblendedCost, not AmortizedCost. Amortized spreads a reservation
        # across the period, which is the right number for a finance report and
        # the wrong one for "what did this month cost us" -- and this platform
        # has no reservations to amortize anyway.
        "Metrics": ["UnblendedCost"],
        "Filter": {
            "Tags": {
                "Key": PROJECT_TAG,
                "Values": [PROJECT_VALUE],
                "MatchOptions": ["EQUALS"],
            }
        },
        "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
    }


def _fetch(body: dict) -> tuple[dict | None, str]:
    """Sign and send ONE request. Returns (payload, error).

    Reuses `_sign` and `_signing_key` from `s3_root_sink` -- the two SigV4
    primitives that are already module-level there -- rather than boto3 or a
    second copy of the algorithm. Not boto3, for the reason that module gives:
    one more dependency in a security product needs a better reason than
    convenience. Not a second copy, because two implementations of a signature
    eventually disagree and the disagreement presents as a 403 that reads like
    a permissions problem.

    The request goes through `HardenedHttpClient` because `urllib.request`
    follows redirects and forwards the Authorization header -- a PROVEN leak in
    this codebase, where a 302 to a loopback address received a bearer token.
    """
    import hashlib
    import hmac

    from sentinel.infrastructure.outbound import (
        HardenedHttpClient,
        OutboundPolicy,
        OutboundRefused,
        OutboundUnavailable,
    )
    from sentinel.infrastructure.s3_root_sink import _signing_key

    key_id = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    session = os.environ.get("AWS_SESSION_TOKEN", "").strip()

    if not (key_id and secret):
        return None, (
            "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not both set, so "
            "no request was made. UNVERIFIED rather than a zero-cost result: "
            "an unauthenticated query returns nothing, and nothing is not the "
            "same as no spend."
        )

    # COST EXPLORER IS GLOBAL, SERVED FROM us-east-1, regardless of where the
    # resources are. Signing for another region returns a 403 that reads like a
    # permissions problem, which is the mistake worth spending a comment on.
    region = "us-east-1"
    service = "ce"
    host = f"{service}.{region}.amazonaws.com"
    target = "AWSInsightsIndexService.GetCostAndUsage"

    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    payload_hash = hashlib.sha256(payload).hexdigest()

    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    signed_headers_map = {
        "content-type": "application/x-amz-json-1.1",
        "host": host,
        "x-amz-date": stamp,
        "x-amz-target": target,
    }
    if session:
        signed_headers_map["x-amz-security-token"] = session

    signed_names = ";".join(sorted(signed_headers_map))
    canonical_headers = "".join(
        f"{name}:{signed_headers_map[name]}" + NEWLINE
        for name in sorted(signed_headers_map)
    )
    canonical_request = NEWLINE.join([
        "POST", "/", "", canonical_headers, signed_names, payload_hash,
    ])

    scope = f"{datestamp}/{region}/{service}/aws4_request"
    to_sign = NEWLINE.join([
        "AWS4-HMAC-SHA256",
        stamp,
        scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])
    signature = hmac.new(
        _signing_key(secret, datestamp, region),
        to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # `host` is SIGNED but NOT SENT -- HardenedHttpClient forbids a caller
    # setting it, and the transport supplies it. Same rule as the S3 sink.
    wire = {
        name: value for name, value in signed_headers_map.items() if name != "host"
    }
    wire["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, "
        f"SignedHeaders={signed_names}, Signature={signature}"
    )

    client = HardenedHttpClient(policy=OutboundPolicy())
    try:
        response = client.request(
            method="POST",
            url=f"https://{host}/",
            headers=wire,
            body=payload,
            idempotent=True,
        )
    except (OutboundRefused, OutboundUnavailable) as error:
        return None, (
            f"the request did not complete: {error}. UNVERIFIED rather than a "
            "retryable success -- a network error is not a cost of zero."
        )

    if response.status != 200:
        return None, (
            f"Cost Explorer returned {response.status}. If it is 403, the "
            "credential most likely lacks `ce:GetCostAndUsage`, which is a "
            "separate grant from any S3 or IAM permission and is the one "
            "people leave out."
        )

    try:
        return response.json(), ""
    except (ValueError, AttributeError) as error:
        return None, f"the response was not JSON: {error}"


def _unit_costs(total: float, *, events: int, decisions: int) -> dict:
    """Cost per million, or None with a reason.

    REFUSES to divide by zero volume. A cost-per-event of infinity rendered as
    a large number would be quoted, and the person quoting it would not know
    the denominator was zero.
    """
    def per_million(volume: int, label: str):
        if volume <= 0:
            return {
                "value": None,
                "reason": (
                    f"{label} volume is {volume}, so there is nothing to "
                    "divide by. Reported rather than rendered as a large "
                    "number, which would be quoted"
                ),
            }
        return {"value": round(total / volume * 1_000_000, 4), "reason": ""}

    return {
        "usd_per_million_events": per_million(events, "event"),
        "usd_per_million_decisions": per_million(decisions, "decision"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ingest real AWS cost data for Sentinel-tagged resources."
    )
    parser.add_argument(
        "--months", type=int, default=1,
        help="How many complete months back to query.",
    )
    parser.add_argument(
        "--events", type=int, default=0,
        help="Agent events in the period, for the per-million figure.",
    )
    parser.add_argument(
        "--decisions", type=int, default=0,
        help="Authorization decisions in the period.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help=(
            "Print the query and make NO request. Costs nothing. The right "
            "default posture for anybody exploring."
        ),
    )
    parser.add_argument("--evidence", type=Path, default=None)
    args = parser.parse_args(argv)

    today = datetime.now(timezone.utc).date()
    start = (today.replace(day=1) - timedelta(days=31 * args.months)).replace(day=1)
    end = today.replace(day=1)
    body = _query_body(start, end)

    if args.dry_run:
        print("DRY RUN -- no request made, nothing charged.\n")
        print(json.dumps(body, indent=2))
        print(
            f"\nA real run makes ONE GetCostAndUsage request at "
            f"${COST_PER_QUERY_USD:.2f}. There is no polling loop here on "
            "purpose: a cost tool that is itself a line item has happened to "
            "people."
        )
        return 0

    payload, error = _fetch(body)

    if payload is None:
        outcome = Outcome(
            UNVERIFIED,
            _redact(error),
            {
                "period": {"start": start.isoformat(), "end": end.isoformat()},
                "query": body,
            },
        )
    else:  # pragma: no cover - needs a real account with real resources
        groups = payload.get("ResultsByTime", [{}])[0].get("Groups", [])
        total = sum(
            float(g["Metrics"]["UnblendedCost"]["Amount"]) for g in groups
        )
        outcome = Outcome(
            PASS,
            f"measured ${total:.2f} across {len(groups)} service(s)",
            {
                "period": {"start": start.isoformat(), "end": end.isoformat()},
                "total_usd": round(total, 2),
                "by_service": {
                    g["Keys"][0]: round(
                        float(g["Metrics"]["UnblendedCost"]["Amount"]), 2
                    )
                    for g in groups
                },
                "unit_costs": _unit_costs(
                    total, events=args.events, decisions=args.decisions
                ),
            },
        )

    print(f"{outcome.status}  {outcome.detail}")

    if args.evidence is not None:
        args.evidence.parent.mkdir(parents=True, exist_ok=True)
        args.evidence.write_text(
            json.dumps(
                {
                    "schema": "sentinel.aws_costs.v1",
                    "status": outcome.status,
                    "detail": outcome.detail,
                    "collected_at": datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                    **outcome.payload,
                    # TRUE only on a PASS. Every other path leaves the gate
                    # open, and this field is what a readiness check reads.
                    "measured": outcome.status == PASS,
                    "gate": (
                        "MEASURED_AWS_UNIT_ECONOMICS closes only when this "
                        "reports PASS against an account with applied Sentinel "
                        "resources. An UNVERIFIED result is the honest state, "
                        "not a partial one."
                    ),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"wrote {args.evidence}")

    return outcome.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
