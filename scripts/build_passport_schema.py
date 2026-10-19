"""Generate spec/execution-passport/schema.json FROM the implementation.

Hand-written next to a dataclass, a schema drifts the first time a field is
added, and it drifts silently -- the schema still validates every document
anybody happens to test with. Generated, it cannot say a field exists that does
not, and `test_the_schema_matches_the_implementation` fails if the two diverge.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.domain.passport import (  # noqa: E402
    PASSPORT_SCHEMA,
    REQUIRED_FIELDS,
    ExecutionPassport,
)

_MAX_EXACT_INT = 2**53 - 1


def _json_type(value) -> dict:
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        # Bounded, per section 1. Past 2^53 a double cannot hold the value
        # exactly, so the document round-trips to a different number.
        return {
            "type": "integer",
            "minimum": -_MAX_EXACT_INT,
            "maximum": _MAX_EXACT_INT,
        }
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        return {"type": "array"}
    if isinstance(value, dict):
        return {"type": "object"}
    raise TypeError(f"no schema mapping for {type(value).__name__}")


def main() -> int:
    sample = ExecutionPassport(
        execution_id="x", tenant_id="t", occurred_at="2026-01-01T00:00:00+00:00"
    ).as_document()

    properties = {name: _json_type(value) for name, value in sample.items()}
    properties["schema"] = {"const": PASSPORT_SCHEMA}

    document = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sentinel.dev/spec/execution-passport/v1/schema.json",
        "title": "Execution Passport v1",
        "description": (
            "Generated from sentinel/domain/passport.py. A hand-written schema "
            "beside a dataclass drifts the first time a field is added, and it "
            "drifts silently, because it still validates every document anybody "
            "happens to test with."
        ),
        "type": "object",
        # TRUE, deliberately. Section 5 requires unknown fields to be preserved
        # and included in the digest: a verifier that dropped them would compute
        # a different digest than the signer did, so forward compatibility and
        # digest stability are the same requirement. `false` here would make
        # this schema contradict the format it describes.
        "additionalProperties": True,
        "required": list(REQUIRED_FIELDS),
        "properties": dict(sorted(properties.items())),
        "$comment": (
            "Schema validation is NECESSARY AND NOT SUFFICIENT. It cannot check "
            "the canonical form, the digest, the signature or the parent chain "
            "-- a document that validates here may still be forged. Use a "
            "conforming verifier; see README.md section 3."
        ),
    }

    out = ROOT / "spec" / "execution-passport" / "schema.json"
    out.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"wrote {out.relative_to(ROOT)} with {len(properties)} properties")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
