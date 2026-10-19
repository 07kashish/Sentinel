"""A deliberately small CBOR decoder, for WebAuthn and nothing else.

WHY WRITE ONE RATHER THAN ADD A DEPENDENCY
------------------------------------------
WebAuthn's attestation object and COSE keys are CBOR, and Python's standard library
has no CBOR. The alternatives were a third-party parser or this.

This is the parser that reads attacker-supplied bytes during authentication, so its
size is the argument. A general CBOR library supports tags, indefinite-length
streams, big floats, bignums and semantic tags, all of which are attack surface for
a caller that needs six types. Roughly 150 lines that a reviewer can read in full
beats several thousand that they will not.

WHAT IS REFUSED, AND WHY EACH REFUSAL MATTERS
---------------------------------------------
* **Indefinite-length items.** A stream that declares no length is a decoder loop
  whose termination depends on the input. WebAuthn never uses them.
* **Trailing bytes.** `decode` requires the input to be exhausted. Extra bytes
  after a valid object are how one parser sees a different structure than another
  -- and in WebAuthn the same bytes are hashed by one component and parsed by
  another, so a disagreement is a signature bypass.
* **Non-canonical map keys.** Duplicates are refused rather than last-wins,
  because two parsers resolving a duplicate differently is the same class of
  defect: the verifier reads one key and the hasher covers another.
* **Unbounded nesting.** A depth limit, because a recursive decoder on hostile
  input is a stack overflow, and `RecursionError` is not the error type any caller
  catches.
* **Floats, tags, bignums.** Not needed. Anything unneeded is refused rather than
  parsed, since a type that is never expected is one whose handling is never
  tested.
"""

from __future__ import annotations

from typing import Any

from sentinel.domain.errors import DomainRuleViolated

__all__ = ["CborError", "decode", "decode_prefix"]

#: Nesting depth. COSE keys are flat; an attestation object is two deep.
MAX_DEPTH = 8
#: Elements in one map or array. An authenticator sends single digits.
MAX_ITEMS = 256
#: Bytes in one string. A credential id is 16-1023; a signature is under 200.
MAX_STRING = 8192


class CborError(DomainRuleViolated):
    """The input is not CBOR this decoder accepts. Always a refusal, never a guess."""


def decode(data: bytes) -> Any:
    """Decode one CBOR item and require the input to be fully consumed.

    The exhaustion check is the security-relevant half. In WebAuthn the
    `attestationObject` bytes are both parsed and (via `authData`) covered by a
    signature; a decoder that ignored trailing bytes would let a caller append
    content that the verifier never sees and the signature never covers.
    """
    value, offset = decode_prefix(data)
    if offset != len(data):
        raise CborError(
            f"{len(data) - offset} trailing bytes after the CBOR item. Refused: "
            "trailing content is how two parsers come to disagree about the same "
            "input, and here one component hashes these bytes while another parses "
            "them."
        )
    return value


def decode_prefix(data: bytes) -> tuple[Any, int]:
    """Decode one item, returning it and the offset just past it."""
    return _item(data, 0, 0)


def _item(data: bytes, offset: int, depth: int) -> tuple[Any, int]:
    if depth > MAX_DEPTH:
        raise CborError(f"CBOR nested deeper than {MAX_DEPTH}")
    if offset >= len(data):
        raise CborError("CBOR input ended mid-item")
    initial = data[offset]
    major, additional = initial >> 5, initial & 0x1F

    if additional == 31:
        raise CborError(
            "indefinite-length CBOR is refused: a stream that declares no length "
            "makes decoder termination depend on the input, and WebAuthn never "
            "uses it"
        )

    if major == 7:
        # Simple values only: false/true/null. Floats (25-27) and `undefined` are
        # refused because nothing here needs them.
        if additional == 20:
            return False, offset + 1
        if additional == 21:
            return True, offset + 1
        if additional == 22:
            return None, offset + 1
        raise CborError(f"unsupported CBOR simple value {additional}")

    length, offset = _argument(data, offset, additional)

    if major == 0:
        return length, offset
    if major == 1:
        return -1 - length, offset
    if major in (2, 3):
        if length > MAX_STRING:
            raise CborError(f"CBOR string of {length} bytes exceeds {MAX_STRING}")
        end = offset + length
        if end > len(data):
            raise CborError("CBOR string runs past the end of the input")
        raw = data[offset:end]
        if major == 2:
            return raw, end
        try:
            return raw.decode("utf-8"), end
        except UnicodeDecodeError as exc:
            raise CborError(f"CBOR text string is not valid UTF-8: {exc}") from exc
    if major == 4:
        if length > MAX_ITEMS:
            raise CborError(f"CBOR array of {length} items exceeds {MAX_ITEMS}")
        items: list[Any] = []
        for _ in range(length):
            value, offset = _item(data, offset, depth + 1)
            items.append(value)
        return items, offset
    if major == 5:
        if length > MAX_ITEMS:
            raise CborError(f"CBOR map of {length} pairs exceeds {MAX_ITEMS}")
        mapping: dict[Any, Any] = {}
        for _ in range(length):
            key, offset = _item(data, offset, depth + 1)
            if isinstance(key, (bytes, list, dict)):
                raise CborError(f"unhashable CBOR map key of type {type(key).__name__}")
            if key in mapping:
                # Last-wins would let the verifier read one value while the signed
                # bytes contain another.
                raise CborError(
                    f"duplicate CBOR map key {key!r}. Refused rather than resolved: "
                    "two parsers resolving a duplicate differently is a signature "
                    "bypass."
                )
            value, offset = _item(data, offset, depth + 1)
            mapping[key] = value
        return mapping, offset
    # Major type 6 is a semantic tag. Refused: a tag changes how the following item
    # should be interpreted, and honouring one means implementing its semantics.
    raise CborError(f"unsupported CBOR major type {major}")


def _argument(data: bytes, offset: int, additional: int) -> tuple[int, int]:
    """Read an item's length/value argument, rejecting non-minimal encodings.

    A non-minimal encoding -- writing 1 as a 4-byte integer -- is two byte strings
    that mean the same thing, so a hash over one does not match a hash over the
    other. Refusing them keeps the encoding canonical, which is what lets a
    signature over these bytes mean something.
    """
    if additional < 24:
        return additional, offset + 1
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
    if width is None:
        raise CborError(f"reserved CBOR additional information {additional}")
    start = offset + 1
    end = start + width
    if end > len(data):
        raise CborError("CBOR argument runs past the end of the input")
    value = int.from_bytes(data[start:end], "big")
    minimum = {1: 24, 2: 256, 4: 65536, 8: 4294967296}[width]
    if value < minimum:
        raise CborError(
            f"non-minimal CBOR encoding: {value} written in {width} bytes. Refused, "
            "because two encodings of one value hash differently and a signature "
            "over these bytes has to be unambiguous."
        )
    return value, end
