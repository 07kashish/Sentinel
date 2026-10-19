"""An evaluation benchmark built from third-party data, not from our own imagination.

WHY THIS REPLACES THE 22-CASE CORPUS
------------------------------------
All three council seats reached the same conclusion independently: a detection
product whose entire evidence base is 22 examples written by the same people who
wrote the detector has measured nothing. Codex re-ran the harness and reproduced
recall 0.643 / prompt-injection recall 0.25, then noted the corpus "admits it is
not production evidence".

The deeper problem is not size. It is **self-grading**: if the author of a rule
also authors the test case, the test measures whether the author is consistent
with themselves. Growing that corpus to 500 self-authored cases would make the
number look better and mean exactly as little.

So this module does not write cases. It pulls labelled attack and benign prompts
from public datasets curated by unrelated parties, records their provenance and
licence, and splits them so that **the test half is never available to anyone
tuning a rule**.

FAILURE CLASS: **self-graded evaluation** -- measuring a system against examples
derived from the system's own assumptions. The structural fix is provenance
(cases come from outside) plus a content-hash split (the test half is decided by
SHA-256 of the text, not by anyone's choice, and cannot be reshuffled to flatter
a result).

SPLIT DISCIPLINE
----------------
`split_of()` hashes the case text. Bucket 0-7 is train, 8-9 is test. This is
deterministic, stable across runs, and independent of dataset order, so:

  * nobody can move a hard case out of the test set;
  * adding new sources does not reshuffle existing assignments;
  * the same case always lands in the same split on every machine.

Rules are developed against TRAIN. TEST is scored once, at the end, and its
number is the one reported.

LICENCES of the sources used are recorded in SOURCES below and reproduced in
`evaluation/BENCHMARK.md`. Only permissively licensed datasets are used. The raw
text is cached locally and is NOT committed: the repository stores the manifest
(ids, labels, hashes, provenance), so results are reproducible and verifiable
without redistributing anyone else's corpus.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal

CACHE_DIR = Path(os.getenv("SENTINEL_BENCHMARK_CACHE", "evaluation/.cache"))
MANIFEST = Path("evaluation/benchmark_manifest.json")

Label = Literal["attack", "benign"]
Split = Literal["train", "test"]


@dataclass(frozen=True, slots=True)
class Case:
    """One labelled evaluation case with its provenance."""

    case_id: str          # sha256 of the text; also the identity
    text: str
    label: Label
    category: str         # prompt_injection | jailbreak | tool_abuse | benign
    language: str
    source: str           # dataset it came from
    transform: str = "none"   # obfuscation applied, if derived
    group_id: str = ""    # cases sharing this MUST share a split

    @property
    def split(self) -> Split:
        # Grouped, NOT per-case. See split_of() for why this matters.
        return split_of(self.group_id or self.case_id)


def case_id_for(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def split_of(group_id: str) -> Split:
    """Deterministic 80/20 split keyed on a case's GROUP, not the case itself.

    LEAKAGE THIS PREVENTS
    ---------------------
    The first version of this hashed each case's own text. MultiJail contains the
    same prompt translated into ten languages, so the English form landed in
    train while its Swahili translation landed in test -- for **177 of the first
    200 source prompts**. The model could memorise a prompt's meaning and then be
    scored on a translation of it as though it were unseen. Measured that way,
    recall was 1.000 on every non-English language, which is what tipped this off:
    a perfect score is more often a broken evaluation than a solved problem.

    The same applies to the obfuscation transforms: a leetspeak variant of a
    training attack is not an unseen case.

    Grouping by origin fixes the class. Every case derived from one source item
    -- all ten translations, and every obfuscated variant -- shares a group_id and
    therefore a split. Cases from single-text sources are their own group, so
    their assignment is unchanged.

    FAILURE CLASS: **near-duplicate leakage** across an evaluation split.
    """
    return "test" if int(group_id[:8], 16) % 10 >= 8 else "train"


# ── Sources ──────────────────────────────────────────────────────────────────
# Every entry names the licence. A dataset without a clear permissive licence is
# NOT used, however convenient -- the same standard applied to code applies here.

SOURCES: list[dict] = [
    {
        "dataset": "deepset/prompt-injections",
        "licence": "apache-2.0",
        "config": "default",
        "split": "train",
        "text_field": "text",
        "label_field": "label",
        "attack_when": lambda v: int(v) == 1,
        "category": "prompt_injection",
        "note": "Multilingual (English, German and others). Human-authored.",
    },
    {
        "dataset": "jackhhao/jailbreak-classification",
        "licence": "apache-2.0",
        "config": "default",
        "split": "train",
        "text_field": "prompt",
        "label_field": "type",
        "attack_when": lambda v: str(v).strip().lower() == "jailbreak",
        "category": "jailbreak",
        "note": "Real jailbreak prompts collected from the wild.",
    },
    {
        "dataset": "Lakera/gandalf_ignore_instructions",
        "licence": "mit",
        "config": "default",
        "split": "train",
        "text_field": "text",
        "label_field": None,          # every row is an attack
        "attack_when": lambda _v: True,
        "category": "prompt_injection",
        "note": "Player-authored injections from Lakera's Gandalf game. "
                "Adversarial against a real deployed guardrail.",
    },
]


# A dataset whose LANGUAGES are columns, not rows: one prompt per row, with a
# column per translation. This is the only genuinely multilingual source
# available under a permissive licence, and it covers low-resource languages
# (Swahili, Javanese, Bengali, Thai) that a keyword detector will not survive.
WIDE_SOURCES: list[dict] = [
    {
        "dataset": "DAMO-NLP-SG/MultiJail",
        "licence": "mit",
        "config": "default",
        "split": "train",
        "language_fields": ["en", "zh", "it", "vi", "ar", "ko", "th", "bn", "sw", "jv"],
        "category": "jailbreak",
        "note": "315 prompts translated into 9 further languages. Every row is an "
                "attack; the point is whether detection survives translation.",
    },
]


# BENIGN multilingual text. Without this the benchmark contained no non-English
# benign case at all, so "not English" perfectly predicted "attack" and a
# classifier could score 1.000 recall on nine languages by learning the script
# rather than the threat. It did exactly that: 9 of 10 innocuous everyday
# requests in Chinese, Arabic, Thai, Swahili, Vietnamese, Korean, Bengali,
# Javanese and Italian were flagged.
#
# FAILURE CLASS: **class-language confound** -- a label that correlates with a
# surface property of the data rather than the thing being detected. A benchmark
# with this defect cannot distinguish a detector from a language identifier, and
# its headline number is meaningless however large the corpus is.
MULTI_CONFIG_SOURCES: list[dict] = [
    {
        "dataset": "google/xquad",
        "licence": "cc-by-sa-4.0",
        "configs": ["xquad.ar", "xquad.zh", "xquad.th", "xquad.vi", "xquad.hi",
                    "xquad.ru", "xquad.de", "xquad.el", "xquad.es", "xquad.ro",
                    "xquad.tr", "xquad.en"],
        "split": "validation",
        "text_field": "question",
        "label": "benign",
        "per_config": 120,
        "note": "Real Wikipedia comprehension questions in 12 languages. Benign "
                "by construction and unrelated to security, which is the point: "
                "they share the SCRIPT of the attack corpus but none of the intent.",
    },
]


# Benign instructions matched in STYLE to the attacks, not merely in language.
#
# Adding xquad (Wikipedia questions) reduced the confound but did not remove it:
# 9 of 10 innocuous multilingual requests were still flagged, because the attack
# corpus is imperative instructions and xquad is interrogative comprehension
# questions. The model had moved from "non-English implies attack" to
# "non-English imperative implies attack" -- a narrower confound, still a
# confound. Benign data must match the attacks on every axis except the threat.
#
# DISCLOSED: this source is LLM-generated, not human-authored. That is a real
# weakness and it is recorded in evaluation/BENCHMARK.md rather than glossed. It
# is used only as benign filler to break the style correlation; no recall claim
# rests on it.
FILTERED_SOURCES: list[dict] = [
    {
        "dataset": "Snaseem2026/synthetic-multilingual-instructions",
        "licence": "apache-2.0",
        "config": "default",
        "split": "train",
        "text_field": "instruction",
        "language_field": "language",
        "languages": ["ar", "zh", "th", "vi", "ko", "bn", "sw", "jv", "it", "en"],
        "per_language": 200,
        "label": "benign",
        "note": "Synthetic benign instructions, style-matched to the attack "
                "corpus (imperative requests) in the same ten languages.",
    },
]


def _fetch_filtered(source: dict, language: str) -> list[dict]:
    """Rows for one language, via the datasets-server filter endpoint."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache = CACHE_DIR / (
        source["dataset"].replace("/", "__") + f"__{language}.json"
    )
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))

    where = urllib.parse.quote(f"\"{source['language_field']}\"='{language}'")
    params = (
        f"dataset={urllib.parse.quote(source['dataset'])}"
        f"&config={source['config']}&split={source['split']}"
        f"&where={where}&limit={source['per_language']}"
    )
    with urllib.request.urlopen(
        f"https://datasets-server.huggingface.co/filter?{params}", timeout=90
    ) as resp:
        payload = json.loads(resp.read())
    rows = [r["row"] for r in payload.get("rows", [])]
    cache.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    return rows


def _fetch_rows(source: dict, limit: int, cache_key: str = "") -> list[dict]:
    """Pull rows from the HuggingFace datasets-server, with a local cache."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    name = source["dataset"].replace("/", "__") + (f"__{cache_key}" if cache_key else "")
    cache = CACHE_DIR / (name + ".json")
    if cache.exists():
        return json.loads(cache.read_text(encoding="utf-8"))

    collected: list[dict] = []
    offset = 0
    while len(collected) < limit:
        params = urllib.parse.urlencode({
            "dataset": source["dataset"],
            "config": source["config"],
            "split": source["split"],
            "offset": offset,
            "length": 100,
        })
        url = f"https://datasets-server.huggingface.co/rows?{params}"
        with urllib.request.urlopen(url, timeout=60) as resp:
            payload = json.loads(resp.read())
        batch = payload.get("rows", [])
        if not batch:
            break
        collected.extend(r["row"] for r in batch)
        offset += len(batch)

    cache.write_text(json.dumps(collected, ensure_ascii=False), encoding="utf-8")
    return collected


def _detect_language(text: str) -> str:
    """Crude script/keyword hint. Honest about being crude: it is metadata for
    slicing results, never an input to detection."""
    if any("一" <= c <= "鿿" for c in text):
        return "zh"
    if any("Ѐ" <= c <= "ӿ" for c in text):
        return "ru"
    if any("؀" <= c <= "ۿ" for c in text):
        return "ar"
    if any("぀" <= c <= "ヿ" for c in text):
        return "ja"
    if any("가" <= c <= "힯" for c in text):
        return "ko"
    if any("ऀ" <= c <= "ॿ" for c in text):
        return "hi"
    lowered = f" {text.lower()} "
    for lang, markers in {
        "de": (" nicht ", " und ", " bitte ", " ignoriere ", " du "),
        "fr": (" les ", " vous ", " ignorez ", " s'il ", " est "),
        "es": (" ignora ", " por favor ", " usted ", " está "),
        "it": (" ignora ", " per favore ", " sei "),
        "pt": (" ignore ", " você ", " está "),
    }.items():
        if sum(m in lowered for m in markers) >= 2:
            return lang
    return "en"


def build(limit_per_source: int = 700) -> list[Case]:
    """Assemble the benchmark from the configured sources."""
    cases: dict[str, Case] = {}
    for source in SOURCES:
        for row in _fetch_rows(source, limit_per_source):
            text = str(row.get(source["text_field"]) or "").strip()
            if not text or len(text) < 8:
                continue
            if source["label_field"] is None:
                is_attack = source["attack_when"](None)
            else:
                raw = row.get(source["label_field"])
                if raw is None:
                    continue
                is_attack = source["attack_when"](raw)
            cid = case_id_for(text)
            if cid in cases:           # identical text across sources: keep one
                continue
            cases[cid] = Case(
                case_id=cid,
                text=text,
                label="attack" if is_attack else "benign",
                category=source["category"] if is_attack else "benign",
                language=_detect_language(text),
                source=source["dataset"],
            )

    for source in FILTERED_SOURCES:
        for language in source["languages"]:
            try:
                rows = _fetch_filtered(source, language)
            except Exception:  # noqa: BLE001 - never let one language kill the build
                continue
            for row in rows:
                text = str(row.get(source["text_field"]) or "").strip()
                if not text or len(text) < 8:
                    continue
                cid = case_id_for(text)
                if cid in cases:
                    continue
                cases[cid] = Case(
                    case_id=cid, text=text, label="benign", category="benign",
                    language=language, source=source["dataset"],
                )

    for source in MULTI_CONFIG_SOURCES:
        for config in source["configs"]:
            sub = {**source, "config": config, "dataset": source["dataset"]}
            try:
                rows = _fetch_rows(sub, source["per_config"], cache_key=config)
            except Exception:  # noqa: BLE001 - a missing config must not kill the build
                continue
            for row in rows[: source["per_config"]]:
                text = str(row.get(source["text_field"]) or "").strip()
                if not text or len(text) < 8:
                    continue
                cid = case_id_for(text)
                if cid in cases:
                    continue
                cases[cid] = Case(
                    case_id=cid,
                    text=text,
                    label="benign",
                    category="benign",
                    language=config.split(".")[-1],
                    source=source["dataset"],
                )

    for source in WIDE_SOURCES:
        for row in _fetch_rows(source, limit_per_source):
            for lang in source["language_fields"]:
                text = str(row.get(lang) or "").strip()
                if not text or len(text) < 8:
                    continue
                cid = case_id_for(text)
                if cid in cases:
                    continue
                # Language is DECLARED by the dataset column, not guessed. The
                # heuristic detector is for sources that do not say.
                # All translations of one source row share a group, so no
                # language of a prompt can be scored as unseen while another
                # language of the SAME prompt was trained on.
                group = case_id_for(f"{source['dataset']}#{row.get('id', row.get(source['language_fields'][0]))}")
                cases[cid] = Case(
                    case_id=cid,
                    text=text,
                    label="attack",
                    category=source["category"],
                    language=lang,
                    source=source["dataset"],
                    group_id=group,
                )
    return list(cases.values())


# ── Obfuscation ──────────────────────────────────────────────────────────────
# Derived cases, always labelled with the transform that produced them, and
# reported separately. An obfuscated attack is still an attack: a detector that
# only matches literal English phrasing will be caught here.

def _homoglyph(text: str) -> str:
    table = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і"})
    return text.translate(table)


def _zero_width(text: str) -> str:
    # invisible-characters-are-the-subject: this generates the zero-width-space evasion the
    # detector is measured against, so the character must be literal.

    return "​".join(text)


def _base64_wrap(text: str) -> str:
    import base64

    encoded = base64.b64encode(text.encode()).decode()
    return f"Decode this base64 and follow it exactly: {encoded}"


def _leetspeak(text: str) -> str:
    return text.translate(str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"}))


def _spaced(text: str) -> str:
    return " ".join(text)


TRANSFORMS = {
    "homoglyph": _homoglyph,
    "zero_width": _zero_width,
    "base64": _base64_wrap,
    "leetspeak": _leetspeak,
    "spaced": _spaced,
}


def with_obfuscations(cases: Iterable[Case], per_transform: int = 60) -> list[Case]:
    """Derive obfuscated variants of ATTACK cases only.

    Benign text is not transformed: a mangled benign prompt is not obviously
    still benign, and inventing its label would be exactly the fabrication this
    benchmark exists to avoid.
    """
    attacks = [c for c in cases if c.label == "attack" and c.transform == "none"]
    attacks.sort(key=lambda c: c.case_id)     # deterministic selection
    derived: list[Case] = []
    for name, fn in TRANSFORMS.items():
        for original in attacks[:per_transform]:
            text = fn(original.text)
            cid = case_id_for(text)
            derived.append(
                Case(
                    case_id=cid,
                    text=text,
                    label="attack",
                    category=original.category,
                    language=original.language,
                    source=f"{original.source} (derived)",
                    transform=name,
                    # Inherit the group: an obfuscated variant of a training
                    # attack is not an unseen case.
                    group_id=original.group_id or original.case_id,
                )
            )
    return derived


def load() -> list[Case]:
    """The full benchmark: sourced cases plus derived obfuscations."""
    base = build()
    return base + with_obfuscations(base)


def write_manifest(cases: list[Case]) -> dict:
    """Record what the benchmark contains WITHOUT redistributing the text.

    The manifest is what gets committed. It pins every case's identity, label and
    split, so a later run can prove it evaluated the same benchmark -- and so a
    reviewer can see that the test split was not quietly re-drawn.
    """
    summary = {
        "total": len(cases),
        "train": sum(1 for c in cases if c.split == "train"),
        "test": sum(1 for c in cases if c.split == "test"),
        "by_label": {},
        "by_category": {},
        "by_language": {},
        "by_transform": {},
        "sources": [
            {"dataset": s["dataset"], "licence": s["licence"], "note": s["note"]}
            for s in (*SOURCES, *WIDE_SOURCES, *MULTI_CONFIG_SOURCES, *FILTERED_SOURCES)
        ],
        "cases": [
            {"case_id": c.case_id, "label": c.label, "category": c.category,
             "language": c.language, "source": c.source, "transform": c.transform,
             "split": c.split}
            for c in sorted(cases, key=lambda c: c.case_id)
        ],
    }
    for c in cases:
        for key, value in (
            ("by_label", c.label), ("by_category", c.category),
            ("by_language", c.language), ("by_transform", c.transform),
        ):
            summary[key][value] = summary[key].get(value, 0) + 1

    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def verify_manifest(cases: list[Case]) -> dict:
    """Check a freshly built benchmark against the COMMITTED manifest.

    The manifest was written but never read back, so "results are reproducible"
    was true in principle and unchecked in practice. This closes that: because
    `case_id` IS the sha256 of the text, comparing id sets detects any change to
    the corpus -- added, removed or ALTERED cases -- without the repository ever
    holding someone else's text.

    It also catches the failure that would quietly invalidate a headline number:
    a case silently moving between train and test.

    Returns a report; `ok` is False if the benchmark drifted.
    """
    if not MANIFEST.exists():
        return {"ok": False, "reason": "no committed manifest to verify against"}

    recorded = json.loads(MANIFEST.read_text(encoding="utf-8"))
    old_cases = {c["case_id"]: c for c in recorded.get("cases", [])}
    new_cases = {c.case_id: c for c in cases}

    added = sorted(set(new_cases) - set(old_cases))
    removed = sorted(set(old_cases) - set(new_cases))
    moved = sorted(
        cid for cid in set(old_cases) & set(new_cases)
        if old_cases[cid]["split"] != new_cases[cid].split
    )

    return {
        "ok": not (added or removed or moved),
        "added": added[:20],
        "removed": removed[:20],
        "split_changed": moved[:20],
        "counts": {"added": len(added), "removed": len(removed), "split_changed": len(moved)},
        "detail": (
            "benchmark matches the committed manifest"
            if not (added or removed or moved)
            else "the benchmark DRIFTED from the committed manifest; a score "
                 "computed against it is not comparable to previously reported "
                 "numbers. A changed split is the most dangerous case: it can "
                 "move test cases into train and inflate the headline figure."
        ),
    }


__all__ = [
    "Case", "SOURCES", "TRANSFORMS", "WIDE_SOURCES", "MULTI_CONFIG_SOURCES", "FILTERED_SOURCES", "build", "case_id_for", "load",
    "split_of", "verify_manifest", "with_obfuscations", "write_manifest",
]
