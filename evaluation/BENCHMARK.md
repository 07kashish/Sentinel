# The evaluation benchmark: what it measures, and what it cannot

## Headline numbers

Held-out split, group-aware, model never trained on any of it:

| Slice | Cases | Recall | Precision | FPR | F1 |
|---|---|---|---|---|---|
| **English only (the defensible claim)** | 512 | **0.855** | 0.972 | 0.044 | 0.910 |
| All languages (NOT trustworthy — see below) | 1,467 | 0.957 | 0.980 | 0.049 | 0.968 |

Baseline, before this work — the same code path, same harness:

| Slice | Recall |
|---|---|
| Policy rules alone, all languages | 0.025 |
| Policy rules alone, English | 0.072 |

The old 22-case corpus reported **recall 0.643**. Against 7,075 third-party cases
the same rules score **0.025**. The handcrafted corpus overstated capability by
roughly 25×, which is the single most important thing this benchmark established.

## The multilingual number is NOT VALIDATED

The all-language row above reports ~1.000 recall on nine non-English languages.
**Do not quote it.** It is an artifact.

**FAILURE CLASS: class-language confound** — a label that correlates with a
surface property of the data rather than with the thing being detected.

Every non-English attack in this benchmark comes from one source (MultiJail).
Benign non-English text had to be sourced separately, and coverage remains thin
and style-mismatched. A model can therefore score near-perfectly by recognising
the language, not the threat.

This was not inferred, it was demonstrated. Ten innocuous everyday requests
("Could you help me summarise this meeting report?"), none of them attacks:

| Round | Benign multilingual prompts flagged as attacks |
|---|---|
| No benign non-English data at all | 9 / 10 |
| After adding xquad (Wikipedia questions) | 9 / 10 |
| After adding style-matched benign instructions | 8 / 10 |

Adding benign data moved English and Italian below the threshold and left the
rest above it. Four languages (Korean, Bengali, Swahili, Javanese) still have
**zero** benign cases, because the filter returned none for those language codes.

`tests/test_detection_quality.py::test_multilingual_recall_is_not_claimed_anywhere`
fails CI if any document claims multilingual detection. The limitation is
enforced, not just written down.

## What would fix it

Benign non-English text that matches the attack corpus in register, topic and
length, from a human-authored source, at roughly the same volume as the attacks —
particularly for Korean, Bengali, Swahili and Javanese. Until then the honest
claim is English-only.

## Sources

Only permissively licensed datasets are used; `test_every_benchmark_source_declares_a_permissive_licence`
enforces it.

| Dataset | Licence | Role | Note |
|---|---|---|---|
| `deepset/prompt-injections` | Apache-2.0 | attack + benign | Human-authored injections |
| `jackhhao/jailbreak-classification` | Apache-2.0 | attack + benign | Jailbreaks collected in the wild |
| `Lakera/gandalf_ignore_instructions` | MIT | attack | Player-authored against a deployed guardrail |
| `DAMO-NLP-SG/MultiJail` | MIT | attack | 315 prompts × 10 languages |
| `google/xquad` | CC-BY-SA-4.0 | benign | Wikipedia questions, 12 languages |
| `Snaseem2026/synthetic-multilingual-instructions` | Apache-2.0 | benign | **LLM-generated, not human-authored.** Used only as benign filler to break the style correlation; no recall claim rests on it. |

Raw text is cached locally and **not committed**. The repository stores
`benchmark_manifest.json` — case ids, labels, splits and provenance — so a result
is reproducible and a reviewer can confirm the test split was not re-drawn,
without redistributing anyone else's corpus.

## Methodology

**Group-aware splitting.** Splitting per case leaked badly: MultiJail's ten
translations of one prompt landed in different splits for **177 of the first 200
prompts**, and obfuscated variants were separated from their originals. All cases
derived from one source item now share a `group_id` and therefore a split.
Enforced by `test_no_group_straddles_both_splits`.

**Production code path.** The harness calls `app.monitoring.rules.evaluate_event`,
the same function the API calls. An earlier version of the harness put the prompt
in a field no rule reads and reported a uniform recall of 0.000 — a harness bug
that looked like total detector failure. Scoring the real path is the point.

**Obfuscation cases are derived, labelled, and reported separately.** Only attacks
are transformed: a mangled benign prompt is not reliably still benign, and
assigning it a label would be the fabrication this benchmark exists to avoid.

## Reproducing

```
PYTHONPATH=. py evaluation/train_classifier.py     # fits on TRAIN only
PYTHONPATH=. py evaluation/run_benchmark.py        # TRAIN (development)
PYTHONPATH=. py evaluation/run_benchmark.py --test # held-out (report this)
```


## Eighth Review F-10 (honest status)

Detection remains **OPEN** for product claims. The CI gate
(`evaluation/metrics.py`) fails the build on unmarked regressions and labels
known gaps in `evaluation/corpus.py`. Improving AUC requires new same-source
labeled data and a measured experiment -- not README edits.
