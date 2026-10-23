# The evaluation benchmark: what it measures, and what it cannot

## Dataset limitations

Every non-English attack in this benchmark comes from one source (MultiJail).
Benign non-English text had to be sourced separately, and coverage remains thin
and style-mismatched. A model can therefore score near-perfectly by recognising
the language, not the threat.

Four languages (Korean, Bengali, Swahili, Javanese) still have zero benign cases.
Do not quote the multilingual result as validated detection capability.

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

**Production code path.** The harness calls `sentinel.infrastructure.detection.DeterministicPolicy`,
the same rules policy the API calls. An earlier version of the harness put the prompt
in a field no rule reads and reported a uniform recall of 0.000 — a harness bug
that looked like total detector failure. Scoring the real path is the point.

**Obfuscation cases are derived, labelled, and reported separately.** Only attacks
are transformed: a mangled benign prompt is not reliably still benign, and
assigning it a label would be the fabrication this benchmark exists to avoid.

## Reproducing

```sh
python evaluation/run_benchmark.py        # TRAIN (development)
python evaluation/run_benchmark.py --test # held-out (report this)
```

Detection remains **OPEN** for product claims. The CI gate
(`evaluation/metrics.py`) fails the build on unmarked regressions and labels
known gaps in `evaluation/corpus.py`.
