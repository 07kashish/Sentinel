# AI / model evaluation (F-10)

## Role of AI in Sentinel

- Deterministic policy remains the structured-event control path
  (`DeterministicPolicy` @ 1.4.0 for files/hosts/shell).
- Soft prompt classifier (char n-gram LR) is OR'd for free-text prompt fields via
  `SoftAugmentedPolicy` when `SENTINEL_SOFT_PROMPT_DETECT=1` (default) and the
  artifact exists at `evaluation/artifacts/soft_prompt_model.pkl`.
- LLM / model advisor remains advisory-only.

### When the artifact does not load

Loading it needs `scikit-learn==1.4.0` — pinned in `requirements.txt`, and
matched to the version recorded inside the pickle (`_sklearn_version` → `1.4.0`).
Bump one without retraining the other and the artifact stops loading.

That path is no longer silent. Detection falls back to the deterministic rules —
**0.067** independent English recall against **0.855** for soft+rules, the two
rows in the table below — and the composition root logs CRITICAL, sets
`sentinel_detection_degraded 1.0`, and reports `detection_mode` on
`/health/diagnostics`. See `docs/OBSERVABILITY.md`. The fallback is still a
severe loss of capability; it is now merely an observable one.

## Evaluation infrastructure

| Artifact | Path |
|---|---|
| Hand corpus (CI gate) | `evaluation/corpus.py` |
| Same-source synthetic (42 cases) | `evaluation/same_source_corpus.py` |
| Independent third-party benchmark | `evaluation/benchmark.py` + `benchmark_manifest.json` |
| Soft model train (TRAIN split only) | `evaluation/train_classifier.py` → `evaluation/artifacts/` |
| Soft loader | `evaluation/soft_prompt.py`, `sentinel/infrastructure/soft_detection.py` |
| Promotion gate | `evaluation/promotion.py` (floor `min_recall=0.70`) |
| Runner (hand) | `evaluation/metrics.py` → `evaluation/metrics.json` |
| Runner (independent) | `evaluation/run_benchmark.py` |

## Measured metrics (this session)

### Hand corpus (CI regression)

Command: `PYTHONPATH=. python evaluation/metrics.py --json evaluation/metrics.json`

| Metric | Primary (22-case) | Same-source synth (42) |
|---|---|---|
| Precision | 1.0 | 0.952 |
| Recall | 0.786 | 0.952 |
| F1 | 0.880 | 0.952 |
| Unexpected misses | [] | n/a |

Promotion on hand corpus: **allowed** (recall 0.786 ≥ 0.70). Floor unchanged.

### Independent English held-out (product-grade claim)

Commands:

```
PYTHONPATH=. py evaluation/train_classifier.py
PYTHONPATH=. py evaluation/run_benchmark.py --test --english
PYTHONPATH=. py evaluation/run_benchmark.py --test --english --soft
```

| Detector | Cases | Recall | Precision | FPR | Promotion |
|---|---|---|---|---|---|
| Rules only (`sentinel-default@1.4.0`) | 512 | 0.067 | 1.000 | 0.000 | refused |
| SoftAugmentedPolicy (rules OR soft@0.5) | 512 | **0.855** | **0.972** | 0.044 | **allowed** |

Evidence: `evaluation/results/benchmark_test_english.json`,
`evaluation/results/benchmark_test_english_soft.json`,
`tests_arch/test_soft_detection_independent.py`.

Provenance: deepset/prompt-injections (Apache-2.0), jackhhao/jailbreak-classification
(Apache-2.0), Lakera/gandalf_ignore_instructions (MIT), DAMO-NLP-SG/MultiJail (MIT),
google/xquad (CC-BY-SA-4.0), Snaseem2026/synthetic-multilingual-instructions
(Apache-2.0). Manifest verified this session (`verify_manifest` ok).

## F-10 status: CLOSED (English independent soft path)

Closing criteria met this session: independently sourced labeled traffic, measured
recall ≥ 0.70, promotion gate allowed, soft path wired into product composition
when the artifact is present.

Still **not** claimed: multilingual detection (class-language confound — see
`evaluation/BENCHMARK.md`). Rules-only independent English remains far below the
floor and must not be quoted as product efficacy.
