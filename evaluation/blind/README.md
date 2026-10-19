# Blind evaluation seals and results

This directory holds **seals** and **results**, never corpora.

A seal (`<digest12>.seal.json`) records the sha256 of a corpus assembled by
someone who has not read the policy, who assembled it, and when. It is
committed before any policy maintainer sees a case. A result
(`<digest12>.result-NN.json`) is produced by `evaluation/run_blind.py run`,
which refuses a corpus without a committed, matching seal and refuses a second
run unless it is acknowledged, in which case the result says `"blind": false`.

There are no seals here yet, so there is no blind detection evidence yet.
That is RISK R-005, and `docs/current/DETECTION_EVIDENCE.md` says the same.
