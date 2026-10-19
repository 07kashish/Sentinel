# Controls blocked by the repository plan

Two required controls cannot be enforced on this repository, for the
same underlying reason: it is a **user-owned private repository**, and
both features require a different plan or a public repository.

| Control | Spec | Status |
|---|---|---|
| Branch protection | §11 | `403 — Upgrade to GitHub Pro` |
| SLSA build provenance | §12 | `Feature not available for user-owned private repositories` |

**What is NOT blocked:** cosign keyless signing works and is verified in
CI on every run (`Verified OK`). The detached signature over the release
manifest is the attestation this build actually relies on; SLSA
provenance would be additive. §12 is therefore substantially met — the
artifacts are signed and the signature is checked — with the GitHub-native
attestation store as the missing piece.

---

## Branch protection — required settings

**Status: NOT ENFORCED BY THE REPOSITORY. This document is the control.**

§11 treats source-control integrity as a product-security requirement. That
requirement is currently unmet, and this document exists so the gap is written
down rather than assumed handled.

## Why it is unmet

Queried against this repository:

```
GET /repos/Loksjain/Sentinel/branches/main/protection
→ 403  "Upgrade to GitHub Pro or make this repository public
        to enable this feature."
```

Branch protection is unavailable on a private repository under the current
plan. This is a billing and hosting decision, not an engineering one, and no
amount of code in this repository can substitute for it.

## What this means today, stated plainly

Anyone with write access can push directly to `main`. There is no enforced
review, and CI cannot block a merge — it can only report after the fact. A
merge queue does not exist.

This has already happened at least once in this repository's history: a pull
request merged while its own CI was still failing, putting a broken build on
`main`. That was a symptom of exactly this gap.

## Required settings, for whoever can apply them

Apply on `main` and on any `release/*` branch, once the plan permits:

| Setting | Required value | Why |
|---|---|---|
| Require a pull request before merging | on | No direct pushes to the release branch |
| Required approvals | ≥ 1 | A second pair of eyes on security-relevant change |
| Dismiss stale approvals on new commits | on | An approval is of a diff, not of a branch name |
| Require status checks to pass | on | The gate that was missing when a red build reached `main` |
| Required checks | `test`, `security`, `dynamic-api-security`, `verification`, `deployment-validation`, `docker`, `kind-helm-smoke`, `live-postgres`, `live-redis`, `live-minio`, `live-postgres-service` | The full CI surface; a subset lets a failing job through |
| Require branches to be up to date | on | Prevents a green result measured against a stale base |
| Require conversation resolution | on | An unresolved review comment is unfinished work |
| Require signed commits | on | Pairs with the artifact signing in §12 |
| Include administrators | **on** | A rule administrators can bypass is a convention, not a control |
| Allow force pushes | off | History is evidence |
| Allow deletions | off | — |

## Interim mitigation

Until the setting can be applied, the compensating controls are weak and should
be understood as weak:

- CI runs on every push and every pull request, so a failure is *visible* even
  though it is not *blocking*.
- `release/readiness.json` records which gates were verified for a given commit,
  so a build that skipped gates can be identified after the fact.

Neither prevents a direct push. They only make one detectable afterwards, and
"detectable afterwards" is not what §11 asks for.

## How to close this

One of:

1. Upgrade the repository's plan to one that includes branch protection for
   private repositories, then apply the table above.
2. Make the repository public (not appropriate for proprietary source).
3. Move to a host where protected branches are available on the current tier.

Option 1 is the expected path. Until it happens, this gate is **UNVERIFIED** in
`release/readiness.json` and must not be reported as satisfied.
