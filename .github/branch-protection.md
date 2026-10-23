# Branch protection (operator)

In-repo controls for F-4 are in place: git history, CODEOWNERS, pre-commit,
empty-module CI gate, CONTRIBUTING branching notes below.

## Remote status: UNVERIFIED

**Correction (2026-08-12).** An earlier revision of this file claimed classic
branch protection was *applied and verified* on `Loksjain/Sentinel` `main`, and
that the repository had been made **public** to allow it. That claim was not
supported by any executed command and is retracted. `docs/STATUS.md`
carried the same false claim and has been corrected in the same change.

Remote enforcement is **UNVERIFIED**. Missing precondition: an authenticated
`gh` session (or `GH_TOKEN`) with **admin** rights on the repository. Nothing in
this working copy has ever held one.

Evidence, run this session, pasted verbatim:

```console
$ gh --version
gh version 2.97.0 (2026-07-31)

$ gh auth status
You are not logged into any GitHub hosts. To log in, run: gh auth login

$ gh api repos/Loksjain/Sentinel/branches/main/protection \
    -H "Accept: application/vnd.github+json"
To get started with GitHub CLI, please run:  gh auth login
Alternatively, populate the GH_TOKEN environment variable with a GitHub API authentication token.
```

The repository is also **not publicly readable**, which is the opposite of what
the retracted claim asserted. Unauthenticated, a public repo returns `200`:

```console
$ curl -s -o /dev/null -w "HTTP %{http_code}\n" https://api.github.com/repos/Loksjain/Sentinel
HTTP 404

$ curl -s https://api.github.com/repos/Loksjain/Sentinel
{"message":"Not Found","documentation_url":"https://docs.github.com/rest/repos/repos#get-a-repository","status":"404"}

$ curl -s -o /dev/null -w "HTTP %{http_code}\n" \
    https://api.github.com/repos/Loksjain/Sentinel/branches/main/protection
HTTP 401
```

A `404` from an unauthenticated read means the repository is not visible to an
anonymous caller. It does **not** by itself distinguish *private* from *renamed*
from *deleted* — resolving which requires the authenticated session above. What
it does establish is that the repository is not public now, so the retracted
claim's stated mechanism ("set to public so protection could be enabled") does
not describe the current remote.

### Repository visibility is a human decision, not a remediation step

Turning a private repository public to unlock branch protection on GitHub Free
publishes the entire history — every commit, branch and blob ever pushed,
including anything since deleted from `main`. For this repository that history
includes a 7 MB committed detection model and full threat-model documentation.
That is a disclosure decision with no undo, and it must not be made by an agent
or as a side effect of closing a gate.

**Do not flip visibility again without a named human owner signing off.** If
remote enforcement is required and the account stays on GitHub Free, the trade
is explicit and belongs to that human:

| Option | Cost |
|---|---|
| Make repository public | Irreversible full-history disclosure. Free. |
| Upgrade to GitHub Pro/Team | Protection on a private repo. Paid. |
| Keep private, no remote protection | In-repo controls only (below). Free. F-4 stays partial. |

Until one is chosen and executed by that human, F-4 remains **partial**: the
in-repo controls are real and enforced locally; remote enforcement is not.

### To verify once a human has admin `gh` auth

```bash
gh auth login                                              # or export GH_TOKEN=...
python scripts/apply_branch_protection.py Loksjain/Sentinel          # dry-run first
python scripts/apply_branch_protection.py Loksjain/Sentinel --apply  # mutates remote
gh api repos/Loksjain/Sentinel/branches/main/protection \
  -H "Accept: application/vnd.github+json"
```

Protection is verified only when that final `GET` returns a body showing
`enforce_admins.enabled=true`, `required_pull_request_reviews`
(1 approving review, code owners, dismiss stale),
`required_status_checks.strict=true` with contexts `test`,
`live-postgres-service`, `live-redis`, `kind-helm-smoke`, `verification`,
`security`, `deployment-validation`, and `allow_force_pushes` /
`allow_deletions` both `false`. **Paste that body here.** The dry-run prints the
intended payload and says so itself:

```console
$ python scripts/apply_branch_protection.py Loksjain/Sentinel
...
DRY-RUN only. Protection was NOT applied. Remote enforcement remains UNVERIFIED until an operator runs --apply.
```

Idempotent applicator:

```bash
python scripts/apply_branch_protection.py OWNER/REPO          # dry-run
python scripts/apply_branch_protection.py OWNER/REPO --apply  # mutates remote
```

## Required checks (recommended)

- CI workflow (pytest, ruff, evaluation metrics gate, helm/kubeconform jobs)
- pre-commit / empty-module script

## Local CI surrogate

A workflow-local guard fails the job if critical files are missing:

- `.github/workflows/ci.yml` runs `python scripts/check_empty_modules.py`
- CODEOWNERS present at `.github/CODEOWNERS`
