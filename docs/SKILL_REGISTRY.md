# Skill registry: agent capabilities as supply-chain artefacts

## Why skills need their own model

`docs/MCP_GATEWAY.md` treats an MCP tool definition as a thing whose identity is
a fingerprint, because a tool that changes after approval presents the same
**name** to the same allowlist.

A skill — a plugin, an extension, an installable agent capability — is the same
problem with a worse blast radius. An MCP tool is a remote call to a server
somebody operates. A skill is **code that runs where the agent runs**, with the
agent's credentials and the agent's network position.

So a skill gets what a dependency gets: a publisher, a version, an integrity
hash, a declared permission set, and a record of what changed since approval.

## Explainable risk, never a magic number

`assess` returns **factors**. Every point names the thing that produced it.

```json
{
  "score": 100,
  "severity": "critical",
  "factors": [
    {"factor": "scan:obfuscated_exec", "points": 45,
     "reason": "executes the result of a decode..."},
    {"factor": "permission:execute_code", "points": 40,
     "reason": "declares the execute_code permission"},
    {"factor": "scan:secret_path", "points": 35,
     "reason": "references '.aws/credentials', a well-known credential location"}
  ]
}
```

An analyst who cannot see what contributed cannot tell a genuine finding from a
scoring artefact, and a score nobody can explain is one nobody acts on
(`test_every_point_is_attributable_to_a_named_factor`).

The factors are properties of the **artefact**, not predictions about behaviour.
"This package imports `subprocess`" is a fact. "This package is malicious" is not
something static inspection can say, and nothing here says it.

The score is capped at 100 (`test_the_score_is_capped_so_the_top_stays_meaningful`):
an uncapped score makes "very bad" and "catastrophic" indistinguishable, and the
decisions above HIGH are the same either way.

## Drift is the primary signal

A skill that was reviewed and has not changed is a skill somebody looked at. The
same skill at a new version, from a new publisher, or requesting a permission it
did not previously request, is a **new artefact wearing an approved name**.

| Change | Weight | Why |
|---|---|---|
| `publisher_changed` | 45 | how supply-chain takeover actually looks |
| `permission_expanded` | 35 | new reach nobody reviewed |
| `destination_added` | 25 | a new place data can go |
| `artifact_changed` | 20 | the bytes are not the bytes that were approved |
| `version_changed` | 5 | what a maintained package does every week |
| `permission_reduced` | 0 | an improvement |

A version bump is expected; a publisher changing underneath a pinned name is
not. Rating them equally would bury the second in the noise of the first
(`test_a_changed_publisher_outweighs_a_version_bump`).

`permission_reduced` scores **zero** and is still reported. Raising risk when a
skill asks for less would teach people to ignore the score
(`test_an_expanded_permission_is_reported_and_a_reduced_one_costs_nothing`).

The fingerprint covers name, version, publisher, artefact hash and permissions —
not the description. A publisher rewording a summary would otherwise raise drift
nobody can action, which is how a drift alert comes to be ignored
(`test_the_fingerprint_covers_reach_and_ignores_prose`).

An **unknown permission is refused**, not scored as zero
(`test_an_unknown_permission_is_refused_rather_than_scored_as_zero`) — otherwise
a skill declaring `read_all_secrets` rates below one declaring `send_message`.

## The scanner parses; it never executes

> **Nothing in `sentinel/infrastructure/skill_scanner.py` runs the code it
> inspects.** Not `import`, not `exec`, not `pickle.load`, not a subprocess.

The whole point of scanning an untrusted skill is that it is untrusted, and a
scanner that imports its subject to enumerate symbols **has already lost** —
module-level code runs on import, and that is exactly where a malicious package
puts its payload.

`test_the_scanner_never_executes_what_it_inspects` writes a package whose
module-level code creates a marker file, scans it, and asserts the marker does
not exist. That test is the reason the module exists in the shape it does.

### What it finds

The honest shapes: `os.system`, `subprocess.run`, `eval`, `exec`,
`pickle.loads`, `ctypes.CDLL`, a hard-coded `~/.aws/credentials`, a credential
environment variable, and a base64 blob passed to `exec`.

Import aliases are resolved before the walk, so `from subprocess import run` and
`import subprocess as sp` both match — a package must not be able to evade every
call rule by changing its import style
(`test_a_from_import_is_matched_as_well_as_a_dotted_call`).

### What it cannot find

`getattr(__import__("o"+"s"), "system")` defeats name matching. So does fetching
the payload at runtime. **Every static analyser has this limit; the difference
between a useful one and a dishonest one is whether it says so.**

> **A clean scan is not a safety certificate.** It means these particular shapes
> were absent from the source that was handed over.

That sentence is in the module docstring, in this document, **and in the
`limits` field of every `ScanResult`**
(`test_the_result_states_its_own_limits`) — so a caller pasting a result into an
approval sees the limit next to the verdict rather than only in a document
nobody opened.

### Noise discipline

A scanner whose output people skim is a scanner that finds nothing.

- An ordinary `os.getenv("HOME")` is **not** a finding
  (`test_an_ordinary_env_read_is_not_a_finding`).
- `~/.aws/credentials` contains the substring "credential", so a naive scanner
  reports it under both `secret_path` and `secret_env`. It is reported **once**
  (`test_a_credential_path_is_reported_once_not_twice`).
- A package calling `subprocess.run` forty times is not forty times more
  dangerous than one calling it once — it is the same capability. Findings are
  deduplicated by rule before scoring
  (`test_repetition_does_not_inflate_the_score`).

### What is reported rather than skipped

- A file that will not parse is a **finding**, not a silent skip
  (`test_a_file_that_will_not_parse_is_reported_not_skipped`). It may be
  deliberately malformed to slip past a scanner that ignores what it cannot
  read. An unscanned file is not a clean one.
- Symlinks are not followed and are reported
  (`test_a_symlink_is_not_followed_and_is_reported`). A symlink named
  `helpers.py` pointing at `/etc/shadow` would otherwise have this process read
  it and put the contents into a finding an analyst can see.
- `ScanResult.skipped` names every file that was present and not scanned, with a
  reason. "We scanned 40 of 60 files" and "we scanned everything" are different
  statements.

## HTTP surface

| Method | Path | Capability |
|---|---|---|
| POST | `/v1/skills/assess` | `evaluate_protect` |

The response carries both the assessment and the raw scan, including its
`limits` string.

## Known limitations

1. **Python source only.** `scan_tree` defaults to `.py`. A skill shipping
   JavaScript, a compiled extension, or a binary is not inspected at all, and the
   `skipped` list is where that shows up.
2. **No package installation or dependency resolution.** The scanner reads the
   source it is given. A skill whose `requirements.txt` pulls a hostile
   transitive dependency is not covered.
3. **No sandboxed dynamic analysis.** Deliberate — see above — but it means
   runtime-constructed behaviour is invisible.
4. **The registry has no durable store yet.** `assess` and `compare` are pure
   functions over records the caller supplies; there is no table holding approved
   skills, so drift comparison requires the caller to keep the approved
   definition. That is the same gap `docs/A2A_GATEWAY.md` records for agent
   cards, and it is the next thing to build.
