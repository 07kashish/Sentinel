"""Skills as supply-chain artefacts: drift, explainable risk, and a scanner
that never runs what it inspects.

THE PROPERTY THAT MATTERS MOST HERE
-------------------------------------
`test_the_scanner_never_executes_what_it_inspects` is the reason this module
exists. Every other test checks that a rule fires; that one checks the scanner
has not become the delivery mechanism for the thing it is scanning. A scanner
that imports its subject to enumerate symbols has already lost, because
module-level code runs on import and that is exactly where a malicious package
puts its payload.

WHY THE SCORE IS TESTED FOR ITS COMPONENTS, NOT ITS TOTAL
-----------------------------------------------------------
Asserting `score == 73` pins an arithmetic accident and breaks on every weight
adjustment. What must hold is the ORDERING and the EXPLANATION: a package that
executes decoded bytes outranks one that imports `socket`, an unenrolled skill
scores above an enrolled one, and every point is attributable to a named factor.
"""

from __future__ import annotations

import pytest

from sentinel.domain.skills import (
    PERMISSION_WEIGHT,
    SkillChangeKind,
    SkillDefinition,
    SkillRuleViolated,
    SkillTrust,
    assess,
    compare,
    skill_fingerprint,
)
from sentinel.infrastructure.skill_scanner import (
    RULES,
    ScanResult,
    findings_for_assessment,
    scan_source,
    scan_tree,
)


def _skill(**overrides) -> SkillDefinition:
    base = {
        "name": "acme-helper",
        "version": "1.0.0",
        "publisher": "acme",
        "permissions": frozenset({"send_message"}),
        "trust": SkillTrust.ENROLLED,
        "artifact_sha256": "a" * 64,
    }
    base.update(overrides)
    return SkillDefinition(**base)


# ── the definition ───────────────────────────────────────────────────────────


def test_an_unknown_permission_is_refused_rather_than_scored_as_zero():
    """A permission nobody weighed, scored as harmless, is how a skill declares
    `read_all_secrets` and rates below one declaring `send_message`.
    """
    with pytest.raises(SkillRuleViolated, match="unknown permissions"):
        _skill(permissions=frozenset({"read_all_secrets"}))


def test_a_malformed_artifact_hash_is_refused():
    with pytest.raises(SkillRuleViolated, match="sha256"):
        _skill(artifact_sha256="not-a-hash")


def test_the_fingerprint_covers_reach_and_ignores_prose():
    """A publisher rewording a summary must not raise drift nobody can action.
    Changing what the skill can DO must.
    """
    base = _skill(description="does a thing")
    reworded = _skill(description="completely different words")
    widened = _skill(permissions=frozenset({"send_message", "execute_code"}))
    republished = _skill(publisher="not-acme")

    assert base.fingerprint == reworded.fingerprint
    assert base.fingerprint != widened.fingerprint
    assert base.fingerprint != republished.fingerprint


def test_the_fingerprint_does_not_depend_on_key_order():
    left = skill_fingerprint(
        {"name": "s", "version": "1", "publisher": "p", "permissions": ["b", "a"]}
    )
    right = skill_fingerprint(
        {"permissions": ["a", "b"], "publisher": "p", "version": "1", "name": "s"}
    )
    assert left == right


# ── drift ────────────────────────────────────────────────────────────────────


def test_a_changed_publisher_outweighs_a_version_bump():
    """A version bump is what a maintained package does every week. A pinned
    name whose publisher changed underneath it is a supply-chain takeover, and
    rating them equally buries the second in the noise of the first.
    """
    changes = compare(_skill(), _skill(publisher="attacker", version="1.0.1"))
    kinds = [c.kind for c in changes]
    assert kinds[0] is SkillChangeKind.PUBLISHER_CHANGED
    assert SkillChangeKind.VERSION_CHANGED in kinds

    by_kind = {c.kind: c.weight for c in changes}
    assert by_kind[SkillChangeKind.PUBLISHER_CHANGED] > by_kind[
        SkillChangeKind.VERSION_CHANGED
    ]


def test_an_expanded_permission_is_reported_and_a_reduced_one_costs_nothing():
    """Raising risk when a skill asks for LESS would teach people to ignore the
    score.
    """
    changes = compare(
        _skill(permissions=frozenset({"send_message", "network_egress"})),
        _skill(permissions=frozenset({"execute_code"})),
    )
    by_kind = {c.kind: c for c in changes}
    assert by_kind[SkillChangeKind.PERMISSION_EXPANDED].weight > 0
    assert by_kind[SkillChangeKind.PERMISSION_REDUCED].weight == 0


def test_a_new_destination_is_drift():
    changes = compare(
        _skill(destinations=frozenset({"api.acme.com"})),
        _skill(destinations=frozenset({"api.acme.com", "paste.example"})),
    )
    assert changes[0].kind is SkillChangeKind.DESTINATION_ADDED
    assert "paste.example" in changes[0].detail


def test_two_different_skills_cannot_be_compared():
    """Drift is a property of ONE skill over time. Comparing two would report
    every difference between unrelated packages as a change.
    """
    with pytest.raises(SkillRuleViolated, match="drift is"):
        compare(_skill(), _skill(name="other-skill"))


# ── risk ─────────────────────────────────────────────────────────────────────


def test_every_point_is_attributable_to_a_named_factor():
    """A score whose components an analyst cannot see is one they cannot
    distinguish from a scoring artefact.
    """
    assessment = assess(_skill(permissions=frozenset({"execute_code"})))
    assert assessment.score == sum(f.points for f in assessment.factors)
    assert all(f.reason for f in assessment.factors)


def test_an_unenrolled_skill_scores_above_an_identical_enrolled_one():
    """A skill nobody registered is a skill nobody reviewed."""
    enrolled = assess(_skill(trust=SkillTrust.ENROLLED))
    unknown = assess(_skill(trust=SkillTrust.UNKNOWN))
    assert unknown.score > enrolled.score
    assert any(f.name == "unenrolled" for f in unknown.factors)


def test_a_blocked_skill_is_critical_on_its_own():
    assessment = assess(_skill(trust=SkillTrust.BLOCKED))
    assert assessment.severity == "critical"


def test_a_missing_integrity_hash_is_a_finding_not_a_neutral_absence():
    """A skill with no artefact hash is one whose content can change without
    anything noticing.
    """
    assessment = assess(_skill(artifact_sha256=""))
    assert any(f.name == "no_integrity_hash" for f in assessment.factors)


def test_the_score_is_capped_so_the_top_stays_meaningful():
    """An uncapped score makes "very bad" and "catastrophic" indistinguishable,
    and the decisions above HIGH are the same either way.
    """
    assessment = assess(
        _skill(
            trust=SkillTrust.UNKNOWN,
            permissions=frozenset(PERMISSION_WEIGHT),
            artifact_sha256="",
        )
    )
    assert assessment.score == 100


def test_an_untrusted_publisher_only_counts_when_a_list_exists():
    """A deployment that has not curated publishers must not have every skill
    flagged; an over-broad signal is one that gets switched off.
    """
    assert not any(
        f.name == "untrusted_publisher" for f in assess(_skill()).factors
    )
    assert any(
        f.name == "untrusted_publisher"
        for f in assess(_skill(), trusted_publishers=["corp"]).factors
    )


# ── the scanner ──────────────────────────────────────────────────────────────


def test_the_scanner_never_executes_what_it_inspects(tmp_path):
    """THE test. If the scanner imported or executed its subject, the
    module-level side effect below would fire — which is exactly where a
    malicious package puts its payload.
    """
    marker = tmp_path / "PAYLOAD_RAN"
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "evil.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n"
        "import subprocess\n",
        encoding="utf-8",
    )

    result = scan_tree(package)

    assert not marker.exists(), (
        "the scanner executed the module it was inspecting; a scanner that "
        "imports its subject IS the delivery mechanism"
    )
    assert result.files_scanned == 1


def test_a_shell_spawn_is_found():
    findings = scan_source("import os\nos.system('rm -rf /')\n")
    assert any(f.rule == "os.system" for f in findings)


def test_executing_decoded_bytes_outranks_a_plain_import():
    """Source that has to be decoded before it runs is source that was hidden
    from review.
    """
    obfuscated = scan_source("import base64\nexec(base64.b64decode('eA=='))\n")
    plain = scan_source("import socket\n")
    assert max(f.points for f in obfuscated) > max(f.points for f in plain)
    assert any(f.rule == "obfuscated_exec" for f in obfuscated)


def test_a_credential_path_is_reported_once_not_twice():
    """`~/.aws/credentials` contains the substring "credential", so a naive
    scanner reports the same string under two rule names — the kind of
    duplicate that teaches people to skim the output.
    """
    findings = scan_source("p = '~/.aws/credentials'\n")
    assert [f.rule for f in findings] == ["secret_path"]


def test_a_credential_env_var_is_still_found_on_its_own():
    findings = scan_source("import os\nos.getenv('AWS_SECRET_ACCESS_KEY')\n")
    assert any(f.rule == "secret_env" for f in findings)


def test_an_ordinary_env_read_is_not_a_finding():
    """A scanner that fires on `getenv("HOME")` produces output nobody reads."""
    assert scan_source("import os\nos.getenv('HOME')\n") == ()


def test_a_from_import_is_matched_as_well_as_a_dotted_call():
    """`from subprocess import run` presents as a bare name. Matching only the
    dotted form would miss the spelling most packages actually use.
    """
    findings = scan_source("from subprocess import run\nrun(['ls'])\n")
    assert any(f.rule == "subprocess.run" for f in findings)


def test_a_file_that_will_not_parse_is_reported_not_skipped():
    """It may be deliberately malformed to slip past a scanner that ignores
    what it cannot read. An unscanned file is not a clean one.
    """
    findings = scan_source("def broken(:\n")
    assert [f.rule for f in findings] == ["unparseable"]
    assert findings[0].points > 0


def test_a_symlink_is_not_followed_and_is_reported(tmp_path):
    """A symlink named `helpers.py` pointing at /etc/shadow would otherwise
    have this process read it and put the contents in a finding.
    """
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "real.py").write_text("x = 1\n", encoding="utf-8")
    secret = tmp_path / "outside.py"
    secret.write_text("SECRET_TOKEN = 'abc'\n", encoding="utf-8")
    try:
        (package / "link.py").symlink_to(secret)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs privileges on this platform")

    result = scan_tree(package)
    assert any("symlink" in reason for _p, reason in result.skipped)
    assert all("outside" not in f.path for f in result.findings)


def test_the_result_states_its_own_limits():
    """A caller serialising this into an approval sees the limit next to the
    verdict, not only in a document nobody opened.
    """
    document = ScanResult(findings=(), files_scanned=0).as_dict()
    assert "nothing was executed" in document["limits"]
    assert "not that the package is safe" in document["limits"]


def test_repetition_does_not_inflate_the_score():
    """A package calling `subprocess.run` forty times is not forty times more
    dangerous than one calling it once — it is the same capability. Letting the
    count drive the score would make a large well-behaved package outrank a
    small hostile one.
    """
    once = scan_source("import subprocess\nsubprocess.run(['ls'])\n")
    many = scan_source(
        "import subprocess\n" + "subprocess.run(['ls'])\n" * 40
    )
    assert len(many) > len(once)

    adapted_once = findings_for_assessment(ScanResult(findings=once, files_scanned=1))
    adapted_many = findings_for_assessment(ScanResult(findings=many, files_scanned=1))
    assert sum(f["points"] for f in adapted_once) == sum(
        f["points"] for f in adapted_many
    )


def test_every_documented_rule_can_actually_fire():
    """A rule enumerated in `RULES` that no code path emits is a capability
    claim with nothing behind it.
    """
    emitted = {
        f.rule
        for source in (
            "import os\nos.system('x')\n",
            "import subprocess\nsubprocess.run(['x'])\n",
            "eval('1')\n",
            "exec('1')\n",
            "import pickle\npickle.loads(b'')\n",
            "import base64\nexec(base64.b64decode('eA=='))\n",
            "p='~/.ssh/id_rsa'\n",
            "import os\nos.getenv('API_KEY')\n",
            "def broken(:\n",
            "import ctypes\nctypes.CDLL('x')\n",
            "import socket\nsocket.socket()\n",
            "__import__('os')\n",
            "compile('1','<s>','eval')\n",
            "import marshal\nmarshal.loads(b'')\n",
            "import codecs\ncodecs.decode('x')\n",
            "import os\nos.popen('x')\n",
            "import os\nos.execv('x',[])\n",
            "import subprocess\nsubprocess.call(['x'])\n",
            "import subprocess\nsubprocess.Popen(['x'])\n",
            "import subprocess\nsubprocess.check_output(['x'])\n",
            "import pickle\npickle.load(open('f','rb'))\n",
        )
        for f in scan_source(source)
    }
    unreachable = RULES - emitted
    assert not unreachable, f"rules that no input in this test can produce: {sorted(unreachable)}"
