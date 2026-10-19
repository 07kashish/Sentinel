"""Secret rotation and the KMS-backed key provider.

WHY OVERLAP IS THE PROPERTY UNDER TEST
--------------------------------------
The naive rotation -- replace the value and restart -- fails every request in
flight and locks out every client still holding the old credential. Operators
learn that rotating causes an outage, so they stop rotating, and the secret ages
for years. The absence of overlap is the reason rotation does not happen.

So these tests are mostly about the WINDOW: that a new version can be issued while
the old one is still accepted, that retiring is a separate decision, and that the
ordering which makes it safe is enforced rather than documented.
"""

from __future__ import annotations

import base64
import json

import pytest

from sentinel.infrastructure.outbound import OutboundPolicy, OutboundResponse
from sentinel.infrastructure.persistence.crypto import (
    KEY_BYTES,
    CryptoError,
    EnvelopeCipher,
)
from sentinel.infrastructure.secrets import (
    KmsKeyProvider,
    RotatingSecret,
    SecretsError,
    secrets_from_environment,
)

OLD = "old-token-that-is-long-enough-for-production"
NEW = "new-token-that-is-long-enough-for-production"
NEWER = "newer-token-that-is-long-enough-for-production"


# ── The rotation window ──────────────────────────────────────────────────────


def test_a_new_version_is_issued_while_the_old_is_still_accepted():
    """THE property. Without it, rotating breaks every client at once."""
    secret = RotatingSecret.from_values("attestation", [OLD])
    secret.add_version(2, NEW.encode())

    assert secret.current() == NEW.encode(), "the newest version must be issued"
    assert secret.verify(NEW) == 2
    assert secret.verify(OLD) == 1, (
        "the old version stopped being accepted the moment the new one was added, "
        "which is the outage this design exists to avoid"
    )


def test_adding_a_version_demotes_only_the_issuing_flag():
    secret = RotatingSecret.from_values("t", [OLD])
    secret.add_version(2, NEW.encode())
    states = {v.version: (v.issued, v.accepted) for v in secret.versions()}
    assert states == {1: (False, True), 2: (True, True)}


def test_retiring_is_a_separate_decision_from_issuing():
    """Two decisions separated by however long the slowest client needs."""
    secret = RotatingSecret.from_values("t", [OLD, NEW])
    assert secret.verify(OLD) == 1
    secret.retire(1)
    assert secret.verify(OLD) is None
    assert secret.verify(NEW) == 2


def test_the_issuing_version_cannot_be_retired():
    """Retiring what you are still handing out locks out every new client."""
    secret = RotatingSecret.from_values("t", [OLD, NEW])
    with pytest.raises(SecretsError) as refused:
        secret.retire(2)
    assert "issuing version" in str(refused.value)
    assert "overlap" in str(refused.value)


def test_retiring_the_last_accepted_version_is_refused():
    """Otherwise a rotation ends with a secret nobody can present, including the
    clients holding the current material."""
    secret = RotatingSecret.from_values("t", [OLD, NEW])
    secret.retire(1)
    with pytest.raises(SecretsError) as refused:
        secret.retire(2)
    # Refused as the issuing version first; either message is a refusal.
    assert "retire" in str(refused.value) or "issuing" in str(refused.value)


def test_rotating_to_the_same_material_is_refused():
    """Rotation theatre: the digest is unchanged, so retiring the old version
    invalidates nothing."""
    secret = RotatingSecret.from_values("t", [OLD])
    with pytest.raises(SecretsError) as refused:
        secret.add_version(2, OLD.encode())
    assert "invalidates nothing" in str(refused.value)


def test_a_three_version_overlap_accepts_all_three():
    secret = RotatingSecret.from_values("t", [OLD, NEW, NEWER])
    assert [secret.verify(v) for v in (OLD, NEW, NEWER)] == [1, 2, 3]
    assert secret.current_version() == 3


def test_an_unknown_credential_matches_nothing():
    secret = RotatingSecret.from_values("t", [OLD, NEW])
    assert secret.verify("not-a-real-token") is None


def test_verification_checks_every_accepted_version_with_no_early_exit():
    """Returning on first match makes the timing depend on WHICH version matched,
    which leaks how recently the secret rotated -- telling an attacker holding an
    old key whether it is still worth trying.

    Asserted structurally: the loop must have no `return` or `break` inside it.
    """
    import ast
    import inspect

    source = inspect.getsource(RotatingSecret.verify)
    tree = ast.parse(source.strip())
    loops = [n for n in ast.walk(tree) if isinstance(n, ast.For)]
    assert loops, "verify no longer loops over versions"
    for loop in loops:
        for node in ast.walk(loop):
            assert not isinstance(node, ast.Break), "verify breaks out of the loop"
            assert not isinstance(node, ast.Return), "verify returns from inside the loop"


# ── Hygiene ──────────────────────────────────────────────────────────────────


def test_a_secret_never_exposes_its_material():
    """The object has to be safe to put in a diagnostics response, because the
    reason nobody rotates is usually that nobody can see the current state."""
    secret = RotatingSecret.from_values("attestation", [OLD, NEW])
    rendered = repr(secret) + str(secret.versions()) + json.dumps(secret.history())
    assert OLD not in rendered
    assert NEW not in rendered
    for version in secret.versions():
        assert len(version.digest) == 64


def test_version_states_are_readable():
    secret = RotatingSecret.from_values("t", [OLD, NEW])
    assert "issuing+accepting" in str(secret.versions()[1])
    assert "accepting-only" in str(secret.versions()[0])
    secret.retire(1)
    assert "retired" in str(secret.versions()[0])


def test_an_empty_secret_is_a_configuration_error():
    with pytest.raises(SecretsError) as refused:
        RotatingSecret.from_values("t", [])
    assert "misconfiguration" in str(refused.value)


def test_history_records_both_halves_of_a_rotation():
    """"When did we stop accepting v1" must have an answer."""
    secret = RotatingSecret.from_values("t", [OLD, NEW])
    secret.retire(1)
    assert secret.history() == ("added v1", "added v2", "retired v1")


# ── Loading from the environment ─────────────────────────────────────────────


def test_secrets_load_as_a_json_array_oldest_first():
    loaded = secrets_from_environment(
        {"SENTINEL_SECRET_ATTESTATION": json.dumps([OLD, NEW]), "OTHER": "x"},
        prefix="SENTINEL_SECRET_",
    )
    assert set(loaded) == {"attestation"}
    assert loaded["attestation"].current_version() == 2


def test_a_comma_separated_value_is_refused_rather_than_split():
    """A secret containing a comma is not hypothetical, and silently splitting one
    produces two invalid credentials instead of an error."""
    with pytest.raises(SecretsError) as refused:
        secrets_from_environment(
            {"SENTINEL_SECRET_T": f"{OLD},{NEW}"}, prefix="SENTINEL_SECRET_"
        )
    assert "JSON array" in str(refused.value)


def test_a_json_object_is_refused():
    with pytest.raises(SecretsError):
        secrets_from_environment(
            {"SENTINEL_SECRET_T": '{"a": "b"}'}, prefix="SENTINEL_SECRET_"
        )


# ── The KMS provider ─────────────────────────────────────────────────────────


def _kek(byte: int = 7) -> str:
    return base64.b64encode(bytes([byte]) * KEY_BYTES).decode()


class _StubKms:
    """Same contract as `HardenedHttpClient`. No network, no DNS."""

    def __init__(self, responder) -> None:
        self.policy = OutboundPolicy()
        self.calls: list[str] = []
        self._responder = responder

    def request(self, *, method, url, headers=None, body=None, idempotent=False):
        self.calls.append(url)
        return self._responder(len(self.calls) - 1, headers or {})


def _ok(_n, _headers):
    return OutboundResponse(
        status=200,
        headers={},
        body=json.dumps({"key": _kek()}).encode(),
        peer="203.0.113.5:443",
    )


def test_a_kek_is_fetched_and_satisfies_the_envelope_cipher():
    """The point of the port: the cipher does not know where keys come from."""
    provider = KmsKeyProvider(
        endpoint="https://kms.example",
        token="t",
        active_key_id="k1",
        client=_StubKms(_ok),
    )
    cipher = EnvelopeCipher(provider)
    sealed = cipher.seal(
        b"evidence", tenant_id="acme", record_type="evidence", record_id="inc-1"
    )
    assert (
        cipher.open(sealed, tenant_id="acme", record_type="evidence", record_id="inc-1")
        == b"evidence"
    )


def test_keys_are_cached_so_a_kms_blip_is_not_a_total_outage():
    """Without a cache, every encrypt and decrypt is a round trip, and a KMS blip
    becomes an outage of every read of every encrypted column."""
    client = _StubKms(_ok)
    provider = KmsKeyProvider(
        endpoint="https://kms.example", token="t", active_key_id="k1", client=client
    )
    for _ in range(5):
        provider.key("k1")
    assert len(client.calls) == 1


def test_the_cache_expires_so_a_revoked_key_stops_working():
    """A key revoked at the KMS must stop working within the window rather than
    living for the life of the process."""
    # An advanceable clock rather than a fixed sequence: `_now()` is called once
    # when a value is stored and once when it is checked, so a hand-written tick
    # list encodes that internal ordering and breaks whenever it changes.
    clock = {"t": 0.0}
    client = _StubKms(_ok)
    provider = KmsKeyProvider(
        endpoint="https://kms.example",
        token="t",
        active_key_id="k1",
        client=client,
        cache_seconds=300.0,
        now=lambda: clock["t"],
    )
    provider.key("k1")
    assert len(client.calls) == 1

    clock["t"] = 299.0
    provider.key("k1")
    assert len(client.calls) == 1, "the cache expired early"

    clock["t"] = 301.0
    provider.key("k1")
    assert len(client.calls) == 2, "the cache did not expire"


def test_invalidate_forces_a_refetch_after_a_rotation():
    client = _StubKms(_ok)
    provider = KmsKeyProvider(
        endpoint="https://kms.example", token="t", active_key_id="k1", client=client
    )
    provider.key("k1")
    provider.invalidate()
    provider.key("k1")
    assert len(client.calls) == 2


def test_a_short_key_from_the_kms_is_refused():
    """A short key is not a weak key here, it is a silently different algorithm."""

    def short(_n, _headers):
        return OutboundResponse(
            status=200,
            headers={},
            body=json.dumps({"key": base64.b64encode(b"tooshort").decode()}).encode(),
            peer="p",
        )

    provider = KmsKeyProvider(
        endpoint="https://kms.example", token="t", active_key_id="k1",
        client=_StubKms(short),
    )
    with pytest.raises(CryptoError) as refused:
        provider.key("k1")
    assert "AES-256 requires" in str(refused.value)


def test_a_kms_error_is_a_crypto_error_not_a_retry_storm():
    """A caller retrying a decrypt in a loop against a down KMS turns one outage
    into a stampede."""

    def down(_n, _headers):
        return OutboundResponse(status=503, headers={}, body=b"", peer="p")

    provider = KmsKeyProvider(
        endpoint="https://kms.example", token="t", active_key_id="k1",
        client=_StubKms(down),
    )
    with pytest.raises(CryptoError) as refused:
        provider.key("k1")
    assert refused.value.is_retryable is False


def test_the_kms_token_is_sent_as_a_bearer_credential():
    seen: dict[str, str] = {}

    def capture(_n, headers):
        seen.update(headers)
        return _ok(_n, headers)

    KmsKeyProvider(
        endpoint="https://kms.example", token="s3cret", active_key_id="k1",
        client=_StubKms(capture),
    ).key("k1")
    assert seen["Authorization"] == "Bearer s3cret"


def test_a_non_https_kms_endpoint_is_refused_at_construction():
    """Fetching a key-encrypting key over cleartext discloses the key."""
    with pytest.raises(SecretsError) as refused:
        KmsKeyProvider(endpoint="http://kms.internal", token="t", active_key_id="k1")
    assert "not callable" in str(refused.value)


def test_a_kms_endpoint_resolving_internally_is_refused_at_use():
    """The key-fetch path goes through the hardened client, so the SSRF and
    redirect defences apply to it too -- a KMS URL is just another configured
    endpoint, and F-1 was proven on exactly that shape."""
    provider = KmsKeyProvider(
        endpoint="https://kms.example", token="t", active_key_id="k1"
    )
    # No stub: the real client resolves and vets. `kms.example` does not resolve,
    # so this must fail as a CryptoError rather than reaching the network.
    with pytest.raises(CryptoError):
        provider.key("k1")


def test_describe_exposes_cache_state_without_key_material():
    client = _StubKms(_ok)
    provider = KmsKeyProvider(
        endpoint="https://kms.example", token="s3cret", active_key_id="k1", client=client
    )
    provider.key("k1")
    described = json.dumps(dict(provider.describe()))
    assert "k1" in described
    assert "s3cret" not in described
    assert _kek() not in described
