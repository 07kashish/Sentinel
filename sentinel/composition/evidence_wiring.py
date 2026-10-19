"""Build the envelope cipher for evidence bodies from settings, or None."""

from __future__ import annotations

import base64
from typing import Any

from sentinel.composition.settings import ConfigurationError, Settings
from sentinel.infrastructure.persistence.crypto import CryptoError, EnvelopeCipher, StaticKeyProvider

__all__ = ["evidence_cipher"]


def evidence_cipher(settings: Settings) -> Any:
    """None when no data key is configured; settings already refused that in
    production unless plaintext storage was stated explicitly."""
    workflow = settings.workflow
    if not workflow.evidence_keys:
        return None
    try:
        keys = {key_id: base64.b64decode(value, validate=True) for key_id, value in workflow.evidence_keys.items()}
        return EnvelopeCipher(StaticKeyProvider(keys=keys, active=workflow.evidence_active_key))
    except (ValueError, CryptoError) as exc:
        raise ConfigurationError(f"evidence data keys are unusable: {type(exc).__name__}") from exc
