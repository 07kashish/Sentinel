"""Choose the advisory model adapter from settings. Advisory only, whichever it is."""

from __future__ import annotations

from sentinel.application.ports import ModelAdvisor
from sentinel.composition.settings import Settings
from sentinel.infrastructure.cli_advisor import AntigravityCliAdvisor
from sentinel.infrastructure.model_advisor import HttpModelAdvisor, UnconfiguredModelAdvisor

__all__ = ["build_advisor"]


def build_advisor(settings: Settings) -> ModelAdvisor:
    advisor = settings.advisor
    if advisor.endpoint:
        return HttpModelAdvisor(endpoint=advisor.endpoint, token=advisor.token, model=advisor.model)
    if advisor.cli_command:
        return AntigravityCliAdvisor(command=advisor.cli_command, model=advisor.model, home=advisor.cli_home)
    return UnconfiguredModelAdvisor()
