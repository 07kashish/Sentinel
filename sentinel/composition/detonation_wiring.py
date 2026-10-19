"""Choose the isolation boundary this deployment configured, or refuse.

THE PRECEDENCE, AND WHY IT ENDS IN A REFUSAL
---------------------------------------------
1. No image configured -> `RefusingDetonator`. Not a subprocess fallback.
   Running untrusted code on the control-plane host shares this process's
   filesystem, network position, environment and credentials, so the
   "degraded" mode would be precisely the attack detonation exists to
   prevent -- and it would be reached by exactly the deployments that never
   configured a boundary.
2. Image configured, tracing off -> `ContainerDetonator`. Contains well,
   observes badly: an exit code and two output streams. Its scope verdict is
   UNOBSERVED, which is the honest answer rather than a disappointing one.
3. Image configured, tracing on -> `TracingContainerDetonator`. Observes
   syscalls, and costs `CAP_SYS_PTRACE` on an otherwise `--cap-drop=ALL`
   container. That widening is opt-in for that reason.

WHY THIS IS A MODULE AND NOT FOUR LINES IN THE CONTAINER
---------------------------------------------------------
The same reason `remediation_wiring` is: the precedence is a security
decision, and a security decision buried in a 650-line constructor is one
nobody reviews. It also keeps `container.py` under the module size cap.
"""

from __future__ import annotations

from typing import Any

from sentinel.application.skill_detonation import SkillDetonationService
from sentinel.composition.settings import Settings
from sentinel.domain.detonation import RefusingDetonator

__all__ = ["build_detonation_service"]


def build_detonation_service(
    settings: Settings, *, detonator: Any | None = None
) -> SkillDetonationService:
    """Build the detonation service this deployment's configuration calls for.

    `detonator` is an injection seam for tests and for a deployment with a
    boundary this module does not know about. It wins over the settings,
    because supplying one was a decision somebody made.
    """
    if detonator is not None:
        return SkillDetonationService(detonator=detonator)

    image = settings.detonation_image
    if not image:
        return SkillDetonationService(
            detonator=RefusingDetonator(
                reason=(
                    "SENTINEL_DETONATION_IMAGE is not set, so no isolation "
                    "boundary is configured"
                )
            )
        )

    if settings.detonation_tracing:
        # Imported here rather than at module scope so a deployment that never
        # enables tracing does not import the tracing path at all -- and so
        # the capability-widening code is reached only by a deployment that
        # asked for it.
        from sentinel.infrastructure.detonation_tracing import (
            TracingContainerDetonator,
        )

        return SkillDetonationService(
            detonator=TracingContainerDetonator(image=image)
        )

    from sentinel.infrastructure.detonation_container import ContainerDetonator

    return SkillDetonationService(detonator=ContainerDetonator(image=image))
