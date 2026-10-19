"""Human principals: users, sessions, enrolment, and step-up.

WHY THERE ARE NO PASSWORDS
--------------------------
This is the design decision everything else follows from, so it is stated first.

A password would require hashing choices, a reset flow, breach-list checks, and a
guessing surface to rate-limit -- and it stays phishable, which is the failure mode
that actually compromises accounts. So there is no password store and no password
field anywhere in this module.

Authentication is a **passkey**. The private key never leaves the authenticator and
the browser binds the signature to the origin, so a convincing replica of the login
page cannot obtain a usable assertion. That is phishing resistance as a property of
the protocol rather than of the user's attention.

The bootstrap problem this creates is solved explicitly, not implicitly: a user is
provisioned with NO credential, an administrator issues a single-use enrolment
ticket with a short lifetime, and the user redeems it to register a passkey. There is
no path from "user exists" to "user can authenticate" that does not pass through a
deliberate act by someone who already can.

WHY TOTP EXISTS WHEN A PASSKEY IS ALREADY TWO FACTORS
-----------------------------------------------------
A passkey with user verification is possession plus a gesture, so it is already
multi-factor. TOTP is not a second factor here -- it is a **step-up** for the one
action with an effect outside this system.

Approving a remediation executes something on a real host. A session that was opened
an hour ago and left unattended should not be able to do that on its own, so
`decide_approval` requires a fresh TOTP code in addition to the session. That gives
the second factor a caller that is not ceremonial: it is asked for at the moment the
risk is taken, not at the moment the user arrives.

SESSIONS ARE OPAQUE AND SERVER-SIDE, NOT JWTs
---------------------------------------------
A JWT cannot be revoked. The whole point of a session in a security product is that
an operator can end one, so the token is a random string, stored as a hash, and
looked up. Two independent expiries: an absolute lifetime that caps how long a
single authentication is worth, and an idle timeout that ends an abandoned session.
An absolute limit alone lets a stolen token live out the window; an idle limit alone
lets a token that is quietly kept warm live forever.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
from typing import Mapping

from sentinel.domain.authorization import Capability, capabilities_for
from sentinel.domain.errors import DomainRuleViolated
from sentinel.domain.primitives import TenantId, Timestamp

__all__ = [
    "ABSOLUTE_SESSION_SECONDS",
    "IDLE_SESSION_SECONDS",
    "STEP_UP_CAPABILITIES",
    "STEP_UP_SECONDS",
    "EnrolmentTicket",
    "IdentityError",
    "Session",
    "SessionExpired",
    "StepUpRequired",
    "User",
    "UserId",
    "UserState",
    "issue_secret",
    "secret_digest",
]

#: How long one authentication is worth, regardless of activity. A stolen session
#: token cannot outlive this even if the thief keeps it warm.
ABSOLUTE_SESSION_SECONDS = 8 * 3600
#: How long a session survives without use. Ends an abandoned browser.
IDLE_SESSION_SECONDS = 30 * 60
#: How recently a step-up must have been satisfied. Deliberately short: it exists to
#: bind the second factor to the ACTION, and a long window unbinds them.
STEP_UP_SECONDS = 300

#: Capabilities that require a fresh second factor even inside a valid session.
#:
#: `DECIDE_APPROVAL` is here because approving a remediation executes something on a
#: real host -- it is the only action whose effect leaves this system. Read
#: capabilities are not here: requiring a code to look at an incident would train
#: people to keep an authenticator in their hand and approve without reading.
STEP_UP_CAPABILITIES = frozenset({Capability.DECIDE_APPROVAL})

_USER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
#: Session and ticket tokens. 32 bytes of CSPRNG output; the digest is what is stored.
TOKEN_BYTES = 32


class IdentityError(DomainRuleViolated):
    """A user, session or enrolment rule was violated."""


class SessionExpired(IdentityError):
    """The session is no longer valid. A distinct type so the edge can answer 401."""


class StepUpRequired(IdentityError):
    """The session is valid but this action needs a fresh second factor.

    Distinct from a 403: the caller is permitted, they simply have to prove presence
    again. Conflating it with a denial teaches users that the system is broken rather
    than that it is asking for something.
    """


def issue_secret() -> str:
    """A fresh bearer token. Returned once and never recoverable."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def secret_digest(token: str) -> str:
    """What gets stored. The token itself never is.

    A session table holding live tokens is a credential store: one SELECT and the
    reader is every logged-in user.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class UserState(str, Enum):
    #: Provisioned, no credential yet. Cannot authenticate.
    INVITED = "invited"
    ACTIVE = "active"
    #: Deactivated by SCIM or an administrator. Sessions are ended, and the record is
    #: kept: deleting a user destroys the audit trail's ability to name them.
    SUSPENDED = "suspended"


@dataclass(frozen=True, slots=True, order=True)
class UserId:
    value: str

    def __post_init__(self) -> None:
        cleaned = self.value.strip() if isinstance(self.value, str) else ""
        if not _USER_ID.match(cleaned):
            raise IdentityError(
                f"user id must be 1-128 chars of [A-Za-z0-9._:-] starting "
                f"alphanumeric, got {self.value!r}"
            )
        object.__setattr__(self, "value", cleaned)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class User:
    """A human principal, scoped to exactly one tenant.

    The role is a role NAME resolved through the same grant table the API keys use.
    Two authorisation models is two models that can disagree, and the disagreement
    would be a privilege difference nobody notices.
    """

    user_id: UserId
    tenant: TenantId
    email: str
    display_name: str
    role: str
    state: UserState = UserState.ACTIVE
    #: Whether a TOTP factor is enrolled. Step-up is impossible without one.
    has_totp: bool = False
    #: How many passkeys are registered. Zero means the user cannot log in.
    passkey_count: int = 0

    def __post_init__(self) -> None:
        # Validating the role here means an unknown role fails at provisioning time
        # rather than at the user's first login, when nobody is watching the logs.
        capabilities_for(self.role)
        if "@" not in self.email or self.email.strip() != self.email:
            raise IdentityError(f"email {self.email!r} is not usable")

    def capabilities(self) -> frozenset[Capability]:
        """No capabilities at all unless active.

        A suspended user retains their role for the audit trail and holds nothing.
        Returning their grants and relying on a separate state check elsewhere is how
        a deactivated account keeps working.
        """
        if self.state is not UserState.ACTIVE:
            return frozenset()
        return capabilities_for(self.role)

    def can_authenticate(self) -> bool:
        return self.state is UserState.ACTIVE and self.passkey_count > 0

    def requires_step_up(self, capability: Capability) -> bool:
        return capability in STEP_UP_CAPABILITIES


@dataclass(frozen=True, slots=True)
class Session:
    """An authenticated session. Opaque token, stored as a digest, revocable."""

    session_id: str
    user_id: UserId
    tenant: TenantId
    token_digest: str
    created_at: Timestamp
    last_seen_at: Timestamp
    #: When a step-up was last satisfied, or None. Not a boolean: a boolean cannot
    #: expire, and a step-up that never expires is a step-up performed once at login.
    stepped_up_at: Timestamp | None = None
    revoked_at: Timestamp | None = None
    #: Recorded for the audit trail and for "where am I logged in", never used as an
    #: authentication input -- binding a session to an IP breaks every mobile user
    #: and is trivially spoofed behind a proxy.
    user_agent: str = ""
    source_address: str = ""

    def matches(self, presented: str) -> bool:
        """Constant-time comparison of the presented token against the stored digest."""
        return hmac.compare_digest(secret_digest(presented), self.token_digest)

    def assert_live(self, *, now: Timestamp) -> None:
        """Raise `SessionExpired` unless this session is usable right now."""
        if self.revoked_at is not None:
            raise SessionExpired("this session was revoked")
        age = (now.value - self.created_at.value).total_seconds()
        if age >= ABSOLUTE_SESSION_SECONDS:
            raise SessionExpired(
                f"this session is {age / 3600:.1f}h old, past the "
                f"{ABSOLUTE_SESSION_SECONDS / 3600:.0f}h absolute limit. One "
                "authentication is not worth an unbounded amount of time."
            )
        idle = (now.value - self.last_seen_at.value).total_seconds()
        if idle >= IDLE_SESSION_SECONDS:
            raise SessionExpired(
                f"this session has been idle for {idle / 60:.0f} minutes, past the "
                f"{IDLE_SESSION_SECONDS / 60:.0f}-minute limit"
            )
        # A clock that has gone backwards past the creation time means the row was
        # tampered with or the host's clock jumped; either way the age checks above
        # are meaningless, so refuse rather than compute with them.
        if now.value < self.created_at.value:
            raise SessionExpired("this session claims to start in the future")

    def stepped_up_within(self, *, now: Timestamp, seconds: int = STEP_UP_SECONDS) -> bool:
        if self.stepped_up_at is None:
            return False
        elapsed = (now.value - self.stepped_up_at.value).total_seconds()
        return 0 <= elapsed < seconds

    def assert_step_up(self, capability: Capability, *, now: Timestamp) -> None:
        """Raise `StepUpRequired` when this action needs a fresher second factor."""
        if capability not in STEP_UP_CAPABILITIES:
            return
        if not self.stepped_up_within(now=now):
            raise StepUpRequired(
                f"{capability.value} requires a second factor confirmed within the "
                f"last {STEP_UP_SECONDS // 60} minutes. This action executes "
                "something outside this system, so it is confirmed at the moment "
                "the risk is taken rather than at login."
            )

    def touched(self, *, now: Timestamp) -> "Session":
        return Session(
            session_id=self.session_id,
            user_id=self.user_id,
            tenant=self.tenant,
            token_digest=self.token_digest,
            created_at=self.created_at,
            last_seen_at=now,
            stepped_up_at=self.stepped_up_at,
            revoked_at=self.revoked_at,
            user_agent=self.user_agent,
            source_address=self.source_address,
        )

    def with_step_up(self, *, now: Timestamp) -> "Session":
        return Session(
            session_id=self.session_id,
            user_id=self.user_id,
            tenant=self.tenant,
            token_digest=self.token_digest,
            created_at=self.created_at,
            last_seen_at=now,
            stepped_up_at=now,
            revoked_at=self.revoked_at,
            user_agent=self.user_agent,
            source_address=self.source_address,
        )


#: How long an enrolment ticket is valid. Short, because it is the one credential
#: that can be delivered over a channel nobody controls (a chat message, an email).
ENROLMENT_TICKET_SECONDS = 15 * 60


@dataclass(frozen=True, slots=True)
class EnrolmentTicket:
    """A single-use, short-lived permission to register a first credential.

    This is the bootstrap. It is deliberately the weakest credential in the system
    and therefore the most constrained: fifteen minutes, one use, issued only by
    someone who already holds `MANAGE_USERS`, and it grants nothing except the right
    to attach a passkey to one named account.
    """

    ticket_id: str
    user_id: UserId
    tenant: TenantId
    token_digest: str
    issued_at: Timestamp
    issued_by: str
    redeemed_at: Timestamp | None = None

    def matches(self, presented: str) -> bool:
        return hmac.compare_digest(secret_digest(presented), self.token_digest)

    def assert_redeemable(self, *, now: Timestamp) -> None:
        if self.redeemed_at is not None:
            raise IdentityError(
                "this enrolment ticket has already been used. Single-use is the point: "
                "a ticket that can be replayed lets whoever saw it in transit enrol "
                "their own authenticator."
            )
        age = (now.value - self.issued_at.value).total_seconds()
        if age >= ENROLMENT_TICKET_SECONDS:
            raise IdentityError(
                f"this enrolment ticket is {age / 60:.0f} minutes old, past the "
                f"{ENROLMENT_TICKET_SECONDS // 60}-minute limit"
            )
        if age < 0:
            raise IdentityError("this enrolment ticket claims to be issued in the future")

    def expires_at(self) -> Timestamp:
        return Timestamp(
            self.issued_at.value + timedelta(seconds=ENROLMENT_TICKET_SECONDS)
        )


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """What the edge resolves a session cookie into. The human analogue of `Principal`."""

    user: User
    session: Session
    capabilities: frozenset[Capability] = field(default_factory=frozenset)

    def can(self, capability: Capability) -> bool:
        return capability in self.capabilities

    def describe(self) -> Mapping[str, object]:
        """Safe to return to the caller. No token, no digest."""
        return {
            "user_id": self.user.user_id.value,
            "email": self.user.email,
            "display_name": self.user.display_name,
            "role": self.user.role,
            "tenant": self.user.tenant.value,
            "capabilities": sorted(c.value for c in self.capabilities),
            "stepped_up": self.session.stepped_up_at is not None,
            "has_totp": self.user.has_totp,
            "passkeys": self.user.passkey_count,
        }
