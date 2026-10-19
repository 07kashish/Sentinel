# Security notes (current hexagonal tree)

**Status:** pre-production.

## Authentication and authorisation

- Bearer API keys; optional OIDC JWT (RS256/ES256, tenant claim required).
- SAML assertion validator (`sentinel/infrastructure/saml.py`) with signature verify.
- SCIM 2.0 Users (`/scim/v2/Users`) and org APIs (`/v1/orgs*`) behind `MANAGE_USERS`.
- Capability grants; ingest cannot read incidents.

## Protect (F-11 in-product)

- `POST /v1/tools/execute` is the only sanctioned remote tool side-effect path.
- Kill switch / budget / circuit via `ProtectControls`.
- SDK: `InterceptedToolClient` fails closed if misconstructed.
- Enrolled-agent silence → `possible_bypass` on `GET /v1/protect/bypass-signals`.
- Optional deployment-time enforcement (egress allowlist / mesh / eBPF): see
  `docs/PROTECT_ENFORCEMENT.md`. **Sentinel cannot see traffic that bypasses this.**
- Residual: processes that never call Sentinel (no transparent network interceptor
  unless a maintainer explicitly scopes that work).

## HTTP / console

- API CSP `default-src 'none'`.
- Analyst console at `/console` with `script-src 'self'`, Trusted Types policy name
  `sentinel-console`, DOM updates via `textContent` only (no `.innerHTML`).

## Tenancy

- FORCE RLS on Postgres; tenant required on UoW / directory / org writes.

## Known limitations

- Full enterprise IdP (hosted SAML IdP, SCIM Groups sync productization): incomplete.
  **SAML in this tree validates signed assertions; it is not an IdP.**
- Detection efficacy CLOSED for English independent soft path (F-10); multilingual not claimed.
- Remote GitHub branch protection UNVERIFIED until an operator runs
  `python scripts/apply_branch_protection.py OWNER/REPO --apply`.
