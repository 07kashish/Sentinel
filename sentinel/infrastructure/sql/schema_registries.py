"""Registry DDL: MCP server trust, tool pins and provenance, A2A cards, grants.

WHY THIS IS A SEPARATE FILE AND NOT A SECOND SOURCE OF TRUTH
---------------------------------------------------------------
`schema.py` says, correctly, that DDL split across modules is how a table ends
up existing in one deployment and not another. That warning is about the
APPLICATION site, not about which file the string literal lives in.

So this module exports statements and applies nothing. `schema.py` concatenates
`REGISTRY_STATEMENTS` into the single `SCHEMA_STATEMENTS` tuple, `migrate.py`
iterates that one tuple, and there is still exactly one place where DDL runs.

The split happened because `schema.py` reached the size at which a module stops
having one reason to change -- 788 of a 800-line budget -- and the registry
tables are the part with their own reason: they change when agent, MCP or A2A
enrolment changes, and not when the incident aggregate does.
"""

from __future__ import annotations

from typing import Final

__all__ = ["REGISTRY_STATEMENTS"]


REGISTRY_STATEMENTS: Final[tuple[str, ...]] = (
    # ── MCP server trust and tool pins ───────────────────────────────────
    #
    # `trust` is stored, never accepted from a caller. The gateway refuses UNKNOWN
    # servers, so a request that could declare its own trust level would simply
    # declare itself ENROLLED and walk through the check. Enrolment is an operator
    # action recorded here; a call site only supplies a server_id to look up.
    """
    CREATE TABLE IF NOT EXISTS mcp_servers (
        tenant_id   TEXT NOT NULL,
        server_id   TEXT NOT NULL,
        endpoint    TEXT NOT NULL DEFAULT '',
        trust       TEXT NOT NULL,
        enrolled_at TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        PRIMARY KEY (tenant_id, server_id)
    )
    """,
    # One row per enrolled A2A agent card. The analogue of `mcp_tool_pins`, and
    # here for the same reason: an agent advertising `read:docs` on Monday and
    # `read:customers` on Friday presents the same NAME to the same allowlist,
    # and only a fingerprint over its capabilities catches that.
    #
    # `fingerprint` is the PIN, written at enrolment and compared on every later
    # evaluation. An enrolled agent whose fingerprint is not recorded could
    # change freely and never trip drift detection, which would make the whole
    # card mechanism decorative.
    #
    # This table is why A2A drift detection works across replicas at all. The
    # in-process store it replaces held pins in one worker's memory, so a card
    # enrolled through one replica was invisible to the next and `card_drift`
    # was unreportable in any deployment running more than one.
    # -- The transparency log ---------------------------------------------
    #
    # `(tenant_id, sequence)` is the PRIMARY KEY, which is what makes this
    # append-only. Re-appending at an occupied position is a constraint
    # violation rather than an overwrite, so history cannot be rewritten by a
    # caller who simply writes the same row again -- the property belongs to
    # the database, not to code remembering to check.
    #
    # `digest` is a passport's 32-byte SHA-256, stored hex. The LEAF HASH is
    # derived and never stored: a stored leaf hash could disagree with the
    # digest beside it, and then the log would have two answers.
    """
    CREATE TABLE IF NOT EXISTS transparency_leaves (
        tenant_id   TEXT    NOT NULL,
        sequence    INTEGER NOT NULL,
        digest      TEXT    NOT NULL,
        appended_at TEXT    NOT NULL,
        PRIMARY KEY (tenant_id, sequence)
    )
    """,
    # Roots that were PUBLISHED, and where they went.
    #
    # `sink` and `external_reference` are the columns that decide whether any
    # of this is worth anything. A root with `sink = 'none'` was served only by
    # the party that wrote the log, which proves nothing about that party -- so
    # the schema RECORDS the sink rather than letting a reader assume one.
    #
    # `(tenant_id, tree_size)` is the primary key: one published root per size,
    # so publishing a DIFFERENT root at a size already published is a
    # constraint violation. That is precisely a fork, refused at the storage
    # layer instead of detected afterwards.
    """
    CREATE TABLE IF NOT EXISTS transparency_roots (
        tenant_id          TEXT    NOT NULL,
        tree_size          INTEGER NOT NULL,
        root_hash          TEXT    NOT NULL,
        published_at       TEXT    NOT NULL,
        sink               TEXT    NOT NULL DEFAULT 'none',
        external_reference TEXT    NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, tree_size)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS a2a_agent_cards (
        tenant_id    TEXT NOT NULL,
        agent_id     TEXT NOT NULL,
        version      TEXT NOT NULL DEFAULT '',
        endpoint     TEXT NOT NULL DEFAULT '',
        capabilities TEXT NOT NULL DEFAULT '',
        description  TEXT NOT NULL DEFAULT '',
        fingerprint  TEXT NOT NULL,
        enrolled_at  TEXT NOT NULL,
        updated_at   TEXT NOT NULL,
        PRIMARY KEY (tenant_id, agent_id)
    )
    """,
    # One row per approved tool. The fingerprint is a SHA-256 over name +
    # description + input schema, so a server that keeps the NAME and changes the
    # description -- the MCP rug pull, which an allowlist cannot see -- produces a
    # different value here and stops matching.
    """
    CREATE TABLE IF NOT EXISTS mcp_tool_pins (
        tenant_id   TEXT NOT NULL,
        server_id   TEXT NOT NULL,
        tool_name   TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        pinned_at   TEXT NOT NULL,
        PRIMARY KEY (tenant_id, server_id, tool_name)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_mcp_pins_server ON mcp_tool_pins(tenant_id, server_id)",
    # One row per (tool, definition version) a server has actually served this
    # tenant. Keyed INCLUDING the fingerprint so a definition change opens a new
    # row instead of overwriting the old one -- the history of what a tool has
    # claimed to be is the provenance, and an UPSERT that flattened it would
    # destroy exactly the record an investigation of a rug pull needs. The
    # description and schema are hashed separately because the first question
    # about any change is "was it the instruction text or the parameters".
    # The description ITSELF is still not stored -- see the module docstring of
    # `infrastructure/mcp_registry.py` for why storing attacker text is refused.
    """
    CREATE TABLE IF NOT EXISTS mcp_tool_provenance (
        tenant_id          TEXT NOT NULL,
        server_id          TEXT NOT NULL,
        tool_name          TEXT NOT NULL,
        fingerprint        TEXT NOT NULL,
        description_sha256 TEXT NOT NULL DEFAULT '',
        schema_sha256      TEXT NOT NULL DEFAULT '',
        first_seen         TEXT NOT NULL,
        last_seen          TEXT NOT NULL,
        times_seen         INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (tenant_id, server_id, tool_name, fingerprint)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_mcp_provenance_server "
    "ON mcp_tool_provenance(tenant_id, server_id, tool_name)",
    # Append-only drift log: every TOOL_ADDED / TOOL_REMOVED /
    # DEFINITION_CHANGED the gateway observed, with the fingerprints on both
    # sides. Deliberately no UPDATE path and no primary key -- it is a log, and
    # the tamper-evident record of WHO was told about each drift lives in
    # `security_audit`; this table is the queryable index of the drifts
    # themselves.
    """
    CREATE TABLE IF NOT EXISTS mcp_tool_changes (
        tenant_id            TEXT NOT NULL,
        server_id            TEXT NOT NULL,
        tool_name            TEXT NOT NULL,
        kind                 TEXT NOT NULL,
        pinned_fingerprint   TEXT NOT NULL DEFAULT '',
        observed_fingerprint TEXT NOT NULL DEFAULT '',
        detail               TEXT NOT NULL DEFAULT '',
        observed_at          TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_mcp_changes_server "
    "ON mcp_tool_changes(tenant_id, server_id, observed_at)",
    """
    CREATE TABLE IF NOT EXISTS agent_tool_grants (
        tenant_id  TEXT NOT NULL,
        agent_id   TEXT NOT NULL,
        tool_name  TEXT NOT NULL,
        granted_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, agent_id, tool_name)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_agent_grants ON agent_tool_grants(tenant_id, agent_id)",
    """
    CREATE TABLE IF NOT EXISTS agent_observations (
        tenant_id   TEXT NOT NULL,
        agent_id    TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        event_count INTEGER NOT NULL DEFAULT 0,
        violation_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (tenant_id, agent_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_agent_obs_seen ON agent_observations(tenant_id, last_seen)",
    """
    CREATE TABLE IF NOT EXISTS agent_observed_edges (
        tenant_id   TEXT NOT NULL,
        agent_id    TEXT NOT NULL,
        kind        TEXT NOT NULL,
        target      TEXT NOT NULL,
        occurrences INTEGER NOT NULL DEFAULT 0,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        PRIMARY KEY (tenant_id, agent_id, kind, target)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_agent_edges_target ON agent_observed_edges(tenant_id, kind, target)",
    """
    CREATE TABLE IF NOT EXISTS execution_nodes (
        tenant_id    TEXT NOT NULL,
        event_id     TEXT NOT NULL,
        session_id   TEXT NOT NULL DEFAULT '',
        parent_id    TEXT NOT NULL DEFAULT '',
        agent_id     TEXT NOT NULL,
        kind         TEXT NOT NULL DEFAULT 'other',
        occurred_at  TEXT NOT NULL,
        action       TEXT NOT NULL DEFAULT '',
        resource     TEXT NOT NULL DEFAULT '',
        destination  TEXT NOT NULL DEFAULT '',
        tool         TEXT NOT NULL DEFAULT '',
        credential   TEXT NOT NULL DEFAULT '',
        principal    TEXT NOT NULL DEFAULT '',
        policy       TEXT NOT NULL DEFAULT '',
        decision     TEXT NOT NULL DEFAULT '',
        severity     INTEGER NOT NULL DEFAULT 0,
        incident_id  TEXT NOT NULL DEFAULT '',
        input_text   TEXT NOT NULL DEFAULT '',
        output_text  TEXT NOT NULL DEFAULT '',
        approval_id  TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, event_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS ix_exec_session ON execution_nodes(tenant_id, session_id, occurred_at)",
    "CREATE INDEX IF NOT EXISTS ix_exec_agent ON execution_nodes(tenant_id, agent_id, occurred_at)",
    """
    CREATE TABLE IF NOT EXISTS agent_declarations (
        tenant_id   TEXT NOT NULL,
        agent_id    TEXT NOT NULL,
        field       TEXT NOT NULL,
        value       TEXT NOT NULL,
        declared_at TEXT NOT NULL,
        declared_by TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (tenant_id, agent_id, field)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS execution_receipts (
        tenant_id                  TEXT NOT NULL,
        receipt_id                 TEXT NOT NULL,
        authorization_id           TEXT NOT NULL DEFAULT '',
        authorization_digest       TEXT NOT NULL DEFAULT '',
        executed_request_digest    TEXT NOT NULL DEFAULT '',
        approved_parameter_digest  TEXT NOT NULL DEFAULT '',
        actual_parameter_digest    TEXT NOT NULL DEFAULT '',
        delegation_passport_digest TEXT NOT NULL DEFAULT '',
        differing_keys             TEXT NOT NULL DEFAULT '',
        bounded_mutations          TEXT NOT NULL DEFAULT '',
        defects                    TEXT NOT NULL DEFAULT '',
        execution_identity         TEXT NOT NULL DEFAULT '',
        side_effect                TEXT NOT NULL DEFAULT '',
        outcome                    TEXT NOT NULL,
        started_at                 TEXT NOT NULL DEFAULT '',
        completed_at               TEXT NOT NULL,
        PRIMARY KEY (tenant_id, receipt_id)
    )
    """,
)
