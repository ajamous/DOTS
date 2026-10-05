-- DOTS receipt service schema, version 1.

CREATE TABLE IF NOT EXISTS schema_version (version int PRIMARY KEY);

-- A node's own CDRs, pseudonymized at ingestion (no full numbers).
CREATE TABLE IF NOT EXISTS cdrs (
    call_key     text NOT NULL,
    direction    text NOT NULL CHECK (direction IN ('out', 'in')),
    peer_node    text NOT NULL,
    status       text NOT NULL,
    period       text NOT NULL,
    dest_prefix  text,
    answer_ts    bigint,
    received_ms  bigint NOT NULL,
    cdr          jsonb NOT NULL,
    PRIMARY KEY (call_key, direction)
);
CREATE INDEX IF NOT EXISTS cdrs_period ON cdrs (period, peer_node);

-- Outbound proposals awaiting a countersignature.
CREATE TABLE IF NOT EXISTS outbox (
    call_key     text PRIMARY KEY,
    peer_node    text NOT NULL,
    proposal     jsonb NOT NULL,
    created_ms   bigint NOT NULL,
    next_try_ms  bigint NOT NULL,
    attempts     int NOT NULL DEFAULT 0,
    done         boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS outbox_pending ON outbox (next_try_ms) WHERE NOT done;

-- Inbound proposals that arrived before this node's own CDR.
CREATE TABLE IF NOT EXISTS inbox (
    call_key     text PRIMARY KEY,
    proposal     jsonb NOT NULL,
    received_ms  bigint NOT NULL
);

-- Disputes this node raised that still have to reach the peer.
CREATE TABLE IF NOT EXISTS dispute_outbox (
    leaf_hash    bytea PRIMARY KEY,
    peer_node    text NOT NULL,
    dispute      jsonb NOT NULL,
    next_try_ms  bigint NOT NULL,
    attempts     int NOT NULL DEFAULT 0,
    done         boolean NOT NULL DEFAULT false
);

-- Final outcome per call (idempotency): exactly one per call_key.
CREATE TABLE IF NOT EXISTS outcomes (
    call_key     text PRIMARY KEY,
    kind         text NOT NULL CHECK (kind IN ('receipt', 'dispute')),
    leaf_idx     bigint NOT NULL
);

-- The Merkle log. Append-only, enforced by trigger.
CREATE TABLE IF NOT EXISTS log_leaves (
    idx          bigint PRIMARY KEY,
    leaf_hash    bytea NOT NULL UNIQUE,
    kind         text NOT NULL CHECK (kind IN ('receipt', 'dispute')),
    call_key     text NOT NULL,
    period       text NOT NULL,
    orig_node    text NOT NULL,
    term_node    text NOT NULL,
    entry        jsonb NOT NULL,
    entry_jcs    bytea NOT NULL,
    created_ms   bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS log_leaves_period ON log_leaves (period, orig_node, term_node);
CREATE INDEX IF NOT EXISTS log_leaves_call ON log_leaves (call_key);

CREATE OR REPLACE FUNCTION dots_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'log_leaves is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS log_leaves_append_only ON log_leaves;
CREATE TRIGGER log_leaves_append_only
    BEFORE UPDATE OR DELETE OR TRUNCATE ON log_leaves
    FOR EACH STATEMENT EXECUTE FUNCTION dots_append_only();

-- Signed tree heads this node published.
CREATE TABLE IF NOT EXISTS sths (
    id           bigserial PRIMARY KEY,
    tree_size    bigint NOT NULL,
    timestamp_ms bigint NOT NULL,
    signed       jsonb NOT NULL
);

-- Latest accepted STH per peer, plus history for equivocation evidence.
CREATE TABLE IF NOT EXISTS peer_sths (
    id           bigserial PRIMARY KEY,
    peer_node    text NOT NULL,
    tree_size    bigint NOT NULL,
    root_hash    text NOT NULL,
    signed       jsonb NOT NULL,
    accepted_ms  bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS peer_sths_latest ON peer_sths (peer_node, id DESC);

-- Entries this node expects to find in a peer's log.
CREATE TABLE IF NOT EXISTS expected_in_peer (
    leaf_hash    bytea NOT NULL,
    peer_node    text NOT NULL,
    since_ms     bigint NOT NULL,
    verified_size bigint,
    PRIMARY KEY (leaf_hash, peer_node)
);

CREATE TABLE IF NOT EXISTS alarms (
    id           bigserial PRIMARY KEY,
    ts_ms        bigint NOT NULL,
    peer_node    text,
    kind         text NOT NULL,
    detail       text NOT NULL
);

-- Settlement freeze per peer after an integrity alarm.
CREATE TABLE IF NOT EXISTS frozen_peers (
    peer_node    text PRIMARY KEY,
    since_ms     bigint NOT NULL,
    reason       text NOT NULL
);

-- How far the call-end spool has been reconciled.
CREATE TABLE IF NOT EXISTS spool_cursor (
    source       text PRIMARY KEY,
    last_id      bigint NOT NULL,
    updated_ms   bigint NOT NULL
);

-- Dispute resolution (ARCHITECTURE.md §5.7). One resolution per call: the
-- receipt (in log_leaves) that settles a logged dispute.
CREATE TABLE IF NOT EXISTS resolutions (
    dispute_leaf text PRIMARY KEY,
    call_key     text NOT NULL UNIQUE,
    receipt_leaf bytea NOT NULL,
    period       text NOT NULL,
    orig_node    text NOT NULL,
    term_node    text NOT NULL,
    created_ms   bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS resolutions_created ON resolutions (created_ms);

-- Originating side: re-proposals on their way to the terminating node.
CREATE TABLE IF NOT EXISTS resolution_outbox (
    dispute_leaf text PRIMARY KEY,
    peer_node    text NOT NULL,
    request      jsonb NOT NULL,
    created_ms   bigint NOT NULL,
    next_try_ms  bigint NOT NULL,
    attempts     int NOT NULL DEFAULT 0,
    state        text NOT NULL DEFAULT 'pending'
                 CHECK (state IN ('pending', 'needs_approval', 'resolved', 'refused', 'expired')),
    detail       text NOT NULL DEFAULT ''
);

-- Terminating side: re-proposals waiting for the operator, and its approvals.
CREATE TABLE IF NOT EXISTS resolution_inbox (
    dispute_leaf text PRIMARY KEY,
    request      jsonb NOT NULL,
    reason       text NOT NULL,
    received_ms  bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS resolution_approvals (
    dispute_leaf text PRIMARY KEY,
    approved_ms  bigint NOT NULL
);

INSERT INTO schema_version VALUES (1) ON CONFLICT DO NOTHING;
