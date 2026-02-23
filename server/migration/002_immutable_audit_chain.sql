-- Migration 008: Immutable audit chain for Garak scan evidence

CREATE TABLE IF NOT EXISTS immutable_audit_chain (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    stream_key TEXT NOT NULL,
    block_index BIGINT NOT NULL CHECK (block_index >= 0),
    record_type TEXT NOT NULL,           -- scan_result | scan_log | scan_summary | scan_failed
    record_id UUID,                      -- id of the row the block corresponds to
    payload JSONB NOT NULL,              -- canonicalized payload captured at append time
    payload_hash TEXT NOT NULL,          -- SHA256(payload)
    previous_hash TEXT NOT NULL,         -- previous block_hash or genesis
    block_hash TEXT NOT NULL,            -- SHA256(stream_key|index|prev|payload_hash|ts)
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    UNIQUE(stream_key, block_index),
    UNIQUE(stream_key, block_hash)
);

CREATE INDEX IF NOT EXISTS idx_immutable_audit_chain_org_created
    ON immutable_audit_chain(organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_immutable_audit_chain_scan_created
    ON immutable_audit_chain(scan_id, created_at DESC);
