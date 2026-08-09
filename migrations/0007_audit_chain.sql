BEGIN;

ALTER TABLE audit_events
  ADD COLUMN occurred_at_unix_ms bigint,
  ADD COLUMN event_schema_version smallint NOT NULL DEFAULT 1
    CHECK (event_schema_version = 1),
  ADD COLUMN chain_sequence bigint,
  ADD COLUMN canonical_payload bytea;

UPDATE audit_events
SET occurred_at_unix_ms = floor(extract(epoch FROM created_at) * 1000)::bigint
WHERE occurred_at_unix_ms IS NULL;

ALTER TABLE audit_events
  ALTER COLUMN occurred_at_unix_ms SET NOT NULL;

CREATE UNIQUE INDEX uq_audit_chain_sequence
  ON audit_events (organization_id, chain_sequence)
  WHERE chain_sequence IS NOT NULL;

CREATE INDEX idx_audit_event_time
  ON audit_events (organization_id, occurred_at_unix_ms DESC, id DESC);

-- Existing pre-chain events are deliberately left with NULL chain/hash/payload
-- so an upgrade can distinguish historical unsealed records from sealed events.
-- Every new application write through AuditStore supplies all sealed fields.
ALTER TABLE audit_events
  ADD CONSTRAINT audit_sealed_fields_together CHECK (
    (chain_sequence IS NULL AND canonical_payload IS NULL AND event_hash IS NULL)
    OR (chain_sequence IS NOT NULL AND chain_sequence > 0
        AND canonical_payload IS NOT NULL AND event_hash IS NOT NULL)
  );

COMMIT;
