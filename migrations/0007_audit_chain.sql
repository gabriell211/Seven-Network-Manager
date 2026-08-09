BEGIN;

ALTER TABLE audit_events
  ADD COLUMN occurred_at_unix_ms bigint,
  ADD COLUMN event_schema_version smallint NOT NULL DEFAULT 1
    CHECK (event_schema_version = 1),
  ADD COLUMN chain_sequence bigint,
  ADD COLUMN canonical_payload bytea;

CREATE UNIQUE INDEX uq_audit_chain_sequence
  ON audit_events (organization_id, chain_sequence)
  WHERE chain_sequence IS NOT NULL;

CREATE INDEX idx_audit_event_time
  ON audit_events (organization_id, occurred_at_unix_ms DESC, id DESC)
  WHERE occurred_at_unix_ms IS NOT NULL;

-- Historical rows are immutable by design and therefore cannot be rewritten by
-- this migration. They remain explicit legacy/unsealed records. Every new write
-- through AuditStore provides the full sealed tuple below.
ALTER TABLE audit_events
  ADD CONSTRAINT audit_sealed_fields_together CHECK (
    (chain_sequence IS NULL AND canonical_payload IS NULL AND event_hash IS NULL)
    OR (chain_sequence IS NOT NULL AND chain_sequence > 0
        AND occurred_at_unix_ms IS NOT NULL
        AND canonical_payload IS NOT NULL AND event_hash IS NOT NULL)
  );

COMMIT;
