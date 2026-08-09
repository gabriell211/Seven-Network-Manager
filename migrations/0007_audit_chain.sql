BEGIN;

ALTER TABLE audit_events
  ADD COLUMN occurred_at_unix_ms bigint,
  ADD COLUMN event_schema_version smallint NOT NULL DEFAULT 1
    CHECK (event_schema_version = 1),
  ADD COLUMN canonical_payload bytea;

UPDATE audit_events
SET occurred_at_unix_ms = floor(extract(epoch FROM created_at) * 1000)::bigint
WHERE occurred_at_unix_ms IS NULL;

ALTER TABLE audit_events
  ALTER COLUMN occurred_at_unix_ms SET NOT NULL;

CREATE INDEX idx_audit_chain_order
  ON audit_events (organization_id, occurred_at_unix_ms, id);

-- Existing pre-chain events are deliberately left with NULL hash/payload so an
-- upgrade can distinguish historical unsealed records from cryptographically
-- sealed events. New application writes through the AuditStore always provide
-- all three values.
ALTER TABLE audit_events
  ADD CONSTRAINT audit_sealed_fields_together CHECK (
    (canonical_payload IS NULL AND event_hash IS NULL)
    OR (canonical_payload IS NOT NULL AND event_hash IS NOT NULL)
  );

COMMIT;
