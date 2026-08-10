BEGIN;

ALTER TABLE discovery_fingerprint_suggestions
  ADD COLUMN device_id uuid,
  ADD CONSTRAINT fk_discovery_fingerprint_device_scope
    FOREIGN KEY (device_id, organization_id, site_id)
    REFERENCES devices(id, organization_id, site_id) ON DELETE SET NULL;

CREATE INDEX idx_discovery_fingerprint_device
  ON discovery_fingerprint_suggestions (organization_id, site_id, device_id, state, last_seen_at DESC)
  WHERE device_id IS NOT NULL;

COMMIT;
