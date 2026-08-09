BEGIN;

ALTER TABLE devices
  ADD COLUMN device_type text NOT NULL DEFAULT 'unknown'
    CHECK (device_type IN ('switch', 'router', 'firewall', 'server', 'printer', 'access_point', 'unknown')),
  ADD COLUMN hostname text,
  ADD COLUMN os_name text,
  ADD COLUMN os_version text,
  ADD COLUMN firmware_version text,
  ADD COLUMN description text,
  ADD COLUMN operational_owner text,
  ADD COLUMN capabilities text[] NOT NULL DEFAULT '{}',
  ADD COLUMN last_seen_at timestamptz,
  ADD COLUMN last_changed_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN onboarded_at timestamptz,
  ADD COLUMN retired_at timestamptz,
  ADD COLUMN retirement_reason text;

ALTER TABLE devices
  ADD CONSTRAINT devices_id_organization_unique UNIQUE (id, organization_id);

CREATE INDEX idx_devices_type_scope
  ON devices (organization_id, site_id, device_type, lifecycle_state);
CREATE INDEX idx_devices_hostname_search
  ON devices (organization_id, site_id, lower(hostname))
  WHERE hostname IS NOT NULL;
CREATE INDEX idx_devices_serial_search
  ON devices (organization_id, site_id, lower(serial_number))
  WHERE serial_number IS NOT NULL;
CREATE INDEX idx_devices_last_seen
  ON devices (organization_id, site_id, last_seen_at DESC NULLS LAST);

ALTER TABLE device_identifiers
  ADD COLUMN organization_id uuid,
  ADD COLUMN site_id uuid,
  ADD COLUMN normalized_value text,
  ADD COLUMN identity_namespace text,
  ADD COLUMN strength text NOT NULL DEFAULT 'weak'
    CHECK (strength IN ('strong', 'weak')),
  ADD COLUMN last_seen_at timestamptz;

UPDATE device_identifiers AS identifier
SET organization_id = device.organization_id,
    site_id = device.site_id,
    normalized_value = CASE
      WHEN identifier.kind IN ('mac', 'snmp_engine_id')
        THEN regexp_replace(lower(trim(identifier.value)), '[^0-9a-f]', '', 'g')
      WHEN identifier.kind = 'hostname'
        THEN regexp_replace(lower(trim(identifier.value)), '\.$', '')
      ELSE lower(trim(identifier.value))
    END,
    identity_namespace = CASE
      WHEN identifier.kind = 'provider_native_id' THEN lower(trim(identifier.source))
      ELSE 'global'
    END,
    strength = CASE
      WHEN identifier.kind IN ('serial', 'mac', 'snmp_engine_id', 'provider_native_id')
        THEN 'strong'
      ELSE 'weak'
    END,
    last_seen_at = identifier.created_at
FROM devices AS device
WHERE device.id = identifier.device_id;

ALTER TABLE device_identifiers
  ALTER COLUMN organization_id SET NOT NULL,
  ALTER COLUMN site_id SET NOT NULL,
  ALTER COLUMN normalized_value SET NOT NULL,
  ALTER COLUMN identity_namespace SET NOT NULL;

ALTER TABLE device_identifiers
  ADD CONSTRAINT device_identifiers_scope_fk
  FOREIGN KEY (device_id, organization_id, site_id)
  REFERENCES devices(id, organization_id, site_id)
  ON DELETE CASCADE;

ALTER TABLE device_identifiers
  DROP CONSTRAINT device_identifiers_device_id_kind_value_key;

CREATE UNIQUE INDEX uq_device_identifier_per_device
  ON device_identifiers (device_id, kind, identity_namespace, normalized_value);
CREATE UNIQUE INDEX uq_device_strong_identifier_scope
  ON device_identifiers (
    organization_id, site_id, kind, identity_namespace, normalized_value
  )
  WHERE strength = 'strong';
CREATE INDEX idx_device_identifiers_normalized_lookup
  ON device_identifiers (
    organization_id, site_id, kind, identity_namespace, normalized_value
  );

CREATE TABLE device_facts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  site_id uuid NOT NULL,
  device_id uuid NOT NULL,
  field_name text NOT NULL,
  value jsonb NOT NULL,
  provenance text NOT NULL CHECK (provenance IN ('observed', 'declared')),
  source text NOT NULL,
  confidence numeric(5,4) CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
  observed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (device_id, organization_id, site_id)
    REFERENCES devices(id, organization_id, site_id)
    ON DELETE CASCADE,
  CHECK (length(trim(field_name)) > 0),
  CHECK (length(trim(source)) > 0),
  CHECK (provenance <> 'observed' OR observed_at IS NOT NULL),
  UNIQUE (device_id, field_name, provenance, source)
);

CREATE INDEX idx_device_facts_scope_field
  ON device_facts (organization_id, site_id, field_name, updated_at DESC);

CREATE TABLE inventory_tags (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL,
  normalized_name text GENERATED ALWAYS AS (lower(trim(name))) STORED,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (length(trim(name)) BETWEEN 1 AND 64),
  UNIQUE (organization_id, normalized_name),
  UNIQUE (id, organization_id)
);

CREATE TABLE device_tags (
  organization_id uuid NOT NULL,
  site_id uuid NOT NULL,
  device_id uuid NOT NULL,
  tag_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (device_id, organization_id, site_id)
    REFERENCES devices(id, organization_id, site_id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id, organization_id)
    REFERENCES inventory_tags(id, organization_id) ON DELETE CASCADE,
  PRIMARY KEY (device_id, tag_id)
);

ALTER TABLE credential_profiles
  ADD CONSTRAINT credential_profiles_id_organization_unique
  UNIQUE (id, organization_id);

CREATE TABLE device_credential_profiles (
  organization_id uuid NOT NULL,
  site_id uuid NOT NULL,
  device_id uuid NOT NULL,
  credential_profile_id uuid NOT NULL,
  purpose text NOT NULL DEFAULT 'management'
    CHECK (purpose IN ('management', 'monitoring', 'discovery', 'fallback')),
  priority integer NOT NULL DEFAULT 100 CHECK (priority BETWEEN 0 AND 10000),
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (device_id, organization_id, site_id)
    REFERENCES devices(id, organization_id, site_id) ON DELETE CASCADE,
  FOREIGN KEY (credential_profile_id, organization_id)
    REFERENCES credential_profiles(id, organization_id) ON DELETE RESTRICT,
  PRIMARY KEY (device_id, credential_profile_id, purpose)
);

CREATE TABLE device_lifecycle_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  site_id uuid NOT NULL,
  device_id uuid NOT NULL,
  from_state text CHECK (from_state IS NULL OR from_state IN (
    'discovered', 'pending_review', 'managed', 'unmanaged',
    'maintenance', 'retired', 'archived'
  )),
  to_state text NOT NULL CHECK (to_state IN (
    'discovered', 'pending_review', 'managed', 'unmanaged',
    'maintenance', 'retired', 'archived'
  )),
  actor_type text NOT NULL CHECK (actor_type IN ('user', 'service_account', 'system')),
  actor_id uuid,
  reason text,
  correlation_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (device_id, organization_id, site_id)
    REFERENCES devices(id, organization_id, site_id) ON DELETE RESTRICT
);

CREATE INDEX idx_device_lifecycle_events_device_time
  ON device_lifecycle_events (device_id, created_at DESC);

CREATE TABLE device_merges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  site_id uuid NOT NULL,
  source_device_id uuid NOT NULL,
  target_device_id uuid NOT NULL,
  actor_type text NOT NULL CHECK (actor_type IN ('user', 'service_account', 'system')),
  actor_id uuid,
  reason text NOT NULL,
  correlation_id uuid NOT NULL,
  merged_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (source_device_id, organization_id, site_id)
    REFERENCES devices(id, organization_id, site_id) ON DELETE RESTRICT,
  FOREIGN KEY (target_device_id, organization_id, site_id)
    REFERENCES devices(id, organization_id, site_id) ON DELETE RESTRICT,
  CHECK (source_device_id <> target_device_id),
  UNIQUE (source_device_id)
);

CREATE TABLE inventory_import_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  site_id uuid NOT NULL,
  idempotency_key text NOT NULL,
  payload_digest bytea NOT NULL,
  status text NOT NULL CHECK (status IN ('processing', 'completed', 'partial', 'failed')),
  created_count integer NOT NULL DEFAULT 0 CHECK (created_count >= 0),
  updated_count integer NOT NULL DEFAULT 0 CHECK (updated_count >= 0),
  skipped_count integer NOT NULL DEFAULT 0 CHECK (skipped_count >= 0),
  failed_count integer NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  FOREIGN KEY (site_id, organization_id)
    REFERENCES sites(id, organization_id) ON DELETE CASCADE,
  UNIQUE (organization_id, site_id, idempotency_key)
);

CREATE TABLE inventory_import_errors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  import_run_id uuid NOT NULL REFERENCES inventory_import_runs(id) ON DELETE CASCADE,
  row_number integer NOT NULL CHECK (row_number > 0),
  error_code text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO permissions (code, description)
VALUES
  ('devices.view', 'View inventory devices'),
  ('devices.create', 'Create inventory devices'),
  ('devices.update', 'Update managed inventory devices'),
  ('devices.delete', 'Retire or archive inventory devices'),
  ('devices.approve', 'Approve discovered devices for management'),
  ('devices.merge', 'Merge duplicate inventory devices'),
  ('devices.import', 'Bulk import inventory devices')
ON CONFLICT (code) DO NOTHING;

COMMIT;
