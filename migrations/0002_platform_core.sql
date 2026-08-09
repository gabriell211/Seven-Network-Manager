BEGIN;

ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_lifecycle_state_check;
ALTER TABLE devices
  ADD CONSTRAINT devices_lifecycle_state_check
  CHECK (lifecycle_state IN (
    'discovered', 'pending_review', 'managed', 'unmanaged',
    'maintenance', 'retired', 'archived'
  ));

ALTER TABLE users
  ADD COLUMN password_hash text,
  ADD COLUMN password_changed_at timestamptz,
  ADD COLUMN last_login_at timestamptz;

CREATE TABLE auth_totp_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  secret_ref text NOT NULL,
  enabled_at timestamptz,
  last_used_step bigint,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id)
);

CREATE TABLE auth_recovery_codes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash bytea NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, code_hash)
);

CREATE TABLE webauthn_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id bytea NOT NULL,
  public_key_cose bytea NOT NULL,
  sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  transports text[] NOT NULL DEFAULT '{}',
  nickname text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_used_at timestamptz,
  UNIQUE (organization_id, credential_id)
);

CREATE TABLE service_account_credentials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service_account_id uuid NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
  token_prefix text NOT NULL,
  token_hash bytea NOT NULL,
  scopes text[] NOT NULL DEFAULT '{}',
  allowed_cidrs cidr[] NOT NULL DEFAULT '{}',
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (service_account_id, token_prefix)
);

CREATE TABLE credential_ciphertexts (
  credential_profile_id uuid PRIMARY KEY REFERENCES credential_profiles(id) ON DELETE CASCADE,
  algorithm text NOT NULL DEFAULT 'AES-256-GCM' CHECK (algorithm = 'AES-256-GCM'),
  key_version integer NOT NULL CHECK (key_version > 0),
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) > 16),
  aad_hash bytea NOT NULL,
  rotated_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE runtime_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  identity_fingerprint text NOT NULL,
  auth_secret_hash bytea NOT NULL,
  protocol_version integer NOT NULL DEFAULT 1 CHECK (protocol_version > 0),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'repair_required')),
  last_seen_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  rotated_at timestamptz,
  UNIQUE (organization_id, site_id, identity_fingerprint)
);

CREATE TABLE discovery_scopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  site_id uuid NOT NULL,
  routing_domain_id uuid NOT NULL,
  network cidr NOT NULL,
  ipv6_strategy text,
  concurrency_limit integer NOT NULL CHECK (concurrency_limit BETWEEN 1 AND 4096),
  rate_per_second integer NOT NULL CHECK (rate_per_second BETWEEN 1 AND 65535),
  timeout_ms integer NOT NULL CHECK (timeout_ms BETWEEN 100 AND 30000),
  enabled boolean NOT NULL DEFAULT true,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (routing_domain_id, site_id, organization_id)
    REFERENCES routing_domains(id, site_id, organization_id) ON DELETE CASCADE,
  UNIQUE (organization_id, site_id, routing_domain_id, network),
  CHECK (family(network) = 4 OR ipv6_strategy IS NOT NULL)
);

CREATE TABLE discovery_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scope_id uuid NOT NULL REFERENCES discovery_scopes(id) ON DELETE RESTRICT,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  routing_domain_id uuid NOT NULL REFERENCES routing_domains(id) ON DELETE CASCADE,
  runtime_identity_id uuid REFERENCES runtime_identities(id) ON DELETE SET NULL,
  status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')),
  correlation_id uuid NOT NULL,
  requested_by uuid,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_discovery_runs_scope_time
  ON discovery_runs (organization_id, site_id, routing_domain_id, created_at DESC);

CREATE TABLE discovery_evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  discovery_run_id uuid NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  routing_domain_id uuid NOT NULL REFERENCES routing_domains(id) ON DELETE CASCADE,
  address inet,
  evidence_type text NOT NULL,
  field text,
  value jsonb NOT NULL,
  source text NOT NULL,
  confidence numeric(5,4) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  observed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_discovery_evidence_scope_address
  ON discovery_evidence (organization_id, site_id, routing_domain_id, address, observed_at DESC);

CREATE TABLE provider_capabilities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider text NOT NULL,
  product_family text NOT NULL,
  capability text NOT NULL,
  access_mode text NOT NULL CHECK (access_mode IN ('read', 'write')),
  status text NOT NULL CHECK (status IN ('supported', 'candidate', 'experimental', 'read_only', 'blocked', 'deprecated', 'unsupported')),
  transports text[] NOT NULL DEFAULT '{}',
  runtime_placement text NOT NULL CHECK (runtime_placement IN ('control_plane', 'site_local', 'either')),
  ipv4 boolean NOT NULL DEFAULT true,
  ipv6 boolean NOT NULL DEFAULT false,
  routing_domains boolean NOT NULL DEFAULT false,
  tested_versions text[] NOT NULL DEFAULT '{}',
  limitations text[] NOT NULL DEFAULT '{}',
  contract_test_ref text,
  lab_evidence_ref text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, product_family, capability, access_mode),
  CHECK (status <> 'supported' OR (contract_test_ref IS NOT NULL AND lab_evidence_ref IS NOT NULL AND cardinality(tested_versions) > 0))
);

CREATE TABLE change_plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  site_id uuid REFERENCES sites(id) ON DELETE SET NULL,
  action text NOT NULL,
  target_fingerprint text NOT NULL,
  input_fingerprint text NOT NULL,
  provider_version text NOT NULL,
  risk text NOT NULL CHECK (risk IN ('low', 'medium', 'high', 'critical')),
  dry_run boolean NOT NULL DEFAULT true,
  rollback_supported boolean NOT NULL DEFAULT false,
  state text NOT NULL CHECK (state IN ('planned', 'awaiting_approval', 'approved', 'running', 'paused', 'partially_succeeded', 'succeeded', 'failed', 'rolled_back', 'unknown', 'cancelled')),
  correlation_id uuid NOT NULL,
  requested_by uuid,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE change_approvals (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  change_plan_id uuid NOT NULL REFERENCES change_plans(id) ON DELETE CASCADE,
  approver_id uuid NOT NULL,
  target_fingerprint text NOT NULL,
  input_fingerprint text NOT NULL,
  provider_version text NOT NULL,
  approved_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at > approved_at)
);

CREATE TABLE change_target_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  change_plan_id uuid NOT NULL REFERENCES change_plans(id) ON DELETE CASCADE,
  target_id text NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('succeeded', 'failed', 'rolled_back', 'unknown', 'not_attempted')),
  confirmed boolean NOT NULL DEFAULT false,
  error_code text,
  before_state jsonb,
  after_state jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (change_plan_id, target_id)
);

CREATE TABLE dataset_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  dataset text NOT NULL UNIQUE,
  owner text NOT NULL,
  purpose text NOT NULL,
  data_class text NOT NULL CHECK (data_class IN ('public', 'internal', 'confidential', 'secret')),
  retention_days integer NOT NULL CHECK (retention_days >= 0),
  purge_strategy text NOT NULL CHECK (purge_strategy IN ('delete', 'anonymize', 'archive_then_delete', 'append_only_policy')),
  legal_hold_supported boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (retention_days > 0 OR purge_strategy = 'append_only_policy')
);

INSERT INTO dataset_policies (dataset, owner, purpose, data_class, retention_days, purge_strategy, legal_hold_supported)
VALUES
  ('audit_events', 'platform-security', 'security and administrative accountability', 'confidential', 2555, 'append_only_policy', true),
  ('discovery_evidence', 'discovery', 'asset identification and reconciliation', 'internal', 90, 'delete', false),
  ('outbox_events', 'platform-events', 'reliable event publication', 'internal', 30, 'delete', false)
ON CONFLICT (dataset) DO NOTHING;

CREATE TABLE trial_licenses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  installation_id uuid NOT NULL UNIQUE,
  state text NOT NULL CHECK (state IN ('inactive', 'active', 'expiring', 'expired', 'converted')),
  starts_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  max_devices integer NOT NULL CHECK (max_devices > 0),
  max_sites integer NOT NULL CHECK (max_sites > 0),
  max_admin_users integer NOT NULL CHECK (max_admin_users > 0),
  allow_read_capabilities boolean NOT NULL DEFAULT true,
  allow_low_risk_mutations boolean NOT NULL DEFAULT false,
  allow_critical_mutations boolean NOT NULL DEFAULT false,
  signed_token_fingerprint text,
  converted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > starts_at)
);

CREATE TABLE trial_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  trial_license_id uuid NOT NULL REFERENCES trial_licenses(id) ON DELETE CASCADE,
  event_type text NOT NULL CHECK (event_type IN ('activated', 'renewed', 'expired', 'limit_reached', 'converted', 'blocked_action')),
  actor_id uuid,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  correlation_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE outbox_events
  ADD COLUMN dead_lettered_at timestamptz,
  ADD COLUMN status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'published', 'failed', 'dead_letter'));

CREATE INDEX idx_outbox_dispatch
  ON outbox_events (status, available_at, occurred_at)
  WHERE status IN ('pending', 'failed');

COMMIT;
