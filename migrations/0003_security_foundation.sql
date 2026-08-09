BEGIN;

ALTER TABLE sessions
  ADD COLUMN refresh_token_prefix text,
  ADD COLUMN last_used_at timestamptz,
  ADD COLUMN created_ip inet,
  ADD COLUMN user_agent text,
  ADD COLUMN auth_time timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN assurance_level text NOT NULL DEFAULT 'password'
    CHECK (assurance_level IN ('password', 'totp', 'webauthn')),
  ADD COLUMN access_revoked_before timestamptz,
  ADD CONSTRAINT sessions_refresh_hash_size CHECK (octet_length(refresh_token_hash) = 32),
  ADD CONSTRAINT sessions_expiry_after_creation CHECK (expires_at > created_at);

CREATE INDEX idx_sessions_active_user
  ON sessions (organization_id, user_id, expires_at DESC)
  WHERE revoked_at IS NULL;

ALTER TABLE service_account_credentials
  ADD CONSTRAINT service_account_token_hash_size CHECK (octet_length(token_hash) = 32);

CREATE INDEX idx_service_account_credentials_active
  ON service_account_credentials (service_account_id, expires_at)
  WHERE revoked_at IS NULL;

CREATE TABLE webauthn_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id uuid REFERENCES sessions(id) ON DELETE CASCADE,
  challenge_hash bytea NOT NULL CHECK (octet_length(challenge_hash) = 32),
  purpose text NOT NULL CHECK (purpose IN ('register', 'authenticate', 'step_up')),
  rp_id text NOT NULL,
  expected_origin text NOT NULL,
  operation_binding_hash bytea,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at),
  CHECK (operation_binding_hash IS NULL OR octet_length(operation_binding_hash) = 32)
);

CREATE UNIQUE INDEX uq_webauthn_active_challenge_hash
  ON webauthn_challenges (challenge_hash)
  WHERE consumed_at IS NULL;

CREATE TABLE step_up_grants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  factor text NOT NULL CHECK (factor IN ('totp', 'webauthn')),
  assurance_level text NOT NULL CHECK (assurance_level IN ('totp', 'webauthn')),
  operation_binding_hash bytea NOT NULL CHECK (octet_length(operation_binding_hash) = 32),
  authenticated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  CHECK (expires_at > authenticated_at)
);

CREATE UNIQUE INDEX uq_step_up_active_operation
  ON step_up_grants (session_id, operation_binding_hash)
  WHERE consumed_at IS NULL;

ALTER TABLE audit_events
  ADD COLUMN session_id uuid REFERENCES sessions(id) ON DELETE SET NULL,
  ADD COLUMN source_ip inet,
  ADD COLUMN request_id text,
  ADD COLUMN provider text,
  ADD COLUMN status text NOT NULL DEFAULT 'succeeded'
    CHECK (status IN ('succeeded', 'failed', 'denied', 'partial', 'unknown', 'cancelled')),
  ADD COLUMN duration_ms bigint CHECK (duration_ms IS NULL OR duration_ms >= 0),
  ADD COLUMN reason_code text,
  ADD COLUMN previous_hash bytea,
  ADD COLUMN event_hash bytea,
  ADD CONSTRAINT audit_previous_hash_size CHECK (previous_hash IS NULL OR octet_length(previous_hash) = 32),
  ADD CONSTRAINT audit_event_hash_size CHECK (event_hash IS NULL OR octet_length(event_hash) = 32);

CREATE UNIQUE INDEX uq_audit_event_hash
  ON audit_events (event_hash)
  WHERE event_hash IS NOT NULL;

CREATE INDEX idx_audit_actor_time
  ON audit_events (organization_id, actor_id, created_at DESC);
CREATE INDEX idx_audit_action_time
  ON audit_events (organization_id, action, created_at DESC);
CREATE INDEX idx_audit_resource_time
  ON audit_events (organization_id, resource_type, resource_id, created_at DESC);

CREATE OR REPLACE FUNCTION validate_role_binding_scope() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  bound_org uuid;
  role_org uuid;
  site_org uuid;
BEGIN
  bound_org := NEW.organization_id;

  SELECT organization_id INTO role_org FROM roles WHERE id = NEW.role_id;
  IF role_org IS NOT NULL AND role_org <> bound_org THEN
    RAISE EXCEPTION 'role binding organization mismatch';
  END IF;

  IF NEW.site_id IS NOT NULL THEN
    SELECT organization_id INTO site_org FROM sites WHERE id = NEW.site_id;
    IF site_org IS NULL OR site_org <> bound_org THEN
      RAISE EXCEPTION 'role binding site organization mismatch';
    END IF;
  END IF;

  IF NEW.user_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM users WHERE id = NEW.user_id AND organization_id = bound_org
  ) THEN
    RAISE EXCEPTION 'role binding user organization mismatch';
  END IF;

  IF NEW.service_account_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM service_accounts WHERE id = NEW.service_account_id AND organization_id = bound_org
  ) THEN
    RAISE EXCEPTION 'role binding service account organization mismatch';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER role_bindings_validate_scope
  BEFORE INSERT OR UPDATE ON role_bindings
  FOR EACH ROW EXECUTE FUNCTION validate_role_binding_scope();

INSERT INTO permissions (code, description) VALUES
  ('devices.view', 'Read device inventory'),
  ('devices.create', 'Create or onboard devices'),
  ('devices.update', 'Update declared device metadata'),
  ('devices.delete', 'Retire/delete devices according to lifecycle policy'),
  ('credentials.manage', 'Create, rotate and revoke credential profiles'),
  ('credentials.use', 'Use a credential profile through an authorized capability'),
  ('audit.view', 'Read audit events'),
  ('changes.approve', 'Approve privileged change plans'),
  ('automation.execute', 'Execute approved automation'),
  ('runtime.status.view', 'Read runtime health and capability status')
ON CONFLICT (code) DO NOTHING;

COMMIT;
