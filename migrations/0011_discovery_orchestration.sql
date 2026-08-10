BEGIN;

CREATE OR REPLACE FUNCTION snm_valid_discovery_tcp_ports(ports integer[])
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT cardinality(ports) <= 64
     AND NOT EXISTS (SELECT 1 FROM unnest(ports) AS port WHERE port < 1 OR port > 65535)
$$;

ALTER TABLE discovery_scopes
  ADD COLUMN name text,
  ADD COLUMN observations text[] NOT NULL DEFAULT ARRAY['reachability','reverse_dns','service']::text[],
  ADD COLUMN tcp_ports integer[] NOT NULL DEFAULT ARRAY[22,80,443]::integer[],
  ADD COLUMN interface_scope text,
  ADD COLUMN source_address inet,
  ADD COLUMN max_targets integer NOT NULL DEFAULT 4096 CHECK (max_targets BETWEEN 1 AND 65536),
  ADD COLUMN schedule_interval_seconds integer CHECK (
    schedule_interval_seconds IS NULL OR schedule_interval_seconds BETWEEN 60 AND 2592000
  ),
  ADD COLUMN next_run_at timestamptz,
  ADD COLUMN last_run_at timestamptz,
  ADD CONSTRAINT discovery_scopes_name_valid CHECK (
    name IS NULL OR length(trim(name)) BETWEEN 1 AND 160
  ),
  ADD CONSTRAINT discovery_scopes_observations_valid CHECK (
    cardinality(observations) BETWEEN 1 AND 5
    AND observations <@ ARRAY['reachability','neighbor','reverse_dns','service','management_protocol']::text[]
  ),
  ADD CONSTRAINT discovery_scopes_tcp_ports_valid CHECK (snm_valid_discovery_tcp_ports(tcp_ports)),
  ADD CONSTRAINT discovery_scopes_interface_scope_valid CHECK (
    interface_scope IS NULL OR length(trim(interface_scope)) BETWEEN 1 AND 128
  ),
  ADD CONSTRAINT discovery_scopes_source_family_matches CHECK (
    source_address IS NULL OR family(source_address) = family(network)
  );

UPDATE discovery_scopes
SET name = coalesce(name, network::text),
    next_run_at = CASE
      WHEN schedule_interval_seconds IS NOT NULL THEN now() + make_interval(secs => schedule_interval_seconds)
      ELSE NULL
    END;

ALTER TABLE discovery_scopes ALTER COLUMN name SET NOT NULL;

CREATE INDEX idx_discovery_scopes_schedule
  ON discovery_scopes (enabled, next_run_at)
  WHERE enabled AND next_run_at IS NOT NULL;

ALTER TABLE discovery_runs
  ADD COLUMN request_kind text NOT NULL DEFAULT 'manual'
    CHECK (request_kind IN ('manual', 'scheduled')),
  ADD COLUMN seed_targets inet[] NOT NULL DEFAULT '{}',
  ADD COLUMN scope_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN cancellation_requested_at timestamptz,
  ADD COLUMN progress_total integer NOT NULL DEFAULT 0 CHECK (progress_total >= 0),
  ADD COLUMN progress_completed integer NOT NULL DEFAULT 0 CHECK (progress_completed >= 0),
  ADD COLUMN summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN error_code text,
  ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now(),
  ADD CONSTRAINT discovery_runs_progress_valid CHECK (progress_completed <= progress_total),
  ADD CONSTRAINT discovery_runs_finished_state_valid CHECK (
    (status IN ('completed','partial','failed','cancelled') AND finished_at IS NOT NULL)
    OR (status IN ('queued','running') AND finished_at IS NULL)
  ) NOT VALID;

ALTER TABLE discovery_runs VALIDATE CONSTRAINT discovery_runs_finished_state_valid;

CREATE INDEX idx_discovery_runs_active
  ON discovery_runs (organization_id, site_id, status, created_at)
  WHERE status IN ('queued','running');

CREATE TABLE discovery_probe_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  discovery_run_id uuid NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  routing_domain_id uuid NOT NULL REFERENCES routing_domains(id) ON DELETE CASCADE,
  address inet NOT NULL,
  interface_scope text,
  interface_scope_key text GENERATED ALWAYS AS (coalesce(interface_scope, '')) STORED,
  probe_kind text NOT NULL CHECK (probe_kind IN ('icmp','arp','reverse_dns','tcp')),
  port integer CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
  port_key integer GENERATED ALWAYS AS (coalesce(port, 0)) STORED,
  status text NOT NULL CHECK (
    status IN ('succeeded','failed','partial','unknown','cancelled','unsupported','not_applicable')
  ),
  latency_ms bigint CHECK (latency_ms IS NULL OR latency_ms >= 0),
  error_code text,
  evidence_count integer NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
  observed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((probe_kind = 'tcp' AND port IS NOT NULL) OR (probe_kind <> 'tcp' AND port IS NULL)),
  CONSTRAINT uq_discovery_probe_result_identity UNIQUE (
    discovery_run_id, address, interface_scope_key, probe_kind, port_key
  )
);

CREATE INDEX idx_discovery_probe_results_run_status
  ON discovery_probe_results (discovery_run_id, status, observed_at);
CREATE INDEX idx_discovery_probe_results_scope_address
  ON discovery_probe_results (
    organization_id, site_id, routing_domain_id, address, observed_at DESC
  );

ALTER TABLE discovery_evidence
  ADD COLUMN probe_result_id uuid REFERENCES discovery_probe_results(id) ON DELETE CASCADE,
  ADD COLUMN probe_kind text CHECK (
    probe_kind IS NULL OR probe_kind IN ('icmp','arp','reverse_dns','tcp','fingerprint')
  ),
  ADD COLUMN port integer CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
  ADD COLUMN last_seen_at timestamptz;

UPDATE discovery_evidence SET last_seen_at = observed_at WHERE last_seen_at IS NULL;
ALTER TABLE discovery_evidence ALTER COLUMN last_seen_at SET NOT NULL;

CREATE INDEX idx_discovery_evidence_probe_result
  ON discovery_evidence (probe_result_id)
  WHERE probe_result_id IS NOT NULL;

CREATE TABLE discovery_fingerprint_suggestions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  discovery_run_id uuid NOT NULL REFERENCES discovery_runs(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  site_id uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  routing_domain_id uuid NOT NULL REFERENCES routing_domains(id) ON DELETE CASCADE,
  address inet NOT NULL,
  field_name text NOT NULL CHECK (field_name IN ('device_type','vendor','os_family','hostname')),
  value text NOT NULL CHECK (length(trim(value)) BETWEEN 1 AND 512),
  source text NOT NULL CHECK (length(trim(source)) BETWEEN 1 AND 120),
  confidence numeric(5,4) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  evidence_ids uuid[] NOT NULL DEFAULT '{}',
  state text NOT NULL DEFAULT 'suggested'
    CHECK (state IN ('suggested','conflict','applied','rejected')),
  last_seen_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uq_discovery_fingerprint_suggestion
  ON discovery_fingerprint_suggestions (
    discovery_run_id, address, field_name, lower(value), source
  );
CREATE INDEX idx_discovery_fingerprint_review
  ON discovery_fingerprint_suggestions (
    organization_id, site_id, state, last_seen_at DESC
  );

INSERT INTO permissions (code, description) VALUES
  ('discovery.view', 'View discovery scopes, runs, progress and evidence'),
  ('discovery.manage', 'Create and update discovery scopes and schedules'),
  ('discovery.execute', 'Start manual discovery runs'),
  ('discovery.cancel', 'Cancel queued or running discovery runs'),
  ('discovery.review', 'Review conflicting fingerprint suggestions')
ON CONFLICT (code) DO NOTHING;

COMMIT;
