CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS organizations (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sites (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS routing_domains (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  site_id uuid NOT NULL REFERENCES sites(id),
  name text NOT NULL,
  vrf_name text,
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (site_id, name)
);

CREATE TABLE IF NOT EXISTS devices (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  site_id uuid NOT NULL REFERENCES sites(id),
  routing_domain_id uuid NOT NULL REFERENCES routing_domains(id),
  display_name text NOT NULL,
  lifecycle_state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ipam_prefixes (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  site_id uuid NOT NULL REFERENCES sites(id),
  routing_domain_id uuid NOT NULL REFERENCES routing_domains(id),
  cidr text NOT NULL,
  ip_version text NOT NULL,
  purpose text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (routing_domain_id, cidr)
);

CREATE TABLE IF NOT EXISTS ipam_addresses (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  prefix_id uuid NOT NULL REFERENCES ipam_prefixes(id),
  address inet NOT NULL,
  state text NOT NULL,
  source text NOT NULL,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (prefix_id, address)
);

CREATE TABLE IF NOT EXISTS discovery_runs (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id uuid NOT NULL REFERENCES organizations(id),
  site_id uuid NOT NULL REFERENCES sites(id),
  routing_domain_id uuid NOT NULL REFERENCES routing_domains(id),
  state text NOT NULL,
  scope jsonb NOT NULL,
  discovered_count integer NOT NULL DEFAULT 0,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS telemetry_samples (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  device_id uuid NOT NULL REFERENCES devices(id),
  metric text NOT NULL,
  value text NOT NULL,
  source text NOT NULL,
  sampled_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id uuid REFERENCES organizations(id),
  severity text NOT NULL,
  state text NOT NULL,
  title text NOT NULL,
  evidence text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz
);

CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id uuid REFERENCES organizations(id),
  actor_id uuid,
  action text NOT NULL,
  target_type text,
  target_id uuid,
  result text NOT NULL,
  correlation_id uuid NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS trial_licenses (
  id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
  installation_id uuid NOT NULL,
  state text NOT NULL,
  started_at timestamptz,
  expires_at timestamptz,
  policy jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
