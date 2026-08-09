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
