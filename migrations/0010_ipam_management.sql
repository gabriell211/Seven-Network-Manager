BEGIN;

CREATE EXTENSION IF NOT EXISTS btree_gist;

ALTER TABLE ip_prefixes
  ADD COLUMN gateway inet,
  ADD COLUMN vlan_id integer CHECK (vlan_id IS NULL OR vlan_id BETWEEN 1 AND 4094),
  ADD COLUMN description text,
  ADD COLUMN purpose text,
  ADD CONSTRAINT ip_prefixes_gateway_inside_prefix
    CHECK (gateway IS NULL OR gateway <<= prefix),
  ADD CONSTRAINT uq_ip_prefixes_scope_identity
    UNIQUE (id, organization_id, site_id, routing_domain_id);

ALTER TABLE ip_prefixes
  ADD CONSTRAINT ip_prefixes_no_overlap_same_routing_domain
  EXCLUDE USING gist (
    organization_id WITH =,
    site_id WITH =,
    routing_domain_id WITH =,
    prefix inet_ops WITH &&
  );

ALTER TABLE ip_addresses
  DROP CONSTRAINT ip_addresses_allocation_state_check;

UPDATE ip_addresses
SET allocation_state = 'excluded'
WHERE allocation_state = 'deprecated';

ALTER TABLE ip_addresses
  ADD COLUMN prefix_id uuid,
  ADD COLUMN device_id uuid,
  ADD COLUMN description text,
  ADD COLUMN version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD CONSTRAINT ip_addresses_allocation_state_check
    CHECK (allocation_state IN ('available', 'reserved', 'assigned', 'observed', 'conflict', 'excluded')),
  ADD CONSTRAINT fk_ip_addresses_prefix_scope
    FOREIGN KEY (prefix_id, organization_id, site_id, routing_domain_id)
    REFERENCES ip_prefixes(id, organization_id, site_id, routing_domain_id) ON DELETE RESTRICT,
  ADD CONSTRAINT fk_ip_addresses_device_scope
    FOREIGN KEY (device_id, organization_id, site_id)
    REFERENCES devices(id, organization_id, site_id) ON DELETE RESTRICT;

CREATE OR REPLACE FUNCTION validate_ip_address_prefix_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.prefix_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM ip_prefixes p
    WHERE p.id = NEW.prefix_id
      AND p.organization_id = NEW.organization_id
      AND p.site_id = NEW.site_id
      AND p.routing_domain_id = NEW.routing_domain_id
      AND NEW.address <<= p.prefix
  ) THEN
    RAISE EXCEPTION 'IP address does not belong to the selected prefix/routing-domain'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER ip_addresses_validate_prefix_scope
  BEFORE INSERT OR UPDATE OF prefix_id, address, organization_id, site_id, routing_domain_id
  ON ip_addresses
  FOR EACH ROW EXECUTE FUNCTION validate_ip_address_prefix_scope();

CREATE INDEX idx_ip_addresses_prefix
  ON ip_addresses (organization_id, site_id, routing_domain_id, prefix_id, allocation_state);
CREATE INDEX idx_ip_addresses_device
  ON ip_addresses (organization_id, site_id, device_id)
  WHERE device_id IS NOT NULL;

INSERT INTO permissions (code, description) VALUES
  ('ipam.view', 'Read IPAM prefixes and allocations'),
  ('ipam.create', 'Create IPAM prefixes and allocations'),
  ('ipam.update', 'Update IPAM prefixes and allocations'),
  ('ipam.delete', 'Remove IPAM prefixes and allocations when safe')
ON CONFLICT (code) DO NOTHING;

COMMIT;
