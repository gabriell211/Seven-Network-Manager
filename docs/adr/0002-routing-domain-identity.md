# ADR-0002: Scope L3 identity by routing domain

- Status: accepted
- Date: 2026-08-09
- Owners: gabriell211

## Context
Private and enterprise networks legitimately reuse prefixes across VRFs. IPv6 link-local addresses additionally require an interface scope.

## Decision
IP addresses are values, not global resource identifiers. L3 records carry organization, site and routing-domain. Link-local IPv6 additionally requires interface scope. Database constraints permit overlap across routing domains while rejecting conflicting allocation inside the same routing domain.

## Consequences
IPAM, discovery, telemetry, topology and configuration APIs must preserve routing-domain context instead of using an IP-only cache key.

## Verification
Domain tests model the same `10.0.0.1` in two routing domains. Migration tests must prove the same overlap in PostgreSQL.
