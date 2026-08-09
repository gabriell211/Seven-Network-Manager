# Seven Network Manager — Architecture Baseline

## Context

The SNM is a network-management control plane. The browser expresses intent; it never becomes a privileged network executor.

```text
Operator
  |
  v
Next.js frontend
  |
  v
Rust/Axum control plane
  |
  | versioned + authenticated local execution contract
  v
Rust site-runtime (headless)
  |
  v
executor-core -> providers -> transports -> managed network
```

PostgreSQL is the transactional source of truth. Redis is ephemeral coordination/cache. MongoDB is optional and has no authoritative dataset by default. RabbitMQ is reserved for the distributed/HA evolution and is not part of the MVP local execution path.

## Allowed dependency direction

`API -> Application -> Domain -> Ports -> Providers/Transports -> Infrastructure`

The physical execution boundary is transversal: application code calls an execution port; the adapter decides whether execution is local now or remote in the future.

Forbidden dependencies:
- domain -> Axum/Next.js/database/vendor SDK;
- backend handler -> SNMP/SSH/WinRM socket as a fallback;
- executor-core -> frontend/Tauri/control-plane handlers;
- Tauri -> provider/probe execution;
- runtime -> unrestricted PostgreSQL/Redis access.

## Bounded contexts

Foundation ownership starts with:
- Identity & Access;
- Organization/Sites;
- Inventory & Lifecycle;
- Network Addressing;
- Connectivity & Transports;
- Execution Runtime;
- Audit & Events;
- Platform Operations.

Feature contexts (SNMP, discovery, monitoring, configuration, topology, hosts/directory, integrations) consume these contracts without collapsing them into a god module.

## Execution semantics

Every execution envelope carries at least:
- organization;
- site;
- routing domain;
- target;
- capability;
- actor/service identity;
- correlation/action IDs;
- idempotency metadata when applicable.

Remote state is not fabricated. `succeeded`, `failed`, `partial`, `unknown`, `cancelled`, `unsupported`, and `not_applicable` are legitimate outcomes.

The runtime rejects malformed or scope-inconsistent envelopes even though authorization originates in the control plane. This is defense in depth, not a replacement for RBAC.

## Routing domains and L3 identity

An IP is not globally unique. The minimum L3 context is organization + site + routing-domain + address. IPv6 link-local additionally requires interface scope.

Example:

```text
org A / site SP / VRF users / 10.0.0.1
org A / site SP / VRF servers / 10.0.0.1
```

Both are valid and distinct. The database therefore scopes prefix/address uniqueness by routing domain.

## MVP deployment

`production-mvp-onprem` runs inside the managed environment:
- frontend: self-hosted Next.js;
- backend: Rust/Axum control plane;
- site-runtime: independent Rust daemon on the same site/host by default;
- PostgreSQL + Redis;
- no mandatory cloud service;
- no GUI/session requirement for runtime execution.

The local runtime binds loopback by default. A Unix Domain Socket may replace loopback in a later hardening slice without changing the domain contract. RabbitMQ is intentionally absent from local backend/runtime communication.

## Evolution

#75 adds an outbound authenticated transport, pairing, offline queue, reconnect and routing for remote sites. It must reuse `executor-core`; it does not fork provider or transport implementations.

#46 later scales the control plane/workers and can introduce RabbitMQ. Distribution and HA are separate axes.

#118 may provide a desktop management surface, but remains off the critical execution path.
