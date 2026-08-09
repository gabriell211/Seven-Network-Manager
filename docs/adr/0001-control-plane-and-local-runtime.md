# ADR 0001: Control plane with local headless runtime

## Status

Accepted.

## Context

SNM must manage private networks where some operations require LAN reachability, L2 adjacency, local routes or privileged host capabilities. A browser or externally hosted frontend cannot safely or correctly perform these operations.

## Decision

Use a modular monolith for the control plane and a separate Rust headless runtime for local execution.

The runtime is separated for placement, lifecycle and least-privilege reasons. This is not a broad microservices strategy.

## Consequences

- Frontend remains optional and safe from provider execution.
- Backend owns product policy, RBAC, audit and orchestration.
- Runtime can run on-premise without graphical session.
- Providers and transports stay behind capability contracts.
- Future remote-site execution reuses `executor-core` instead of creating another execution model.
