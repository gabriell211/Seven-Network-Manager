# ADR-0001: Separate control plane from site-local execution runtime

- Status: accepted
- Date: 2026-08-09
- Owners: gabriell211

## Context
LAN/L2 operations need network placement and privileges that should not belong to browser/frontend code or to the control-plane request process. The future remote-site topology also needs a reusable execution core.

## Decision
The control plane is a modular monolith in `apps/backend`. Technical network execution lives in `crates/executor-core`, hosted by `apps/site-runtime` as a headless process. MVP communication is authenticated loopback or UDS; RabbitMQ is not used locally.

The backend does not execute transports/providers directly when the runtime is unavailable. Runtime failure is an explicit degraded/unavailable state.

## Consequences
- independent lifecycle and privilege boundary;
- runtime survives frontend restarts and does not require a user session;
- #75 can replace the local transport without forking the execution core;
- deployment has one additional service to operate and observe.

## Verification
Architecture lint rejects transport/provider imports under backend API/application code. Runtime tests must run without frontend/Tauri dependencies.
