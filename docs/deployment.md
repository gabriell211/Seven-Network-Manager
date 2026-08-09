# On-prem deployment

The reference deployment is intentionally split into independent processes:

- frontend;
- backend/control plane;
- site runtime;
- PostgreSQL;
- Redis;
- optional MongoDB and RabbitMQ profiles.

PostgreSQL is the durable source of truth. Redis is mandatory in the base profile but is configured as ephemeral coordination/cache (`appendonly no`, snapshots disabled). MongoDB and RabbitMQ are not started unless their profiles are selected.

## Local secret bootstrap

Do not copy production credentials into Git. Generate a local `.env`:

```bash
python3 scripts/bootstrap_env.py
```

The generated file is ignored by Git and contains distinct random values for database, runtime and access-token secrets.

## Repeatable lifecycle commands

Use the repository wrapper instead of remembering ad-hoc Compose commands:

```bash
python3 scripts/snm_stack.py up
python3 scripts/snm_stack.py inspect
python3 scripts/snm_stack.py logs --service backend
python3 scripts/snm_stack.py down
```

Optional datastores are explicit:

```bash
python3 scripts/snm_stack.py up --profile mongo
python3 scripts/snm_stack.py up --profile rabbit
python3 scripts/snm_stack.py up --profile mongo --profile rabbit
```

`inspect` fails when a selected service is not running or reports unhealthy.

## Destructive reset

A reset deletes PostgreSQL and any selected optional datastore volumes. It is deliberately fail-closed:

```bash
python3 scripts/snm_stack.py reset --confirm-reset
```

To delete the current local `.env` and generate new secrets as part of the reset:

```bash
python3 scripts/snm_stack.py reset --confirm-reset --regenerate-secrets
```

Do not use reset as an upgrade strategy. Normal upgrades must preserve PostgreSQL volumes and execute versioned migrations.

## Base network placement

The normal profile keeps:

- PostgreSQL and Redis on the internal `data` network;
- backend on `control + data`;
- frontend on `control`;
- site runtime on `control + managed`;
- runtime out of the `data` network;
- no `privileged: true` service;
- all application containers with `cap_drop: ALL`.

The backend never receives LAN-execution capabilities. If the runtime is unavailable, the backend reports that fact and does not open a direct network transport as fallback.

## Linux L2 / ARP mode

Routed TCP/UDP operations work through the base runtime placement. Raw L2/ARP operations are different: a Docker bridge does not place the runtime in the host LAN broadcast domain.

For a controlled Linux deployment or laboratory where real L2 discovery is required, use the dedicated override:

```bash
python3 scripts/snm_stack.py up --l2
```

This applies `docker-compose.l2.yml` and changes **only the site runtime** to:

- host networking;
- `CAP_NET_RAW`;
- non-loopback runtime bind so the bridge-isolated backend can reach it through the Docker host gateway.

The backend, frontend and datastores do not receive host networking or `NET_RAW`.

Because host networking makes the runtime listener reachable on host interfaces, the runtime bearer token remains mandatory and must be random. Production hosts should additionally restrict TCP/9765 with the host firewall to the Docker/backend path and trusted administration sources. Do not expose this port through an edge/load balancer.

`--l2` is Linux-only. The wrapper rejects it on other operating systems.

## Validation before deployment

Repository CI renders both Compose variants and fails on invalid merge semantics. It also verifies that the runtime does not gain database access and that the base configuration contains no unpinned `latest` image or privileged container.

For a release candidate, validate the L2 path on a real Linux host or VM connected to a test VLAN. The laboratory evidence should include:

1. backend and runtime readiness;
2. a routed runtime operation;
3. an L2/ARP observation from the intended interface;
4. proof that backend/datastore containers do not have host networking or `NET_RAW`;
5. correlation/audit evidence for the operation.

A synthetic Docker-only test is not sufficient evidence for physical-LAN L2 support.
