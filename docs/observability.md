# Observability contract

Seven Network Manager uses one versioned telemetry vocabulary across the control plane and site runtime. The current contract is `snm.telemetry.v1`.

## Operating rule

Observability must not become a control-plane dependency. Structured JSON logging remains available locally even when no collector exists. OTLP is opt-in, and exporter configuration failure disables export without making the backend or site runtime unavailable.

## Correlation

Every HTTP request receives two UUID identifiers:

- `x-request-id`: one concrete HTTP request/response exchange;
- `x-correlation-id`: the logical operation that may continue through additional services, jobs or provider calls.

A valid incoming value is preserved. Missing or malformed values are replaced with UUIDv7 values. Both headers are returned to the caller and attached to the request span. Internal calls must forward the existing correlation ID instead of inventing a new logical operation.

Resource identifiers, addresses and credentials are not correlation identifiers.

## Stable service attributes

Telemetry providers expose low-cardinality service metadata:

- `service.name`;
- `service.version`;
- `service.instance.id`;
- `deployment.environment.name`;
- `snm.telemetry.convention`.

`service.instance.id` may be supplied with `SNM_INSTANCE_ID`; otherwise the process generates an instance UUID for that startup.

## Event names

The v1 vocabulary reserves these stable operation families:

- `snm.http.request`;
- `snm.database.query`;
- `snm.runtime.operation`;
- `snm.provider.operation`;
- `snm.job.transition`;
- `snm.outbox.delivery`;
- `snm.audit.append`.

Code may add attributes to these events without renaming the family. A breaking semantic change requires a new telemetry convention version.

## Metrics vocabulary

The v1 contract reserves:

- `snm.http.server.requests`;
- `snm.http.server.duration.seconds`;
- `snm.database.operation.duration.seconds`;
- `snm.runtime.operation.duration.seconds`;
- `snm.provider.operation.duration.seconds`;
- `snm.provider.operation.errors`;
- `snm.jobs.queue.depth`;
- `snm.jobs.retries`;
- `snm.outbox.backlog`;
- `snm.outbox.retries`;
- `snm.queue.lag.seconds`.

Allowed dimensions must be bounded values such as capability, provider, transport and outcome. IP addresses, UUID resource IDs, correlation IDs, hostnames, serial numbers, user IDs and similar unbounded values are forbidden as metric labels.

## Error codes

Telemetry and API layers should prefer stable machine-readable classifications. The common v1 set includes:

- `timeout`;
- `cancelled`;
- `unavailable`;
- `rate_limited`;
- `authentication_failed`;
- `authorization_failed`;
- `remote_state_unknown`.

Provider-specific detail belongs in bounded provider/result fields, not in new one-off metric names.

## Secret redaction

A shared recursive redactor treats secret-bearing keys independently of naming style. Examples include password, token, access token, refresh token, client secret, API key, authorization, cookie, CSRF material, SNMP community and private key fields.

The redactor canonicalizes key names before classification, so forms such as `accessToken`, `access_token`, `access-token` and `access.token` receive the same treatment. Tests use sentinel secrets and fail if the sentinel survives serialization.

Do not log raw request bodies, bearer headers, cookies, credential payloads or provider command output by default. A field being absent from the redaction dictionary is not permission to log a credential-like value.

## OTLP configuration

Local JSON logs are always the baseline. OTLP export is disabled unless explicitly enabled:

```text
SNM_OTEL_ENABLED=false
SNM_OTEL_EXPORT_TIMEOUT_MS=5000
SNM_DEPLOYMENT_ENV=development
SNM_INSTANCE_ID=<optional-stable-instance-name>
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318
```

The exporter uses OTLP over HTTP/protobuf. Endpoint and other standard OTLP transport options are supplied through OpenTelemetry environment configuration.

Exporter timeout is bounded so telemetry cannot indefinitely hold an SNM operation. Export initialization errors are reported in the local structured log and export is disabled for that process.

## Sampling policy

For the MVP, when OTLP is enabled the application does not perform custom per-resource sampling. The goal is to preserve complete low-volume control-plane traces while avoiding IDs/IPs as metric dimensions. Large-scale deployments should apply ingestion/sampling policy at the collector until an application-side sampler is introduced under a versioned configuration contract.

Security/audit events are never made optional by trace sampling: the immutable audit trail remains a separate product record in PostgreSQL.

## Health and readiness

`/health` proves the process is alive. `/ready` reflects dependencies required to serve the product. An OTLP collector is never a readiness dependency.

Runtime availability is reported independently by the backend; the backend must not fall back to direct LAN execution merely to turn readiness green.

## Current coverage and completion gate

The backend and site runtime share the v1 tracing/redaction foundation and correlation headers. Issue #14 remains open until the remaining jobs/providers/outbox/queue paths emit the reserved metrics and an end-to-end test proves correlation across a real control-plane operation into the site runtime.
