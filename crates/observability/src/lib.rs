use std::{env, time::Duration};

use opentelemetry::{KeyValue, global, trace::TracerProvider as _};
use opentelemetry_otlp::{Protocol, WithExportConfig};
use opentelemetry_sdk::{
    Resource, metrics::SdkMeterProvider, propagation::TraceContextPropagator,
    trace::SdkTracerProvider,
};
use serde_json::{Map, Value};
use thiserror::Error;
use tracing::Span;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

pub const CONVENTION_VERSION: &str = "snm.telemetry.v1";

pub mod event_names {
    pub const HTTP_REQUEST: &str = "snm.http.request";
    pub const DATABASE_QUERY: &str = "snm.database.query";
    pub const RUNTIME_OPERATION: &str = "snm.runtime.operation";
    pub const PROVIDER_OPERATION: &str = "snm.provider.operation";
    pub const JOB_TRANSITION: &str = "snm.job.transition";
    pub const OUTBOX_DELIVERY: &str = "snm.outbox.delivery";
    pub const AUDIT_APPEND: &str = "snm.audit.append";
}

pub mod metric_names {
    pub const HTTP_REQUESTS: &str = "snm.http.server.requests";
    pub const HTTP_DURATION_SECONDS: &str = "snm.http.server.duration.seconds";
    pub const DATABASE_DURATION_SECONDS: &str = "snm.database.operation.duration.seconds";
    pub const RUNTIME_DURATION_SECONDS: &str = "snm.runtime.operation.duration.seconds";
    pub const PROVIDER_DURATION_SECONDS: &str = "snm.provider.operation.duration.seconds";
    pub const PROVIDER_ERRORS: &str = "snm.provider.operation.errors";
    pub const JOB_QUEUE_DEPTH: &str = "snm.jobs.queue.depth";
    pub const JOB_RETRIES: &str = "snm.jobs.retries";
    pub const OUTBOX_BACKLOG: &str = "snm.outbox.backlog";
    pub const OUTBOX_RETRIES: &str = "snm.outbox.retries";
    pub const QUEUE_LAG_SECONDS: &str = "snm.queue.lag.seconds";
}

pub mod error_codes {
    pub const TIMEOUT: &str = "timeout";
    pub const CANCELLED: &str = "cancelled";
    pub const UNAVAILABLE: &str = "unavailable";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const AUTHENTICATION_FAILED: &str = "authentication_failed";
    pub const AUTHORIZATION_FAILED: &str = "authorization_failed";
    pub const REMOTE_STATE_UNKNOWN: &str = "remote_state_unknown";
}

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub service_name: String,
    pub service_version: String,
    pub service_instance_id: String,
    pub deployment_environment: String,
    pub otlp_enabled: bool,
    pub export_timeout: Duration,
}

impl TelemetryConfig {
    pub fn from_env(service_name: impl Into<String>, service_version: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            service_version: service_version.into(),
            service_instance_id: env::var("SNM_INSTANCE_ID")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| Uuid::now_v7().to_string()),
            deployment_environment: env::var("SNM_DEPLOYMENT_ENV")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "development".to_owned()),
            otlp_enabled: env_flag("SNM_OTEL_ENABLED"),
            export_timeout: Duration::from_millis(
                env::var("SNM_OTEL_EXPORT_TIMEOUT_MS")
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(5_000)
                    .clamp(100, 30_000),
            ),
        }
    }
}

#[derive(Debug)]
pub struct TelemetryGuard {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
    exporter_error: Option<String>,
}

impl TelemetryGuard {
    pub fn exporter_error(&self) -> Option<&str> {
        self.exporter_error.as_deref()
    }

    pub fn shutdown(&self) {
        if let Some(provider) = &self.tracer_provider {
            let _ = provider.shutdown();
        }
        if let Some(provider) = &self.meter_provider {
            let _ = provider.shutdown();
        }
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn init(config: TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    global::set_text_map_propagator(TraceContextPropagator::new());

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(true)
        .with_target(false);

    let (tracer_provider, meter_provider, exporter_error) = if config.otlp_enabled {
        match build_otlp_providers(&config) {
            Ok((tracer, meter)) => (Some(tracer), Some(meter), None),
            Err(error) => (None, None, Some(error.to_string())),
        }
    } else {
        (None, None, None)
    };

    let otel_layer = tracer_provider.as_ref().map(|provider| {
        let tracer = provider.tracer(config.service_name.clone());
        tracing_opentelemetry::layer().with_tracer(tracer)
    });

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .map_err(|error| TelemetryError::Subscriber(error.to_string()))?;

    if let Some(provider) = &tracer_provider {
        global::set_tracer_provider(provider.clone());
    }
    if let Some(provider) = &meter_provider {
        global::set_meter_provider(provider.clone());
    }

    Ok(TelemetryGuard {
        tracer_provider,
        meter_provider,
        exporter_error,
    })
}

fn build_otlp_providers(
    config: &TelemetryConfig,
) -> Result<(SdkTracerProvider, SdkMeterProvider), TelemetryError> {
    let resource = Resource::builder()
        .with_service_name(config.service_name.clone())
        .with_attributes([
            KeyValue::new("service.version", config.service_version.clone()),
            KeyValue::new("service.instance.id", config.service_instance_id.clone()),
            KeyValue::new(
                "deployment.environment.name",
                config.deployment_environment.clone(),
            ),
            KeyValue::new("snm.telemetry.convention", CONVENTION_VERSION),
        ])
        .build();

    let span_exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_timeout(config.export_timeout)
        .build()
        .map_err(|error| TelemetryError::Exporter(error.to_string()))?;
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_batch_exporter(span_exporter)
        .build();

    let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .with_timeout(config.export_timeout)
        .build()
        .map_err(|error| TelemetryError::Exporter(error.to_string()))?;
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource)
        .with_periodic_exporter(metric_exporter)
        .build();

    Ok((tracer_provider, meter_provider))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationContext {
    request_id: Uuid,
    correlation_id: Uuid,
}

impl CorrelationContext {
    pub fn new(request_id: Option<&str>, correlation_id: Option<&str>) -> Self {
        Self {
            request_id: parse_uuid(request_id).unwrap_or_else(Uuid::now_v7),
            correlation_id: parse_uuid(correlation_id).unwrap_or_else(Uuid::now_v7),
        }
    }

    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }

    pub fn operation_span(&self, operation: &'static str) -> Span {
        tracing::info_span!(
            "snm.operation",
            otel.name = operation,
            "request.id" = %self.request_id,
            "snm.correlation_id" = %self.correlation_id,
            "snm.telemetry.convention" = CONVENTION_VERSION,
        )
    }
}

fn parse_uuid(value: Option<&str>) -> Option<Uuid> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|value| Uuid::parse_str(value).ok())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricDimensions {
    pub capability: Option<String>,
    pub provider: Option<String>,
    pub transport: Option<String>,
    pub outcome: String,
}

impl MetricDimensions {
    pub fn validate(&self) -> Result<(), TelemetryError> {
        validate_dimension(self.capability.as_deref())?;
        validate_dimension(self.provider.as_deref())?;
        validate_dimension(self.transport.as_deref())?;
        validate_dimension(Some(&self.outcome))?;
        Ok(())
    }
}

fn validate_dimension(value: Option<&str>) -> Result<(), TelemetryError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty()
        || value.len() > 80
        || value.parse::<Uuid>().is_ok()
        || value.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(TelemetryError::HighCardinalityMetricDimension);
    }
    Ok(())
}

pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut redacted = Map::with_capacity(object.len());
            for (key, value) in object {
                if is_sensitive_key(key) {
                    redacted.insert(key.clone(), Value::String("[REDACTED]".to_owned()));
                } else {
                    redacted.insert(key.clone(), redact_json(value));
                }
            }
            Value::Object(redacted)
        }
        Value::Array(values) => Value::Array(values.iter().map(redact_json).collect()),
        _ => value.clone(),
    }
}

pub fn is_sensitive_key(key: &str) -> bool {
    let canonical: String = key
        .trim()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_lowercase())
        .collect();

    [
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "csrf",
        "community",
        "privatekey",
        "clientsecret",
        "refreshtoken",
        "accesstoken",
        "apikey",
    ]
    .iter()
    .any(|needle| canonical == *needle || canonical.ends_with(needle))
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("failed to initialize tracing subscriber: {0}")]
    Subscriber(String),
    #[error("failed to configure OTLP exporter: {0}")]
    Exporter(String),
    #[error("high-cardinality value is not allowed as a metric dimension")]
    HighCardinalityMetricDimension,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn redaction_removes_nested_credentials() {
        let value = json!({
            "username": "operator",
            "password": "sentinel-password",
            "nested": {
                "accessToken": "sentinel-token",
                "refresh_token": "sentinel-refresh",
                "client-secret": "sentinel-client-secret",
                "api.key": "sentinel-api-key",
                "authorization": "Bearer sentinel"
            },
            "items": [{"private-key": "sentinel-key"}]
        });
        let redacted = redact_json(&value);
        let serialized = serde_json::to_string(&redacted).unwrap();
        for sentinel in [
            "sentinel-password",
            "sentinel-token",
            "sentinel-refresh",
            "sentinel-client-secret",
            "sentinel-api-key",
            "Bearer sentinel",
            "sentinel-key",
        ] {
            assert!(!serialized.contains(sentinel));
        }
        assert_eq!(redacted["username"], "operator");
    }

    #[test]
    fn sensitive_key_detection_is_naming_style_independent() {
        for key in [
            "accessToken",
            "access_token",
            "access-token",
            "refreshToken",
            "clientSecret",
            "private.key",
            "apiKey",
            "SNMPCommunity",
        ] {
            assert!(is_sensitive_key(key), "expected {key} to be sensitive");
        }
        assert!(!is_sensitive_key("tokenBucketCapacity"));
        assert!(!is_sensitive_key("communityName"));
    }

    #[test]
    fn metric_dimensions_reject_ip_and_resource_ids() {
        assert!(
            MetricDimensions {
                capability: Some("inventory.read".into()),
                provider: Some("snmp".into()),
                transport: Some("udp".into()),
                outcome: "success".into(),
            }
            .validate()
            .is_ok()
        );
        assert!(
            MetricDimensions {
                capability: Some("10.0.0.15".into()),
                provider: None,
                transport: None,
                outcome: "success".into(),
            }
            .validate()
            .is_err()
        );
        assert!(
            MetricDimensions {
                capability: Some(Uuid::now_v7().to_string()),
                provider: None,
                transport: None,
                outcome: "success".into(),
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn correlation_context_preserves_valid_ids_and_replaces_invalid_ids() {
        let request = Uuid::now_v7();
        let correlation = Uuid::now_v7();
        let context =
            CorrelationContext::new(Some(&request.to_string()), Some(&correlation.to_string()));
        assert_eq!(context.request_id(), request);
        assert_eq!(context.correlation_id(), correlation);

        let invalid = CorrelationContext::new(Some("not-a-uuid"), Some(""));
        assert_ne!(invalid.request_id(), Uuid::nil());
        assert_ne!(invalid.correlation_id(), Uuid::nil());
    }

    #[test]
    fn exporter_is_disabled_by_default() {
        unsafe {
            std::env::remove_var("SNM_OTEL_ENABLED");
        }
        let config = TelemetryConfig::from_env("test", "0.1.0");
        assert!(!config.otlp_enabled);
    }
}
