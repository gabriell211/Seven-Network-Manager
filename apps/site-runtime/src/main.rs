use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use snm_domain::TcpConnectRequest;
use snm_executor_core::{DefaultNetworkExecutor, NetworkExecutor, NetworkPolicy};
use snm_observability::{CorrelationContext, TelemetryConfig};
use subtle::ConstantTimeEq;
use tower_http::{catch_panic::CatchPanicLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{error, info, warn, Instrument};

#[derive(Clone)]
struct AppState {
    token: Arc<str>,
    executor: Arc<dyn NetworkExecutor>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    component: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct CapabilityResponse {
    capabilities: Vec<&'static str>,
}

#[derive(Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let telemetry = snm_observability::init(TelemetryConfig::from_env(
        "snm-site-runtime",
        env!("CARGO_PKG_VERSION"),
    ))?;
    if let Some(exporter_error) = telemetry.exporter_error() {
        warn!(error = exporter_error, "OTLP exporter disabled after configuration failure");
    }

    let bind: SocketAddr = env::var("SNM_RUNTIME_BIND")
        .unwrap_or_else(|_| "127.0.0.1:9765".to_owned())
        .parse()?;
    let allow_non_loopback = env_flag("SNM_RUNTIME_ALLOW_NON_LOOPBACK");
    if !bind.ip().is_loopback() && !allow_non_loopback {
        return Err(
            "runtime refuses non-loopback bind unless SNM_RUNTIME_ALLOW_NON_LOOPBACK=true".into(),
        );
    }

    let token = env::var("SNM_RUNTIME_TOKEN")?;
    if token.len() < 32 || token == "change-me-with-a-long-random-secret" {
        return Err(
            "SNM_RUNTIME_TOKEN must be a non-default secret with at least 32 characters".into(),
        );
    }

    let executor = DefaultNetworkExecutor::new(NetworkPolicy {
        allow_public_targets: env_flag("SNM_RUNTIME_ALLOW_PUBLIC_TARGETS"),
    });

    let state = AppState {
        token: Arc::from(token),
        executor: Arc::new(executor),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/execute/tcp-connect", post(tcp_connect))
        .with_state(state)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(35),
        ))
        .layer(middleware::from_fn(correlation_middleware))
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new());

    let listener = tokio::net::TcpListener::bind(bind).await?;
    info!(%bind, "site runtime listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    telemetry.shutdown();
    Ok(())
}

async fn correlation_middleware(mut request: Request<Body>, next: Next) -> Response {
    let request_id = header_text(request.headers(), "x-request-id");
    let correlation_id = header_text(request.headers(), "x-correlation-id");
    let context = CorrelationContext::new(request_id, correlation_id);

    let request_header = HeaderValue::from_str(&context.request_id().to_string())
        .expect("UUID request ID is always a valid header value");
    let correlation_header = HeaderValue::from_str(&context.correlation_id().to_string())
        .expect("UUID correlation ID is always a valid header value");
    request
        .headers_mut()
        .insert(HeaderName::from_static("x-request-id"), request_header.clone());
    request.headers_mut().insert(
        HeaderName::from_static("x-correlation-id"),
        correlation_header.clone(),
    );
    request.extensions_mut().insert(context.clone());

    let span = context.operation_span("runtime.http.request");
    let mut response = next.run(request).instrument(span).await;
    response
        .headers_mut()
        .insert(HeaderName::from_static("x-request-id"), request_header);
    response.headers_mut().insert(
        HeaderName::from_static("x-correlation-id"),
        correlation_header,
    );
    response
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        component: "site-runtime",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn ready() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ready",
        component: "site-runtime",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn capabilities(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(status) = authorize(&headers, &state.token) {
        return status.into_response();
    }

    Json(CapabilityResponse {
        capabilities: state
            .executor
            .capabilities()
            .iter()
            .map(|item| item.as_str())
            .collect(),
    })
    .into_response()
}

async fn tcp_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TcpConnectRequest>,
) -> Response {
    if let Err(status) = authorize(&headers, &state.token) {
        return status.into_response();
    }

    let transport_span = tracing::info_span!(
        "snm.runtime.operation",
        capability = "network.tcp.connect",
        transport = "tcp"
    );
    match state.executor.tcp_connect(request).instrument(transport_span).await {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(error) => {
            let (status, code) = match error {
                snm_executor_core::ExecutorError::InvalidRequest(_) => (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "invalid_execution_request",
                ),
                snm_executor_core::ExecutorError::TargetDenied => {
                    (StatusCode::FORBIDDEN, "target_denied")
                }
            };
            (
                status,
                Json(ErrorResponse {
                    code,
                    message: error.to_string(),
                }),
            )
                .into_response()
        }
    }
}

fn authorize(headers: &HeaderMap, expected: &str) -> Result<(), StatusCode> {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Ok(value) = value.to_str() else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let Some(provided) = value.strip_prefix("Bearer ") else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let same_length = provided.len() == expected.len();
    let matches = same_length && provided.as_bytes().ct_eq(expected.as_bytes()).into();
    if matches {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(%error, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => error!(%error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
