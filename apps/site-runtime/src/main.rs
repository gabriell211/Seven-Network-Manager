use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use snm_domain::TcpConnectRequest;
use snm_executor_core::{DefaultNetworkExecutor, NetworkExecutor, NetworkPolicy};
use subtle::ConstantTimeEq;
use tower_http::{catch_panic::CatchPanicLayer, timeout::TimeoutLayer, trace::TraceLayer};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

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
    init_tracing();

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
        .layer(TimeoutLayer::new(Duration::from_secs(35)))
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new());

    let listener = tokio::net::TcpListener::bind(bind).await?;
    info!(%bind, "site runtime listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
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
    if let Err(response) = authorize(&headers, &state.token) {
        return response;
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
    if let Err(response) = authorize(&headers, &state.token) {
        return response;
    }

    match state.executor.tcp_connect(request).await {
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

fn authorize(headers: &HeaderMap, expected: &str) -> Result<(), Response> {
    let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    let Ok(value) = value.to_str() else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };
    let Some(provided) = value.strip_prefix("Bearer ") else {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    };

    let same_length = provided.len() == expected.len();
    let matches = same_length && provided.as_bytes().ct_eq(expected.as_bytes()).into();
    if matches {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED.into_response())
    }
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_target(false)
        .init();
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
