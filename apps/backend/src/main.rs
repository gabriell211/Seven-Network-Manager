use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderName, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState {
    runtime: Arc<dyn RuntimePort>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ErrorEnvelope {
    code: &'static str,
    message: String,
    details: Option<serde_json::Value>,
    request_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    component: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadinessResponse {
    status: &'static str,
    runtime: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SystemResponse {
    name: &'static str,
    version: &'static str,
    deployment_mode: &'static str,
}

#[derive(Debug)]
enum RuntimeHealth {
    Ready,
    Unavailable,
}

#[async_trait]
trait RuntimePort: Send + Sync {
    async fn health(&self) -> RuntimeHealth;
}

#[derive(Clone)]
struct HttpRuntimeClient {
    client: reqwest::Client,
    base_url: String,
}

impl HttpRuntimeClient {
    fn new(base_url: String) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(1))
                .timeout(Duration::from_secs(2))
                .build()?,
            base_url,
        })
    }
}

#[async_trait]
impl RuntimePort for HttpRuntimeClient {
    async fn health(&self) -> RuntimeHealth {
        match self
            .client
            .get(format!("{}/health", self.base_url))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => RuntimeHealth::Ready,
            _ => RuntimeHealth::Unavailable,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let bind: SocketAddr = env::var("SNM_BACKEND_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        .parse()?;
    let runtime_url =
        env::var("SNM_RUNTIME_URL").unwrap_or_else(|_| "http://127.0.0.1:9765".to_owned());

    let state = AppState {
        runtime: Arc::new(HttpRuntimeClient::new(runtime_url)?),
    };

    let request_id_header = HeaderName::from_static("x-request-id");
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/system", get(system))
        .with_state(state)
        .layer(TimeoutLayer::new(Duration::from_secs(15)))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new());

    let listener = tokio::net::TcpListener::bind(bind).await?;
    info!(%bind, "backend listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        component: "backend",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn ready(State(state): State<AppState>) -> Response {
    let runtime = state.runtime.health().await;
    let body = match runtime {
        RuntimeHealth::Ready => ReadinessResponse {
            status: "ready",
            runtime: "ready",
        },
        RuntimeHealth::Unavailable => ReadinessResponse {
            status: "degraded",
            runtime: "unavailable",
        },
    };

    // Runtime availability is reported separately. The control-plane remains
    // alive and observable instead of falling back to direct LAN execution.
    (StatusCode::OK, Json(body)).into_response()
}

async fn system<B>(request: Request<B>) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    let _contract_example = ErrorEnvelope {
        code: "example",
        message: "public errors use a stable envelope".to_owned(),
        details: None,
        request_id,
    };

    Json(SystemResponse {
        name: "Seven Network Manager",
        version: env!("CARGO_PKG_VERSION"),
        deployment_mode: "production-mvp-onprem",
    })
    .into_response()
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
