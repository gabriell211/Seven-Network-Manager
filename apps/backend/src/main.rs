mod auth;
mod db;

use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use auth::AuthService;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, HeaderName, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use db::Database;
use serde::Serialize;
use tower_http::{
    catch_panic::CatchPanicLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState {
    runtime: Arc<dyn RuntimePort>,
    database: Database,
    auth: Arc<AuthService>,
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
    database: &'static str,
    runtime: &'static str,
    applied_migrations: i64,
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
    let database_url = env::var("DATABASE_URL")?;
    let max_connections = env::var("SNM_DATABASE_MAX_CONNECTIONS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(10);

    let database = Database::connect(&database_url, max_connections).await?;
    if env_flag("SNM_RUN_MIGRATIONS") {
        database.migrate().await?;
        info!("database migrations applied");
    }
    maybe_bootstrap_scope(&database).await?;

    let auth = Arc::new(AuthService::from_env(database.clone())?);
    maybe_bootstrap_admin(&auth).await?;

    let state = AppState {
        runtime: Arc::new(HttpRuntimeClient::new(runtime_url)?),
        database,
        auth,
    };

    let request_id_header = HeaderName::from_static("x-request-id");
    let app = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/system", get(system))
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/refresh", post(auth::refresh))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/me", get(auth::me))
        .with_state(state)
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(15),
        ))
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

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|value| !value.trim().is_empty())
}

async fn maybe_bootstrap_scope(database: &Database) -> Result<(), sqlx::Error> {
    let Some(organization_slug) = non_empty_env("SNM_BOOTSTRAP_ORG_SLUG") else {
        return Ok(());
    };
    let organization_name = non_empty_env("SNM_BOOTSTRAP_ORG_NAME")
        .unwrap_or_else(|| "Seven Network Manager".to_owned());
    let site_slug =
        non_empty_env("SNM_BOOTSTRAP_SITE_SLUG").unwrap_or_else(|| "default".to_owned());
    let site_name =
        non_empty_env("SNM_BOOTSTRAP_SITE_NAME").unwrap_or_else(|| "Default Site".to_owned());
    let (organization_id, site_id, routing_domain_id) = database
        .bootstrap_scope(
            &organization_slug,
            &organization_name,
            &site_slug,
            &site_name,
        )
        .await?;
    info!(%organization_id, %site_id, %routing_domain_id, "bootstrap scope ready");
    Ok(())
}

async fn maybe_bootstrap_admin(auth: &AuthService) -> Result<(), Box<dyn std::error::Error>> {
    let Some(email) = non_empty_env("SNM_BOOTSTRAP_ADMIN_EMAIL") else {
        return Ok(());
    };
    let organization_slug = non_empty_env("SNM_BOOTSTRAP_ORG_SLUG")
        .ok_or("SNM_BOOTSTRAP_ORG_SLUG is required when bootstrapping an administrator")?;
    let password = non_empty_env("SNM_BOOTSTRAP_ADMIN_PASSWORD")
        .ok_or("SNM_BOOTSTRAP_ADMIN_PASSWORD is required when bootstrapping an administrator")?;
    let display_name = non_empty_env("SNM_BOOTSTRAP_ADMIN_NAME")
        .unwrap_or_else(|| "SNM Administrator".to_owned());
    auth.bootstrap_admin(
        &organization_slug,
        &email,
        &display_name,
        password.as_bytes(),
    )
    .await?;
    info!("bootstrap administrator ensured");
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
    let database = match state.database.health().await {
        Ok(health) => health,
        Err(error) => {
            warn!(error = %error, "database readiness failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadinessResponse {
                    status: "not_ready",
                    database: "unavailable",
                    runtime: match runtime {
                        RuntimeHealth::Ready => "ready",
                        RuntimeHealth::Unavailable => "unavailable",
                    },
                    applied_migrations: 0,
                }),
            )
                .into_response();
        }
    };

    let (status, runtime_status) = match runtime {
        RuntimeHealth::Ready => ("ready", "ready"),
        RuntimeHealth::Unavailable => ("degraded", "unavailable"),
    };

    // Runtime availability is reported separately. The control-plane stays
    // observable and never falls back to direct LAN execution.
    (
        StatusCode::OK,
        Json(ReadinessResponse {
            status,
            database: "ready",
            runtime: runtime_status,
            applied_migrations: database.migration_count,
        }),
    )
        .into_response()
}

async fn system(headers: HeaderMap) -> Response {
    let request_id = headers
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
