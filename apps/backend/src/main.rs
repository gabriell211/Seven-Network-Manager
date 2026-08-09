use anyhow::Result;
use axum::{routing::get, Json, Router};
use serde::Serialize;
use snm_domain::{
    foundation_capabilities, Alert, AlertId, AlertState, DiscoveryRun, DiscoveryRunId,
    DiscoveryRunState, DiscoveryScope, Severity, TrialStatus,
};
use snm_shared::ApiEnvelope;
use std::net::SocketAddr;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    component: &'static str,
}

#[derive(Debug, Serialize)]
struct SystemResponse {
    name: &'static str,
    phase: &'static str,
    roadmap_checkpoint: &'static str,
    local_runtime_required: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("snm_backend=info,tower_http=info")
        .init();

    let bind = std::env::var("SNM_BACKEND_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let addr: SocketAddr = bind.parse()?;

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/system", get(system))
        .route("/api/v1/capabilities", get(capabilities))
        .route("/api/v1/inventory/devices", get(devices))
        .route("/api/v1/discovery/runs", get(discovery_runs))
        .route("/api/v1/alerts", get(alerts))
        .route("/api/v1/trial/status", get(trial_status))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    tracing::info!(%addr, "Seven Network Manager backend started");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> Json<ApiEnvelope<HealthResponse>> {
    Json(ApiEnvelope::v1(HealthResponse {
        status: "ok",
        component: "snm-backend",
    }))
}

async fn system() -> Json<ApiEnvelope<SystemResponse>> {
    Json(ApiEnvelope::v1(SystemResponse {
        name: "Seven Network Manager",
        phase: "FOUNDATION",
        roadmap_checkpoint: "C0/C1",
        local_runtime_required: true,
    }))
}

async fn capabilities() -> Json<ApiEnvelope<Vec<snm_domain::CapabilityDescriptor>>> {
    Json(ApiEnvelope::v1(foundation_capabilities()))
}

async fn devices() -> Json<ApiEnvelope<Vec<snm_domain::Device>>> {
    Json(ApiEnvelope::v1(Vec::new()))
}

async fn discovery_runs() -> Json<ApiEnvelope<Vec<DiscoveryRun>>> {
    Json(ApiEnvelope::v1(vec![DiscoveryRun {
        id: DiscoveryRunId(uuid::Uuid::new_v4()),
        scope: DiscoveryScope {
            site_id: snm_domain::SiteId(uuid::Uuid::new_v4()),
            routing_domain_id: snm_domain::RoutingDomainId(uuid::Uuid::new_v4()),
            cidrs: vec!["192.168.0.0/24".to_string()],
            include_arp: true,
            include_dns: true,
            include_tcp: true,
        },
        state: DiscoveryRunState::Planned,
        discovered_count: 0,
    }]))
}

async fn alerts() -> Json<ApiEnvelope<Vec<Alert>>> {
    Json(ApiEnvelope::v1(vec![Alert {
        id: AlertId(uuid::Uuid::new_v4()),
        severity: Severity::Info,
        state: AlertState::Open,
        title: "SNM foundation online".to_string(),
        evidence: "Backend contract is reachable; providers are not bound yet".to_string(),
        created_at: chrono::Utc::now(),
    }]))
}

async fn trial_status() -> Json<ApiEnvelope<TrialStatus>> {
    Json(ApiEnvelope::v1(TrialStatus::local_development()))
}
