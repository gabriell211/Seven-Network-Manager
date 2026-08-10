use std::net::IpAddr;

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use snm_audit_store::AuditStore;
use snm_discovery_store::{
    DiscoveryStoreError, MutationContext, NewDiscoveryScope, RunRequestKind, UpdateDiscoveryScope,
};
use snm_observability::CorrelationContext;
use snm_security::audit::{AuditActorType, AuditEventDraft, AuditStatus};
use uuid::Uuid;

use crate::{
    AppState,
    authorization::{AuthorizationError, Principal},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RunListQuery {
    scope_id: Option<Uuid>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResultListQuery {
    #[serde(default = "default_result_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateRunRequest {
    #[serde(default)]
    seed_targets: Vec<IpAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeleteScopeRequest {
    expected_version: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    code: &'static str,
    message: String,
    details: Option<serde_json::Value>,
}

pub(crate) async fn list_scopes(
    State(state): State<AppState>,
    Path(site_id): Path<Uuid>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "discovery.view",
        &correlation,
        "discovery.scope.list",
        None,
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match state
        .discovery
        .list_scopes(principal.organization_id, site_id)
        .await
    {
        Ok(scopes) => Json(scopes).into_response(),
        Err(error) => discovery_error_response(error),
    }
}

pub(crate) async fn get_scope(
    State(state): State<AppState>,
    Path((site_id, scope_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "discovery.view",
        &correlation,
        "discovery.scope.get",
        Some(scope_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match state
        .discovery
        .get_scope(principal.organization_id, site_id, scope_id)
        .await
    {
        Ok(Some(scope)) => Json(scope).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "discovery_scope_not_found",
            "discovery scope was not found",
            None,
        ),
        Err(error) => discovery_error_response(error),
    }
}

pub(crate) async fn create_scope(
    State(state): State<AppState>,
    Path(site_id): Path<Uuid>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(input): Json<NewDiscoveryScope>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "discovery.manage",
        &correlation,
        "discovery.scope.create",
        None,
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let context = mutation_context(&principal, site_id, &correlation);
    match state.discovery.create_scope(&context, input).await {
        Ok(scope) => (StatusCode::CREATED, Json(scope)).into_response(),
        Err(error) => discovery_error_response(error),
    }
}

pub(crate) async fn update_scope(
    State(state): State<AppState>,
    Path((site_id, scope_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(input): Json<UpdateDiscoveryScope>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "discovery.manage",
        &correlation,
        "discovery.scope.update",
        Some(scope_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let context = mutation_context(&principal, site_id, &correlation);
    match state
        .discovery
        .update_scope(&context, scope_id, input)
        .await
    {
        Ok(scope) => Json(scope).into_response(),
        Err(error) => discovery_error_response(error),
    }
}

pub(crate) async fn delete_scope(
    State(state): State<AppState>,
    Path((site_id, scope_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(request): Json<DeleteScopeRequest>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "discovery.manage",
        &correlation,
        "discovery.scope.delete",
        Some(scope_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let context = mutation_context(&principal, site_id, &correlation);
    match state
        .discovery
        .delete_scope(&context, scope_id, request.expected_version)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => discovery_error_response(error),
    }
}

pub(crate) async fn create_run(
    State(state): State<AppState>,
    Path((site_id, scope_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(request): Json<CreateRunRequest>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "discovery.execute",
        &correlation,
        "discovery.run.create",
        Some(scope_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let context = mutation_context(&principal, site_id, &correlation);
    match state
        .discovery
        .create_run(
            &context,
            scope_id,
            RunRequestKind::Manual,
            request.seed_targets,
        )
        .await
    {
        Ok(run) => (StatusCode::ACCEPTED, Json(run)).into_response(),
        Err(error) => discovery_error_response(error),
    }
}

pub(crate) async fn list_runs(
    State(state): State<AppState>,
    Path(site_id): Path<Uuid>,
    Query(query): Query<RunListQuery>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "discovery.view",
        &correlation,
        "discovery.run.list",
        query.scope_id,
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match state
        .discovery
        .list_runs(
            principal.organization_id,
            site_id,
            query.scope_id,
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(runs) => Json(runs).into_response(),
        Err(error) => discovery_error_response(error),
    }
}

pub(crate) async fn get_run(
    State(state): State<AppState>,
    Path((site_id, run_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "discovery.view",
        &correlation,
        "discovery.run.get",
        Some(run_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match state
        .discovery
        .get_run(principal.organization_id, site_id, run_id)
        .await
    {
        Ok(Some(run)) => Json(run).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "discovery_run_not_found",
            "discovery run was not found",
            None,
        ),
        Err(error) => discovery_error_response(error),
    }
}

pub(crate) async fn cancel_run(
    State(state): State<AppState>,
    Path((site_id, run_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "discovery.cancel",
        &correlation,
        "discovery.run.cancel",
        Some(run_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let context = mutation_context(&principal, site_id, &correlation);
    match state.discovery.request_cancel(&context, run_id).await {
        Ok(run) => Json(run).into_response(),
        Err(error) => discovery_error_response(error),
    }
}

pub(crate) async fn list_results(
    State(state): State<AppState>,
    Path((site_id, run_id)): Path<(Uuid, Uuid)>,
    Query(query): Query<ResultListQuery>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "discovery.view",
        &correlation,
        "discovery.run.results.list",
        Some(run_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match state
        .discovery
        .list_probe_results(
            principal.organization_id,
            site_id,
            run_id,
            query.limit,
            query.offset,
        )
        .await
    {
        Ok(results) => Json(results).into_response(),
        Err(error) => discovery_error_response(error),
    }
}

async fn authorize(
    state: &AppState,
    headers: &HeaderMap,
    site_id: Uuid,
    permission: &str,
    correlation: &CorrelationContext,
    action: &str,
    resource_id: Option<Uuid>,
) -> Result<Principal, Response> {
    let principal = state
        .authorization
        .authenticate(headers)
        .await
        .map_err(authorization_error_response)?;
    match state
        .authorization
        .require_site_permission(&principal, site_id, permission)
        .await
    {
        Ok(()) => Ok(principal),
        Err(AuthorizationError::PermissionDenied) => {
            audit_denial(
                state,
                &principal,
                site_id,
                correlation,
                action,
                resource_id,
                permission,
            )
            .await;
            Err(api_error(
                StatusCode::FORBIDDEN,
                "permission_denied",
                "the authenticated principal is not allowed to perform this action",
                None,
            ))
        }
        Err(error) => Err(authorization_error_response(error)),
    }
}

async fn audit_denial(
    state: &AppState,
    principal: &Principal,
    site_id: Uuid,
    correlation: &CorrelationContext,
    action: &str,
    resource_id: Option<Uuid>,
    permission: &str,
) {
    let store = AuditStore::new(state.database.pool().clone());
    let result = store
        .append(AuditEventDraft {
            organization_id: principal.organization_id,
            site_id: Some(site_id),
            actor_type: AuditActorType::User,
            actor_id: Some(principal.user_id),
            session_id: Some(principal.session_id),
            source_ip: None,
            request_id: correlation.request_id().to_string(),
            correlation_id: correlation.correlation_id(),
            action: action.to_owned(),
            resource_type: "discovery".to_owned(),
            resource_id: resource_id.map(|value| value.to_string()),
            provider: None,
            occurred_at_unix_ms: Utc::now().timestamp_millis(),
            duration_ms: None,
            status: AuditStatus::Denied,
            reason_code: Some("permission_denied".to_owned()),
            before: None,
            after: None,
            result: Some(json!({"requiredPermission": permission, "allowed": false})),
        })
        .await;
    if let Err(error) = result {
        tracing::error!(error = %error, action, permission, "failed to persist discovery authorization denial");
    }
}

fn mutation_context(
    principal: &Principal,
    site_id: Uuid,
    correlation: &CorrelationContext,
) -> MutationContext {
    MutationContext {
        organization_id: principal.organization_id,
        site_id,
        actor_type: AuditActorType::User,
        actor_id: Some(principal.user_id),
        session_id: Some(principal.session_id),
        source_ip: None,
        request_id: correlation.request_id().to_string(),
        correlation_id: correlation.correlation_id(),
    }
}

fn authorization_error_response(error: AuthorizationError) -> Response {
    match error {
        AuthorizationError::InvalidSession => api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "invalid or expired session",
            None,
        ),
        AuthorizationError::PermissionDenied => api_error(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "permission denied",
            None,
        ),
        AuthorizationError::Unavailable => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization_unavailable",
            "authorization subsystem is temporarily unavailable",
            None,
        ),
    }
}

fn discovery_error_response(error: DiscoveryStoreError) -> Response {
    match error {
        DiscoveryStoreError::InvalidInput(message) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_discovery_request",
            message,
            None,
        ),
        DiscoveryStoreError::ScopeNotFound => api_error(
            StatusCode::NOT_FOUND,
            "discovery_scope_not_found",
            "discovery scope was not found",
            None,
        ),
        DiscoveryStoreError::RunNotFound => api_error(
            StatusCode::NOT_FOUND,
            "discovery_run_not_found",
            "discovery run was not found",
            None,
        ),
        DiscoveryStoreError::ScopeDisabled => api_error(
            StatusCode::CONFLICT,
            "discovery_scope_disabled",
            "discovery scope is disabled",
            None,
        ),
        DiscoveryStoreError::ScopeHasActiveRun => api_error(
            StatusCode::CONFLICT,
            "discovery_scope_active_run",
            "discovery scope already has a queued or running job",
            None,
        ),
        DiscoveryStoreError::ScopeHasHistory => api_error(
            StatusCode::CONFLICT,
            "discovery_scope_has_history",
            "scope with run history cannot be deleted",
            None,
        ),
        DiscoveryStoreError::DuplicateScope => api_error(
            StatusCode::CONFLICT,
            "duplicate_discovery_scope",
            "the same CIDR already exists in this routing domain",
            None,
        ),
        DiscoveryStoreError::RoutingDomainNotFound => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "routing_domain_not_found",
            "routing domain does not belong to this site",
            None,
        ),
        DiscoveryStoreError::SeedOutsideScope(address) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "discovery_seed_outside_scope",
            "seed target is outside the configured CIDR",
            Some(json!({"address": address})),
        ),
        DiscoveryStoreError::RunNotRunning => api_error(
            StatusCode::CONFLICT,
            "discovery_run_not_running",
            "discovery run is not currently running",
            None,
        ),
        DiscoveryStoreError::ProbeScopeMismatch
        | DiscoveryStoreError::InvalidStoredValue(_)
        | DiscoveryStoreError::Database(_)
        | DiscoveryStoreError::Serialization(_)
        | DiscoveryStoreError::Audit(_)
        | DiscoveryStoreError::Outbox(_) => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "discovery_unavailable",
            "discovery subsystem is temporarily unavailable",
            None,
        ),
        DiscoveryStoreError::VersionConflict { expected, actual } => api_error(
            StatusCode::CONFLICT,
            "discovery_version_conflict",
            "discovery resource changed since it was read",
            Some(json!({"expectedVersion": expected, "actualVersion": actual})),
        ),
    }
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    details: Option<serde_json::Value>,
) -> Response {
    (
        status,
        Json(ApiErrorBody {
            code,
            message: message.into(),
            details,
        }),
    )
        .into_response()
}

fn default_limit() -> i64 {
    50
}

fn default_result_limit() -> i64 {
    200
}
