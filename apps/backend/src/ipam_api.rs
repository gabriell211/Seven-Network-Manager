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
use snm_domain::ipam::AddressState;
use snm_ipam_store::{
    AddressQuery, IpamError, MutationContext, NewIpAddress, NewIpPrefix, UpdateIpAddress,
    UpdateIpPrefix,
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
pub(crate) struct PrefixListQuery {
    routing_domain_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AddressListQuery {
    routing_domain_id: Option<Uuid>,
    prefix_id: Option<Uuid>,
    state: Option<AddressState>,
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeleteRequest {
    expected_version: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    code: &'static str,
    message: String,
    details: Option<serde_json::Value>,
    request_id: String,
}

pub(crate) async fn list_prefixes(
    State(state): State<AppState>,
    Path(site_id): Path<Uuid>,
    Query(query): Query<PrefixListQuery>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "ipam.view",
        &correlation,
        "ipam.prefix.list",
        None,
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match state
        .ipam
        .list_prefixes(
            principal.organization_id,
            site_id,
            query.routing_domain_id,
        )
        .await
    {
        Ok(prefixes) => Json(prefixes).into_response(),
        Err(error) => ipam_error_response(error, &correlation),
    }
}

pub(crate) async fn create_prefix(
    State(state): State<AppState>,
    Path(site_id): Path<Uuid>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(input): Json<NewIpPrefix>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "ipam.create",
        &correlation,
        "ipam.prefix.create",
        None,
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mutation = mutation_context(&principal, site_id, &correlation);
    match state.ipam.create_prefix(&mutation, input).await {
        Ok(prefix) => (StatusCode::CREATED, Json(prefix)).into_response(),
        Err(error) => ipam_error_response(error, &correlation),
    }
}

pub(crate) async fn update_prefix(
    State(state): State<AppState>,
    Path((site_id, prefix_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(input): Json<UpdateIpPrefix>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "ipam.update",
        &correlation,
        "ipam.prefix.update",
        Some(prefix_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mutation = mutation_context(&principal, site_id, &correlation);
    match state.ipam.update_prefix(&mutation, prefix_id, input).await {
        Ok(prefix) => Json(prefix).into_response(),
        Err(error) => ipam_error_response(error, &correlation),
    }
}

pub(crate) async fn delete_prefix(
    State(state): State<AppState>,
    Path((site_id, prefix_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(input): Json<DeleteRequest>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "ipam.delete",
        &correlation,
        "ipam.prefix.delete",
        Some(prefix_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mutation = mutation_context(&principal, site_id, &correlation);
    match state
        .ipam
        .delete_prefix(&mutation, prefix_id, input.expected_version)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => ipam_error_response(error, &correlation),
    }
}

pub(crate) async fn list_addresses(
    State(state): State<AppState>,
    Path(site_id): Path<Uuid>,
    Query(query): Query<AddressListQuery>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "ipam.view",
        &correlation,
        "ipam.address.list",
        None,
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let query = AddressQuery {
        routing_domain_id: query.routing_domain_id,
        prefix_id: query.prefix_id,
        state: query.state,
        search: query.search,
        limit: query.limit,
        offset: query.offset,
    };
    match state
        .ipam
        .list_addresses(principal.organization_id, site_id, query)
        .await
    {
        Ok(addresses) => Json(addresses).into_response(),
        Err(error) => ipam_error_response(error, &correlation),
    }
}

pub(crate) async fn create_address(
    State(state): State<AppState>,
    Path(site_id): Path<Uuid>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(input): Json<NewIpAddress>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "ipam.create",
        &correlation,
        "ipam.address.create",
        None,
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mutation = mutation_context(&principal, site_id, &correlation);
    match state.ipam.create_address(&mutation, input).await {
        Ok(address) => (StatusCode::CREATED, Json(address)).into_response(),
        Err(error) => ipam_error_response(error, &correlation),
    }
}

pub(crate) async fn update_address(
    State(state): State<AppState>,
    Path((site_id, address_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(input): Json<UpdateIpAddress>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "ipam.update",
        &correlation,
        "ipam.address.update",
        Some(address_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mutation = mutation_context(&principal, site_id, &correlation);
    match state
        .ipam
        .update_address(&mutation, address_id, input)
        .await
    {
        Ok(address) => Json(address).into_response(),
        Err(error) => ipam_error_response(error, &correlation),
    }
}

pub(crate) async fn delete_address(
    State(state): State<AppState>,
    Path((site_id, address_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(input): Json<DeleteRequest>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "ipam.delete",
        &correlation,
        "ipam.address.delete",
        Some(address_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mutation = mutation_context(&principal, site_id, &correlation);
    match state
        .ipam
        .delete_address(&mutation, address_id, input.expected_version)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => ipam_error_response(error, &correlation),
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
        .map_err(|error| authorization_error_response(error, correlation))?;
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
                correlation,
            ))
        }
        Err(error) => Err(authorization_error_response(error, correlation)),
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
            resource_type: "ipam".to_owned(),
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
        tracing::error!(error = %error, action, permission, "failed to persist IPAM authorization denial audit");
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

fn authorization_error_response(
    error: AuthorizationError,
    correlation: &CorrelationContext,
) -> Response {
    match error {
        AuthorizationError::InvalidSession => api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "invalid or expired session",
            None,
            correlation,
        ),
        AuthorizationError::PermissionDenied => api_error(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "permission denied",
            None,
            correlation,
        ),
        AuthorizationError::Unavailable => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization_unavailable",
            "authorization subsystem is temporarily unavailable",
            None,
            correlation,
        ),
    }
}

fn ipam_error_response(error: IpamError, correlation: &CorrelationContext) -> Response {
    match error {
        IpamError::InvalidInput(message) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_ipam_request",
            message,
            None,
            correlation,
        ),
        IpamError::PrefixOverlap => api_error(
            StatusCode::CONFLICT,
            "ipam_prefix_overlap",
            "prefix overlaps another prefix in the same routing domain",
            None,
            correlation,
        ),
        IpamError::AddressConflict => api_error(
            StatusCode::CONFLICT,
            "ipam_address_conflict",
            "address is already allocated in the requested routing domain",
            None,
            correlation,
        ),
        IpamError::ReferenceConflict => api_error(
            StatusCode::CONFLICT,
            "ipam_reference_conflict",
            "resource has dependent references or does not belong to this scope",
            None,
            correlation,
        ),
        IpamError::PrefixNotFound => api_error(
            StatusCode::NOT_FOUND,
            "ipam_prefix_not_found",
            "prefix was not found in the requested scope",
            None,
            correlation,
        ),
        IpamError::AddressNotFound => api_error(
            StatusCode::NOT_FOUND,
            "ipam_address_not_found",
            "address was not found in the requested scope",
            None,
            correlation,
        ),
        IpamError::VersionConflict { expected, actual } => api_error(
            StatusCode::CONFLICT,
            "ipam_version_conflict",
            "resource changed since it was read",
            Some(json!({"expectedVersion": expected, "actualVersion": actual})),
            correlation,
        ),
        IpamError::InvalidStoredValue(message) => {
            tracing::error!(%message, "invalid value persisted in IPAM storage");
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ipam_invalid_stored_value",
                "IPAM storage contains an invalid value",
                None,
                correlation,
            )
        }
        IpamError::Audit(error) => internal_error("audit", error, correlation),
        IpamError::Outbox(error) => internal_error("outbox", error, correlation),
        IpamError::Serialization(error) => internal_error("serialization", error, correlation),
        IpamError::Database(error) => internal_error("database", error, correlation),
    }
}

fn internal_error(
    subsystem: &'static str,
    error: impl std::fmt::Display,
    correlation: &CorrelationContext,
) -> Response {
    tracing::error!(%error, subsystem, "IPAM operation failed");
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "ipam_unavailable",
        "IPAM subsystem is temporarily unavailable",
        Some(json!({"subsystem": subsystem})),
        correlation,
    )
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    details: Option<serde_json::Value>,
    correlation: &CorrelationContext,
) -> Response {
    (
        status,
        Json(ApiErrorBody {
            code,
            message: message.into(),
            details,
            request_id: correlation.request_id().to_string(),
        }),
    )
        .into_response()
}

const fn default_limit() -> i64 {
    100
}
