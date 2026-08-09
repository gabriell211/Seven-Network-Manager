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
use snm_domain::inventory::{DeviceLifecycle, DeviceType};
use snm_inventory_store::{
    InventoryError, InventoryQuery, MetadataPatch, MutationContext, NewDevice,
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
pub(crate) struct DeviceListQuery {
    search: Option<String>,
    lifecycle: Option<DeviceLifecycle>,
    device_type: Option<DeviceType>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpdateDeviceRequest {
    expected_version: i64,
    #[serde(flatten)]
    patch: MetadataPatch,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LifecycleRequest {
    expected_version: i64,
    next: DeviceLifecycle,
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    code: &'static str,
    message: String,
    details: Option<serde_json::Value>,
}

pub(crate) async fn list_devices(
    State(state): State<AppState>,
    Path(site_id): Path<Uuid>,
    Query(query): Query<DeviceListQuery>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "devices.view",
        &correlation,
        "inventory.device.list",
        None,
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let query = InventoryQuery {
        search: query.search,
        lifecycle: query.lifecycle,
        device_type: query.device_type,
        limit: query.limit,
        offset: query.offset,
    };
    match state
        .inventory
        .list(principal.organization_id, site_id, query)
        .await
    {
        Ok(devices) => Json(devices).into_response(),
        Err(error) => inventory_error_response(error),
    }
}

pub(crate) async fn get_device(
    State(state): State<AppState>,
    Path((site_id, device_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "devices.view",
        &correlation,
        "inventory.device.get",
        Some(device_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    match state
        .inventory
        .get(principal.organization_id, site_id, device_id)
        .await
    {
        Ok(Some(device)) => Json(device).into_response(),
        Ok(None) => api_error(
            StatusCode::NOT_FOUND,
            "device_not_found",
            "device was not found in the requested scope",
            None,
        ),
        Err(error) => inventory_error_response(error),
    }
}

pub(crate) async fn create_device(
    State(state): State<AppState>,
    Path(site_id): Path<Uuid>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(input): Json<NewDevice>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "devices.create",
        &correlation,
        "inventory.device.create",
        None,
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mutation = mutation_context(&principal, site_id, &correlation);
    match state
        .inventory
        .create_manual(&mutation, input, state.inventory_require_approval)
        .await
    {
        Ok(device) => (StatusCode::CREATED, Json(device)).into_response(),
        Err(error) => inventory_error_response(error),
    }
}

pub(crate) async fn update_device(
    State(state): State<AppState>,
    Path((site_id, device_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(request): Json<UpdateDeviceRequest>,
) -> Response {
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        "devices.update",
        &correlation,
        "inventory.device.update",
        Some(device_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mutation = mutation_context(&principal, site_id, &correlation);
    match state
        .inventory
        .update_metadata(
            &mutation,
            device_id,
            request.expected_version,
            request.patch,
        )
        .await
    {
        Ok(device) => Json(device).into_response(),
        Err(error) => inventory_error_response(error),
    }
}

pub(crate) async fn transition_lifecycle(
    State(state): State<AppState>,
    Path((site_id, device_id)): Path<(Uuid, Uuid)>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
    Json(request): Json<LifecycleRequest>,
) -> Response {
    let permission = match request.next {
        DeviceLifecycle::Managed => "devices.approve",
        DeviceLifecycle::Retired | DeviceLifecycle::Archived => "devices.delete",
        _ => "devices.update",
    };
    let principal = match authorize(
        &state,
        &headers,
        site_id,
        permission,
        &correlation,
        "inventory.device.lifecycle.transition",
        Some(device_id),
    )
    .await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let mutation = mutation_context(&principal, site_id, &correlation);
    match state
        .inventory
        .transition_lifecycle(
            &mutation,
            device_id,
            request.expected_version,
            request.next,
            request.reason.as_deref(),
        )
        .await
    {
        Ok(device) => Json(device).into_response(),
        Err(error) => inventory_error_response(error),
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
            resource_type: "device".to_owned(),
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
        tracing::error!(error = %error, action, permission, "failed to persist authorization denial audit");
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

fn inventory_error_response(error: InventoryError) -> Response {
    match error {
        InventoryError::InvalidInput(message) => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_inventory_request",
            message,
            None,
        ),
        InventoryError::DeviceNotFound => api_error(
            StatusCode::NOT_FOUND,
            "device_not_found",
            "device was not found in the requested scope",
            None,
        ),
        InventoryError::VersionConflict { expected, actual } => api_error(
            StatusCode::CONFLICT,
            "device_version_conflict",
            "device changed since it was read",
            Some(json!({"expectedVersion": expected, "actualVersion": actual})),
        ),
        InventoryError::LifecycleBlocksMutation(lifecycle) => api_error(
            StatusCode::CONFLICT,
            "device_lifecycle_blocks_mutation",
            "device lifecycle blocks this mutation",
            Some(json!({"lifecycle": lifecycle})),
        ),
        InventoryError::InvalidLifecycleTransition { from, to } => api_error(
            StatusCode::CONFLICT,
            "invalid_device_lifecycle_transition",
            "the requested lifecycle transition is not allowed",
            Some(json!({"from": from, "to": to})),
        ),
        InventoryError::LifecycleReasonRequired => api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "lifecycle_reason_required",
            "retire or archive operations require a reason",
            None,
        ),
        InventoryError::DuplicateIdentifier => api_error(
            StatusCode::CONFLICT,
            "duplicate_strong_identifier",
            "a strong identifier already belongs to another device",
            None,
        ),
        InventoryError::ReconciliationConflict(device_ids) => api_error(
            StatusCode::CONFLICT,
            "inventory_reconciliation_conflict",
            "the observation matches multiple devices and requires manual review",
            Some(json!({"deviceIds": device_ids})),
        ),
        InventoryError::ReactivationRequiresReview(device_id) => api_error(
            StatusCode::CONFLICT,
            "device_reactivation_requires_review",
            "retired or archived devices require explicit review before reactivation",
            Some(json!({"deviceId": device_id})),
        ),
        InventoryError::CorruptStoredValue(_) | InventoryError::Json(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "inventory_internal_error",
            "inventory data could not be processed",
            None,
        ),
        InventoryError::Audit(_) | InventoryError::Outbox(_) | InventoryError::Database(_) => {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "inventory_unavailable",
                "inventory persistence is temporarily unavailable",
                None,
            )
        }
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
