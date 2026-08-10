use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use snm_observability::CorrelationContext;
use uuid::Uuid;

use crate::{AppState, authorization::AuthorizationError};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationView {
    id: Uuid,
    slug: String,
    name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RoutingDomainView {
    id: Uuid,
    name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SiteView {
    id: Uuid,
    slug: String,
    name: String,
    timezone: String,
    default_routing_domain: Option<RoutingDomainView>,
    permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationalContextResponse {
    organization: OrganizationView,
    sites: Vec<SiteView>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
    details: Option<serde_json::Value>,
    request_id: String,
}

type SiteRow = (Uuid, String, String, String, Option<Uuid>, Option<String>);

pub(crate) async fn get_context(
    State(state): State<AppState>,
    Extension(correlation): Extension<CorrelationContext>,
    headers: HeaderMap,
) -> Response {
    let principal = match state.authorization.authenticate(&headers).await {
        Ok(principal) => principal,
        Err(error) => return authorization_error(error, &correlation),
    };

    let organization = match sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT id, slug, name FROM organizations WHERE id = $1",
    )
    .bind(principal.organization_id)
    .fetch_optional(state.database.pool())
    .await
    {
        Ok(Some((id, slug, name))) => OrganizationView { id, slug, name },
        Ok(None) => {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "invalid_session",
                "organization for the authenticated session no longer exists",
                &correlation,
            );
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to load authenticated organization context");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "context_unavailable",
                "operational context is temporarily unavailable",
                &correlation,
            );
        }
    };

    let rows = match sqlx::query_as::<_, SiteRow>(
        r#"
        SELECT DISTINCT s.id, s.slug, s.name, s.timezone, rd.id, rd.name
        FROM sites s
        JOIN role_bindings rb
          ON rb.organization_id = s.organization_id
         AND rb.user_id = $2
         AND (rb.site_id IS NULL OR rb.site_id = s.id)
        LEFT JOIN routing_domains rd
          ON rd.organization_id = s.organization_id
         AND rd.site_id = s.id
         AND rd.is_default = true
        WHERE s.organization_id = $1
        ORDER BY s.name, s.id
        "#,
    )
    .bind(principal.organization_id)
    .bind(principal.user_id)
    .fetch_all(state.database.pool())
    .await
    {
        Ok(rows) => rows,
        Err(error) => {
            tracing::error!(error = %error, "failed to load accessible sites");
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "context_unavailable",
                "operational context is temporarily unavailable",
                &correlation,
            );
        }
    };

    let mut sites = Vec::with_capacity(rows.len());
    for (id, slug, name, timezone, routing_domain_id, routing_domain_name) in rows {
        let permissions = match sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT p.code
            FROM role_bindings rb
            JOIN roles r ON r.id = rb.role_id
            JOIN role_permissions rp ON rp.role_id = rb.role_id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE rb.organization_id = $1
              AND rb.user_id = $2
              AND (rb.site_id IS NULL OR rb.site_id = $3)
              AND (r.organization_id IS NULL OR r.organization_id = $1)
            ORDER BY p.code
            "#,
        )
        .bind(principal.organization_id)
        .bind(principal.user_id)
        .bind(id)
        .fetch_all(state.database.pool())
        .await
        {
            Ok(permissions) => permissions,
            Err(error) => {
                tracing::error!(error = %error, site_id = %id, "failed to load effective site permissions");
                return api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authorization_unavailable",
                    "authorization subsystem is temporarily unavailable",
                    &correlation,
                );
            }
        };

        let default_routing_domain = routing_domain_id.map(|domain_id| RoutingDomainView {
            id: domain_id,
            name: routing_domain_name.unwrap_or_else(|| "default".to_owned()),
        });
        sites.push(SiteView {
            id,
            slug,
            name,
            timezone,
            default_routing_domain,
            permissions,
        });
    }

    Json(OperationalContextResponse {
        organization,
        sites,
    })
    .into_response()
}

fn authorization_error(error: AuthorizationError, correlation: &CorrelationContext) -> Response {
    match error {
        AuthorizationError::InvalidSession => api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "invalid or expired session",
            correlation,
        ),
        AuthorizationError::PermissionDenied => api_error(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "permission denied",
            correlation,
        ),
        AuthorizationError::Unavailable => api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authorization_unavailable",
            "authorization subsystem is temporarily unavailable",
            correlation,
        ),
    }
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    correlation: &CorrelationContext,
) -> Response {
    (
        status,
        Json(ApiErrorBody {
            code,
            message,
            details: None,
            request_id: correlation.request_id().to_string(),
        }),
    )
        .into_response()
}
