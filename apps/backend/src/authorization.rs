use std::{env, sync::Arc};

use axum::{http::HeaderMap, http::header};
use chrono::{DateTime, Utc};
use snm_security::token::{AccessTokenKey, decode_access_token};
use thiserror::Error;
use uuid::Uuid;

use crate::db::Database;

#[derive(Clone)]
pub(crate) struct AuthorizationService {
    database: Database,
    access_key: AccessTokenKey,
    issuer: Arc<str>,
    audience: Arc<str>,
}

#[derive(Debug, Clone)]
pub(crate) struct Principal {
    pub(crate) session_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) organization_id: Uuid,
}

#[derive(Debug, Error)]
pub(crate) enum AuthorizationInitError {
    #[error("SNM_ACCESS_TOKEN_KEY must contain at least 32 bytes")]
    MissingOrWeakAccessTokenKey,
    #[error("failed to initialize access-token verification key")]
    SigningKey,
}

#[derive(Debug, Error)]
pub(crate) enum AuthorizationError {
    #[error("invalid or expired session")]
    InvalidSession,
    #[error("permission denied")]
    PermissionDenied,
    #[error("authorization subsystem is temporarily unavailable")]
    Unavailable,
}

impl AuthorizationService {
    pub(crate) fn from_env(database: Database) -> Result<Self, AuthorizationInitError> {
        let signing_secret = env::var("SNM_ACCESS_TOKEN_KEY")
            .map_err(|_| AuthorizationInitError::MissingOrWeakAccessTokenKey)?;
        let issuer = env::var("SNM_AUTH_ISSUER").unwrap_or_else(|_| "snm".to_owned());
        let audience = env::var("SNM_AUTH_AUDIENCE").unwrap_or_else(|_| "snm-api".to_owned());
        Self::new(database, signing_secret.as_bytes(), issuer, audience)
    }

    fn new(
        database: Database,
        signing_secret: &[u8],
        issuer: impl Into<Arc<str>>,
        audience: impl Into<Arc<str>>,
    ) -> Result<Self, AuthorizationInitError> {
        if signing_secret.len() < 32 {
            return Err(AuthorizationInitError::MissingOrWeakAccessTokenKey);
        }
        let access_key = AccessTokenKey::new(signing_secret.to_vec())
            .map_err(|_| AuthorizationInitError::SigningKey)?;
        Ok(Self {
            database,
            access_key,
            issuer: issuer.into(),
            audience: audience.into(),
        })
    }

    pub(crate) async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<Principal, AuthorizationError> {
        let token = bearer_token(headers).ok_or(AuthorizationError::InvalidSession)?;
        let now = Utc::now();
        let claims = decode_access_token(
            token,
            &self.access_key,
            now.timestamp(),
            &self.issuer,
            &self.audience,
        )
        .map_err(|_| AuthorizationError::InvalidSession)?;

        let row = sqlx::query_as::<
            _,
            (
                Uuid,
                Uuid,
                DateTime<Utc>,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
                String,
            ),
        >(
            r#"
            SELECT s.user_id, s.organization_id, s.expires_at, s.revoked_at,
                   s.access_revoked_before, u.status
            FROM sessions s
            JOIN users u ON u.id = s.user_id AND u.organization_id = s.organization_id
            WHERE s.id = $1
            "#,
        )
        .bind(claims.sid)
        .fetch_optional(self.database.pool())
        .await
        .map_err(|_| AuthorizationError::Unavailable)?
        .ok_or(AuthorizationError::InvalidSession)?;

        let (user_id, organization_id, expires_at, revoked_at, revoked_before, user_status) = row;
        if user_id != claims.sub
            || organization_id != claims.org
            || user_status != "active"
            || revoked_at.is_some()
            || expires_at <= now
            || revoked_before.is_some_and(|cutoff| claims.iat <= cutoff.timestamp())
        {
            return Err(AuthorizationError::InvalidSession);
        }

        Ok(Principal {
            session_id: claims.sid,
            user_id,
            organization_id,
        })
    }

    pub(crate) async fn require_site_permission(
        &self,
        principal: &Principal,
        site_id: Uuid,
        permission: &str,
    ) -> Result<(), AuthorizationError> {
        if permission.trim().is_empty() || permission.len() > 120 {
            return Err(AuthorizationError::PermissionDenied);
        }
        let allowed = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
              SELECT 1
              FROM sites s
              JOIN role_bindings rb
                ON rb.organization_id = s.organization_id
               AND rb.user_id = $2
               AND (rb.site_id IS NULL OR rb.site_id = s.id)
              JOIN roles r ON r.id = rb.role_id
              JOIN role_permissions rp ON rp.role_id = rb.role_id
              JOIN permissions p ON p.id = rp.permission_id
              WHERE s.id = $4
                AND s.organization_id = $1
                AND p.code = $3
                AND (r.organization_id IS NULL OR r.organization_id = $1)
            )
            "#,
        )
        .bind(principal.organization_id)
        .bind(principal.user_id)
        .bind(permission)
        .bind(site_id)
        .fetch_one(self.database.pool())
        .await
        .map_err(|_| AuthorizationError::Unavailable)?;
        if allowed {
            Ok(())
        } else {
            Err(AuthorizationError::PermissionDenied)
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use snm_security::{
        password::{PasswordPolicy, hash_password},
        token::{AccessClaims, encode_access_token},
    };

    use super::*;

    const TEST_KEY: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef";

    async fn database() -> Option<Database> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let database = Database::connect(&url, 8).await.ok()?;
        database.migrate().await.ok()?;
        Some(database)
    }

    fn service(database: Database) -> AuthorizationService {
        AuthorizationService::new(database, TEST_KEY, "snm", "snm-api").unwrap()
    }

    async fn fixture(database: &Database) -> (Uuid, Uuid, Uuid, Uuid, Uuid) {
        let suffix = Uuid::now_v7().simple().to_string();
        let organization_id: Uuid = sqlx::query_scalar(
            "INSERT INTO organizations (slug, name) VALUES ($1, 'Authz Test') RETURNING id",
        )
        .bind(format!("authz-{suffix}"))
        .fetch_one(database.pool())
        .await
        .unwrap();
        let site_a: Uuid = sqlx::query_scalar(
            "INSERT INTO sites (organization_id, slug, name) VALUES ($1, 'a', 'A') RETURNING id",
        )
        .bind(organization_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
        let site_b: Uuid = sqlx::query_scalar(
            "INSERT INTO sites (organization_id, slug, name) VALUES ($1, 'b', 'B') RETURNING id",
        )
        .bind(organization_id)
        .fetch_one(database.pool())
        .await
        .unwrap();
        let password_hash = hash_password(b"test-only-password", PasswordPolicy::default()).unwrap();
        let user_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO users (organization_id, email, display_name, status, password_hash)
            VALUES ($1, $2, 'Scoped User', 'active', $3) RETURNING id
            "#,
        )
        .bind(organization_id)
        .bind(format!("{suffix}@example.invalid"))
        .bind(password_hash)
        .fetch_one(database.pool())
        .await
        .unwrap();
        let session_id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO sessions (id, organization_id, user_id, refresh_token_hash, expires_at)
            VALUES ($1,$2,$3,$4,now() + interval '1 hour')
            "#,
        )
        .bind(session_id)
        .bind(organization_id)
        .bind(user_id)
        .bind(vec![0_u8; 32])
        .execute(database.pool())
        .await
        .unwrap();
        (organization_id, site_a, site_b, user_id, session_id)
    }

    #[tokio::test]
    async fn site_binding_does_not_authorize_another_site() {
        let Some(database) = database().await else { return };
        let (organization_id, site_a, site_b, user_id, session_id) = fixture(&database).await;
        let permission_id: Uuid = sqlx::query_scalar(
            "INSERT INTO permissions (code, description) VALUES ($1, 'fixture') ON CONFLICT (code) DO UPDATE SET description = excluded.description RETURNING id",
        )
        .bind(format!("fixture.{}", Uuid::now_v7().simple()))
        .fetch_one(database.pool())
        .await
        .unwrap();
        let permission: String = sqlx::query_scalar("SELECT code FROM permissions WHERE id = $1")
            .bind(permission_id)
            .fetch_one(database.pool())
            .await
            .unwrap();
        let role_id: Uuid = sqlx::query_scalar(
            "INSERT INTO roles (organization_id, name) VALUES ($1, $2) RETURNING id",
        )
        .bind(organization_id)
        .bind(format!("site-a-{}", Uuid::now_v7().simple()))
        .fetch_one(database.pool())
        .await
        .unwrap();
        sqlx::query("INSERT INTO role_permissions (role_id, permission_id) VALUES ($1,$2)")
            .bind(role_id)
            .bind(permission_id)
            .execute(database.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO role_bindings (organization_id, role_id, user_id, site_id) VALUES ($1,$2,$3,$4)",
        )
        .bind(organization_id)
        .bind(role_id)
        .bind(user_id)
        .bind(site_a)
        .execute(database.pool())
        .await
        .unwrap();

        let principal = Principal {
            session_id,
            user_id,
            organization_id,
        };
        let service = service(database);
        assert!(service.require_site_permission(&principal, site_a, &permission).await.is_ok());
        assert!(matches!(
            service.require_site_permission(&principal, site_b, &permission).await,
            Err(AuthorizationError::PermissionDenied)
        ));
    }

    #[tokio::test]
    async fn revoked_session_is_rejected_even_with_valid_signature() {
        let Some(database) = database().await else { return };
        let (organization_id, _site_a, _site_b, user_id, session_id) = fixture(&database).await;
        let key = AccessTokenKey::new(TEST_KEY.to_vec()).unwrap();
        let now = Utc::now();
        let claims = AccessClaims {
            iss: "snm".into(),
            aud: "snm-api".into(),
            sub: user_id,
            org: organization_id,
            sid: session_id,
            jti: Uuid::now_v7(),
            scopes: vec!["devices.view".into()],
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: (now + chrono::Duration::minutes(10)).timestamp(),
        };
        let token = encode_access_token(&claims, &key).unwrap();
        sqlx::query("UPDATE sessions SET revoked_at = now() WHERE id = $1")
            .bind(session_id)
            .execute(database.pool())
            .await
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let service = service(database);
        assert!(matches!(
            service.authenticate(&headers).await,
            Err(AuthorizationError::InvalidSession)
        ));
    }
}
