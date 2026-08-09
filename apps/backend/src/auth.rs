use std::{env, sync::Arc};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use snm_security::{
    password::{PasswordPolicy, hash_password, verify_password},
    token::{
        AccessClaims, AccessTokenKey, IssuedOpaqueToken, decode_access_token, encode_access_token,
        hash_opaque_token, issue_opaque_token, opaque_token_matches,
    },
};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use tracing::{error, warn};
use uuid::Uuid;

use crate::{AppState, db::Database};

const ACCESS_TTL_SECONDS: i64 = 10 * 60;
const REFRESH_TTL_DAYS: i64 = 30;
const REFRESH_PREFIX: &str = "snm_rt";
const CSRF_PREFIX: &str = "csrf";
const CSRF_HEADER: &str = "x-snm-csrf";

#[derive(Clone)]
pub(crate) struct AuthService {
    database: Database,
    access_key: AccessTokenKey,
    issuer: Arc<str>,
    audience: Arc<str>,
    cookie_secure: bool,
    dummy_password_hash: Arc<str>,
}

#[derive(Debug, Error)]
pub(crate) enum AuthInitError {
    #[error("SNM_ACCESS_TOKEN_KEY must contain at least 32 bytes")]
    MissingOrWeakAccessTokenKey,
    #[error("failed to initialize password verification policy")]
    PasswordPolicy,
    #[error("failed to initialize access-token signing key")]
    SigningKey,
}

#[derive(Debug, Error)]
pub(crate) enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("invalid or expired session")]
    InvalidSession,
    #[error("refresh token reuse detected")]
    RefreshReuseDetected,
    #[error("CSRF validation failed")]
    CsrfRejected,
    #[error("authentication request is invalid")]
    InvalidRequest,
    #[error("authentication subsystem is temporarily unavailable")]
    Unavailable,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LoginRequest {
    organization_slug: String,
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessResponse {
    access_token: String,
    token_type: &'static str,
    expires_in_seconds: i64,
    csrf_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MeResponse {
    user_id: Uuid,
    organization_id: Uuid,
    session_id: Uuid,
    permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthErrorResponse {
    code: &'static str,
    message: &'static str,
}

#[derive(Debug)]
struct LoginUser {
    user_id: Uuid,
    organization_id: Uuid,
    password_hash: Option<String>,
}

#[derive(Debug, Clone)]
struct SessionIdentity {
    session_id: Uuid,
    user_id: Uuid,
    organization_id: Uuid,
    permissions: Vec<String>,
}

struct IssuedSession {
    identity: SessionIdentity,
    access_token: String,
    refresh_token: IssuedOpaqueToken,
    csrf_token: IssuedOpaqueToken,
}

impl AuthService {
    pub(crate) fn from_env(database: Database) -> Result<Self, AuthInitError> {
        let signing_secret = env::var("SNM_ACCESS_TOKEN_KEY")
            .map_err(|_| AuthInitError::MissingOrWeakAccessTokenKey)?;
        if signing_secret.len() < 32 {
            return Err(AuthInitError::MissingOrWeakAccessTokenKey);
        }
        let access_key = AccessTokenKey::new(signing_secret.into_bytes())
            .map_err(|_| AuthInitError::SigningKey)?;
        let dummy_password_hash = hash_password(
            b"snm dummy password never accepted",
            PasswordPolicy::default(),
        )
        .map_err(|_| AuthInitError::PasswordPolicy)?;

        Ok(Self {
            database,
            access_key,
            issuer: Arc::from(env::var("SNM_AUTH_ISSUER").unwrap_or_else(|_| "snm".to_owned())),
            audience: Arc::from(
                env::var("SNM_AUTH_AUDIENCE").unwrap_or_else(|_| "snm-api".to_owned()),
            ),
            cookie_secure: env::var("SNM_AUTH_COOKIE_SECURE")
                .map(|value| !matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            dummy_password_hash: Arc::from(dummy_password_hash),
        })
    }

    pub(crate) async fn bootstrap_admin(
        &self,
        organization_slug: &str,
        email: &str,
        display_name: &str,
        password: &[u8],
    ) -> Result<(), AuthError> {
        if email.len() > 320
            || display_name.trim().is_empty()
            || organization_slug.trim().is_empty()
        {
            return Err(AuthError::InvalidRequest);
        }
        let encoded = hash_password(password, PasswordPolicy::default())
            .map_err(|_| AuthError::InvalidRequest)?;
        let mut tx = self
            .database
            .pool()
            .begin()
            .await
            .map_err(|_| AuthError::Unavailable)?;

        let organization_id: Uuid =
            sqlx::query_scalar("SELECT id FROM organizations WHERE slug = $1")
                .bind(organization_slug)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| AuthError::Unavailable)?
                .ok_or(AuthError::InvalidRequest)?;

        let user_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO users (organization_id, email, display_name, status, password_hash, password_changed_at)
            VALUES ($1, lower($2), $3, 'active', $4, now())
            ON CONFLICT (organization_id, email) DO UPDATE
            SET password_hash = COALESCE(users.password_hash, EXCLUDED.password_hash)
            RETURNING id
            "#,
        )
        .bind(organization_id)
        .bind(email)
        .bind(display_name)
        .bind(encoded)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        let role_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO roles (organization_id, name, is_system)
            VALUES ($1, 'organization-admin', true)
            ON CONFLICT (organization_id, name) DO UPDATE SET is_system = true
            RETURNING id
            "#,
        )
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        sqlx::query(
            r#"
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT $1, id FROM permissions
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(role_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        sqlx::query(
            r#"
            INSERT INTO role_bindings (organization_id, role_id, user_id)
            SELECT $1, $2, $3
            WHERE NOT EXISTS (
              SELECT 1 FROM role_bindings
              WHERE organization_id = $1 AND role_id = $2 AND user_id = $3 AND site_id IS NULL
            )
            "#,
        )
        .bind(organization_id)
        .bind(role_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        sqlx::query(
            r#"
            INSERT INTO audit_events (
              organization_id, actor_type, action, resource_type, resource_id,
              correlation_id, result, status, reason_code
            ) VALUES ($1, 'system', 'auth.bootstrap_admin.ensure', 'user', $2, $3,
                      '{"outcome":"ensured"}'::jsonb, 'succeeded', 'bootstrap')
            "#,
        )
        .bind(organization_id)
        .bind(user_id.to_string())
        .bind(Uuid::now_v7())
        .execute(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        tx.commit().await.map_err(|_| AuthError::Unavailable)
    }

    async fn login(&self, request: LoginRequest) -> Result<IssuedSession, AuthError> {
        if request.organization_slug.len() > 128
            || request.email.len() > 320
            || request.password.len() > 1024
            || request.organization_slug.trim().is_empty()
            || request.email.trim().is_empty()
        {
            return Err(AuthError::InvalidCredentials);
        }

        let user = self
            .load_login_user(&request.organization_slug, &request.email)
            .await?;
        let encoded = user
            .as_ref()
            .and_then(|value| value.password_hash.as_deref())
            .unwrap_or(self.dummy_password_hash.as_ref());
        let verified = verify_password(request.password.as_bytes(), encoded).unwrap_or(false);
        let Some(user) = user else {
            return Err(AuthError::InvalidCredentials);
        };
        if !verified || user.password_hash.is_none() {
            return Err(AuthError::InvalidCredentials);
        }

        let refresh = issue_opaque_token(REFRESH_PREFIX).map_err(|_| AuthError::Unavailable)?;
        let csrf = issue_opaque_token(CSRF_PREFIX).map_err(|_| AuthError::Unavailable)?;
        let now = Utc::now();
        let session_id = Uuid::now_v7();
        let family_id = Uuid::now_v7();
        let expires_at = now + Duration::days(REFRESH_TTL_DAYS);
        let mut tx = self
            .database
            .pool()
            .begin()
            .await
            .map_err(|_| AuthError::Unavailable)?;

        sqlx::query(
            r#"
            INSERT INTO sessions (
              id, organization_id, user_id, refresh_token_hash, refresh_token_prefix,
              expires_at, last_used_at, auth_time, assurance_level
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, 'password')
            "#,
        )
        .bind(session_id)
        .bind(user.organization_id)
        .bind(user.user_id)
        .bind(refresh.hash.as_slice())
        .bind(&refresh.prefix)
        .bind(expires_at)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        sqlx::query(
            r#"
            INSERT INTO session_refresh_tokens (
              session_id, family_id, generation, token_prefix, token_hash, expires_at
            ) VALUES ($1, $2, 0, $3, $4, $5)
            "#,
        )
        .bind(session_id)
        .bind(family_id)
        .bind(&refresh.prefix)
        .bind(refresh.hash.as_slice())
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        sqlx::query("UPDATE users SET last_login_at = $2 WHERE id = $1")
            .bind(user.user_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|_| AuthError::Unavailable)?;

        tx.commit().await.map_err(|_| AuthError::Unavailable)?;
        let permissions = self
            .permissions_for_user(user.organization_id, user.user_id)
            .await?;
        let identity = SessionIdentity {
            session_id,
            user_id: user.user_id,
            organization_id: user.organization_id,
            permissions,
        };
        let access_token = self.issue_access_token(&identity, now)?;
        Ok(IssuedSession {
            identity,
            access_token,
            refresh_token: refresh,
            csrf_token: csrf,
        })
    }

    async fn refresh(&self, presented: &[u8]) -> Result<IssuedSession, AuthError> {
        let presented_hash = hash_opaque_token(presented);
        let next_refresh =
            issue_opaque_token(REFRESH_PREFIX).map_err(|_| AuthError::Unavailable)?;
        let csrf = issue_opaque_token(CSRF_PREFIX).map_err(|_| AuthError::Unavailable)?;
        let now = Utc::now();
        let mut tx = self
            .database
            .pool()
            .begin()
            .await
            .map_err(|_| AuthError::Unavailable)?;

        type RefreshRow = (
            Uuid,
            Uuid,
            Uuid,
            i64,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Uuid,
            Uuid,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
        );
        let row = sqlx::query_as::<_, RefreshRow>(
            r#"
            SELECT rt.id, rt.session_id, rt.family_id, rt.generation, rt.expires_at,
                   rt.consumed_at, rt.revoked_at, s.user_id, s.organization_id,
                   s.expires_at, s.revoked_at
            FROM session_refresh_tokens rt
            JOIN sessions s ON s.id = rt.session_id
            WHERE rt.token_hash = $1
            FOR UPDATE OF rt, s
            "#,
        )
        .bind(presented_hash.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        let Some((
            refresh_id,
            session_id,
            family_id,
            generation,
            refresh_expires_at,
            consumed_at,
            refresh_revoked_at,
            user_id,
            organization_id,
            session_expires_at,
            session_revoked_at,
        )) = row
        else {
            return Err(AuthError::InvalidSession);
        };

        if consumed_at.is_some() || refresh_revoked_at.is_some() || session_revoked_at.is_some() {
            revoke_family(&mut tx, family_id, session_id, now).await?;
            tx.commit().await.map_err(|_| AuthError::Unavailable)?;
            warn!(%session_id, %family_id, "refresh token reuse detected; family revoked");
            return Err(AuthError::RefreshReuseDetected);
        }
        if refresh_expires_at <= now || session_expires_at <= now {
            revoke_family(&mut tx, family_id, session_id, now).await?;
            tx.commit().await.map_err(|_| AuthError::Unavailable)?;
            return Err(AuthError::InvalidSession);
        }

        let next_id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO session_refresh_tokens (
              id, session_id, family_id, generation, token_prefix, token_hash, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(next_id)
        .bind(session_id)
        .bind(family_id)
        .bind(generation + 1)
        .bind(&next_refresh.prefix)
        .bind(next_refresh.hash.as_slice())
        .bind(session_expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        sqlx::query(
            "UPDATE session_refresh_tokens SET consumed_at = $2, replaced_by_id = $3 WHERE id = $1",
        )
        .bind(refresh_id)
        .bind(now)
        .bind(next_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        sqlx::query(
            r#"
            UPDATE sessions
            SET refresh_token_hash = $2, refresh_token_prefix = $3, last_used_at = $4
            WHERE id = $1
            "#,
        )
        .bind(session_id)
        .bind(next_refresh.hash.as_slice())
        .bind(&next_refresh.prefix)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;

        tx.commit().await.map_err(|_| AuthError::Unavailable)?;
        let permissions = self.permissions_for_user(organization_id, user_id).await?;
        let identity = SessionIdentity {
            session_id,
            user_id,
            organization_id,
            permissions,
        };
        let access_token = self.issue_access_token(&identity, now)?;
        Ok(IssuedSession {
            identity,
            access_token,
            refresh_token: next_refresh,
            csrf_token: csrf,
        })
    }

    async fn logout(&self, presented: &[u8]) -> Result<(), AuthError> {
        let token_hash = hash_opaque_token(presented);
        let now = Utc::now();
        let mut tx = self
            .database
            .pool()
            .begin()
            .await
            .map_err(|_| AuthError::Unavailable)?;
        let row = sqlx::query_as::<_, (Uuid, Uuid)>(
            "SELECT family_id, session_id FROM session_refresh_tokens WHERE token_hash = $1 FOR UPDATE",
        )
        .bind(token_hash.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;
        if let Some((family_id, session_id)) = row {
            revoke_family(&mut tx, family_id, session_id, now).await?;
        }
        tx.commit().await.map_err(|_| AuthError::Unavailable)
    }

    async fn authenticate_access(&self, token: &str) -> Result<SessionIdentity, AuthError> {
        let now = Utc::now();
        let claims = decode_access_token(
            token,
            &self.access_key,
            now.timestamp(),
            &self.issuer,
            &self.audience,
        )
        .map_err(|_| AuthError::InvalidSession)?;

        let row = sqlx::query_as::<
            _,
            (
                Uuid,
                Uuid,
                DateTime<Utc>,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
            ),
        >(
            r#"
            SELECT user_id, organization_id, expires_at, revoked_at, access_revoked_before
            FROM sessions WHERE id = $1
            "#,
        )
        .bind(claims.sid)
        .fetch_optional(self.database.pool())
        .await
        .map_err(|_| AuthError::Unavailable)?
        .ok_or(AuthError::InvalidSession)?;

        let (user_id, organization_id, expires_at, revoked_at, access_revoked_before) = row;
        if user_id != claims.sub
            || organization_id != claims.org
            || revoked_at.is_some()
            || expires_at <= now
            || access_revoked_before.is_some_and(|cutoff| claims.iat <= cutoff.timestamp())
        {
            return Err(AuthError::InvalidSession);
        }

        let permissions = self.permissions_for_user(organization_id, user_id).await?;
        Ok(SessionIdentity {
            session_id: claims.sid,
            user_id,
            organization_id,
            permissions,
        })
    }

    async fn load_login_user(
        &self,
        organization_slug: &str,
        email: &str,
    ) -> Result<Option<LoginUser>, AuthError> {
        let row = sqlx::query_as::<_, (Uuid, Uuid, Option<String>)>(
            r#"
            SELECT u.id, u.organization_id, u.password_hash
            FROM users u
            JOIN organizations o ON o.id = u.organization_id
            WHERE o.slug = $1 AND lower(u.email) = lower($2) AND u.status = 'active'
            "#,
        )
        .bind(organization_slug)
        .bind(email)
        .fetch_optional(self.database.pool())
        .await
        .map_err(|_| AuthError::Unavailable)?;
        Ok(
            row.map(|(user_id, organization_id, password_hash)| LoginUser {
                user_id,
                organization_id,
                password_hash,
            }),
        )
    }

    async fn permissions_for_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<String>, AuthError> {
        sqlx::query_scalar::<_, String>(
            r#"
            SELECT DISTINCT p.code
            FROM role_bindings rb
            JOIN role_permissions rp ON rp.role_id = rb.role_id
            JOIN permissions p ON p.id = rp.permission_id
            WHERE rb.organization_id = $1 AND rb.user_id = $2
            ORDER BY p.code
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_all(self.database.pool())
        .await
        .map_err(|_| AuthError::Unavailable)
    }

    fn issue_access_token(
        &self,
        identity: &SessionIdentity,
        now: DateTime<Utc>,
    ) -> Result<String, AuthError> {
        let claims = AccessClaims {
            iss: self.issuer.to_string(),
            aud: self.audience.to_string(),
            sub: identity.user_id,
            org: identity.organization_id,
            sid: identity.session_id,
            jti: Uuid::now_v7(),
            scopes: identity.permissions.clone(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: (now + Duration::seconds(ACCESS_TTL_SECONDS)).timestamp(),
        };
        encode_access_token(&claims, &self.access_key).map_err(|_| AuthError::Unavailable)
    }

    fn refresh_cookie_name(&self) -> &'static str {
        if self.cookie_secure {
            "__Host-snm_refresh"
        } else {
            "snm_refresh"
        }
    }

    fn csrf_cookie_name(&self) -> &'static str {
        if self.cookie_secure {
            "__Host-snm_csrf"
        } else {
            "snm_csrf"
        }
    }

    fn session_cookie_headers(&self, issued: &IssuedSession) -> Result<HeaderMap, AuthError> {
        let mut headers = HeaderMap::new();
        let secure = if self.cookie_secure { "; Secure" } else { "" };
        let refresh = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}{}",
            self.refresh_cookie_name(),
            issued.refresh_token.expose_once(),
            REFRESH_TTL_DAYS * 24 * 60 * 60,
            secure,
        );
        let csrf = format!(
            "{}={}; Path=/; SameSite=Strict; Max-Age={}{}",
            self.csrf_cookie_name(),
            issued.csrf_token.expose_once(),
            REFRESH_TTL_DAYS * 24 * 60 * 60,
            secure,
        );
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_str(&refresh).map_err(|_| AuthError::Unavailable)?,
        );
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_str(&csrf).map_err(|_| AuthError::Unavailable)?,
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        Ok(headers)
    }

    fn clear_cookie_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let secure = if self.cookie_secure { "; Secure" } else { "" };
        for name in [self.refresh_cookie_name(), self.csrf_cookie_name()] {
            let http_only = if name.contains("refresh") {
                "; HttpOnly"
            } else {
                ""
            };
            let value = format!("{name}=; Path=/; SameSite=Strict; Max-Age=0{http_only}{secure}");
            if let Ok(value) = HeaderValue::from_str(&value) {
                headers.append(header::SET_COOKIE, value);
            }
        }
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers
    }
}

async fn revoke_family(
    tx: &mut Transaction<'_, Postgres>,
    family_id: Uuid,
    session_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    sqlx::query(
        "UPDATE session_refresh_tokens SET revoked_at = COALESCE(revoked_at, $2) WHERE family_id = $1",
    )
    .bind(family_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|_| AuthError::Unavailable)?;
    sqlx::query("UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1")
        .bind(session_id)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|_| AuthError::Unavailable)?;
    Ok(())
}

pub(crate) async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Response {
    match state.auth.login(request).await {
        Ok(issued) => issued_response(&state.auth, issued),
        Err(error) => auth_error_response(error),
    }
}

pub(crate) async fn refresh(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(refresh) = cookie_value(&headers, state.auth.refresh_cookie_name()) else {
        return auth_error_response(AuthError::InvalidSession);
    };
    if !csrf_valid(&headers, state.auth.csrf_cookie_name()) {
        return auth_error_response(AuthError::CsrfRejected);
    }

    match state.auth.refresh(refresh.as_bytes()).await {
        Ok(issued) => issued_response(&state.auth, issued),
        Err(error) => auth_error_response(error),
    }
}

pub(crate) async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(refresh) = cookie_value(&headers, state.auth.refresh_cookie_name()) else {
        return (state.auth.clear_cookie_headers(), StatusCode::NO_CONTENT).into_response();
    };
    if !csrf_valid(&headers, state.auth.csrf_cookie_name()) {
        return auth_error_response(AuthError::CsrfRejected);
    }

    match state.auth.logout(refresh.as_bytes()).await {
        Ok(()) => (state.auth.clear_cookie_headers(), StatusCode::NO_CONTENT).into_response(),
        Err(error) => auth_error_response(error),
    }
}

pub(crate) async fn me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return auth_error_response(AuthError::InvalidSession);
    };
    match state.auth.authenticate_access(token).await {
        Ok(identity) => Json(MeResponse {
            user_id: identity.user_id,
            organization_id: identity.organization_id,
            session_id: identity.session_id,
            permissions: identity.permissions,
        })
        .into_response(),
        Err(error) => auth_error_response(error),
    }
}

fn issued_response(auth: &AuthService, issued: IssuedSession) -> Response {
    let _ = &issued.identity;
    let headers = match auth.session_cookie_headers(&issued) {
        Ok(headers) => headers,
        Err(error) => return auth_error_response(error),
    };
    (
        headers,
        Json(AccessResponse {
            access_token: issued.access_token,
            token_type: "Bearer",
            expires_in_seconds: ACCESS_TTL_SECONDS,
            csrf_token: issued.csrf_token.expose_once().to_owned(),
        }),
    )
        .into_response()
}

fn csrf_valid(headers: &HeaderMap, cookie_name: &str) -> bool {
    let Some(cookie) = cookie_value(headers, cookie_name) else {
        return false;
    };
    let Some(header_value) = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let expected = hash_opaque_token(cookie.as_bytes());
    opaque_token_matches(header_value.as_bytes(), &expected)
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .filter_map(|part| part.split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_owned()))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
}

fn auth_error_response(error: AuthError) -> Response {
    let (status, code, message) = match error {
        AuthError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "invalid credentials",
        ),
        AuthError::InvalidSession => (
            StatusCode::UNAUTHORIZED,
            "invalid_session",
            "invalid or expired session",
        ),
        AuthError::RefreshReuseDetected => (
            StatusCode::UNAUTHORIZED,
            "refresh_reuse_detected",
            "session revoked after refresh-token reuse",
        ),
        AuthError::CsrfRejected => (
            StatusCode::FORBIDDEN,
            "csrf_rejected",
            "CSRF validation failed",
        ),
        AuthError::InvalidRequest => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_auth_request",
            "authentication request is invalid",
        ),
        AuthError::Unavailable => {
            error!("authentication subsystem failure");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "auth_unavailable",
                "authentication subsystem is temporarily unavailable",
            )
        }
    };
    (status, Json(AuthErrorResponse { code, message })).into_response()
}
