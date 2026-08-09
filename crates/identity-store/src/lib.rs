use std::{collections::BTreeSet, net::IpAddr};

use serde::{Deserialize, Serialize};
use snm_security::token::{IssuedOpaqueToken, issue_opaque_token, opaque_token_matches};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

const SERVICE_TOKEN_PREFIX: &str = "snm_sa";
const VISIBLE_PREFIX_LENGTH: usize = SERVICE_TOKEN_PREFIX.len() + 9;

#[derive(Clone)]
pub struct ServiceAccountStore {
    pool: PgPool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccountSummary {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct NewServiceAccountCredential {
    pub scopes: Vec<String>,
    pub allowed_cidrs: Vec<String>,
    pub expires_at_unix_seconds: Option<i64>,
}

pub struct IssuedServiceAccountCredential {
    pub credential_id: Uuid,
    pub token: IssuedOpaqueToken,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePrincipal {
    pub service_account_id: Uuid,
    pub credential_id: Uuid,
    pub organization_id: Uuid,
    pub effective_permissions: Vec<String>,
}

impl ServiceAccountStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_account(
        &self,
        organization_id: Uuid,
        name: &str,
    ) -> Result<ServiceAccountSummary, IdentityStoreError> {
        let name = name.trim();
        if name.is_empty() || name.len() > 160 {
            return Err(IdentityStoreError::InvalidInput);
        }
        let row = sqlx::query(
            r#"
            INSERT INTO service_accounts (organization_id, name, status)
            VALUES ($1, $2, 'active')
            RETURNING id, organization_id, name, status
            "#,
        )
        .bind(organization_id)
        .bind(name)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_to_account(row)?)
    }

    pub async fn disable_account(
        &self,
        organization_id: Uuid,
        service_account_id: Uuid,
    ) -> Result<bool, IdentityStoreError> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            r#"
            UPDATE service_accounts SET status = 'disabled', updated_at = now()
            WHERE id = $1 AND organization_id = $2 AND status <> 'disabled'
            "#,
        )
        .bind(service_account_id)
        .bind(organization_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 1 {
            sqlx::query(
                "UPDATE service_account_credentials SET revoked_at = COALESCE(revoked_at, now()) WHERE service_account_id = $1",
            )
            .bind(service_account_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(updated.rows_affected() == 1)
    }

    pub async fn issue_credential(
        &self,
        organization_id: Uuid,
        service_account_id: Uuid,
        input: NewServiceAccountCredential,
    ) -> Result<IssuedServiceAccountCredential, IdentityStoreError> {
        validate_scopes(&input.scopes)?;
        validate_cidrs(&input.allowed_cidrs)?;
        let token = issue_opaque_token(SERVICE_TOKEN_PREFIX)
            .map_err(|_| IdentityStoreError::TokenGeneration)?;
        let credential_id = Uuid::now_v7();

        let inserted = sqlx::query(
            r#"
            INSERT INTO service_account_credentials (
              id, service_account_id, token_prefix, token_hash, scopes,
              allowed_cidrs, expires_at
            )
            SELECT $1, sa.id, $4, $5, $6,
                   ARRAY(SELECT value::cidr FROM unnest($7::text[]) AS value),
                   CASE WHEN $8::bigint IS NULL THEN NULL ELSE to_timestamp($8) END
            FROM service_accounts sa
            WHERE sa.id = $2 AND sa.organization_id = $3 AND sa.status = 'active'
            "#,
        )
        .bind(credential_id)
        .bind(service_account_id)
        .bind(organization_id)
        .bind(&token.prefix)
        .bind(token.hash.as_slice())
        .bind(&input.scopes)
        .bind(&input.allowed_cidrs)
        .bind(input.expires_at_unix_seconds)
        .execute(&self.pool)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(IdentityStoreError::NotFoundOrDisabled);
        }
        Ok(IssuedServiceAccountCredential {
            credential_id,
            token,
        })
    }

    pub async fn revoke_credential(
        &self,
        organization_id: Uuid,
        service_account_id: Uuid,
        credential_id: Uuid,
    ) -> Result<bool, IdentityStoreError> {
        let updated = sqlx::query(
            r#"
            UPDATE service_account_credentials c
            SET revoked_at = COALESCE(c.revoked_at, now())
            FROM service_accounts sa
            WHERE c.id = $1 AND c.service_account_id = $2
              AND sa.id = c.service_account_id AND sa.organization_id = $3
              AND c.revoked_at IS NULL
            "#,
        )
        .bind(credential_id)
        .bind(service_account_id)
        .bind(organization_id)
        .execute(&self.pool)
        .await?;
        Ok(updated.rows_affected() == 1)
    }

    pub async fn authenticate(
        &self,
        token: &[u8],
        source_ip: IpAddr,
    ) -> Result<ServicePrincipal, IdentityStoreError> {
        let token_text = std::str::from_utf8(token).map_err(|_| IdentityStoreError::InvalidToken)?;
        if !token_text.starts_with("snm_sa_") || token_text.len() > 256 {
            return Err(IdentityStoreError::InvalidToken);
        }
        let visible_prefix: String = token_text.chars().take(VISIBLE_PREFIX_LENGTH).collect();
        if visible_prefix.len() != VISIBLE_PREFIX_LENGTH {
            return Err(IdentityStoreError::InvalidToken);
        }

        let rows = sqlx::query(
            r#"
            SELECT c.id AS credential_id, c.service_account_id, sa.organization_id,
                   c.token_hash, c.scopes,
                   ARRAY(SELECT cidr::text FROM unnest(c.allowed_cidrs) AS cidr) AS allowed_cidrs,
                   c.expires_at, c.revoked_at,
                   ARRAY(
                     SELECT DISTINCT p.code
                     FROM role_bindings rb
                     JOIN role_permissions rp ON rp.role_id = rb.role_id
                     JOIN permissions p ON p.id = rp.permission_id
                     WHERE rb.organization_id = sa.organization_id
                       AND rb.service_account_id = sa.id
                     ORDER BY p.code
                   ) AS rbac_permissions
            FROM service_account_credentials c
            JOIN service_accounts sa ON sa.id = c.service_account_id
            WHERE c.token_prefix = $1 AND sa.status = 'active'
              AND c.revoked_at IS NULL
              AND (c.expires_at IS NULL OR c.expires_at > now())
              AND (
                cardinality(c.allowed_cidrs) = 0
                OR $2::inet <<= ANY(c.allowed_cidrs)
              )
            "#,
        )
        .bind(&visible_prefix)
        .bind(source_ip.to_string())
        .fetch_all(&self.pool)
        .await?;

        for row in rows {
            let token_hash: Vec<u8> = row.try_get("token_hash")?;
            let expected_hash: [u8; 32] = token_hash
                .try_into()
                .map_err(|_| IdentityStoreError::InvalidStoredCredential)?;
            if !opaque_token_matches(token, &expected_hash) {
                continue;
            }

            let token_scopes: Vec<String> = row.try_get("scopes")?;
            let rbac_permissions: Vec<String> = row.try_get("rbac_permissions")?;
            let effective_permissions = intersect_permissions(&token_scopes, &rbac_permissions);
            let credential_id: Uuid = row.try_get("credential_id")?;
            sqlx::query(
                "UPDATE service_account_credentials SET last_used_at = now() WHERE id = $1",
            )
            .bind(credential_id)
            .execute(&self.pool)
            .await?;

            return Ok(ServicePrincipal {
                service_account_id: row.try_get("service_account_id")?,
                credential_id,
                organization_id: row.try_get("organization_id")?,
                effective_permissions,
            });
        }
        Err(IdentityStoreError::InvalidToken)
    }

    pub async fn bind_role(
        &self,
        organization_id: Uuid,
        service_account_id: Uuid,
        role_id: Uuid,
        site_id: Option<Uuid>,
    ) -> Result<(), IdentityStoreError> {
        sqlx::query(
            r#"
            INSERT INTO role_bindings (
              organization_id, role_id, service_account_id, site_id
            ) VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(organization_id)
        .bind(role_id)
        .bind(service_account_id)
        .bind(site_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn validate_scopes(scopes: &[String]) -> Result<(), IdentityStoreError> {
    if scopes.is_empty() || scopes.len() > 128 {
        return Err(IdentityStoreError::InvalidInput);
    }
    for scope in scopes {
        if scope.is_empty()
            || scope.len() > 128
            || !scope.contains('.')
            || !scope.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(IdentityStoreError::InvalidInput);
        }
    }
    Ok(())
}

fn validate_cidrs(cidrs: &[String]) -> Result<(), IdentityStoreError> {
    if cidrs.len() > 128 {
        return Err(IdentityStoreError::InvalidInput);
    }
    for cidr in cidrs {
        let Some((address, prefix)) = cidr.split_once('/') else {
            return Err(IdentityStoreError::InvalidInput);
        };
        let address: IpAddr = address.parse().map_err(|_| IdentityStoreError::InvalidInput)?;
        let prefix: u8 = prefix.parse().map_err(|_| IdentityStoreError::InvalidInput)?;
        let valid = match address {
            IpAddr::V4(_) => prefix <= 32,
            IpAddr::V6(_) => prefix <= 128,
        };
        if !valid {
            return Err(IdentityStoreError::InvalidInput);
        }
    }
    Ok(())
}

fn intersect_permissions(token_scopes: &[String], rbac_permissions: &[String]) -> Vec<String> {
    let rbac: BTreeSet<&str> = rbac_permissions.iter().map(String::as_str).collect();
    let mut effective: BTreeSet<String> = BTreeSet::new();
    for scope in token_scopes {
        if rbac.contains(scope.as_str()) {
            effective.insert(scope.clone());
        }
    }
    effective.into_iter().collect()
}

fn row_to_account(row: sqlx::postgres::PgRow) -> Result<ServiceAccountSummary, IdentityStoreError> {
    Ok(ServiceAccountSummary {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        name: row.try_get("name")?,
        status: row.try_get("status")?,
    })
}

#[derive(Debug, Error)]
pub enum IdentityStoreError {
    #[error("identity request is invalid")]
    InvalidInput,
    #[error("service account is not found or disabled")]
    NotFoundOrDisabled,
    #[error("service account token is invalid")]
    InvalidToken,
    #[error("stored service account credential is invalid")]
    InvalidStoredCredential,
    #[error("service account token generation failed")]
    TokenGeneration,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(6)
            .connect(&url)
            .await
            .ok()?;
        sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    async fn organization(pool: &PgPool) -> Uuid {
        let suffix = Uuid::now_v7().simple().to_string();
        sqlx::query_scalar(
            "INSERT INTO organizations (slug, name) VALUES ($1, 'Identity Test') RETURNING id",
        )
        .bind(format!("identity-{suffix}"))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn role_with_permission(pool: &PgPool, organization_id: Uuid, permission: &str) -> Uuid {
        let role_id: Uuid = sqlx::query_scalar(
            "INSERT INTO roles (organization_id, name) VALUES ($1, $2) RETURNING id",
        )
        .bind(organization_id)
        .bind(format!("role-{permission}-{}", Uuid::now_v7().simple()))
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"
            INSERT INTO role_permissions (role_id, permission_id)
            SELECT $1, id FROM permissions WHERE code = $2
            "#,
        )
        .bind(role_id)
        .bind(permission)
        .execute(pool)
        .await
        .unwrap();
        role_id
    }

    #[tokio::test]
    async fn token_scope_can_only_reduce_rbac() {
        let Some(pool) = pool().await else { return };
        let organization_id = organization(&pool).await;
        let store = ServiceAccountStore::new(pool.clone());
        let account = store.create_account(organization_id, "collector").await.unwrap();
        let role = role_with_permission(&pool, organization_id, "devices.view").await;
        store
            .bind_role(organization_id, account.id, role, None)
            .await
            .unwrap();
        let credential = store
            .issue_credential(
                organization_id,
                account.id,
                NewServiceAccountCredential {
                    scopes: vec!["devices.view".into(), "credentials.manage".into()],
                    allowed_cidrs: vec!["10.0.0.0/8".into()],
                    expires_at_unix_seconds: None,
                },
            )
            .await
            .unwrap();
        let principal = store
            .authenticate(credential.token.expose_once().as_bytes(), "10.10.10.10".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(principal.effective_permissions, vec!["devices.view"]);
        assert!(matches!(
            store
                .authenticate(credential.token.expose_once().as_bytes(), "192.168.1.10".parse().unwrap())
                .await,
            Err(IdentityStoreError::InvalidToken)
        ));
    }

    #[tokio::test]
    async fn overlapping_rotation_keeps_old_token_until_explicit_revoke() {
        let Some(pool) = pool().await else { return };
        let organization_id = organization(&pool).await;
        let store = ServiceAccountStore::new(pool.clone());
        let account = store.create_account(organization_id, "automation").await.unwrap();
        let role = role_with_permission(&pool, organization_id, "devices.view").await;
        store
            .bind_role(organization_id, account.id, role, None)
            .await
            .unwrap();
        let input = || NewServiceAccountCredential {
            scopes: vec!["devices.view".into()],
            allowed_cidrs: vec![],
            expires_at_unix_seconds: None,
        };
        let old = store
            .issue_credential(organization_id, account.id, input())
            .await
            .unwrap();
        let new = store
            .issue_credential(organization_id, account.id, input())
            .await
            .unwrap();

        assert!(store
            .authenticate(old.token.expose_once().as_bytes(), "127.0.0.1".parse().unwrap())
            .await
            .is_ok());
        assert!(store
            .authenticate(new.token.expose_once().as_bytes(), "127.0.0.1".parse().unwrap())
            .await
            .is_ok());

        assert!(store
            .revoke_credential(organization_id, account.id, old.credential_id)
            .await
            .unwrap());
        assert!(matches!(
            store
                .authenticate(old.token.expose_once().as_bytes(), "127.0.0.1".parse().unwrap())
                .await,
            Err(IdentityStoreError::InvalidToken)
        ));
        assert!(store
            .authenticate(new.token.expose_once().as_bytes(), "127.0.0.1".parse().unwrap())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn plaintext_token_is_not_persisted() {
        let Some(pool) = pool().await else { return };
        let organization_id = organization(&pool).await;
        let store = ServiceAccountStore::new(pool.clone());
        let account = store.create_account(organization_id, "no-plaintext").await.unwrap();
        let credential = store
            .issue_credential(
                organization_id,
                account.id,
                NewServiceAccountCredential {
                    scopes: vec!["devices.view".into()],
                    allowed_cidrs: vec![],
                    expires_at_unix_seconds: None,
                },
            )
            .await
            .unwrap();
        let persisted: Vec<u8> = sqlx::query_scalar(
            "SELECT token_hash FROM service_account_credentials WHERE id = $1",
        )
        .bind(credential.credential_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_ne!(persisted, credential.token.expose_once().as_bytes());
    }
}
