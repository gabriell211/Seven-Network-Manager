use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use snm_security::vault::{EncryptedSecret, KeyRing, VaultError};
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct CredentialVaultStore {
    pool: PgPool,
    keys: Arc<KeyRing>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProfileSummary {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub kind: String,
    pub username: Option<String>,
    pub metadata: Value,
    pub active: bool,
    pub key_version: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct NewCredentialProfile<'a> {
    pub organization_id: Uuid,
    pub name: &'a str,
    pub kind: &'a str,
    pub username: Option<&'a str>,
    pub metadata: Value,
    pub secret: &'a [u8],
}

impl CredentialVaultStore {
    pub fn new(pool: PgPool, keys: Arc<KeyRing>) -> Result<Self, CredentialStoreError> {
        keys.current()?;
        Ok(Self { pool, keys })
    }

    pub async fn create(
        &self,
        input: NewCredentialProfile<'_>,
    ) -> Result<CredentialProfileSummary, CredentialStoreError> {
        validate_profile_input(&input)?;
        let profile_id = Uuid::now_v7();
        let aad = profile_aad(input.organization_id, profile_id, input.kind);
        let encrypted = EncryptedSecret::encrypt(input.secret, &aad, self.keys.current()?)?;

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r#"
            INSERT INTO credential_profiles (
              id, organization_id, name, kind, username, metadata, active
            ) VALUES ($1, $2, $3, $4, $5, $6, true)
            "#,
        )
        .bind(profile_id)
        .bind(input.organization_id)
        .bind(input.name.trim())
        .bind(input.kind.trim())
        .bind(input.username.map(str::trim))
        .bind(&input.metadata)
        .execute(&mut *tx)
        .await?;

        insert_ciphertext(&mut tx, profile_id, &encrypted).await?;
        tx.commit().await?;

        Ok(CredentialProfileSummary {
            id: profile_id,
            organization_id: input.organization_id,
            name: input.name.trim().to_owned(),
            kind: input.kind.trim().to_owned(),
            username: input.username.map(|value| value.trim().to_owned()),
            metadata: input.metadata,
            active: true,
            key_version: Some(i32::try_from(encrypted.key_version).map_err(|_| {
                CredentialStoreError::InvalidStoredCiphertext
            })?),
        })
    }

    pub async fn get_summary(
        &self,
        organization_id: Uuid,
        profile_id: Uuid,
    ) -> Result<Option<CredentialProfileSummary>, CredentialStoreError> {
        let row = sqlx::query(
            r#"
            SELECT p.id, p.organization_id, p.name, p.kind, p.username, p.metadata,
                   p.active, c.key_version
            FROM credential_profiles p
            LEFT JOIN credential_ciphertexts c ON c.credential_profile_id = p.id
            WHERE p.id = $1 AND p.organization_id = $2
            "#,
        )
        .bind(profile_id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(row_to_summary).transpose()
    }

    pub async fn list_summaries(
        &self,
        organization_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CredentialProfileSummary>, CredentialStoreError> {
        let rows = sqlx::query(
            r#"
            SELECT p.id, p.organization_id, p.name, p.kind, p.username, p.metadata,
                   p.active, c.key_version
            FROM credential_profiles p
            LEFT JOIN credential_ciphertexts c ON c.credential_profile_id = p.id
            WHERE p.organization_id = $1
            ORDER BY p.created_at DESC, p.id
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(organization_id)
        .bind(limit.clamp(1, 250))
        .bind(offset.max(0))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_summary).collect()
    }

    /// Internal execution path only. API DTOs must never contain this value.
    pub async fn resolve_secret(
        &self,
        organization_id: Uuid,
        profile_id: Uuid,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialStoreError> {
        let row = sqlx::query(
            r#"
            SELECT p.kind, p.active, c.key_version, c.wrapped_dek_nonce,
                   c.wrapped_dek, c.data_nonce, c.ciphertext, c.aad_hash
            FROM credential_profiles p
            JOIN credential_ciphertexts c ON c.credential_profile_id = p.id
            WHERE p.id = $1 AND p.organization_id = $2
            "#,
        )
        .bind(profile_id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CredentialStoreError::NotFound)?;

        let active: bool = row.try_get("active")?;
        if !active {
            return Err(CredentialStoreError::Inactive);
        }
        let kind: String = row.try_get("kind")?;
        let encrypted = row_to_ciphertext(&row)?;
        let aad = profile_aad(organization_id, profile_id, &kind);
        encrypted.decrypt(&aad, &self.keys).map_err(Into::into)
    }

    pub async fn replace_secret(
        &self,
        organization_id: Uuid,
        profile_id: Uuid,
        new_secret: &[u8],
    ) -> Result<(), CredentialStoreError> {
        if new_secret.is_empty() || new_secret.len() > 64 * 1024 {
            return Err(CredentialStoreError::InvalidSecret);
        }
        let kind: String = sqlx::query_scalar(
            r#"
            SELECT kind FROM credential_profiles
            WHERE id = $1 AND organization_id = $2 AND active = true
            "#,
        )
        .bind(profile_id)
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CredentialStoreError::NotFound)?;
        let aad = profile_aad(organization_id, profile_id, &kind);
        let encrypted = EncryptedSecret::encrypt(new_secret, &aad, self.keys.current()?)?;
        update_ciphertext(&self.pool, profile_id, &encrypted).await?;
        Ok(())
    }

    pub async fn deactivate(
        &self,
        organization_id: Uuid,
        profile_id: Uuid,
    ) -> Result<bool, CredentialStoreError> {
        let updated = sqlx::query(
            r#"
            UPDATE credential_profiles SET active = false, updated_at = now()
            WHERE id = $1 AND organization_id = $2 AND active = true
            "#,
        )
        .bind(profile_id)
        .bind(organization_id)
        .execute(&self.pool)
        .await?;
        Ok(updated.rows_affected() == 1)
    }

    pub async fn rotate_profile_key(
        &self,
        organization_id: Uuid,
        profile_id: Uuid,
    ) -> Result<bool, CredentialStoreError> {
        let current_version = self.keys.current()?.version;
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT p.kind, c.key_version, c.wrapped_dek_nonce, c.wrapped_dek,
                   c.data_nonce, c.ciphertext, c.aad_hash
            FROM credential_profiles p
            JOIN credential_ciphertexts c ON c.credential_profile_id = p.id
            WHERE p.id = $1 AND p.organization_id = $2
            FOR UPDATE
            "#,
        )
        .bind(profile_id)
        .bind(organization_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(CredentialStoreError::NotFound)?;

        let stored_version: i32 = row.try_get("key_version")?;
        let current_version_i32 = i32::try_from(current_version)
            .map_err(|_| CredentialStoreError::InvalidStoredCiphertext)?;
        if stored_version == current_version_i32 {
            tx.rollback().await?;
            return Ok(false);
        }

        let kind: String = row.try_get("kind")?;
        let encrypted = row_to_ciphertext(&row)?;
        let aad = profile_aad(organization_id, profile_id, &kind);
        let rotated = encrypted.rotate(&aad, &self.keys)?;
        update_ciphertext_tx(&mut tx, profile_id, &rotated).await?;
        tx.commit().await?;
        Ok(true)
    }
}

fn validate_profile_input(input: &NewCredentialProfile<'_>) -> Result<(), CredentialStoreError> {
    if input.name.trim().is_empty()
        || input.name.len() > 200
        || input.kind.trim().is_empty()
        || input.kind.len() > 100
    {
        return Err(CredentialStoreError::InvalidMetadata);
    }
    if input.secret.is_empty() || input.secret.len() > 64 * 1024 {
        return Err(CredentialStoreError::InvalidSecret);
    }
    if input
        .username
        .is_some_and(|value| value.trim().is_empty() || value.len() > 320)
    {
        return Err(CredentialStoreError::InvalidMetadata);
    }
    Ok(())
}

fn profile_aad(organization_id: Uuid, profile_id: Uuid, kind: &str) -> Vec<u8> {
    format!("snm:credential:v1:{organization_id}:{profile_id}:{kind}").into_bytes()
}

async fn insert_ciphertext(
    tx: &mut Transaction<'_, Postgres>,
    profile_id: Uuid,
    encrypted: &EncryptedSecret,
) -> Result<(), CredentialStoreError> {
    sqlx::query(
        r#"
        INSERT INTO credential_ciphertexts (
          credential_profile_id, algorithm, key_version, envelope_version,
          wrapped_dek_nonce, wrapped_dek, data_nonce, ciphertext, aad_hash
        ) VALUES ($1, 'AES-256-GCM', $2, 1, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(profile_id)
    .bind(i32::try_from(encrypted.key_version).map_err(|_| {
        CredentialStoreError::InvalidStoredCiphertext
    })?)
    .bind(encrypted.wrapped_dek_nonce.to_vec())
    .bind(&encrypted.wrapped_dek)
    .bind(encrypted.data_nonce.to_vec())
    .bind(&encrypted.ciphertext)
    .bind(encrypted.aad_hash.to_vec())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn update_ciphertext(
    pool: &PgPool,
    profile_id: Uuid,
    encrypted: &EncryptedSecret,
) -> Result<(), CredentialStoreError> {
    let mut tx = pool.begin().await?;
    update_ciphertext_tx(&mut tx, profile_id, encrypted).await?;
    tx.commit().await?;
    Ok(())
}

async fn update_ciphertext_tx(
    tx: &mut Transaction<'_, Postgres>,
    profile_id: Uuid,
    encrypted: &EncryptedSecret,
) -> Result<(), CredentialStoreError> {
    let updated = sqlx::query(
        r#"
        UPDATE credential_ciphertexts
        SET key_version = $2, envelope_version = 1,
            wrapped_dek_nonce = $3, wrapped_dek = $4,
            data_nonce = $5, ciphertext = $6, aad_hash = $7,
            rotated_at = now()
        WHERE credential_profile_id = $1
        "#,
    )
    .bind(profile_id)
    .bind(i32::try_from(encrypted.key_version).map_err(|_| {
        CredentialStoreError::InvalidStoredCiphertext
    })?)
    .bind(encrypted.wrapped_dek_nonce.to_vec())
    .bind(&encrypted.wrapped_dek)
    .bind(encrypted.data_nonce.to_vec())
    .bind(&encrypted.ciphertext)
    .bind(encrypted.aad_hash.to_vec())
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(CredentialStoreError::NotFound);
    }
    Ok(())
}

fn row_to_summary(row: sqlx::postgres::PgRow) -> Result<CredentialProfileSummary, CredentialStoreError> {
    Ok(CredentialProfileSummary {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        name: row.try_get("name")?,
        kind: row.try_get("kind")?,
        username: row.try_get("username")?,
        metadata: row.try_get("metadata")?,
        active: row.try_get("active")?,
        key_version: row.try_get("key_version")?,
    })
}

fn row_to_ciphertext(row: &sqlx::postgres::PgRow) -> Result<EncryptedSecret, CredentialStoreError> {
    let key_version: i32 = row.try_get("key_version")?;
    Ok(EncryptedSecret {
        key_version: u32::try_from(key_version)
            .map_err(|_| CredentialStoreError::InvalidStoredCiphertext)?,
        wrapped_dek_nonce: fixed::<12>(row.try_get("wrapped_dek_nonce")?)?,
        wrapped_dek: row.try_get("wrapped_dek")?,
        data_nonce: fixed::<12>(row.try_get("data_nonce")?)?,
        ciphertext: row.try_get("ciphertext")?,
        aad_hash: fixed::<32>(row.try_get("aad_hash")?)?,
    })
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], CredentialStoreError> {
    value
        .try_into()
        .map_err(|_| CredentialStoreError::InvalidStoredCiphertext)
}

#[derive(Debug, Error)]
pub enum CredentialStoreError {
    #[error("credential metadata is invalid")]
    InvalidMetadata,
    #[error("credential secret is invalid")]
    InvalidSecret,
    #[error("credential profile was not found")]
    NotFound,
    #[error("credential profile is inactive")]
    Inactive,
    #[error("stored credential ciphertext is invalid")]
    InvalidStoredCiphertext,
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use snm_security::vault::MasterKey;

    async fn pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect(&url)
            .await
            .ok()?;
        sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    async fn organization(pool: &PgPool) -> Uuid {
        let suffix = Uuid::now_v7().simple().to_string();
        sqlx::query_scalar(
            "INSERT INTO organizations (slug, name) VALUES ($1, 'Vault Test') RETURNING id",
        )
        .bind(format!("vault-{suffix}"))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    fn ring(current: u32) -> Arc<KeyRing> {
        let mut ring = KeyRing::default();
        ring.insert(MasterKey::new(1, [0x11; 32]).unwrap(), current == 1);
        ring.insert(MasterKey::new(2, [0x22; 32]).unwrap(), current == 2);
        Arc::new(ring)
    }

    #[tokio::test]
    async fn database_never_stores_plaintext_secret() {
        let Some(pool) = pool().await else { return };
        let organization_id = organization(&pool).await;
        let store = CredentialVaultStore::new(pool.clone(), ring(1)).unwrap();
        let sentinel = b"SNM-SENTINEL-SECRET-DO-NOT-LEAK";
        let summary = store
            .create(NewCredentialProfile {
                organization_id,
                name: "SNMP test",
                kind: "snmp_v3",
                username: Some("monitor"),
                metadata: serde_json::json!({"auth":"sha256","privacy":"aes"}),
                secret: sentinel,
            })
            .await
            .unwrap();

        let row = sqlx::query(
            "SELECT wrapped_dek, ciphertext FROM credential_ciphertexts WHERE credential_profile_id = $1",
        )
        .bind(summary.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let wrapped_dek: Vec<u8> = row.try_get("wrapped_dek").unwrap();
        let ciphertext: Vec<u8> = row.try_get("ciphertext").unwrap();
        assert!(!wrapped_dek.windows(sentinel.len()).any(|value| value == sentinel));
        assert!(!ciphertext.windows(sentinel.len()).any(|value| value == sentinel));
        assert_eq!(
            store
                .resolve_secret(organization_id, summary.id)
                .await
                .unwrap()
                .as_slice(),
            sentinel
        );
    }

    #[tokio::test]
    async fn rotation_changes_master_key_version_without_changing_secret() {
        let Some(pool) = pool().await else { return };
        let organization_id = organization(&pool).await;
        let sentinel = b"rotate-me-without-plaintext";
        let old_store = CredentialVaultStore::new(pool.clone(), ring(1)).unwrap();
        let summary = old_store
            .create(NewCredentialProfile {
                organization_id,
                name: "Rotation fixture",
                kind: "api_token",
                username: None,
                metadata: Value::Null,
                secret: sentinel,
            })
            .await
            .unwrap();

        let new_store = CredentialVaultStore::new(pool.clone(), ring(2)).unwrap();
        assert!(new_store
            .rotate_profile_key(organization_id, summary.id)
            .await
            .unwrap());
        assert!(!new_store
            .rotate_profile_key(organization_id, summary.id)
            .await
            .unwrap());
        let key_version: i32 = sqlx::query_scalar(
            "SELECT key_version FROM credential_ciphertexts WHERE credential_profile_id = $1",
        )
        .bind(summary.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(key_version, 2);
        assert_eq!(
            new_store
                .resolve_secret(organization_id, summary.id)
                .await
                .unwrap()
                .as_slice(),
            sentinel
        );
    }

    #[tokio::test]
    async fn organization_scope_prevents_cross_tenant_secret_resolution() {
        let Some(pool) = pool().await else { return };
        let organization_a = organization(&pool).await;
        let organization_b = organization(&pool).await;
        let store = CredentialVaultStore::new(pool, ring(1)).unwrap();
        let summary = store
            .create(NewCredentialProfile {
                organization_id: organization_a,
                name: "Scoped",
                kind: "password",
                username: Some("admin"),
                metadata: Value::Null,
                secret: b"scoped-secret",
            })
            .await
            .unwrap();
        assert!(matches!(
            store.resolve_secret(organization_b, summary.id).await,
            Err(CredentialStoreError::NotFound)
        ));
    }
}
