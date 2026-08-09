use sha2::{Digest, Sha256};
use snm_security::audit::{AuditEventDraft, AuditStatus, SealedAuditEvent};
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone)]
pub struct AuditStore {
    pool: PgPool,
}

impl AuditStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn append(&self, draft: AuditEventDraft) -> Result<Uuid, AuditStoreError> {
        let mut tx = self.pool.begin().await?;
        let id = Self::append_in_tx(&mut tx, draft).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Uses the caller transaction so a privileged mutation and its audit entry
    /// either commit together or roll back together.
    pub async fn append_in_tx(
        tx: &mut Transaction<'_, Postgres>,
        draft: AuditEventDraft,
    ) -> Result<Uuid, AuditStoreError> {
        validate_draft(&draft)?;
        lock_organization_chain(tx, draft.organization_id).await?;
        let (chain_sequence, previous_hash) = next_chain_position(tx, draft.organization_id).await?;
        let sealed = draft.seal(previous_hash)?;
        let canonical_payload = serde_json::to_vec(&sealed.event)?;
        let id = Uuid::now_v7();
        let result = sealed.event.result.clone().unwrap_or(serde_json::Value::Null);

        sqlx::query(
            r#"
            INSERT INTO audit_events (
              id, organization_id, site_id, actor_type, actor_id, session_id,
              source_ip, request_id, action, resource_type, resource_id,
              correlation_id, provider, status, duration_ms, reason_code,
              before_state, after_state, result, occurred_at_unix_ms,
              event_schema_version, chain_sequence, canonical_payload,
              previous_hash, event_hash
            ) VALUES (
              $1,$2,$3,$4,$5,$6,$7::inet,$8,$9,$10,$11,$12,$13,$14,$15,$16,
              $17,$18,$19,$20,1,$21,$22,$23,$24
            )
            "#,
        )
        .bind(id)
        .bind(sealed.event.organization_id)
        .bind(sealed.event.site_id)
        .bind(sealed.event.actor_type.as_str())
        .bind(sealed.event.actor_id)
        .bind(sealed.event.session_id)
        .bind(sealed.event.source_ip.as_deref())
        .bind(&sealed.event.request_id)
        .bind(&sealed.event.action)
        .bind(&sealed.event.resource_type)
        .bind(sealed.event.resource_id.as_deref())
        .bind(sealed.event.correlation_id)
        .bind(sealed.event.provider.as_deref())
        .bind(status_str(sealed.event.status))
        .bind(sealed.event.duration_ms.map(|value| i64::try_from(value).unwrap_or(i64::MAX)))
        .bind(sealed.event.reason_code.as_deref())
        .bind(sealed.event.before.as_ref())
        .bind(sealed.event.after.as_ref())
        .bind(&result)
        .bind(sealed.event.occurred_at_unix_ms)
        .bind(chain_sequence)
        .bind(canonical_payload)
        .bind(sealed.previous_hash.map(|value| value.to_vec()))
        .bind(sealed.event_hash.to_vec())
        .execute(&mut **tx)
        .await?;
        Ok(id)
    }

    pub async fn verify_organization_chain(
        &self,
        organization_id: Uuid,
    ) -> Result<AuditVerification, AuditStoreError> {
        let rows = sqlx::query(
            r#"
            SELECT id, chain_sequence, canonical_payload, previous_hash, event_hash
            FROM audit_events
            WHERE organization_id = $1 AND chain_sequence IS NOT NULL
            ORDER BY chain_sequence
            "#,
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?;

        let mut expected_previous: Option<[u8; 32]> = None;
        let mut expected_sequence = 1_i64;
        let mut checked = 0_u64;
        for row in rows {
            let id: Uuid = row.try_get("id")?;
            let sequence: i64 = row.try_get("chain_sequence")?;
            if sequence != expected_sequence {
                return Ok(AuditVerification::Broken {
                    checked,
                    event_id: id,
                    reason: "chain_sequence_gap",
                });
            }
            let canonical_payload: Vec<u8> = row.try_get("canonical_payload")?;
            let stored_previous = optional_fixed::<32>(row.try_get("previous_hash")?)?;
            let event_hash = fixed::<32>(row.try_get("event_hash")?)?;
            if stored_previous != expected_previous {
                return Ok(AuditVerification::Broken {
                    checked,
                    event_id: id,
                    reason: "previous_hash_mismatch",
                });
            }
            if hash_event(&canonical_payload, stored_previous) != event_hash {
                return Ok(AuditVerification::Broken {
                    checked,
                    event_id: id,
                    reason: "event_hash_mismatch",
                });
            }
            let event: AuditEventDraft = serde_json::from_slice(&canonical_payload)?;
            let sealed = SealedAuditEvent {
                event,
                previous_hash: stored_previous,
                event_hash,
            };
            if !sealed.verify()? {
                return Ok(AuditVerification::Broken {
                    checked,
                    event_id: id,
                    reason: "canonical_payload_invalid",
                });
            }
            expected_previous = Some(event_hash);
            expected_sequence += 1;
            checked += 1;
        }
        Ok(AuditVerification::Valid { checked })
    }
}

async fn lock_organization_chain(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<(), AuditStoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(organization_id.to_string())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn next_chain_position(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
) -> Result<(i64, Option<[u8; 32]>), AuditStoreError> {
    let row = sqlx::query(
        r#"
        SELECT chain_sequence, event_hash
        FROM audit_events
        WHERE organization_id = $1 AND chain_sequence IS NOT NULL
        ORDER BY chain_sequence DESC
        LIMIT 1
        "#,
    )
    .bind(organization_id)
    .fetch_optional(&mut **tx)
    .await?;
    match row {
        Some(row) => {
            let sequence: i64 = row.try_get("chain_sequence")?;
            let hash = fixed::<32>(row.try_get("event_hash")?)?;
            Ok((sequence.checked_add(1).ok_or(AuditStoreError::InvalidStoredChain)?, Some(hash)))
        }
        None => Ok((1, None)),
    }
}

fn validate_draft(draft: &AuditEventDraft) -> Result<(), AuditStoreError> {
    if draft.request_id.trim().is_empty()
        || draft.request_id.len() > 200
        || draft.action.trim().is_empty()
        || draft.action.len() > 200
        || draft.resource_type.trim().is_empty()
        || draft.resource_type.len() > 120
        || draft.occurred_at_unix_ms < 0
    {
        return Err(AuditStoreError::InvalidDraft);
    }
    if draft
        .source_ip
        .as_ref()
        .is_some_and(|value| value.parse::<std::net::IpAddr>().is_err())
    {
        return Err(AuditStoreError::InvalidDraft);
    }
    Ok(())
}

fn status_str(status: AuditStatus) -> &'static str {
    match status {
        AuditStatus::Succeeded => "succeeded",
        AuditStatus::Failed => "failed",
        AuditStatus::Denied => "denied",
        AuditStatus::Partial => "partial",
        AuditStatus::Unknown => "unknown",
        AuditStatus::Cancelled => "cancelled",
    }
}

fn hash_event(canonical_payload: &[u8], previous_hash: Option<[u8; 32]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"snm:audit:v1\0");
    if let Some(previous) = previous_hash {
        hasher.update(previous);
    }
    hasher.update(canonical_payload);
    hasher.finalize().into()
}

fn fixed<const N: usize>(value: Vec<u8>) -> Result<[u8; N], AuditStoreError> {
    value
        .try_into()
        .map_err(|_| AuditStoreError::InvalidStoredChain)
}

fn optional_fixed<const N: usize>(
    value: Option<Vec<u8>>,
) -> Result<Option<[u8; N]>, AuditStoreError> {
    value.map(fixed).transpose()
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuditVerification {
    Valid {
        checked: u64,
    },
    Broken {
        checked: u64,
        event_id: Uuid,
        reason: &'static str,
    },
}

#[derive(Debug, Error)]
pub enum AuditStoreError {
    #[error("audit event draft is invalid")]
    InvalidDraft,
    #[error("stored audit chain is invalid")]
    InvalidStoredChain,
    #[error(transparent)]
    Audit(#[from] snm_security::audit::AuditError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use snm_security::audit::AuditActorType;

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
            "INSERT INTO organizations (slug, name) VALUES ($1, 'Audit Test') RETURNING id",
        )
        .bind(format!("audit-{suffix}"))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    fn draft(organization_id: Uuid, action: &str, timestamp: i64) -> AuditEventDraft {
        AuditEventDraft {
            organization_id,
            site_id: None,
            actor_type: AuditActorType::User,
            actor_id: Some(Uuid::now_v7()),
            session_id: None,
            source_ip: Some("127.0.0.1".into()),
            request_id: Uuid::now_v7().to_string(),
            correlation_id: Uuid::now_v7(),
            action: action.into(),
            resource_type: "fixture".into(),
            resource_id: Some("resource-1".into()),
            provider: None,
            occurred_at_unix_ms: timestamp,
            duration_ms: Some(2),
            status: AuditStatus::Succeeded,
            reason_code: None,
            before: Some(json!({"username":"admin","password":"old-secret"})),
            after: Some(json!({"username":"admin","password":"new-secret"})),
            result: Some(json!({"token":"secret-token","ok":true})),
        }
    }

    #[tokio::test]
    async fn append_sanitizes_before_persistence_and_builds_valid_chain() {
        let Some(pool) = pool().await else { return };
        let organization_id = organization(&pool).await;
        let store = AuditStore::new(pool.clone());
        store.append(draft(organization_id, "fixture.one", 1000)).await.unwrap();
        store.append(draft(organization_id, "fixture.two", 1001)).await.unwrap();

        let payloads: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT canonical_payload FROM audit_events WHERE organization_id = $1 AND chain_sequence IS NOT NULL ORDER BY chain_sequence",
        )
        .bind(organization_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(payloads.len(), 2);
        for payload in payloads {
            let text = String::from_utf8(payload).unwrap();
            assert!(!text.contains("old-secret"));
            assert!(!text.contains("new-secret"));
            assert!(!text.contains("secret-token"));
            assert!(text.contains("[REDACTED]"));
        }
        assert_eq!(
            store.verify_organization_chain(organization_id).await.unwrap(),
            AuditVerification::Valid { checked: 2 }
        );
    }

    #[tokio::test]
    async fn database_rejects_update_and_delete_of_audit_events() {
        let Some(pool) = pool().await else { return };
        let organization_id = organization(&pool).await;
        let store = AuditStore::new(pool.clone());
        let id = store
            .append(draft(organization_id, "fixture.immutable", 2000))
            .await
            .unwrap();

        assert!(
            sqlx::query("UPDATE audit_events SET action = 'tampered' WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("DELETE FROM audit_events WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn concurrent_appends_do_not_fork_even_if_event_times_are_reversed() {
        let Some(pool) = pool().await else { return };
        let organization_id = organization(&pool).await;
        let store = AuditStore::new(pool);
        let first = store.clone();
        let second = store.clone();
        let a = tokio::spawn(async move {
            first.append(draft(organization_id, "fixture.a", 5000)).await
        });
        let b = tokio::spawn(async move {
            second.append(draft(organization_id, "fixture.b", 1000)).await
        });
        a.await.unwrap().unwrap();
        b.await.unwrap().unwrap();
        assert_eq!(
            store.verify_organization_chain(organization_id).await.unwrap(),
            AuditVerification::Valid { checked: 2 }
        );
    }
}
