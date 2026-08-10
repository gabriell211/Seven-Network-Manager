use chrono::Utc;
use serde_json::json;
use snm_security::audit::AuditActorType;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    DiscoveryStoreError, MutationContext, MutationRecord, load_scope_in_tx, write_mutation_records,
};

pub async fn enqueue_due_scheduled_runs(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<Uuid>, DiscoveryStoreError> {
    if !(1..=100).contains(&limit) {
        return Err(DiscoveryStoreError::InvalidInput(
            "scheduler batch size is invalid",
        ));
    }
    let mut tx = pool.begin().await?;
    let rows = sqlx::query(
        r#"
        SELECT s.id, s.organization_id, s.site_id
        FROM discovery_scopes s
        WHERE s.enabled
          AND s.schedule_interval_seconds IS NOT NULL
          AND s.next_run_at IS NOT NULL
          AND s.next_run_at <= now()
          AND NOT EXISTS (
            SELECT 1 FROM discovery_runs r
            WHERE r.scope_id = s.id AND r.status IN ('queued','running')
          )
        ORDER BY s.next_run_at, s.id
        FOR UPDATE SKIP LOCKED
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;

    let mut queued = Vec::with_capacity(rows.len());
    for row in rows {
        let scope_id: Uuid = row.try_get("id")?;
        let organization_id: Uuid = row.try_get("organization_id")?;
        let site_id: Uuid = row.try_get("site_id")?;
        let scope = load_scope_in_tx(&mut tx, organization_id, site_id, scope_id, false)
            .await?
            .ok_or(DiscoveryStoreError::ScopeNotFound)?;
        let run_id = Uuid::now_v7();
        let correlation_id = Uuid::now_v7();
        let snapshot = serde_json::to_value(&scope)?;
        sqlx::query(
            r#"
            INSERT INTO discovery_runs (
              id, scope_id, organization_id, site_id, routing_domain_id,
              status, correlation_id, requested_by, request_kind,
              seed_targets, scope_snapshot
            ) VALUES ($1,$2,$3,$4,$5,'queued',$6,NULL,'scheduled','{}'::inet[],$7)
            "#,
        )
        .bind(run_id)
        .bind(scope_id)
        .bind(organization_id)
        .bind(site_id)
        .bind(scope.routing_domain_id)
        .bind(correlation_id)
        .bind(snapshot)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            UPDATE discovery_scopes
            SET last_run_at = now(),
                next_run_at = now() + make_interval(secs => schedule_interval_seconds),
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(scope_id)
        .execute(&mut *tx)
        .await?;
        let context = MutationContext {
            organization_id,
            site_id,
            actor_type: AuditActorType::System,
            actor_id: None,
            session_id: None,
            source_ip: None,
            request_id: format!("discovery-schedule-{run_id}"),
            correlation_id,
        };
        write_mutation_records(
            &mut tx,
            &context,
            MutationRecord {
                action: "discovery.run.schedule.enqueue",
                event_type: "discovery.run.queued",
                resource_type: "discovery_run",
                resource_id: run_id,
                before: None,
                after: Some(json!({
                    "id": run_id,
                    "scopeId": scope_id,
                    "requestKind": "scheduled",
                    "queuedAt": Utc::now(),
                })),
            },
        )
        .await?;
        queued.push(run_id);
    }
    tx.commit().await?;
    Ok(queued)
}
