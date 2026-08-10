use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use snm_audit_store::{AuditStore, AuditStoreError};
use snm_domain::{
    ExecutionStatus, OrganizationId, RoutingDomainId, SiteId,
    discovery::{
        DiscoveryExecutionScope, DiscoveryProbeResult, DiscoveryScope, DiscoveryStatus,
        Ipv6DiscoveryStrategy, ObservationKind,
    },
};
use snm_platform_events::{NewOutboxEvent, OutboxError, OutboxStore};
use snm_security::audit::{AuditActorType, AuditEventDraft, AuditStatus};
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone)]
pub struct DiscoveryStore {
    pool: PgPool,
}

impl DiscoveryStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_scopes(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
    ) -> Result<Vec<DiscoveryScopeView>, DiscoveryStoreError> {
        let rows = sqlx::query(SCOPE_SELECT_LIST)
            .bind(organization_id)
            .bind(site_id)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(row_to_scope).collect()
    }

    pub async fn get_scope(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        scope_id: Uuid,
    ) -> Result<Option<DiscoveryScopeView>, DiscoveryStoreError> {
        let row = sqlx::query(SCOPE_SELECT_ONE)
            .bind(organization_id)
            .bind(site_id)
            .bind(scope_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_scope).transpose()
    }

    pub async fn create_scope(
        &self,
        context: &MutationContext,
        input: NewDiscoveryScope,
    ) -> Result<DiscoveryScopeView, DiscoveryStoreError> {
        context.validate()?;
        input.validate(context)?;
        let mut tx = self.pool.begin().await?;
        let id = Uuid::now_v7();
        let ipv6_strategy = input.ipv6_strategy.map(|value| value.as_str());
        let observations = input
            .observations
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        let ports = input.tcp_ports.iter().map(|value| i32::from(*value)).collect::<Vec<_>>();
        let source_address = input.source_address.map(|value| value.to_string());
        sqlx::query(
            r#"
            INSERT INTO discovery_scopes (
              id, organization_id, site_id, routing_domain_id, network,
              ipv6_strategy, concurrency_limit, rate_per_second, timeout_ms,
              enabled, name, observations, tcp_ports, interface_scope,
              source_address, max_targets, schedule_interval_seconds, next_run_at
            ) VALUES (
              $1,$2,$3,$4,$5::cidr,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::inet,$16,$17,
              CASE WHEN $10 AND $17::integer IS NOT NULL
                   THEN now() + make_interval(secs => $17)
                   ELSE NULL END
            )
            "#,
        )
        .bind(id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(input.routing_domain_id)
        .bind(input.network.to_string())
        .bind(ipv6_strategy)
        .bind(i32::from(input.concurrency_limit))
        .bind(i32::from(input.rate_per_second))
        .bind(i32::try_from(input.timeout_ms).map_err(|_| DiscoveryStoreError::InvalidInput("timeout is invalid"))?)
        .bind(input.enabled)
        .bind(input.name.trim())
        .bind(observations)
        .bind(ports)
        .bind(clean_optional(input.interface_scope))
        .bind(source_address)
        .bind(i32::try_from(input.max_targets).map_err(|_| DiscoveryStoreError::InvalidInput("max targets is invalid"))?)
        .bind(input.schedule_interval_seconds.map(i32::from))
        .execute(&mut *tx)
        .await
        .map_err(map_scope_database_error)?;

        let created = load_scope_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            id,
            false,
        )
        .await?
        .ok_or(DiscoveryStoreError::ScopeNotFound)?;
        write_mutation_records(
            &mut tx,
            context,
            "discovery.scope.create",
            "discovery.scope.created",
            "discovery_scope",
            id,
            None,
            Some(serde_json::to_value(&created)?),
        )
        .await?;
        tx.commit().await?;
        Ok(created)
    }

    pub async fn update_scope(
        &self,
        context: &MutationContext,
        scope_id: Uuid,
        input: UpdateDiscoveryScope,
    ) -> Result<DiscoveryScopeView, DiscoveryStoreError> {
        context.validate()?;
        input.values.validate(context)?;
        let mut tx = self.pool.begin().await?;
        let current = load_scope_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            scope_id,
            true,
        )
        .await?
        .ok_or(DiscoveryStoreError::ScopeNotFound)?;
        if current.version != input.expected_version {
            return Err(DiscoveryStoreError::VersionConflict {
                expected: input.expected_version,
                actual: current.version,
            });
        }
        if current.has_active_run {
            return Err(DiscoveryStoreError::ScopeHasActiveRun);
        }
        let before = serde_json::to_value(&current)?;
        let values = input.values;
        let observations = values
            .observations
            .iter()
            .map(|value| value.as_str().to_owned())
            .collect::<Vec<_>>();
        let ports = values
            .tcp_ports
            .iter()
            .map(|value| i32::from(*value))
            .collect::<Vec<_>>();
        sqlx::query(
            r#"
            UPDATE discovery_scopes
            SET routing_domain_id = $4, network = $5::cidr, ipv6_strategy = $6,
                concurrency_limit = $7, rate_per_second = $8, timeout_ms = $9,
                enabled = $10, name = $11, observations = $12, tcp_ports = $13,
                interface_scope = $14, source_address = $15::inet, max_targets = $16,
                schedule_interval_seconds = $17,
                next_run_at = CASE
                  WHEN $10 AND $17::integer IS NOT NULL THEN
                    CASE WHEN schedule_interval_seconds IS DISTINCT FROM $17 OR next_run_at IS NULL
                         THEN now() + make_interval(secs => $17)
                         ELSE next_run_at END
                  ELSE NULL
                END,
                version = version + 1, updated_at = now()
            WHERE id = $1 AND organization_id = $2 AND site_id = $3
            "#,
        )
        .bind(scope_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(values.routing_domain_id)
        .bind(values.network.to_string())
        .bind(values.ipv6_strategy.map(|value| value.as_str()))
        .bind(i32::from(values.concurrency_limit))
        .bind(i32::from(values.rate_per_second))
        .bind(i32::try_from(values.timeout_ms).map_err(|_| DiscoveryStoreError::InvalidInput("timeout is invalid"))?)
        .bind(values.enabled)
        .bind(values.name.trim())
        .bind(observations)
        .bind(ports)
        .bind(clean_optional(values.interface_scope))
        .bind(values.source_address.map(|value| value.to_string()))
        .bind(i32::try_from(values.max_targets).map_err(|_| DiscoveryStoreError::InvalidInput("max targets is invalid"))?)
        .bind(values.schedule_interval_seconds.map(i32::from))
        .execute(&mut *tx)
        .await
        .map_err(map_scope_database_error)?;

        let updated = load_scope_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            scope_id,
            false,
        )
        .await?
        .ok_or(DiscoveryStoreError::ScopeNotFound)?;
        write_mutation_records(
            &mut tx,
            context,
            "discovery.scope.update",
            "discovery.scope.updated",
            "discovery_scope",
            scope_id,
            Some(before),
            Some(serde_json::to_value(&updated)?),
        )
        .await?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn delete_scope(
        &self,
        context: &MutationContext,
        scope_id: Uuid,
        expected_version: i64,
    ) -> Result<(), DiscoveryStoreError> {
        context.validate()?;
        let mut tx = self.pool.begin().await?;
        let current = load_scope_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            scope_id,
            true,
        )
        .await?
        .ok_or(DiscoveryStoreError::ScopeNotFound)?;
        if current.version != expected_version {
            return Err(DiscoveryStoreError::VersionConflict {
                expected: expected_version,
                actual: current.version,
            });
        }
        if current.has_active_run {
            return Err(DiscoveryStoreError::ScopeHasActiveRun);
        }
        let before = serde_json::to_value(&current)?;
        let deleted = sqlx::query(
            r#"
            DELETE FROM discovery_scopes
            WHERE id = $1 AND organization_id = $2 AND site_id = $3
              AND NOT EXISTS (SELECT 1 FROM discovery_runs r WHERE r.scope_id = discovery_scopes.id)
            "#,
        )
        .bind(scope_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .execute(&mut *tx)
        .await?;
        if deleted.rows_affected() != 1 {
            return Err(DiscoveryStoreError::ScopeHasHistory);
        }
        write_mutation_records(
            &mut tx,
            context,
            "discovery.scope.delete",
            "discovery.scope.deleted",
            "discovery_scope",
            scope_id,
            Some(before),
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn create_run(
        &self,
        context: &MutationContext,
        scope_id: Uuid,
        request_kind: RunRequestKind,
        seed_targets: Vec<IpAddr>,
    ) -> Result<DiscoveryRunView, DiscoveryStoreError> {
        context.validate()?;
        validate_seeds(&seed_targets)?;
        let mut tx = self.pool.begin().await?;
        let scope = load_scope_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            scope_id,
            true,
        )
        .await?
        .ok_or(DiscoveryStoreError::ScopeNotFound)?;
        if !scope.enabled {
            return Err(DiscoveryStoreError::ScopeDisabled);
        }
        for seed in &seed_targets {
            if !scope.network.contains(seed) {
                return Err(DiscoveryStoreError::SeedOutsideScope(*seed));
            }
        }
        let existing: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id FROM discovery_runs
            WHERE scope_id = $1 AND status IN ('queued','running')
            LIMIT 1
            "#,
        )
        .bind(scope_id)
        .fetch_optional(&mut *tx)
        .await?;
        if existing.is_some() {
            return Err(DiscoveryStoreError::ScopeHasActiveRun);
        }

        let id = Uuid::now_v7();
        let snapshot = serde_json::to_value(&scope)?;
        let seed_text = seed_targets
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        sqlx::query(
            r#"
            INSERT INTO discovery_runs (
              id, scope_id, organization_id, site_id, routing_domain_id,
              status, correlation_id, requested_by, request_kind,
              seed_targets, scope_snapshot
            ) VALUES ($1,$2,$3,$4,$5,'queued',$6,$7,$8,
                      ARRAY(SELECT value::inet FROM unnest($9::text[]) AS value),$10)
            "#,
        )
        .bind(id)
        .bind(scope_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(scope.routing_domain_id)
        .bind(context.correlation_id)
        .bind(context.actor_id)
        .bind(request_kind.as_str())
        .bind(seed_text)
        .bind(snapshot)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            UPDATE discovery_scopes
            SET last_run_at = now(),
                next_run_at = CASE
                  WHEN schedule_interval_seconds IS NOT NULL AND enabled
                    THEN now() + make_interval(secs => schedule_interval_seconds)
                  ELSE NULL END,
                updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(scope_id)
        .execute(&mut *tx)
        .await?;
        let run = load_run_in_tx(&mut tx, context.organization_id, context.site_id, id, false)
            .await?
            .ok_or(DiscoveryStoreError::RunNotFound)?;
        write_mutation_records(
            &mut tx,
            context,
            "discovery.run.enqueue",
            "discovery.run.queued",
            "discovery_run",
            id,
            None,
            Some(serde_json::to_value(&run)?),
        )
        .await?;
        tx.commit().await?;
        Ok(run)
    }

    pub async fn list_runs(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        scope_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DiscoveryRunView>, DiscoveryStoreError> {
        if !(1..=200).contains(&limit) || offset < 0 {
            return Err(DiscoveryStoreError::InvalidInput("pagination is invalid"));
        }
        let rows = sqlx::query(
            r#"
            SELECT id, scope_id, organization_id, site_id, routing_domain_id,
                   status, correlation_id, requested_by, request_kind,
                   ARRAY(SELECT host(value) FROM unnest(seed_targets) AS value) AS seed_targets,
                   scope_snapshot, cancellation_requested_at, progress_total,
                   progress_completed, summary, error_code, version, started_at,
                   finished_at, created_at, updated_at
            FROM discovery_runs
            WHERE organization_id = $1 AND site_id = $2
              AND ($3::uuid IS NULL OR scope_id = $3)
            ORDER BY created_at DESC, id DESC
            LIMIT $4 OFFSET $5
            "#,
        )
        .bind(organization_id)
        .bind(site_id)
        .bind(scope_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_run).collect()
    }

    pub async fn get_run(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        run_id: Uuid,
    ) -> Result<Option<DiscoveryRunView>, DiscoveryStoreError> {
        let mut tx = self.pool.begin().await?;
        let run = load_run_in_tx(&mut tx, organization_id, site_id, run_id, false).await?;
        tx.rollback().await?;
        Ok(run)
    }

    pub async fn claim_next_queued_run(
        &self,
        organization_id: Option<Uuid>,
    ) -> Result<Option<RunExecutionInput>, DiscoveryStoreError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            r#"
            SELECT id
            FROM discovery_runs
            WHERE status = 'queued'
              AND cancellation_requested_at IS NULL
              AND ($1::uuid IS NULL OR organization_id = $1)
            ORDER BY created_at, id
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            "#,
        )
        .bind(organization_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let run_id: Uuid = row.try_get("id")?;
        sqlx::query(
            r#"
            UPDATE discovery_runs
            SET status = 'running', started_at = coalesce(started_at, now()),
                updated_at = now(), version = version + 1
            WHERE id = $1 AND status = 'queued'
            "#,
        )
        .bind(run_id)
        .execute(&mut *tx)
        .await?;
        let run = load_run_by_id_in_tx(&mut tx, run_id, false)
            .await?
            .ok_or(DiscoveryStoreError::RunNotFound)?;
        let scope: DiscoveryScopeView = serde_json::from_value(run.scope_snapshot.clone())
            .map_err(|_| DiscoveryStoreError::InvalidStoredValue("scope snapshot is invalid"))?;
        tx.commit().await?;
        Ok(Some(RunExecutionInput { run, scope }))
    }

    pub async fn set_progress_total(
        &self,
        run_id: Uuid,
        total: usize,
    ) -> Result<(), DiscoveryStoreError> {
        let total = i32::try_from(total)
            .map_err(|_| DiscoveryStoreError::InvalidInput("progress total is too large"))?;
        let updated = sqlx::query(
            r#"
            UPDATE discovery_runs
            SET progress_total = $2, updated_at = now(), version = version + 1
            WHERE id = $1 AND status = 'running' AND progress_completed <= $2
            "#,
        )
        .bind(run_id)
        .bind(total)
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(DiscoveryStoreError::RunNotRunning);
        }
        Ok(())
    }

    pub async fn cancellation_requested(&self, run_id: Uuid) -> Result<bool, DiscoveryStoreError> {
        let value = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT cancellation_requested_at IS NOT NULL
            FROM discovery_runs WHERE id = $1
            "#,
        )
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DiscoveryStoreError::RunNotFound)?;
        Ok(value)
    }

    pub async fn request_cancel(
        &self,
        context: &MutationContext,
        run_id: Uuid,
    ) -> Result<DiscoveryRunView, DiscoveryStoreError> {
        context.validate()?;
        let mut tx = self.pool.begin().await?;
        let current = load_run_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            run_id,
            true,
        )
        .await?
        .ok_or(DiscoveryStoreError::RunNotFound)?;
        if matches!(
            current.status,
            DiscoveryStatus::Completed
                | DiscoveryStatus::Partial
                | DiscoveryStatus::Failed
                | DiscoveryStatus::Cancelled
        ) {
            tx.rollback().await?;
            return Ok(current);
        }
        let before = serde_json::to_value(&current)?;
        sqlx::query(
            r#"
            UPDATE discovery_runs
            SET cancellation_requested_at = coalesce(cancellation_requested_at, now()),
                status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END,
                finished_at = CASE WHEN status = 'queued' THEN now() ELSE finished_at END,
                updated_at = now(), version = version + 1
            WHERE id = $1
            "#,
        )
        .bind(run_id)
        .execute(&mut *tx)
        .await?;
        let updated = load_run_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            run_id,
            false,
        )
        .await?
        .ok_or(DiscoveryStoreError::RunNotFound)?;
        write_mutation_records(
            &mut tx,
            context,
            "discovery.run.cancel.request",
            "discovery.run.cancel_requested",
            "discovery_run",
            run_id,
            Some(before),
            Some(serde_json::to_value(&updated)?),
        )
        .await?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn record_probe_result(
        &self,
        run_id: Uuid,
        result: &DiscoveryProbeResult,
    ) -> Result<Uuid, DiscoveryStoreError> {
        let observed_at = result
            .evidence
            .iter()
            .map(|item| item.observed_at)
            .max()
            .unwrap_or_else(Utc::now);
        let mut tx = self.pool.begin().await?;
        let run = load_run_by_id_in_tx(&mut tx, run_id, true)
            .await?
            .ok_or(DiscoveryStoreError::RunNotFound)?;
        if run.status != DiscoveryStatus::Running {
            return Err(DiscoveryStoreError::RunNotRunning);
        }
        if run.routing_domain_id != result.target.routing_domain_id.0
            || run.organization_id != result.target.organization_id.0
            || run.site_id != result.target.site_id.0
        {
            return Err(DiscoveryStoreError::ProbeScopeMismatch);
        }
        let id = Uuid::now_v7();
        let inserted_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO discovery_probe_results (
              id, discovery_run_id, organization_id, site_id, routing_domain_id,
              address, interface_scope, probe_kind, port, status, latency_ms,
              error_code, evidence_count, observed_at
            ) VALUES ($1,$2,$3,$4,$5,$6::inet,$7,$8,$9,$10,$11,$12,$13,$14)
            ON CONFLICT (
              discovery_run_id, address, coalesce(interface_scope, ''), probe_kind, coalesce(port, 0)
            ) DO UPDATE SET
              status = EXCLUDED.status,
              latency_ms = EXCLUDED.latency_ms,
              error_code = EXCLUDED.error_code,
              evidence_count = EXCLUDED.evidence_count,
              observed_at = EXCLUDED.observed_at
            RETURNING id
            "#,
        )
        .bind(id)
        .bind(run_id)
        .bind(run.organization_id)
        .bind(run.site_id)
        .bind(run.routing_domain_id)
        .bind(result.target.address.to_string())
        .bind(result.target.interface_scope.as_deref())
        .bind(result.probe.as_str())
        .bind(result.port.map(i32::from))
        .bind(execution_status_str(&result.status))
        .bind(result.latency_ms.and_then(|value| i64::try_from(value).ok()))
        .bind(result.error_code.as_deref())
        .bind(i32::try_from(result.evidence.len()).unwrap_or(i32::MAX))
        .bind(observed_at)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM discovery_evidence WHERE probe_result_id = $1")
            .bind(inserted_id)
            .execute(&mut *tx)
            .await?;
        for evidence in &result.evidence {
            evidence
                .validate()
                .map_err(DiscoveryStoreError::InvalidInput)?;
            sqlx::query(
                r#"
                INSERT INTO discovery_evidence (
                  discovery_run_id, organization_id, site_id, routing_domain_id,
                  address, evidence_type, field, value, source, confidence,
                  observed_at, probe_result_id, probe_kind, port, last_seen_at
                ) VALUES ($1,$2,$3,$4,$5::inet,$6,$7,to_jsonb($8::text),$9,$10::numeric,
                          $11,$12,$13,$14,$11)
                "#,
            )
            .bind(run_id)
            .bind(run.organization_id)
            .bind(run.site_id)
            .bind(run.routing_domain_id)
            .bind(result.target.address.to_string())
            .bind(result.probe.as_str())
            .bind(&evidence.field)
            .bind(&evidence.value)
            .bind(&evidence.source)
            .bind(evidence.confidence.to_string())
            .bind(evidence.observed_at)
            .bind(inserted_id)
            .bind(result.probe.as_str())
            .bind(result.port.map(i32::from))
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            r#"
            UPDATE discovery_runs
            SET progress_completed = LEAST(progress_total, progress_completed + 1),
                updated_at = now(), version = version + 1
            WHERE id = $1 AND status = 'running'
            "#,
        )
        .bind(run_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(inserted_id)
    }

    pub async fn finish_run(
        &self,
        run_id: Uuid,
        status: DiscoveryStatus,
        summary: Value,
        error_code: Option<&str>,
    ) -> Result<DiscoveryRunView, DiscoveryStoreError> {
        if matches!(status, DiscoveryStatus::Queued | DiscoveryStatus::Running) {
            return Err(DiscoveryStoreError::InvalidInput("finish status must be terminal"));
        }
        let mut tx = self.pool.begin().await?;
        let current = load_run_by_id_in_tx(&mut tx, run_id, true)
            .await?
            .ok_or(DiscoveryStoreError::RunNotFound)?;
        if current.status != DiscoveryStatus::Running {
            return Err(DiscoveryStoreError::RunNotRunning);
        }
        sqlx::query(
            r#"
            UPDATE discovery_runs
            SET status = $2, summary = $3, error_code = $4,
                finished_at = now(), updated_at = now(), version = version + 1
            WHERE id = $1
            "#,
        )
        .bind(run_id)
        .bind(status.as_str())
        .bind(summary)
        .bind(error_code)
        .execute(&mut *tx)
        .await?;
        let updated = load_run_by_id_in_tx(&mut tx, run_id, false)
            .await?
            .ok_or(DiscoveryStoreError::RunNotFound)?;
        let system_context = MutationContext {
            organization_id: updated.organization_id,
            site_id: updated.site_id,
            actor_type: AuditActorType::System,
            actor_id: None,
            session_id: None,
            source_ip: None,
            request_id: format!("discovery-run-{run_id}"),
            correlation_id: updated.correlation_id,
        };
        write_mutation_records(
            &mut tx,
            &system_context,
            "discovery.run.finish",
            "discovery.run.finished",
            "discovery_run",
            run_id,
            Some(serde_json::to_value(&current)?),
            Some(serde_json::to_value(&updated)?),
        )
        .await?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn list_probe_results(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        run_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ProbeResultView>, DiscoveryStoreError> {
        if !(1..=500).contains(&limit) || offset < 0 {
            return Err(DiscoveryStoreError::InvalidInput("pagination is invalid"));
        }
        let rows = sqlx::query(
            r#"
            SELECT id, discovery_run_id, organization_id, site_id, routing_domain_id,
                   host(address) AS address, interface_scope, probe_kind, port,
                   status, latency_ms, error_code, evidence_count, observed_at
            FROM discovery_probe_results
            WHERE discovery_run_id = $1 AND organization_id = $2 AND site_id = $3
            ORDER BY address, probe_kind, port NULLS FIRST
            LIMIT $4 OFFSET $5
            "#,
        )
        .bind(run_id)
        .bind(organization_id)
        .bind(site_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_probe_result).collect()
    }
}

const SCOPE_SELECT_LIST: &str = r#"
SELECT s.id, s.organization_id, s.site_id, s.routing_domain_id,
       s.network::text AS network, s.ipv6_strategy, s.concurrency_limit,
       s.rate_per_second, s.timeout_ms, s.enabled, s.version, s.name,
       s.observations, s.tcp_ports, s.interface_scope, host(s.source_address) AS source_address,
       s.max_targets, s.schedule_interval_seconds, s.next_run_at, s.last_run_at,
       s.created_at, s.updated_at,
       EXISTS (
         SELECT 1 FROM discovery_runs r
         WHERE r.scope_id = s.id AND r.status IN ('queued','running')
       ) AS has_active_run
FROM discovery_scopes s
WHERE s.organization_id = $1 AND s.site_id = $2
ORDER BY s.name, s.network, s.id
"#;

const SCOPE_SELECT_ONE: &str = r#"
SELECT s.id, s.organization_id, s.site_id, s.routing_domain_id,
       s.network::text AS network, s.ipv6_strategy, s.concurrency_limit,
       s.rate_per_second, s.timeout_ms, s.enabled, s.version, s.name,
       s.observations, s.tcp_ports, s.interface_scope, host(s.source_address) AS source_address,
       s.max_targets, s.schedule_interval_seconds, s.next_run_at, s.last_run_at,
       s.created_at, s.updated_at,
       EXISTS (
         SELECT 1 FROM discovery_runs r
         WHERE r.scope_id = s.id AND r.status IN ('queued','running')
       ) AS has_active_run
FROM discovery_scopes s
WHERE s.organization_id = $1 AND s.site_id = $2 AND s.id = $3
"#;

#[derive(Debug, Clone)]
pub struct MutationContext {
    pub organization_id: Uuid,
    pub site_id: Uuid,
    pub actor_type: AuditActorType,
    pub actor_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub source_ip: Option<String>,
    pub request_id: String,
    pub correlation_id: Uuid,
}

impl MutationContext {
    pub fn validate(&self) -> Result<(), DiscoveryStoreError> {
        if self.request_id.trim().is_empty() || self.request_id.len() > 200 {
            return Err(DiscoveryStoreError::InvalidInput("request id is invalid"));
        }
        if self
            .source_ip
            .as_ref()
            .is_some_and(|value| value.parse::<IpAddr>().is_err())
        {
            return Err(DiscoveryStoreError::InvalidInput("source IP is invalid"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewDiscoveryScope {
    pub routing_domain_id: Uuid,
    pub name: String,
    pub network: IpNet,
    pub observations: Vec<ObservationKind>,
    pub tcp_ports: Vec<u16>,
    pub ipv6_strategy: Option<Ipv6DiscoveryStrategy>,
    pub interface_scope: Option<String>,
    pub source_address: Option<IpAddr>,
    pub concurrency_limit: u16,
    pub rate_per_second: u16,
    pub timeout_ms: u32,
    pub max_targets: u32,
    pub schedule_interval_seconds: Option<u32>,
    pub enabled: bool,
}

impl NewDiscoveryScope {
    fn validate(&self, context: &MutationContext) -> Result<(), DiscoveryStoreError> {
        if self.name.trim().is_empty() || self.name.len() > 160 {
            return Err(DiscoveryStoreError::InvalidInput("scope name is invalid"));
        }
        if self.tcp_ports.len() > 64 || self.tcp_ports.iter().any(|port| *port == 0) {
            return Err(DiscoveryStoreError::InvalidInput("TCP ports are invalid"));
        }
        if self.max_targets == 0 || self.max_targets > 65_536 {
            return Err(DiscoveryStoreError::InvalidInput("max targets is invalid"));
        }
        if self
            .schedule_interval_seconds
            .is_some_and(|value| !(60..=2_592_000).contains(&value))
        {
            return Err(DiscoveryStoreError::InvalidInput("schedule interval is invalid"));
        }
        if self
            .interface_scope
            .as_ref()
            .is_some_and(|value| value.trim().is_empty() || value.len() > 128)
        {
            return Err(DiscoveryStoreError::InvalidInput("interface scope is invalid"));
        }
        let domain_scope = DiscoveryScope {
            id: Uuid::nil(),
            organization_id: OrganizationId(context.organization_id),
            site_id: SiteId(context.site_id),
            routing_domain_id: RoutingDomainId(self.routing_domain_id),
            network: self.network,
            observations: self.observations.clone(),
            ipv6_strategy: self.ipv6_strategy,
            concurrency_limit: self.concurrency_limit,
            rate_per_second: self.rate_per_second,
            timeout_ms: self.timeout_ms,
        };
        domain_scope
            .validate()
            .map_err(DiscoveryStoreError::InvalidInput)?;
        let execution_scope = DiscoveryExecutionScope {
            organization_id: OrganizationId(context.organization_id),
            site_id: SiteId(context.site_id),
            routing_domain_id: RoutingDomainId(self.routing_domain_id),
            network: self.network,
            interface_scope: self.interface_scope.clone(),
            source_address: self.source_address,
        };
        execution_scope
            .validate()
            .map_err(|_| DiscoveryStoreError::InvalidInput("execution scope is invalid"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDiscoveryScope {
    pub expected_version: i64,
    #[serde(flatten)]
    pub values: NewDiscoveryScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryScopeView {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub site_id: Uuid,
    pub routing_domain_id: Uuid,
    pub name: String,
    pub network: IpNet,
    pub observations: Vec<ObservationKind>,
    pub tcp_ports: Vec<u16>,
    pub ipv6_strategy: Option<Ipv6DiscoveryStrategy>,
    pub interface_scope: Option<String>,
    pub source_address: Option<IpAddr>,
    pub concurrency_limit: u16,
    pub rate_per_second: u16,
    pub timeout_ms: u32,
    pub max_targets: u32,
    pub schedule_interval_seconds: Option<u32>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub version: i64,
    pub has_active_run: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl DiscoveryScopeView {
    pub fn domain_scope(&self) -> DiscoveryScope {
        DiscoveryScope {
            id: self.id,
            organization_id: OrganizationId(self.organization_id),
            site_id: SiteId(self.site_id),
            routing_domain_id: RoutingDomainId(self.routing_domain_id),
            network: self.network,
            observations: self.observations.clone(),
            ipv6_strategy: self.ipv6_strategy,
            concurrency_limit: self.concurrency_limit,
            rate_per_second: self.rate_per_second,
            timeout_ms: self.timeout_ms,
        }
    }

    pub fn execution_scope(&self) -> DiscoveryExecutionScope {
        DiscoveryExecutionScope {
            organization_id: OrganizationId(self.organization_id),
            site_id: SiteId(self.site_id),
            routing_domain_id: RoutingDomainId(self.routing_domain_id),
            network: self.network,
            interface_scope: self.interface_scope.clone(),
            source_address: self.source_address,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunRequestKind {
    Manual,
    Scheduled,
}

impl RunRequestKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Scheduled => "scheduled",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryRunView {
    pub id: Uuid,
    pub scope_id: Uuid,
    pub organization_id: Uuid,
    pub site_id: Uuid,
    pub routing_domain_id: Uuid,
    pub status: DiscoveryStatus,
    pub correlation_id: Uuid,
    pub requested_by: Option<Uuid>,
    pub request_kind: RunRequestKind,
    pub seed_targets: Vec<IpAddr>,
    #[serde(skip_serializing)]
    pub scope_snapshot: Value,
    pub cancellation_requested_at: Option<DateTime<Utc>>,
    pub progress_total: i32,
    pub progress_completed: i32,
    pub summary: Value,
    pub error_code: Option<String>,
    pub version: i64,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RunExecutionInput {
    pub run: DiscoveryRunView,
    pub scope: DiscoveryScopeView,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeResultView {
    pub id: Uuid,
    pub discovery_run_id: Uuid,
    pub organization_id: Uuid,
    pub site_id: Uuid,
    pub routing_domain_id: Uuid,
    pub address: IpAddr,
    pub interface_scope: Option<String>,
    pub probe_kind: String,
    pub port: Option<u16>,
    pub status: ExecutionStatus,
    pub latency_ms: Option<u64>,
    pub error_code: Option<String>,
    pub evidence_count: i32,
    pub observed_at: DateTime<Utc>,
}

async fn load_scope_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    scope_id: Uuid,
    for_update: bool,
) -> Result<Option<DiscoveryScopeView>, DiscoveryStoreError> {
    let sql = if for_update {
        format!("{SCOPE_SELECT_ONE} FOR UPDATE")
    } else {
        SCOPE_SELECT_ONE.to_owned()
    };
    let row = sqlx::query(&sql)
        .bind(organization_id)
        .bind(site_id)
        .bind(scope_id)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(row_to_scope).transpose()
}

async fn load_run_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    run_id: Uuid,
    for_update: bool,
) -> Result<Option<DiscoveryRunView>, DiscoveryStoreError> {
    let mut sql = RUN_SELECT.to_owned();
    sql.push_str(" WHERE organization_id = $1 AND site_id = $2 AND id = $3");
    if for_update {
        sql.push_str(" FOR UPDATE");
    }
    let row = sqlx::query(&sql)
        .bind(organization_id)
        .bind(site_id)
        .bind(run_id)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(row_to_run).transpose()
}

async fn load_run_by_id_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    run_id: Uuid,
    for_update: bool,
) -> Result<Option<DiscoveryRunView>, DiscoveryStoreError> {
    let mut sql = RUN_SELECT.to_owned();
    sql.push_str(" WHERE id = $1");
    if for_update {
        sql.push_str(" FOR UPDATE");
    }
    let row = sqlx::query(&sql)
        .bind(run_id)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(row_to_run).transpose()
}

const RUN_SELECT: &str = r#"
SELECT id, scope_id, organization_id, site_id, routing_domain_id,
       status, correlation_id, requested_by, request_kind,
       ARRAY(SELECT host(value) FROM unnest(seed_targets) AS value) AS seed_targets,
       scope_snapshot, cancellation_requested_at, progress_total,
       progress_completed, summary, error_code, version, started_at,
       finished_at, created_at, updated_at
FROM discovery_runs
"#;

fn row_to_scope(row: sqlx::postgres::PgRow) -> Result<DiscoveryScopeView, DiscoveryStoreError> {
    let network: String = row.try_get("network")?;
    let observation_values: Vec<String> = row.try_get("observations")?;
    let port_values: Vec<i32> = row.try_get("tcp_ports")?;
    Ok(DiscoveryScopeView {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        site_id: row.try_get("site_id")?,
        routing_domain_id: row.try_get("routing_domain_id")?,
        name: row.try_get("name")?,
        network: network
            .parse()
            .map_err(|_| DiscoveryStoreError::InvalidStoredValue("scope network is invalid"))?,
        observations: observation_values
            .iter()
            .map(|value| parse_observation(value))
            .collect::<Result<Vec<_>, _>>()?,
        tcp_ports: port_values
            .into_iter()
            .map(|value| {
                u16::try_from(value)
                    .map_err(|_| DiscoveryStoreError::InvalidStoredValue("TCP port is invalid"))
            })
            .collect::<Result<Vec<_>, _>>()?,
        ipv6_strategy: row
            .try_get::<Option<String>, _>("ipv6_strategy")?
            .as_deref()
            .map(parse_ipv6_strategy)
            .transpose()?,
        interface_scope: row.try_get("interface_scope")?,
        source_address: row
            .try_get::<Option<String>, _>("source_address")?
            .map(|value| {
                value.parse().map_err(|_| {
                    DiscoveryStoreError::InvalidStoredValue("source address is invalid")
                })
            })
            .transpose()?,
        concurrency_limit: u16::try_from(row.try_get::<i32, _>("concurrency_limit")?)
            .map_err(|_| DiscoveryStoreError::InvalidStoredValue("concurrency is invalid"))?,
        rate_per_second: u16::try_from(row.try_get::<i32, _>("rate_per_second")?)
            .map_err(|_| DiscoveryStoreError::InvalidStoredValue("rate is invalid"))?,
        timeout_ms: u32::try_from(row.try_get::<i32, _>("timeout_ms")?)
            .map_err(|_| DiscoveryStoreError::InvalidStoredValue("timeout is invalid"))?,
        max_targets: u32::try_from(row.try_get::<i32, _>("max_targets")?)
            .map_err(|_| DiscoveryStoreError::InvalidStoredValue("max targets is invalid"))?,
        schedule_interval_seconds: row
            .try_get::<Option<i32>, _>("schedule_interval_seconds")?
            .map(|value| {
                u32::try_from(value).map_err(|_| {
                    DiscoveryStoreError::InvalidStoredValue("schedule interval is invalid")
                })
            })
            .transpose()?,
        next_run_at: row.try_get("next_run_at")?,
        last_run_at: row.try_get("last_run_at")?,
        enabled: row.try_get("enabled")?,
        version: row.try_get("version")?,
        has_active_run: row.try_get("has_active_run")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_run(row: sqlx::postgres::PgRow) -> Result<DiscoveryRunView, DiscoveryStoreError> {
    let seeds: Vec<String> = row.try_get("seed_targets")?;
    Ok(DiscoveryRunView {
        id: row.try_get("id")?,
        scope_id: row.try_get("scope_id")?,
        organization_id: row.try_get("organization_id")?,
        site_id: row.try_get("site_id")?,
        routing_domain_id: row.try_get("routing_domain_id")?,
        status: parse_status(&row.try_get::<String, _>("status")?)?,
        correlation_id: row.try_get("correlation_id")?,
        requested_by: row.try_get("requested_by")?,
        request_kind: parse_request_kind(&row.try_get::<String, _>("request_kind")?)?,
        seed_targets: seeds
            .into_iter()
            .map(|value| {
                value.parse().map_err(|_| {
                    DiscoveryStoreError::InvalidStoredValue("seed target is invalid")
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        scope_snapshot: row.try_get("scope_snapshot")?,
        cancellation_requested_at: row.try_get("cancellation_requested_at")?,
        progress_total: row.try_get("progress_total")?,
        progress_completed: row.try_get("progress_completed")?,
        summary: row.try_get("summary")?,
        error_code: row.try_get("error_code")?,
        version: row.try_get("version")?,
        started_at: row.try_get("started_at")?,
        finished_at: row.try_get("finished_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn row_to_probe_result(
    row: sqlx::postgres::PgRow,
) -> Result<ProbeResultView, DiscoveryStoreError> {
    let address: String = row.try_get("address")?;
    let port = row
        .try_get::<Option<i32>, _>("port")?
        .map(|value| {
            u16::try_from(value)
                .map_err(|_| DiscoveryStoreError::InvalidStoredValue("port is invalid"))
        })
        .transpose()?;
    Ok(ProbeResultView {
        id: row.try_get("id")?,
        discovery_run_id: row.try_get("discovery_run_id")?,
        organization_id: row.try_get("organization_id")?,
        site_id: row.try_get("site_id")?,
        routing_domain_id: row.try_get("routing_domain_id")?,
        address: address
            .parse()
            .map_err(|_| DiscoveryStoreError::InvalidStoredValue("address is invalid"))?,
        interface_scope: row.try_get("interface_scope")?,
        probe_kind: row.try_get("probe_kind")?,
        port,
        status: parse_execution_status(&row.try_get::<String, _>("status")?)?,
        latency_ms: row
            .try_get::<Option<i64>, _>("latency_ms")?
            .map(|value| u64::try_from(value).unwrap_or(0)),
        error_code: row.try_get("error_code")?,
        evidence_count: row.try_get("evidence_count")?,
        observed_at: row.try_get("observed_at")?,
    })
}

fn parse_observation(value: &str) -> Result<ObservationKind, DiscoveryStoreError> {
    match value {
        "reachability" => Ok(ObservationKind::Reachability),
        "neighbor" => Ok(ObservationKind::Neighbor),
        "reverse_dns" => Ok(ObservationKind::ReverseDns),
        "service" => Ok(ObservationKind::Service),
        "management_protocol" => Ok(ObservationKind::ManagementProtocol),
        _ => Err(DiscoveryStoreError::InvalidStoredValue("observation kind is invalid")),
    }
}

fn parse_ipv6_strategy(value: &str) -> Result<Ipv6DiscoveryStrategy, DiscoveryStoreError> {
    match value {
        "seeded_targets" => Ok(Ipv6DiscoveryStrategy::SeededTargets),
        "neighbor_evidence" => Ok(Ipv6DiscoveryStrategy::NeighborEvidence),
        "dns_evidence" => Ok(Ipv6DiscoveryStrategy::DnsEvidence),
        "provider_inventory" => Ok(Ipv6DiscoveryStrategy::ProviderInventory),
        _ => Err(DiscoveryStoreError::InvalidStoredValue("IPv6 strategy is invalid")),
    }
}

fn parse_status(value: &str) -> Result<DiscoveryStatus, DiscoveryStoreError> {
    match value {
        "queued" => Ok(DiscoveryStatus::Queued),
        "running" => Ok(DiscoveryStatus::Running),
        "completed" => Ok(DiscoveryStatus::Completed),
        "partial" => Ok(DiscoveryStatus::Partial),
        "failed" => Ok(DiscoveryStatus::Failed),
        "cancelled" => Ok(DiscoveryStatus::Cancelled),
        _ => Err(DiscoveryStoreError::InvalidStoredValue("run status is invalid")),
    }
}

fn parse_request_kind(value: &str) -> Result<RunRequestKind, DiscoveryStoreError> {
    match value {
        "manual" => Ok(RunRequestKind::Manual),
        "scheduled" => Ok(RunRequestKind::Scheduled),
        _ => Err(DiscoveryStoreError::InvalidStoredValue("request kind is invalid")),
    }
}

fn parse_execution_status(value: &str) -> Result<ExecutionStatus, DiscoveryStoreError> {
    match value {
        "succeeded" => Ok(ExecutionStatus::Succeeded),
        "failed" => Ok(ExecutionStatus::Failed),
        "partial" => Ok(ExecutionStatus::Partial),
        "unknown" => Ok(ExecutionStatus::Unknown),
        "cancelled" => Ok(ExecutionStatus::Cancelled),
        "unsupported" => Ok(ExecutionStatus::Unsupported),
        "not_applicable" => Ok(ExecutionStatus::NotApplicable),
        _ => Err(DiscoveryStoreError::InvalidStoredValue("execution status is invalid")),
    }
}

fn execution_status_str(value: &ExecutionStatus) -> &'static str {
    match value {
        ExecutionStatus::Succeeded => "succeeded",
        ExecutionStatus::Failed => "failed",
        ExecutionStatus::Partial => "partial",
        ExecutionStatus::Unknown => "unknown",
        ExecutionStatus::Cancelled => "cancelled",
        ExecutionStatus::Unsupported => "unsupported",
        ExecutionStatus::NotApplicable => "not_applicable",
    }
}

fn validate_seeds(seeds: &[IpAddr]) -> Result<(), DiscoveryStoreError> {
    if seeds.len() > 65_536 {
        return Err(DiscoveryStoreError::InvalidInput("too many seed targets"));
    }
    if seeds
        .iter()
        .any(|value| value.is_unspecified() || value.is_multicast())
    {
        return Err(DiscoveryStoreError::InvalidInput("seed target is invalid"));
    }
    Ok(())
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn map_scope_database_error(error: sqlx::Error) -> DiscoveryStoreError {
    if let sqlx::Error::Database(database) = &error {
        if database.is_unique_violation() {
            return DiscoveryStoreError::DuplicateScope;
        }
        if database.is_foreign_key_violation() {
            return DiscoveryStoreError::RoutingDomainNotFound;
        }
    }
    DiscoveryStoreError::Database(error)
}

#[allow(clippy::too_many_arguments)]
async fn write_mutation_records(
    tx: &mut Transaction<'_, Postgres>,
    context: &MutationContext,
    action: &str,
    event_type: &str,
    resource_type: &str,
    resource_id: Uuid,
    before: Option<Value>,
    after: Option<Value>,
) -> Result<(), DiscoveryStoreError> {
    AuditStore::append_in_tx(
        tx,
        AuditEventDraft {
            organization_id: context.organization_id,
            site_id: Some(context.site_id),
            actor_type: context.actor_type,
            actor_id: context.actor_id,
            session_id: context.session_id,
            source_ip: context.source_ip.clone(),
            request_id: context.request_id.clone(),
            correlation_id: context.correlation_id,
            action: action.to_owned(),
            resource_type: resource_type.to_owned(),
            resource_id: Some(resource_id.to_string()),
            provider: None,
            occurred_at_unix_ms: Utc::now().timestamp_millis(),
            duration_ms: None,
            status: AuditStatus::Succeeded,
            reason_code: None,
            before: before.clone(),
            after: after.clone(),
            result: Some(json!({"outcome":"committed"})),
        },
    )
    .await?;
    OutboxStore::enqueue(
        tx,
        &NewOutboxEvent {
            id: Uuid::now_v7(),
            organization_id: context.organization_id,
            aggregate_type: resource_type.to_owned(),
            aggregate_id: resource_id.to_string(),
            event_type: event_type.to_owned(),
            event_version: 1,
            payload: json!({
                "resourceId": resource_id,
                "siteId": context.site_id,
                "before": before,
                "after": after,
            }),
            correlation_id: context.correlation_id,
        },
    )
    .await?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum DiscoveryStoreError {
    #[error("discovery request is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("discovery scope not found")]
    ScopeNotFound,
    #[error("discovery run not found")]
    RunNotFound,
    #[error("discovery scope is disabled")]
    ScopeDisabled,
    #[error("discovery scope already has an active run")]
    ScopeHasActiveRun,
    #[error("discovery scope has run history and cannot be deleted")]
    ScopeHasHistory,
    #[error("discovery scope already exists in this routing domain")]
    DuplicateScope,
    #[error("routing domain does not exist in the requested scope")]
    RoutingDomainNotFound,
    #[error("seed target {0} is outside the discovery scope")]
    SeedOutsideScope(IpAddr),
    #[error("discovery run is not running")]
    RunNotRunning,
    #[error("probe result scope does not match its discovery run")]
    ProbeScopeMismatch,
    #[error("resource version conflict: expected {expected}, actual {actual}")]
    VersionConflict { expected: i64, actual: i64 },
    #[error("stored discovery value is invalid: {0}")]
    InvalidStoredValue(&'static str),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Audit(#[from] AuditStoreError),
    #[error(transparent)]
    Outbox(#[from] OutboxError),
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

    async fn scope_context(pool: &PgPool) -> (MutationContext, Uuid, Uuid) {
        let organization_id: Uuid = sqlx::query_scalar(
            "INSERT INTO organizations (slug, name) VALUES ($1, 'Discovery Test') RETURNING id",
        )
        .bind(format!("discovery-{}", Uuid::now_v7().simple()))
        .fetch_one(pool)
        .await
        .unwrap();
        let site_id: Uuid = sqlx::query_scalar(
            "INSERT INTO sites (organization_id, slug, name) VALUES ($1,$2,'Site') RETURNING id",
        )
        .bind(organization_id)
        .bind(format!("site-{}", Uuid::now_v7().simple()))
        .fetch_one(pool)
        .await
        .unwrap();
        let routing_domain_id: Uuid = sqlx::query_scalar(
            "INSERT INTO routing_domains (organization_id, site_id, name, is_default) VALUES ($1,$2,'default',true) RETURNING id",
        )
        .bind(organization_id)
        .bind(site_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let second_routing_domain: Uuid = sqlx::query_scalar(
            "INSERT INTO routing_domains (organization_id, site_id, name) VALUES ($1,$2,'vrf-two') RETURNING id",
        )
        .bind(organization_id)
        .bind(site_id)
        .fetch_one(pool)
        .await
        .unwrap();
        (
            MutationContext {
                organization_id,
                site_id,
                actor_type: AuditActorType::System,
                actor_id: None,
                session_id: None,
                source_ip: None,
                request_id: format!("test-{}", Uuid::now_v7()),
                correlation_id: Uuid::now_v7(),
            },
            routing_domain_id,
            second_routing_domain,
        )
    }

    fn input(routing_domain_id: Uuid) -> NewDiscoveryScope {
        NewDiscoveryScope {
            routing_domain_id,
            name: "LAN".into(),
            network: "10.0.0.0/30".parse().unwrap(),
            observations: vec![ObservationKind::Reachability, ObservationKind::Service],
            tcp_ports: vec![22, 443],
            ipv6_strategy: None,
            interface_scope: None,
            source_address: None,
            concurrency_limit: 4,
            rate_per_second: 100,
            timeout_ms: 1000,
            max_targets: 1024,
            schedule_interval_seconds: None,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn same_cidr_is_legal_in_different_routing_domains() {
        let Some(pool) = pool().await else { return };
        let (context, first, second) = scope_context(&pool).await;
        let store = DiscoveryStore::new(pool);
        let first_scope = store.create_scope(&context, input(first)).await.unwrap();
        let second_scope = store.create_scope(&context, input(second)).await.unwrap();
        assert_eq!(first_scope.network, second_scope.network);
        assert_ne!(first_scope.routing_domain_id, second_scope.routing_domain_id);
    }

    #[tokio::test]
    async fn queued_run_can_be_cancelled_without_becoming_running() {
        let Some(pool) = pool().await else { return };
        let (context, routing_domain_id, _) = scope_context(&pool).await;
        let store = DiscoveryStore::new(pool);
        let scope = store
            .create_scope(&context, input(routing_domain_id))
            .await
            .unwrap();
        let run = store
            .create_run(&context, scope.id, RunRequestKind::Manual, Vec::new())
            .await
            .unwrap();
        let cancelled = store.request_cancel(&context, run.id).await.unwrap();
        assert_eq!(cancelled.status, DiscoveryStatus::Cancelled);
        assert!(cancelled.finished_at.is_some());
    }
}
