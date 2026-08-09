use std::{error::Error, fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct NewOutboxEvent {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub event_type: String,
    pub event_version: i32,
    pub payload: Value,
    pub correlation_id: Uuid,
}

impl NewOutboxEvent {
    pub fn validate(&self) -> Result<(), OutboxError> {
        if self.aggregate_type.trim().is_empty()
            || self.aggregate_id.trim().is_empty()
            || self.event_type.trim().is_empty()
            || self.event_version <= 0
        {
            return Err(OutboxError::InvalidEvent);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct OutboxEvent {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub event_type: String,
    pub event_version: i32,
    pub payload: Value,
    pub correlation_id: Uuid,
    pub attempts: i32,
}

#[derive(Clone)]
pub struct OutboxStore {
    pool: PgPool,
}

impl OutboxStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Must execute inside the same PostgreSQL transaction as the mutation
    /// that produced the event. This is the core outbox consistency invariant.
    pub async fn enqueue(
        tx: &mut Transaction<'_, Postgres>,
        event: &NewOutboxEvent,
    ) -> Result<(), OutboxError> {
        event.validate()?;
        sqlx::query(
            r#"
            INSERT INTO outbox_events (
              id, organization_id, aggregate_type, aggregate_id, event_type,
              event_version, payload, correlation_id
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
            "#,
        )
        .bind(event.id)
        .bind(event.organization_id)
        .bind(&event.aggregate_type)
        .bind(&event.aggregate_id)
        .bind(&event.event_type)
        .bind(event.event_version)
        .bind(&event.payload)
        .bind(event.correlation_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    pub async fn claim(
        &self,
        worker_id: &str,
        batch_size: i64,
        lease: Duration,
    ) -> Result<Vec<OutboxEvent>, OutboxError> {
        if worker_id.trim().is_empty() || batch_size <= 0 {
            return Err(OutboxError::InvalidClaim);
        }
        let lease_seconds =
            i32::try_from(lease.as_secs().clamp(1, 300)).map_err(|_| OutboxError::InvalidClaim)?;
        let rows = sqlx::query(
            r#"
            WITH picked AS (
              SELECT id
              FROM outbox_events
              WHERE status IN ('pending', 'failed')
                AND available_at <= now()
                AND (lease_expires_at IS NULL OR lease_expires_at < now())
              ORDER BY available_at, occurred_at, id
              FOR UPDATE SKIP LOCKED
              LIMIT $1
            )
            UPDATE outbox_events AS event
            SET lease_owner = $2,
                lease_expires_at = now() + make_interval(secs => $3),
                attempts = event.attempts + 1,
                status = 'pending'
            FROM picked
            WHERE event.id = picked.id
            RETURNING event.id, event.organization_id, event.aggregate_type,
                      event.aggregate_id, event.event_type, event.event_version,
                      event.payload, event.correlation_id, event.attempts
            "#,
        )
        .bind(batch_size.clamp(1, 250))
        .bind(worker_id)
        .bind(lease_seconds)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(row_to_event).collect()
    }

    pub async fn mark_published(
        &self,
        worker_id: &str,
        event: &OutboxEvent,
    ) -> Result<(), OutboxError> {
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            r#"
            UPDATE outbox_events
            SET status = 'published', published_at = now(), lease_owner = NULL,
                lease_expires_at = NULL, last_error_code = NULL, last_error_at = NULL
            WHERE id = $1 AND lease_owner = $2 AND status = 'pending'
            "#,
        )
        .bind(event.id)
        .bind(worker_id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(OutboxError::LeaseLost);
        }
        sqlx::query(
            r#"
            INSERT INTO outbox_delivery_attempts (event_id, attempt, worker_id, outcome)
            VALUES ($1, $2, $3, 'published')
            "#,
        )
        .bind(event.id)
        .bind(event.attempts)
        .bind(worker_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn mark_failed(
        &self,
        worker_id: &str,
        event: &OutboxEvent,
        error_code: &str,
        max_attempts: i32,
        retry_after: Duration,
    ) -> Result<DeliveryDisposition, OutboxError> {
        if error_code.trim().is_empty() || max_attempts <= 0 {
            return Err(OutboxError::InvalidFailure);
        }
        let retry_seconds = i32::try_from(retry_after.as_secs().clamp(1, 3600))
            .map_err(|_| OutboxError::InvalidFailure)?;
        let dead_letter = event.attempts >= max_attempts;
        let mut tx = self.pool.begin().await?;

        let updated = if dead_letter {
            sqlx::query(
                r#"
                UPDATE outbox_events
                SET status = 'dead_letter', dead_lettered_at = now(),
                    lease_owner = NULL, lease_expires_at = NULL,
                    last_error_code = $3, last_error_at = now()
                WHERE id = $1 AND lease_owner = $2
                "#,
            )
            .bind(event.id)
            .bind(worker_id)
            .bind(error_code)
            .execute(&mut *tx)
            .await?
        } else {
            sqlx::query(
                r#"
                UPDATE outbox_events
                SET status = 'failed', available_at = now() + make_interval(secs => $4),
                    lease_owner = NULL, lease_expires_at = NULL,
                    last_error_code = $3, last_error_at = now()
                WHERE id = $1 AND lease_owner = $2
                "#,
            )
            .bind(event.id)
            .bind(worker_id)
            .bind(error_code)
            .bind(retry_seconds)
            .execute(&mut *tx)
            .await?
        };
        if updated.rows_affected() != 1 {
            return Err(OutboxError::LeaseLost);
        }

        let outcome = if dead_letter { "dead_letter" } else { "retry" };
        sqlx::query(
            r#"
            INSERT INTO outbox_delivery_attempts (event_id, attempt, worker_id, outcome, error_code)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(event.id)
        .bind(event.attempts)
        .bind(worker_id)
        .bind(outcome)
        .bind(error_code)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(if dead_letter {
            DeliveryDisposition::DeadLetter
        } else {
            DeliveryDisposition::Retry
        })
    }

    /// Returns true only for the first successful consumption of this event by
    /// the named consumer. Redelivery is expected; consumers stay idempotent.
    pub async fn record_consumption(
        &self,
        consumer: &str,
        event_id: Uuid,
    ) -> Result<bool, OutboxError> {
        if consumer.trim().is_empty() {
            return Err(OutboxError::InvalidConsumer);
        }
        let inserted = sqlx::query(
            r#"
            INSERT INTO event_consumptions (consumer, event_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(consumer)
        .bind(event_id)
        .execute(&self.pool)
        .await?;
        Ok(inserted.rows_affected() == 1)
    }

    pub async fn backlog(&self) -> Result<i64, OutboxError> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT count(*)::bigint FROM outbox_events WHERE status IN ('pending','failed')",
        )
        .fetch_one(&self.pool)
        .await?)
    }
}

fn row_to_event(row: sqlx::postgres::PgRow) -> Result<OutboxEvent, OutboxError> {
    Ok(OutboxEvent {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        aggregate_type: row.try_get("aggregate_type")?,
        aggregate_id: row.try_get("aggregate_id")?,
        event_type: row.try_get("event_type")?,
        event_version: row.try_get("event_version")?,
        payload: row.try_get("payload")?,
        correlation_id: row.try_get("correlation_id")?,
        attempts: row.try_get("attempts")?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryDisposition {
    Retry,
    DeadLetter,
}

#[async_trait]
pub trait EventPublisher: Send + Sync {
    async fn publish(&self, event: &OutboxEvent) -> Result<(), PublishError>;
}

#[derive(Debug)]
pub struct PublishError {
    pub code: String,
}

impl fmt::Display for PublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "event publication failed: {}", self.code)
    }
}

impl Error for PublishError {}

pub struct OutboxDispatcher<P> {
    store: OutboxStore,
    publisher: Arc<P>,
    worker_id: String,
    max_attempts: i32,
    lease: Duration,
    concurrency: Arc<Semaphore>,
}

impl<P> OutboxDispatcher<P>
where
    P: EventPublisher + 'static,
{
    pub fn new(
        store: OutboxStore,
        publisher: Arc<P>,
        worker_id: impl Into<String>,
        max_attempts: i32,
        concurrency: usize,
    ) -> Result<Self, OutboxError> {
        let worker_id = worker_id.into();
        if worker_id.trim().is_empty() || max_attempts <= 0 || concurrency == 0 {
            return Err(OutboxError::InvalidDispatcher);
        }
        Ok(Self {
            store,
            publisher,
            worker_id,
            max_attempts,
            lease: Duration::from_secs(30),
            concurrency: Arc::new(Semaphore::new(concurrency.min(64))),
        })
    }

    pub async fn dispatch_once(&self, batch_size: i64) -> Result<usize, OutboxError> {
        let events = self
            .store
            .claim(&self.worker_id, batch_size, self.lease)
            .await?;
        let count = events.len();
        let mut handles = Vec::with_capacity(count);
        for event in events {
            let permit = self
                .concurrency
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| OutboxError::DispatcherClosed)?;
            let store = self.store.clone();
            let publisher = self.publisher.clone();
            let worker_id = self.worker_id.clone();
            let max_attempts = self.max_attempts;
            handles.push(tokio::spawn(async move {
                let _permit = permit;
                match publisher.publish(&event).await {
                    Ok(()) => {
                        store.mark_published(&worker_id, &event).await?;
                        info!(event_id = %event.id, attempt = event.attempts, "outbox event published");
                    }
                    Err(publish_error) => {
                        let retry = Duration::from_secs(retry_delay_seconds(event.attempts));
                        let disposition = store
                            .mark_failed(
                                &worker_id,
                                &event,
                                &publish_error.code,
                                max_attempts,
                                retry,
                            )
                            .await?;
                        match disposition {
                            DeliveryDisposition::Retry => warn!(event_id = %event.id, attempt = event.attempts, error_code = %publish_error.code, "outbox event scheduled for retry"),
                            DeliveryDisposition::DeadLetter => error!(event_id = %event.id, attempt = event.attempts, error_code = %publish_error.code, "outbox event dead-lettered"),
                        }
                    }
                }
                Ok::<(), OutboxError>(())
            }));
        }
        for handle in handles {
            handle
                .await
                .map_err(|_| OutboxError::DispatcherTaskFailed)??;
        }
        Ok(count)
    }
}

fn retry_delay_seconds(attempt: i32) -> u64 {
    let exponent = u32::try_from(attempt.saturating_sub(1).clamp(0, 6)).unwrap_or(0);
    2_u64.saturating_pow(exponent).clamp(1, 60)
}

#[derive(Debug)]
pub enum OutboxError {
    InvalidEvent,
    InvalidClaim,
    InvalidFailure,
    InvalidConsumer,
    InvalidDispatcher,
    LeaseLost,
    DispatcherClosed,
    DispatcherTaskFailed,
    Database(sqlx::Error),
}

impl fmt::Display for OutboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEvent => "outbox event is invalid",
            Self::InvalidClaim => "outbox claim is invalid",
            Self::InvalidFailure => "outbox delivery failure parameters are invalid",
            Self::InvalidConsumer => "outbox consumer identifier is invalid",
            Self::InvalidDispatcher => "outbox dispatcher configuration is invalid",
            Self::LeaseLost => "outbox lease was lost",
            Self::DispatcherClosed => "outbox dispatcher has been closed",
            Self::DispatcherTaskFailed => "outbox dispatcher task failed",
            Self::Database(_) => "outbox database operation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for OutboxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<sqlx::Error> for OutboxError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;

    use super::*;

    struct CountingPublisher {
        calls: AtomicUsize,
        fail_first: bool,
    }

    #[async_trait]
    impl EventPublisher for CountingPublisher {
        async fn publish(&self, _event: &OutboxEvent) -> Result<(), PublishError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_first && call == 0 {
                Err(PublishError {
                    code: "fixture_failure".into(),
                })
            } else {
                Ok(())
            }
        }
    }

    async fn pool() -> Option<PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .ok()?;
        sqlx::migrate!("../../migrations").run(&pool).await.ok()?;
        Some(pool)
    }

    async fn organization(pool: &PgPool) -> Uuid {
        let suffix = Uuid::now_v7().simple().to_string();
        sqlx::query_scalar(
            "INSERT INTO organizations (slug, name) VALUES ($1, 'Outbox Test') RETURNING id",
        )
        .bind(format!("outbox-{suffix}"))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn committed_event(pool: &PgPool, organization_id: Uuid) -> NewOutboxEvent {
        let event = NewOutboxEvent {
            id: Uuid::now_v7(),
            organization_id,
            aggregate_type: "device".into(),
            aggregate_id: Uuid::now_v7().to_string(),
            event_type: "device.created".into(),
            event_version: 1,
            payload: json!({"displayName":"fixture"}),
            correlation_id: Uuid::now_v7(),
        };
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("INSERT INTO system_settings (key, value) VALUES ($1, $2)")
            .bind(format!("mutation/{}", event.id))
            .bind(json!({"committed":true}))
            .execute(&mut *tx)
            .await
            .unwrap();
        OutboxStore::enqueue(&mut tx, &event).await.unwrap();
        tx.commit().await.unwrap();
        event
    }

    #[tokio::test]
    async fn event_survives_commit_before_publication_and_is_claimed_once() {
        let Some(pool) = pool().await else { return };
        let organization_id = organization(&pool).await;
        let event = committed_event(&pool, organization_id).await;
        let store = OutboxStore::new(pool);

        let first = store
            .claim("worker-a", 10, Duration::from_secs(30))
            .await
            .unwrap();
        assert!(first.iter().any(|item| item.id == event.id));
        let second = store
            .claim("worker-b", 10, Duration::from_secs(30))
            .await
            .unwrap();
        assert!(!second.iter().any(|item| item.id == event.id));
    }

    #[tokio::test]
    async fn consumer_deduplication_is_idempotent() {
        let Some(pool) = pool().await else { return };
        let store = OutboxStore::new(pool);
        let event_id = Uuid::now_v7();
        assert!(
            store
                .record_consumption("fixture-consumer", event_id)
                .await
                .unwrap()
        );
        assert!(
            !store
                .record_consumption("fixture-consumer", event_id)
                .await
                .unwrap()
        );
        assert!(
            store
                .record_consumption("another-consumer", event_id)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn failed_publication_is_retried_without_false_success() {
        let Some(pool) = pool().await else { return };
        let organization_id = organization(&pool).await;
        let event = committed_event(&pool, organization_id).await;
        let store = OutboxStore::new(pool.clone());
        let publisher = Arc::new(CountingPublisher {
            calls: AtomicUsize::new(0),
            fail_first: true,
        });
        let dispatcher = OutboxDispatcher::new(store, publisher, "worker-retry", 3, 2).unwrap();
        dispatcher.dispatch_once(10).await.unwrap();

        let row = sqlx::query(
            "SELECT status, (published_at IS NOT NULL) AS published FROM outbox_events WHERE id = $1",
        )
        .bind(event.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let status: String = row.try_get("status").unwrap();
        let published: bool = row.try_get("published").unwrap();
        assert_eq!(status, "failed");
        assert!(!published);
    }
}
