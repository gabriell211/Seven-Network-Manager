use std::time::Duration;

use serde::Serialize;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseHealth {
    pub connected: bool,
    pub migration_count: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceSummary {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub site_id: Uuid,
    pub lifecycle_state: String,
    pub display_name: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub version: i64,
}

impl Database {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.clamp(1, 64))
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("../../migrations").run(&self.pool).await
    }

    pub async fn health(&self) -> Result<DatabaseHealth, sqlx::Error> {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await?;
        let migration_count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*)::bigint FROM _sqlx_migrations WHERE success = true",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);
        Ok(DatabaseHealth {
            connected: true,
            migration_count,
        })
    }

    pub async fn list_devices(
        &self,
        organization_id: Uuid,
        site_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DeviceSummary>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, organization_id, site_id, lifecycle_state, display_name,
                   vendor, model, serial_number, version
            FROM devices
            WHERE organization_id = $1
              AND ($2::uuid IS NULL OR site_id = $2)
            ORDER BY updated_at DESC, id
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(organization_id)
        .bind(site_id)
        .bind(limit.clamp(1, 250))
        .bind(offset.max(0))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(DeviceSummary {
                    id: row.try_get("id")?,
                    organization_id: row.try_get("organization_id")?,
                    site_id: row.try_get("site_id")?,
                    lifecycle_state: row.try_get("lifecycle_state")?,
                    display_name: row.try_get("display_name")?,
                    vendor: row.try_get("vendor")?,
                    model: row.try_get("model")?,
                    serial_number: row.try_get("serial_number")?,
                    version: row.try_get("version")?,
                })
            })
            .collect()
    }

    pub async fn bootstrap_scope(
        &self,
        organization_slug: &str,
        organization_name: &str,
        site_slug: &str,
        site_name: &str,
    ) -> Result<(Uuid, Uuid, Uuid), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let organization_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO organizations (slug, name)
            VALUES ($1, $2)
            ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name, updated_at = now()
            RETURNING id
            "#,
        )
        .bind(organization_slug)
        .bind(organization_name)
        .fetch_one(&mut *tx)
        .await?;

        let site_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO sites (organization_id, slug, name)
            VALUES ($1, $2, $3)
            ON CONFLICT (organization_id, slug)
            DO UPDATE SET name = EXCLUDED.name, updated_at = now()
            RETURNING id
            "#,
        )
        .bind(organization_id)
        .bind(site_slug)
        .bind(site_name)
        .fetch_one(&mut *tx)
        .await?;

        let routing_domain_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO routing_domains (organization_id, site_id, name, is_default)
            VALUES ($1, $2, 'default', true)
            ON CONFLICT (organization_id, site_id, name)
            DO UPDATE SET is_default = true, updated_at = now()
            RETURNING id
            "#,
        )
        .bind(organization_id)
        .bind(site_id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok((organization_id, site_id, routing_domain_id))
    }
}
