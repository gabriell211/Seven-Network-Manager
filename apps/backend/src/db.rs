use std::time::Duration;

use serde::Serialize;
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
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

impl Database {
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.clamp(1, 64))
            .acquire_timeout(Duration::from_secs(5))
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_database() -> Option<Database> {
        let url = std::env::var("DATABASE_URL").ok()?;
        let database = Database::connect(&url, 4).await.ok()?;
        database.migrate().await.ok()?;
        Some(database)
    }

    #[tokio::test]
    async fn clean_database_migrates_and_supports_scoped_inventory() {
        let Some(database) = test_database().await else {
            return;
        };
        let suffix = Uuid::now_v7().simple().to_string();
        let (organization_id, site_id, _) = database
            .bootstrap_scope(
                &format!("ci-{suffix}"),
                "CI Organization",
                "default",
                "CI Site",
            )
            .await
            .expect("bootstrap scope");

        sqlx::query(
            r#"
            INSERT INTO devices (
              organization_id, site_id, lifecycle_state, display_name, serial_number
            ) VALUES ($1, $2, 'pending_review', 'CI Device', $3)
            "#,
        )
        .bind(organization_id)
        .bind(site_id)
        .bind(format!("SERIAL-{suffix}"))
        .execute(&database.pool)
        .await
        .expect("insert device");

        let lifecycle_state: String = sqlx::query_scalar(
            r#"
            SELECT lifecycle_state
            FROM devices
            WHERE organization_id = $1 AND site_id = $2
            ORDER BY updated_at DESC, id
            LIMIT 1
            "#,
        )
        .bind(organization_id)
        .bind(site_id)
        .fetch_one(&database.pool)
        .await
        .expect("query scoped inventory");
        assert_eq!(lifecycle_state, "pending_review");
    }

    #[tokio::test]
    async fn database_allows_same_ip_in_different_routing_domains_only() {
        let Some(database) = test_database().await else {
            return;
        };
        let suffix = Uuid::now_v7().simple().to_string();
        let (organization_id, site_id, default_rd) = database
            .bootstrap_scope(&format!("vrf-{suffix}"), "VRF Test", "default", "VRF Site")
            .await
            .expect("bootstrap scope");

        let other_rd: Uuid = sqlx::query_scalar(
            "INSERT INTO routing_domains (organization_id, site_id, name) VALUES ($1, $2, 'blue') RETURNING id",
        )
        .bind(organization_id)
        .bind(site_id)
        .fetch_one(&database.pool)
        .await
        .expect("second routing domain");

        for routing_domain_id in [default_rd, other_rd] {
            sqlx::query(
                "INSERT INTO ip_addresses (organization_id, site_id, routing_domain_id, address, source) VALUES ($1, $2, $3, '10.0.0.1', 'ci')",
            )
            .bind(organization_id)
            .bind(site_id)
            .bind(routing_domain_id)
            .execute(&database.pool)
            .await
            .expect("overlap across routing domains must be valid");
        }

        let duplicate = sqlx::query(
            "INSERT INTO ip_addresses (organization_id, site_id, routing_domain_id, address, source) VALUES ($1, $2, $3, '10.0.0.1', 'ci')",
        )
        .bind(organization_id)
        .bind(site_id)
        .bind(default_rd)
        .execute(&database.pool)
        .await;
        assert!(duplicate.is_err());
    }
}
