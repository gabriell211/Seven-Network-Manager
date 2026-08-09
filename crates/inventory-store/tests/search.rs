use snm_domain::inventory::{DeviceLifecycle, DeviceType, IdentifierKind};
use snm_inventory_store::{
    InventoryQuery, InventoryStore, MutationContext, NewDevice, NewIdentifier,
};
use snm_security::audit::AuditActorType;
use sqlx::PgPool;
use uuid::Uuid;

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

async fn scope(pool: &PgPool) -> (Uuid, Uuid, Uuid) {
    let suffix = Uuid::now_v7().simple().to_string();
    let organization_id: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (slug, name) VALUES ($1, 'Search Test') RETURNING id",
    )
    .bind(format!("search-{suffix}"))
    .fetch_one(pool)
    .await
    .unwrap();
    let site_a: Uuid = sqlx::query_scalar(
        "INSERT INTO sites (organization_id, slug, name) VALUES ($1, 'a', 'Site A') RETURNING id",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let site_b: Uuid = sqlx::query_scalar(
        "INSERT INTO sites (organization_id, slug, name) VALUES ($1, 'b', 'Site B') RETURNING id",
    )
    .bind(organization_id)
    .fetch_one(pool)
    .await
    .unwrap();
    (organization_id, site_a, site_b)
}

fn context(organization_id: Uuid, site_id: Uuid) -> MutationContext {
    MutationContext {
        organization_id,
        site_id,
        actor_type: AuditActorType::System,
        actor_id: None,
        session_id: None,
        source_ip: Some("127.0.0.1".into()),
        request_id: Uuid::now_v7().to_string(),
        correlation_id: Uuid::now_v7(),
    }
}

fn device(serial: &str, hostname: &str, device_type: DeviceType) -> NewDevice {
    NewDevice {
        device_type,
        display_name: Some(format!("Device {serial}")),
        hostname: Some(hostname.into()),
        vendor: Some("Seven Lab".into()),
        model: Some("Fixture".into()),
        os_name: None,
        os_version: None,
        firmware_version: None,
        description: None,
        operational_owner: Some("network".into()),
        capabilities: vec!["inventory.read".into()],
        identifiers: vec![NewIdentifier {
            kind: IdentifierKind::Serial,
            value: serial.into(),
            source: "manual".into(),
            confidence: Some(1.0),
        }],
    }
}

fn query(search: Option<&str>) -> InventoryQuery {
    InventoryQuery {
        search: search.map(ToOwned::to_owned),
        lifecycle: None,
        device_type: None,
        limit: 50,
        offset: 0,
    }
}

#[tokio::test]
async fn search_finds_hostname_and_normalized_serial_without_leaking_other_sites() {
    let Some(pool) = pool().await else { return };
    let (organization_id, site_a, site_b) = scope(&pool).await;
    let store = InventoryStore::new(pool);

    let a = store
        .create_manual(
            &context(organization_id, site_a),
            device("SER-ABC-001", "core-a.example", DeviceType::Switch),
            false,
        )
        .await
        .unwrap();
    store
        .create_manual(
            &context(organization_id, site_b),
            device("SER-ABC-002", "core-b.example", DeviceType::Router),
            false,
        )
        .await
        .unwrap();

    let hostname = store
        .list(organization_id, site_a, query(Some("CORE-A")))
        .await
        .unwrap();
    assert_eq!(hostname.len(), 1);
    assert_eq!(hostname[0].id, a.id);

    let serial = store
        .list(organization_id, site_a, query(Some("serabc001")))
        .await
        .unwrap();
    assert_eq!(serial.len(), 1);
    assert_eq!(serial[0].id, a.id);

    let other_site = store
        .list(organization_id, site_a, query(Some("SER-ABC-002")))
        .await
        .unwrap();
    assert!(other_site.is_empty());
}

#[tokio::test]
async fn search_finds_ip_address_but_keeps_routing_data_site_scoped() {
    let Some(pool) = pool().await else { return };
    let (organization_id, site_a, site_b) = scope(&pool).await;
    let store = InventoryStore::new(pool.clone());

    let a = store
        .create_manual(
            &context(organization_id, site_a),
            device("IP-A", "ip-a.example", DeviceType::Server),
            false,
        )
        .await
        .unwrap();
    let b = store
        .create_manual(
            &context(organization_id, site_b),
            device("IP-B", "ip-b.example", DeviceType::Server),
            false,
        )
        .await
        .unwrap();

    let routing_a: Uuid = sqlx::query_scalar(
        "INSERT INTO routing_domains (organization_id, site_id, name, is_default) VALUES ($1,$2,'default',true) RETURNING id",
    )
    .bind(organization_id)
    .bind(site_a)
    .fetch_one(&pool)
    .await
    .unwrap();
    let routing_b: Uuid = sqlx::query_scalar(
        "INSERT INTO routing_domains (organization_id, site_id, name, is_default) VALUES ($1,$2,'default',true) RETURNING id",
    )
    .bind(organization_id)
    .bind(site_b)
    .fetch_one(&pool)
    .await
    .unwrap();
    let interface_a: Uuid = sqlx::query_scalar(
        "INSERT INTO interfaces (organization_id, site_id, device_id, name) VALUES ($1,$2,$3,'eth0') RETURNING id",
    )
    .bind(organization_id)
    .bind(site_a)
    .bind(a.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let interface_b: Uuid = sqlx::query_scalar(
        "INSERT INTO interfaces (organization_id, site_id, device_id, name) VALUES ($1,$2,$3,'eth0') RETURNING id",
    )
    .bind(organization_id)
    .bind(site_b)
    .bind(b.id)
    .fetch_one(&pool)
    .await
    .unwrap();

    for (site_id, routing_domain_id, interface_id) in [
        (site_a, routing_a, interface_a),
        (site_b, routing_b, interface_b),
    ] {
        sqlx::query(
            r#"
            INSERT INTO ip_addresses (
              organization_id, site_id, routing_domain_id, interface_id, address, source
            ) VALUES ($1,$2,$3,$4,'10.20.30.40','manual')
            "#,
        )
        .bind(organization_id)
        .bind(site_id)
        .bind(routing_domain_id)
        .bind(interface_id)
        .execute(&pool)
        .await
        .unwrap();
    }

    let result = store
        .list(organization_id, site_a, query(Some("10.20.30.40")))
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].id, a.id);
}

#[tokio::test]
async fn list_filters_type_and_lifecycle_together() {
    let Some(pool) = pool().await else { return };
    let (organization_id, site_a, _site_b) = scope(&pool).await;
    let store = InventoryStore::new(pool);

    let switch = store
        .create_manual(
            &context(organization_id, site_a),
            device("FILTER-SW", "filter-sw.example", DeviceType::Switch),
            false,
        )
        .await
        .unwrap();
    store
        .create_manual(
            &context(organization_id, site_a),
            device("FILTER-RTR", "filter-rtr.example", DeviceType::Router),
            false,
        )
        .await
        .unwrap();

    let result = store
        .list(
            organization_id,
            site_a,
            InventoryQuery {
                search: None,
                lifecycle: Some(DeviceLifecycle::Managed),
                device_type: Some(DeviceType::Switch),
                limit: 50,
                offset: 0,
            },
        )
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].id, switch.id);
}
