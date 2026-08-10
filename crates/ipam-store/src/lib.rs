use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use snm_audit_store::{AuditStore, AuditStoreError};
use snm_domain::ipam::{AddressState, is_ipv6_link_local};
use snm_platform_events::{NewOutboxEvent, OutboxError, OutboxStore};
use snm_security::audit::{AuditActorType, AuditEventDraft, AuditStatus};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone)]
pub struct IpamStore {
    pool: PgPool,
}

impl IpamStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_prefixes(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        routing_domain_id: Option<Uuid>,
    ) -> Result<Vec<IpPrefixView>, IpamError> {
        let rows = sqlx::query(
            r#"
            SELECT p.id, p.organization_id, p.site_id, p.routing_domain_id,
                   p.prefix::text AS prefix, p.name, host(p.gateway) AS gateway,
                   p.vlan_id, p.description, p.purpose, p.version,
                   p.created_at, p.updated_at,
                   (SELECT count(*) FROM ip_addresses a WHERE a.prefix_id = p.id) AS allocation_count
            FROM ip_prefixes p
            WHERE p.organization_id = $1 AND p.site_id = $2
              AND ($3::uuid IS NULL OR p.routing_domain_id = $3)
            ORDER BY family(p.prefix), p.prefix, p.name NULLS LAST, p.id
            "#,
        )
        .bind(organization_id)
        .bind(site_id)
        .bind(routing_domain_id)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_prefix).collect()
    }

    pub async fn get_prefix(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        prefix_id: Uuid,
    ) -> Result<Option<IpPrefixView>, IpamError> {
        let row = sqlx::query(
            r#"
            SELECT p.id, p.organization_id, p.site_id, p.routing_domain_id,
                   p.prefix::text AS prefix, p.name, host(p.gateway) AS gateway,
                   p.vlan_id, p.description, p.purpose, p.version,
                   p.created_at, p.updated_at,
                   (SELECT count(*) FROM ip_addresses a WHERE a.prefix_id = p.id) AS allocation_count
            FROM ip_prefixes p
            WHERE p.id = $1 AND p.organization_id = $2 AND p.site_id = $3
            "#,
        )
        .bind(prefix_id)
        .bind(organization_id)
        .bind(site_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(row_to_prefix).transpose()
    }

    pub async fn create_prefix(
        &self,
        context: &MutationContext,
        input: NewIpPrefix,
    ) -> Result<IpPrefixView, IpamError> {
        context.validate()?;
        let normalized = validate_prefix_input(&input)?;
        let mut tx = self.pool.begin().await?;
        let id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO ip_prefixes (
              id, organization_id, site_id, routing_domain_id, prefix, name,
              gateway, vlan_id, description, purpose
            ) VALUES ($1,$2,$3,$4,$5::cidr,$6,$7::inet,$8,$9,$10)
            "#,
        )
        .bind(id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(input.routing_domain_id)
        .bind(normalized.prefix.to_string())
        .bind(clean_optional(input.name))
        .bind(normalized.gateway.map(|value| value.to_string()))
        .bind(input.vlan_id)
        .bind(clean_optional(input.description))
        .bind(clean_optional(input.purpose))
        .execute(&mut *tx)
        .await?;

        let created =
            load_prefix_in_tx(&mut tx, context.organization_id, context.site_id, id, false)
                .await?
                .ok_or(IpamError::PrefixNotFound)?;
        let after = serde_json::to_value(&created)?;
        write_mutation_records(
            &mut tx,
            context,
            "ipam.prefix.create",
            "ipam.prefix.created",
            "ip_prefix",
            id,
            None,
            Some(after),
        )
        .await?;
        tx.commit().await?;
        Ok(created)
    }

    pub async fn update_prefix(
        &self,
        context: &MutationContext,
        prefix_id: Uuid,
        input: UpdateIpPrefix,
    ) -> Result<IpPrefixView, IpamError> {
        context.validate()?;
        let normalized = validate_prefix_update(&input)?;
        let mut tx = self.pool.begin().await?;
        let current = load_prefix_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            prefix_id,
            true,
        )
        .await?
        .ok_or(IpamError::PrefixNotFound)?;
        if current.version != input.expected_version {
            return Err(IpamError::VersionConflict {
                expected: input.expected_version,
                actual: current.version,
            });
        }
        let before = serde_json::to_value(&current)?;
        sqlx::query(
            r#"
            UPDATE ip_prefixes
            SET routing_domain_id = $4, prefix = $5::cidr, name = $6,
                gateway = $7::inet, vlan_id = $8, description = $9,
                purpose = $10, version = version + 1, updated_at = now()
            WHERE id = $1 AND organization_id = $2 AND site_id = $3
            "#,
        )
        .bind(prefix_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(input.routing_domain_id)
        .bind(normalized.prefix.to_string())
        .bind(clean_optional(input.name))
        .bind(normalized.gateway.map(|value| value.to_string()))
        .bind(input.vlan_id)
        .bind(clean_optional(input.description))
        .bind(clean_optional(input.purpose))
        .execute(&mut *tx)
        .await?;

        let updated = load_prefix_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            prefix_id,
            false,
        )
        .await?
        .ok_or(IpamError::PrefixNotFound)?;
        let after = serde_json::to_value(&updated)?;
        write_mutation_records(
            &mut tx,
            context,
            "ipam.prefix.update",
            "ipam.prefix.updated",
            "ip_prefix",
            prefix_id,
            Some(before),
            Some(after),
        )
        .await?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn delete_prefix(
        &self,
        context: &MutationContext,
        prefix_id: Uuid,
        expected_version: i64,
    ) -> Result<(), IpamError> {
        context.validate()?;
        let mut tx = self.pool.begin().await?;
        let current = load_prefix_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            prefix_id,
            true,
        )
        .await?
        .ok_or(IpamError::PrefixNotFound)?;
        if current.version != expected_version {
            return Err(IpamError::VersionConflict {
                expected: expected_version,
                actual: current.version,
            });
        }
        let before = serde_json::to_value(&current)?;
        let deleted = sqlx::query(
            "DELETE FROM ip_prefixes WHERE id = $1 AND organization_id = $2 AND site_id = $3",
        )
        .bind(prefix_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .execute(&mut *tx)
        .await?;
        if deleted.rows_affected() != 1 {
            return Err(IpamError::PrefixNotFound);
        }
        write_mutation_records(
            &mut tx,
            context,
            "ipam.prefix.delete",
            "ipam.prefix.deleted",
            "ip_prefix",
            prefix_id,
            Some(before),
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_addresses(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        query: AddressQuery,
    ) -> Result<Vec<IpAddressView>, IpamError> {
        query.validate()?;
        let mut builder = QueryBuilder::<Postgres>::new(
            r#"
            SELECT a.id, a.organization_id, a.site_id, a.routing_domain_id,
                   a.prefix_id, a.device_id, a.interface_id, host(a.address) AS address,
                   a.dns_name, a.allocation_state, a.source, a.description,
                   a.version, a.created_at, a.updated_at
            FROM ip_addresses a
            WHERE a.organization_id =
            "#,
        );
        builder.push_bind(organization_id);
        builder.push(" AND a.site_id = ");
        builder.push_bind(site_id);
        if let Some(routing_domain_id) = query.routing_domain_id {
            builder.push(" AND a.routing_domain_id = ");
            builder.push_bind(routing_domain_id);
        }
        if let Some(prefix_id) = query.prefix_id {
            builder.push(" AND a.prefix_id = ");
            builder.push_bind(prefix_id);
        }
        if let Some(state) = query.state {
            builder.push(" AND a.allocation_state = ");
            builder.push_bind(state.as_str());
        }
        if let Some(search) = query
            .search
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let contains = format!("%{}%", search.to_ascii_lowercase());
            builder.push(" AND (lower(host(a.address)) LIKE ");
            builder.push_bind(contains.clone());
            builder.push(" OR lower(coalesce(a.dns_name, '')) LIKE ");
            builder.push_bind(contains);
            builder.push(")");
        }
        builder.push(" ORDER BY family(a.address), a.address, a.id LIMIT ");
        builder.push_bind(query.limit);
        builder.push(" OFFSET ");
        builder.push_bind(query.offset);
        let rows = builder.build().fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_address).collect()
    }

    pub async fn create_address(
        &self,
        context: &MutationContext,
        input: NewIpAddress,
    ) -> Result<IpAddressView, IpamError> {
        context.validate()?;
        let address = validate_address_input(&input)?;
        let mut tx = self.pool.begin().await?;
        let id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO ip_addresses (
              id, organization_id, site_id, routing_domain_id, prefix_id,
              device_id, interface_id, address, dns_name, allocation_state,
              source, description
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::inet,$9,$10,$11,$12)
            "#,
        )
        .bind(id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(input.routing_domain_id)
        .bind(input.prefix_id)
        .bind(input.device_id)
        .bind(input.interface_id)
        .bind(address.to_string())
        .bind(clean_optional(input.dns_name))
        .bind(input.state.as_str())
        .bind(input.source.trim())
        .bind(clean_optional(input.description))
        .execute(&mut *tx)
        .await?;
        let created =
            load_address_in_tx(&mut tx, context.organization_id, context.site_id, id, false)
                .await?
                .ok_or(IpamError::AddressNotFound)?;
        let after = serde_json::to_value(&created)?;
        write_mutation_records(
            &mut tx,
            context,
            "ipam.address.create",
            "ipam.address.created",
            "ip_address",
            id,
            None,
            Some(after),
        )
        .await?;
        tx.commit().await?;
        Ok(created)
    }

    pub async fn update_address(
        &self,
        context: &MutationContext,
        address_id: Uuid,
        input: UpdateIpAddress,
    ) -> Result<IpAddressView, IpamError> {
        context.validate()?;
        validate_address_update(&input)?;
        let mut tx = self.pool.begin().await?;
        let current = load_address_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            address_id,
            true,
        )
        .await?
        .ok_or(IpamError::AddressNotFound)?;
        if current.version != input.expected_version {
            return Err(IpamError::VersionConflict {
                expected: input.expected_version,
                actual: current.version,
            });
        }
        if is_ipv6_link_local(current.address.parse().map_err(|_| {
            IpamError::InvalidStoredValue("stored IP address cannot be parsed".to_owned())
        })?) && input.interface_id.is_none()
        {
            return Err(IpamError::InvalidInput(
                "IPv6 link-local allocation requires interface scope".to_owned(),
            ));
        }
        let before = serde_json::to_value(&current)?;
        sqlx::query(
            r#"
            UPDATE ip_addresses
            SET device_id = $4, interface_id = $5, dns_name = $6,
                allocation_state = $7, source = $8, description = $9,
                version = version + 1, updated_at = now()
            WHERE id = $1 AND organization_id = $2 AND site_id = $3
            "#,
        )
        .bind(address_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(input.device_id)
        .bind(input.interface_id)
        .bind(clean_optional(input.dns_name))
        .bind(input.state.as_str())
        .bind(input.source.trim())
        .bind(clean_optional(input.description))
        .execute(&mut *tx)
        .await?;
        let updated = load_address_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            address_id,
            false,
        )
        .await?
        .ok_or(IpamError::AddressNotFound)?;
        let after = serde_json::to_value(&updated)?;
        write_mutation_records(
            &mut tx,
            context,
            "ipam.address.update",
            "ipam.address.updated",
            "ip_address",
            address_id,
            Some(before),
            Some(after),
        )
        .await?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn delete_address(
        &self,
        context: &MutationContext,
        address_id: Uuid,
        expected_version: i64,
    ) -> Result<(), IpamError> {
        context.validate()?;
        let mut tx = self.pool.begin().await?;
        let current = load_address_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            address_id,
            true,
        )
        .await?
        .ok_or(IpamError::AddressNotFound)?;
        if current.version != expected_version {
            return Err(IpamError::VersionConflict {
                expected: expected_version,
                actual: current.version,
            });
        }
        let before = serde_json::to_value(&current)?;
        let deleted = sqlx::query(
            "DELETE FROM ip_addresses WHERE id = $1 AND organization_id = $2 AND site_id = $3",
        )
        .bind(address_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .execute(&mut *tx)
        .await?;
        if deleted.rows_affected() != 1 {
            return Err(IpamError::AddressNotFound);
        }
        write_mutation_records(
            &mut tx,
            context,
            "ipam.address.delete",
            "ipam.address.deleted",
            "ip_address",
            address_id,
            Some(before),
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

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
    fn validate(&self) -> Result<(), IpamError> {
        if self.request_id.trim().is_empty() || self.request_id.len() > 200 {
            return Err(IpamError::InvalidInput("invalid request id".to_owned()));
        }
        if self
            .source_ip
            .as_deref()
            .is_some_and(|value| value.parse::<IpAddr>().is_err())
        {
            return Err(IpamError::InvalidInput("invalid source IP".to_owned()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixCapacity {
    pub total_addresses: String,
    pub allocated_addresses: i64,
    pub utilization_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpPrefixView {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub site_id: Uuid,
    pub routing_domain_id: Uuid,
    pub prefix: String,
    pub name: Option<String>,
    pub gateway: Option<String>,
    pub vlan_id: Option<i32>,
    pub description: Option<String>,
    pub purpose: Option<String>,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub capacity: PrefixCapacity,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewIpPrefix {
    pub routing_domain_id: Uuid,
    pub prefix: String,
    pub name: Option<String>,
    pub gateway: Option<String>,
    pub vlan_id: Option<i32>,
    pub description: Option<String>,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateIpPrefix {
    pub expected_version: i64,
    pub routing_domain_id: Uuid,
    pub prefix: String,
    pub name: Option<String>,
    pub gateway: Option<String>,
    pub vlan_id: Option<i32>,
    pub description: Option<String>,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone)]
struct ValidatedPrefix {
    prefix: IpNet,
    gateway: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpAddressView {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub site_id: Uuid,
    pub routing_domain_id: Uuid,
    pub prefix_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub interface_id: Option<Uuid>,
    pub address: String,
    pub dns_name: Option<String>,
    pub state: AddressState,
    pub source: String,
    pub description: Option<String>,
    pub version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewIpAddress {
    pub routing_domain_id: Uuid,
    pub prefix_id: Uuid,
    pub device_id: Option<Uuid>,
    pub interface_id: Option<Uuid>,
    pub address: String,
    pub dns_name: Option<String>,
    pub state: AddressState,
    pub source: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateIpAddress {
    pub expected_version: i64,
    pub device_id: Option<Uuid>,
    pub interface_id: Option<Uuid>,
    pub dns_name: Option<String>,
    pub state: AddressState,
    pub source: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AddressQuery {
    pub routing_domain_id: Option<Uuid>,
    pub prefix_id: Option<Uuid>,
    pub state: Option<AddressState>,
    pub search: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

impl AddressQuery {
    fn validate(&self) -> Result<(), IpamError> {
        if !(1..=200).contains(&self.limit) || self.offset < 0 {
            return Err(IpamError::InvalidInput(
                "address pagination is outside supported bounds".to_owned(),
            ));
        }
        if self.search.as_ref().is_some_and(|value| value.len() > 255) {
            return Err(IpamError::InvalidInput(
                "address search is too long".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_prefix_input(input: &NewIpPrefix) -> Result<ValidatedPrefix, IpamError> {
    validate_prefix_fields(
        &input.prefix,
        input.gateway.as_deref(),
        input.vlan_id,
        input.name.as_deref(),
        input.description.as_deref(),
        input.purpose.as_deref(),
    )
}

fn validate_prefix_update(input: &UpdateIpPrefix) -> Result<ValidatedPrefix, IpamError> {
    if input.expected_version <= 0 {
        return Err(IpamError::InvalidInput(
            "expectedVersion must be positive".to_owned(),
        ));
    }
    validate_prefix_fields(
        &input.prefix,
        input.gateway.as_deref(),
        input.vlan_id,
        input.name.as_deref(),
        input.description.as_deref(),
        input.purpose.as_deref(),
    )
}

fn validate_prefix_fields(
    prefix: &str,
    gateway: Option<&str>,
    vlan_id: Option<i32>,
    name: Option<&str>,
    description: Option<&str>,
    purpose: Option<&str>,
) -> Result<ValidatedPrefix, IpamError> {
    let parsed: IpNet = prefix
        .trim()
        .parse()
        .map_err(|_| IpamError::InvalidInput("prefix must be a valid IPv4/IPv6 CIDR".to_owned()))?;
    let canonical = IpNet::new(parsed.network(), parsed.prefix_len())
        .map_err(|_| IpamError::InvalidInput("prefix length is invalid".to_owned()))?;
    if vlan_id.is_some_and(|value| !(1..=4094).contains(&value)) {
        return Err(IpamError::InvalidInput(
            "VLAN must be between 1 and 4094".to_owned(),
        ));
    }
    validate_optional_text("name", name, 255)?;
    validate_optional_text("description", description, 4000)?;
    validate_optional_text("purpose", purpose, 255)?;

    let gateway = gateway
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse::<IpAddr>().map_err(|_| {
                IpamError::InvalidInput("gateway must be a valid IP address".to_owned())
            })
        })
        .transpose()?;
    if let Some(value) = gateway {
        if !canonical.contains(&value) {
            return Err(IpamError::InvalidInput(
                "gateway must belong to the selected prefix".to_owned(),
            ));
        }
        if value == canonical.network() {
            return Err(IpamError::InvalidInput(
                "gateway cannot be the network address".to_owned(),
            ));
        }
        if let (IpNet::V4(network), IpAddr::V4(gateway)) = (canonical, value)
            && network.prefix_len() < 31
            && gateway == network.broadcast()
        {
            return Err(IpamError::InvalidInput(
                "gateway cannot be the IPv4 broadcast address".to_owned(),
            ));
        }
    }
    Ok(ValidatedPrefix {
        prefix: canonical,
        gateway,
    })
}

fn validate_address_input(input: &NewIpAddress) -> Result<IpAddr, IpamError> {
    validate_optional_text("dnsName", input.dns_name.as_deref(), 255)?;
    validate_optional_text("description", input.description.as_deref(), 4000)?;
    validate_source(&input.source)?;
    if input.state == AddressState::Available {
        return Err(IpamError::InvalidInput(
            "available addresses are derived from the prefix and are not persisted as allocations"
                .to_owned(),
        ));
    }
    let address = input
        .address
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| IpamError::InvalidInput("address must be valid IPv4/IPv6".to_owned()))?;
    if is_ipv6_link_local(address) && input.interface_id.is_none() {
        return Err(IpamError::InvalidInput(
            "IPv6 link-local allocation requires interface scope".to_owned(),
        ));
    }
    Ok(address)
}

fn validate_address_update(input: &UpdateIpAddress) -> Result<(), IpamError> {
    if input.expected_version <= 0 {
        return Err(IpamError::InvalidInput(
            "expectedVersion must be positive".to_owned(),
        ));
    }
    validate_optional_text("dnsName", input.dns_name.as_deref(), 255)?;
    validate_optional_text("description", input.description.as_deref(), 4000)?;
    validate_source(&input.source)?;
    if input.state == AddressState::Available {
        return Err(IpamError::InvalidInput(
            "available addresses are derived from the prefix and are not persisted as allocations"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_source(source: &str) -> Result<(), IpamError> {
    let source = source.trim();
    if source.is_empty() || source.len() > 120 {
        return Err(IpamError::InvalidInput(
            "allocation source is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_optional_text(name: &str, value: Option<&str>, max: usize) -> Result<(), IpamError> {
    if value.is_some_and(|value| value.trim().len() > max) {
        return Err(IpamError::InvalidInput(format!("{name} is too long")));
    }
    Ok(())
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

async fn load_prefix_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    prefix_id: Uuid,
    lock: bool,
) -> Result<Option<IpPrefixView>, IpamError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let sql = format!(
        r#"
        SELECT p.id, p.organization_id, p.site_id, p.routing_domain_id,
               p.prefix::text AS prefix, p.name, host(p.gateway) AS gateway,
               p.vlan_id, p.description, p.purpose, p.version,
               p.created_at, p.updated_at,
               (SELECT count(*) FROM ip_addresses a WHERE a.prefix_id = p.id) AS allocation_count
        FROM ip_prefixes p
        WHERE p.id = $1 AND p.organization_id = $2 AND p.site_id = $3{suffix}
        "#
    );
    let row = sqlx::query(&sql)
        .bind(prefix_id)
        .bind(organization_id)
        .bind(site_id)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(row_to_prefix).transpose()
}

async fn load_address_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    address_id: Uuid,
    lock: bool,
) -> Result<Option<IpAddressView>, IpamError> {
    let suffix = if lock { " FOR UPDATE" } else { "" };
    let sql = format!(
        r#"
        SELECT a.id, a.organization_id, a.site_id, a.routing_domain_id,
               a.prefix_id, a.device_id, a.interface_id, host(a.address) AS address,
               a.dns_name, a.allocation_state, a.source, a.description,
               a.version, a.created_at, a.updated_at
        FROM ip_addresses a
        WHERE a.id = $1 AND a.organization_id = $2 AND a.site_id = $3{suffix}
        "#
    );
    let row = sqlx::query(&sql)
        .bind(address_id)
        .bind(organization_id)
        .bind(site_id)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(row_to_address).transpose()
}

fn row_to_prefix(row: sqlx::postgres::PgRow) -> Result<IpPrefixView, IpamError> {
    let prefix: String = row.try_get("prefix")?;
    let parsed: IpNet = prefix
        .parse()
        .map_err(|_| IpamError::InvalidStoredValue("stored prefix cannot be parsed".to_owned()))?;
    let allocated_addresses: i64 = row.try_get("allocation_count")?;
    let host_bits = match parsed {
        IpNet::V4(network) => 32_u8 - network.prefix_len(),
        IpNet::V6(network) => 128_u8 - network.prefix_len(),
    };
    let total_addresses = power_of_two_decimal(host_bits);
    let total_float = 2_f64.powi(i32::from(host_bits));
    let utilization_percent = if total_float == 0.0 {
        0.0
    } else {
        ((allocated_addresses as f64 / total_float) * 100.0).clamp(0.0, 100.0)
    };
    Ok(IpPrefixView {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        site_id: row.try_get("site_id")?,
        routing_domain_id: row.try_get("routing_domain_id")?,
        prefix,
        name: row.try_get("name")?,
        gateway: row.try_get("gateway")?,
        vlan_id: row.try_get("vlan_id")?,
        description: row.try_get("description")?,
        purpose: row.try_get("purpose")?,
        version: row.try_get("version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        capacity: PrefixCapacity {
            total_addresses,
            allocated_addresses,
            utilization_percent,
        },
    })
}

fn row_to_address(row: sqlx::postgres::PgRow) -> Result<IpAddressView, IpamError> {
    let state_text: String = row.try_get("allocation_state")?;
    let state = parse_address_state(&state_text)?;
    Ok(IpAddressView {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        site_id: row.try_get("site_id")?,
        routing_domain_id: row.try_get("routing_domain_id")?,
        prefix_id: row.try_get("prefix_id")?,
        device_id: row.try_get("device_id")?,
        interface_id: row.try_get("interface_id")?,
        address: row.try_get("address")?,
        dns_name: row.try_get("dns_name")?,
        state,
        source: row.try_get("source")?,
        description: row.try_get("description")?,
        version: row.try_get("version")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn parse_address_state(value: &str) -> Result<AddressState, IpamError> {
    match value {
        "available" => Ok(AddressState::Available),
        "reserved" => Ok(AddressState::Reserved),
        "assigned" => Ok(AddressState::Assigned),
        "observed" => Ok(AddressState::Observed),
        "conflict" => Ok(AddressState::Conflict),
        "excluded" => Ok(AddressState::Excluded),
        _ => Err(IpamError::InvalidStoredValue(format!(
            "unknown allocation state: {value}"
        ))),
    }
}

fn power_of_two_decimal(exponent: u8) -> String {
    let mut digits = vec![1_u8];
    for _ in 0..exponent {
        let mut carry = 0_u8;
        for digit in &mut digits {
            let value = *digit * 2 + carry;
            *digit = value % 10;
            carry = value / 10;
        }
        if carry > 0 {
            digits.push(carry);
        }
    }
    digits
        .iter()
        .rev()
        .map(|digit| char::from(b'0' + *digit))
        .collect()
}

async fn write_mutation_records(
    tx: &mut Transaction<'_, Postgres>,
    context: &MutationContext,
    action: &str,
    event_type: &str,
    resource_type: &str,
    resource_id: Uuid,
    before: Option<Value>,
    after: Option<Value>,
) -> Result<(), IpamError> {
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
            before,
            after: after.clone(),
            result: Some(json!({"confirmed": true})),
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
            payload: after.unwrap_or_else(|| json!({"id": resource_id, "deleted": true})),
            correlation_id: context.correlation_id,
        },
    )
    .await?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum IpamError {
    #[error("invalid IPAM request: {0}")]
    InvalidInput(String),
    #[error("stored IPAM value is invalid: {0}")]
    InvalidStoredValue(String),
    #[error("prefix overlaps another prefix in the same routing domain")]
    PrefixOverlap,
    #[error("IP address is already allocated in this routing domain")]
    AddressConflict,
    #[error("IPAM resource has dependent references or invalid scope")]
    ReferenceConflict,
    #[error("IP prefix not found")]
    PrefixNotFound,
    #[error("IP address not found")]
    AddressNotFound,
    #[error("resource changed since it was read: expected {expected}, actual {actual}")]
    VersionConflict { expected: i64, actual: i64 },
    #[error(transparent)]
    Audit(#[from] AuditStoreError),
    #[error(transparent)]
    Outbox(#[from] OutboxError),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Database(sqlx::Error),
}

impl From<sqlx::Error> for IpamError {
    fn from(error: sqlx::Error) -> Self {
        if let Some(database) = error.as_database_error() {
            match database.code().as_deref() {
                Some("23P01") => return Self::PrefixOverlap,
                Some("23505") => return Self::AddressConflict,
                Some("23503") => return Self::ReferenceConflict,
                Some("23514") => {
                    return Self::InvalidInput(
                        "database constraint rejected IPAM mutation".to_owned(),
                    );
                }
                _ => {}
            }
        }
        Self::Database(error)
    }
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

    async fn scope(pool: &PgPool) -> (Uuid, Uuid, Uuid, Uuid) {
        let suffix = Uuid::now_v7().simple().to_string();
        let organization_id: Uuid = sqlx::query_scalar(
            "INSERT INTO organizations (slug, name) VALUES ($1, 'IPAM Test') RETURNING id",
        )
        .bind(format!("ipam-{suffix}"))
        .fetch_one(pool)
        .await
        .unwrap();
        let site_id: Uuid = sqlx::query_scalar(
            "INSERT INTO sites (organization_id, slug, name) VALUES ($1, 'site', 'IPAM Site') RETURNING id",
        )
        .bind(organization_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let first: Uuid = sqlx::query_scalar(
            "INSERT INTO routing_domains (organization_id, site_id, name, is_default) VALUES ($1,$2,'default',true) RETURNING id",
        )
        .bind(organization_id)
        .bind(site_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let second: Uuid = sqlx::query_scalar(
            "INSERT INTO routing_domains (organization_id, site_id, name) VALUES ($1,$2,'isolated') RETURNING id",
        )
        .bind(organization_id)
        .bind(site_id)
        .fetch_one(pool)
        .await
        .unwrap();
        (organization_id, site_id, first, second)
    }

    fn context(organization_id: Uuid, site_id: Uuid) -> MutationContext {
        MutationContext {
            organization_id,
            site_id,
            actor_type: AuditActorType::System,
            actor_id: None,
            session_id: None,
            source_ip: None,
            request_id: Uuid::now_v7().to_string(),
            correlation_id: Uuid::now_v7(),
        }
    }

    fn prefix(routing_domain_id: Uuid, value: &str) -> NewIpPrefix {
        NewIpPrefix {
            routing_domain_id,
            prefix: value.to_owned(),
            name: None,
            gateway: None,
            vlan_id: None,
            description: None,
            purpose: None,
        }
    }

    #[tokio::test]
    async fn overlapping_prefix_is_blocked_only_inside_same_routing_domain() {
        let Some(pool) = pool().await else { return };
        let (organization_id, site_id, first, second) = scope(&pool).await;
        let store = IpamStore::new(pool);
        let mutation = context(organization_id, site_id);
        store
            .create_prefix(&mutation, prefix(first, "10.20.0.0/24"))
            .await
            .unwrap();
        store
            .create_prefix(&mutation, prefix(second, "10.20.0.0/24"))
            .await
            .unwrap();
        assert!(matches!(
            store
                .create_prefix(&mutation, prefix(first, "10.20.0.128/25"))
                .await,
            Err(IpamError::PrefixOverlap)
        ));
    }

    #[tokio::test]
    async fn address_must_belong_to_selected_prefix_and_link_local_is_scoped() {
        let Some(pool) = pool().await else { return };
        let (organization_id, site_id, routing_domain_id, _) = scope(&pool).await;
        let store = IpamStore::new(pool);
        let mutation = context(organization_id, site_id);
        let prefix = store
            .create_prefix(&mutation, prefix(routing_domain_id, "192.0.2.0/24"))
            .await
            .unwrap();
        let outside = store
            .create_address(
                &mutation,
                NewIpAddress {
                    routing_domain_id,
                    prefix_id: prefix.id,
                    device_id: None,
                    interface_id: None,
                    address: "198.51.100.1".to_owned(),
                    dns_name: None,
                    state: AddressState::Reserved,
                    source: "manual".to_owned(),
                    description: None,
                },
            )
            .await;
        assert!(matches!(outside, Err(IpamError::InvalidInput(_))));

        let link_local = NewIpAddress {
            routing_domain_id,
            prefix_id: prefix.id,
            device_id: None,
            interface_id: None,
            address: "fe80::1".to_owned(),
            dns_name: None,
            state: AddressState::Observed,
            source: "discovery".to_owned(),
            description: None,
        };
        assert!(matches!(
            validate_address_input(&link_local),
            Err(IpamError::InvalidInput(_))
        ));
    }

    #[test]
    fn capacity_is_exact_for_ipv4_and_ipv6() {
        assert_eq!(power_of_two_decimal(8), "256");
        assert_eq!(power_of_two_decimal(64), "18446744073709551616");
        assert_eq!(
            power_of_two_decimal(128),
            "340282366920938463463374607431768211456"
        );
    }
}
