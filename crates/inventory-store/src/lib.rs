use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use snm_audit_store::{AuditStore, AuditStoreError};
use snm_domain::inventory::{
    DeviceLifecycle, DeviceType, IdentifierKind, IdentifierStrength,
};
use snm_platform_events::{NewOutboxEvent, OutboxError, OutboxStore};
use snm_security::audit::{AuditActorType, AuditEventDraft, AuditStatus};
use sqlx::{PgPool, Postgres, QueryBuilder, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone)]
pub struct InventoryStore {
    pool: PgPool,
}

impl InventoryStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        device_id: Uuid,
    ) -> Result<Option<DeviceView>, InventoryError> {
        let row = sqlx::query(DEVICE_SELECT)
            .bind(organization_id)
            .bind(site_id)
            .bind(device_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(row_to_device).transpose()
    }

    pub async fn list(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        query: InventoryQuery,
    ) -> Result<Vec<DeviceView>, InventoryError> {
        query.validate()?;
        let mut builder = QueryBuilder::<Postgres>::new(
            r#"
            SELECT d.id, d.organization_id, d.site_id, d.lifecycle_state,
                   d.device_type, d.display_name, d.hostname, d.vendor, d.model,
                   d.serial_number, d.os_name, d.os_version, d.firmware_version,
                   d.description, d.operational_owner, d.capabilities, d.version,
                   d.last_seen_at, d.last_changed_at, d.onboarded_at, d.retired_at,
                   d.retirement_reason
            FROM devices d
            WHERE d.organization_id =
            "#,
        );
        builder.push_bind(organization_id);
        builder.push(" AND d.site_id = ");
        builder.push_bind(site_id);

        if let Some(lifecycle) = query.lifecycle {
            builder.push(" AND d.lifecycle_state = ");
            builder.push_bind(lifecycle.as_str());
        }
        if let Some(device_type) = query.device_type {
            builder.push(" AND d.device_type = ");
            builder.push_bind(device_type.as_str());
        }
        if let Some(search) = query.search.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
            let contains = format!("%{}%", search.to_ascii_lowercase());
            let normalized: String = search
                .chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .map(|character| character.to_ascii_lowercase())
                .collect();
            builder.push(
                r#" AND (
                    lower(coalesce(d.display_name, '')) LIKE "#,
            );
            builder.push_bind(contains.clone());
            builder.push(" OR lower(coalesce(d.hostname, '')) LIKE ");
            builder.push_bind(contains.clone());
            builder.push(" OR lower(coalesce(d.serial_number, '')) LIKE ");
            builder.push_bind(contains.clone());
            builder.push(
                r#" OR EXISTS (
                    SELECT 1 FROM device_identifiers di
                    WHERE di.device_id = d.id
                      AND di.organization_id = d.organization_id
                      AND di.site_id = d.site_id
                      AND (lower(di.value) LIKE "#,
            );
            builder.push_bind(contains.clone());
            if normalized.is_empty() {
                builder.push(" OR false");
            } else {
                builder.push(" OR di.normalized_value LIKE ");
                builder.push_bind(format!("%{normalized}%"));
            }
            builder.push(
                r#")
                ) OR EXISTS (
                    SELECT 1
                    FROM interfaces i
                    JOIN ip_addresses ip ON ip.interface_id = i.id
                    WHERE i.device_id = d.id
                      AND i.organization_id = d.organization_id
                      AND i.site_id = d.site_id
                      AND lower(host(ip.address)) LIKE "#,
            );
            builder.push_bind(contains);
            builder.push(") )");
        }

        builder.push(" ORDER BY d.last_changed_at DESC, d.id DESC LIMIT ");
        builder.push_bind(query.limit);
        builder.push(" OFFSET ");
        builder.push_bind(query.offset);

        let rows = builder.build().fetch_all(&self.pool).await?;
        rows.into_iter().map(row_to_device).collect()
    }

    pub async fn create_manual(
        &self,
        context: &MutationContext,
        input: NewDevice,
        approval_required: bool,
    ) -> Result<DeviceView, InventoryError> {
        context.validate()?;
        input.validate()?;
        let lifecycle = if approval_required {
            DeviceLifecycle::PendingReview
        } else {
            DeviceLifecycle::Managed
        };
        let mut tx = self.pool.begin().await?;
        let device_id = Uuid::now_v7();
        let serial = first_identifier_value(&input.identifiers, IdentifierKind::Serial);
        let hostname = input
            .hostname
            .clone()
            .or_else(|| first_identifier_value(&input.identifiers, IdentifierKind::Hostname));

        sqlx::query(
            r#"
            INSERT INTO devices (
              id, organization_id, site_id, lifecycle_state, device_type,
              display_name, hostname, vendor, model, serial_number, os_name,
              os_version, firmware_version, description, operational_owner,
              capabilities, onboarded_at, last_changed_at
            ) VALUES (
              $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
              CASE WHEN $4 = 'managed' THEN now() ELSE NULL END, now()
            )
            "#,
        )
        .bind(device_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(lifecycle.as_str())
        .bind(input.device_type.as_str())
        .bind(clean_optional(input.display_name.clone()))
        .bind(clean_optional(hostname.clone()))
        .bind(clean_optional(input.vendor.clone()))
        .bind(clean_optional(input.model.clone()))
        .bind(clean_optional(serial.clone()))
        .bind(clean_optional(input.os_name.clone()))
        .bind(clean_optional(input.os_version.clone()))
        .bind(clean_optional(input.firmware_version.clone()))
        .bind(clean_optional(input.description.clone()))
        .bind(clean_optional(input.operational_owner.clone()))
        .bind(&input.capabilities)
        .execute(&mut *tx)
        .await?;

        for identifier in &input.identifiers {
            upsert_identifier(
                &mut tx,
                context.organization_id,
                context.site_id,
                device_id,
                identifier,
                None,
            )
            .await?;
        }

        persist_declared_facts(
            &mut tx,
            context.organization_id,
            context.site_id,
            device_id,
            &input,
        )
        .await?;
        append_lifecycle_event(&mut tx, context, device_id, None, lifecycle, Some("manual_create"))
            .await?;

        let device = load_device_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            device_id,
            false,
        )
        .await?
        .ok_or(InventoryError::DeviceNotFound)?;
        write_mutation_records(
            &mut tx,
            context,
            "inventory.device.create",
            "inventory.device.created",
            &device,
            None,
            Some(serde_json::to_value(&device)?),
        )
        .await?;
        tx.commit().await?;
        Ok(device)
    }

    pub async fn update_metadata(
        &self,
        context: &MutationContext,
        device_id: Uuid,
        expected_version: i64,
        patch: MetadataPatch,
    ) -> Result<DeviceView, InventoryError> {
        context.validate()?;
        patch.validate()?;
        let mut tx = self.pool.begin().await?;
        let current = load_device_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            device_id,
            true,
        )
        .await?
        .ok_or(InventoryError::DeviceNotFound)?;
        if current.version != expected_version {
            return Err(InventoryError::VersionConflict {
                expected: expected_version,
                actual: current.version,
            });
        }
        if !current.lifecycle.allows_normal_mutation() {
            return Err(InventoryError::LifecycleBlocksMutation(current.lifecycle));
        }

        let before = serde_json::to_value(&current)?;
        let next_display_name = patch
            .display_name
            .clone()
            .unwrap_or_else(|| current.display_name.clone());
        let next_hostname = patch
            .hostname
            .clone()
            .unwrap_or_else(|| current.hostname.clone());
        let next_vendor = patch.vendor.clone().unwrap_or_else(|| current.vendor.clone());
        let next_model = patch.model.clone().unwrap_or_else(|| current.model.clone());
        let next_os_name = patch.os_name.clone().unwrap_or_else(|| current.os_name.clone());
        let next_os_version = patch
            .os_version
            .clone()
            .unwrap_or_else(|| current.os_version.clone());
        let next_firmware = patch
            .firmware_version
            .clone()
            .unwrap_or_else(|| current.firmware_version.clone());
        let next_description = patch
            .description
            .clone()
            .unwrap_or_else(|| current.description.clone());
        let next_owner = patch
            .operational_owner
            .clone()
            .unwrap_or_else(|| current.operational_owner.clone());
        let next_type = patch.device_type.unwrap_or(current.device_type);
        let next_capabilities = patch
            .capabilities
            .clone()
            .unwrap_or_else(|| current.capabilities.clone());

        sqlx::query(
            r#"
            UPDATE devices
            SET display_name = $4, hostname = $5, vendor = $6, model = $7,
                os_name = $8, os_version = $9, firmware_version = $10,
                description = $11, operational_owner = $12, device_type = $13,
                capabilities = $14, version = version + 1,
                last_changed_at = now(), updated_at = now()
            WHERE id = $1 AND organization_id = $2 AND site_id = $3
            "#,
        )
        .bind(device_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(clean_optional(next_display_name.clone()))
        .bind(clean_optional(next_hostname.clone()))
        .bind(clean_optional(next_vendor.clone()))
        .bind(clean_optional(next_model.clone()))
        .bind(clean_optional(next_os_name.clone()))
        .bind(clean_optional(next_os_version.clone()))
        .bind(clean_optional(next_firmware.clone()))
        .bind(clean_optional(next_description.clone()))
        .bind(clean_optional(next_owner.clone()))
        .bind(next_type.as_str())
        .bind(&next_capabilities)
        .execute(&mut *tx)
        .await?;

        persist_patch_facts(
            &mut tx,
            context.organization_id,
            context.site_id,
            device_id,
            &patch,
        )
        .await?;

        let updated = load_device_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            device_id,
            false,
        )
        .await?
        .ok_or(InventoryError::DeviceNotFound)?;
        write_mutation_records(
            &mut tx,
            context,
            "inventory.device.update",
            "inventory.device.updated",
            &updated,
            Some(before),
            Some(serde_json::to_value(&updated)?),
        )
        .await?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn transition_lifecycle(
        &self,
        context: &MutationContext,
        device_id: Uuid,
        expected_version: i64,
        next: DeviceLifecycle,
        reason: Option<&str>,
    ) -> Result<DeviceView, InventoryError> {
        context.validate()?;
        let mut tx = self.pool.begin().await?;
        let current = load_device_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            device_id,
            true,
        )
        .await?
        .ok_or(InventoryError::DeviceNotFound)?;
        if current.version != expected_version {
            return Err(InventoryError::VersionConflict {
                expected: expected_version,
                actual: current.version,
            });
        }
        if current.lifecycle == next {
            tx.rollback().await?;
            return Ok(current);
        }
        if !current.lifecycle.can_transition_to(next) {
            return Err(InventoryError::InvalidLifecycleTransition {
                from: current.lifecycle,
                to: next,
            });
        }
        let reason = clean_optional(reason.map(ToOwned::to_owned));
        if matches!(next, DeviceLifecycle::Retired | DeviceLifecycle::Archived)
            && reason.as_deref().is_none_or(str::is_empty)
        {
            return Err(InventoryError::LifecycleReasonRequired);
        }

        let before = serde_json::to_value(&current)?;
        sqlx::query(
            r#"
            UPDATE devices
            SET lifecycle_state = $4,
                onboarded_at = CASE
                  WHEN $4 = 'managed' THEN coalesce(onboarded_at, now())
                  ELSE onboarded_at
                END,
                retired_at = CASE
                  WHEN $4 = 'retired' THEN now()
                  WHEN lifecycle_state = 'retired' AND $4 = 'pending_review' THEN NULL
                  ELSE retired_at
                END,
                retirement_reason = CASE
                  WHEN $4 = 'retired' THEN $5
                  WHEN lifecycle_state = 'retired' AND $4 = 'pending_review' THEN NULL
                  ELSE retirement_reason
                END,
                version = version + 1, last_changed_at = now(), updated_at = now()
            WHERE id = $1 AND organization_id = $2 AND site_id = $3
            "#,
        )
        .bind(device_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(next.as_str())
        .bind(reason.as_deref())
        .execute(&mut *tx)
        .await?;
        append_lifecycle_event(
            &mut tx,
            context,
            device_id,
            Some(current.lifecycle),
            next,
            reason.as_deref(),
        )
        .await?;

        let updated = load_device_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            device_id,
            false,
        )
        .await?
        .ok_or(InventoryError::DeviceNotFound)?;
        write_mutation_records(
            &mut tx,
            context,
            "inventory.device.lifecycle.transition",
            "inventory.device.lifecycle_changed",
            &updated,
            Some(before),
            Some(serde_json::to_value(&updated)?),
        )
        .await?;
        tx.commit().await?;
        Ok(updated)
    }

    pub async fn reconcile_observation(
        &self,
        context: &MutationContext,
        observation: DeviceObservation,
    ) -> Result<ReconciliationResult, InventoryError> {
        context.validate()?;
        observation.validate()?;
        let mut tx = self.pool.begin().await?;
        let mut matches = BTreeSet::new();
        for identifier in observation
            .identifiers
            .iter()
            .filter(|identifier| identifier.kind.strength() == IdentifierStrength::Strong)
        {
            let normalized = identifier.kind.normalize(&identifier.value)?;
            let namespace = identity_namespace(&identifier.kind, &identifier.source)?;
            let device_id = sqlx::query_scalar::<_, Uuid>(
                r#"
                SELECT device_id
                FROM device_identifiers
                WHERE organization_id = $1 AND site_id = $2 AND kind = $3
                  AND identity_namespace = $4 AND normalized_value = $5
                  AND strength = 'strong'
                FOR UPDATE
                "#,
            )
            .bind(context.organization_id)
            .bind(context.site_id)
            .bind(identifier.kind.as_str())
            .bind(namespace)
            .bind(normalized)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(device_id) = device_id {
                matches.insert(device_id);
            }
        }
        if matches.len() > 1 {
            return Err(InventoryError::ReconciliationConflict(
                matches.into_iter().collect(),
            ));
        }

        let observed_at = observation.observed_at.unwrap_or_else(Utc::now);
        if let Some(device_id) = matches.into_iter().next() {
            let current = load_device_in_tx(
                &mut tx,
                context.organization_id,
                context.site_id,
                device_id,
                true,
            )
            .await?
            .ok_or(InventoryError::DeviceNotFound)?;
            if matches!(
                current.lifecycle,
                DeviceLifecycle::Retired | DeviceLifecycle::Archived
            ) {
                return Err(InventoryError::ReactivationRequiresReview(device_id));
            }
            let before = serde_json::to_value(&current)?;
            for identifier in &observation.identifiers {
                upsert_identifier(
                    &mut tx,
                    context.organization_id,
                    context.site_id,
                    device_id,
                    identifier,
                    Some(observed_at),
                )
                .await?;
            }
            persist_observed_facts(
                &mut tx,
                context.organization_id,
                context.site_id,
                device_id,
                &observation,
                observed_at,
            )
            .await?;
            apply_observed_canonical_fields(&mut tx, device_id, &observation, observed_at).await?;

            let updated = load_device_in_tx(
                &mut tx,
                context.organization_id,
                context.site_id,
                device_id,
                false,
            )
            .await?
            .ok_or(InventoryError::DeviceNotFound)?;
            write_mutation_records(
                &mut tx,
                context,
                "inventory.device.reconcile",
                "inventory.device.observed",
                &updated,
                Some(before),
                Some(serde_json::to_value(&updated)?),
            )
            .await?;
            tx.commit().await?;
            return Ok(ReconciliationResult::Updated(updated));
        }

        let device_id = Uuid::now_v7();
        let serial = first_identifier_value(&observation.identifiers, IdentifierKind::Serial);
        let hostname = observation.hostname.clone().or_else(|| {
            first_identifier_value(&observation.identifiers, IdentifierKind::Hostname)
        });
        sqlx::query(
            r#"
            INSERT INTO devices (
              id, organization_id, site_id, lifecycle_state, device_type,
              display_name, hostname, vendor, model, serial_number,
              os_name, os_version, firmware_version, capabilities,
              last_seen_at, last_changed_at
            ) VALUES ($1,$2,$3,'discovered',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now())
            "#,
        )
        .bind(device_id)
        .bind(context.organization_id)
        .bind(context.site_id)
        .bind(observation.device_type.as_str())
        .bind(clean_optional(observation.display_name.clone()))
        .bind(clean_optional(hostname))
        .bind(clean_optional(observation.vendor.clone()))
        .bind(clean_optional(observation.model.clone()))
        .bind(clean_optional(serial))
        .bind(clean_optional(observation.os_name.clone()))
        .bind(clean_optional(observation.os_version.clone()))
        .bind(clean_optional(observation.firmware_version.clone()))
        .bind(&observation.capabilities)
        .bind(observed_at)
        .execute(&mut *tx)
        .await?;
        for identifier in &observation.identifiers {
            upsert_identifier(
                &mut tx,
                context.organization_id,
                context.site_id,
                device_id,
                identifier,
                Some(observed_at),
            )
            .await?;
        }
        persist_observed_facts(
            &mut tx,
            context.organization_id,
            context.site_id,
            device_id,
            &observation,
            observed_at,
        )
        .await?;
        append_lifecycle_event(
            &mut tx,
            context,
            device_id,
            None,
            DeviceLifecycle::Discovered,
            Some("discovery"),
        )
        .await?;
        let created = load_device_in_tx(
            &mut tx,
            context.organization_id,
            context.site_id,
            device_id,
            false,
        )
        .await?
        .ok_or(InventoryError::DeviceNotFound)?;
        write_mutation_records(
            &mut tx,
            context,
            "inventory.device.discovery.create",
            "inventory.device.discovered",
            &created,
            None,
            Some(serde_json::to_value(&created)?),
        )
        .await?;
        tx.commit().await?;
        Ok(ReconciliationResult::Created(created))
    }
}

const DEVICE_SELECT: &str = r#"
SELECT id, organization_id, site_id, lifecycle_state, device_type,
       display_name, hostname, vendor, model, serial_number, os_name,
       os_version, firmware_version, description, operational_owner,
       capabilities, version, last_seen_at, last_changed_at, onboarded_at,
       retired_at, retirement_reason
FROM devices
WHERE organization_id = $1 AND site_id = $2 AND id = $3
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
    pub fn validate(&self) -> Result<(), InventoryError> {
        if self.request_id.trim().is_empty() || self.request_id.len() > 200 {
            return Err(InventoryError::InvalidInput("request id is invalid"));
        }
        if self
            .source_ip
            .as_ref()
            .is_some_and(|value| value.parse::<std::net::IpAddr>().is_err())
        {
            return Err(InventoryError::InvalidInput("source IP is invalid"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewIdentifier {
    pub kind: IdentifierKind,
    pub value: String,
    pub source: String,
    pub confidence: Option<f32>,
}

impl NewIdentifier {
    fn validate(&self) -> Result<(), InventoryError> {
        self.kind.normalize(&self.value)?;
        if self.source.trim().is_empty() || self.source.len() > 120 {
            return Err(InventoryError::InvalidInput("identifier source is invalid"));
        }
        if self
            .confidence
            .is_some_and(|confidence| !(0.0..=1.0).contains(&confidence))
        {
            return Err(InventoryError::InvalidInput(
                "identifier confidence is invalid",
            ));
        }
        identity_namespace(&self.kind, &self.source)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NewDevice {
    pub device_type: DeviceType,
    pub display_name: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub firmware_version: Option<String>,
    pub description: Option<String>,
    pub operational_owner: Option<String>,
    pub capabilities: Vec<String>,
    pub identifiers: Vec<NewIdentifier>,
}

impl NewDevice {
    fn validate(&self) -> Result<(), InventoryError> {
        validate_text_fields([
            self.display_name.as_deref(),
            self.hostname.as_deref(),
            self.vendor.as_deref(),
            self.model.as_deref(),
            self.os_name.as_deref(),
            self.os_version.as_deref(),
            self.firmware_version.as_deref(),
            self.operational_owner.as_deref(),
        ])?;
        if self.description.as_ref().is_some_and(|value| value.len() > 4096) {
            return Err(InventoryError::InvalidInput("description is too long"));
        }
        if self.capabilities.len() > 256
            || self.capabilities.iter().any(|value| value.trim().is_empty() || value.len() > 120)
        {
            return Err(InventoryError::InvalidInput("capabilities are invalid"));
        }
        for identifier in &self.identifiers {
            identifier.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceObservation {
    pub device_type: DeviceType,
    pub display_name: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub firmware_version: Option<String>,
    pub capabilities: Vec<String>,
    pub identifiers: Vec<NewIdentifier>,
    pub observed_at: Option<DateTime<Utc>>,
}

impl DeviceObservation {
    fn validate(&self) -> Result<(), InventoryError> {
        if self.identifiers.is_empty() {
            return Err(InventoryError::InvalidInput(
                "observation requires at least one identifier",
            ));
        }
        validate_text_fields([
            self.display_name.as_deref(),
            self.hostname.as_deref(),
            self.vendor.as_deref(),
            self.model.as_deref(),
            self.os_name.as_deref(),
            self.os_version.as_deref(),
            self.firmware_version.as_deref(),
        ])?;
        for identifier in &self.identifiers {
            identifier.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetadataPatch {
    pub device_type: Option<DeviceType>,
    pub display_name: Option<Option<String>>,
    pub hostname: Option<Option<String>>,
    pub vendor: Option<Option<String>>,
    pub model: Option<Option<String>>,
    pub os_name: Option<Option<String>>,
    pub os_version: Option<Option<String>>,
    pub firmware_version: Option<Option<String>>,
    pub description: Option<Option<String>>,
    pub operational_owner: Option<Option<String>>,
    pub capabilities: Option<Vec<String>>,
}

impl MetadataPatch {
    fn validate(&self) -> Result<(), InventoryError> {
        validate_text_fields([
            nested_ref(&self.display_name),
            nested_ref(&self.hostname),
            nested_ref(&self.vendor),
            nested_ref(&self.model),
            nested_ref(&self.os_name),
            nested_ref(&self.os_version),
            nested_ref(&self.firmware_version),
            nested_ref(&self.operational_owner),
        ])?;
        if nested_ref(&self.description).is_some_and(|value| value.len() > 4096) {
            return Err(InventoryError::InvalidInput("description is too long"));
        }
        if self.capabilities.as_ref().is_some_and(|values| {
            values.len() > 256
                || values
                    .iter()
                    .any(|value| value.trim().is_empty() || value.len() > 120)
        }) {
            return Err(InventoryError::InvalidInput("capabilities are invalid"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct InventoryQuery {
    pub search: Option<String>,
    pub lifecycle: Option<DeviceLifecycle>,
    pub device_type: Option<DeviceType>,
    pub limit: i64,
    pub offset: i64,
}

impl InventoryQuery {
    fn validate(&self) -> Result<(), InventoryError> {
        if !(1..=200).contains(&self.limit) || self.offset < 0 {
            return Err(InventoryError::InvalidInput("pagination is invalid"));
        }
        if self.search.as_ref().is_some_and(|value| value.len() > 256) {
            return Err(InventoryError::InvalidInput("search is too long"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub site_id: Uuid,
    pub lifecycle: DeviceLifecycle,
    pub device_type: DeviceType,
    pub display_name: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub firmware_version: Option<String>,
    pub description: Option<String>,
    pub operational_owner: Option<String>,
    pub capabilities: Vec<String>,
    pub version: i64,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_changed_at: DateTime<Utc>,
    pub onboarded_at: Option<DateTime<Utc>>,
    pub retired_at: Option<DateTime<Utc>>,
    pub retirement_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "device")]
pub enum ReconciliationResult {
    Created(DeviceView),
    Updated(DeviceView),
}

async fn load_device_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    device_id: Uuid,
    for_update: bool,
) -> Result<Option<DeviceView>, InventoryError> {
    let sql = if for_update {
        format!("{DEVICE_SELECT} FOR UPDATE")
    } else {
        DEVICE_SELECT.to_owned()
    };
    let row = sqlx::query(&sql)
        .bind(organization_id)
        .bind(site_id)
        .bind(device_id)
        .fetch_optional(&mut **tx)
        .await?;
    row.map(row_to_device).transpose()
}

fn row_to_device(row: sqlx::postgres::PgRow) -> Result<DeviceView, InventoryError> {
    Ok(DeviceView {
        id: row.try_get("id")?,
        organization_id: row.try_get("organization_id")?,
        site_id: row.try_get("site_id")?,
        lifecycle: parse_lifecycle(&row.try_get::<String, _>("lifecycle_state")?)?,
        device_type: parse_device_type(&row.try_get::<String, _>("device_type")?)?,
        display_name: row.try_get("display_name")?,
        hostname: row.try_get("hostname")?,
        vendor: row.try_get("vendor")?,
        model: row.try_get("model")?,
        serial_number: row.try_get("serial_number")?,
        os_name: row.try_get("os_name")?,
        os_version: row.try_get("os_version")?,
        firmware_version: row.try_get("firmware_version")?,
        description: row.try_get("description")?,
        operational_owner: row.try_get("operational_owner")?,
        capabilities: row.try_get("capabilities")?,
        version: row.try_get("version")?,
        last_seen_at: row.try_get("last_seen_at")?,
        last_changed_at: row.try_get("last_changed_at")?,
        onboarded_at: row.try_get("onboarded_at")?,
        retired_at: row.try_get("retired_at")?,
        retirement_reason: row.try_get("retirement_reason")?,
    })
}

async fn upsert_identifier(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    device_id: Uuid,
    identifier: &NewIdentifier,
    observed_at: Option<DateTime<Utc>>,
) -> Result<(), InventoryError> {
    identifier.validate()?;
    let normalized = identifier.kind.normalize(&identifier.value)?;
    let namespace = identity_namespace(&identifier.kind, &identifier.source)?;
    let confidence = identifier.confidence.map(|value| value.to_string());
    let updated = sqlx::query(
        r#"
        UPDATE device_identifiers
        SET value = $6, source = $7, confidence = $8::numeric,
            last_seen_at = coalesce($9, last_seen_at)
        WHERE device_id = $1 AND organization_id = $2 AND site_id = $3
          AND kind = $4 AND identity_namespace = $5 AND normalized_value = $10
        "#,
    )
    .bind(device_id)
    .bind(organization_id)
    .bind(site_id)
    .bind(identifier.kind.as_str())
    .bind(&namespace)
    .bind(identifier.value.trim())
    .bind(identifier.source.trim())
    .bind(confidence.as_deref())
    .bind(observed_at)
    .bind(&normalized)
    .execute(&mut **tx)
    .await?;
    if updated.rows_affected() > 0 {
        return Ok(());
    }

    let result = sqlx::query(
        r#"
        INSERT INTO device_identifiers (
          device_id, kind, value, source, confidence, organization_id, site_id,
          normalized_value, identity_namespace, strength, last_seen_at
        ) VALUES ($1,$2,$3,$4,$5::numeric,$6,$7,$8,$9,$10,$11)
        "#,
    )
    .bind(device_id)
    .bind(identifier.kind.as_str())
    .bind(identifier.value.trim())
    .bind(identifier.source.trim())
    .bind(confidence.as_deref())
    .bind(organization_id)
    .bind(site_id)
    .bind(normalized)
    .bind(namespace)
    .bind(identifier.kind.strength().as_str())
    .bind(observed_at)
    .execute(&mut **tx)
    .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if is_identifier_conflict(&error) => Err(InventoryError::DuplicateIdentifier),
        Err(error) => Err(error.into()),
    }
}

fn identity_namespace(kind: &IdentifierKind, source: &str) -> Result<String, InventoryError> {
    if *kind == IdentifierKind::ProviderNativeId {
        let namespace = source.trim().to_ascii_lowercase();
        if namespace.is_empty() {
            return Err(InventoryError::InvalidInput(
                "provider-native identifier requires provider namespace",
            ));
        }
        Ok(namespace)
    } else {
        Ok("global".to_owned())
    }
}

async fn persist_declared_facts(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    device_id: Uuid,
    input: &NewDevice,
) -> Result<(), InventoryError> {
    upsert_declared_fact(tx, organization_id, site_id, device_id, "device_type", json!(input.device_type.as_str())).await?;
    for (field, value) in [
        ("display_name", input.display_name.as_ref()),
        ("hostname", input.hostname.as_ref()),
        ("vendor", input.vendor.as_ref()),
        ("model", input.model.as_ref()),
        ("os_name", input.os_name.as_ref()),
        ("os_version", input.os_version.as_ref()),
        ("firmware_version", input.firmware_version.as_ref()),
        ("description", input.description.as_ref()),
        ("operational_owner", input.operational_owner.as_ref()),
    ] {
        if let Some(value) = value {
            upsert_declared_fact(tx, organization_id, site_id, device_id, field, json!(value)).await?;
        }
    }
    if !input.capabilities.is_empty() {
        upsert_declared_fact(tx, organization_id, site_id, device_id, "capabilities", json!(input.capabilities)).await?;
    }
    Ok(())
}

async fn persist_patch_facts(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    device_id: Uuid,
    patch: &MetadataPatch,
) -> Result<(), InventoryError> {
    if let Some(device_type) = patch.device_type {
        upsert_declared_fact(tx, organization_id, site_id, device_id, "device_type", json!(device_type.as_str())).await?;
    }
    let fields: [(&str, &Option<Option<String>>); 9] = [
        ("display_name", &patch.display_name),
        ("hostname", &patch.hostname),
        ("vendor", &patch.vendor),
        ("model", &patch.model),
        ("os_name", &patch.os_name),
        ("os_version", &patch.os_version),
        ("firmware_version", &patch.firmware_version),
        ("description", &patch.description),
        ("operational_owner", &patch.operational_owner),
    ];
    for (field, value) in fields {
        if let Some(value) = value {
            upsert_declared_fact(tx, organization_id, site_id, device_id, field, json!(value)).await?;
        }
    }
    if let Some(capabilities) = &patch.capabilities {
        upsert_declared_fact(tx, organization_id, site_id, device_id, "capabilities", json!(capabilities)).await?;
    }
    Ok(())
}

async fn upsert_declared_fact(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    device_id: Uuid,
    field: &str,
    value: Value,
) -> Result<(), InventoryError> {
    sqlx::query(
        r#"
        INSERT INTO device_facts (
          organization_id, site_id, device_id, field_name, value,
          provenance, source, confidence
        ) VALUES ($1,$2,$3,$4,$5,'declared','manual',1::numeric)
        ON CONFLICT (device_id, field_name, provenance, source)
        DO UPDATE SET value = excluded.value, confidence = excluded.confidence,
                      updated_at = now()
        "#,
    )
    .bind(organization_id)
    .bind(site_id)
    .bind(device_id)
    .bind(field)
    .bind(value)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn persist_observed_facts(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    device_id: Uuid,
    observation: &DeviceObservation,
    observed_at: DateTime<Utc>,
) -> Result<(), InventoryError> {
    upsert_observed_fact(
        tx,
        organization_id,
        site_id,
        device_id,
        "device_type",
        json!(observation.device_type.as_str()),
        "discovery",
        observed_at,
    )
    .await?;
    for (field, value) in [
        ("display_name", observation.display_name.as_ref()),
        ("hostname", observation.hostname.as_ref()),
        ("vendor", observation.vendor.as_ref()),
        ("model", observation.model.as_ref()),
        ("os_name", observation.os_name.as_ref()),
        ("os_version", observation.os_version.as_ref()),
        ("firmware_version", observation.firmware_version.as_ref()),
    ] {
        if let Some(value) = value {
            upsert_observed_fact(
                tx,
                organization_id,
                site_id,
                device_id,
                field,
                json!(value),
                "discovery",
                observed_at,
            )
            .await?;
        }
    }
    if !observation.capabilities.is_empty() {
        upsert_observed_fact(
            tx,
            organization_id,
            site_id,
            device_id,
            "capabilities",
            json!(observation.capabilities),
            "discovery",
            observed_at,
        )
        .await?;
    }
    Ok(())
}

async fn upsert_observed_fact(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    site_id: Uuid,
    device_id: Uuid,
    field: &str,
    value: Value,
    source: &str,
    observed_at: DateTime<Utc>,
) -> Result<(), InventoryError> {
    sqlx::query(
        r#"
        INSERT INTO device_facts (
          organization_id, site_id, device_id, field_name, value,
          provenance, source, confidence, observed_at
        ) VALUES ($1,$2,$3,$4,$5,'observed',$6,1::numeric,$7)
        ON CONFLICT (device_id, field_name, provenance, source)
        DO UPDATE SET value = excluded.value, confidence = excluded.confidence,
                      observed_at = excluded.observed_at, updated_at = now()
        "#,
    )
    .bind(organization_id)
    .bind(site_id)
    .bind(device_id)
    .bind(field)
    .bind(value)
    .bind(source)
    .bind(observed_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn apply_observed_canonical_fields(
    tx: &mut Transaction<'_, Postgres>,
    device_id: Uuid,
    observation: &DeviceObservation,
    observed_at: DateTime<Utc>,
) -> Result<(), InventoryError> {
    sqlx::query(
        r#"
        UPDATE devices d
        SET display_name = CASE WHEN $2 IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM device_facts f WHERE f.device_id = d.id
                AND f.field_name = 'display_name' AND f.provenance = 'declared'
            ) THEN $2 ELSE d.display_name END,
            hostname = CASE WHEN $3 IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM device_facts f WHERE f.device_id = d.id
                AND f.field_name = 'hostname' AND f.provenance = 'declared'
            ) THEN $3 ELSE d.hostname END,
            vendor = CASE WHEN $4 IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM device_facts f WHERE f.device_id = d.id
                AND f.field_name = 'vendor' AND f.provenance = 'declared'
            ) THEN $4 ELSE d.vendor END,
            model = CASE WHEN $5 IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM device_facts f WHERE f.device_id = d.id
                AND f.field_name = 'model' AND f.provenance = 'declared'
            ) THEN $5 ELSE d.model END,
            os_name = CASE WHEN $6 IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM device_facts f WHERE f.device_id = d.id
                AND f.field_name = 'os_name' AND f.provenance = 'declared'
            ) THEN $6 ELSE d.os_name END,
            os_version = CASE WHEN $7 IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM device_facts f WHERE f.device_id = d.id
                AND f.field_name = 'os_version' AND f.provenance = 'declared'
            ) THEN $7 ELSE d.os_version END,
            firmware_version = CASE WHEN $8 IS NOT NULL AND NOT EXISTS (
              SELECT 1 FROM device_facts f WHERE f.device_id = d.id
                AND f.field_name = 'firmware_version' AND f.provenance = 'declared'
            ) THEN $8 ELSE d.firmware_version END,
            device_type = CASE WHEN NOT EXISTS (
              SELECT 1 FROM device_facts f WHERE f.device_id = d.id
                AND f.field_name = 'device_type' AND f.provenance = 'declared'
            ) THEN $9 ELSE d.device_type END,
            capabilities = CASE WHEN cardinality($10::text[]) > 0 AND NOT EXISTS (
              SELECT 1 FROM device_facts f WHERE f.device_id = d.id
                AND f.field_name = 'capabilities' AND f.provenance = 'declared'
            ) THEN $10 ELSE d.capabilities END,
            last_seen_at = GREATEST(coalesce(d.last_seen_at, $11), $11),
            last_changed_at = now(), version = version + 1, updated_at = now()
        WHERE d.id = $1
        "#,
    )
    .bind(device_id)
    .bind(clean_optional(observation.display_name.clone()))
    .bind(clean_optional(observation.hostname.clone()))
    .bind(clean_optional(observation.vendor.clone()))
    .bind(clean_optional(observation.model.clone()))
    .bind(clean_optional(observation.os_name.clone()))
    .bind(clean_optional(observation.os_version.clone()))
    .bind(clean_optional(observation.firmware_version.clone()))
    .bind(observation.device_type.as_str())
    .bind(&observation.capabilities)
    .bind(observed_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn append_lifecycle_event(
    tx: &mut Transaction<'_, Postgres>,
    context: &MutationContext,
    device_id: Uuid,
    from: Option<DeviceLifecycle>,
    to: DeviceLifecycle,
    reason: Option<&str>,
) -> Result<(), InventoryError> {
    sqlx::query(
        r#"
        INSERT INTO device_lifecycle_events (
          organization_id, site_id, device_id, from_state, to_state,
          actor_type, actor_id, reason, correlation_id
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        "#,
    )
    .bind(context.organization_id)
    .bind(context.site_id)
    .bind(device_id)
    .bind(from.map(DeviceLifecycle::as_str))
    .bind(to.as_str())
    .bind(context.actor_type.as_str())
    .bind(context.actor_id)
    .bind(reason)
    .bind(context.correlation_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn write_mutation_records(
    tx: &mut Transaction<'_, Postgres>,
    context: &MutationContext,
    action: &str,
    event_type: &str,
    device: &DeviceView,
    before: Option<Value>,
    after: Option<Value>,
) -> Result<(), InventoryError> {
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
            resource_type: "device".to_owned(),
            resource_id: Some(device.id.to_string()),
            provider: None,
            occurred_at_unix_ms: Utc::now().timestamp_millis(),
            duration_ms: None,
            status: AuditStatus::Succeeded,
            reason_code: None,
            before,
            after: after.clone(),
            result: Some(json!({"ok": true})),
        },
    )
    .await?;
    OutboxStore::enqueue(
        tx,
        &NewOutboxEvent {
            id: Uuid::now_v7(),
            organization_id: context.organization_id,
            aggregate_type: "device".to_owned(),
            aggregate_id: device.id.to_string(),
            event_type: event_type.to_owned(),
            event_version: 1,
            payload: after.unwrap_or_else(|| json!({"deviceId": device.id})),
            correlation_id: context.correlation_id,
        },
    )
    .await?;
    Ok(())
}

fn parse_lifecycle(value: &str) -> Result<DeviceLifecycle, InventoryError> {
    match value {
        "discovered" => Ok(DeviceLifecycle::Discovered),
        "pending_review" => Ok(DeviceLifecycle::PendingReview),
        "managed" => Ok(DeviceLifecycle::Managed),
        "unmanaged" => Ok(DeviceLifecycle::Unmanaged),
        "maintenance" => Ok(DeviceLifecycle::Maintenance),
        "retired" => Ok(DeviceLifecycle::Retired),
        "archived" => Ok(DeviceLifecycle::Archived),
        _ => Err(InventoryError::CorruptStoredValue("lifecycle_state")),
    }
}

fn parse_device_type(value: &str) -> Result<DeviceType, InventoryError> {
    match value {
        "switch" => Ok(DeviceType::Switch),
        "router" => Ok(DeviceType::Router),
        "firewall" => Ok(DeviceType::Firewall),
        "server" => Ok(DeviceType::Server),
        "printer" => Ok(DeviceType::Printer),
        "access_point" => Ok(DeviceType::AccessPoint),
        "unknown" => Ok(DeviceType::Unknown),
        _ => Err(InventoryError::CorruptStoredValue("device_type")),
    }
}

fn first_identifier_value(identifiers: &[NewIdentifier], kind: IdentifierKind) -> Option<String> {
    identifiers
        .iter()
        .find(|identifier| identifier.kind == kind)
        .map(|identifier| identifier.value.trim().to_owned())
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}

fn nested_ref(value: &Option<Option<String>>) -> Option<&str> {
    value.as_ref().and_then(|inner| inner.as_deref())
}

fn validate_text_fields<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Result<(), InventoryError> {
    if values
        .into_iter()
        .flatten()
        .any(|value| value.trim().is_empty() || value.len() > 512)
    {
        return Err(InventoryError::InvalidInput("text field is invalid"));
    }
    Ok(())
}

fn is_identifier_conflict(error: &sqlx::Error) -> bool {
    error.as_database_error().and_then(|error| error.constraint()).is_some_and(|constraint| {
        matches!(
            constraint,
            "uq_device_strong_identifier_scope" | "device_identifiers_device_id_kind_value_key"
        )
    })
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("invalid inventory input: {0}")]
    InvalidInput(&'static str),
    #[error("device was not found in the requested scope")]
    DeviceNotFound,
    #[error("device version conflict: expected {expected}, actual {actual}")]
    VersionConflict { expected: i64, actual: i64 },
    #[error("device lifecycle {0:?} blocks normal mutation")]
    LifecycleBlocksMutation(DeviceLifecycle),
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    InvalidLifecycleTransition {
        from: DeviceLifecycle,
        to: DeviceLifecycle,
    },
    #[error("retire/archive transition requires a reason")]
    LifecycleReasonRequired,
    #[error("strong identifier already belongs to another device")]
    DuplicateIdentifier,
    #[error("observation matches multiple devices and requires manual merge: {0:?}")]
    ReconciliationConflict(Vec<Uuid>),
    #[error("retired or archived device {0} requires explicit review before reactivation")]
    ReactivationRequiresReview(Uuid),
    #[error("stored inventory value is invalid: {0}")]
    CorruptStoredValue(&'static str),
    #[error(transparent)]
    Audit(#[from] AuditStoreError),
    #[error(transparent)]
    Outbox(#[from] OutboxError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl From<&'static str> for InventoryError {
    fn from(message: &'static str) -> Self {
        Self::InvalidInput(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    async fn scope(pool: &PgPool) -> (Uuid, Uuid) {
        let suffix = Uuid::now_v7().simple().to_string();
        let organization_id: Uuid = sqlx::query_scalar(
            "INSERT INTO organizations (slug, name) VALUES ($1, 'Inventory Test') RETURNING id",
        )
        .bind(format!("inv-{suffix}"))
        .fetch_one(pool)
        .await
        .unwrap();
        let site_id: Uuid = sqlx::query_scalar(
            "INSERT INTO sites (organization_id, slug, name) VALUES ($1, 'default', 'Default') RETURNING id",
        )
        .bind(organization_id)
        .fetch_one(pool)
        .await
        .unwrap();
        (organization_id, site_id)
    }

    fn context(organization_id: Uuid, site_id: Uuid) -> MutationContext {
        MutationContext {
            organization_id,
            site_id,
            actor_type: AuditActorType::User,
            actor_id: Some(Uuid::now_v7()),
            session_id: Some(Uuid::now_v7()),
            source_ip: Some("127.0.0.1".into()),
            request_id: Uuid::now_v7().to_string(),
            correlation_id: Uuid::now_v7(),
        }
    }

    fn manual(serial: &str) -> NewDevice {
        NewDevice {
            device_type: DeviceType::Switch,
            display_name: Some("Core Switch".into()),
            hostname: Some("sw-core.example".into()),
            vendor: Some("Vendor".into()),
            model: Some("Model".into()),
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

    fn observed(serial: &str) -> DeviceObservation {
        DeviceObservation {
            device_type: DeviceType::Switch,
            display_name: Some("Observed Switch".into()),
            hostname: Some("switch-observed.example".into()),
            vendor: Some("Observed Vendor".into()),
            model: Some("Observed Model".into()),
            os_name: None,
            os_version: None,
            firmware_version: None,
            capabilities: vec!["snmp.read".into()],
            identifiers: vec![NewIdentifier {
                kind: IdentifierKind::Serial,
                value: serial.into(),
                source: "snmp".into(),
                confidence: Some(1.0),
            }],
            observed_at: Some(Utc::now()),
        }
    }

    #[tokio::test]
    async fn discovery_never_auto_manages_a_new_device() {
        let Some(pool) = pool().await else { return };
        let (organization_id, site_id) = scope(&pool).await;
        let store = InventoryStore::new(pool);
        let result = store
            .reconcile_observation(&context(organization_id, site_id), observed("DISC-1"))
            .await
            .unwrap();
        let ReconciliationResult::Created(device) = result else {
            panic!("expected a new discovered device");
        };
        assert_eq!(device.lifecycle, DeviceLifecycle::Discovered);
    }

    #[tokio::test]
    async fn same_strong_identifier_from_different_sources_reconciles_one_device() {
        let Some(pool) = pool().await else { return };
        let (organization_id, site_id) = scope(&pool).await;
        let store = InventoryStore::new(pool);
        let ctx = context(organization_id, site_id);
        let first = store
            .reconcile_observation(&ctx, observed("SER-RECONCILE"))
            .await
            .unwrap();
        let first_id = match first {
            ReconciliationResult::Created(device) => device.id,
            ReconciliationResult::Updated(_) => panic!("unexpected update"),
        };
        let second = store
            .reconcile_observation(
                &ctx,
                DeviceObservation {
                    identifiers: vec![NewIdentifier {
                        kind: IdentifierKind::Serial,
                        value: "ser-reconcile".into(),
                        source: "wmi".into(),
                        confidence: Some(1.0),
                    }],
                    ..observed("unused")
                },
            )
            .await
            .unwrap();
        let ReconciliationResult::Updated(device) = second else {
            panic!("expected reconciliation update");
        };
        assert_eq!(device.id, first_id);
    }

    #[tokio::test]
    async fn declared_fields_win_over_later_observation() {
        let Some(pool) = pool().await else { return };
        let (organization_id, site_id) = scope(&pool).await;
        let store = InventoryStore::new(pool);
        let ctx = context(organization_id, site_id);
        let manual = store
            .create_manual(&ctx, manual("DECLARED-1"), false)
            .await
            .unwrap();
        let updated = store
            .reconcile_observation(&ctx, observed("DECLARED-1"))
            .await
            .unwrap();
        let ReconciliationResult::Updated(updated) = updated else {
            panic!("expected update");
        };
        assert_eq!(updated.id, manual.id);
        assert_eq!(updated.display_name.as_deref(), Some("Core Switch"));
        assert_eq!(updated.vendor.as_deref(), Some("Vendor"));
    }

    #[tokio::test]
    async fn retired_device_blocks_normal_mutation_and_direct_reactivation() {
        let Some(pool) = pool().await else { return };
        let (organization_id, site_id) = scope(&pool).await;
        let store = InventoryStore::new(pool);
        let ctx = context(organization_id, site_id);
        let device = store
            .create_manual(&ctx, manual("RETIRE-1"), false)
            .await
            .unwrap();
        let retired = store
            .transition_lifecycle(
                &ctx,
                device.id,
                device.version,
                DeviceLifecycle::Retired,
                Some("decommissioned"),
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .update_metadata(
                    &ctx,
                    retired.id,
                    retired.version,
                    MetadataPatch {
                        display_name: Some(Some("should fail".into())),
                        ..Default::default()
                    },
                )
                .await,
            Err(InventoryError::LifecycleBlocksMutation(DeviceLifecycle::Retired))
        ));
        assert!(matches!(
            store
                .transition_lifecycle(
                    &ctx,
                    retired.id,
                    retired.version,
                    DeviceLifecycle::Managed,
                    Some("invalid shortcut"),
                )
                .await,
            Err(InventoryError::InvalidLifecycleTransition { .. })
        ));
    }

    #[tokio::test]
    async fn mutation_commits_audit_and_outbox_in_same_transaction() {
        let Some(pool) = pool().await else { return };
        let (organization_id, site_id) = scope(&pool).await;
        let store = InventoryStore::new(pool.clone());
        let ctx = context(organization_id, site_id);
        let device = store
            .create_manual(&ctx, manual("ATOMIC-1"), true)
            .await
            .unwrap();
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM audit_events WHERE organization_id = $1 AND resource_id = $2",
        )
        .bind(organization_id)
        .bind(device.id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        let outbox_count: i64 = sqlx::query_scalar(
            "SELECT count(*)::bigint FROM outbox_events WHERE organization_id = $1 AND aggregate_id = $2",
        )
        .bind(organization_id)
        .bind(device.id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 1);
        assert_eq!(outbox_count, 1);
        assert_eq!(device.lifecycle, DeviceLifecycle::PendingReview);
    }
}
