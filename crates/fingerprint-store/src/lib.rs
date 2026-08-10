use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use snm_fingerprint_core::{FingerprintField, FingerprintSuggestion};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone)]
pub struct FingerprintStore {
    pool: PgPool,
}

impl FingerprintStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn upsert_suggestions(
        &self,
        context: SuggestionContext,
        confirmed: &ConfirmedFingerprintFacts,
        suggestions: &[FingerprintSuggestion],
    ) -> Result<Vec<FingerprintSuggestionView>, FingerprintStoreError> {
        if suggestions.is_empty() {
            return Ok(Vec::new());
        }
        let mut tx = self.pool.begin().await?;
        let mut persisted = Vec::with_capacity(suggestions.len());
        for suggestion in suggestions {
            validate_suggestion(suggestion)?;
            let state = if conflicts_with_confirmed(confirmed, suggestion) {
                SuggestionState::Conflict
            } else {
                SuggestionState::Suggested
            };
            let row = sqlx::query(
                r#"
                INSERT INTO discovery_fingerprint_suggestions (
                  discovery_run_id, organization_id, site_id, routing_domain_id,
                  address, device_id, field_name, value, source, confidence,
                  evidence_ids, state, last_seen_at
                ) VALUES ($1,$2,$3,$4,$5::inet,$6,$7,$8,$9,$10::numeric,'{}',$11,$12)
                ON CONFLICT (discovery_run_id, address, field_name, lower(value), source)
                DO UPDATE SET
                  device_id = coalesce(EXCLUDED.device_id, discovery_fingerprint_suggestions.device_id),
                  confidence = GREATEST(discovery_fingerprint_suggestions.confidence, EXCLUDED.confidence),
                  state = CASE
                    WHEN discovery_fingerprint_suggestions.state IN ('applied','rejected')
                      THEN discovery_fingerprint_suggestions.state
                    WHEN EXCLUDED.state = 'conflict' THEN 'conflict'
                    ELSE discovery_fingerprint_suggestions.state
                  END,
                  last_seen_at = GREATEST(discovery_fingerprint_suggestions.last_seen_at, EXCLUDED.last_seen_at),
                  updated_at = now()
                RETURNING id, discovery_run_id, organization_id, site_id,
                          routing_domain_id, host(address) AS address, device_id,
                          field_name, value, source, confidence::float8 AS confidence,
                          state, last_seen_at, created_at, updated_at
                "#,
            )
            .bind(context.discovery_run_id)
            .bind(context.organization_id)
            .bind(context.site_id)
            .bind(context.routing_domain_id)
            .bind(context.address.to_string())
            .bind(context.device_id)
            .bind(suggestion.field.as_str())
            .bind(&suggestion.value)
            .bind(&suggestion.source)
            .bind(suggestion.confidence.to_string())
            .bind(state.as_str())
            .bind(suggestion.last_seen)
            .fetch_one(&mut *tx)
            .await?;
            persisted.push(row_to_view(row)?);
        }
        tx.commit().await?;
        Ok(persisted)
    }

    pub async fn list_for_site(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        state: Option<SuggestionState>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<FingerprintSuggestionView>, FingerprintStoreError> {
        if !(1..=500).contains(&limit) || offset < 0 {
            return Err(FingerprintStoreError::InvalidInput);
        }
        let rows = sqlx::query(
            r#"
            SELECT id, discovery_run_id, organization_id, site_id,
                   routing_domain_id, host(address) AS address, device_id,
                   field_name, value, source, confidence::float8 AS confidence,
                   state, last_seen_at, created_at, updated_at
            FROM discovery_fingerprint_suggestions
            WHERE organization_id = $1 AND site_id = $2
              AND ($3::text IS NULL OR state = $3)
            ORDER BY CASE state WHEN 'conflict' THEN 0 WHEN 'suggested' THEN 1 ELSE 2 END,
                     last_seen_at DESC, id DESC
            LIMIT $4 OFFSET $5
            "#,
        )
        .bind(organization_id)
        .bind(site_id)
        .bind(state.map(SuggestionState::as_str))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(row_to_view).collect()
    }

    pub async fn set_review_state(
        &self,
        organization_id: Uuid,
        site_id: Uuid,
        suggestion_id: Uuid,
        next: SuggestionState,
    ) -> Result<FingerprintSuggestionView, FingerprintStoreError> {
        if !matches!(next, SuggestionState::Rejected | SuggestionState::Suggested) {
            return Err(FingerprintStoreError::InvalidReviewTransition);
        }
        let row = sqlx::query(
            r#"
            UPDATE discovery_fingerprint_suggestions
            SET state = $4, updated_at = now()
            WHERE id = $1 AND organization_id = $2 AND site_id = $3
              AND state IN ('suggested','conflict','rejected')
            RETURNING id, discovery_run_id, organization_id, site_id,
                      routing_domain_id, host(address) AS address, device_id,
                      field_name, value, source, confidence::float8 AS confidence,
                      state, last_seen_at, created_at, updated_at
            "#,
        )
        .bind(suggestion_id)
        .bind(organization_id)
        .bind(site_id)
        .bind(next.as_str())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(FingerprintStoreError::SuggestionNotFound)?;
        row_to_view(row)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SuggestionContext {
    pub discovery_run_id: Uuid,
    pub organization_id: Uuid,
    pub site_id: Uuid,
    pub routing_domain_id: Uuid,
    pub address: IpAddr,
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Clone, Default)]
pub struct ConfirmedFingerprintFacts {
    pub device_type: Option<String>,
    pub vendor: Option<String>,
    pub os_family: Option<String>,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionState {
    Suggested,
    Conflict,
    Applied,
    Rejected,
}

impl SuggestionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suggested => "suggested",
            Self::Conflict => "conflict",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintSuggestionView {
    pub id: Uuid,
    pub discovery_run_id: Uuid,
    pub organization_id: Uuid,
    pub site_id: Uuid,
    pub routing_domain_id: Uuid,
    pub address: IpAddr,
    pub device_id: Option<Uuid>,
    pub field: FingerprintField,
    pub value: String,
    pub source: String,
    pub confidence: f64,
    pub state: SuggestionState,
    pub last_seen_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn conflicts_with_confirmed(
    facts: &ConfirmedFingerprintFacts,
    suggestion: &FingerprintSuggestion,
) -> bool {
    let current = match suggestion.field {
        FingerprintField::DeviceType => facts.device_type.as_deref(),
        FingerprintField::Vendor => facts.vendor.as_deref(),
        FingerprintField::OsFamily => facts.os_family.as_deref(),
        FingerprintField::Hostname => facts.hostname.as_deref(),
    };
    current
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| !value.eq_ignore_ascii_case(suggestion.value.trim()))
}

fn validate_suggestion(suggestion: &FingerprintSuggestion) -> Result<(), FingerprintStoreError> {
    if suggestion.value.trim().is_empty()
        || suggestion.value.len() > 512
        || suggestion.source.trim().is_empty()
        || suggestion.source.len() > 120
        || !(0.0..=1.0).contains(&suggestion.confidence)
    {
        return Err(FingerprintStoreError::InvalidInput);
    }
    Ok(())
}

fn row_to_view(
    row: sqlx::postgres::PgRow,
) -> Result<FingerprintSuggestionView, FingerprintStoreError> {
    let address: String = row.try_get("address")?;
    Ok(FingerprintSuggestionView {
        id: row.try_get("id")?,
        discovery_run_id: row.try_get("discovery_run_id")?,
        organization_id: row.try_get("organization_id")?,
        site_id: row.try_get("site_id")?,
        routing_domain_id: row.try_get("routing_domain_id")?,
        address: address.parse().map_err(|_| FingerprintStoreError::InvalidStoredValue)?,
        device_id: row.try_get("device_id")?,
        field: parse_field(&row.try_get::<String, _>("field_name")?)?,
        value: row.try_get("value")?,
        source: row.try_get("source")?,
        confidence: row.try_get("confidence")?,
        state: parse_state(&row.try_get::<String, _>("state")?)?,
        last_seen_at: row.try_get("last_seen_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn parse_field(value: &str) -> Result<FingerprintField, FingerprintStoreError> {
    match value {
        "device_type" => Ok(FingerprintField::DeviceType),
        "vendor" => Ok(FingerprintField::Vendor),
        "os_family" => Ok(FingerprintField::OsFamily),
        "hostname" => Ok(FingerprintField::Hostname),
        _ => Err(FingerprintStoreError::InvalidStoredValue),
    }
}

fn parse_state(value: &str) -> Result<SuggestionState, FingerprintStoreError> {
    match value {
        "suggested" => Ok(SuggestionState::Suggested),
        "conflict" => Ok(SuggestionState::Conflict),
        "applied" => Ok(SuggestionState::Applied),
        "rejected" => Ok(SuggestionState::Rejected),
        _ => Err(FingerprintStoreError::InvalidStoredValue),
    }
}

#[derive(Debug, Error)]
pub enum FingerprintStoreError {
    #[error("fingerprint suggestion is invalid")]
    InvalidInput,
    #[error("fingerprint suggestion was not found")]
    SuggestionNotFound,
    #[error("fingerprint suggestion review transition is invalid")]
    InvalidReviewTransition,
    #[error("stored fingerprint suggestion is invalid")]
    InvalidStoredValue,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suggestion(field: FingerprintField, value: &str) -> FingerprintSuggestion {
        FingerprintSuggestion {
            field,
            value: value.into(),
            source: "test".into(),
            confidence: 0.9,
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn differing_confirmed_vendor_becomes_conflict() {
        let facts = ConfirmedFingerprintFacts {
            vendor: Some("Vendor A".into()),
            ..Default::default()
        };
        assert!(conflicts_with_confirmed(
            &facts,
            &suggestion(FingerprintField::Vendor, "Vendor B")
        ));
    }

    #[test]
    fn same_confirmed_hostname_is_not_a_conflict() {
        let facts = ConfirmedFingerprintFacts {
            hostname: Some("printer.example".into()),
            ..Default::default()
        };
        assert!(!conflicts_with_confirmed(
            &facts,
            &suggestion(FingerprintField::Hostname, "PRINTER.EXAMPLE")
        ));
    }
}
