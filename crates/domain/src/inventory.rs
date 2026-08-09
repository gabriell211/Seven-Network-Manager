use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{OrganizationId, RoutingDomainId, SiteId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLifecycle {
    Discovered,
    PendingReview,
    Managed,
    Unmanaged,
    Maintenance,
    Retired,
    Archived,
}

impl DeviceLifecycle {
    pub fn allows_normal_mutation(self) -> bool {
        matches!(self, Self::Managed | Self::Maintenance)
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        matches!(
            (self, next),
            (Self::Discovered, Self::PendingReview)
                | (Self::Discovered, Self::Unmanaged)
                | (Self::Discovered, Self::Archived)
                | (Self::PendingReview, Self::Managed)
                | (Self::PendingReview, Self::Unmanaged)
                | (Self::PendingReview, Self::Archived)
                | (Self::Managed, Self::Maintenance)
                | (Self::Managed, Self::Unmanaged)
                | (Self::Managed, Self::Retired)
                | (Self::Unmanaged, Self::PendingReview)
                | (Self::Unmanaged, Self::Managed)
                | (Self::Unmanaged, Self::Retired)
                | (Self::Unmanaged, Self::Archived)
                | (Self::Maintenance, Self::Managed)
                | (Self::Maintenance, Self::Retired)
                | (Self::Retired, Self::PendingReview)
                | (Self::Retired, Self::Archived)
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::PendingReview => "pending_review",
            Self::Managed => "managed",
            Self::Unmanaged => "unmanaged",
            Self::Maintenance => "maintenance",
            Self::Retired => "retired",
            Self::Archived => "archived",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    Switch,
    Router,
    Firewall,
    Server,
    Printer,
    AccessPoint,
    Unknown,
}

impl DeviceType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Switch => "switch",
            Self::Router => "router",
            Self::Firewall => "firewall",
            Self::Server => "server",
            Self::Printer => "printer",
            Self::AccessPoint => "access_point",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence<T> {
    pub value: T,
    pub source: String,
    pub confidence: f32,
    pub observed_at_unix_ms: i64,
}

impl<T> Evidence<T> {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.source.trim().is_empty() {
            return Err("evidence source is required");
        }
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err("confidence must be between 0 and 1");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierStrength {
    Strong,
    Weak,
}

impl IdentifierStrength {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strong => "strong",
            Self::Weak => "weak",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierKind {
    Serial,
    Mac,
    Hostname,
    SnmpEngineId,
    ProviderNativeId,
    AssetTag,
}

impl IdentifierKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Serial => "serial",
            Self::Mac => "mac",
            Self::Hostname => "hostname",
            Self::SnmpEngineId => "snmp_engine_id",
            Self::ProviderNativeId => "provider_native_id",
            Self::AssetTag => "asset_tag",
        }
    }

    pub fn strength(&self) -> IdentifierStrength {
        match self {
            Self::Serial | Self::Mac | Self::SnmpEngineId | Self::ProviderNativeId => {
                IdentifierStrength::Strong
            }
            Self::Hostname | Self::AssetTag => IdentifierStrength::Weak,
        }
    }

    pub fn normalize(&self, value: &str) -> Result<String, &'static str> {
        let value = value.trim();
        if value.is_empty() {
            return Err("identifier value is required");
        }

        let normalized = match self {
            Self::Mac | Self::SnmpEngineId => value
                .chars()
                .filter(|character| character.is_ascii_hexdigit())
                .map(|character| character.to_ascii_lowercase())
                .collect(),
            Self::Hostname => value.trim_end_matches('.').to_ascii_lowercase(),
            Self::Serial | Self::ProviderNativeId | Self::AssetTag => value.to_ascii_lowercase(),
        };

        if normalized.is_empty() {
            return Err("identifier value is invalid after normalization");
        }
        Ok(normalized)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIdentifier {
    pub kind: IdentifierKind,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub id: Uuid,
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub routing_domain_id: Option<RoutingDomainId>,
    pub lifecycle: DeviceLifecycle,
    pub display_name: Option<String>,
    pub identifiers: BTreeSet<DeviceIdentifier>,
    pub vendor: Option<Evidence<String>>,
    pub model: Option<Evidence<String>>,
    pub version: u64,
}

impl DeviceRecord {
    pub fn has_stable_match_with(&self, other: &Self) -> bool {
        if self.organization_id != other.organization_id || self.site_id != other.site_id {
            return false;
        }
        self.identifiers.iter().any(|identifier| {
            matches!(
                identifier.kind,
                IdentifierKind::Serial
                    | IdentifierKind::Mac
                    | IdentifierKind::SnmpEngineId
                    | IdentifierKind::ProviderNativeId
            ) && other.identifiers.contains(identifier)
        })
    }

    pub fn can_auto_merge_with(&self, other: &Self) -> bool {
        self.has_stable_match_with(other)
            && self.lifecycle != DeviceLifecycle::Retired
            && other.lifecycle != DeviceLifecycle::Retired
            && self.lifecycle != DeviceLifecycle::Archived
            && other.lifecycle != DeviceLifecycle::Archived
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeDecision {
    SameResource,
    RequiresReview,
    DifferentResource,
}

pub fn decide_merge(left: &DeviceRecord, right: &DeviceRecord) -> MergeDecision {
    if left.can_auto_merge_with(right) {
        return MergeDecision::SameResource;
    }
    if left.organization_id == right.organization_id && left.site_id == right.site_id {
        let weak_match = left.identifiers.iter().any(|identifier| {
            matches!(
                identifier.kind,
                IdentifierKind::Hostname | IdentifierKind::AssetTag
            ) && right.identifiers.contains(identifier)
        });
        if weak_match {
            return MergeDecision::RequiresReview;
        }
    }
    MergeDecision::DifferentResource
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(serial: &str) -> DeviceRecord {
        DeviceRecord {
            id: Uuid::now_v7(),
            organization_id: OrganizationId::new(),
            site_id: SiteId::new(),
            routing_domain_id: None,
            lifecycle: DeviceLifecycle::Discovered,
            display_name: None,
            identifiers: BTreeSet::from([DeviceIdentifier {
                kind: IdentifierKind::Serial,
                value: serial.to_owned(),
            }]),
            vendor: None,
            model: None,
            version: 1,
        }
    }

    #[test]
    fn retired_device_cannot_be_auto_merged() {
        let mut left = record("A-1");
        let mut right = left.clone();
        right.id = Uuid::now_v7();
        left.lifecycle = DeviceLifecycle::Retired;
        assert!(!left.can_auto_merge_with(&right));
    }

    #[test]
    fn same_identifier_does_not_cross_organization_boundary() {
        let left = record("A-1");
        let mut right = left.clone();
        right.id = Uuid::now_v7();
        right.organization_id = OrganizationId::new();
        assert_eq!(
            decide_merge(&left, &right),
            MergeDecision::DifferentResource
        );
    }

    #[test]
    fn identifier_normalization_is_stable_across_common_formats() {
        assert_eq!(
            IdentifierKind::Mac.normalize("AA:BB:CC:00:11:22").unwrap(),
            "aabbcc001122"
        );
        assert_eq!(
            IdentifierKind::Mac.normalize("aa-bb-cc-00-11-22").unwrap(),
            "aabbcc001122"
        );
        assert_eq!(
            IdentifierKind::Hostname
                .normalize("SW-CORE.EXAMPLE.")
                .unwrap(),
            "sw-core.example"
        );
        assert_eq!(
            IdentifierKind::Serial.strength(),
            IdentifierStrength::Strong
        );
        assert_eq!(
            IdentifierKind::Hostname.strength(),
            IdentifierStrength::Weak
        );
    }

    #[test]
    fn retired_device_requires_review_before_reactivation() {
        assert!(DeviceLifecycle::Retired.can_transition_to(DeviceLifecycle::PendingReview));
        assert!(!DeviceLifecycle::Retired.can_transition_to(DeviceLifecycle::Managed));
    }

    #[test]
    fn discovery_cannot_skip_review_and_become_managed() {
        assert!(!DeviceLifecycle::Discovered.can_transition_to(DeviceLifecycle::Managed));
        assert!(DeviceLifecycle::Discovered.can_transition_to(DeviceLifecycle::PendingReview));
        assert!(DeviceLifecycle::PendingReview.can_transition_to(DeviceLifecycle::Managed));
    }
}
