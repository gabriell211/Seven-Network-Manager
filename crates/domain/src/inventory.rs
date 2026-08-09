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
}
