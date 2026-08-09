use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routing::{OrganizationId, RoutingDomainId, SiteId};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DeviceId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceLifecycleState {
    Discovered,
    Managed,
    Retired,
    Merged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceConfidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentityEvidence {
    pub source: String,
    pub value: String,
    pub confidence: EvidenceConfidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub routing_domain_id: RoutingDomainId,
    pub display_name: String,
    pub lifecycle_state: DeviceLifecycleState,
    pub evidence: Vec<DeviceIdentityEvidence>,
}
