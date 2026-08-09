use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routing::{OrganizationId, RoutingDomainId, SiteId};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct PrefixId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prefix {
    pub id: PrefixId,
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub routing_domain_id: RoutingDomainId,
    pub cidr: String,
    pub ip_version: IpVersion,
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AddressState {
    Available,
    Reserved,
    Assigned,
    Conflict,
    Deprecated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressLease {
    pub address: String,
    pub state: AddressState,
    pub source: String,
    pub evidence: Option<String>,
}
