use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::routing::{RoutingDomainId, SiteId};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct DiscoveryRunId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryRunState {
    Planned,
    Running,
    Completed,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryScope {
    pub site_id: SiteId,
    pub routing_domain_id: RoutingDomainId,
    pub cidrs: Vec<String>,
    pub include_arp: bool,
    pub include_dns: bool,
    pub include_tcp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryRun {
    pub id: DiscoveryRunId,
    pub scope: DiscoveryScope,
    pub state: DiscoveryRunState,
    pub discovered_count: u32,
}
