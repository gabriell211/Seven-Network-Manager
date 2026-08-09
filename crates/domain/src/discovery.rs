use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{OrganizationId, RoutingDomainId, SiteId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryStatus {
    Queued,
    Running,
    Completed,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    Reachability,
    Neighbor,
    ReverseDns,
    Service,
    ManagementProtocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6DiscoveryStrategy {
    SeededTargets,
    NeighborEvidence,
    DnsEvidence,
    ProviderInventory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryScope {
    pub id: Uuid,
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub routing_domain_id: RoutingDomainId,
    pub network: IpNet,
    pub observations: Vec<ObservationKind>,
    pub ipv6_strategy: Option<Ipv6DiscoveryStrategy>,
    pub concurrency_limit: u16,
    pub rate_per_second: u16,
    pub timeout_ms: u32,
}

impl DiscoveryScope {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.concurrency_limit == 0 || self.rate_per_second == 0 || self.timeout_ms == 0 {
            return Err("discovery limits must be non-zero");
        }
        if self.network.is_ipv6() && self.network.prefix_len() <= 64 && self.ipv6_strategy.is_none()
        {
            return Err("large IPv6 scopes require an explicit evidence-based strategy");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintEvidence {
    pub field: String,
    pub value: String,
    pub source: String,
    pub confidence: f32,
}

impl FingerprintEvidence {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.field.trim().is_empty() || self.source.trim().is_empty() {
            return Err("fingerprint field/source are required");
        }
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err("confidence must be between 0 and 1");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_ipv6_scope_requires_strategy() {
        let scope = DiscoveryScope {
            id: Uuid::now_v7(),
            organization_id: OrganizationId::new(),
            site_id: SiteId::new(),
            routing_domain_id: RoutingDomainId::new(),
            network: "2001:db8::/64".parse().unwrap(),
            observations: vec![ObservationKind::Reachability],
            ipv6_strategy: None,
            concurrency_limit: 16,
            rate_per_second: 32,
            timeout_ms: 1000,
        };
        assert!(scope.validate().is_err());
    }
}
