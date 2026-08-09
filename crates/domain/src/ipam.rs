use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{OrganizationId, RoutingDomainId, SiteId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressState {
    Observed,
    Available,
    Reserved,
    Assigned,
    Deprecated,
    Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopedPrefix {
    pub id: Uuid,
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub routing_domain_id: RoutingDomainId,
    pub prefix: IpNet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpAllocation {
    pub id: Uuid,
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub routing_domain_id: RoutingDomainId,
    pub interface_id: Option<Uuid>,
    pub address: IpAddr,
    pub state: AddressState,
}

impl IpAllocation {
    pub fn same_l3_identity(&self, other: &Self) -> bool {
        self.organization_id == other.organization_id
            && self.site_id == other.site_id
            && self.routing_domain_id == other.routing_domain_id
            && self.address == other.address
            && (!is_ipv6_link_local(self.address) || self.interface_id == other.interface_id)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if is_ipv6_link_local(self.address) && self.interface_id.is_none() {
            return Err("IPv6 link-local allocation requires interface scope");
        }
        Ok(())
    }
}

pub fn prefixes_conflict(left: &ScopedPrefix, right: &ScopedPrefix) -> bool {
    if left.organization_id != right.organization_id
        || left.site_id != right.site_id
        || left.routing_domain_id != right.routing_domain_id
    {
        return false;
    }
    left.prefix.contains(&right.prefix.network()) || right.prefix.contains(&left.prefix.network())
}

pub fn is_ipv6_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V6(value) => (value.segments()[0] & 0xffc0) == 0xfe80,
        IpAddr::V4(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_prefix_is_legal_in_different_routing_domains() {
        let org = OrganizationId::new();
        let site = SiteId::new();
        let left = ScopedPrefix {
            id: Uuid::now_v7(),
            organization_id: org,
            site_id: site,
            routing_domain_id: RoutingDomainId::new(),
            prefix: "10.0.0.0/24".parse().unwrap(),
        };
        let mut right = left.clone();
        right.id = Uuid::now_v7();
        right.routing_domain_id = RoutingDomainId::new();
        assert!(!prefixes_conflict(&left, &right));
    }

    #[test]
    fn overlap_conflicts_inside_same_routing_domain() {
        let org = OrganizationId::new();
        let site = SiteId::new();
        let routing_domain = RoutingDomainId::new();
        let left = ScopedPrefix {
            id: Uuid::now_v7(),
            organization_id: org,
            site_id: site,
            routing_domain_id: routing_domain,
            prefix: "10.0.0.0/24".parse().unwrap(),
        };
        let right = ScopedPrefix {
            id: Uuid::now_v7(),
            organization_id: org,
            site_id: site,
            routing_domain_id: routing_domain,
            prefix: "10.0.0.128/25".parse().unwrap(),
        };
        assert!(prefixes_conflict(&left, &right));
    }
}
