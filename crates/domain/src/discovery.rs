use std::net::IpAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    DomainError, ExecutionContext, ExecutionStatus, OrganizationId, RoutingDomainId, ScopedIpTarget,
    SiteId,
};

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

impl DiscoveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
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

impl ObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reachability => "reachability",
            Self::Neighbor => "neighbor",
            Self::ReverseDns => "reverse_dns",
            Self::Service => "service",
            Self::ManagementProtocol => "management_protocol",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryProbeKind {
    Icmp,
    Arp,
    ReverseDns,
    Tcp,
}

impl DiscoveryProbeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Arp => "arp",
            Self::ReverseDns => "reverse_dns",
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6DiscoveryStrategy {
    SeededTargets,
    NeighborEvidence,
    DnsEvidence,
    ProviderInventory,
}

impl Ipv6DiscoveryStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SeededTargets => "seeded_targets",
            Self::NeighborEvidence => "neighbor_evidence",
            Self::DnsEvidence => "dns_evidence",
            Self::ProviderInventory => "provider_inventory",
        }
    }
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
        if self.concurrency_limit > 4096 || self.rate_per_second > 65_535 {
            return Err("discovery limits exceed supported bounds");
        }
        if self.timeout_ms < 100 || self.timeout_ms > 30_000 {
            return Err("discovery timeout must be between 100 and 30000 milliseconds");
        }
        if self.observations.is_empty() {
            return Err("discovery scope requires at least one observation kind");
        }
        if matches!(&self.network, IpNet::V6(_))
            && self.network.prefix_len() <= 64
            && self.ipv6_strategy.is_none()
        {
            return Err("large IPv6 scopes require an explicit evidence-based strategy");
        }
        Ok(())
    }
}

/// Scope copied into every runtime probe envelope. The runtime validates this
/// independently from the control plane so a compromised/misconfigured caller
/// cannot silently turn a discovery scope into unrestricted egress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryExecutionScope {
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub routing_domain_id: RoutingDomainId,
    pub network: IpNet,
    pub interface_scope: Option<String>,
    pub source_address: Option<IpAddr>,
}

impl DiscoveryExecutionScope {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self
            .interface_scope
            .as_ref()
            .is_some_and(|value| value.trim().is_empty() || value.len() > 128)
        {
            return Err(DomainError::InvalidInterfaceScope);
        }
        if let Some(source) = self.source_address {
            if source.is_unspecified() || source.is_multicast() {
                return Err(DomainError::InvalidTargetAddress(source));
            }
            if !same_family(self.network, source) {
                return Err(DomainError::AddressFamilyMismatch);
            }
        }
        Ok(())
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        self.network.contains(&address)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryProbeRequest {
    pub context: ExecutionContext,
    pub scope: DiscoveryExecutionScope,
    pub target: ScopedIpTarget,
    pub probe: DiscoveryProbeKind,
    pub port: Option<u16>,
    pub timeout_ms: u64,
}

impl DiscoveryProbeRequest {
    pub fn validate(&self) -> Result<(), DomainError> {
        self.target.validate()?;
        self.scope.validate()?;
        if self.context.organization_id != self.target.organization_id
            || self.context.site_id != self.target.site_id
            || self.context.routing_domain_id != self.target.routing_domain_id
            || self.scope.organization_id != self.target.organization_id
            || self.scope.site_id != self.target.site_id
            || self.scope.routing_domain_id != self.target.routing_domain_id
        {
            return Err(DomainError::ExecutionScopeMismatch);
        }
        if !self.scope.contains(self.target.address) {
            return Err(DomainError::TargetOutsideAuthorizedScope);
        }
        if is_ipv4_network_or_broadcast(self.scope.network, self.target.address) {
            return Err(DomainError::InvalidDiscoveryTarget);
        }
        if !(100..=30_000).contains(&self.timeout_ms) {
            return Err(DomainError::InvalidExecutionTimeout);
        }
        match self.probe {
            DiscoveryProbeKind::Tcp => {
                if self.port.is_none_or(|port| port == 0) {
                    return Err(DomainError::InvalidPort);
                }
            }
            DiscoveryProbeKind::Arp => {
                if self.port.is_some() {
                    return Err(DomainError::UnexpectedProbePort);
                }
                if !matches!(self.target.address, IpAddr::V4(_)) {
                    return Err(DomainError::ProbeNotApplicable);
                }
                let Some(source) = self.scope.source_address else {
                    return Err(DomainError::MissingProbeSourceAddress);
                };
                if !matches!(source, IpAddr::V4(_)) {
                    return Err(DomainError::AddressFamilyMismatch);
                }
                if self
                    .scope
                    .interface_scope
                    .as_deref()
                    .is_none_or(str::is_empty)
                {
                    return Err(DomainError::InvalidInterfaceScope);
                }
            }
            DiscoveryProbeKind::Icmp | DiscoveryProbeKind::ReverseDns => {
                if self.port.is_some() {
                    return Err(DomainError::UnexpectedProbePort);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeEvidence {
    pub field: String,
    pub value: String,
    pub source: String,
    pub confidence: f32,
    pub observed_at: DateTime<Utc>,
}

impl ProbeEvidence {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.field.trim().is_empty()
            || self.field.len() > 120
            || self.source.trim().is_empty()
            || self.source.len() > 120
            || self.value.len() > 4096
        {
            return Err("probe evidence field/value/source is invalid");
        }
        if !(0.0..=1.0).contains(&self.confidence) {
            return Err("confidence must be between 0 and 1");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryProbeResult {
    pub status: ExecutionStatus,
    pub probe: DiscoveryProbeKind,
    pub target: ScopedIpTarget,
    pub port: Option<u16>,
    pub latency_ms: Option<u64>,
    pub evidence: Vec<ProbeEvidence>,
    pub error_code: Option<String>,
}

impl DiscoveryProbeResult {
    pub fn validate_for(&self, request: &DiscoveryProbeRequest) -> Result<(), DomainError> {
        if self.probe != request.probe
            || self.target != request.target
            || self.port != request.port
            || self.evidence.iter().any(|item| item.validate().is_err())
        {
            return Err(DomainError::ExecutionResponseMismatch);
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
    pub last_seen: DateTime<Utc>,
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

fn same_family(network: IpNet, address: IpAddr) -> bool {
    matches!((network, address), (IpNet::V4(_), IpAddr::V4(_)) | (IpNet::V6(_), IpAddr::V6(_)))
}

pub fn is_ipv4_network_or_broadcast(network: IpNet, address: IpAddr) -> bool {
    let (IpNet::V4(network), IpAddr::V4(address)) = (network, address) else {
        return false;
    };
    if network.prefix_len() >= 31 {
        return false;
    }
    address == network.network() || address == network.broadcast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActionId, ActorId, CorrelationId};

    fn request(network: &str, target: &str, probe: DiscoveryProbeKind) -> DiscoveryProbeRequest {
        let organization_id = OrganizationId::new();
        let site_id = SiteId::new();
        let routing_domain_id = RoutingDomainId::new();
        let address = target.parse().unwrap();
        DiscoveryProbeRequest {
            context: ExecutionContext {
                organization_id,
                site_id,
                routing_domain_id,
                actor_id: ActorId::new(),
                correlation_id: CorrelationId::new(),
                action_id: ActionId::new(),
                idempotency_key: None,
            },
            scope: DiscoveryExecutionScope {
                organization_id,
                site_id,
                routing_domain_id,
                network: network.parse().unwrap(),
                interface_scope: None,
                source_address: None,
            },
            target: ScopedIpTarget {
                organization_id,
                site_id,
                routing_domain_id,
                address,
                interface_scope: None,
            },
            probe,
            port: None,
            timeout_ms: 1000,
        }
    }

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

    #[test]
    fn target_outside_scope_is_rejected() {
        let request = request("10.0.0.0/24", "10.0.1.10", DiscoveryProbeKind::Icmp);
        assert!(matches!(
            request.validate(),
            Err(DomainError::TargetOutsideAuthorizedScope)
        ));
    }

    #[test]
    fn ipv4_network_and_broadcast_are_rejected_but_point_to_point_is_valid() {
        assert!(matches!(
            request("10.0.0.0/24", "10.0.0.0", DiscoveryProbeKind::Icmp).validate(),
            Err(DomainError::InvalidDiscoveryTarget)
        ));
        assert!(matches!(
            request("10.0.0.0/24", "10.0.0.255", DiscoveryProbeKind::Icmp).validate(),
            Err(DomainError::InvalidDiscoveryTarget)
        ));
        assert!(request("10.0.0.0/31", "10.0.0.0", DiscoveryProbeKind::Icmp)
            .validate()
            .is_ok());
    }

    #[test]
    fn arp_requires_real_interface_and_source_context() {
        let request = request("10.0.0.0/24", "10.0.0.10", DiscoveryProbeKind::Arp);
        assert!(matches!(
            request.validate(),
            Err(DomainError::MissingProbeSourceAddress)
        ));
    }
}
