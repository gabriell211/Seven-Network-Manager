//! Core domain primitives shared by the control plane and execution runtime.
//! This crate intentionally has no dependency on HTTP frameworks, databases,
//! vendor SDKs, transports, or presentation code.

pub mod change_control;
pub mod discovery;
pub mod governance;
pub mod inventory;
pub mod ipam;
pub mod monitoring;
pub mod provider;
pub mod trial;

use std::{fmt, net::IpAddr, str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

macro_rules! typed_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

typed_id!(OrganizationId);
typed_id!(SiteId);
typed_id!(RoutingDomainId);
typed_id!(DeviceId);
typed_id!(ActorId);
typed_id!(CorrelationId);
typed_id!(ActionId);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RoutingDomainRef {
    pub id: RoutingDomainId,
    pub name: String,
}

impl RoutingDomainRef {
    pub fn new(name: impl Into<String>) -> Result<Self, DomainError> {
        let name = name.into();
        if name.trim().is_empty() {
            return Err(DomainError::InvalidRoutingDomainName);
        }
        Ok(Self {
            id: RoutingDomainId::new(),
            name,
        })
    }
}

/// A network endpoint is never identified by its IP address alone.
/// Organization/site/routing-domain scope is carried explicitly so overlapping
/// RFC1918/ULA address space remains legitimate and unambiguous.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScopedIpTarget {
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub routing_domain_id: RoutingDomainId,
    pub address: IpAddr,
    pub interface_scope: Option<String>,
}

impl ScopedIpTarget {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.address.is_unspecified() || self.address.is_multicast() {
            return Err(DomainError::InvalidTargetAddress(self.address));
        }

        if let IpAddr::V6(ip) = self.address {
            if ip.is_unicast_link_local()
                && self.interface_scope.as_deref().unwrap_or("").is_empty()
            {
                return Err(DomainError::MissingIpv6LinkLocalScope);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    RuntimeCapabilitiesRead,
    NetworkTcpConnect,
    NetworkIcmpEcho,
    NetworkArpResolve,
    NetworkReverseDns,
}

impl Capability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RuntimeCapabilitiesRead => "runtime.capabilities.read",
            Self::NetworkTcpConnect => "network.tcp.connect",
            Self::NetworkIcmpEcho => "network.icmp.echo",
            Self::NetworkArpResolve => "network.arp.resolve",
            Self::NetworkReverseDns => "network.dns.reverse",
        }
    }
}

impl FromStr for Capability {
    type Err = DomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "runtime.capabilities.read" => Ok(Self::RuntimeCapabilitiesRead),
            "network.tcp.connect" => Ok(Self::NetworkTcpConnect),
            "network.icmp.echo" => Ok(Self::NetworkIcmpEcho),
            "network.arp.resolve" => Ok(Self::NetworkArpResolve),
            "network.dns.reverse" => Ok(Self::NetworkReverseDns),
            other => Err(DomainError::UnsupportedCapability(other.to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Succeeded,
    Failed,
    Partial,
    Unknown,
    Cancelled,
    Unsupported,
    NotApplicable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionContext {
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub routing_domain_id: RoutingDomainId,
    pub actor_id: ActorId,
    pub correlation_id: CorrelationId,
    pub action_id: ActionId,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TcpConnectRequest {
    pub context: ExecutionContext,
    pub target: ScopedIpTarget,
    pub port: u16,
    pub timeout_ms: u64,
}

impl TcpConnectRequest {
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.clamp(100, 30_000))
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        self.target.validate()?;
        if self.port == 0 {
            return Err(DomainError::InvalidPort);
        }
        if self.target.organization_id != self.context.organization_id
            || self.target.site_id != self.context.site_id
            || self.target.routing_domain_id != self.context.routing_domain_id
        {
            return Err(DomainError::ExecutionScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("routing domain name cannot be empty")]
    InvalidRoutingDomainName,
    #[error("invalid target address: {0}")]
    InvalidTargetAddress(IpAddr),
    #[error("IPv6 link-local target requires interface scope")]
    MissingIpv6LinkLocalScope,
    #[error("port must be greater than zero")]
    InvalidPort,
    #[error("execution target scope does not match the execution context")]
    ExecutionScopeMismatch,
    #[error("target is outside the authorized discovery scope")]
    TargetOutsideAuthorizedScope,
    #[error("network/broadcast address is not a valid discovery target")]
    InvalidDiscoveryTarget,
    #[error("execution timeout is outside supported bounds")]
    InvalidExecutionTimeout,
    #[error("probe port is not valid for this probe type")]
    UnexpectedProbePort,
    #[error("probe requires an authorized source address")]
    MissingProbeSourceAddress,
    #[error("interface scope is invalid or missing")]
    InvalidInterfaceScope,
    #[error("address family does not match the authorized scope")]
    AddressFamilyMismatch,
    #[error("probe is not applicable to this target/context")]
    ProbeNotApplicable,
    #[error("runtime response does not match the execution request")]
    ExecutionResponseMismatch,
    #[error("unsupported capability: {0}")]
    UnsupportedCapability(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_ip_is_valid_in_distinct_routing_domains() {
        let organization_id = OrganizationId::new();
        let site_id = SiteId::new();
        let ip = "10.0.0.1".parse().unwrap();

        let first = ScopedIpTarget {
            organization_id,
            site_id,
            routing_domain_id: RoutingDomainId::new(),
            address: ip,
            interface_scope: None,
        };
        let second = ScopedIpTarget {
            organization_id,
            site_id,
            routing_domain_id: RoutingDomainId::new(),
            address: ip,
            interface_scope: None,
        };

        assert_ne!(first.routing_domain_id, second.routing_domain_id);
        assert_eq!(first.address, second.address);
        assert!(first.validate().is_ok());
        assert!(second.validate().is_ok());
    }

    #[test]
    fn ipv6_link_local_requires_interface_scope() {
        let target = ScopedIpTarget {
            organization_id: OrganizationId::new(),
            site_id: SiteId::new(),
            routing_domain_id: RoutingDomainId::new(),
            address: "fe80::1".parse().unwrap(),
            interface_scope: None,
        };

        assert!(matches!(
            target.validate(),
            Err(DomainError::MissingIpv6LinkLocalScope)
        ));
    }
}
