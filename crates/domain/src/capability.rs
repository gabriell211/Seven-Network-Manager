use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CapabilityKind {
    InventoryRead,
    DiscoveryRead,
    ProbePing,
    ProbeArp,
    ProbeDns,
    ProbeTcp,
    SnmpRead,
    DhcpRead,
    DhcpWrite,
    DnsRead,
    DnsWrite,
    TrialStatusRead,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CapabilityMode {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionPlacement {
    ControlPlane,
    LocalRuntime,
    RemoteSiteRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportKind {
    Internal,
    Icmp,
    Arp,
    Dns,
    Tcp,
    Snmp,
    WinRm,
    Ssh,
    Netconf,
    Restconf,
    Gnmi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityDescriptor {
    pub kind: CapabilityKind,
    pub mode: CapabilityMode,
    pub placement: ExecutionPlacement,
    pub supported_transports: Vec<TransportKind>,
    pub requires_approval: bool,
    pub requires_snapshot: bool,
}

pub fn foundation_capabilities() -> Vec<CapabilityDescriptor> {
    vec![
        CapabilityDescriptor {
            kind: CapabilityKind::TrialStatusRead,
            mode: CapabilityMode::Read,
            placement: ExecutionPlacement::ControlPlane,
            supported_transports: vec![TransportKind::Internal],
            requires_approval: false,
            requires_snapshot: false,
        },
        CapabilityDescriptor {
            kind: CapabilityKind::InventoryRead,
            mode: CapabilityMode::Read,
            placement: ExecutionPlacement::ControlPlane,
            supported_transports: vec![TransportKind::Internal],
            requires_approval: false,
            requires_snapshot: false,
        },
        CapabilityDescriptor {
            kind: CapabilityKind::ProbePing,
            mode: CapabilityMode::Read,
            placement: ExecutionPlacement::LocalRuntime,
            supported_transports: vec![TransportKind::Icmp],
            requires_approval: false,
            requires_snapshot: false,
        },
        CapabilityDescriptor {
            kind: CapabilityKind::SnmpRead,
            mode: CapabilityMode::Read,
            placement: ExecutionPlacement::LocalRuntime,
            supported_transports: vec![TransportKind::Snmp],
            requires_approval: false,
            requires_snapshot: false,
        },
    ]
}
