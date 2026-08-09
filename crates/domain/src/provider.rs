use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{OrganizationId, RoutingDomainId, SiteId};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityId(pub String);

impl CapabilityId {
    pub fn parse(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_'));
        if !valid || !value.contains('.') {
            return Err("capability id must be a dotted lowercase identifier");
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportStatus {
    Supported,
    Candidate,
    Experimental,
    ReadOnly,
    Blocked,
    Deprecated,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    HttpsApi,
    Snmp,
    Ssh,
    WinRm,
    Netconf,
    Restconf,
    Gnmi,
    LocalSystem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPlacement {
    ControlPlane,
    SiteLocal,
    Either,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectivityProfileRef {
    pub id: Uuid,
    pub organization_id: OrganizationId,
    pub site_id: SiteId,
    pub routing_domain_id: Option<RoutingDomainId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCapability {
    pub provider: String,
    pub product_family: String,
    pub tested_versions: Vec<String>,
    pub capability: CapabilityId,
    pub access: AccessMode,
    pub status: SupportStatus,
    pub transports: Vec<TransportKind>,
    pub placement: ExecutionPlacement,
    pub ipv4: bool,
    pub ipv6: bool,
    pub routing_domains: bool,
    pub limitations: Vec<String>,
    pub contract_test_ref: Option<String>,
    pub lab_evidence_ref: Option<String>,
}

impl ProviderCapability {
    pub fn may_be_advertised_supported(&self) -> bool {
        self.status == SupportStatus::Supported
            && self.contract_test_ref.is_some()
            && self.lab_evidence_ref.is_some()
            && !self.tested_versions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_requires_contract_and_lab_evidence() {
        let entry = ProviderCapability {
            provider: "fixture".into(),
            product_family: "simulated".into(),
            tested_versions: vec!["1".into()],
            capability: CapabilityId::parse("interfaces.read").unwrap(),
            access: AccessMode::Read,
            status: SupportStatus::Supported,
            transports: vec![TransportKind::HttpsApi],
            placement: ExecutionPlacement::SiteLocal,
            ipv4: true,
            ipv6: true,
            routing_domains: true,
            limitations: vec![],
            contract_test_ref: Some("contract/interfaces-read".into()),
            lab_evidence_ref: None,
        };
        assert!(!entry.may_be_advertised_supported());
    }
}
