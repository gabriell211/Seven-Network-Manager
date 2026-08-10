use serde::{Deserialize, Serialize};

use crate::{
    DomainError, ExecutionContext,
    discovery::{DiscoveryProbeRequest, DiscoveryProbeResult},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveryProbeResponse {
    pub context: ExecutionContext,
    pub result: DiscoveryProbeResult,
}

impl DiscoveryProbeResponse {
    pub fn validate_for(&self, request: &DiscoveryProbeRequest) -> Result<(), DomainError> {
        if self.context != request.context {
            return Err(DomainError::ExecutionResponseMismatch);
        }
        self.result.validate_for(request)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::{
        ActionId, ActorId, CorrelationId, ExecutionStatus, OrganizationId, RoutingDomainId,
        ScopedIpTarget, SiteId,
        discovery::{
            DiscoveryExecutionScope, DiscoveryProbeKind, DiscoveryProbeRequest,
            DiscoveryProbeResult,
        },
    };

    use super::*;

    fn request() -> DiscoveryProbeRequest {
        let organization_id = OrganizationId::new();
        let site_id = SiteId::new();
        let routing_domain_id = RoutingDomainId::new();
        let context = ExecutionContext {
            organization_id,
            site_id,
            routing_domain_id,
            actor_id: ActorId::new(),
            correlation_id: CorrelationId::new(),
            action_id: ActionId::new(),
            idempotency_key: None,
        };
        let address: IpAddr = "10.0.0.10".parse().unwrap();
        DiscoveryProbeRequest {
            context,
            scope: DiscoveryExecutionScope {
                organization_id,
                site_id,
                routing_domain_id,
                network: "10.0.0.0/24".parse().unwrap(),
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
            probe: DiscoveryProbeKind::Icmp,
            port: None,
            timeout_ms: 1000,
        }
    }

    #[test]
    fn mismatched_action_or_correlation_is_rejected() {
        let request = request();
        let mut response = DiscoveryProbeResponse {
            context: request.context.clone(),
            result: DiscoveryProbeResult {
                status: ExecutionStatus::Succeeded,
                probe: request.probe,
                target: request.target.clone(),
                port: request.port,
                latency_ms: Some(1),
                evidence: Vec::new(),
                error_code: None,
            },
        };
        assert!(response.validate_for(&request).is_ok());
        response.context.action_id = ActionId::new();
        assert!(matches!(
            response.validate_for(&request),
            Err(DomainError::ExecutionResponseMismatch)
        ));
    }
}
