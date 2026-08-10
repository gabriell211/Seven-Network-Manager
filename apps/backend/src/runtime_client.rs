use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::StatusCode;
use snm_domain::{
    ExecutionStatus,
    discovery::{DiscoveryProbeRequest, DiscoveryProbeResult},
    runtime_contract::DiscoveryProbeResponse,
};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeHealth {
    Ready,
    Unavailable,
}

#[derive(Debug, Error)]
pub(crate) enum RuntimeError {
    #[error("site runtime is unavailable")]
    Unavailable,
    #[error("site runtime authentication failed")]
    AuthenticationFailed,
    #[error("site runtime rejected the execution request")]
    RequestRejected,
    #[error("site runtime returned an invalid response identity")]
    ResponseIdentityMismatch,
    #[error("site runtime returned an invalid response")]
    InvalidResponse,
}

#[async_trait]
pub(crate) trait RuntimePort: Send + Sync {
    async fn health(&self) -> RuntimeHealth;
    async fn discovery_probe(
        &self,
        request: DiscoveryProbeRequest,
    ) -> Result<DiscoveryProbeResult, RuntimeError>;
}

#[derive(Clone)]
pub(crate) struct HttpRuntimeClient {
    client: reqwest::Client,
    base_url: Arc<str>,
    token: Arc<str>,
}

impl HttpRuntimeClient {
    pub(crate) fn new(base_url: String, token: String) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(1))
                .timeout(Duration::from_secs(35))
                .build()?,
            base_url: Arc::from(base_url),
            token: Arc::from(token),
        })
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

#[async_trait]
impl RuntimePort for HttpRuntimeClient {
    async fn health(&self) -> RuntimeHealth {
        match self.client.get(self.endpoint("/health")).send().await {
            Ok(response) if response.status().is_success() => RuntimeHealth::Ready,
            _ => RuntimeHealth::Unavailable,
        }
    }

    async fn discovery_probe(
        &self,
        request: DiscoveryProbeRequest,
    ) -> Result<DiscoveryProbeResult, RuntimeError> {
        let response = self
            .client
            .post(self.endpoint("/v1/execute/discovery-probe"))
            .bearer_auth(self.token.as_ref())
            .header("x-request-id", request.context.action_id.to_string())
            .header(
                "x-correlation-id",
                request.context.correlation_id.to_string(),
            )
            .json(&request)
            .send()
            .await
            .map_err(|_| RuntimeError::Unavailable)?;
        match response.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(RuntimeError::AuthenticationFailed);
            }
            StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST => {
                return Err(RuntimeError::RequestRejected);
            }
            status if !status.is_success() => return Err(RuntimeError::Unavailable),
            _ => {}
        }
        let envelope = response
            .json::<DiscoveryProbeResponse>()
            .await
            .map_err(|_| RuntimeError::InvalidResponse)?;
        envelope
            .validate_for(&request)
            .map_err(|_| RuntimeError::ResponseIdentityMismatch)?;
        Ok(envelope.result)
    }
}

pub(crate) fn runtime_failure_result(
    request: &DiscoveryProbeRequest,
    error: &RuntimeError,
) -> DiscoveryProbeResult {
    let (status, code) = match error {
        RuntimeError::Unavailable => (ExecutionStatus::Unknown, "runtime_unavailable"),
        RuntimeError::AuthenticationFailed => {
            (ExecutionStatus::Unknown, "runtime_authentication_failed")
        }
        RuntimeError::RequestRejected => (ExecutionStatus::Unknown, "runtime_request_rejected"),
        RuntimeError::ResponseIdentityMismatch => (
            ExecutionStatus::Unknown,
            "runtime_response_identity_mismatch",
        ),
        RuntimeError::InvalidResponse => (ExecutionStatus::Unknown, "runtime_invalid_response"),
    };
    DiscoveryProbeResult {
        status,
        probe: request.probe,
        target: request.target.clone(),
        port: request.port,
        latency_ms: None,
        evidence: Vec::new(),
        error_code: Some(code.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use snm_domain::{
        ActionId, ActorId, CorrelationId, ExecutionContext, OrganizationId, RoutingDomainId,
        ScopedIpTarget, SiteId,
        discovery::{DiscoveryExecutionScope, DiscoveryProbeKind},
    };

    use super::*;

    #[test]
    fn runtime_unavailable_never_becomes_success() {
        let organization_id = OrganizationId::new();
        let site_id = SiteId::new();
        let routing_domain_id = RoutingDomainId::new();
        let target: IpAddr = "10.0.0.10".parse().unwrap();
        let request = DiscoveryProbeRequest {
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
                network: "10.0.0.0/24".parse().unwrap(),
                interface_scope: None,
                source_address: None,
            },
            target: ScopedIpTarget {
                organization_id,
                site_id,
                routing_domain_id,
                address: target,
                interface_scope: None,
            },
            probe: DiscoveryProbeKind::Icmp,
            port: None,
            timeout_ms: 1000,
        };
        let result = runtime_failure_result(&request, &RuntimeError::Unavailable);
        assert_eq!(result.status, ExecutionStatus::Unknown);
        assert_eq!(result.error_code.as_deref(), Some("runtime_unavailable"));
    }
}
