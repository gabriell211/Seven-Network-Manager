//! Headless execution core. It owns technical execution semantics, not HTTP,
//! user sessions, RBAC, database access, or UI concerns.

use std::{net::IpAddr, time::Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use snm_domain::{Capability, ExecutionStatus, TcpConnectRequest};
use thiserror::Error;
use tokio::{net::TcpStream, time::timeout};

#[derive(Clone, Debug)]
pub struct NetworkPolicy {
    pub allow_public_targets: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allow_public_targets: false,
        }
    }
}

impl NetworkPolicy {
    pub fn allows(&self, address: IpAddr) -> bool {
        if self.allow_public_targets {
            return !address.is_unspecified() && !address.is_multicast();
        }

        match address {
            IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
            IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unicast_link_local() || (ip.segments()[0] & 0xfe00) == 0xfc00
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TcpConnectResult {
    pub status: ExecutionStatus,
    pub latency_ms: Option<u64>,
    pub error_code: Option<String>,
}

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("execution request is invalid: {0}")]
    InvalidRequest(String),
    #[error("target is outside runtime network policy")]
    TargetDenied,
}

#[async_trait]
pub trait NetworkExecutor: Send + Sync {
    async fn tcp_connect(&self, request: TcpConnectRequest) -> Result<TcpConnectResult, ExecutorError>;
    fn capabilities(&self) -> &'static [Capability];
}

#[derive(Clone, Debug)]
pub struct DefaultNetworkExecutor {
    network_policy: NetworkPolicy,
}

impl DefaultNetworkExecutor {
    pub fn new(network_policy: NetworkPolicy) -> Self {
        Self { network_policy }
    }
}

#[async_trait]
impl NetworkExecutor for DefaultNetworkExecutor {
    async fn tcp_connect(&self, request: TcpConnectRequest) -> Result<TcpConnectResult, ExecutorError> {
        request
            .validate()
            .map_err(|error| ExecutorError::InvalidRequest(error.to_string()))?;

        if !self.network_policy.allows(request.target.address) {
            return Err(ExecutorError::TargetDenied);
        }

        let socket = (request.target.address, request.port);
        let started = Instant::now();
        let result = timeout(request.timeout(), TcpStream::connect(socket)).await;

        let response = match result {
            Ok(Ok(stream)) => {
                drop(stream);
                TcpConnectResult {
                    status: ExecutionStatus::Succeeded,
                    latency_ms: Some(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)),
                    error_code: None,
                }
            }
            Ok(Err(error)) => TcpConnectResult {
                status: ExecutionStatus::Failed,
                latency_ms: None,
                error_code: Some(match error.kind() {
                    std::io::ErrorKind::ConnectionRefused => "connection_refused",
                    std::io::ErrorKind::PermissionDenied => "permission_denied",
                    std::io::ErrorKind::NetworkUnreachable => "network_unreachable",
                    std::io::ErrorKind::HostUnreachable => "host_unreachable",
                    _ => "transport_error",
                }
                .to_owned()),
            },
            Err(_) => TcpConnectResult {
                status: ExecutionStatus::Failed,
                latency_ms: None,
                error_code: Some("timeout".to_owned()),
            },
        };

        Ok(response)
    }

    fn capabilities(&self) -> &'static [Capability] {
        const CAPABILITIES: &[Capability] = &[
            Capability::RuntimeCapabilitiesRead,
            Capability::NetworkTcpConnect,
        ];
        CAPABILITIES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_rejects_public_targets() {
        let policy = NetworkPolicy::default();
        assert!(!policy.allows("8.8.8.8".parse().unwrap()));
        assert!(policy.allows("10.0.0.1".parse().unwrap()));
        assert!(policy.allows("fd00::1".parse().unwrap()));
    }
}
