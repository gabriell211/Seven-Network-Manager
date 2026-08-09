use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use snm_domain::{CapabilityKind, ExecutionPlacement, RoutingDomainId};
use snm_shared::{SnmError, SnmResult};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub request_id: Uuid,
    pub capability: CapabilityKind,
    pub placement: ExecutionPlacement,
    pub routing_domain_id: RoutingDomainId,
    pub target: ExecutionTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTarget {
    pub host: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionState {
    Succeeded,
    Failed,
    Unsupported,
    Partial,
    Unknown,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub request_id: Uuid,
    pub state: ExecutionState,
    pub message: String,
    pub completed_at: DateTime<Utc>,
}

#[async_trait]
pub trait CapabilityExecutor: Send + Sync {
    async fn execute(&self, request: ExecutionRequest) -> SnmResult<ExecutionResult>;
}

#[derive(Debug, Default)]
pub struct LocalRuntimeExecutor;

#[async_trait]
impl CapabilityExecutor for LocalRuntimeExecutor {
    async fn execute(&self, request: ExecutionRequest) -> SnmResult<ExecutionResult> {
        if request.placement != ExecutionPlacement::LocalRuntime {
            return Err(SnmError::Unsupported(
                "local runtime only accepts LocalRuntime placement".to_string(),
            ));
        }

        Ok(ExecutionResult {
            request_id: request.request_id,
            state: ExecutionState::Unknown,
            message: "provider not bound yet; foundation contract accepted request".to_string(),
            completed_at: Utc::now(),
        })
    }
}
