use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub type SnmResult<T> = Result<T, SnmError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationId(pub Uuid);

impl CorrelationId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyKey(pub String);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ApiVersion {
    V1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEnvelope<T> {
    pub api_version: ApiVersion,
    pub correlation_id: CorrelationId,
    pub data: T,
    pub emitted_at: DateTime<Utc>,
}

impl<T> ApiEnvelope<T> {
    pub fn v1(data: T) -> Self {
        Self {
            api_version: ApiVersion::V1,
            correlation_id: CorrelationId::new(),
            data,
            emitted_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub correlation_id: CorrelationId,
}

#[derive(Debug, Error)]
pub enum SnmError {
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("resource not found: {0}")]
    NotFound(String),
    #[error("operation is not supported: {0}")]
    Unsupported(String),
    #[error("operation requires approval: {0}")]
    ApprovalRequired(String),
    #[error("trial policy blocked the operation: {0}")]
    TrialBlocked(String),
    #[error("infrastructure failure: {0}")]
    Infrastructure(String),
}
