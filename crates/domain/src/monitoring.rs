use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::inventory::DeviceId;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AlertId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertState {
    Open,
    Acknowledged,
    Suppressed,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySample {
    pub device_id: DeviceId,
    pub metric: String,
    pub value: String,
    pub source: String,
    pub sampled_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: AlertId,
    pub severity: Severity,
    pub state: AlertState,
    pub title: String,
    pub evidence: String,
    pub created_at: DateTime<Utc>,
}
