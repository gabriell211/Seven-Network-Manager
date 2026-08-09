use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Up,
    Down,
    Degraded,
    Unknown,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    Open,
    Acknowledged,
    Resolved,
    Suppressed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation<T> {
    pub value: Option<T>,
    pub state: HealthState,
    pub observed_at_unix_ms: i64,
    pub source: String,
    pub error_code: Option<String>,
}

impl<T> Observation<T> {
    pub fn unknown(source: impl Into<String>, observed_at_unix_ms: i64, error_code: impl Into<String>) -> Self {
        Self {
            value: None,
            state: HealthState::Unknown,
            observed_at_unix_ms,
            source: source.into(),
            error_code: Some(error_code.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AlertFingerprint {
    pub organization: String,
    pub site: Option<String>,
    pub resource: String,
    pub rule: String,
    pub dimension: Option<String>,
}

impl AlertFingerprint {
    pub fn stable_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.organization,
            self.site.as_deref().unwrap_or("-"),
            self.resource,
            self.rule,
            self.dimension.as_deref().unwrap_or("-")
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionDecision {
    Deliver,
    SuppressMaintenance,
    SuppressDebounce,
}

pub fn suppression_decision(in_maintenance: bool, stable_for_samples: u16, required_samples: u16) -> SuppressionDecision {
    if in_maintenance {
        SuppressionDecision::SuppressMaintenance
    } else if stable_for_samples < required_samples {
        SuppressionDecision::SuppressDebounce
    } else {
        SuppressionDecision::Deliver
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_measurement_is_unknown_not_zero() {
        let item: Observation<u64> = Observation::unknown("snmp", 10, "unsupported");
        assert_eq!(item.state, HealthState::Unknown);
        assert!(item.value.is_none());
    }
}
