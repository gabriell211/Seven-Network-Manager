use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRisk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeState {
    Planned,
    AwaitingApproval,
    Approved,
    Running,
    Paused,
    PartiallySucceeded,
    Succeeded,
    Failed,
    RolledBack,
    Unknown,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePlan {
    pub id: Uuid,
    pub action: String,
    pub target_fingerprint: String,
    pub input_fingerprint: String,
    pub provider_version: String,
    pub risk: ChangeRisk,
    pub dry_run: bool,
    pub rollback_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub plan_id: Uuid,
    pub approver_id: Uuid,
    pub target_fingerprint: String,
    pub input_fingerprint: String,
    pub provider_version: String,
    pub approved_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
}

impl Approval {
    pub fn is_valid_for(&self, plan: &ChangePlan, now_unix_ms: i64) -> bool {
        self.plan_id == plan.id
            && self.target_fingerprint == plan.target_fingerprint
            && self.input_fingerprint == plan.input_fingerprint
            && self.provider_version == plan.provider_version
            && now_unix_ms < self.expires_at_unix_ms
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetOutcome {
    Succeeded,
    Failed,
    RolledBack,
    Unknown,
    NotAttempted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetResult {
    pub target_id: String,
    pub outcome: TargetOutcome,
    pub confirmed: bool,
    pub error_code: Option<String>,
}

pub fn summarize_targets(results: &[TargetResult]) -> ChangeState {
    if results.is_empty() {
        return ChangeState::Failed;
    }
    if results
        .iter()
        .any(|item| item.outcome == TargetOutcome::Unknown || !item.confirmed)
    {
        return ChangeState::Unknown;
    }
    let succeeded = results
        .iter()
        .filter(|item| item.outcome == TargetOutcome::Succeeded)
        .count();
    let failed = results
        .iter()
        .filter(|item| item.outcome == TargetOutcome::Failed)
        .count();
    if succeeded == results.len() {
        ChangeState::Succeeded
    } else if failed == results.len() {
        ChangeState::Failed
    } else {
        ChangeState::PartiallySucceeded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_is_invalidated_when_plan_changes() {
        let plan = ChangePlan {
            id: Uuid::now_v7(),
            action: "vlans.write".into(),
            target_fingerprint: "target-a".into(),
            input_fingerprint: "input-a".into(),
            provider_version: "1".into(),
            risk: ChangeRisk::High,
            dry_run: false,
            rollback_supported: true,
        };
        let approval = Approval {
            plan_id: plan.id,
            approver_id: Uuid::now_v7(),
            target_fingerprint: plan.target_fingerprint.clone(),
            input_fingerprint: "different-input".into(),
            provider_version: plan.provider_version.clone(),
            approved_at_unix_ms: 100,
            expires_at_unix_ms: 1000,
        };
        assert!(!approval.is_valid_for(&plan, 200));
    }

    #[test]
    fn unconfirmed_remote_state_never_becomes_success() {
        let state = summarize_targets(&[TargetResult {
            target_id: "a".into(),
            outcome: TargetOutcome::Succeeded,
            confirmed: false,
            error_code: None,
        }]);
        assert_eq!(state, ChangeState::Unknown);
    }
}
