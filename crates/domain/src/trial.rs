use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialState {
    Inactive,
    Active,
    Expiring,
    Expired,
    Converted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrialPolicy {
    pub max_devices: u32,
    pub max_sites: u16,
    pub max_admin_users: u16,
    pub allow_read_capabilities: bool,
    pub allow_low_risk_mutations: bool,
    pub allow_critical_mutations: bool,
}

impl Default for TrialPolicy {
    fn default() -> Self {
        Self {
            max_devices: 100,
            max_sites: 3,
            max_admin_users: 3,
            allow_read_capabilities: true,
            allow_low_risk_mutations: false,
            allow_critical_mutations: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrialLicense {
    pub id: Uuid,
    pub installation_id: Uuid,
    pub state: TrialState,
    pub starts_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub policy: TrialPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialAction {
    Read,
    LowRiskMutation,
    CriticalMutation,
    CreateDevice,
    CreateSite,
    CreateAdminUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrialUsage {
    pub devices: u32,
    pub sites: u16,
    pub admin_users: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialDecision {
    Allow,
    DenyExpired,
    DenyPolicy,
    DenyLimit,
}

impl TrialLicense {
    pub fn effective_state(&self, now_unix_ms: i64, expiring_window_ms: i64) -> TrialState {
        if self.state == TrialState::Converted {
            return TrialState::Converted;
        }
        if now_unix_ms >= self.expires_at_unix_ms {
            return TrialState::Expired;
        }
        if now_unix_ms >= self.expires_at_unix_ms.saturating_sub(expiring_window_ms) {
            return TrialState::Expiring;
        }
        TrialState::Active
    }

    pub fn decide(
        &self,
        action: TrialAction,
        usage: TrialUsage,
        now_unix_ms: i64,
    ) -> TrialDecision {
        if self.effective_state(now_unix_ms, 0) == TrialState::Converted {
            return TrialDecision::Allow;
        }
        if now_unix_ms >= self.expires_at_unix_ms {
            return if action == TrialAction::Read {
                TrialDecision::Allow
            } else {
                TrialDecision::DenyExpired
            };
        }
        match action {
            TrialAction::Read => {
                if self.policy.allow_read_capabilities {
                    TrialDecision::Allow
                } else {
                    TrialDecision::DenyPolicy
                }
            }
            TrialAction::LowRiskMutation => {
                if self.policy.allow_low_risk_mutations {
                    TrialDecision::Allow
                } else {
                    TrialDecision::DenyPolicy
                }
            }
            TrialAction::CriticalMutation => {
                if self.policy.allow_critical_mutations {
                    TrialDecision::Allow
                } else {
                    TrialDecision::DenyPolicy
                }
            }
            TrialAction::CreateDevice => {
                if usage.devices < self.policy.max_devices {
                    TrialDecision::Allow
                } else {
                    TrialDecision::DenyLimit
                }
            }
            TrialAction::CreateSite => {
                if usage.sites < self.policy.max_sites {
                    TrialDecision::Allow
                } else {
                    TrialDecision::DenyLimit
                }
            }
            TrialAction::CreateAdminUser => {
                if usage.admin_users < self.policy.max_admin_users {
                    TrialDecision::Allow
                } else {
                    TrialDecision::DenyLimit
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expired_trial_keeps_read_access_but_blocks_mutation() {
        let license = TrialLicense {
            id: Uuid::now_v7(),
            installation_id: Uuid::now_v7(),
            state: TrialState::Active,
            starts_at_unix_ms: 0,
            expires_at_unix_ms: 100,
            policy: TrialPolicy::default(),
        };
        let usage = TrialUsage {
            devices: 0,
            sites: 0,
            admin_users: 0,
        };
        assert_eq!(
            license.decide(TrialAction::Read, usage, 101),
            TrialDecision::Allow
        );
        assert_eq!(
            license.decide(TrialAction::LowRiskMutation, usage, 101),
            TrialDecision::DenyExpired
        );
    }
}
