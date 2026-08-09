use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct InstallationId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrialState {
    NotActivated,
    Active,
    Expiring,
    Expired,
    Converted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialLimits {
    pub max_devices: u32,
    pub max_sites: u32,
    pub max_admin_users: u32,
    pub allow_write_capabilities: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialUsage {
    pub devices: u32,
    pub sites: u32,
    pub admin_users: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialStatus {
    pub installation_id: InstallationId,
    pub state: TrialState,
    pub started_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub limits: TrialLimits,
    pub usage: TrialUsage,
}

impl TrialStatus {
    pub fn local_development() -> Self {
        Self {
            installation_id: InstallationId(Uuid::new_v4()),
            state: TrialState::NotActivated,
            started_at: None,
            expires_at: None,
            limits: TrialLimits {
                max_devices: 25,
                max_sites: 1,
                max_admin_users: 2,
                allow_write_capabilities: false,
            },
            usage: TrialUsage {
                devices: 0,
                sites: 0,
                admin_users: 0,
            },
        }
    }
}
