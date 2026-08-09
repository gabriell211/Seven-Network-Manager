use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Internal,
    Confidential,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PurgeStrategy {
    Delete,
    Anonymize,
    ArchiveThenDelete,
    AppendOnlyPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetPolicy {
    pub dataset: String,
    pub owner: String,
    pub purpose: String,
    pub class: DataClass,
    pub retention_days: u32,
    pub purge_strategy: PurgeStrategy,
    pub legal_hold_supported: bool,
}

impl DatasetPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.dataset.trim().is_empty()
            || self.owner.trim().is_empty()
            || self.purpose.trim().is_empty()
        {
            return Err("dataset, owner and purpose are required");
        }
        if self.retention_days == 0 && self.purge_strategy != PurgeStrategy::AppendOnlyPolicy {
            return Err("non append-only datasets need an explicit positive retention");
        }
        Ok(())
    }
}

pub fn redact_value(key: &str, value: &str) -> String {
    let key = key.to_ascii_lowercase();
    let sensitive = [
        "password",
        "secret",
        "token",
        "community",
        "private_key",
        "refresh_token",
        "authorization",
        "cookie",
    ];
    if sensitive.iter().any(|needle| key.contains(needle)) {
        "[REDACTED]".to_owned()
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentinel_secret_is_redacted() {
        let sentinel = "SNM-SENTINEL-SECRET-DO-NOT-LEAK";
        assert_eq!(redact_value("snmp_community", sentinel), "[REDACTED]");
        assert_eq!(redact_value("display_name", sentinel), sentinel);
    }
}
