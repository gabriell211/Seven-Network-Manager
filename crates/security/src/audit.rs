use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use snm_domain::governance::redact_value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Succeeded,
    Failed,
    Denied,
    Partial,
    Unknown,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventDraft {
    pub organization_id: Uuid,
    pub site_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub source_ip: Option<String>,
    pub request_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub provider: Option<String>,
    pub occurred_at_unix_ms: i64,
    pub duration_ms: Option<u64>,
    pub status: AuditStatus,
    pub reason_code: Option<String>,
    pub before: Option<Value>,
    pub after: Option<Value>,
    pub result: Option<Value>,
}

impl AuditEventDraft {
    pub fn sanitize(mut self) -> Self {
        self.before = self.before.map(sanitize_json);
        self.after = self.after.map(sanitize_json);
        self.result = self.result.map(sanitize_json);
        self
    }

    pub fn seal(self, previous_hash: Option<[u8; 32]>) -> Result<SealedAuditEvent, AuditError> {
        let sanitized = self.sanitize();
        let payload =
            serde_json::to_vec(&sanitized).map_err(|_| AuditError::SerializationFailed)?;
        let mut hasher = Sha256::new();
        hasher.update(b"snm:audit:v1\0");
        if let Some(previous) = previous_hash {
            hasher.update(previous);
        }
        hasher.update(&payload);
        let event_hash: [u8; 32] = hasher.finalize().into();
        Ok(SealedAuditEvent {
            event: sanitized,
            previous_hash,
            event_hash,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedAuditEvent {
    pub event: AuditEventDraft,
    pub previous_hash: Option<[u8; 32]>,
    pub event_hash: [u8; 32],
}

impl SealedAuditEvent {
    pub fn verify(&self) -> Result<bool, AuditError> {
        let recomputed = self.event.clone().seal(self.previous_hash)?;
        Ok(recomputed.event_hash == self.event_hash)
    }
}

fn sanitize_json(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let marker = redact_value(&key, "SNM-SENTINEL");
                    if marker == "[REDACTED]" {
                        (key, Value::String("[REDACTED]".to_owned()))
                    } else {
                        (key, sanitize_json(value))
                    }
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(sanitize_json).collect()),
        other => other,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuditError {
    #[error("audit event serialization failed")]
    SerializationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn draft() -> AuditEventDraft {
        AuditEventDraft {
            organization_id: Uuid::now_v7(),
            site_id: None,
            actor_id: Some(Uuid::now_v7()),
            session_id: Some(Uuid::now_v7()),
            source_ip: Some("127.0.0.1".into()),
            request_id: "req-1".into(),
            action: "credentials.update".into(),
            resource_type: "credential_profile".into(),
            resource_id: Some("cred-1".into()),
            provider: None,
            occurred_at_unix_ms: 100,
            duration_ms: Some(4),
            status: AuditStatus::Succeeded,
            reason_code: None,
            before: Some(json!({"username":"admin","password":"old-secret"})),
            after: Some(json!({"username":"admin","password":"new-secret"})),
            result: Some(json!({"token":"secret-token","ok":true})),
        }
    }

    #[test]
    fn secret_fields_are_redacted_before_hashing() {
        let sealed = draft().seal(None).unwrap();
        let serialized = serde_json::to_string(&sealed.event).unwrap();
        assert!(!serialized.contains("old-secret"));
        assert!(!serialized.contains("new-secret"));
        assert!(!serialized.contains("secret-token"));
        assert!(serialized.contains("[REDACTED]"));
        assert!(sealed.verify().unwrap());
    }

    #[test]
    fn chain_detects_tampering() {
        let first = draft().seal(None).unwrap();
        let mut second = draft().seal(Some(first.event_hash)).unwrap();
        second.event.action = "tampered.action".into();
        assert!(!second.verify().unwrap());
    }
}
