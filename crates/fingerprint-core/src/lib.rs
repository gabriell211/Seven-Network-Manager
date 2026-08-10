use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use snm_domain::discovery::ProbeEvidence;
use thiserror::Error;

const BUNDLED_OUI: &str = include_str!("../../../data/oui/ieee.csv");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuiAssignment {
    pub prefix: u64,
    pub bits: u8,
    pub organization: String,
    pub registry: String,
}

#[derive(Debug, Clone, Default)]
pub struct OuiRegistry {
    by_bits: BTreeMap<u8, BTreeMap<u64, OuiAssignment>>,
}

impl OuiRegistry {
    pub fn bundled() -> Result<Self, FingerprintError> {
        Self::from_compact_csv(BUNDLED_OUI)
    }

    pub fn from_compact_csv(input: &str) -> Result<Self, FingerprintError> {
        let mut registry = Self::default();
        for (index, line) in input.lines().enumerate() {
            if index == 0 {
                if line.trim() != "prefix,bits,organization,registry" {
                    return Err(FingerprintError::InvalidOuiSnapshot);
                }
                continue;
            }
            if line.trim().is_empty() {
                continue;
            }
            let fields = parse_csv_line(line)?;
            if fields.len() != 4 {
                return Err(FingerprintError::InvalidOuiSnapshot);
            }
            let prefix_hex = fields[0].trim();
            let bits = fields[1]
                .trim()
                .parse::<u8>()
                .map_err(|_| FingerprintError::InvalidOuiSnapshot)?;
            if !matches!(bits, 24 | 28 | 36) {
                return Err(FingerprintError::InvalidOuiSnapshot);
            }
            let prefix = u64::from_str_radix(prefix_hex, 16)
                .map_err(|_| FingerprintError::InvalidOuiSnapshot)?;
            let organization = fields[2].trim().to_owned();
            let registry_name = fields[3].trim().to_owned();
            if organization.is_empty() || registry_name.is_empty() {
                return Err(FingerprintError::InvalidOuiSnapshot);
            }
            registry.by_bits.entry(bits).or_default().insert(
                prefix,
                OuiAssignment {
                    prefix,
                    bits,
                    organization,
                    registry: registry_name,
                },
            );
        }
        Ok(registry)
    }

    pub fn lookup(&self, mac: &str) -> Option<&OuiAssignment> {
        let mac = parse_mac(mac)?;
        for bits in [36_u8, 28, 24] {
            let prefix = mac >> (48 - bits);
            if let Some(assignment) = self.by_bits.get(&bits).and_then(|map| map.get(&prefix)) {
                return Some(assignment);
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool {
        self.by_bits.values().all(BTreeMap::is_empty)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintSuggestion {
    pub field: FingerprintField,
    pub value: String,
    pub source: String,
    pub confidence: f32,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintField {
    DeviceType,
    Vendor,
    OsFamily,
    Hostname,
}

impl FingerprintField {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceType => "device_type",
            Self::Vendor => "vendor",
            Self::OsFamily => "os_family",
            Self::Hostname => "hostname",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceHint {
    pub port: u16,
    pub source: String,
    pub confidence: f32,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintClassification {
    pub suggestions: Vec<FingerprintSuggestion>,
    pub service_hints: Vec<ServiceHint>,
}

pub fn classify(
    evidence: &[ProbeEvidence],
    oui: &OuiRegistry,
) -> Result<FingerprintClassification, FingerprintError> {
    let mut classification = FingerprintClassification::default();
    let mut best_hostname: Option<&ProbeEvidence> = None;
    let mut best_mac: Option<&ProbeEvidence> = None;

    for item in evidence {
        item.validate().map_err(FingerprintError::InvalidEvidence)?;
        match item.field.as_str() {
            "hostname" => {
                if best_hostname.is_none_or(|current| current.confidence < item.confidence) {
                    best_hostname = Some(item);
                }
            }
            "mac" => {
                if best_mac.is_none_or(|current| current.confidence < item.confidence) {
                    best_mac = Some(item);
                }
            }
            "service.port" => {
                if let Ok(port) = item.value.parse::<u16>()
                    && port > 0
                {
                    classification.service_hints.push(ServiceHint {
                        port,
                        source: item.source.clone(),
                        confidence: item.confidence.min(0.90),
                        last_seen: item.observed_at,
                    });
                }
            }
            _ => {}
        }
    }

    if let Some(item) = best_mac
        && let Some(assignment) = oui.lookup(&item.value)
    {
        classification.suggestions.push(FingerprintSuggestion {
            field: FingerprintField::Vendor,
            value: assignment.organization.clone(),
            source: format!("ieee_oui:{}:{}", assignment.registry, item.source),
            confidence: item.confidence.min(0.98),
            last_seen: item.observed_at,
        });
    }

    if let Some(item) = best_hostname {
        let hostname = normalize_hostname(&item.value)?;
        classification.suggestions.push(FingerprintSuggestion {
            field: FingerprintField::Hostname,
            value: hostname,
            source: item.source.clone(),
            confidence: item.confidence.min(0.70),
            last_seen: item.observed_at,
        });
    }

    classification
        .service_hints
        .sort_by_key(|hint| (hint.port, hint.source.clone()));
    classification.service_hints.dedup_by(|left, right| {
        left.port == right.port && left.source == right.source
    });
    classification.suggestions.sort_by(|left, right| {
        left.field
            .as_str()
            .cmp(right.field.as_str())
            .then_with(|| left.value.cmp(&right.value))
    });
    Ok(classification)
}

fn normalize_hostname(value: &str) -> Result<String, FingerprintError> {
    let hostname = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(FingerprintError::InvalidHostname);
    }
    Ok(hostname)
}

fn parse_mac(value: &str) -> Option<u64> {
    let compact = value
        .chars()
        .filter(|character| character.is_ascii_hexdigit())
        .collect::<String>();
    if compact.len() != 12 {
        return None;
    }
    let value = u64::from_str_radix(&compact, 16).ok()?;
    let first_octet = (value >> 40) as u8;
    if first_octet & 0x01 != 0 || first_octet & 0x02 != 0 {
        return None;
    }
    Some(value)
}

fn parse_csv_line(line: &str) -> Result<Vec<String>, FingerprintError> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '"' if quoted && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => {
                fields.push(current);
                current = String::new();
            }
            other => current.push(other),
        }
    }
    if quoted {
        return Err(FingerprintError::InvalidOuiSnapshot);
    }
    fields.push(current);
    Ok(fields)
}

#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("versioned IEEE OUI snapshot is invalid")]
    InvalidOuiSnapshot,
    #[error("fingerprint evidence is invalid: {0}")]
    InvalidEvidence(&'static str),
    #[error("hostname evidence is invalid")]
    InvalidHostname,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(field: &str, value: &str, source: &str, confidence: f32) -> ProbeEvidence {
        ProbeEvidence {
            field: field.into(),
            value: value.into(),
            source: source.into(),
            confidence,
            observed_at: Utc::now(),
        }
    }

    fn registry() -> OuiRegistry {
        OuiRegistry::from_compact_csv(
            "prefix,bits,organization,registry\n001122,24,Example Networks,MA-L\n0011223,28,Example Division,MA-M\n001122334,36,Example Appliance,MA-S\n",
        )
        .unwrap()
    }

    #[test]
    fn longest_registered_mac_prefix_wins() {
        let registry = registry();
        assert_eq!(
            registry.lookup("00:11:22:33:44:55").unwrap().organization,
            "Example Appliance"
        );
        assert_eq!(
            registry.lookup("00:11:22:3f:44:55").unwrap().organization,
            "Example Division"
        );
        assert_eq!(
            registry.lookup("00:11:22:ff:44:55").unwrap().organization,
            "Example Networks"
        );
    }

    #[test]
    fn locally_administered_mac_never_matches_public_oui() {
        let registry = registry();
        assert!(registry.lookup("02:11:22:33:44:55").is_none());
    }

    #[test]
    fn open_ports_never_invent_os_model_or_device_type() {
        let classification = classify(
            &[
                evidence("service.port", "22", "tcp_connect", 0.85),
                evidence("service.port", "9100", "tcp_connect", 0.85),
            ],
            &registry(),
        )
        .unwrap();
        assert!(classification.suggestions.is_empty());
        assert_eq!(classification.service_hints.len(), 2);
    }

    #[test]
    fn mac_and_reverse_dns_produce_only_supported_suggestions() {
        let classification = classify(
            &[
                evidence("mac", "00:11:22:33:44:55", "arp", 1.0),
                evidence("hostname", "Printer-01.EXAMPLE.", "reverse_dns", 0.65),
            ],
            &registry(),
        )
        .unwrap();
        assert!(classification.suggestions.iter().any(|item| {
            item.field == FingerprintField::Vendor && item.value == "Example Appliance"
        }));
        assert!(classification.suggestions.iter().any(|item| {
            item.field == FingerprintField::Hostname && item.value == "printer-01.example"
        }));
        assert!(!classification
            .suggestions
            .iter()
            .any(|item| matches!(item.field, FingerprintField::OsFamily | FingerprintField::DeviceType)));
    }
}
