use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

type HmacSha1 = Hmac<Sha1>;

pub const TOTP_STEP_SECONDS: i64 = 30;
pub const TOTP_DIGITS: u32 = 6;

pub fn generate_secret() -> [u8; 20] {
    let mut secret = [0_u8; 20];
    OsRng.fill_bytes(&mut secret);
    secret
}

pub fn code_at(secret: &[u8], unix_seconds: i64) -> Result<u32, TotpError> {
    if secret.len() < 20 {
        return Err(TotpError::WeakSecret);
    }
    if unix_seconds < 0 {
        return Err(TotpError::InvalidTime);
    }
    let counter = (unix_seconds / TOTP_STEP_SECONDS) as u64;
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| TotpError::WeakSecret)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(binary % 10_u32.pow(TOTP_DIGITS))
}

pub fn verify_code(secret: &[u8], code: &str, unix_seconds: i64) -> Result<bool, TotpError> {
    if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(false);
    }
    for offset in [-TOTP_STEP_SECONDS, 0, TOTP_STEP_SECONDS] {
        let candidate_time = unix_seconds.saturating_add(offset);
        if candidate_time < 0 {
            continue;
        }
        let expected = format!("{:06}", code_at(secret, candidate_time)?);
        if bool::from(expected.as_bytes().ct_eq(code.as_bytes())) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub struct RecoveryCodeSet {
    codes: Vec<Zeroizing<String>>,
    pub hashes: Vec<[u8; 32]>,
}

impl RecoveryCodeSet {
    pub fn expose_once(&self) -> impl Iterator<Item = &str> {
        self.codes.iter().map(|code| code.as_str())
    }
}

impl Drop for RecoveryCodeSet {
    fn drop(&mut self) {
        for code in &mut self.codes {
            code.zeroize();
        }
    }
}

pub fn issue_recovery_codes(count: usize) -> Result<RecoveryCodeSet, TotpError> {
    if !(4..=20).contains(&count) {
        return Err(TotpError::InvalidRecoveryCodeCount);
    }
    let mut codes = Vec::with_capacity(count);
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        let code = Zeroizing::new(URL_SAFE_NO_PAD.encode(random));
        random.zeroize();
        hashes.push(Sha256::digest(code.as_bytes()).into());
        codes.push(code);
    }
    Ok(RecoveryCodeSet { codes, hashes })
}

pub fn recovery_code_matches(code: &[u8], expected_hash: &[u8; 32]) -> bool {
    let actual: [u8; 32] = Sha256::digest(code).into();
    bool::from(actual.ct_eq(expected_hash))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TotpError {
    #[error("TOTP secret must contain at least 160 bits")]
    WeakSecret,
    #[error("TOTP time is invalid")]
    InvalidTime,
    #[error("recovery code count must be between 4 and 20")]
    InvalidRecoveryCodeCount,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_vector_matches_dynamic_truncation() {
        let secret = b"12345678901234567890";
        assert_eq!(code_at(secret, 59).unwrap(), 287_082);
    }

    #[test]
    fn verification_accepts_small_clock_skew_and_rejects_wrong_code() {
        let secret = b"12345678901234567890";
        let code = format!("{:06}", code_at(secret, 60).unwrap());
        assert!(verify_code(secret, &code, 89).unwrap());
        assert!(!verify_code(secret, "000000", 89).unwrap());
    }

    #[test]
    fn recovery_codes_are_stored_as_hashes() {
        let codes = issue_recovery_codes(8).unwrap();
        let first = codes.expose_once().next().unwrap().as_bytes().to_vec();
        assert!(recovery_code_matches(&first, &codes.hashes[0]));
        assert!(!recovery_code_matches(
            b"not-a-recovery-code",
            &codes.hashes[0]
        ));
    }
}
