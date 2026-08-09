use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand::{RngCore, rngs::OsRng};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        // Deliberately explicit and versioned in the PHC string. These values
        // can be raised over time without invalidating existing hashes.
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl PasswordPolicy {
    fn argon2(&self) -> Result<Argon2<'static>, PasswordError> {
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|_| PasswordError::InvalidPolicy)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

pub fn hash_password(password: &[u8], policy: PasswordPolicy) -> Result<String, PasswordError> {
    if password.len() < 12 || password.len() > 1024 {
        return Err(PasswordError::InvalidLength);
    }
    let mut salt_bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| PasswordError::HashFailed)?;
    policy
        .argon2()?
        .hash_password(password, &salt)
        .map(|value| value.to_string())
        .map_err(|_| PasswordError::HashFailed)
}

pub fn verify_password(password: &[u8], encoded: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(encoded).map_err(|_| PasswordError::MalformedHash)?;
    Ok(Argon2::default().verify_password(password, &parsed).is_ok())
}

pub fn needs_rehash(encoded: &str, policy: PasswordPolicy) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(encoded).map_err(|_| PasswordError::MalformedHash)?;
    if parsed.algorithm.as_str() != "argon2id" || parsed.version != Some(19) {
        return Ok(true);
    }
    let memory = parsed.params.get_decimal("m").unwrap_or(0);
    let iterations = parsed.params.get_decimal("t").unwrap_or(0);
    let parallelism = parsed.params.get_decimal("p").unwrap_or(0);
    Ok(memory != policy.memory_kib
        || iterations != policy.iterations
        || parallelism != policy.parallelism)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordError {
    #[error("password length is outside the supported range")]
    InvalidLength,
    #[error("password hashing policy is invalid")]
    InvalidPolicy,
    #[error("password hashing failed")]
    HashFailed,
    #[error("stored password hash is malformed")]
    MalformedHash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip_and_wrong_password_fail() {
        let password = b"correct horse battery staple";
        let encoded = hash_password(password, PasswordPolicy::default()).unwrap();
        assert!(encoded.starts_with("$argon2id$v=19$"));
        assert!(verify_password(password, &encoded).unwrap());
        assert!(!verify_password(b"a completely wrong password", &encoded).unwrap());
        assert!(!needs_rehash(&encoded, PasswordPolicy::default()).unwrap());
    }

    #[test]
    fn weakly_parameterized_hash_is_marked_for_rehash() {
        let weak = PasswordPolicy {
            memory_kib: 8_192,
            iterations: 1,
            parallelism: 1,
        };
        let encoded = hash_password(b"long enough password", weak).unwrap();
        assert!(needs_rehash(&encoded, PasswordPolicy::default()).unwrap());
    }
}
