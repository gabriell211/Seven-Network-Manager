use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;
const ACCESS_TOKEN_CLOCK_SKEW_SECONDS: i64 = 60;
const ACCESS_TOKEN_MAX_LIFETIME_SECONDS: i64 = 15 * 60;

#[derive(Clone)]
pub struct AccessTokenKey(Zeroizing<Vec<u8>>);

impl AccessTokenKey {
    pub fn new(secret: Vec<u8>) -> Result<Self, TokenError> {
        if secret.len() < 32 {
            return Err(TokenError::WeakSigningKey);
        }
        Ok(Self(Zeroizing::new(secret)))
    }

    fn mac(&self) -> Result<HmacSha256, TokenError> {
        HmacSha256::new_from_slice(self.0.as_slice()).map_err(|_| TokenError::InvalidSigningKey)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessClaims {
    pub iss: String,
    pub aud: String,
    pub sub: Uuid,
    pub org: Uuid,
    pub sid: Uuid,
    pub jti: Uuid,
    pub scopes: Vec<String>,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtHeader {
    alg: String,
    typ: String,
}

pub fn encode_access_token(
    claims: &AccessClaims,
    key: &AccessTokenKey,
) -> Result<String, TokenError> {
    validate_claim_lifetime(claims)?;
    let header = JwtHeader {
        alg: "HS256".to_owned(),
        typ: "JWT".to_owned(),
    };
    let encoded_header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|_| TokenError::SerializationFailed)?,
    );
    let encoded_claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(claims).map_err(|_| TokenError::SerializationFailed)?,
    );
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let mut mac = key.mac()?;
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{signing_input}.{signature}"))
}

pub fn decode_access_token(
    token: &str,
    key: &AccessTokenKey,
    now_unix_seconds: i64,
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<AccessClaims, TokenError> {
    if token.len() > 16_384 {
        return Err(TokenError::MalformedToken);
    }
    let mut parts = token.split('.');
    let header_part = parts.next().ok_or(TokenError::MalformedToken)?;
    let claims_part = parts.next().ok_or(TokenError::MalformedToken)?;
    let signature_part = parts.next().ok_or(TokenError::MalformedToken)?;
    if parts.next().is_some() {
        return Err(TokenError::MalformedToken);
    }

    let signature = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| TokenError::MalformedToken)?;
    let signing_input = format!("{header_part}.{claims_part}");
    let mut mac = key.mac()?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| TokenError::InvalidSignature)?;

    let header: JwtHeader = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header_part)
            .map_err(|_| TokenError::MalformedToken)?,
    )
    .map_err(|_| TokenError::MalformedToken)?;
    if header.alg != "HS256" || header.typ != "JWT" {
        return Err(TokenError::UnsupportedTokenAlgorithm);
    }

    let claims: AccessClaims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(claims_part)
            .map_err(|_| TokenError::MalformedToken)?,
    )
    .map_err(|_| TokenError::MalformedToken)?;

    if claims.iss != expected_issuer || claims.aud != expected_audience {
        return Err(TokenError::InvalidContext);
    }
    validate_claim_lifetime(&claims)?;
    if claims.exp <= now_unix_seconds
        || claims.nbf > now_unix_seconds.saturating_add(ACCESS_TOKEN_CLOCK_SKEW_SECONDS)
        || claims.iat > now_unix_seconds.saturating_add(ACCESS_TOKEN_CLOCK_SKEW_SECONDS)
    {
        return Err(TokenError::ExpiredOrNotYetValid);
    }
    Ok(claims)
}

fn validate_claim_lifetime(claims: &AccessClaims) -> Result<(), TokenError> {
    if claims.iat < 0
        || claims.nbf < claims.iat.saturating_sub(ACCESS_TOKEN_CLOCK_SKEW_SECONDS)
        || claims.exp <= claims.nbf
        || claims.exp <= claims.iat
        || claims.exp.saturating_sub(claims.iat) > ACCESS_TOKEN_MAX_LIFETIME_SECONDS
    {
        return Err(TokenError::InvalidLifetime);
    }
    Ok(())
}

pub struct IssuedOpaqueToken {
    secret: Zeroizing<String>,
    pub prefix: String,
    pub hash: [u8; 32],
}

impl IssuedOpaqueToken {
    pub fn expose_once(&self) -> &str {
        self.secret.as_str()
    }
}

impl Drop for IssuedOpaqueToken {
    fn drop(&mut self) {
        self.prefix.zeroize();
    }
}

pub fn issue_opaque_token(prefix: &str) -> Result<IssuedOpaqueToken, TokenError> {
    if prefix.is_empty()
        || prefix.len() > 16
        || !prefix
            .bytes()
            .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == b'_')
    {
        return Err(TokenError::InvalidPrefix);
    }
    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    let encoded = URL_SAFE_NO_PAD.encode(random);
    random.zeroize();
    let secret = Zeroizing::new(format!("{prefix}_{encoded}"));
    let hash = hash_opaque_token(secret.as_bytes());
    let visible_prefix = secret.chars().take(prefix.len() + 9).collect();
    Ok(IssuedOpaqueToken {
        secret,
        prefix: visible_prefix,
        hash,
    })
}

pub fn hash_opaque_token(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

pub fn opaque_token_matches(token: &[u8], expected_hash: &[u8; 32]) -> bool {
    let actual = hash_opaque_token(token);
    let mut mac = HmacSha256::new_from_slice(b"snm-token-hash-compare")
        .expect("constant HMAC key is valid");
    mac.update(&actual);
    let left = mac.clone().finalize().into_bytes();
    let mut right_mac = HmacSha256::new_from_slice(b"snm-token-hash-compare")
        .expect("constant HMAC key is valid");
    right_mac.update(expected_hash);
    right_mac.verify_slice(&left).is_ok()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("access token signing key must contain at least 256 bits")]
    WeakSigningKey,
    #[error("access token signing key is invalid")]
    InvalidSigningKey,
    #[error("token lifetime is invalid")]
    InvalidLifetime,
    #[error("token serialization failed")]
    SerializationFailed,
    #[error("token is malformed")]
    MalformedToken,
    #[error("token signature is invalid")]
    InvalidSignature,
    #[error("token algorithm/type is unsupported")]
    UnsupportedTokenAlgorithm,
    #[error("token issuer or audience is invalid")]
    InvalidContext,
    #[error("token is expired or not yet valid")]
    ExpiredOrNotYetValid,
    #[error("opaque token prefix is invalid")]
    InvalidPrefix,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AccessTokenKey {
        AccessTokenKey::new(vec![0x5a; 32]).unwrap()
    }

    fn claims() -> AccessClaims {
        AccessClaims {
            iss: "snm".into(),
            aud: "snm-api".into(),
            sub: Uuid::now_v7(),
            org: Uuid::now_v7(),
            sid: Uuid::now_v7(),
            jti: Uuid::now_v7(),
            scopes: vec!["devices.view".into()],
            iat: 1_000,
            nbf: 1_000,
            exp: 1_600,
        }
    }

    #[test]
    fn access_token_round_trip_and_tamper_detection() {
        let encoded = encode_access_token(&claims(), &key()).unwrap();
        let decoded = decode_access_token(&encoded, &key(), 1_100, "snm", "snm-api").unwrap();
        assert_eq!(decoded.aud, "snm-api");

        let mut tampered = encoded.into_bytes();
        let index = tampered.len() - 2;
        tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
        assert_eq!(
            decode_access_token(&tampered, &key(), 1_100, "snm", "snm-api").unwrap_err(),
            TokenError::InvalidSignature
        );
    }

    #[test]
    fn token_is_rejected_before_nbf() {
        let mut value = claims();
        value.nbf = 1_300;
        let encoded = encode_access_token(&value, &key()).unwrap();
        assert_eq!(
            decode_access_token(&encoded, &key(), 1_100, "snm", "snm-api").unwrap_err(),
            TokenError::ExpiredOrNotYetValid
        );
    }

    #[test]
    fn opaque_token_is_single_reveal_material_with_hash_for_storage() {
        let token = issue_opaque_token("snm_sa").unwrap();
        assert!(token.expose_once().starts_with("snm_sa_"));
        assert!(opaque_token_matches(token.expose_once().as_bytes(), &token.hash));
        assert!(!opaque_token_matches(b"wrong", &token.hash));
    }
}
