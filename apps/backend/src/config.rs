use std::{collections::BTreeMap, env, net::SocketAddr, time::Duration};

use thiserror::Error;

#[derive(Debug, Clone)]
pub(crate) struct BackendConfig {
    pub(crate) bind: SocketAddr,
    pub(crate) runtime_url: String,
    pub(crate) database_url: String,
    pub(crate) redis_url: String,
    pub(crate) database_max_connections: u32,
    pub(crate) run_migrations: bool,
    pub(crate) request_timeout: Duration,
    pub(crate) body_limit_bytes: usize,
    pub(crate) inventory_require_approval: bool,
}

impl BackendConfig {
    pub(crate) fn from_env() -> Result<Self, ConfigError> {
        Self::from_reader(|name| env::var(name).ok())
    }

    fn from_reader(mut read: impl FnMut(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let bind = read_or_default(&mut read, "SNM_BACKEND_BIND", "127.0.0.1:8080")
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::InvalidSocketAddress("SNM_BACKEND_BIND"))?;

        let runtime_url = normalized_http_url(
            "SNM_RUNTIME_URL",
            read_or_default(&mut read, "SNM_RUNTIME_URL", "http://127.0.0.1:9765"),
        )?;
        let database_url = required(&mut read, "DATABASE_URL")?;
        require_scheme(
            "DATABASE_URL",
            &database_url,
            &["postgres://", "postgresql://"],
        )?;
        let redis_url = required(&mut read, "REDIS_URL")?;
        require_scheme("REDIS_URL", &redis_url, &["redis://", "rediss://"])?;

        let database_max_connections = parse_bounded_u32(
            &mut read,
            "SNM_DATABASE_MAX_CONNECTIONS",
            10,
            1,
            100,
        )?;
        let request_timeout_ms = parse_bounded_u64(
            &mut read,
            "SNM_REQUEST_TIMEOUT_MS",
            15_000,
            100,
            120_000,
        )?;
        let body_limit_bytes = parse_bounded_usize(
            &mut read,
            "SNM_HTTP_BODY_LIMIT_BYTES",
            1_048_576,
            1_024,
            16 * 1024 * 1024,
        )?;

        Ok(Self {
            bind,
            runtime_url,
            database_url,
            redis_url,
            database_max_connections,
            run_migrations: parse_bool(
                read("SNM_RUN_MIGRATIONS").as_deref(),
                true,
                "SNM_RUN_MIGRATIONS",
            )?,
            request_timeout: Duration::from_millis(request_timeout_ms),
            body_limit_bytes,
            inventory_require_approval: parse_bool(
                read("SNM_INVENTORY_REQUIRE_APPROVAL").as_deref(),
                true,
                "SNM_INVENTORY_REQUIRE_APPROVAL",
            )?,
        })
    }
}

fn read_or_default(
    read: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
    default: &'static str,
) -> String {
    read(name)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn required(
    read: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
) -> Result<String, ConfigError> {
    read(name)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::Missing(name))
}

fn normalized_http_url(name: &'static str, value: String) -> Result<String, ConfigError> {
    let value = value.trim().trim_end_matches('/').to_owned();
    if value.starts_with("http://") || value.starts_with("https://") {
        Ok(value)
    } else {
        Err(ConfigError::InvalidUrlScheme(name))
    }
}

fn require_scheme(
    name: &'static str,
    value: &str,
    allowed: &[&str],
) -> Result<(), ConfigError> {
    if allowed.iter().any(|scheme| value.starts_with(scheme)) {
        Ok(())
    } else {
        Err(ConfigError::InvalidUrlScheme(name))
    }
}

fn parse_bool(
    value: Option<&str>,
    default: bool,
    name: &'static str,
) -> Result<bool, ConfigError> {
    let Some(value) = value else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidBoolean(name)),
    }
}

fn parse_bounded_u32(
    read: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
    default: u32,
    min: u32,
    max: u32,
) -> Result<u32, ConfigError> {
    let value = match read(name) {
        Some(value) if !value.trim().is_empty() => value
            .trim()
            .parse::<u32>()
            .map_err(|_| ConfigError::InvalidInteger(name))?,
        _ => default,
    };
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::OutOfRange { name, min: min as u64, max: max as u64 })
    }
}

fn parse_bounded_u64(
    read: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ConfigError> {
    let value = match read(name) {
        Some(value) if !value.trim().is_empty() => value
            .trim()
            .parse::<u64>()
            .map_err(|_| ConfigError::InvalidInteger(name))?,
        _ => default,
    };
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::OutOfRange { name, min, max })
    }
}

fn parse_bounded_usize(
    read: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, ConfigError> {
    let value = match read(name) {
        Some(value) if !value.trim().is_empty() => value
            .trim()
            .parse::<usize>()
            .map_err(|_| ConfigError::InvalidInteger(name))?,
        _ => default,
    };
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::OutOfRange {
            name,
            min: min as u64,
            max: max as u64,
        })
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum ConfigError {
    #[error("missing required configuration: {0}")]
    Missing(&'static str),
    #[error("invalid socket address in {0}")]
    InvalidSocketAddress(&'static str),
    #[error("invalid URL scheme in {0}")]
    InvalidUrlScheme(&'static str),
    #[error("invalid boolean in {0}")]
    InvalidBoolean(&'static str),
    #[error("invalid integer in {0}")]
    InvalidInteger(&'static str),
    #[error("{name} must be between {min} and {max}")]
    OutOfRange {
        name: &'static str,
        min: u64,
        max: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "DATABASE_URL".to_owned(),
                "postgresql://snm:secret@127.0.0.1/snm".to_owned(),
            ),
            ("REDIS_URL".to_owned(), "redis://127.0.0.1:6379/0".to_owned()),
        ])
    }

    fn parse(values: BTreeMap<String, String>) -> Result<BackendConfig, ConfigError> {
        BackendConfig::from_reader(|name| values.get(name).cloned())
    }

    #[test]
    fn defaults_are_bounded_and_production_safe() {
        let config = parse(base()).unwrap();
        assert_eq!(config.bind, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(config.database_max_connections, 10);
        assert_eq!(config.request_timeout, Duration::from_secs(15));
        assert_eq!(config.body_limit_bytes, 1024 * 1024);
        assert!(config.run_migrations);
        assert!(config.inventory_require_approval);
    }

    #[test]
    fn malformed_boolean_fails_closed() {
        let mut values = base();
        values.insert("SNM_RUN_MIGRATIONS".into(), "sometimes".into());
        assert_eq!(
            parse(values).unwrap_err(),
            ConfigError::InvalidBoolean("SNM_RUN_MIGRATIONS")
        );
    }

    #[test]
    fn oversized_body_limit_is_rejected() {
        let mut values = base();
        values.insert("SNM_HTTP_BODY_LIMIT_BYTES".into(), (32 * 1024 * 1024).to_string());
        assert!(matches!(
            parse(values),
            Err(ConfigError::OutOfRange {
                name: "SNM_HTTP_BODY_LIMIT_BYTES",
                ..
            })
        ));
    }

    #[test]
    fn invalid_dependency_scheme_is_rejected_before_connecting() {
        let mut values = base();
        values.insert("REDIS_URL".into(), "http://127.0.0.1:6379".into());
        assert_eq!(
            parse(values).unwrap_err(),
            ConfigError::InvalidUrlScheme("REDIS_URL")
        );
    }

    #[test]
    fn runtime_url_is_normalized_once() {
        let mut values = base();
        values.insert("SNM_RUNTIME_URL".into(), "http://runtime:9765///".into());
        let config = parse(values).unwrap();
        assert_eq!(config.runtime_url, "http://runtime:9765");
    }
}
