use serde::Deserialize;
use std::{
    fs, io,
    net::IpAddr,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub bind_address: IpAddr,
    pub port: u16,
    pub banner: String,
    pub trap_id: Uuid,
    /// Optional persistent SSH host key. When omitted, a key is generated in memory.
    pub host_key_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: IpAddr::from([127, 0, 0, 1]),
            port: 2222,
            banner: "SSH-2.0-OpenSSH_9.6".into(),
            // Stable development identity. Assign a unique UUID per deployed trap.
            trap_id: Uuid::from_u128(0x9a8a8262_556b_43c4_a73f_736c32556721),
            host_key_path: None,
        }
    }
}

impl Config {
    pub fn from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        let config: Self = serde_json::from_slice(&fs::read(path)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> io::Result<()> {
        // Leave room for CRLF in the 255-byte SSH identification line.
        if self.banner.is_empty()
            || self.banner.len() > 253
            || !self.banner.bytes().all(|byte| (32..=126).contains(&byte))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "banner must contain 1–253 printable ASCII bytes, without CR/LF",
            ));
        }
        if self.trap_id.is_nil() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trap_id must be a non-nil UUID",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_local_and_valid() {
        let config: Config = serde_json::from_str("{}").unwrap();
        config.validate().unwrap();
        assert!(config.bind_address.is_loopback());
        assert_eq!(config.port, 2222);
    }

    #[test]
    fn configuration_overrides_defaults() {
        let config: Config = serde_json::from_str(
            r#"{"port":2022,"banner":"SSH-2.0-HoneyForge","trap_id":"75f0660d-962a-40e0-b5ab-15c0b097a29a"}"#,
        ).unwrap();
        config.validate().unwrap();
        assert_eq!(config.port, 2022);
        assert_eq!(config.banner, "SSH-2.0-HoneyForge");
        assert_eq!(
            config.trap_id.to_string(),
            "75f0660d-962a-40e0-b5ab-15c0b097a29a"
        );
    }

    #[test]
    fn invalid_config_is_rejected() {
        assert!(serde_json::from_str::<Config>(r#"{"trap_id":"invalid"}"#).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"port":70000}"#).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"prot":2222}"#).is_err());
        for banner in [
            "".into(),
            "SSH-2.0-test\r\ninjected".into(),
            "x".repeat(254),
        ] {
            assert!(
                Config {
                    banner,
                    ..Config::default()
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            Config {
                trap_id: Uuid::nil(),
                ..Config::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn server_identity_cannot_be_supplied_by_trap_config() {
        let result = serde_json::from_str::<Config>(
            r#"{"server_id":"75f0660d-962a-40e0-b5ab-15c0b097a29a"}"#,
        );
        let error = result.unwrap_err().to_string();
        assert!(error.contains("unknown field `server_id`"), "{error}");
    }
}
