use std::time::Duration;

use anyhow::{Context, bail};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

#[derive(Clone)]
pub struct BackendRegistry {
    client: Client,
    endpoint: String,
    token: String,
}

#[derive(Deserialize)]
struct RegistrationAck {
    agent_id: Uuid,
    server_id: Uuid,
    trap_id: Uuid,
}

impl BackendRegistry {
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let Ok(endpoint) = std::env::var("HF_CENTER_REGISTRY_URL") else { return Ok(None) };
        let token = std::env::var("HF_CENTER_POSTGRES_TELEMETRY_TOKEN")
            .context("HF_CENTER_POSTGRES_TELEMETRY_TOKEN is required with registry URL")?;
        let url = url::Url::parse(&endpoint)?;
        anyhow::ensure!(url.scheme() == "http" && url.host_str() == Some("127.0.0.1")
            && url.path() == "/internal/v1/center/traps", "registry must use local backend route");
        Ok(Some(Self { client: Client::builder().timeout(Duration::from_secs(10)).build()?, endpoint, token }))
    }

    pub async fn register(&self, agent_id: Uuid, trap_id: Uuid, target: &str,
        ssh_port: u16, tier: &str, host_port: u16) -> anyhow::Result<Uuid> {
        let body = json!({"agent_id":agent_id,"server_id":null,"trap_id":trap_id,
            "host":target,"ssh_port":ssh_port,"tier":tier,"host_port":host_port});
        let response = self.client.post(&self.endpoint).bearer_auth(&self.token)
            .json(&body).send().await?;
        if !response.status().is_success() {
            bail!("backend trap registry returned HTTP {}", response.status());
        }
        let ack: RegistrationAck = response.json().await?;
        anyhow::ensure!(ack.agent_id == agent_id && ack.trap_id == trap_id && !ack.server_id.is_nil(),
            "backend registry returned mismatched registration");
        Ok(ack.server_id)
    }

    pub async fn mark_removed(&self, agent_id: Uuid, trap_id: Uuid) -> anyhow::Result<()> {
        let endpoint = format!("{}/removed", self.endpoint);
        self.client.post(endpoint).bearer_auth(&self.token)
            .json(&json!({"agent_id":agent_id,"trap_id":trap_id}))
            .send().await?.error_for_status()?;
        Ok(())
    }
}
