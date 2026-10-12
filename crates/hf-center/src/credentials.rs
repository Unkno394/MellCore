use std::{collections::HashMap, fs, io::Write, path::PathBuf};

use uuid::Uuid;

/// Serialized only under AppState's mutex; publish the file before accepting credentials.
#[derive(Default)]
pub(crate) struct CredentialStore {
    path: Option<PathBuf>,
    entries: HashMap<Uuid, String>,
}

impl CredentialStore {
    pub(crate) fn open(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let entries = match path.as_ref().map(fs::read) {
            Some(Ok(bytes)) => serde_json::from_slice(&bytes)?,
            Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Some(Err(error)) => return Err(error.into()),
            None => HashMap::new(),
        };
        Ok(Self { path, entries })
    }

    pub(crate) fn get(&self, agent_id: &Uuid) -> Option<&String> {
        self.entries.get(agent_id)
    }

    pub(crate) fn authenticate(&self, credential: &str) -> Option<Uuid> {
        self.entries
            .iter()
            .find_map(|(id, value)| (value == credential).then_some(*id))
    }

    pub(crate) fn insert(&mut self, agent_id: Uuid, credential: String) -> anyhow::Result<()> {
        let mut next = self.entries.clone();
        next.insert(agent_id, credential);
        self.persist(next)
    }

    pub(crate) fn remove(&mut self, agent_id: &Uuid) -> anyhow::Result<bool> {
        let mut next = self.entries.clone();
        if next.remove(agent_id).is_none() {
            return Ok(false);
        }
        self.persist(next)?;
        Ok(true)
    }

    fn persist(&mut self, next: HashMap<Uuid, String>) -> anyhow::Result<()> {
        if let Some(path) = &self.path {
            let temporary = path.with_extension("tmp");
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&serde_json::to_vec(&next)?)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
        }
        self.entries = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_survive_restart_and_failed_writes_do_not_authorize() {
        let dir = std::env::temp_dir().join(format!("hf-credentials-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("credentials.json");
        let agent = Uuid::new_v4();
        let mut store = CredentialStore::open(Some(path.clone())).unwrap();
        store.insert(agent, "transport-secret".into()).unwrap();
        let restored = CredentialStore::open(Some(path)).unwrap();
        assert_eq!(restored.authenticate("transport-secret"), Some(agent));
        assert_eq!(restored.authenticate("wrong"), None);
        let mut restored = restored;
        assert!(restored.remove(&agent).unwrap());
        assert_eq!(
            CredentialStore::open(Some(dir.join("credentials.json")))
                .unwrap()
                .get(&agent),
            None
        );
        assert!(!restored.remove(&agent).unwrap());
        let mut broken = CredentialStore::open(Some(dir.join("missing/credentials.json"))).unwrap();
        assert!(broken.insert(agent, "not-persisted".into()).is_err());
        assert_eq!(broken.authenticate("not-persisted"), None);
        let vanished = dir.join("vanished");
        fs::create_dir(&vanished).unwrap();
        let mut stored = CredentialStore::open(Some(vanished.join("credentials.json"))).unwrap();
        stored.insert(agent, "still-authorized".into()).unwrap();
        fs::remove_dir_all(vanished).unwrap();
        assert!(stored.remove(&agent).is_err());
        assert_eq!(stored.authenticate("still-authorized"), Some(agent));
        fs::remove_dir_all(dir).unwrap();
    }
}
