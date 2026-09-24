use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::domain::{SCHEMA_VERSION, Server};

pub struct StaticCatalog {
    catalog_path: PathBuf,
    secrets_root: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogFile {
    schema_version: u32,
    servers: Vec<CatalogServer>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogServer {
    id: String,
    country: String,
    #[serde(default)]
    city: String,
    name: String,
    #[serde(default)]
    features: Vec<String>,
    config_file: String,
}

impl StaticCatalog {
    pub fn new(catalog_path: impl Into<PathBuf>, secrets_root: impl Into<PathBuf>) -> Self {
        Self {
            catalog_path: catalog_path.into(),
            secrets_root: secrets_root.into(),
        }
    }

    pub fn list(&self) -> Result<Vec<Server>> {
        let content = fs::read(&self.catalog_path).context("read static catalog")?;
        let catalog: CatalogFile =
            serde_json::from_slice(&content).context("decode static catalog")?;
        if catalog.schema_version != SCHEMA_VERSION {
            bail!("unsupported catalog schema {}", catalog.schema_version);
        }
        let mut seen = HashSet::new();
        let mut servers = Vec::with_capacity(catalog.servers.len());
        for server in catalog.servers {
            if server.id.is_empty()
                || server.country.is_empty()
                || server.name.is_empty()
                || server.config_file.is_empty()
            {
                bail!("catalog server requires id, country, name, and configFile");
            }
            let config_path = Path::new(&server.config_file);
            if config_path.is_absolute()
                || config_path
                    .components()
                    .any(|component| !matches!(component, Component::Normal(_)))
            {
                bail!("server {:?} has unsafe configFile", server.id);
            }
            if !seen.insert(server.id.clone()) {
                bail!("duplicate server ID {:?}", server.id);
            }
            servers.push(Server {
                id: server.id,
                country: server.country,
                city: server.city,
                name: server.name,
                load: None,
                features: server.features,
                config_file: self
                    .secrets_root
                    .join(config_path)
                    .to_string_lossy()
                    .into_owned(),
            });
        }
        servers.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(servers)
    }

    pub fn resolve(&self, server_id: &str) -> Result<Server> {
        let server = self
            .list()?
            .into_iter()
            .find(|server| server.id == server_id)
            .ok_or_else(|| anyhow::anyhow!("unknown server {server_id:?}"))?;
        fs::metadata(&server.config_file)
            .with_context(|| format!("server {server_id:?} transport file"))?;
        Ok(server)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal() {
        let directory = tempfile::tempdir().unwrap();
        let catalog_path = directory.path().join("catalog.json");
        fs::write(
            &catalog_path,
            r#"{"schemaVersion":1,"servers":[{"id":"bad","country":"CH","name":"Bad","configFile":"../secret"}]}"#,
        )
        .unwrap();
        let error = StaticCatalog::new(catalog_path, directory.path())
            .list()
            .unwrap_err();
        assert!(error.to_string().contains("unsafe configFile"));
    }
}
