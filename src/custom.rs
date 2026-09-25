//! WireGuard configurations imported by hand, from any provider.
//!
//! Kept by the agent in its state directory: `catalog.json` lists them and
//! each configuration (it holds a private key) is a separate 0600 file named
//! after a random ID, so nothing a person types becomes a path. The API never
//! returns a configuration's contents.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::domain::{Server, ServerSource};
use crate::wireguard;

const CATALOG_FILE: &str = "catalog.json";
const ID_PREFIX: &str = "custom-";
pub const DEFAULT_PROVIDER: &str = "WireGuard";

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CatalogFile {
    #[serde(default)]
    servers: Vec<Entry>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    id: String,
    name: String,
    provider: String,
    country: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    city: String,
}

/// What a person supplies when importing a configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Import {
    pub name: String,
    #[serde(default)]
    pub provider: String,
    pub country: String,
    #[serde(default)]
    pub city: String,
    pub config: String,
}

pub struct CustomExits {
    directory: PathBuf,
    // Serializes read-modify-write of the catalog within this process.
    lock: Mutex<()>,
}

impl CustomExits {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            lock: Mutex::new(()),
        }
    }

    fn config_path(&self, id: &str) -> PathBuf {
        self.directory.join(format!("{id}.conf"))
    }

    fn load(&self) -> Result<CatalogFile> {
        match fs::read(self.directory.join(CATALOG_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("decode imported configurations"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(CatalogFile::default())
            }
            Err(error) => Err(error).context("read imported configurations"),
        }
    }

    fn store(&self, catalog: &CatalogFile) -> Result<()> {
        write_private(
            &self.directory,
            &self.directory.join(CATALOG_FILE),
            &serde_json::to_vec_pretty(catalog)?,
        )
    }

    pub fn list(&self) -> Result<Vec<Server>> {
        Ok(self
            .load()?
            .servers
            .into_iter()
            .filter(|entry| valid_id(&entry.id))
            .map(|entry| Server {
                config_file: self.config_path(&entry.id).to_string_lossy().into_owned(),
                id: entry.id,
                source: ServerSource::Custom,
                provider: entry.provider,
                country: entry.country,
                city: entry.city,
                name: entry.name,
                load: None,
                features: Vec::new(),
            })
            .collect())
    }

    /// Validates and stores a configuration; returns the new server.
    pub fn add(&self, import: Import) -> Result<Server> {
        let name = clean(&import.name, 48, "name")?;
        if name.is_empty() {
            bail!("enter a name for this location");
        }
        let provider = match clean(&import.provider, 32, "provider")? {
            provider if provider.is_empty() => DEFAULT_PROVIDER.to_owned(),
            provider => provider,
        };
        let country = import.country.trim().to_ascii_uppercase();
        if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase()) {
            bail!("choose the country the server is in");
        }
        let city = clean(&import.city, 48, "city")?;
        if import.config.len() > wireguard::MAX_IMPORT_BYTES {
            bail!("the configuration is too large");
        }
        let parsed = wireguard::parse(&import.config)?;
        parsed.check_importable()?;

        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut catalog = self.load()?;
        let id = format!("{ID_PREFIX}{}", random_hex(6));
        write_private(
            &self.directory,
            &self.config_path(&id),
            import.config.as_bytes(),
        )?;
        catalog.servers.push(Entry {
            id: id.clone(),
            name,
            provider,
            country,
            city,
        });
        if let Err(error) = self.store(&catalog) {
            let _ = fs::remove_file(self.config_path(&id));
            return Err(error);
        }
        self.list()?
            .into_iter()
            .find(|server| server.id == id)
            .context("imported configuration disappeared")
    }

    pub fn remove(&self, id: &str) -> Result<()> {
        if !valid_id(id) {
            bail!("unknown imported location");
        }
        let _guard = self
            .lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut catalog = self.load()?;
        let before = catalog.servers.len();
        catalog.servers.retain(|entry| entry.id != id);
        if catalog.servers.len() == before {
            bail!("unknown imported location");
        }
        self.store(&catalog)?;
        let _ = fs::remove_file(self.config_path(id));
        Ok(())
    }

    pub fn contains(&self, id: &str) -> bool {
        self.load()
            .map(|catalog| catalog.servers.iter().any(|entry| entry.id == id))
            .unwrap_or(false)
    }
}

fn valid_id(id: &str) -> bool {
    id.strip_prefix(ID_PREFIX)
        .is_some_and(|rest| rest.len() == 12 && rest.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Trimmed text without control characters, at most `max` characters.
fn clean(value: &str, max: usize, field: &str) -> Result<String> {
    let value = value.trim();
    if value.chars().any(char::is_control) {
        bail!("the {field} contains control characters");
    }
    if value.chars().count() > max {
        bail!("the {field} is longer than {max} characters");
    }
    Ok(value.to_owned())
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut buffer);
    hex::encode(buffer)
}

fn write_private(directory: &Path, path: &Path, contents: &[u8]) -> Result<()> {
    fs::create_dir_all(directory)?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    std::io::Write::write_all(&mut temporary, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600))?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .context("save imported configuration")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "[Interface]\nPrivateKey = aGlkZGVuLXByaXZhdGUta2V5LWZvci10ZXN0cy1vbmx5\nAddress = 10.64.1.2/32\nDNS = 10.64.0.1\n[Peer]\nPublicKey = cHVibGlj\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 185.65.134.1:51820\n";

    fn import(name: &str, config: &str) -> Import {
        Import {
            name: name.into(),
            provider: "Mullvad".into(),
            country: "ch".into(),
            city: "Zurich".into(),
            config: config.into(),
        }
    }

    #[test]
    fn stores_imports_privately_and_lists_them() {
        let directory = tempfile::tempdir().unwrap();
        let store = CustomExits::new(directory.path());
        assert!(store.list().unwrap().is_empty());
        let server = store.add(import("Mullvad Zurich", CONFIG)).unwrap();
        assert!(valid_id(&server.id));
        assert_eq!(
            (
                server.source,
                server.provider.as_str(),
                server.country.as_str()
            ),
            (ServerSource::Custom, "Mullvad", "CH")
        );
        assert_eq!(fs::read_to_string(&server.config_file).unwrap(), CONFIG);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [
                PathBuf::from(&server.config_file),
                directory.path().join(CATALOG_FILE),
            ] {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        // The private key never lands in the catalog.
        assert!(
            !fs::read_to_string(directory.path().join(CATALOG_FILE))
                .unwrap()
                .contains("PrivateKey")
        );
        assert_eq!(store.list().unwrap().len(), 1);
        assert!(store.contains(&server.id));

        store.remove(&server.id).unwrap();
        assert!(store.list().unwrap().is_empty());
        assert!(!Path::new(&server.config_file).exists());
        assert!(store.remove(&server.id).is_err());
        assert!(store.remove("../catalog.json").is_err());
    }

    #[test]
    fn rejects_unusable_imports() {
        let directory = tempfile::tempdir().unwrap();
        let store = CustomExits::new(directory.path());
        assert!(
            store
                .add(import("", CONFIG))
                .unwrap_err()
                .to_string()
                .contains("name")
        );
        let mut bad_country = import("x", CONFIG);
        bad_country.country = "Switzerland".into();
        assert!(
            store
                .add(bad_country)
                .unwrap_err()
                .to_string()
                .contains("country")
        );
        assert!(store.add(import("x", "not a config")).is_err());
        let split = CONFIG.replace("0.0.0.0/0, ::/0", "10.0.0.0/8");
        assert!(
            store
                .add(import("x", &split))
                .unwrap_err()
                .to_string()
                .contains("0.0.0.0/0")
        );
        assert!(
            store
                .add(import("x", &"#".repeat(wireguard::MAX_IMPORT_BYTES + 1)))
                .is_err()
        );
        assert!(store.add(import("line\nbreak", CONFIG)).is_err());
        let mut unnamed_provider = import("Home server", CONFIG);
        unnamed_provider.provider = "  ".into();
        assert_eq!(
            store.add(unnamed_provider).unwrap().provider,
            DEFAULT_PROVIDER
        );
    }
}
