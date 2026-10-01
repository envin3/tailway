//! Console sessions kept across restarts ("Keep me signed in").
//!
//! Only a hash of each session token is stored, so the file alone cannot be
//! used to sign in. Sessions that were not remembered stay in memory and end
//! when the console restarts.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const SESSIONS_FILE: &str = "sessions.json";
const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredSession {
    /// SHA-256 of the session token, hex.
    pub key: String,
    pub csrf_token: String,
    /// The password generation the session was opened under, hex.
    pub generation: String,
    /// Unix seconds.
    pub created: u64,
    pub last_seen: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct File {
    schema_version: u32,
    sessions: Vec<StoredSession>,
}

pub struct SessionStore {
    path: PathBuf,
}

impl SessionStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            path: directory.into().join(SESSIONS_FILE),
        }
    }

    /// The saved sessions; none if the file does not exist or is unreadable
    /// (signing in again is the only consequence).
    pub fn load(&self) -> Vec<StoredSession> {
        let Ok(bytes) = fs::read(&self.path) else {
            return Vec::new();
        };
        serde_json::from_slice::<File>(&bytes)
            .ok()
            .filter(|file| file.schema_version == SCHEMA_VERSION)
            .map(|file| file.sessions)
            .unwrap_or_default()
    }

    pub fn save(&self, sessions: &[StoredSession]) -> Result<()> {
        if sessions.is_empty() {
            return match fs::remove_file(&self.path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    Err(error).context("remove the saved console sessions")
                }
                _ => Ok(()),
            };
        }
        let directory = self
            .path
            .parent()
            .context("sessions file has no directory")?;
        fs::create_dir_all(directory)?;
        let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
        temporary.write_all(&serde_json::to_vec(&File {
            schema_version: SCHEMA_VERSION,
            sessions: sessions.to_vec(),
        })?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600))?;
        }
        temporary.as_file().sync_all()?;
        temporary
            .persist(&self.path)
            .context("save the console sessions")?;
        Ok(())
    }
}

/// Wall-clock Unix seconds: remembered sessions must outlive reboots, which
/// reset the monotonic clock.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(key: &str) -> StoredSession {
        StoredSession {
            key: key.into(),
            csrf_token: "csrf".into(),
            generation: "00".into(),
            created: 1,
            last_seen: 2,
        }
    }

    #[test]
    fn saves_privately_and_loads_back() {
        let directory = tempfile::tempdir().unwrap();
        let store = SessionStore::new(directory.path());
        assert!(store.load().is_empty());
        store.save(&[session("a"), session("b")]).unwrap();
        assert_eq!(store.load(), vec![session("a"), session("b")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(directory.path().join(SESSIONS_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        store.save(&[]).unwrap();
        assert!(!directory.path().join(SESSIONS_FILE).exists());
        store.save(&[]).unwrap();
    }

    #[test]
    fn ignores_unreadable_files() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join(SESSIONS_FILE), b"not json").unwrap();
        assert!(SessionStore::new(directory.path()).load().is_empty());
    }
}
