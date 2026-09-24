use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::domain::{DesiredState, SCHEMA_VERSION};
use anyhow::{Context, Result, bail};

pub const REVISION_CONFLICT: &str = "state revision conflict";

pub struct Store {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: Mutex::new(()),
        }
    }

    pub fn load(&self) -> Result<DesiredState> {
        let _guard = self.lock.lock().expect("state mutex poisoned");
        self.load_unlocked()
    }

    pub fn update<F>(&self, expected_revision: u64, mutate: F) -> Result<DesiredState>
    where
        F: FnOnce(&mut DesiredState) -> Result<()>,
    {
        let _guard = self.lock.lock().expect("state mutex poisoned");
        let mut current = self.load_unlocked()?;
        if current.revision != expected_revision {
            bail!(REVISION_CONFLICT);
        }
        mutate(&mut current)?;
        current.revision += 1;
        self.write_unlocked(&current)?;
        Ok(current)
    }

    fn load_unlocked(&self) -> Result<DesiredState> {
        let content = match fs::read(&self.path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DesiredState::default());
            }
            Err(error) => return Err(error).context("read desired state"),
        };
        let desired: DesiredState =
            serde_json::from_slice(&content).context("decode desired state")?;
        if desired.schema_version != SCHEMA_VERSION {
            bail!("unsupported state schema {}", desired.schema_version);
        }
        Ok(desired)
    }

    fn write_unlocked(&self, desired: &DesiredState) -> Result<()> {
        let directory = self.path.parent().unwrap_or_else(|| Path::new("."));
        let created = !directory.exists();
        fs::create_dir_all(directory).context("create state directory")?;
        if created {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o770))
                .context("set state directory permissions")?;
        }
        let content = serde_json::to_vec_pretty(desired).context("encode desired state")?;
        let mut temporary = tempfile::Builder::new()
            .prefix(".desired-")
            .suffix(".json")
            .tempfile_in(directory)
            .context("create state temporary file")?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .context("set state permissions")?;
        temporary.write_all(&content).context("write state")?;
        temporary.as_file().sync_all().context("sync state")?;
        temporary
            .persist(&self.path)
            .map_err(|error| error.error)
            .context("replace state")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Assignment;

    #[test]
    fn update_is_atomic_and_versioned() {
        let directory = tempfile::tempdir().unwrap();
        let state_directory = directory.path().join("state");
        let store = Store::new(state_directory.join("desired.json"));
        let updated = store
            .update(0, |desired| {
                desired.assignments.push(Assignment {
                    node_id: "node-a".into(),
                    exit_id: "exit-ch".into(),
                });
                Ok(())
            })
            .unwrap();
        assert_eq!(updated.revision, 1);
        assert_eq!(store.load().unwrap().assignments[0].node_id, "node-a");
        assert_eq!(
            fs::metadata(state_directory).unwrap().permissions().mode() & 0o777,
            0o770
        );
        assert_eq!(
            store.update(0, |_| Ok(())).unwrap_err().to_string(),
            REVISION_CONFLICT
        );
    }
}
