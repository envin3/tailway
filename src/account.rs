//! The console's administrator account.
//!
//! Kept in `account.json` in the console's private directory (mode 0600). A
//! `password.bcrypt` from `scripts/create-ui-secrets.sh` in the same directory
//! still works as the `admin` account until the account is first changed.
//! The file is re-read when it changes on disk, so a reset made with
//! `gateway-ui reset-password` applies without a restart and ends every session.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_USERNAME: &str = "admin";
pub const MIN_PASSWORD_LENGTH: usize = 12;
/// bcrypt only uses the first 72 bytes; longer passwords would be silently cut.
pub const MAX_PASSWORD_BYTES: usize = 72;
pub const BCRYPT_COST: u32 = 12;
const ACCOUNT_FILE: &str = "account.json";
const LEGACY_HASH_FILE: &str = "password.bcrypt";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub username: String,
    pub password_hash: String,
    /// Unix seconds; 0 when the password was set outside the console.
    #[serde(default)]
    pub password_changed_at: u64,
}

impl Account {
    /// Changes whenever the password changes; sessions from before are void.
    pub fn generation(&self) -> [u8; 32] {
        Sha256::digest(self.password_hash.as_bytes()).into()
    }

    pub fn verify(&self, password: &str) -> bool {
        bcrypt::verify(password, &self.password_hash).unwrap_or(false)
    }
}

/// A new account with a freshly hashed password (slow: run off async threads).
pub fn new_account(username: &str, password: &str) -> Result<Account> {
    new_account_with_cost(username, password, BCRYPT_COST)
}

pub fn new_account_with_cost(username: &str, password: &str, cost: u32) -> Result<Account> {
    validate_username(username)?;
    validate_password(password)?;
    Ok(Account {
        username: username.to_owned(),
        password_hash: bcrypt::hash(password, cost).context("hash password")?,
        password_changed_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty()
        || username.len() > 64
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._@-".contains(&byte))
    {
        bail!("the username must be 1–64 letters, digits, or . _ @ -");
    }
    Ok(())
}

pub fn validate_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        bail!("the password must be at least {MIN_PASSWORD_LENGTH} characters");
    }
    if password.len() > MAX_PASSWORD_BYTES {
        bail!("the password must be at most {MAX_PASSWORD_BYTES} bytes");
    }
    Ok(())
}

pub struct AccountStore {
    directory: PathBuf,
    cache: Mutex<Option<(Option<SystemTime>, Account)>>,
}

impl AccountStore {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            cache: Mutex::new(None),
        }
    }

    fn account_path(&self) -> PathBuf {
        self.directory.join(ACCOUNT_FILE)
    }

    /// The current account; cheap when the file has not changed.
    pub fn load(&self) -> Result<Account> {
        let path = self.account_path();
        let (source, modified) = match fs::metadata(&path) {
            Ok(metadata) => (path, metadata.modified().ok()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let legacy = self.directory.join(LEGACY_HASH_FILE);
                let modified = fs::metadata(&legacy)
                    .with_context(|| {
                        format!(
                            "no console account in {}; set one with scripts/reset-console-password.sh",
                            self.directory.display()
                        )
                    })?
                    .modified()
                    .ok();
                (legacy, modified)
            }
            Err(error) => return Err(error).context("read the console account"),
        };
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((cached_modified, account)) = cache.as_ref()
            && modified.is_some()
            && *cached_modified == modified
        {
            return Ok(account.clone());
        }
        let account = read_account(&source)?;
        *cache = Some((modified, account.clone()));
        Ok(account)
    }

    pub fn save(&self, account: &Account) -> Result<()> {
        validate_username(&account.username)?;
        fs::create_dir_all(&self.directory)?;
        let mut temporary = tempfile::NamedTempFile::new_in(&self.directory)?;
        std::io::Write::write_all(&mut temporary, &serde_json::to_vec_pretty(account)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600))?;
        }
        temporary.as_file().sync_all()?;
        temporary
            .persist(self.account_path())
            .context("save the console account")?;
        // The legacy hash would otherwise shadow nothing but still hold an old secret.
        let _ = fs::remove_file(self.directory.join(LEGACY_HASH_FILE));
        let modified = fs::metadata(self.account_path())
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        *self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((modified, account.clone()));
        Ok(())
    }
}

fn read_account(path: &Path) -> Result<Account> {
    let content = fs::read_to_string(path).context("read the console account")?;
    if path
        .file_name()
        .is_some_and(|name| name == LEGACY_HASH_FILE)
    {
        let hash = content.trim();
        if hash.is_empty() {
            bail!("{} is empty", path.display());
        }
        return Ok(Account {
            username: DEFAULT_USERNAME.into(),
            password_hash: hash.into(),
            password_changed_at: 0,
        });
    }
    serde_json::from_str(&content).context("parse the console account")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(username: &str, password: &str) -> Account {
        new_account_with_cost(username, password, 4).unwrap()
    }

    #[test]
    fn validates_usernames_and_passwords() {
        for username in ["admin", "envin.m", "ops@home", "a-b_c"] {
            validate_username(username).unwrap();
        }
        for username in ["", "has space", "slash/", &"x".repeat(65)] {
            assert!(validate_username(username).is_err(), "{username:?}");
        }
        validate_password("twelve chars").unwrap();
        assert!(validate_password("short").is_err());
        assert!(validate_password(&"x".repeat(73)).is_err());
        // Length is counted in characters, the bcrypt limit in bytes.
        validate_password(&"é".repeat(12)).unwrap();
        assert!(validate_password(&"é".repeat(37)).is_err());
    }

    #[test]
    fn falls_back_to_the_legacy_hash_until_an_account_is_saved() {
        let directory = tempfile::tempdir().unwrap();
        let store = AccountStore::new(directory.path());
        assert!(
            store
                .load()
                .unwrap_err()
                .to_string()
                .contains("reset-console-password")
        );

        let legacy = account("admin", "legacy password");
        fs::write(
            directory.path().join(LEGACY_HASH_FILE),
            format!("{}\n", legacy.password_hash),
        )
        .unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.username, "admin");
        assert!(loaded.verify("legacy password"));

        let replacement = account("envin", "a brand new password");
        store.save(&replacement).unwrap();
        assert!(!directory.path().join(LEGACY_HASH_FILE).exists());
        let loaded = AccountStore::new(directory.path()).load().unwrap();
        assert_eq!(loaded, replacement);
        assert!(loaded.verify("a brand new password") && !loaded.verify("legacy password"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(directory.path().join(ACCOUNT_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn picks_up_changes_made_by_another_process() {
        let directory = tempfile::tempdir().unwrap();
        let store = AccountStore::new(directory.path());
        store.save(&account("admin", "first password!")).unwrap();
        let before = store.load().unwrap().generation();
        // Another process (the reset command) writes the file.
        std::thread::sleep(std::time::Duration::from_millis(20));
        AccountStore::new(directory.path())
            .save(&account("admin", "second password!"))
            .unwrap();
        let after = store.load().unwrap();
        assert!(after.verify("second password!"));
        assert_ne!(after.generation(), before);
    }
}
