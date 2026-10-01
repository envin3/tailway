use std::ffi::OsStr;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use tokio::process::Command;

#[derive(Clone)]
pub struct Runner {
    dry_run: bool,
}

impl Runner {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    pub async fn run<I, S>(&self, program: &str, arguments: I) -> Result<Vec<u8>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        if self.dry_run {
            return Ok(Vec::new());
        }
        let output = Command::new(program)
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .await
            .with_context(|| format!("run {program}"))?;
        if !output.status.success() {
            bail!(
                "{program} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(output.stdout)
    }
}
