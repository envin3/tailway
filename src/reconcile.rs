use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::catalog::StaticCatalog;
use crate::domain::{Exit, ExitStatus};
use crate::platform::Runner;
use crate::policy::{self, MARK_MASK};
use crate::state::Store;
use crate::tailscale::Provider;
use crate::wireguard;

#[derive(Clone)]
pub struct Config {
    pub wan_interface: String,
    pub tailscale_interface: String,
    pub runtime_directory: PathBuf,
    pub dry_run: bool,
}

#[derive(Default)]
struct Runtime {
    exits: Vec<Exit>,
    last_error: String,
    tunnels: HashMap<String, [u8; 32]>,
    slots: HashMap<String, u32>,
}

pub struct Reconciler {
    config: Config,
    store: Arc<Store>,
    catalog: Arc<StaticCatalog>,
    devices: Arc<Provider>,
    runner: Runner,
    runtime: Mutex<Runtime>,
}

impl Reconciler {
    pub fn new(
        config: Config,
        store: Arc<Store>,
        catalog: Arc<StaticCatalog>,
        devices: Arc<Provider>,
        runner: Runner,
    ) -> Self {
        Self {
            config,
            store,
            catalog,
            devices,
            runner,
            runtime: Mutex::new(Runtime::default()),
        }
    }

    pub fn dry_run(&self) -> bool {
        self.config.dry_run
    }

    pub async fn install_baseline(&self) -> Result<()> {
        let ruleset = policy::compile(policy::Input {
            wan_interface: &self.config.wan_interface,
            tailscale_interface: &self.config.tailscale_interface,
            exits: &[],
            devices: &[],
            assignments: &[],
        })?;
        self.apply_ruleset(&ruleset).await
    }

    pub async fn snapshot(&self) -> (Vec<Exit>, String) {
        let runtime = self.runtime.lock().await;
        (runtime.exits.clone(), runtime.last_error.clone())
    }

    pub async fn reconcile(&self) -> Result<()> {
        match self.reconcile_inner().await {
            Ok(()) => Ok(()),
            Err(error) => {
                self.runtime.lock().await.last_error = error.to_string();
                Err(error)
            }
        }
    }

    async fn reconcile_inner(&self) -> Result<()> {
        let mut desired = self.store.load()?;
        let devices = match self.devices.devices().await {
            Ok(devices) => devices,
            Err(_) if self.config.dry_run => Vec::new(),
            Err(error) => return Err(error),
        };
        desired.exits.sort_by(|left, right| left.id.cmp(&right.id));
        let desired_ids: HashSet<_> = desired.exits.iter().map(|exit| exit.id.clone()).collect();

        let mut runtime = self.runtime.lock().await;
        self.remove_stale_tunnels(&mut runtime, &desired_ids).await;
        let mut runtime_exits = Vec::with_capacity(desired.exits.len());
        let mut healthy = HashSet::new();
        for mut wanted in desired.exits {
            let slot = allocate_slot(&mut runtime, &wanted.id)?;
            wanted.interface = format!("proton{slot}");
            wanted.mark = (slot + 1) << 8;
            wanted.table = 10_000 + slot;
            wanted.status = ExitStatus::Pending;
            let result = match self.catalog.resolve(&wanted.server_id) {
                Ok(server) => {
                    self.ensure_tunnel(&mut runtime, &wanted, &server.config_file)
                        .await
                }
                Err(error) => Err(error),
            };
            if result.is_ok() {
                wanted.status = ExitStatus::Healthy;
                healthy.insert(wanted.id.clone());
            } else {
                wanted.status = ExitStatus::Failed;
            }
            runtime_exits.push(wanted);
        }
        let ruleset = policy::compile(policy::Input {
            wan_interface: &self.config.wan_interface,
            tailscale_interface: &self.config.tailscale_interface,
            exits: &runtime_exits,
            devices: &devices,
            assignments: &desired.assignments,
        })?;
        self.apply_ruleset(&ruleset).await?;
        runtime.exits = runtime_exits;
        runtime.last_error.clear();
        Ok(())
    }

    async fn ensure_tunnel(
        &self,
        runtime: &mut Runtime,
        exit: &Exit,
        config_path: &str,
    ) -> Result<()> {
        let configuration = wireguard::parse_file(config_path)?;
        let mut hasher = Sha256::new();
        hasher.update(configuration.set_conf.as_bytes());
        for (address, prefix) in &configuration.addresses {
            hasher.update(address.octets());
            hasher.update([*prefix]);
        }
        hasher.update(exit.interface.as_bytes());
        hasher.update(exit.mark.to_be_bytes());
        hasher.update(exit.table.to_be_bytes());
        let fingerprint: [u8; 32] = hasher.finalize().into();
        if runtime.tunnels.get(&exit.id) == Some(&fingerprint) {
            return Ok(());
        }
        if self.config.dry_run {
            runtime.tunnels.insert(exit.id.clone(), fingerprint);
            return Ok(());
        }
        fs::create_dir_all(&self.config.runtime_directory)?;
        let set_conf_path = self
            .config
            .runtime_directory
            .join(format!("{}.conf", exit.interface));
        fs::write(&set_conf_path, configuration.set_conf.as_bytes())?;
        set_private_permissions(&set_conf_path)?;
        let _ = self
            .runner
            .run("ip", ["link", "delete", &exit.interface])
            .await;
        let mut commands = vec![
            vec![
                "link".into(),
                "add".into(),
                exit.interface.clone(),
                "type".into(),
                "wireguard".into(),
            ],
            vec![
                "__wg__".into(),
                "setconf".into(),
                exit.interface.clone(),
                set_conf_path.to_string_lossy().into_owned(),
            ],
        ];
        for (address, prefix) in configuration.addresses {
            commands.push(vec![
                "address".into(),
                "add".into(),
                format!("{address}/{prefix}"),
                "dev".into(),
                exit.interface.clone(),
            ]);
        }
        commands.push(vec![
            "link".into(),
            "set".into(),
            "up".into(),
            "dev".into(),
            exit.interface.clone(),
        ]);
        commands.push(vec![
            "route".into(),
            "replace".into(),
            "default".into(),
            "dev".into(),
            exit.interface.clone(),
            "table".into(),
            exit.table.to_string(),
        ]);
        let mark = format!("{:#x}/{:#x}", exit.mark, MARK_MASK);
        let table = exit.table.to_string();
        let _ = self
            .runner
            .run("ip", ["rule", "del", "fwmark", &mark, "table", &table])
            .await;
        commands.push(vec![
            "rule".into(),
            "add".into(),
            "fwmark".into(),
            mark,
            "table".into(),
            table,
            "priority".into(),
            (11_000 + exit.table - 10_000).to_string(),
        ]);
        for mut command in commands {
            let program = if command.first().map(String::as_str) == Some("__wg__") {
                command.remove(0);
                "wg"
            } else {
                "ip"
            };
            if let Err(error) = self.runner.run(program, &command).await {
                let _ = self
                    .runner
                    .run("ip", ["link", "delete", &exit.interface])
                    .await;
                return Err(error);
            }
        }
        runtime.tunnels.insert(exit.id.clone(), fingerprint);
        Ok(())
    }

    async fn remove_stale_tunnels(&self, runtime: &mut Runtime, desired_ids: &HashSet<String>) {
        let stale: BTreeMap<_, _> = runtime
            .slots
            .iter()
            .filter(|(exit_id, _)| !desired_ids.contains(*exit_id))
            .map(|(exit_id, slot)| (exit_id.clone(), *slot))
            .collect();
        for (exit_id, slot) in stale {
            if !self.config.dry_run {
                let interface = format!("proton{slot}");
                let mark = format!("{:#x}/{:#x}", (slot + 1) << 8, MARK_MASK);
                let table = (10_000 + slot).to_string();
                let _ = self
                    .runner
                    .run("ip", ["rule", "del", "fwmark", &mark, "table", &table])
                    .await;
                let _ = self
                    .runner
                    .run("ip", ["route", "flush", "table", &table])
                    .await;
                let _ = self.runner.run("ip", ["link", "delete", &interface]).await;
            }
            runtime.slots.remove(&exit_id);
            runtime.tunnels.remove(&exit_id);
        }
    }

    async fn apply_ruleset(&self, ruleset: &str) -> Result<()> {
        fs::create_dir_all(&self.config.runtime_directory)?;
        let path = self.config.runtime_directory.join("policy.nft");
        fs::write(&path, ruleset)?;
        set_private_permissions(&path)?;
        if self.config.dry_run {
            return Ok(());
        }
        let path = path.to_string_lossy().into_owned();
        self.runner.run("nft", ["-c", "-f", &path]).await?;
        self.runner.run("nft", ["-f", &path]).await?;
        Ok(())
    }
}

fn allocate_slot(runtime: &mut Runtime, exit_id: &str) -> Result<u32> {
    if let Some(slot) = runtime.slots.get(exit_id) {
        return Ok(*slot);
    }
    for slot in 0..255 {
        if !runtime.slots.values().any(|candidate| *candidate == slot) {
            runtime.slots.insert(exit_id.into(), slot);
            return Ok(slot);
        }
    }
    bail!("no runtime exit slot available")
}

#[cfg(unix)]
fn set_private_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_all_supported_runtime_exit_slots() {
        let mut runtime = Runtime::default();
        for slot in 0..255 {
            assert_eq!(
                allocate_slot(&mut runtime, &format!("exit-{slot}")).unwrap(),
                slot
            );
        }
        assert!(allocate_slot(&mut runtime, "exit-overflow").is_err());
    }
}
