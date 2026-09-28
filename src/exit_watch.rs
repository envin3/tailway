//! Notices when a device routed through a VPN stops using the gateway as its
//! Tailscale exit node (someone switched it off, or picked another one).
//!
//! Only a change is reported: a device must first have been seen using the
//! gateway. While a device is offline nothing is concluded either way. The
//! "not using" signal comes from `usage`, which already needs `usage::WINDOW`
//! without Internet traffic; the alert adds its own grace period on top, so an
//! idle but connected device does not raise it.

use std::collections::HashSet;
use std::time::Duration;

use crate::usage;

/// Extra time on top of `usage::WINDOW` before the alert fires.
pub const GRACE: Duration = Duration::from_secs(10 * 60);
pub const KEY_PREFIX: &str = "exit-node:";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceUse {
    pub node_id: String,
    pub name: String,
    pub online: bool,
    /// The VPN location the device is routed to; `None` for Direct, Local only,
    /// or the default route.
    pub route: Option<String>,
    /// Sent Internet traffic through the gateway within `usage::WINDOW`.
    pub using: bool,
}

#[derive(Default)]
pub struct ExitNodeWatch {
    seen_using: HashSet<String>,
}

impl ExitNodeWatch {
    /// The alert condition for each device: `Some(message)` while the problem
    /// holds, `None` when it does not. Offline devices are left out, so their
    /// condition stays as it was.
    pub fn evaluate(&mut self, devices: &[DeviceUse]) -> Vec<(String, Option<String>)> {
        self.seen_using
            .retain(|node_id| devices.iter().any(|device| &device.node_id == node_id));
        let mut conditions = Vec::new();
        for device in devices {
            let key = key(device);
            let Some(route) = &device.route else {
                self.seen_using.remove(&device.node_id);
                conditions.push((key, None));
                continue;
            };
            if device.using {
                self.seen_using.insert(device.node_id.clone());
                conditions.push((key, None));
                continue;
            }
            if !device.online {
                continue;
            }
            let problem = self.seen_using.contains(&device.node_id).then(|| {
                format!(
                    "{} is routed to {route} but has sent no Internet traffic through the gateway for {} minutes while online. Its exit node may have been switched off in Tailscale.",
                    device.name,
                    usage::WINDOW.as_secs() / 60
                )
            });
            conditions.push((key, problem));
        }
        conditions
    }
}

pub fn key(device: &DeviceUse) -> String {
    format!("{KEY_PREFIX}{}", device.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(online: bool, route: Option<&str>, using: bool) -> DeviceUse {
        DeviceUse {
            node_id: "node-a".into(),
            name: "iphone".into(),
            online,
            route: route.map(String::from),
            using,
        }
    }

    fn only(conditions: Vec<(String, Option<String>)>) -> Option<Option<String>> {
        assert!(conditions.len() <= 1);
        conditions.into_iter().next().map(|(key, problem)| {
            assert_eq!(key, "exit-node:iphone");
            problem
        })
    }

    #[test]
    fn a_device_that_never_used_the_gateway_raises_nothing() {
        let mut watch = ExitNodeWatch::default();
        assert_eq!(
            only(watch.evaluate(&[device(true, Some("NL#227"), false)])),
            Some(None)
        );
    }

    #[test]
    fn stopping_while_online_is_reported_and_clears_when_it_resumes() {
        let mut watch = ExitNodeWatch::default();
        assert_eq!(
            only(watch.evaluate(&[device(true, Some("NL#227"), true)])),
            Some(None)
        );
        let problem = only(watch.evaluate(&[device(true, Some("NL#227"), false)]))
            .unwrap()
            .unwrap();
        assert!(problem.contains("iphone is routed to NL#227"));
        assert!(problem.contains("15 minutes"));
        assert_eq!(
            only(watch.evaluate(&[device(true, Some("NL#227"), true)])),
            Some(None)
        );
    }

    #[test]
    fn going_offline_concludes_nothing() {
        let mut watch = ExitNodeWatch::default();
        watch.evaluate(&[device(true, Some("NL#227"), true)]);
        assert_eq!(
            only(watch.evaluate(&[device(false, Some("NL#227"), false)])),
            None
        );
        // Back online and still not using it: now it counts.
        assert!(
            only(watch.evaluate(&[device(true, Some("NL#227"), false)]))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn leaving_the_vpn_route_resets_the_device() {
        let mut watch = ExitNodeWatch::default();
        watch.evaluate(&[device(true, Some("NL#227"), true)]);
        assert_eq!(
            only(watch.evaluate(&[device(true, None, false)])),
            Some(None)
        );
        // Routed to a VPN again: it has to be seen using the gateway first.
        assert_eq!(
            only(watch.evaluate(&[device(true, Some("NL#227"), false)])),
            Some(None)
        );
    }

    #[test]
    fn forgets_devices_that_left_the_tailnet() {
        let mut watch = ExitNodeWatch::default();
        watch.evaluate(&[device(true, Some("NL#227"), true)]);
        watch.evaluate(&[]);
        assert_eq!(
            only(watch.evaluate(&[device(true, Some("NL#227"), false)])),
            Some(None)
        );
    }
}
