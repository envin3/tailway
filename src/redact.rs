//! Keeping secrets out of logs.
//!
//! Types that hold a password, token, private key, or password hash implement
//! `Debug` by hand and print [`secret`] in its place, so a `{:?}` in a log line
//! or error message cannot reveal it. They still serialize normally, because
//! their files must keep the real value. The tests below fail if a type
//! starts printing a secret again.

/// What a secret field shows in `Debug` output.
pub fn secret(value: &str) -> &'static str {
    if value.is_empty() {
        "<empty>"
    } else {
        "<redacted>"
    }
}

/// A URL with everything after the host hidden: webhook paths and queries
/// often carry tokens.
pub fn url(value: &str) -> String {
    let Some((scheme, rest)) = value.split_once("://") else {
        return secret(value).into();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // Drop any user:password@ before the host.
    let host = authority.rsplit('@').next().unwrap_or_default();
    if rest.len() > authority.len() {
        format!("{scheme}://{host}/<redacted>")
    } else {
        format!("{scheme}://{host}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Account;
    use crate::custom::Import;
    use crate::mail::{EmailRecovery, Security, Smtp};
    use crate::notify::{Format, Settings, Telegram, Webhook};

    const SENTINEL: &str = "s3ntinel-SECRET-value";

    fn assert_hidden(debug: String) {
        assert!(!debug.contains(SENTINEL), "secret printed: {debug}");
        assert!(debug.contains("<redacted>"), "no redaction marker: {debug}");
    }

    #[test]
    fn secrets_never_appear_in_debug_output() {
        let smtp = Smtp {
            host: "smtp.example.com".into(),
            port: 587,
            security: Security::Starttls,
            username: "me".into(),
            password: SENTINEL.into(),
            from: "me@example.com".into(),
        };
        assert_hidden(format!("{smtp:?}"));
        let recovery = EmailRecovery {
            email: "me@example.com".into(),
            smtp,
        };
        assert_hidden(format!("{recovery:?}"));
        assert_hidden(format!(
            "{:?}",
            Account {
                username: "admin".into(),
                password_hash: SENTINEL.into(),
                password_changed_at: 0,
                recovery: Some(recovery),
            }
        ));
        let settings = Settings {
            telegram: Some(Telegram {
                bot_token: SENTINEL.into(),
                chat_id: "42".into(),
            }),
            webhook: Some(Webhook {
                url: format!("https://ntfy.sh/{SENTINEL}?auth={SENTINEL}"),
                format: Format::Ntfy,
            }),
        };
        assert_hidden(format!("{settings:?}"));
        assert_hidden(format!(
            "{:?}",
            Import {
                name: "home".into(),
                provider: String::new(),
                country: "NL".into(),
                city: String::new(),
                config: format!("[Interface]\nPrivateKey = {SENTINEL}\n"),
            }
        ));
        let config = crate::wireguard::parse(&format!(
            "[Interface]\nPrivateKey = {SENTINEL}\nAddress = 10.2.0.2/32\n[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n"
        ))
        .unwrap();
        assert_hidden(format!("{config:?}"));
    }

    #[test]
    fn urls_keep_only_the_host() {
        assert_eq!(
            url("https://ntfy.sh/topic?x=1"),
            "https://ntfy.sh/<redacted>"
        );
        assert_eq!(
            url("https://user:pw@hooks.example.com"),
            "https://hooks.example.com"
        );
        assert_eq!(url("not a url"), "<redacted>");
        assert_eq!(url(""), "<empty>");
    }
}
