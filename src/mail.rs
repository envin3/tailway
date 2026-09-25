//! Email for console password recovery: the recovery address and the SMTP
//! server that sends to it. Both are part of the console account, so changing
//! them needs the current password.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use lettre::message::header::ContentType;
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use serde::{Deserialize, Serialize};

const SMTP_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Security {
    /// Plain connection upgraded with STARTTLS (usually port 587).
    #[default]
    Starttls,
    /// TLS from the first byte (usually port 465).
    Tls,
    /// No encryption: only for a relay on the local network.
    None,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Smtp {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub security: Security,
    /// Empty for a relay that does not need authentication.
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    /// Sender, e.g. `Exit Gateway <gateway@example.com>`.
    pub from: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmailRecovery {
    /// Where reset codes are sent.
    pub email: String,
    pub smtp: Smtp,
}

impl EmailRecovery {
    pub fn validate(&self) -> Result<()> {
        self.email
            .parse::<Address>()
            .context("invalid recovery email address")?;
        let smtp = &self.smtp;
        if smtp.host.is_empty()
            || smtp.host.len() > 253
            || smtp
                .host
                .contains(|character: char| character.is_whitespace() || character == '/')
        {
            bail!("invalid SMTP server name");
        }
        if smtp.port == 0 {
            bail!("invalid SMTP port");
        }
        if smtp.username.is_empty() != smtp.password.is_empty() {
            bail!("enter both the SMTP username and password, or neither");
        }
        smtp.from
            .parse::<Mailbox>()
            .context("invalid sender address")?;
        Ok(())
    }

    /// The recovery address with most of the mailbox hidden, for the sign-in page.
    pub fn masked_email(&self) -> String {
        match self.email.split_once('@') {
            Some((mailbox, domain)) => {
                let first: String = mailbox.chars().take(1).collect();
                format!("{first}•••@{domain}")
            }
            None => "the recovery address".into(),
        }
    }

    pub async fn send_recovery_code(&self, code: &str, console: &str) -> Result<()> {
        self.send(
            "Console password reset code",
            format!(
                "Your password reset code for the Exit Gateway console\n({console}) is:\n\n    {code}\n\nIt expires in 10 minutes and works once.\n\nIf you did not ask for it, someone is trying to reset the\nconsole password. Nothing changes unless the code is used.\n"
            ),
        )
        .await
    }

    pub async fn send_test(&self, console: &str) -> Result<()> {
        self.send(
            "Console password recovery test",
            format!(
                "Password reset codes for the Exit Gateway console\n({console}) will be sent to this address.\n"
            ),
        )
        .await
    }

    /// Bodies are kept to short ASCII lines so they are sent as plain 7-bit text.
    async fn send(&self, subject: &str, body: String) -> Result<()> {
        self.validate()?;
        let message = Message::builder()
            .from(self.smtp.from.parse()?)
            .to(Mailbox::new(None, self.email.parse()?))
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body)
            .context("build the email")?;
        let smtp = &self.smtp;
        let builder = match smtp.security {
            Security::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)?,
            Security::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)?,
            Security::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host),
        };
        let mut builder = builder.port(smtp.port).timeout(Some(SMTP_TIMEOUT));
        if !smtp.username.is_empty() {
            builder = builder.credentials(Credentials::new(
                smtp.username.clone(),
                smtp.password.clone(),
            ));
        }
        builder.build().send(message).await.map_err(|error| {
            anyhow::anyhow!("the mail server refused or could not be reached: {error}")
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    fn recovery(port: u16) -> EmailRecovery {
        EmailRecovery {
            email: "envin@example.com".into(),
            smtp: Smtp {
                host: "127.0.0.1".into(),
                port,
                security: Security::None,
                username: String::new(),
                password: String::new(),
                from: "Exit Gateway <gateway@example.com>".into(),
            },
        }
    }

    #[test]
    fn validates_settings() {
        recovery(25).validate().unwrap();
        let mut invalid = recovery(25);
        invalid.email = "not an address".into();
        assert!(invalid.validate().is_err());
        let mut invalid = recovery(0);
        assert!(invalid.validate().is_err());
        invalid = recovery(25);
        invalid.smtp.host = "smtp example".into();
        assert!(invalid.validate().is_err());
        invalid = recovery(25);
        invalid.smtp.username = "user".into();
        assert!(
            invalid
                .validate()
                .unwrap_err()
                .to_string()
                .contains("username and password")
        );
        invalid = recovery(25);
        invalid.smtp.from = "nobody".into();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn masks_the_recovery_address() {
        assert_eq!(recovery(25).masked_email(), "e•••@example.com");
    }

    /// A minimal SMTP server that accepts one message and returns its data.
    async fn fake_smtp() -> (u16, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();
            writer.write_all(b"220 fake ESMTP\r\n").await.unwrap();
            let mut transcript = String::new();
            let mut in_data = false;
            while let Some(line) = lines.next_line().await.unwrap() {
                transcript.push_str(&line);
                transcript.push('\n');
                if in_data {
                    if line == "." {
                        in_data = false;
                        writer.write_all(b"250 queued\r\n").await.unwrap();
                    }
                    continue;
                }
                let reply: &[u8] = match line
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_uppercase()
                    .as_str()
                {
                    "EHLO" | "HELO" => b"250 fake\r\n",
                    "DATA" => {
                        in_data = true;
                        b"354 go ahead\r\n"
                    }
                    "QUIT" => {
                        writer.write_all(b"221 bye\r\n").await.unwrap();
                        break;
                    }
                    _ => b"250 ok\r\n",
                };
                writer.write_all(reply).await.unwrap();
            }
            transcript
        });
        (port, handle)
    }

    #[tokio::test]
    async fn sends_the_recovery_code_by_smtp() {
        let (port, server) = fake_smtp().await;
        recovery(port)
            .send_recovery_code("12345678", "192.168.0.52:8443")
            .await
            .unwrap();
        let transcript = server.await.unwrap();
        assert!(
            transcript.contains("RCPT TO:<envin@example.com>"),
            "{transcript}"
        );
        assert!(transcript.contains("Subject: Console password reset code"));
        assert!(transcript.contains("\n    12345678\n"), "{transcript}");
        assert!(transcript.contains("(192.168.0.52:8443) is:"));
        assert!(!transcript.contains("quoted-printable"));
    }

    /// Needs the Internet: `cargo test -- --ignored`. With made-up credentials
    /// the server must reject the login, which proves the TLS handshake worked.
    #[tokio::test]
    #[ignore]
    async fn negotiates_tls_with_a_public_mail_server() {
        for (port, security) in [(587, Security::Starttls), (465, Security::Tls)] {
            let mut settings = recovery(port);
            settings.smtp.host = "smtp.gmail.com".into();
            settings.smtp.security = security;
            settings.smtp.username = "nobody@example.com".into();
            settings.smtp.password = "not-a-password".into();
            let error = settings.send_test("console").await.unwrap_err().to_string();
            assert!(
                error.contains("535") || error.to_lowercase().contains("credentials"),
                "{security:?}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn reports_an_unreachable_server() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let error = recovery(port).send_test("console").await.unwrap_err();
        assert!(
            error.to_string().contains("could not be reached"),
            "{error}"
        );
    }
}
