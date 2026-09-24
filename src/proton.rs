use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Request;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::UnixStream;

pub const RUNTIME_EXIT_LIMIT: usize = 255;

#[derive(Clone)]
pub struct AccountLimits {
    socket_path: PathBuf,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountResponse {
    state: String,
    max_connections: Option<usize>,
}

impl AccountLimits {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn exit_limit(&self) -> Result<Option<usize>> {
        read_exit_limit(&self.socket_path).await
    }
}

async fn read_exit_limit(socket_path: &Path) -> Result<Option<usize>> {
    let stream = UnixStream::connect(socket_path)
        .await
        .context("connect to Proton account broker")?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .context("handshake with Proton account broker")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .uri("/v1/proton/account")
        .header("Host", "broker")
        .body(Empty::<Bytes>::new())?;
    let response = sender
        .send_request(request)
        .await
        .context("request Proton account metadata")?;
    if !response.status().is_success() {
        bail!("Proton account broker returned {}", response.status());
    }
    let body = response.into_body().collect().await?.to_bytes();
    let account: AccountResponse = serde_json::from_slice(&body)?;
    Ok((account.state == "authenticated")
        .then(|| {
            account
                .max_connections
                .map(|limit| limit.min(RUNTIME_EXIT_LIMIT))
        })
        .flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    #[test]
    fn account_response_uses_authenticated_quota() {
        let account: AccountResponse =
            serde_json::from_str(r#"{"state":"authenticated","maxConnections":11}"#).unwrap();
        assert_eq!(account.max_connections, Some(11));
    }

    #[tokio::test]
    async fn reads_quota_from_broker_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket_path = directory.path().join("broker.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let length = stream.read(&mut request).await.unwrap();
            assert!(
                String::from_utf8_lossy(&request[..length])
                    .starts_with("GET /v1/proton/account HTTP/1.1")
            );
            let body = r#"{"state":"authenticated","maxConnections":11}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        assert_eq!(read_exit_limit(&socket_path).await.unwrap(), Some(11));
        server.await.unwrap();
    }
}
