//! Fixed tenant-to-worker routing. The public edge owns account authority;
//! each native Faculties process owns its pile, signer, and MCP protocol state.
//! No tool-specific wrappers, caller-selected destinations, proxy discovery,
//! redirects, retries, or public bearer tokens on the internal hop.

use super::*;
use std::collections::HashSet;
use std::io::Read;
use std::path::PathBuf;

use axum::body::Body;
use axum::http::{HeaderValue, Method, Request};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUESTS: usize = 16;
const BODY_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WORKER_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    workers: Vec<WorkerSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerSpec {
    tenant: String,
    address: SocketAddr,
    token_file: PathBuf,
}

struct Worker {
    address: SocketAddr,
    authorization: HeaderValue,
}

pub(super) struct Gateway {
    workers: HashMap<String, Worker>,
    admission: Arc<Semaphore>,
}

impl Gateway {
    /// Read once at startup. Token paths resolve relative to the manifest;
    /// rotating mappings/tokens requires restarting this edge. Public account
    /// revocation remains live through the existing token/OAuth authorities.
    pub(super) fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 1024 * 1024, "worker manifest exceeds 1 MiB");
        let manifest: Manifest = serde_json::from_slice(&bytes).context("parse worker manifest")?;
        anyhow::ensure!(
            !manifest.workers.is_empty() && manifest.workers.len() <= 1024,
            "worker manifest must contain 1..=1024 tenants"
        );
        let mut workers = HashMap::new();
        let mut addresses = HashSet::new();
        for spec in manifest.workers {
            anyhow::ensure!(!spec.tenant.is_empty(), "worker tenant cannot be empty");
            anyhow::ensure!(
                spec.address.ip().is_loopback() && spec.address.port() != 0,
                "worker address must be literal loopback with a nonzero port"
            );
            anyhow::ensure!(
                addresses.insert(spec.address),
                "tenants must have distinct worker addresses"
            );
            anyhow::ensure!(
                !workers.contains_key(&spec.tenant),
                "duplicate worker tenant"
            );
            let token_path = path
                .parent()
                .unwrap_or(Path::new("."))
                .join(spec.token_file);
            let authorization = read_token(&token_path)
                .with_context(|| format!("load internal token for tenant {:?}", spec.tenant))?;
            workers.insert(
                spec.tenant,
                Worker {
                    address: spec.address,
                    authorization,
                },
            );
        }
        Ok(Self {
            workers,
            admission: Arc::new(Semaphore::new(MAX_REQUESTS)),
        })
    }

    fn worker(&self, token: &TokenEntry) -> Result<&Worker, Response> {
        self.workers.get(&token.tenant).ok_or_else(|| {
            http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "no Faculties worker configured for this account",
            )
        })
    }

    fn admit(&self) -> Result<OwnedSemaphorePermit, Response> {
        self.admission.clone().try_acquire_owned().map_err(|_| {
            http_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Faculties gateway is at capacity; retry later",
            )
        })
    }

    pub(super) async fn post(
        &self,
        state: &HttpState,
        token: &TokenEntry,
        headers: &HeaderMap,
        body: Body,
    ) -> Response {
        let worker = match self.worker(token) {
            Ok(worker) => worker,
            Err(error) => return error,
        };
        let permit = match self.admit() {
            Ok(permit) => permit,
            Err(error) => return error,
        };
        let body = match tokio::time::timeout(
            BODY_TIMEOUT,
            axum::body::to_bytes(body, state.config.max_body_bytes),
        )
        .await
        {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => {
                return http_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds limit or could not be read",
                );
            }
            Err(_) => return http_error(StatusCode::REQUEST_TIMEOUT, "request body timed out"),
        };
        let request: Value = match serde_json::from_slice(&body) {
            Ok(request) => request,
            Err(_) => return http_error(StatusCode::BAD_REQUEST, "invalid JSON body"),
        };
        if !request.is_object() {
            return http_error(
                StatusCode::BAD_REQUEST,
                "send one JSON-RPC message per request",
            );
        }
        let initialize = request.get("method").and_then(Value::as_str) == Some("initialize");
        // Native dispatch validates the complete envelope and argument schema.
        // Here only initialization needs interpretation, to wrap its session.
        let mut pending = if initialize {
            if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
                || !request
                    .get("id")
                    .is_some_and(|id| id.is_string() || id.is_number())
                || headers.contains_key("mcp-session-id")
            {
                return http_error(
                    StatusCode::BAD_REQUEST,
                    "initialize must be a request without a session header",
                );
            }
            let id = match open_session(state, &token.tenant) {
                Ok(id) => id,
                Err(error) => return error,
            };
            Some(PendingSession {
                state,
                id,
                retained: false,
            })
        } else {
            None
        };
        let upstream_session = if initialize {
            None
        } else {
            match worker_session(state, token, headers) {
                Ok(id) => Some(id),
                Err(error) => return error,
            }
        };
        let reply = match worker
            .forward(Method::POST, headers, upstream_session.as_deref(), body)
            .await
        {
            Ok(reply) => reply,
            Err(error) => return error,
        };
        let mut public_session = None;
        if let Some(pending) = &mut pending {
            if reply.status == StatusCode::OK {
                let value: Value = match serde_json::from_slice(&reply.body) {
                    Ok(value) => value,
                    Err(_) => return bad_worker("invalid initialize response"),
                };
                if value.get("result").is_some() && value.get("error").is_none() {
                    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
                        || value.get("id") != request.get("id")
                    {
                        return bad_worker("mismatched initialize response");
                    }
                    let Some(session) = reply
                        .headers
                        .get("mcp-session-id")
                        .and_then(|v| v.to_str().ok())
                        .filter(|s| valid_session(s))
                    else {
                        return bad_worker("successful initialize missing a valid worker session");
                    };
                    let mut sessions = state.sessions.lock().expect("sessions poisoned");
                    let Some(entry) = sessions.get_mut(&pending.id) else {
                        return bad_worker("initialize reservation expired; initialize again");
                    };
                    entry.worker_session = Some(session.to_string());
                    entry.last_seen = Instant::now();
                    pending.retained = true;
                    public_session = Some(pending.id.clone());
                }
            }
        } else if reply.status == StatusCode::NOT_FOUND {
            forget_session(state, headers);
        }
        reply.into_response(public_session.as_deref(), permit)
    }

    pub(super) async fn delete(
        &self,
        state: &HttpState,
        token: &TokenEntry,
        headers: &HeaderMap,
    ) -> Response {
        let worker = match self.worker(token) {
            Ok(worker) => worker,
            Err(error) => return error,
        };
        let permit = match self.admit() {
            Ok(permit) => permit,
            Err(error) => return error,
        };
        let session = match worker_session(state, token, headers) {
            Ok(session) => session,
            Err(error) => return error,
        };
        let reply = match worker
            .forward(Method::DELETE, headers, Some(&session), Bytes::new())
            .await
        {
            Ok(reply) => reply,
            Err(error) => return error,
        };
        if reply.status == StatusCode::NO_CONTENT || reply.status == StatusCode::NOT_FOUND {
            forget_session(state, headers);
        }
        reply.into_response(None, permit)
    }
}

fn read_token(path: &Path) -> Result<HeaderValue> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1027)
        .read_to_end(&mut bytes)?;
    let token = bytes
        .strip_suffix(b"\r\n")
        .or_else(|| bytes.strip_suffix(b"\n"))
        .unwrap_or(&bytes);
    let valid = (32..=1024).contains(&token.len())
        && token
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(b));
    let result = if valid {
        let mut bearer = b"Bearer ".to_vec();
        bearer.extend_from_slice(token);
        let header = HeaderValue::from_bytes(&bearer).context("invalid internal bearer token");
        bearer.fill(0);
        header
    } else {
        Err(anyhow::anyhow!(
            "internal token must be 32..=1024 ASCII bearer characters"
        ))
    };
    bytes.fill(0);
    let mut header = result?;
    header.set_sensitive(true);
    Ok(header)
}

fn worker_session(
    state: &HttpState,
    token: &TokenEntry,
    headers: &HeaderMap,
) -> Result<String, Response> {
    validate_session(state, headers, token)?;
    state
        .sessions
        .lock()
        .expect("sessions poisoned")
        .get(header_str(headers, "mcp-session-id").expect("validated session header"))
        .and_then(|s| s.worker_session.clone())
        .ok_or_else(|| {
            http_error(
                StatusCode::NOT_FOUND,
                "worker session no longer available; initialize again",
            )
        })
}

fn forget_session(state: &HttpState, headers: &HeaderMap) {
    if let Some(id) = header_str(headers, "mcp-session-id") {
        state.sessions.lock().expect("sessions poisoned").remove(id);
    }
}

/// A failed or cancelled initialize releases its reserved outer slot. If the
/// worker accepted it before disconnection, its own idle expiry owns cleanup.
struct PendingSession<'a> {
    state: &'a HttpState,
    id: String,
    retained: bool,
}
impl Drop for PendingSession<'_> {
    fn drop(&mut self) {
        if !self.retained {
            self.state
                .sessions
                .lock()
                .expect("sessions poisoned")
                .remove(&self.id);
        }
    }
}

fn valid_session(session: &str) -> bool {
    !session.is_empty()
        && session.len() <= 256
        && session.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn bad_worker(message: &str) -> Response {
    http_error(StatusCode::BAD_GATEWAY, message)
}

struct WorkerReply {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl Worker {
    async fn forward(
        &self,
        method: Method,
        headers: &HeaderMap,
        session: Option<&str>,
        body: Bytes,
    ) -> Result<WorkerReply, Response> {
        // One literal socket connection and one request. Hyper's connection
        // API does not consult proxy env, resolve DNS, redirect, or retry.
        let socket = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(self.address),
        )
        .await
        {
            Ok(Ok(socket)) => socket,
            _ => {
                return Err(http_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Faculties worker unavailable; request not sent",
                ));
            }
        };
        let exchange = async {
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
            let mut request = Request::builder()
                .method(method)
                .uri("/")
                .header(header::HOST, self.address.to_string())
                .header(header::AUTHORIZATION, self.authorization.clone())
                .header(header::CONNECTION, "close");
            for name in [
                "content-type",
                "content-encoding",
                "accept",
                "mcp-protocol-version",
            ] {
                for value in headers.get_all(name) {
                    request = request.header(name, value.clone());
                }
            }
            if let Some(session) = session {
                request = request.header("mcp-session-id", session);
            }
            let request = request.body(Full::new(body))?;
            let response = async {
                let response = sender.send_request(request).await?;
                let (parts, body) = response.into_parts();
                let body = Limited::new(body, MAX_RESPONSE_BYTES)
                    .collect()
                    .await
                    .map_err(|_| anyhow::anyhow!("worker response unreadable or too large"))?
                    .to_bytes();
                Ok::<_, anyhow::Error>(WorkerReply {
                    status: parts.status,
                    headers: parts.headers,
                    body,
                })
            };
            // Drive both futures without a detached task; cancellation closes
            // this connection, but cannot promise to cancel native execution.
            tokio::pin!(connection);
            tokio::pin!(response);
            tokio::select! {
                result = &mut response => result,
                result = &mut connection => { result?; response.await }
            }
        };
        match tokio::time::timeout(WORKER_TIMEOUT, exchange).await {
            Ok(Ok(reply)) => {
                // Internal-hop failures must not redirect callers or start a
                // second login flow. Only the public edge issues challenges.
                if reply.status.is_redirection()
                    || reply.status == StatusCode::UNAUTHORIZED
                    || reply.status == StatusCode::FORBIDDEN
                {
                    return Err(bad_worker(
                        "Faculties worker configuration rejected the internal request",
                    ));
                }
                if reply.headers.contains_key(header::CONTENT_ENCODING)
                    || reply.headers.get_all("mcp-session-id").iter().count() > 1
                    || reply.headers.get_all(header::CONTENT_TYPE).iter().count() > 1
                {
                    return Err(bad_worker("unsupported worker response headers"));
                }
                if !reply.body.is_empty()
                    && !reply
                        .headers
                        .get(header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|v| {
                            v.split(';')
                                .next()
                                .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
                        })
                {
                    return Err(bad_worker(
                        "worker must return JSON, not an SSE stream or other media",
                    ));
                }
                Ok(reply)
            }
            Ok(Err(_)) => Err(bad_worker(
                "worker response failed; execution outcome is unknown; request was not retried",
            )),
            Err(_) => Err(http_error(
                StatusCode::GATEWAY_TIMEOUT,
                "worker response timed out; execution outcome is unknown; request was not retried",
            )),
        }
    }
}

impl WorkerReply {
    fn into_response(self, session: Option<&str>, permit: OwnedSemaphorePermit) -> Response {
        let mut response = Response::new(Body::from(Bytes::from_owner(AdmittedBody {
            bytes: self.body,
            _permit: permit,
        })));
        *response.status_mut() = self.status;
        for name in [header::CONTENT_TYPE, header::ALLOW, header::RETRY_AFTER] {
            if let Some(value) = self.headers.get(&name) {
                response.headers_mut().insert(name, value.clone());
            }
        }
        if let Some(session) = session {
            response.headers_mut().insert(
                "mcp-session-id",
                HeaderValue::from_str(session).expect("public session id"),
            );
        }
        response
    }
}

/// Keep admission until the buffered outgoing bytes (including HTTP frame
/// clones retained for a slow reader) have actually been released.
struct AdmittedBody {
    bytes: Bytes,
    _permit: OwnedSemaphorePermit,
}
impl AsRef<[u8]> for AdmittedBody {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod config_tests;
