//! Private loopback fixtures: no real worker, pile, model, account, or proxy.
//! Scripted upstream HTTP preserves the exact request bytes and lets a test
//! close the connection after admission without inventing a successful reply.

use super::*;
use crate::mcp_http::tests::{agent, post, rpc, test_state};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

const INTERNAL_TOKEN: &str = "worker-test-only-0123456789abcdef0123456789";
const UPSTREAM_SESSION: &str = "same-session-from-two-independent-workers";
const WAIT: Duration = Duration::from_secs(5);
const ORIGIN: &str = "https://mcp.example.test";
const MIXED: &str = r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"first"},{"type":"image","mimeType":"image/png","data":"AP8="},{"type":"audio","mimeType":"audio/wav","data":"AQID"},{"type":"resource","resource":{"uri":"files:test","mimeType":"application/octet-stream","blob":"AP8K"}}],"isError":false}}"#;

#[derive(Clone, Debug)]
struct Received {
    method: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

enum Script {
    Reply {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    Disconnect,
}

impl Script {
    fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::Reply {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.into(),
        }
    }

    fn initialize() -> Self {
        Self::json(200, br#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"test-worker","version":"1"}}}"#.to_vec())
            .header("Mcp-Session-Id", UPSTREAM_SESSION)
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        if let Self::Reply { headers, .. } = &mut self {
            headers.push((name.into(), value.into()));
        }
        self
    }
}

struct FakeWorker {
    addr: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeWorker {
    fn new(scripts: Vec<Script>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let received = Arc::new(Mutex::new(Vec::new()));
        let saved = received.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let worker = thread::spawn(move || {
            let mut scripts: VecDeque<_> = scripts.into();
            loop {
                let (stream, _) = listener.accept().unwrap();
                if stopped.load(Ordering::SeqCst) {
                    break;
                }
                stream.set_read_timeout(Some(WAIT)).unwrap();
                stream.set_write_timeout(Some(WAIT)).unwrap();
                let mut input = BufReader::new(stream);
                let mut first = String::new();
                input.read_line(&mut first).unwrap();
                let method = first.split_whitespace().next().unwrap().to_owned();
                let mut headers = HeaderMap::new();
                loop {
                    let mut line = String::new();
                    assert_ne!(
                        input.read_line(&mut line).unwrap(),
                        0,
                        "truncated request headers"
                    );
                    if line == "\r\n" {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap();
                    headers.append(
                        axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                        HeaderValue::from_str(value.trim()).unwrap(),
                    );
                }
                assert!(
                    !headers.contains_key("transfer-encoding"),
                    "the gateway's Full body has an exact length"
                );
                let length = headers
                    .get("content-length")
                    .map(|value| value.to_str().unwrap().parse::<usize>().unwrap())
                    .unwrap_or(0);
                assert!(length <= DEFAULT_MAX_BODY_BYTES);
                let mut body = vec![0; length];
                input.read_exact(&mut body).unwrap();
                saved.lock().unwrap().push(Received {
                    method,
                    headers,
                    body,
                });
                let mut stream = input.into_inner();
                match scripts
                    .pop_front()
                    .expect("unexpected extra upstream request, possibly a retry")
                {
                    Script::Disconnect => {}
                    Script::Reply {
                        status,
                        headers,
                        body,
                    } => {
                        let mut head = format!("HTTP/1.1 {status} Test\r\nConnection: close\r\n");
                        if status != 204 {
                            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
                        }
                        for (name, value) in headers {
                            head.push_str(&format!("{name}: {value}\r\n"));
                        }
                        head.push_str("\r\n");
                        // An oversized response is expected to make the gateway
                        // close before all bytes have been sent.
                        if stream.write_all(head.as_bytes()).is_ok() {
                            let _ = stream.write_all(&body);
                            let _ = stream.flush();
                        }
                    }
                }
            }
        });
        Self {
            addr,
            received,
            stop,
            thread: Some(worker),
        }
    }

    fn requests(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}

impl Drop for FakeWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, WAIT);
        if let Some(worker) = self.thread.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("fake worker panicked");
            }
        }
    }
}

fn gateway_state(workers: &[(&str, &FakeWorker)]) -> Arc<HttpState> {
    let mut state =
        Arc::into_inner(test_state(vec![ORIGIN.into()], Duration::from_secs(3600))).unwrap();
    state.server = None; // A missed worker must never fall through to a sandbox.
    state.workers = Some(Gateway {
        workers: workers
            .iter()
            .map(|(tenant, worker)| {
                (
                    (*tenant).to_owned(),
                    Worker {
                        address: worker.addr,
                        authorization: HeaderValue::from_str(&format!("Bearer {INTERNAL_TOKEN}"))
                            .unwrap(),
                    },
                )
            })
            .collect(),
        admission: Arc::new(Semaphore::new(MAX_REQUESTS)),
    });
    Arc::new(state)
}

struct Edge {
    addr: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Edge {
    fn new(state: Arc<HttpState>) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let thread = thread::spawn(move || {
            runtime.block_on(async move {
                axum::serve(listener, router(state))
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
                    .unwrap();
            })
        });
        Self {
            addr,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }
}

impl Drop for Edge {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(worker) = self.thread.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("edge worker panicked");
            }
        }
    }
}

fn initialize(agent: &ureq::Agent, edge: &Edge, token: &str) -> String {
    let reply = post(
        agent,
        edge.addr,
        Some(token),
        None,
        None,
        &rpc(1, "initialize", json!({})),
    );
    assert_eq!(reply.status, 200, "{:?}", reply.body);
    let public = reply.session.unwrap();
    assert_ne!(public, UPSTREAM_SESSION);
    public
}

fn delete(agent: &ureq::Agent, edge: &Edge, token: &str, session: &str) -> u16 {
    let mut response = agent
        .delete(format!("http://{}/", edge.addr))
        .header("authorization", format!("Bearer {token}"))
        .header("mcp-session-id", session)
        .call()
        .unwrap();
    let status = response.status().as_u16();
    response.body_mut().read_to_string().unwrap();
    status
}

#[test]
fn identical_upstream_sessions_get_distinct_tenant_owned_public_sessions() {
    let alice = FakeWorker::new(vec![
        Script::initialize(),
        Script::json(200, MIXED.as_bytes()),
    ]);
    let bob = FakeWorker::new(vec![
        Script::initialize(),
        Script::json(200, MIXED.as_bytes()),
    ]);
    let state = gateway_state(&[("alice", &alice), ("bob", &bob)]);
    let edge = Edge::new(state.clone());
    let client = agent();
    let a = initialize(&client, &edge, "tok-alice");
    let b = initialize(&client, &edge, "tok-bob");
    assert_ne!(a, b);
    {
        let sessions = state.sessions.lock().unwrap();
        assert_eq!(sessions[&a].tenant, "alice");
        assert_eq!(sessions[&b].tenant, "bob");
        assert_eq!(
            sessions[&a].worker_session.as_deref(),
            Some(UPSTREAM_SESSION)
        );
        assert_eq!(
            sessions[&b].worker_session.as_deref(),
            Some(UPSTREAM_SESSION)
        );
    }
    for (token, session) in [("tok-bob", &a), ("tok-alice", &b)] {
        assert_eq!(
            post(
                &client,
                edge.addr,
                Some(token),
                Some(session),
                None,
                &rpc(2, "tools/list", json!({}))
            )
            .status,
            403
        );
        assert_eq!(delete(&client, &edge, token, session), 403);
    }
    assert_eq!(alice.requests().len(), 1);
    assert_eq!(bob.requests().len(), 1);
    for (token, session) in [("tok-alice", &a), ("tok-bob", &b)] {
        assert_eq!(
            post(
                &client,
                edge.addr,
                Some(token),
                Some(session),
                None,
                &rpc(2, "tools/list", json!({}))
            )
            .status,
            200
        );
    }
    assert_eq!(
        alice.requests()[1].headers["mcp-session-id"],
        UPSTREAM_SESSION
    );
    assert_eq!(
        bob.requests()[1].headers["mcp-session-id"],
        UPSTREAM_SESSION
    );
}

#[test]
fn raw_duplicate_arguments_native_media_and_only_internal_credentials_cross_the_worker_hop() {
    let worker = FakeWorker::new(vec![
        Script::initialize().header("Set-Cookie", "internal-session=secret"),
        Script::json(200, MIXED.as_bytes())
            .header("Mcp-Session-Id", UPSTREAM_SESSION)
            .header("Authorization", &format!("Bearer {INTERNAL_TOKEN}"))
            .header("Set-Cookie", "internal-session=secret"),
    ]);
    let edge = Edge::new(gateway_state(&[("alice", &worker)]));
    let client = agent();
    let public = initialize(&client, &edge, "tok-alice");
    let raw = b"{\n \"jsonrpc\": \"2.0\", \"id\": 2, \"method\": \"tools/call\", \"params\": {\"name\":\"native\",\"arguments\":{\"x\":1,\"x\":2}}\n}";
    let mut response = client
        .post(format!("http://{}/", edge.addr))
        .header("Authorization", "Bearer tok-alice")
        .header("Cookie", "public-browser-cookie=never-forward")
        .header("Origin", ORIGIN)
        .header("Mcp-Session-Id", &public)
        .header("Mcp-Protocol-Version", "2025-06-18")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .send(raw.as_slice())
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    for name in ["mcp-session-id", "authorization", "set-cookie"] {
        assert!(!response.headers().contains_key(name), "leaked {name}");
    }
    assert_eq!(
        response.body_mut().read_to_string().unwrap().as_bytes(),
        MIXED.as_bytes()
    );
    let requests = worker.requests();
    assert_eq!(requests.len(), 2);
    let forwarded = &requests[1];
    assert_eq!(forwarded.method, "POST");
    assert_eq!(forwarded.body.as_slice(), raw.as_slice());
    assert_eq!(
        forwarded.headers["authorization"],
        format!("Bearer {INTERNAL_TOKEN}")
    );
    assert_eq!(forwarded.headers["mcp-session-id"], UPSTREAM_SESSION);
    assert_eq!(forwarded.headers["mcp-protocol-version"], "2025-06-18");
    assert_eq!(
        forwarded.headers["accept"],
        "application/json, text/event-stream"
    );
    assert!(!forwarded.headers.contains_key("origin"));
    assert!(!forwarded.headers.contains_key("cookie"));
    assert!(!requests[0].headers.contains_key("mcp-session-id"));
}

#[test]
fn dropped_upstream_response_reports_unknown_outcome_with_exactly_one_attempt() {
    let worker = FakeWorker::new(vec![Script::initialize(), Script::Disconnect]);
    let state = gateway_state(&[("alice", &worker)]);
    let edge = Edge::new(state.clone());
    let client = agent();
    let session = initialize(&client, &edge, "tok-alice");
    let reply = post(
        &client,
        edge.addr,
        Some("tok-alice"),
        Some(&session),
        None,
        &rpc(
            2,
            "tools/call",
            json!({"name": "write_once", "arguments": {}}),
        ),
    );
    assert_eq!(reply.status, 502);
    let message = reply.body["error"].as_str().unwrap();
    assert!(message.contains("outcome is unknown"), "{message}");
    assert!(message.contains("not retried"), "{message}");
    assert_eq!(worker.requests().len(), 2); // One initialize, one possibly-effective write.
    assert!(state.sessions.lock().unwrap().contains_key(&session));
}

#[test]
fn worker_auth_errors_and_redirects_are_not_public_challenges_or_followed() {
    for status in [301, 307, 401, 403] {
        let worker = FakeWorker::new(vec![
            Script::json(status, b"{}".to_vec())
                .header("Location", "http://127.0.0.1:1/must-not-follow")
                .header("WWW-Authenticate", "Bearer internal-only"),
        ]);
        let state = gateway_state(&[("alice", &worker)]);
        let edge = Edge::new(state.clone());
        let client = agent();
        let mut response = client
            .post(format!("http://{}/", edge.addr))
            .header("Authorization", "Bearer tok-alice")
            .send_json(rpc(1, "initialize", json!({})))
            .unwrap();
        assert_eq!(response.status().as_u16(), 502, "upstream status {status}");
        for name in ["location", "www-authenticate", "mcp-session-id"] {
            assert!(!response.headers().contains_key(name));
        }
        response.body_mut().read_to_string().unwrap();
        assert_eq!(worker.requests().len(), 1);
        assert!(state.sessions.lock().unwrap().is_empty());
    }
}

#[test]
fn malformed_and_notification_initialize_do_not_hit_worker_or_reserve_public_sessions() {
    let worker = FakeWorker::new(vec![Script::initialize()]);
    let mut state = gateway_state(&[("alice", &worker)]);
    Arc::get_mut(&mut state)
        .unwrap()
        .config
        .max_sessions_per_tenant = 1;
    let edge = Edge::new(state.clone());
    let client = agent();
    for body in [
        "{",
        "[]",
        "null",
        r#"{"jsonrpc":"2.0","method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":null,"method":"initialize","params":{}}"#,
    ] {
        let mut response = client
            .post(format!("http://{}/", edge.addr))
            .header("Authorization", "Bearer tok-alice")
            .header("Content-Type", "application/json")
            .send(body)
            .unwrap();
        assert_eq!(response.status().as_u16(), 400, "{body}");
        assert!(!response.headers().contains_key("mcp-session-id"));
        response.body_mut().read_to_string().unwrap();
        assert!(state.sessions.lock().unwrap().is_empty());
    }
    assert!(worker.requests().is_empty());
    initialize(&client, &edge, "tok-alice");
}

#[test]
fn every_failed_initialize_releases_its_reservation_before_a_valid_one() {
    let worker = FakeWorker::new(vec![
        Script::json(
            200,
            br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}"#
                .to_vec(),
        ),
        Script::json(200, b"not-json".to_vec()),
        Script::json(200, br#"{"jsonrpc":"2.0","id":99,"result":{}}"#.to_vec())
            .header("Mcp-Session-Id", UPSTREAM_SESSION),
        Script::json(200, br#"{"jsonrpc":"2.0","id":1,"result":{}}"#.to_vec()),
        Script::json(202, Vec::new()),
        Script::Disconnect,
        Script::initialize(),
    ]);
    let mut state = gateway_state(&[("alice", &worker)]);
    Arc::get_mut(&mut state)
        .unwrap()
        .config
        .max_sessions_per_tenant = 1;
    let edge = Edge::new(state.clone());
    let client = agent();
    for expected in [200, 502, 502, 502, 202, 502] {
        let reply = post(
            &client,
            edge.addr,
            Some("tok-alice"),
            None,
            None,
            &rpc(1, "initialize", json!({})),
        );
        assert_eq!(reply.status, expected, "{:?}", reply.body);
        assert!(reply.session.is_none());
        assert!(state.sessions.lock().unwrap().is_empty());
    }
    initialize(&client, &edge, "tok-alice");
    assert_eq!(worker.requests().len(), 7);
    assert_eq!(state.sessions.lock().unwrap().len(), 1);
}

#[test]
fn adjacent_initialize_ids_above_u64_are_compared_exactly_not_rounded_together() {
    let request =
        r#"{"jsonrpc":"2.0","id":18446744073709551617,"method":"initialize","params":{}}"#;
    let mismatched = br#"{"jsonrpc":"2.0","id":18446744073709551616,"result":{}}"#;
    let matching = br#"{"jsonrpc":"2.0","id":18446744073709551617,"result":{}}"#;
    let worker = FakeWorker::new(vec![
        Script::json(200, mismatched.to_vec()).header("Mcp-Session-Id", UPSTREAM_SESSION),
        Script::json(200, matching.to_vec()).header("Mcp-Session-Id", UPSTREAM_SESSION),
    ]);
    let state = gateway_state(&[("alice", &worker)]);
    let edge = Edge::new(state.clone());
    let client = agent();
    for expected in [502, 200] {
        let mut response = client
            .post(format!("http://{}/", edge.addr))
            .header("Authorization", "Bearer tok-alice")
            .header("Content-Type", "application/json")
            .send(request)
            .unwrap();
        assert_eq!(response.status().as_u16(), expected);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.headers().contains_key("mcp-session-id"),
            expected == 200
        );
        let text = response.body_mut().read_to_string().unwrap();
        if expected == 200 {
            assert_eq!(text.as_bytes(), matching);
            assert_eq!(state.sessions.lock().unwrap().len(), 1);
        } else {
            assert!(state.sessions.lock().unwrap().is_empty());
        }
    }
    let requests = worker.requests();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|seen| seen.body == request.as_bytes()));
}

#[test]
fn missing_worker_never_opens_a_session_or_falls_back_to_sandbox_tools() {
    let worker = FakeWorker::new(vec![]);
    let state = gateway_state(&[("alice", &worker)]);
    let edge = Edge::new(state.clone());
    let client = agent();
    let reply = post(
        &client,
        edge.addr,
        Some("tok-bob"),
        None,
        None,
        &rpc(1, "initialize", json!({})),
    );
    assert_eq!(reply.status, 503);
    assert!(
        reply.body["error"]
            .as_str()
            .unwrap()
            .contains("no Faculties worker")
    );
    assert!(reply.session.is_none());
    assert!(state.sessions.lock().unwrap().is_empty());
    assert!(worker.requests().is_empty());
}

#[test]
fn worker_not_found_and_explicit_delete_both_remove_only_the_public_mapping() {
    for terminate_with_delete in [false, true] {
        let worker = FakeWorker::new(vec![
            Script::initialize(),
            if terminate_with_delete {
                Script::json(204, Vec::new())
            } else {
                Script::json(404, br#"{"error":"worker session expired"}"#.to_vec())
            },
        ]);
        let state = gateway_state(&[("alice", &worker)]);
        let edge = Edge::new(state.clone());
        let client = agent();
        let session = initialize(&client, &edge, "tok-alice");
        if terminate_with_delete {
            assert_eq!(delete(&client, &edge, "tok-alice", &session), 204);
        } else {
            assert_eq!(
                post(
                    &client,
                    edge.addr,
                    Some("tok-alice"),
                    Some(&session),
                    None,
                    &rpc(2, "ping", json!({}))
                )
                .status,
                404
            );
        }
        assert!(!state.sessions.lock().unwrap().contains_key(&session));
        assert_eq!(
            post(
                &client,
                edge.addr,
                Some("tok-alice"),
                Some(&session),
                None,
                &rpc(2, "ping", json!({}))
            )
            .status,
            404
        );
        assert_eq!(delete(&client, &edge, "tok-alice", &session), 404);
        let requests = worker.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].method,
            if terminate_with_delete {
                "DELETE"
            } else {
                "POST"
            }
        );
        assert_eq!(requests[1].headers["mcp-session-id"], UPSTREAM_SESSION);
    }
}

#[test]
fn per_tenant_and_global_caps_refuse_without_eviction_or_extra_upstream_initialize() {
    for global_cap in [1, 2] {
        let alice = FakeWorker::new(vec![Script::initialize()]);
        let bob = FakeWorker::new(vec![]);
        let mut state = gateway_state(&[("alice", &alice), ("bob", &bob)]);
        let config = &mut Arc::get_mut(&mut state).unwrap().config;
        config.max_sessions_global = global_cap;
        config.max_sessions_per_tenant = 1;
        let edge = Edge::new(state.clone());
        let client = agent();
        let session = initialize(&client, &edge, "tok-alice");
        let token = if global_cap == 1 {
            "tok-bob"
        } else {
            "tok-alice"
        };
        let reply = post(
            &client,
            edge.addr,
            Some(token),
            None,
            None,
            &rpc(1, "initialize", json!({})),
        );
        assert_eq!(reply.status, 503);
        assert!(reply.session.is_none());
        assert_eq!(state.sessions.lock().unwrap().len(), 1);
        assert!(state.sessions.lock().unwrap().contains_key(&session));
        assert_eq!(alice.requests().len(), 1);
        assert!(bob.requests().is_empty());
    }
}

#[test]
fn request_and_response_budgets_bound_the_gateway_without_retry() {
    let worker = FakeWorker::new(vec![
        Script::initialize(),
        Script::json(200, vec![b' '; MAX_RESPONSE_BYTES + 1]),
    ]);
    let mut state = gateway_state(&[("alice", &worker)]);
    Arc::get_mut(&mut state).unwrap().config.max_body_bytes = 256;
    let edge = Edge::new(state.clone());
    let client = agent();
    let oversized = post(
        &client,
        edge.addr,
        Some("tok-alice"),
        None,
        None,
        &rpc(1, "initialize", json!({"large": "x".repeat(512)})),
    );
    assert_eq!(oversized.status, 413);
    assert!(worker.requests().is_empty());
    assert!(state.sessions.lock().unwrap().is_empty());
    let session = initialize(&client, &edge, "tok-alice");
    let response = post(
        &client,
        edge.addr,
        Some("tok-alice"),
        Some(&session),
        None,
        &rpc(2, "tools/list", json!({})),
    );
    assert_eq!(response.status, 502);
    assert!(
        response.body["error"]
            .as_str()
            .unwrap()
            .contains("outcome is unknown")
    );
    assert!(
        response.body["error"]
            .as_str()
            .unwrap()
            .contains("not retried")
    );
    assert_eq!(worker.requests().len(), 2);
}

#[test]
fn outgoing_byte_clones_retain_admission_until_the_last_owner_is_dropped() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let admission = Arc::new(Semaphore::new(1));
        let permit = admission.clone().try_acquire_owned().unwrap();
        let reply = WorkerReply {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::from_static(b"native bytes"),
        };
        let response = reply.into_response(None, permit);
        assert_eq!(admission.available_permits(), 0);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let last_owner = bytes.clone();
        assert_eq!(bytes.as_ref(), b"native bytes");
        drop(bytes);
        assert_eq!(admission.available_permits(), 0);
        drop(last_owner);
        assert_eq!(admission.available_permits(), 1);
    });
}

#[test]
fn revoked_public_token_cannot_reuse_an_existing_worker_mapping() {
    let worker = FakeWorker::new(vec![Script::initialize()]);
    let state = gateway_state(&[("alice", &worker)]);
    let edge = Edge::new(state.clone());
    let client = agent();
    let session = initialize(&client, &edge, "tok-alice");
    state.tokens.tokens.write().unwrap().remove("tok-alice");
    assert_eq!(
        post(
            &client,
            edge.addr,
            Some("tok-alice"),
            Some(&session),
            None,
            &rpc(2, "tools/list", json!({}))
        )
        .status,
        401
    );
    assert_eq!(delete(&client, &edge, "tok-alice", &session), 401);
    assert_eq!(worker.requests().len(), 1);
}

#[test]
fn persisted_oauth_revocation_is_live_before_a_worker_call_or_delete() {
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let scratch = Scratch(
        std::env::temp_dir().join(format!("playground_gateway_oauth_{}", random_urlsafe(16))),
    );
    std::fs::create_dir(&scratch.0).unwrap();
    let path = scratch.0.join("oauth.json");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut store = crate::oauth::OauthStore::default();
    let (access, _) = store.mint_token_pair(
        "alice",
        "mock",
        "test-client",
        ORIGIN,
        None,
        Duration::from_secs(3600),
        now,
    );
    store.save(&path).unwrap();
    let worker = FakeWorker::new(vec![Script::initialize()]);
    let mut state = gateway_state(&[("alice", &worker)]);
    Arc::get_mut(&mut state).unwrap().oauth = Some(
        crate::oauth::OauthRuntime::new(crate::oauth::OauthConfig {
            public_url: ORIGIN.into(),
            state_path: path.clone(),
            access_ttl: Duration::from_secs(3600),
        })
        .unwrap(),
    );
    let edge = Edge::new(state.clone());
    let client = agent();
    let session = initialize(&client, &edge, &access);
    let revoked = crate::oauth::revoke_tenant_locked(&path, "alice").unwrap();
    assert_eq!(revoked.access_tokens, 1);
    assert_eq!(revoked.refresh_tokens, 1);
    let reply = post(
        &client,
        edge.addr,
        Some(&access),
        Some(&session),
        None,
        &rpc(2, "tools/list", json!({})),
    );
    assert_eq!(reply.status, 401);
    assert_eq!(delete(&client, &edge, &access, &session), 401);
    assert_eq!(worker.requests().len(), 1);
    assert!(
        crate::oauth::OauthStore::load(&path)
            .unwrap()
            .access_tokens
            .is_empty()
    );
}
