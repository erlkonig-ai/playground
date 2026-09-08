//! The real gateway executable must start without constructing a sandbox
//! backend, even with an empty PATH and no remote-jail host configuration.
#![cfg(feature = "mcp-http")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Fixture {
    child: Option<Child>,
    workers: Vec<Child>,
    root: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        for child in &mut self.workers {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn gateway_cli_starts_without_sandbox_tools_and_reuses_oauth_discovery() {
    let root = std::env::temp_dir().join(format!(
        "playground-gateway-cli-{}-{:x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    let mut fixture = Fixture {
        child: None,
        workers: Vec::new(),
        root,
    };
    std::fs::write(
        fixture.root.join("tokens.json"),
        r#"{"tokens":{"public-alice":{"tenant":"alice","backend":"jail"}}}"#,
    )
    .unwrap();
    std::fs::write(
        fixture.root.join("worker.key"),
        "local-internal-token-with-at-least-32-characters\n",
    )
    .unwrap();
    std::fs::write(
        fixture.root.join("workers.json"),
        r#"{"workers":[{"tenant":"alice","address":"127.0.0.1:19876","token_file":"worker.key"}]}"#,
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    fixture.child = Some(
        Command::new(env!("CARGO_BIN_EXE_playground"))
            .env_clear()
            .env("PATH", "/no-sandbox-commands")
            .args([
                "mcp-http",
                "--backend",
                "jail",
                "--bind",
                &address.to_string(),
            ])
            .arg("--tokens")
            .arg(fixture.root.join("tokens.json"))
            .arg("--faculties-workers")
            .arg(fixture.root.join("workers.json"))
            .args(["--public-url", "https://mcp.example.test"])
            .arg("--oauth-state")
            .arg(fixture.root.join("oauth.json"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(2)))
            .build(),
    );
    let until = Instant::now() + Duration::from_secs(10);
    let mut metadata = loop {
        if let Ok(response) = agent
            .get(format!(
                "http://{address}/.well-known/oauth-protected-resource"
            ))
            .call()
        {
            break response;
        }
        assert!(
            fixture
                .child
                .as_mut()
                .unwrap()
                .try_wait()
                .unwrap()
                .is_none(),
            "gateway exited during startup"
        );
        assert!(Instant::now() < until, "gateway did not bind");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(metadata.status().as_u16(), 200);
    let value: serde_json::Value = metadata.body_mut().read_json().unwrap();
    assert_eq!(value["resource"], "https://mcp.example.test");
    assert_eq!(
        value["authorization_servers"][0],
        "https://mcp.example.test"
    );
    let mut rejected = agent
        .post(format!("http://{address}/"))
        .send_json(serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}))
        .unwrap();
    assert_eq!(rejected.status().as_u16(), 401);
    assert_eq!(
        rejected.headers().get("www-authenticate").unwrap(),
        "Bearer resource_metadata=\"https://mcp.example.test/.well-known/oauth-protected-resource\""
    );
    let _ = rejected.body_mut().read_to_string();
}

/// Run explicitly against an exact independently-built native HTTP cohort:
/// FACULTIES_HTTP_BINARY=/absolute/path/faculties cargo test --test cli_gateway -- --ignored
/// Discovery uses deliberately absent pile/key paths; it must remain inert.
#[test]
#[ignore = "requires an independently-built native Faculties HTTP executable"]
fn native_faculties_discovery_through_real_gateway_is_inert() {
    let faculties = std::env::var_os("FACULTIES_HTTP_BINARY").expect("set FACULTIES_HTTP_BINARY");
    let version = Command::new(&faculties).arg("--version").output().unwrap();
    assert!(version.status.success());
    eprintln!(
        "native worker under test: {}",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    let root = std::env::temp_dir().join(format!(
        "playground-native-gateway-{}-{:x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&root).unwrap();
    let mut fixture = Fixture {
        child: None,
        workers: Vec::new(),
        root,
    };
    let port = || {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let worker_address = port();
    let token = fixture.root.join("worker.key");
    std::fs::write(&token, "native-worker-only-test-token-with-32-characters\n").unwrap();
    let pile = fixture.root.join("absent.pile");
    let key = fixture.root.join("absent.key");
    fixture.workers.push(
        Command::new(&faculties)
            .env_clear()
            .args(["mcp", "--http-listen", &worker_address.to_string()])
            .arg("--http-token-file")
            .arg(&token)
            .arg("--pile")
            .arg(&pile)
            .arg("--key")
            .arg(&key)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    std::fs::write(
        fixture.root.join("tokens.json"),
        r#"{"tokens":{"public-alice":{"tenant":"alice","backend":"jail"}}}"#,
    )
    .unwrap();
    std::fs::write(
        fixture.root.join("workers.json"),
        serde_json::to_vec(&serde_json::json!({"workers":[{
            "tenant":"alice", "address":worker_address.to_string(), "token_file":"worker.key"
        }]}))
        .unwrap(),
    )
    .unwrap();
    let address = port();
    fixture.child = Some(
        Command::new(env!("CARGO_BIN_EXE_playground"))
            .env_clear()
            .env("PATH", "/no-sandbox-commands")
            .args([
                "mcp-http",
                "--backend",
                "jail",
                "--bind",
                &address.to_string(),
            ])
            .arg("--tokens")
            .arg(fixture.root.join("tokens.json"))
            .arg("--faculties-workers")
            .arg(fixture.root.join("workers.json"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(2)))
            .build(),
    );
    for addr in [worker_address, address] {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(mut response) = agent.get(format!("http://{addr}/")).call() {
                let _ = response.body_mut().read_to_string();
                break;
            }
            assert!(Instant::now() < until, "server did not bind");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let post = |session: Option<&str>, body: serde_json::Value| {
        let mut request = agent
            .post(format!("http://{address}/"))
            .header("Authorization", "Bearer public-alice")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-06-18");
        if let Some(session) = session {
            request = request.header("MCP-Session-Id", session);
        }
        request.send_json(body).unwrap()
    };
    let mut init = post(
        None,
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18", "capabilities":{}, "clientInfo":{"name":"gateway-test","version":"1"}
        }}),
    );
    assert_eq!(
        init.status().as_u16(),
        200,
        "{}",
        init.body_mut().read_to_string().unwrap()
    );
    let session = init
        .headers()
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let result: serde_json::Value = init.body_mut().read_json().unwrap();
    assert_eq!(result["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        post(
            Some(&session),
            serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .status()
        .as_u16(),
        202
    );
    let mut listed = post(
        Some(&session),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    );
    assert_eq!(listed.status().as_u16(), 200);
    assert_eq!(listed.headers().get("cache-control").unwrap(), "no-store");
    let tools: serde_json::Value = listed.body_mut().read_json().unwrap();
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 218);
    assert!(
        names.contains(&"files_view")
            && names.contains(&"files_get")
            && names.contains(&"wiki_show")
    );
    let deleted = agent
        .delete(format!("http://{address}/"))
        .header("Authorization", "Bearer public-alice")
        .header("MCP-Session-Id", &session)
        .header("MCP-Protocol-Version", "2025-06-18")
        .call()
        .unwrap();
    assert_eq!(deleted.status().as_u16(), 204);
    assert!(
        !pile.exists() && !key.exists(),
        "discovery must not create/open tenant storage"
    );
}
