//! CLI smoke test: run the real `playground mcp` binary and drive a live MCP
//! handshake over its stdio transport.
//!
//! Guards the whole serving path (arg parsing, backend construction, the
//! stdio JSON-RPC loop) end-to-end through the actual process — the class of
//! breakage a pure in-process unit-test suite misses. `initialize` and
//! `tools/list` are backend-agnostic protocol methods, so this drives the real
//! server without provisioning a Lima VM.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn mcp_stdio_handshake_lists_three_tools() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_playground"))
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn playground mcp");

    let mut stdin = child.stdin.take().expect("child stdin");
    let mut stdout = BufReader::new(child.stdout.take().expect("child stdout"));

    // A real initialize + initialized + tools/list exchange.
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18"}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#
    )
    .unwrap();
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}"#).unwrap();
    stdin.flush().unwrap();

    let read_response = |stdout: &mut BufReader<std::process::ChildStdout>| {
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read response line");
        serde_json::from_str::<serde_json::Value>(line.trim()).expect("parse JSON-RPC response")
    };

    // initialize -> negotiated protocol version + serverInfo.
    let init = read_response(&mut stdout);
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "playground-sandbox");

    // tools/list -> the three sandbox tools (the notification produced no reply).
    let tools = read_response(&mut stdout);
    assert_eq!(tools["id"], 2);
    let names: Vec<&str> = tools["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 3);
    for want in ["open_session", "exec", "close_session"] {
        assert!(names.contains(&want), "missing tool {want} in {names:?}");
    }

    // Closing stdin is EOF for the server; it exits the serve loop cleanly.
    drop(stdin);
    let status = child.wait().expect("wait for child");
    assert!(status.success(), "server exited with {status:?}");
}
