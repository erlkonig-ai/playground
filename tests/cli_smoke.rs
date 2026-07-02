//! CLI smoke test: run the real binary against a fresh temp pile.
//!
//! Guards the whole startup path (arg parsing, pile open + refresh,
//! Repository/Workspace setup, config branch bootstrap) against substrate
//! version drift — the class of breakage a pure unit-test suite misses.

use std::process::Command;

#[test]
fn config_show_on_fresh_temp_pile() {
    let dir = std::env::temp_dir().join(format!(
        "playground_cli_smoke_{}_{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let pile = dir.join("smoke.pile");
    // Pile::open requires an existing file; the workers are started against
    // an already-initialised pile, so mirror that here.
    std::fs::File::create(&pile).expect("create pile file");

    let output = Command::new(env!("CARGO_BIN_EXE_playground"))
        .args(["--pile", pile.to_str().unwrap(), "config", "show"])
        .output()
        .expect("run playground binary");

    assert!(
        output.status.success(),
        "playground config show failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let _ = std::fs::remove_dir_all(&dir);
}
