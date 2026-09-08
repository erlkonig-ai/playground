use super::*;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "playground-worker-config-{}-{:x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::write(
            root.join("internal.key"),
            "local-worker-token-with-at-least-32-characters\r\n",
        )
        .unwrap();
        Self(root)
    }
    fn load(&self, value: Value) -> Result<Gateway> {
        let path = self.0.join("workers.json");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        Gateway::load(&path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn worker(tenant: &str, address: &str) -> Value {
    json!({"tenant": tenant, "address": address, "token_file": "internal.key"})
}

#[test]
fn manifest_resolves_relative_tokens_without_network_or_account_normalization() {
    let fixture = Fixture::new();
    let gateway = fixture
        .load(json!({"workers":[worker("Alice", "[::1]:8123")]}))
        .unwrap();
    let configured = &gateway.workers["Alice"];
    assert_eq!(configured.address, "[::1]:8123".parse().unwrap());
    assert!(configured.authorization.is_sensitive());
    assert!(!gateway.workers.contains_key("alice"));
    assert_eq!(gateway.admission.available_permits(), MAX_REQUESTS);
}

#[test]
fn manifest_rejects_empty_duplicate_or_shared_tenant_routes() {
    let fixture = Fixture::new();
    for entries in [
        vec![],
        vec![worker("", "127.0.0.1:8123")],
        vec![
            worker("alice", "127.0.0.1:8123"),
            worker("alice", "127.0.0.1:8124"),
        ],
        vec![
            worker("alice", "127.0.0.1:8123"),
            worker("bob", "127.0.0.1:8123"),
        ],
    ] {
        assert!(fixture.load(json!({"workers": entries})).is_err());
    }
}

#[test]
fn manifest_only_accepts_literal_nonzero_loopback_endpoints_and_known_fields() {
    let fixture = Fixture::new();
    for address in [
        "0.0.0.0:8123",
        "192.168.1.1:8123",
        "127.0.0.1:0",
        "localhost:8123",
        "https://127.0.0.1:8123/",
    ] {
        assert!(
            fixture
                .load(json!({"workers":[worker("alice", address)]}))
                .is_err(),
            "accepted {address}"
        );
    }
    let mut entry = worker("alice", "127.0.0.1:8123");
    entry["pile"] = json!("/caller-selected.pile");
    assert!(fixture.load(json!({"workers":[entry]})).is_err());
    assert!(
        fixture
            .load(json!({"workers":[worker("alice", "127.0.0.1:8123")], "extra":true}))
            .is_err()
    );
}

#[test]
fn internal_token_read_is_bounded_and_diagnostics_do_not_repeat_secret_bytes() {
    let fixture = Fixture::new();
    let path = fixture.0.join("internal.key");
    for invalid in [
        String::new(),
        "short".into(),
        "x".repeat(1025),
        format!("{}\n\n", "x".repeat(32)),
        format!("{} contains spaces", "x".repeat(32)),
        "ä".repeat(32),
    ] {
        std::fs::write(&path, &invalid).unwrap();
        let error = read_token(&path).unwrap_err().to_string();
        assert_eq!(
            error,
            "internal token must be 32..=1024 ASCII bearer characters"
        );
    }
    for valid in ["a".repeat(32), format!("{}\n", "z".repeat(1024))] {
        std::fs::write(&path, valid).unwrap();
        assert!(read_token(&path).unwrap().is_sensitive());
    }
}

#[test]
fn manifest_size_is_bounded_before_json_decoding() {
    let fixture = Fixture::new();
    let path = fixture.0.join("workers.json");
    std::fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
    assert!(
        Gateway::load(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("exceeds 1 MiB")
    );
}
