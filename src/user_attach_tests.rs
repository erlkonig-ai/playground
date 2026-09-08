use super::*;
use sandbox::{
    ExecControl, ExecRequest, ExecResult, OpenSpec, ProvisionSpec, SandboxBackend, SessionId,
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct AttachOnly {
    opens: AtomicUsize,
    fail: bool,
}

impl SandboxBackend for AttachOnly {
    fn name(&self) -> &'static str {
        "attach-only"
    }

    fn open_session(&self, spec: &OpenSpec) -> Result<SessionId> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        assert_eq!(spec.tenant.label, "Alice \"QA\"");
        anyhow::ensure!(!self.fail, "existing sandbox could not be verified");
        Ok(SessionId::new("backend-owned-opaque-session-id"))
    }

    fn provision_sandbox(&self, _: &ProvisionSpec) -> Result<()> {
        panic!("attach must never provision")
    }

    fn reattach_all(&self) -> Result<usize> {
        panic!("attach must affect only the named tenant")
    }

    fn exec(&self, _: &SessionId, _: &ExecRequest, _: &ExecControl) -> Result<ExecResult> {
        panic!("attach must never run a guest command")
    }

    fn close_session(&self, _: &SessionId) -> Result<()> {
        panic!("attach must leave the sandbox running")
    }

    fn destroy_session(&self, _: &SessionId) -> Result<()> {
        panic!("attach must never destroy")
    }

    fn shutdown(&self) -> Result<usize> {
        panic!("attach must never shut down other sandboxes")
    }
}

#[test]
fn attach_uses_only_open_and_returns_backend_identity_as_json() {
    let backend = AttachOnly::default();
    let result = attach_user(&backend, McpBackendKind::Jail, "Alice \"QA\"").unwrap();
    let persona = sandbox::policy::TenantAssistantPersona::for_tenant("Alice \"QA\"").unwrap();
    assert_eq!(
        result,
        serde_json::json!({
            "session_id": "backend-owned-opaque-session-id",
            "persona": persona.label,
        })
    );
    assert_eq!(backend.opens.load(Ordering::SeqCst), 1);
    // Scripts consume JSON, not shell assignments or whitespace-delimited
    // labels: quotation marks must survive the stdout representation exactly.
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&result.to_string()).unwrap(),
        result
    );
}

#[test]
fn attach_propagates_verification_failure_without_fallback() {
    let backend = AttachOnly {
        fail: true,
        ..Default::default()
    };
    let error = attach_user(&backend, McpBackendKind::Jail, "Alice \"QA\"").unwrap_err();
    assert!(format!("{error:#}").contains("existing sandbox could not be verified"));
    assert_eq!(backend.opens.load(Ordering::SeqCst), 1);
}

#[test]
fn attach_rejects_an_invalid_persona_before_open() {
    let backend = AttachOnly::default();
    for name in [" Alice", "Alice ", "abcdefghijklmnopqrstuvw"] {
        assert!(attach_user(&backend, McpBackendKind::Jail, name).is_err());
    }
    assert_eq!(backend.opens.load(Ordering::SeqCst), 0);
}

#[test]
fn attach_preserves_limas_existing_persona_convention() {
    let backend = AttachOnly::default();
    let result = attach_user(&backend, McpBackendKind::Lima, "Alice \"QA\"").unwrap();
    assert_eq!(result["persona"], "Alice \"QA\"");
    assert_eq!(backend.opens.load(Ordering::SeqCst), 1);
}

#[test]
fn attach_cli_needs_no_auth_state_and_accepts_exact_jail_topology() {
    let cli = Cli::try_parse_from([
        "playground",
        "user",
        "attach",
        "alice",
        "--backend",
        "jail",
        "--jail-local",
        "--jail-external-rctl",
        "--jail-prefix",
        "colleague",
        "--jail-dataset-parent",
        "pool/playground/jails",
        "--jail-pile-root",
        "/var/db/playground/piles",
    ])
    .unwrap();
    let Some(CommandMode::User {
        command: UserCommand::Attach(args),
    }) = cli.command
    else {
        panic!("attach command")
    };
    assert_eq!(args.name, "alice");
    assert_eq!(args.backend.backend.name(), "jail");
    assert!(args.backend.jail_local);
    assert!(args.backend.jail_external_rctl);
    assert_eq!(args.backend.jail_prefix, "colleague");
    assert_eq!(args.backend.jail_dataset_parent, "pool/playground/jails");
    assert_eq!(args.backend.jail_pile_root, "/var/db/playground/piles");
    for flag in ["--tokens", "--oauth-state", "--faculty-pile"] {
        assert!(
            Cli::try_parse_from(["playground", "user", "attach", "alice", flag, "not-opened",])
                .is_err(),
            "attach must not accept {flag}"
        );
    }
}

#[test]
fn credential_commands_keep_their_explicit_token_store() {
    for arguments in [
        vec!["playground", "user", "create", "alice"],
        vec!["playground", "user", "list"],
        vec!["playground", "user", "destroy", "alice"],
        vec!["playground", "user", "token", "show", "alice"],
        vec!["playground", "user", "token", "reset", "alice"],
    ] {
        // An explicit value must still round-trip for every existing verb.
        // Don't test absence here: the operator may set PLAYGROUND_MCP_TOKENS.
        let cli = Cli::try_parse_from(arguments.into_iter().chain(["--tokens", "accounts.json"]))
            .unwrap();
        let Some(CommandMode::User { command }) = cli.command else {
            panic!("user command")
        };
        let tokens = match command {
            UserCommand::Create(args) => args.tokens,
            UserCommand::List(args) => args.tokens,
            UserCommand::Destroy(args) => args.tokens,
            UserCommand::Token(UserTokenCommand::Show(args)) => args.tokens,
            UserCommand::Token(UserTokenCommand::Reset(args)) => args.tokens,
            _ => panic!("credential command"),
        };
        assert_eq!(tokens, PathBuf::from("accounts.json"));
    }
}
