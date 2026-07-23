//! playground — the sandbox-MCP provider.
//!
//! playground provisions isolated, stateful shells (Lima VMs on macOS, FreeBSD
//! jails over SSH) and exposes them over the Model Context Protocol. It is the
//! *sandbox layer* (layer 3 of 4: Substrate / Verbs / **Sandbox** / Drive) — the
//! exec transport the drive (the being's realtime cognition loop) calls to run
//! its shell commands. The cognition machinery lives in the `drive` crate now;
//! playground is only the provider.
//!
//! Subcommands:
//!   - `mcp`       — serve the provider over stdio (JSON-RPC 2.0), operator-local.
//!   - `mcp-http`  — serve over Streamable-HTTP with per-sandbox bearer tokens
//!                   (feature `mcp-http`).
//!   - `user`      — provision/list/destroy per-tenant sandboxes and manage the
//!                   bearer tokens `mcp-http` checks against (feature `mcp-http`).

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

mod mcp;
#[cfg(feature = "mcp-http")]
mod mcp_http;
#[cfg(feature = "mcp-http")]
mod oauth;
mod sandbox;

#[derive(Subcommand, Debug)]
enum CommandMode {
    #[command(about = "Serve the sandbox provider over MCP (JSON-RPC 2.0 on stdio)")]
    Mcp(McpArgs),
    #[cfg(feature = "mcp-http")]
    #[command(
        name = "mcp-http",
        about = "Serve the sandbox provider over Streamable-HTTP MCP (per-sandbox bearer tokens)"
    )]
    McpHttp(McpHttpArgs),
    #[cfg(feature = "mcp-http")]
    #[command(about = "Provision per-tenant sandboxes and manage their MCP bearer tokens")]
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    #[cfg(feature = "mcp-http")]
    #[command(about = "Mint an OAuth invite code (the human gate of the browser-connector flow)")]
    Invite(TokenInviteArgs),
    #[cfg(feature = "mcp-http")]
    #[command(
        about = "Spin down orphaned sandbox VMs left running after a hard kill (Lima; jail is a no-op)"
    )]
    Clean(CleanArgs),
}

#[derive(Args, Debug, Clone)]
#[command(about = "MCP sandbox-provider server settings")]
struct McpArgs {
    /// Which sandbox backend provisions sessions.
    #[arg(long, value_enum, default_value_t = McpBackendKind::Lima)]
    backend: McpBackendKind,
    /// Lima instance-name prefix; concrete instance is `<prefix>-<tenant>`.
    #[arg(long, default_value = "playground-sbx")]
    instance_prefix: String,
    /// Directory for rendered per-session Lima configs.
    #[arg(long)]
    state_root: Option<PathBuf>,
    /// Lima session template (defaults to scripts/lima-session.yaml.tmpl).
    #[arg(long)]
    template: Option<PathBuf>,
    /// Lima backend: host path to the `faculties` crate. When set, its CLI
    /// binaries are built for Linux-aarch64 (once, cached) and staged into every
    /// session on PATH with `PILE` pointing at the mounted pile, so `compass
    /// list` / `wiki search X` run in a session operate on its pile.
    #[arg(long, env = "PLAYGROUND_FACULTIES_SRC")]
    faculties_src: Option<PathBuf>,
    /// Jail backend: SSH host that runs the jails (needs BatchMode keys +
    /// non-interactive root via `sudo -n`).
    #[arg(long, default_value = "ai.bultmann.eu")]
    jail_host: String,
    /// Jail backend: ZFS template snapshot cloned per session.
    #[arg(long, default_value = "aitemp/playground/template@base")]
    jail_template_snapshot: String,
    /// Jail backend: parent dataset that holds per-session clones.
    #[arg(long, default_value = "aitemp/playground")]
    jail_dataset_parent: String,
    /// Jail backend: jail-name prefix; concrete jail is `<prefix>-<tenant>`.
    #[arg(long, default_value = "playground")]
    jail_prefix: String,
    /// Jail backend: host directory root holding per-coworker pile dirs and the
    /// shared pile dir (Model B: host-owned, decoupled from the jail lifecycle).
    #[arg(long, default_value = "/aitemp/playground/piles")]
    jail_pile_root: String,
    /// Jail backend: host path to the `bootstrap.pile` seed copied into a new
    /// coworker's `self.pile` (and the shared pile) when absent.
    #[arg(long, default_value = "/aitemp/playground/bootstrap.pile")]
    jail_bootstrap_pile: String,
    /// Jail backend: run zfs/jail/jexec directly on this machine instead of
    /// over SSH (server-side hosting on the FreeBSD jail host itself;
    /// `--jail-host` is ignored).
    #[arg(long, default_value_t = false)]
    jail_local: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum McpBackendKind {
    /// Local Lima VM per session (macOS host).
    Lima,
    /// FreeBSD jail per session on a remote host over SSH (pile-less v1;
    /// see src/sandbox/jail.rs for the trust boundary).
    Jail,
}

impl McpBackendKind {
    /// The backend name as recorded in the token store and reported by
    /// `SandboxBackend::name` — the three must agree for auth to line up.
    #[cfg_attr(not(feature = "mcp-http"), allow(dead_code))]
    fn name(self) -> &'static str {
        match self {
            McpBackendKind::Lima => "lima",
            McpBackendKind::Jail => "jail",
        }
    }

    /// Build the concrete backend this kind selects.
    #[allow(clippy::too_many_arguments)]
    fn build(
        self,
        instance_prefix: String,
        state_root: Option<PathBuf>,
        template: Option<PathBuf>,
        faculties_src: Option<PathBuf>,
        jail_host: String,
        jail_local: bool,
        jail_prefix: String,
        jail_template_snapshot: String,
        jail_dataset_parent: String,
        jail_pile_root: String,
        jail_bootstrap_pile: String,
    ) -> Result<Box<dyn sandbox::SandboxBackend>> {
        match self {
            McpBackendKind::Lima => {
                let mut backend = sandbox::lima::LimaBackend::new(instance_prefix);
                if let Some(root) = state_root {
                    backend.state_root = root;
                }
                backend.template = template;
                // Stage faculties: build (once, cached) a Linux-aarch64 bundle
                // and hand its host path to the backend, which mounts it into
                // every session on PATH with PILE set. Done up front (not per
                // session) so the slow build happens at server start.
                if let Some(src) = faculties_src {
                    let builder = format!("{}-faculties-builder", backend.instance_prefix);
                    let bundle = sandbox::faculties::ensure_faculties_bundle(&src, &builder)
                        .context("provision faculties bundle for sandbox sessions")?;
                    backend.faculties_bundle = Some(bundle);
                }
                Ok(Box::new(backend))
            }
            McpBackendKind::Jail => {
                let mut backend = if jail_local {
                    sandbox::jail::JailBackend::local()
                } else {
                    sandbox::jail::JailBackend::ssh(jail_host)
                };
                backend.jail_prefix = jail_prefix;
                backend.template_snapshot = jail_template_snapshot;
                backend.dataset_parent = jail_dataset_parent;
                backend.pile_root = jail_pile_root;
                backend.bootstrap_pile = jail_bootstrap_pile;
                Ok(Box::new(backend))
            }
        }
    }
}

#[cfg(feature = "mcp-http")]
#[derive(Args, Debug, Clone)]
#[command(about = "Streamable-HTTP MCP server settings")]
struct McpHttpArgs {
    /// Address to bind. Loopback by default; internet exposure is expected to
    /// go behind a TLS-terminating reverse proxy (this server is plain HTTP).
    #[arg(long, default_value = "127.0.0.1:8377")]
    bind: std::net::SocketAddr,
    /// Token store (JSON) provisioned with `playground user create`.
    #[arg(long, env = "PLAYGROUND_MCP_TOKENS")]
    tokens: PathBuf,
    /// Origin header values to accept (repeatable). Requests carrying any
    /// other Origin are rejected (DNS-rebinding defence); requests without an
    /// Origin header (plain MCP clients) always pass.
    #[arg(long = "allow-origin")]
    allow_origin: Vec<String>,
    /// Idle MCP-session expiry in seconds (sessions are transport state only;
    /// sandbox sessions survive and are reachable after re-initialize).
    #[arg(long, default_value_t = 3600)]
    idle_timeout_secs: u64,
    /// Public base URL of this server as clients reach it (through the TLS
    /// proxy), e.g. `https://mcp.example.org`. Enables OAuth 2.1 for
    /// browser-based MCP connectors; requires --oauth-state.
    #[arg(long, requires = "oauth_state")]
    public_url: Option<String>,
    /// OAuth persistent state (JSON: clients, invite codes, tokens); created
    /// if missing, written mode 0600. Requires --public-url.
    #[arg(long, env = "PLAYGROUND_MCP_OAUTH_STATE", requires = "public_url")]
    oauth_state: Option<PathBuf>,
    /// OAuth access-token lifetime in seconds (refresh tokens rotate forever).
    #[arg(long, default_value_t = 3600)]
    oauth_access_ttl_secs: u64,
    /// Which sandbox backend provisions sessions.
    #[arg(long, value_enum, default_value_t = McpBackendKind::Lima)]
    backend: McpBackendKind,
    /// Lima instance-name prefix; concrete instance is `<prefix>-<tenant>`.
    #[arg(long, default_value = "playground-sbx")]
    instance_prefix: String,
    /// Directory for rendered per-session Lima configs.
    #[arg(long)]
    state_root: Option<PathBuf>,
    /// Lima session template (defaults to scripts/lima-session.yaml.tmpl).
    #[arg(long)]
    template: Option<PathBuf>,
    /// Lima backend: host path to the `faculties` crate. When set, its CLI
    /// binaries are built for Linux-aarch64 (once, cached) and staged into every
    /// session on PATH with `PILE` set to the mounted pile.
    #[arg(long, env = "PLAYGROUND_FACULTIES_SRC")]
    faculties_src: Option<PathBuf>,
    /// Jail backend: SSH host that runs the jails (needs BatchMode keys +
    /// non-interactive root via `sudo -n`).
    #[arg(long, default_value = "ai.bultmann.eu")]
    jail_host: String,
    /// Jail backend: ZFS template snapshot cloned per session.
    #[arg(long, default_value = "aitemp/playground/template@base")]
    jail_template_snapshot: String,
    /// Jail backend: parent dataset that holds per-session clones.
    #[arg(long, default_value = "aitemp/playground")]
    jail_dataset_parent: String,
    /// Jail backend: jail-name prefix; concrete jail is `<prefix>-<tenant>`.
    #[arg(long, default_value = "playground")]
    jail_prefix: String,
    /// Jail backend: host directory root holding per-coworker pile dirs and the
    /// shared pile dir (Model B: host-owned, decoupled from the jail lifecycle).
    #[arg(long, default_value = "/aitemp/playground/piles")]
    jail_pile_root: String,
    /// Jail backend: host path to the `bootstrap.pile` seed copied into a new
    /// coworker's `self.pile` (and the shared pile) when absent.
    #[arg(long, default_value = "/aitemp/playground/bootstrap.pile")]
    jail_bootstrap_pile: String,
    /// Jail backend: run zfs/jail/jexec directly on this machine instead of
    /// over SSH (server-side hosting on the FreeBSD jail host itself;
    /// `--jail-host` is ignored).
    #[arg(long, default_value_t = false)]
    jail_local: bool,
}

/// Backend/token configuration shared by every `user` verb: which sandbox
/// backend owns the tenant (so the CLI can build it and the token records the
/// right backend name), the token store to read/write, and the jail-backend
/// connection details. Flattened into each `user` subcommand's args so the flag
/// surface matches `mcp-http`'s.
#[cfg(feature = "mcp-http")]
#[derive(Args, Debug, Clone)]
struct UserBackendArgs {
    /// Token store (JSON) — where bearer tokens live; created if missing.
    #[arg(long, env = "PLAYGROUND_MCP_TOKENS")]
    tokens: PathBuf,
    /// Which sandbox backend owns this tenant (must match the serving
    /// `mcp-http --backend`; the minted token is scoped to it).
    #[arg(long, value_enum, default_value_t = McpBackendKind::Jail)]
    backend: McpBackendKind,
    /// Lima backend: instance-name prefix; concrete instance is
    /// `<prefix>-<tenant>`. Must match the serving `mcp-http --instance-prefix`.
    #[arg(long, default_value = "playground-sbx")]
    instance_prefix: String,
    /// Lima backend: directory for rendered per-session Lima configs.
    #[arg(long)]
    state_root: Option<PathBuf>,
    /// Lima backend: session template (defaults to scripts/lima-session.yaml.tmpl).
    #[arg(long)]
    template: Option<PathBuf>,
    /// Lima backend: host path to the `faculties` crate. When set, its CLI
    /// binaries are built for Linux-aarch64 (once, cached) and staged into the
    /// provisioned sandbox on PATH with `PILE` set to the mounted pile.
    #[arg(long, env = "PLAYGROUND_FACULTIES_SRC")]
    faculties_src: Option<PathBuf>,
    /// Jail backend: SSH host that runs the jails (needs BatchMode keys +
    /// non-interactive root via `sudo -n`).
    #[arg(long, default_value = "ai.bultmann.eu")]
    jail_host: String,
    /// Jail backend: ZFS template snapshot cloned per session.
    #[arg(long, default_value = "aitemp/playground/template@base")]
    jail_template_snapshot: String,
    /// Jail backend: parent dataset that holds per-session clones.
    #[arg(long, default_value = "aitemp/playground")]
    jail_dataset_parent: String,
    /// Jail backend: jail-name prefix; concrete jail is `<prefix>-<tenant>`.
    #[arg(long, default_value = "playground")]
    jail_prefix: String,
    /// Jail backend: host directory root holding per-coworker pile dirs and the
    /// shared pile dir (Model B: host-owned, decoupled from the jail lifecycle).
    #[arg(long, default_value = "/aitemp/playground/piles")]
    jail_pile_root: String,
    /// Jail backend: host path to the `bootstrap.pile` seed copied into a new
    /// coworker's `self.pile` (and the shared pile) when absent.
    #[arg(long, default_value = "/aitemp/playground/bootstrap.pile")]
    jail_bootstrap_pile: String,
    /// Jail backend: run zfs/jail/jexec directly on this machine instead of
    /// over SSH (server-side hosting on the FreeBSD jail host itself).
    #[arg(long, default_value_t = false)]
    jail_local: bool,
}

#[cfg(feature = "mcp-http")]
impl UserBackendArgs {
    /// Build the concrete backend these args select as a boxed trait object.
    /// Both shipped backends (jail, lima) are persistent/provision-based, so
    /// `user create`/`user destroy` work for either. The token verbs never call
    /// this — they only touch the token store.
    fn build_backend(&self) -> Result<Box<dyn sandbox::SandboxBackend>> {
        match self.backend {
            McpBackendKind::Jail => {
                let mut backend = if self.jail_local {
                    sandbox::jail::JailBackend::local()
                } else {
                    sandbox::jail::JailBackend::ssh(self.jail_host.clone())
                };
                backend.jail_prefix = self.jail_prefix.clone();
                backend.template_snapshot = self.jail_template_snapshot.clone();
                backend.dataset_parent = self.jail_dataset_parent.clone();
                backend.pile_root = self.jail_pile_root.clone();
                backend.bootstrap_pile = self.jail_bootstrap_pile.clone();
                Ok(Box::new(backend))
            }
            McpBackendKind::Lima => {
                let mut backend = sandbox::lima::LimaBackend::new(self.instance_prefix.clone());
                if let Some(root) = &self.state_root {
                    backend.state_root = root.clone();
                }
                backend.template = self.template.clone();
                // Stage faculties into the provisioned box (same as the server),
                // so a provisioned Lima sandbox comes up with faculties on PATH.
                if let Some(src) = &self.faculties_src {
                    let builder = format!("{}-faculties-builder", backend.instance_prefix);
                    let bundle = sandbox::faculties::ensure_faculties_bundle(src, &builder)
                        .context("provision faculties bundle for sandbox sessions")?;
                    backend.faculties_bundle = Some(bundle);
                }
                Ok(Box::new(backend))
            }
        }
    }

    /// The backend-appropriate session id (instance / jail name) for a tenant
    /// label. Both backends sanitise the same way (`<prefix>-<sanitised>`), so
    /// the CLI's `destroy` targets the exact box the backend provisioned.
    fn session_id_for(&self, label: &str) -> sandbox::SessionId {
        let name = match self.backend {
            McpBackendKind::Jail => {
                // Reuse the backend's own derivation so prefixes/sanitisation agree.
                let mut b = sandbox::jail::JailBackend::local();
                b.jail_prefix = self.jail_prefix.clone();
                b.jail_name(label)
            }
            McpBackendKind::Lima => {
                sandbox::lima::LimaBackend::new(self.instance_prefix.clone()).instance_name(label)
            }
        };
        sandbox::SessionId::new(name)
    }

    /// Best-effort liveness probe for `user list`: is the tenant's box currently
    /// running? Both persistent backends can answer.
    fn running_for_label(&self, label: &str) -> bool {
        match self.backend {
            McpBackendKind::Jail => {
                let mut b = if self.jail_local {
                    sandbox::jail::JailBackend::local()
                } else {
                    sandbox::jail::JailBackend::ssh(self.jail_host.clone())
                };
                b.jail_prefix = self.jail_prefix.clone();
                b.jail_running_for_label(label)
            }
            McpBackendKind::Lima => sandbox::lima::LimaBackend::new(self.instance_prefix.clone())
                .instance_running_for_label(label),
        }
    }
}

#[cfg(feature = "mcp-http")]
#[derive(Subcommand, Debug)]
enum UserCommand {
    #[command(about = "Provision a tenant's persistent sandbox and mint its bearer token")]
    Create(UserCreateArgs),
    #[command(about = "List the tenants known to the token store (and whether their jail is live)")]
    List(UserListArgs),
    #[command(about = "Destroy a tenant's sandbox and remove its tokens")]
    Destroy(UserDestroyArgs),
    #[command(subcommand, about = "Show or reset a tenant's bearer token")]
    Token(UserTokenCommand),
}

#[cfg(feature = "mcp-http")]
#[derive(Subcommand, Debug)]
enum UserTokenCommand {
    #[command(about = "Print the token(s) for a tenant (from the store)")]
    Show(UserTokenShowArgs),
    #[command(about = "Revoke a tenant's existing token(s) and mint a fresh one")]
    Reset(UserTokenResetArgs),
}

#[cfg(feature = "mcp-http")]
#[derive(Args, Debug, Clone)]
struct UserCreateArgs {
    /// Tenant label (persona / instance); sandbox + token are scoped to it.
    name: String,
    #[command(flatten)]
    backend: UserBackendArgs,
}

#[cfg(feature = "mcp-http")]
#[derive(Args, Debug, Clone)]
struct UserListArgs {
    #[command(flatten)]
    backend: UserBackendArgs,
}

#[cfg(feature = "mcp-http")]
#[derive(Args, Debug, Clone)]
struct UserDestroyArgs {
    /// Tenant label to destroy (its sandbox is torn down, tokens removed).
    name: String,
    #[command(flatten)]
    backend: UserBackendArgs,
}

#[cfg(feature = "mcp-http")]
#[derive(Args, Debug, Clone)]
struct UserTokenShowArgs {
    /// Tenant whose token(s) to print.
    name: String,
    #[command(flatten)]
    backend: UserBackendArgs,
}

#[cfg(feature = "mcp-http")]
#[derive(Args, Debug, Clone)]
struct UserTokenResetArgs {
    /// Tenant whose token(s) to revoke and re-mint.
    name: String,
    #[command(flatten)]
    backend: UserBackendArgs,
}

#[cfg(feature = "mcp-http")]
#[derive(Args, Debug, Clone)]
struct CleanArgs {
    #[command(flatten)]
    backend: UserBackendArgs,
}

#[cfg(feature = "mcp-http")]
#[derive(Args, Debug, Clone)]
#[command(about = "OAuth invite-code mint settings")]
struct TokenInviteArgs {
    /// Tenant label whoever redeems the invite acts as.
    #[arg(long)]
    tenant: String,
    /// OAuth state file (JSON) to append to; created if missing. Must be the
    /// same file the server runs with (`mcp-http --oauth-state`).
    #[arg(long, env = "PLAYGROUND_MCP_OAUTH_STATE")]
    oauth_state: PathBuf,
    /// Keep the invite valid after use (default: single-use, consumed on
    /// first successful authorization).
    #[arg(long, default_value_t = false)]
    reusable: bool,
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "playground — the sandbox-MCP provider (isolated shells over MCP)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<CommandMode>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    match command {
        CommandMode::Mcp(args) => run_mcp(args),
        #[cfg(feature = "mcp-http")]
        CommandMode::McpHttp(args) => run_mcp_http(args),
        #[cfg(feature = "mcp-http")]
        CommandMode::User { command } => match command {
            UserCommand::Create(args) => run_user_create(args),
            UserCommand::List(args) => run_user_list(args),
            UserCommand::Destroy(args) => run_user_destroy(args),
            UserCommand::Token(command) => match command {
                UserTokenCommand::Show(args) => run_user_token_show(args),
                UserTokenCommand::Reset(args) => run_user_token_reset(args),
            },
        },
        #[cfg(feature = "mcp-http")]
        CommandMode::Invite(args) => run_token_invite(args),
        #[cfg(feature = "mcp-http")]
        CommandMode::Clean(args) => run_clean(args),
    }
}

/// Serve the sandbox provider over MCP (stdio, JSON-RPC 2.0).
///
/// This does not open a pile itself — tenants (pile mount × driver) are
/// supplied per `open_session` tool call, so one server can host several piles.
/// Diagnostics go to stderr; stdout is reserved for the JSON-RPC stream.
///
/// Sandbox lifecycle guarantee: every session this connection opens is torn
/// down when the connection ends (client EOF/disconnect) or the process is
/// asked to stop (SIGINT/SIGTERM). A crashed or disconnected client can never
/// leak a VM/jail — the guarantee lives here, in the provider, never in the
/// client.
fn run_mcp(args: McpArgs) -> Result<()> {
    let backend = args.backend.build(
        args.instance_prefix,
        args.state_root,
        args.template,
        args.faculties_src,
        args.jail_host,
        args.jail_local,
        args.jail_prefix,
        args.jail_template_snapshot,
        args.jail_dataset_parent,
        args.jail_pile_root,
        args.jail_bootstrap_pile,
    )?;

    let provider = mcp::SandboxProvider::new(backend);
    let server = mcp::McpServer::new(provider);
    eprintln!("playground mcp: sandbox provider on stdio (JSON-RPC 2.0)");
    let mut transport = mcp::StdioTransport::stdio();
    server.serve_stdio(&mut transport)
}

/// Serve the sandbox provider over Streamable-HTTP MCP with per-sandbox
/// bearer-token auth. See `src/mcp_http.rs` for the protocol/auth model and
/// the concurrency design.
#[cfg(feature = "mcp-http")]
fn run_mcp_http(args: McpHttpArgs) -> Result<()> {
    let backend = args.backend.build(
        args.instance_prefix,
        args.state_root,
        args.template,
        args.faculties_src,
        args.jail_host,
        args.jail_local,
        args.jail_prefix,
        args.jail_template_snapshot,
        args.jail_dataset_parent,
        args.jail_pile_root,
        args.jail_bootstrap_pile,
    )?;

    let tokens = mcp_http::TokenStore::load(&args.tokens)?;
    let usable = tokens
        .tokens
        .values()
        .filter(|entry| entry.backend == args.backend.name())
        .count();
    if usable == 0 {
        eprintln!(
            "warning: no tokens for backend '{}' in {} — every request will be rejected; \
             provision a tenant with `playground user create <label> --backend {} --tokens {}`",
            args.backend.name(),
            args.tokens.display(),
            args.backend.name(),
            args.tokens.display(),
        );
    }

    // OAuth 2.1 (browser-based connectors) needs both the public issuer URL
    // and a state file; clap's `requires` enforces the pairing, so a lone
    // flag never reaches here. Absent both, the server is byte-for-byte v1.
    let oauth = match (args.public_url, args.oauth_state) {
        (Some(public_url), Some(state_path)) => {
            // Cap the access-token lifetime: a misconfigured `--oauth-access-ttl
            // -secs` must not be able to mint near-immortal bearer tokens (the
            // long-lived path is refresh rotation, gated by theft-detection).
            let access_ttl = std::time::Duration::from_secs(args.oauth_access_ttl_secs);
            if access_ttl > oauth::MAX_ACCESS_TTL {
                anyhow::bail!(
                    "--oauth-access-ttl-secs {} exceeds the {}s (24h) maximum",
                    args.oauth_access_ttl_secs,
                    oauth::MAX_ACCESS_TTL.as_secs(),
                );
            }
            Some(oauth::OauthConfig {
                public_url,
                state_path,
                access_ttl,
            })
        }
        _ => None,
    };

    // Startup reattach sweep: after a host reboot the on-disk state survives but
    // the running contexts are gone (jail: in-kernel jail records; lima: the VMs
    // are stopped). Bring every provisioned sandbox back up before serving so a
    // reconnecting tenant finds its box live. Both backends implement this.
    match backend.reattach_all() {
        Ok(n) => eprintln!("playground mcp-http: reattached {n} persistent sandbox(es)"),
        Err(e) => eprintln!("playground mcp-http: reattach sweep failed: {e:#}"),
    }

    let provider = mcp::SandboxProvider::new(backend);
    let server = mcp::McpServer::new(provider);
    mcp_http::serve(
        server,
        tokens,
        mcp_http::HttpServerConfig {
            bind: args.bind,
            backend_name: args.backend.name().to_string(),
            allowed_origins: args.allow_origin,
            idle_timeout: std::time::Duration::from_secs(args.idle_timeout_secs),
            oauth,
        },
    )
}

/// The `SessionSpec` a `user` verb builds for a tenant. It lines up with how
/// `mcp.rs::parse_tenant` synthesises one (host path `.../<name>/self.pile`,
/// default guest path `/pile/self.pile`). Default cwd/env (empty) match the
/// server's `open_session` defaults.
///
/// Backend nuance: the jail backend is pile-less by design (see
/// src/sandbox/jail.rs) — it logs this mount and never realises it. The lima
/// backend DOES mount the pile, and because provisioning renders the instance
/// config once (open no longer re-renders), this host path is the mount that
/// persists for the box; point `--state-root`/`--template` and the pile parent
/// directory accordingly before `user create --backend lima`.
#[cfg(feature = "mcp-http")]
fn spec_for(name: &str) -> sandbox::SessionSpec {
    let host_path = PathBuf::from(format!("/pile/{name}/self.pile"));
    sandbox::SessionSpec {
        tenant: sandbox::Tenant {
            label: name.to_string(),
            pile: sandbox::PileMount {
                host_path,
                guest_path: PathBuf::from("/pile/self.pile"),
                append_only: true,
            },
        },
        cwd: None,
        env: Vec::new(),
    }
}

/// `user create <name>`: provision the tenant's persistent sandbox, then mint a
/// bearer token for it. The token is printed to stdout exactly once; the store
/// keeps it (mode 0600) for the server to check against.
#[cfg(feature = "mcp-http")]
fn run_user_create(args: UserCreateArgs) -> Result<()> {
    let backend = args.backend.build_backend()?;
    let backend_name = args.backend.backend.name();
    backend
        .provision_sandbox(&spec_for(&args.name))
        .with_context(|| format!("provision sandbox for tenant '{}'", args.name))?;

    let mut store = mcp_http::TokenStore::load(&args.backend.tokens)?;
    let token = store.mint(&args.name, backend_name);
    store.save(&args.backend.tokens)?;
    eprintln!(
        "provisioned sandbox and minted token for tenant '{}' (backend {}) into {} — \
         shown once below, store it now:",
        args.name,
        backend_name,
        args.backend.tokens.display(),
    );
    println!("{token}");
    Ok(())
}

/// `user list`: the distinct tenants named in the token store, annotated with
/// whether their box is currently live (best-effort). Both persistent backends
/// (jail, lima) can answer the liveness probe.
#[cfg(feature = "mcp-http")]
fn run_user_list(args: UserListArgs) -> Result<()> {
    let store = mcp_http::TokenStore::load(&args.backend.tokens)?;
    // Distinct tenants, sorted for stable output.
    let mut tenants: Vec<String> = store
        .tokens
        .values()
        .map(|entry| entry.tenant.clone())
        .collect();
    tenants.sort();
    tenants.dedup();

    if tenants.is_empty() {
        eprintln!("no tenants in {}", args.backend.tokens.display());
        return Ok(());
    }

    for tenant in &tenants {
        let live = args.backend.running_for_label(tenant);
        println!("{tenant}\t{}", if live { "live" } else { "down" });
    }
    Ok(())
}

/// `user destroy <name>`: tear the tenant's sandbox down (permanent — jail:
/// `jail -r` + devfs unmount + `zfs destroy`; lima: `limactl stop` +
/// `limactl delete`) and remove every token bound to it.
#[cfg(feature = "mcp-http")]
fn run_user_destroy(args: UserDestroyArgs) -> Result<()> {
    let backend = args.backend.build_backend()?;
    let session = args.backend.session_id_for(&args.name);
    backend
        .destroy_session(&session)
        .with_context(|| format!("destroy sandbox for tenant '{}'", args.name))?;

    let mut store = mcp_http::TokenStore::load(&args.backend.tokens)?;
    let before = store.tokens.len();
    store.tokens.retain(|_, entry| entry.tenant != args.name);
    let removed = before - store.tokens.len();
    store.save(&args.backend.tokens)?;
    eprintln!(
        "destroyed sandbox '{}' and removed {removed} token(s) for tenant '{}' from {}",
        session.as_str(),
        args.name,
        args.backend.tokens.display(),
    );
    Ok(())
}

/// `user token <name>`: print the token(s) bound to a tenant (or a notice that
/// there are none). This reads the store — the secret is already on disk, this
/// just surfaces it.
#[cfg(feature = "mcp-http")]
fn run_user_token_show(args: UserTokenShowArgs) -> Result<()> {
    let store = mcp_http::TokenStore::load(&args.backend.tokens)?;
    let mut found = false;
    for (token, entry) in &store.tokens {
        if entry.tenant == args.name {
            println!("{token}");
            found = true;
        }
    }
    if !found {
        eprintln!("no token for '{}' in {}", args.name, args.backend.tokens.display());
    }
    Ok(())
}

/// `user token reset <name>`: revoke every existing token for a tenant and mint
/// a fresh one, printed once.
#[cfg(feature = "mcp-http")]
fn run_user_token_reset(args: UserTokenResetArgs) -> Result<()> {
    let backend_name = args.backend.backend.name();
    let mut store = mcp_http::TokenStore::load(&args.backend.tokens)?;
    let before = store.tokens.len();
    store.tokens.retain(|_, entry| entry.tenant != args.name);
    let revoked = before - store.tokens.len();
    let token = store.mint(&args.name, backend_name);
    store.save(&args.backend.tokens)?;
    eprintln!(
        "revoked {revoked} token(s) and minted a fresh one for tenant '{}' (backend {}) into {} — \
         shown once below, store it now:",
        args.name,
        backend_name,
        args.backend.tokens.display(),
    );
    println!("{token}");
    Ok(())
}

/// `playground clean`: spin down every owned sandbox that must not outlive the
/// playground process (Lima VMs), for use after a hard kill left them running.
/// A killed process cannot run its own shutdown, so this is the reliable sweep.
/// Idempotent and safe to run anytime — the jail backend is a no-op (jails are
/// free in-kernel records that persist by design; there is nothing to spin
/// down), so this only does real work under `--backend lima`.
#[cfg(feature = "mcp-http")]
fn run_clean(args: CleanArgs) -> Result<()> {
    let backend = args.backend.build_backend()?;
    let n = backend.shutdown()?;
    eprintln!(
        "playground clean: spun down {n} orphaned sandbox(es) [backend: {}]",
        backend.name()
    );
    Ok(())
}

/// Mint an OAuth invite code into the OAuth state file. The invite is what a
/// human pastes into the `/oauth/authorize` form; it binds the resulting
/// tokens to the tenant. No backend argument — OAuth tokens are minted for
/// whatever backend the redeeming server runs.
#[cfg(feature = "mcp-http")]
fn run_token_invite(args: TokenInviteArgs) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs();
    // Mint under the shared advisory file lock (M2): a plain load/save here
    // races the running server's read-modify-write and could roll back a
    // server mutation (worst case resurrecting a revoked token family). The
    // locked path re-reads the server's latest state before writing.
    let invite = oauth::mint_invite_locked(&args.oauth_state, &args.tenant, args.reusable, now)?;
    eprintln!(
        "minted {} invite for tenant '{}' into {} — hand it to the human authorizing a connector:",
        if args.reusable { "reusable" } else { "single-use" },
        args.tenant,
        args.oauth_state.display(),
    );
    println!("{invite}");
    Ok(())
}
