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
//!   - `token`     — mint/manage the bearer tokens `mcp-http` checks against.

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
    #[command(about = "Manage MCP access tokens (per-sandbox bearer auth)")]
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
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
    /// Token store (JSON) minted with `playground token mint`.
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
    /// Jail backend: run zfs/jail/jexec directly on this machine instead of
    /// over SSH (server-side hosting on the FreeBSD jail host itself;
    /// `--jail-host` is ignored).
    #[arg(long, default_value_t = false)]
    jail_local: bool,
}

#[cfg(feature = "mcp-http")]
#[derive(Subcommand, Debug)]
enum TokenCommand {
    #[command(about = "Mint a bearer token bound to a tenant (printed once, then only in the store)")]
    Mint(TokenMintArgs),
    #[command(
        about = "Mint an OAuth invite code bound to a tenant (the human gate of the browser-connector flow)"
    )]
    Invite(TokenInviteArgs),
}

#[cfg(feature = "mcp-http")]
#[derive(Args, Debug, Clone)]
#[command(about = "Token mint settings")]
struct TokenMintArgs {
    /// Tenant label the token acts as (sessions/sandboxes are scoped to it).
    #[arg(long)]
    tenant: String,
    /// Token store (JSON) to append to; created if missing.
    #[arg(long, env = "PLAYGROUND_MCP_TOKENS")]
    tokens: PathBuf,
    /// Backend the token is valid for (must match the serving `mcp-http --backend`).
    #[arg(long, value_enum, default_value_t = McpBackendKind::Lima)]
    backend: McpBackendKind,
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
        CommandMode::Token { command } => match command {
            TokenCommand::Mint(args) => run_token_mint(args),
            TokenCommand::Invite(args) => run_token_invite(args),
        },
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
             mint one with `playground token mint --tenant <label> --backend {} --tokens {}`",
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

/// Mint a bearer token into the store. The token is printed to stdout exactly
/// once; the store keeps it (mode 0600) for the server to check against.
#[cfg(feature = "mcp-http")]
fn run_token_mint(args: TokenMintArgs) -> Result<()> {
    let mut store = mcp_http::TokenStore::load(&args.tokens)?;
    let token = store.mint(&args.tenant, args.backend.name());
    store.save(&args.tokens)?;
    eprintln!(
        "minted token for tenant '{}' (backend {}) into {} — shown once below, store it now:",
        args.tenant,
        args.backend.name(),
        args.tokens.display(),
    );
    println!("{token}");
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
