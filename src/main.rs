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

use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

mod mcp;
#[cfg(feature = "mcp-http")]
mod mcp_http;
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
    fn build(
        self,
        instance_prefix: String,
        state_root: Option<PathBuf>,
        template: Option<PathBuf>,
        jail_host: String,
        jail_local: bool,
        jail_prefix: String,
        jail_template_snapshot: String,
        jail_dataset_parent: String,
    ) -> Box<dyn sandbox::SandboxBackend> {
        match self {
            McpBackendKind::Lima => {
                let mut backend = sandbox::lima::LimaBackend::new(instance_prefix);
                if let Some(root) = state_root {
                    backend.state_root = root;
                }
                backend.template = template;
                Box::new(backend)
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
                Box::new(backend)
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
        args.jail_host,
        args.jail_local,
        args.jail_prefix,
        args.jail_template_snapshot,
        args.jail_dataset_parent,
    );

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
        args.jail_host,
        args.jail_local,
        args.jail_prefix,
        args.jail_template_snapshot,
        args.jail_dataset_parent,
    );

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
