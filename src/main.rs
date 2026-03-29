use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, sleep};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use triblespace::core::blob::Bytes;
use triblespace::core::blob::schemas::UnknownBlob;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

mod archive_schema;
mod blob_refs;
mod chat_prompt;
mod config;
#[cfg(feature = "diagnostics")]
mod diagnostics;
mod exec_worker;
mod model_worker;
mod relations_schema;
mod repo_ops;
mod repo_util;
mod schema;
mod time_util;

use chat_prompt::{ChatMessage, ChatRole};
use config::Config;
use repo_util::{
    close_repo, current_branch_head, init_repo, load_text, pull_workspace, push_workspace,
    refresh_cached_checkout,
};
use schema::{model_chat, playground_cog, playground_context, playground_exec};
use time_util::{epoch_interval, format_tai_interval_timestamp, format_time_range, interval_key, interval_width, now_epoch};

const MEMORY_BRANCH_NAME: &str = "memory";

mod reason_events {
    use triblespace::prelude::attributes;
    use triblespace::prelude::blobschemas;
    use triblespace::prelude::valueschemas;

    attributes! {
        "B10329D5D1087D15A3DAFF7A7CC50696" as text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "FBA9BC32A457C7BFFDB7E0181D3E82A4" as created_at: valueschemas::NsTAIInterval;
        "79C9CB4C48864D28B215D4264E1037BF" as ordered_created_at: valueschemas::OrderedNsTAIInterval;
        "E6B1C728F1AE9F46CAB4DBB60D1A9528" as about_turn: valueschemas::GenId;
        "721DED6DA776F2CF4FB91C54D9F82358" as worker: valueschemas::GenId;
        "514F4FE9F560FB155450462C8CF50749" as command_text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
    }
}

#[derive(Subcommand, Debug)]
enum CommandMode {
    #[command(about = "Run core + Model and start the exec worker in a Lima VM")]
    Run(RunArgs),
    #[command(about = "Run only the core loop (no model/exec workers)")]
    Core,
    #[command(about = "Run only the exec worker (remote host)")]
    Exec(WorkerArgs),
    #[command(about = "Run only the Model worker (host)")]
    Model(WorkerArgs),
    #[cfg(feature = "diagnostics")]
    #[command(about = "Open the diagnostics dashboard")]
    Diagnostics(DiagnosticsArgs),
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCommand {
    Show {
        #[arg(long, default_value_t = false)]
        show_secrets: bool,
    },
    Set(ConfigSetArgs),
    #[command(about = "Clear an optional config field in the pile")]
    Unset(ConfigUnsetArgs),
}


#[derive(Args, Debug, Clone)]
#[command(about = "Run core + Model and start the exec worker in a Lima VM")]
struct RunArgs {
    #[arg(long)]
    poll_ms: Option<u64>,
    #[command(flatten)]
    lima: LimaExecArgs,
}

#[derive(Args, Debug, Clone)]
#[command(about = "Exec worker settings")]
struct WorkerArgs {
    #[arg(long)]
    worker_id: Option<String>,
    #[arg(long)]
    poll_ms: Option<u64>,
}

#[derive(Args, Debug, Clone)]
#[command(about = "Diagnostics dashboard settings")]
#[cfg(feature = "diagnostics")]
struct DiagnosticsArgs {
    #[arg(long, default_value_t = false)]
    headless: bool,
    #[arg(long)]
    out_dir: Option<PathBuf>,
    #[arg(long)]
    scale: Option<f32>,
    #[arg(long)]
    headless_wait_ms: Option<u64>,
}

#[derive(Args, Debug, Clone)]
#[command(about = "Lima VM settings for the exec worker")]
struct LimaExecArgs {
    #[arg(long, default_value = "playground")]
    instance: String,
    #[arg(long)]
    template: Option<PathBuf>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value = "/workspace")]
    vm_root: PathBuf,
}
#[derive(Args, Debug, Clone)]
#[command(about = "Set a single config field in the pile")]
struct ConfigSetArgs {
    #[arg(
        value_enum,
        value_name = "FIELD",
        help = "Config field to set (see possible values below)."
    )]
    field: ConfigField,
    #[arg(
        value_name = "VALUE",
        help = "Value to set. Use @path to read from file, @- to read stdin; use `config unset` to clear optional fields."
    )]
    value: String,
}

#[derive(Args, Debug, Clone)]
#[command(about = "Clear an optional config field in the pile")]
struct ConfigUnsetArgs {
    #[arg(
        value_enum,
        value_name = "FIELD",
        help = "Optional config field to clear (see possible values below)."
    )]
    field: OptionalConfigField,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "kebab-case")]
enum ConfigField {
    SystemPrompt,
    Branch,
    Author,
    AuthorRole,
    PersonaId,
    PollMs,
    TavilyApiKey,
    ExaApiKey,
    ExecDefaultCwd,
    ExecSandboxProfile,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "kebab-case")]
enum OptionalConfigField {
    PersonaId,
    TavilyApiKey,
    ExaApiKey,
    ExecDefaultCwd,
    ExecSandboxProfile,
}

#[derive(Parser, Debug)]
#[command(
    version,
    about = "Playground runner that turns Model output into exec requests"
)]
struct Cli {
    #[arg(long, global = true)]
    pile: Option<PathBuf>,
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
        CommandMode::Run(args) => {
            let instance = resolve_instance_name(args.lima.instance.as_str());
            let pile_path = resolve_pile_path(cli.pile.clone(), instance.as_str());
            let config = Config::load(Some(pile_path.as_path())).context("load config")?;
            run_with_exec(config, args)
        }
        CommandMode::Core => {
            let instance = default_instance_name();
            let pile_path = resolve_pile_path(cli.pile.clone(), instance.as_str());
            let config = Config::load(Some(pile_path.as_path())).context("load config")?;
            run_loop(config)
        }
        CommandMode::Exec(args) => {
            let instance = default_instance_name();
            let pile_path = resolve_pile_path(cli.pile.clone(), instance.as_str());
            let config = Config::load(Some(pile_path.as_path())).context("load config")?;
            run_exec_worker(config, args)
        }
        CommandMode::Model(args) => {
            let instance = default_instance_name();
            let pile_path = resolve_pile_path(cli.pile.clone(), instance.as_str());
            let config = Config::load(Some(pile_path.as_path())).context("load config")?;
            run_model_worker(config, args)
        }
        #[cfg(feature = "diagnostics")]
        CommandMode::Diagnostics(args) => {
            let DiagnosticsArgs {
                headless,
                out_dir,
                scale,
                headless_wait_ms,
            } = args;
            let instance = default_instance_name();
            let pile_path = resolve_pile_path(cli.pile.clone(), instance.as_str());
            diagnostics::set_default_pile(Some(pile_path));
            diagnostics::run_diagnostics(headless, out_dir, scale, headless_wait_ms)
                .context("run diagnostics")?;
            Ok(())
        }
        CommandMode::Config { command } => {
            let instance = default_instance_name();
            let pile_path = resolve_pile_path(cli.pile.clone(), instance.as_str());
            handle_config(Some(pile_path.as_path()), command)
        }
    }
}

fn run_with_exec(mut config: Config, args: RunArgs) -> Result<()> {
    let poll_ms = args.poll_ms.unwrap_or(config.poll_ms);
    config.poll_ms = poll_ms;

    let stop = Arc::new(AtomicBool::new(false));
    let model_stop = stop.clone();
    let model_config = config.clone();
    let model_worker_id = *ufoid();
    let model_handle = thread::spawn(move || {
        model_worker::run_model_loop(model_config, model_worker_id, poll_ms, Some(model_stop))
    });

    let instance = env_string("PLAYGROUND_LIMA_INSTANCE").unwrap_or_else(|| args.lima.instance.clone());
    prepare_lima_service(&config, &args.lima)?;

    let core_result = run_loop(config);
    stop.store(true, Ordering::Relaxed);

    // Stop the Lima VM so it doesn't keep writing to the pile after exit.
    stop_lima_instance(&instance);

    let model_result = model_handle
        .join()
        .map_err(|_| anyhow!("model worker panicked"))?;

    core_result?;
    model_result.context("model worker")?;
    Ok(())
}

fn run_exec_worker(config: Config, args: WorkerArgs) -> Result<()> {
    let poll_ms = args.poll_ms.unwrap_or(config.poll_ms);
    let worker_id = parse_worker_id(args.worker_id)?;
    exec_worker::run_exec_loop(config, worker_id, poll_ms, None)
}

fn run_model_worker(config: Config, args: WorkerArgs) -> Result<()> {
    let poll_ms = args.poll_ms.unwrap_or(config.poll_ms);
    let worker_id = parse_worker_id(args.worker_id)?;
    model_worker::run_model_loop(config, worker_id, poll_ms, None)
}

fn handle_config(pile: Option<&Path>, command: ConfigCommand) -> Result<()> {
    let mut config = Config::load(pile).context("load config")?;
    match command {
        ConfigCommand::Show { show_secrets } => {
            print_config(&config, show_secrets);
        }
        ConfigCommand::Set(args) => {
            apply_config_set(&mut config, args.field, args.value.as_str())?;
            config.store().context("store config")?;
            print_config(&config, false);
        }
        ConfigCommand::Unset(args) => {
            apply_config_unset(&mut config, args.field)?;
            config.store().context("store config")?;
            print_config(&config, false);
        }
    }
    Ok(())
}

fn apply_config_set(config: &mut Config, field: ConfigField, value: &str) -> Result<()> {
    match field {
        ConfigField::SystemPrompt => {
            config.system_prompt = load_value_or_file(value, "system_prompt")?;
        }
        ConfigField::Branch => {
            config.branch = load_value_or_file(value, "branch")?;
        }
        ConfigField::Author => {
            config.author = load_value_or_file(value, "author")?;
        }
        ConfigField::AuthorRole => {
            config.author_role = load_value_or_file(value, "author_role")?;
        }
        ConfigField::PersonaId => {
            config.persona_id = Some(parse_hex_id(value, "persona_id")?);
        }
        ConfigField::PollMs => {
            config.poll_ms = parse_u64(value, "poll_ms")?;
        }
        ConfigField::TavilyApiKey => {
            config.tavily_api_key = Some(load_value_or_file_trimmed(value, "tavily_api_key")?);
        }
        ConfigField::ExaApiKey => {
            config.exa_api_key = Some(load_value_or_file_trimmed(value, "exa_api_key")?);
        }
        ConfigField::ExecDefaultCwd => {
            let value = load_value_or_file(value, "exec_default_cwd")?;
            config.exec.default_cwd = Some(PathBuf::from(value.trim()));
        }
        ConfigField::ExecSandboxProfile => {
            config.exec.sandbox_profile = Some(parse_hex_id(value, "exec_sandbox_profile")?);
        }
    }
    Ok(())
}

fn apply_config_unset(config: &mut Config, field: OptionalConfigField) -> Result<()> {
    match field {
        OptionalConfigField::PersonaId => config.persona_id = None,
        OptionalConfigField::TavilyApiKey => config.tavily_api_key = None,
        OptionalConfigField::ExaApiKey => config.exa_api_key = None,
        OptionalConfigField::ExecDefaultCwd => config.exec.default_cwd = None,
        OptionalConfigField::ExecSandboxProfile => config.exec.sandbox_profile = None,
    }
    Ok(())
}

fn parse_hex_id(raw: &str, label: &str) -> Result<Id> {
    let raw = raw.trim();
    Id::from_hex(raw).ok_or_else(|| anyhow!("invalid {label} {raw}"))
}

fn parse_worker_id(raw: Option<String>) -> Result<Id> {
    if let Some(hex) = raw {
        let id = Id::from_hex(hex.as_str()).ok_or_else(|| anyhow!("invalid worker_id {hex}"))?;
        return Ok(id);
    }
    Ok(*ufoid())
}

fn prepare_lima_service(config: &Config, args: &LimaExecArgs) -> Result<()> {
    let repo_root = repo_root();
    let playground_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let instance = env_string("PLAYGROUND_LIMA_INSTANCE").unwrap_or_else(|| args.instance.clone());
    let vm_root = env_path("PLAYGROUND_LIMA_ROOT").unwrap_or_else(|| args.vm_root.clone());

    let pile_abs = absolute_pile_path(&config.pile_path)?;
    let pile_root = pile_abs
        .parent()
        .ok_or_else(|| anyhow!("pile path missing parent directory"))?
        .to_path_buf();

    let persona_root = repo_root.join("personas").join(&instance);
    fs::create_dir_all(&persona_root).ok();
    let workspace_root = persona_root.join("workspace");
    fs::create_dir_all(&workspace_root).ok();

    let template = env_path("PLAYGROUND_LIMA_TEMPLATE")
        .or_else(|| args.template.clone())
        .unwrap_or_else(|| playground_root.join("scripts/lima.yaml.tmpl"));
    if !template.exists() {
        return Err(anyhow!("missing Lima template: {}", template.display()));
    }

    let config_path = env_path("PLAYGROUND_LIMA_CONFIG")
        .or_else(|| args.config.clone())
        .unwrap_or_else(|| persona_root.join("state/lima.yaml"));
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).context("create Lima config directory")?;
    }

    let pile_name = pile_abs
        .file_name()
        .ok_or_else(|| anyhow!("pile path missing filename"))?;
    let pile_vm = PathBuf::from("/pile").join(pile_name);
    render_lima_template(
        &template,
        &config_path,
        &playground_root,
        &pile_root,
        &workspace_root,
        &pile_vm,
        &vm_root,
    )?;

    ensure_lima_instance(&instance, &config_path)?;
    Ok(())
}

fn ensure_lima_instance(instance: &str, config_path: &Path) -> Result<()> {
    // Best-effort cleanup of any previous instance.
    let _ = Command::new("limactl")
        .args(["delete", "--force", instance])
        .status();

    let status = Command::new("limactl")
        .args(["start", "--tty=false", "--name", instance, &config_path.to_string_lossy()])
        .status()
        .context("run limactl start")?;
    if !status.success() {
        return Err(anyhow!("limactl start failed for instance '{instance}'"));
    }
    Ok(())
}

fn stop_lima_instance(instance: &str) {
    let _ = Command::new("limactl")
        .args(["stop", instance])
        .status();
}

fn render_lima_template(
    template: &Path,
    out_path: &Path,
    playground_root: &Path,
    pile_root: &Path,
    workspace_root: &Path,
    pile_vm: &Path,
    vm_root: &Path,
) -> Result<()> {
    let mut text = fs::read_to_string(template)
        .with_context(|| format!("read Lima template {}", template.display()))?;

    let replacements = [
        ("__PLAYGROUND_ROOT__", playground_root),
        ("__PILE_ROOT__", pile_root),
        ("__WORKSPACE_ROOT__", workspace_root),
        ("__PILE_PATH__", pile_vm),
        ("__VM_ROOT__", vm_root),
    ];

    for (token, path) in replacements {
        text = text.replace(token, &path.to_string_lossy());
    }

    // Lima's default user is typically the host username; allow overriding for portability.
    let vm_user = env_string("PLAYGROUND_LIMA_USER")
        .or_else(|| env_string("USER"))
        .unwrap_or_else(|| "lima".to_string());
    text = text.replace("__VM_USER__", vm_user.as_str());

    fs::write(out_path, text)
        .with_context(|| format!("write Lima config {}", out_path.display()))?;
    Ok(())
}

fn absolute_pile_path(path: &Path) -> Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = abs
        .parent()
        .ok_or_else(|| anyhow!("pile path has no parent"))?;
    fs::create_dir_all(parent).context("create pile directory")?;
    let parent_abs = parent
        .canonicalize()
        .context("canonicalize pile directory")?;
    let file = abs
        .file_name()
        .ok_or_else(|| anyhow!("pile path missing filename"))?;
    Ok(parent_abs.join(file))
}

fn default_instance_name() -> String {
    env_string("PLAYGROUND_INSTANCE")
        .or_else(|| env_string("PLAYGROUND_LIMA_INSTANCE"))
        .unwrap_or_else(|| "playground".to_string())
}

fn resolve_instance_name(default: &str) -> String {
    env_string("PLAYGROUND_LIMA_INSTANCE").unwrap_or_else(|| default.to_string())
}

fn default_pile_path(instance: &str) -> PathBuf {
    repo_root()
        .join("personas")
        .join(instance)
        .join("pile")
        .join("self.pile")
}

fn resolve_pile_path(explicit: Option<PathBuf>, instance: &str) -> PathBuf {
    explicit.unwrap_or_else(|| default_pile_path(instance))
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn env_path(key: &str) -> Option<PathBuf> {
    env_string(key).map(PathBuf::from)
}

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return fs::read_to_string(path).with_context(|| format!("read {label} from {}", path));
    }
    Ok(raw.to_string())
}

fn load_value_or_file_trimmed(raw: &str, label: &str) -> Result<String> {
    Ok(load_value_or_file(raw, label)?.trim().to_string())
}

fn parse_u64(raw: &str, label: &str) -> Result<u64> {
    raw.parse::<u64>()
        .map_err(|_| anyhow!("invalid {label} {raw}"))
}

fn print_config(config: &Config, show_secrets: bool) {
    println!("pile = \"{}\"", config.pile_path.display());
    println!("branch = \"{}\"", config.branch);
    println!("poll_ms = {}", config.poll_ms);
    println!("author = \"{}\"", config.author);
    println!("author_role = \"{}\"", config.author_role);
    println!(
        "persona_id = {}",
        config
            .persona_id
            .map(|id| format!("\"{id:x}\""))
            .unwrap_or_else(|| "null".to_string())
    );
    println!(
        "system_prompt = \"{}\"",
        config.system_prompt.replace('\"', "\\\"")
    );

    println!("\n[model]");
    println!(
        "profile_id = {}",
        config
            .model_profile_id
            .map(|id| format!("\"{id:x}\""))
            .unwrap_or_else(|| "null".to_string())
    );
    println!("profile_name = \"{}\"", config.model_profile_name);
    println!("model = \"{}\"", config.model.model);
    println!("base_url = \"{}\"", config.model.base_url);
    match (&config.model.api_key, show_secrets) {
        (Some(key), true) => println!("api_key = \"{}\"", key),
        (Some(_), false) => println!("api_key = \"<redacted>\""),
        (None, _) => println!("api_key = null"),
    }
    println!(
        "reasoning_effort = {}",
        config
            .model
            .reasoning_effort
            .as_ref()
            .map(|value| format!("\"{}\"", value))
            .unwrap_or_else(|| "null".to_string())
    );
    println!("stream = {}", config.model.stream);
    println!(
        "context_window_tokens = {}",
        config.model.context_window_tokens
    );
    println!("max_output_tokens = {}", config.model.max_output_tokens);
    println!(
        "context_safety_margin_tokens = {}",
        config.model.context_safety_margin_tokens
    );
    println!(
        "chars_per_token = {}",
        config.model.chars_per_token
    );
    println!("\n[integrations]");
    match (&config.tavily_api_key, show_secrets) {
        (Some(key), true) => println!("tavily_api_key = \"{}\"", key),
        (Some(_), false) => println!("tavily_api_key = \"<redacted>\""),
        (None, _) => println!("tavily_api_key = null"),
    }
    match (&config.exa_api_key, show_secrets) {
        (Some(key), true) => println!("exa_api_key = \"{}\"", key),
        (Some(_), false) => println!("exa_api_key = \"<redacted>\""),
        (None, _) => println!("exa_api_key = null"),
    }

    println!("\n[exec]");
    println!(
        "default_cwd = {}",
        config
            .exec
            .default_cwd
            .as_ref()
            .map(|path| format!("\"{}\"", path.display()))
            .unwrap_or_else(|| "null".to_string())
    );
    println!(
        "sandbox_profile = {}",
        config
            .exec
            .sandbox_profile
            .map(|id| format!("\"{id:x}\""))
            .unwrap_or_else(|| "null".to_string())
    );
}

fn run_loop(config: Config) -> Result<()> {
    let (mut repo, branch_id) = init_repo(&config).context("open triblespace repo")?;
    let exec_cwd = config
        .exec
        .default_cwd
        .as_ref()
        .map(|path| path.to_string_lossy().to_string());
    let exec_profile = config.exec.sandbox_profile;

    let result = (|| -> Result<()> {
        let mut prev_cover: Option<MemoryCoverState> = None;
        let mut request_info = ensure_model_request(&mut repo, branch_id, &config, &mut prev_cover)?;

        loop {
            let model_result =
                wait_for_model_result(&mut repo, branch_id, request_info.id, config.poll_ms)?;
            if let Some(error) = model_result.error {
                eprintln!(
                    "warning: model request {request_id:x} failed: {error}",
                    request_id = request_info.id
                );
                // Retry the same thought instead of bootstrapping a new orient cycle.
                request_info = retry_model_request(
                    &mut repo,
                    branch_id,
                    request_info.thought_id,
                    &config,
                    &mut prev_cover,
                )?;
                sleep(Duration::from_millis(config.poll_ms));
                continue;
            }

            let command = model_result.output_text.trim();
            if command.eq_ignore_ascii_case("exit") {
                break;
            }

            let command_request_id = ensure_command_request(
                &mut repo,
                branch_id,
                command,
                request_info.thought_id,
                exec_cwd.as_deref(),
                exec_profile,
            )?;
            let command_result_id =
                wait_for_command_result(&mut repo, branch_id, command_request_id, config.poll_ms)?;
            request_info =
                create_thought_and_request(&mut repo, branch_id, Some(command_result_id), &config, &mut prev_cover)?;
        }
        Ok(())
    })();

    if let Err(err) = close_repo(repo) {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }

    result
}

#[derive(Debug, Clone)]
struct ModelRequestInfo {
    id: Id,
    thought_id: Option<Id>,
}

/// Snapshot of the memory cover from the last context we sent.
/// Used to detect changes and delay context updates by one turn so that the
/// Anthropic prompt cache can seed entries for the old prefix before switching.
struct MemoryCoverState {
    messages: Vec<ChatMessage>,
    used_chars: usize,
    breath_idx: usize,
    cover_end_key: Option<i128>,
}

#[derive(Debug, Clone)]
struct ReasonEventInfo {
    text: Option<Value<Handle<Blake3, LongString>>>,
    command_text: Option<Value<Handle<Blake3, LongString>>>,
}

fn ensure_model_request(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    config: &Config,
    prev_cover: &mut Option<MemoryCoverState>,
) -> Result<ModelRequestInfo> {
    let mut cached_head = None;
    let mut cached_catalog = TribleSet::new();
    loop {
        let branch_head = current_branch_head(repo, branch_id)?;
        if branch_head == cached_head {
            sleep(Duration::from_millis(config.poll_ms));
            continue;
        }

        let mut ws = pull_workspace(repo, branch_id, "pull workspace for model request")?;
        let _delta = refresh_cached_checkout(&mut ws, &mut cached_head, &mut cached_catalog)?;

        // Wait for pending commands before advancing model requests.
        // On restart, orphaned commands (claimed by a dead worker) will be
        // picked up by the new exec worker. Proceeding before they finish
        // would re-send the model request and create duplicate execs.
        if has_pending_command_request(&cached_catalog) {
            sleep(Duration::from_millis(config.poll_ms));
            continue;
        }

        if let Some(exec_result) = latest_unprocessed_exec_result(&cached_catalog) {
            drop(ws);
            return create_thought_and_request(repo, branch_id, Some(exec_result.id), config, prev_cover);
        }

        if let Some(request) = latest_pending_model_request(&cached_catalog) {
            return Ok(request);
        }

        if let Some(thought_id) = latest_unrequested_thought(&cached_catalog) {
            let request_id =
                create_request_for_thought_from_catalog(&mut ws, &cached_catalog, thought_id, config)?;
            push_workspace(repo, &mut ws).context("push model request")?;
            return Ok(ModelRequestInfo {
                id: request_id,
                thought_id: Some(thought_id),
            });
        }

        // Nothing pending — create a thought with no exec result.
        // The breath is injected into the context, giving the model
        // enough to decide its first action.
        drop(ws);
        return create_thought_and_request(repo, branch_id, None, config, prev_cover);
    }
}

fn create_thought_and_request(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    about_exec_result: Option<Id>,
    config: &Config,
    prev_cover: &mut Option<MemoryCoverState>,
) -> Result<ModelRequestInfo> {
    let mut ws = pull_workspace(repo, branch_id, "pull workspace for thought")?;
    let catalog = ws.checkout(..).context("checkout workspace")?.into_facts();

    if let Some(exec_result_id) = about_exec_result {
        if let Some(thought_id) = thought_for_exec_result(&catalog, exec_result_id) {
            let request_id =
                create_request_for_thought_from_catalog(&mut ws, &catalog, thought_id, config)?;
            push_workspace(repo, &mut ws).context("push model request")?;
            return Ok(ModelRequestInfo {
                id: request_id,
                thought_id: Some(thought_id),
            });
        }
    }

    let now = epoch_interval(now_epoch());
    let memory_catalog = match repo.ensure_branch(MEMORY_BRANCH_NAME, None) {
        Ok(memory_branch_id) => {
            let mut memory_ws = pull_workspace(repo, memory_branch_id, "pull memory branch")?;
            memory_ws.checkout(..).context("checkout memory branch")?.into_facts()
        }
        Err(_) => TribleSet::new(),
    };
    let context_json = if let Some(exec_result_id) = about_exec_result {
        context_for_exec_result_with_history(
            &mut ws,
            &catalog,
            &memory_catalog,
            exec_result_id,
            config,
            prev_cover,
        )?
    } else {
        // Cold start: no exec result yet. Build a minimal context with
        // memory cover + breath so the model can orient itself.
        let index = load_context_chunks(&memory_catalog);
        let body_budget_chars = context_body_budget_chars(config);
        let (mut messages, used_chars, breath_idx, cover_end_key) =
            build_memory_cover_messages(&mut ws, &index, body_budget_chars, None)?;

        // Record as the initial cover state (no delay on first request).
        *prev_cover = Some(MemoryCoverState {
            messages: messages.clone(),
            used_chars,
            breath_idx,
            cover_end_key,
        });

        let fill_pct = if body_budget_chars > 0 {
            (used_chars * 100) / body_budget_chars
        } else {
            0
        };
        messages.insert(breath_idx, ChatMessage::user(
            "present moment begins.".to_string(),
        ));
        messages.insert(breath_idx, ChatMessage::assistant("breath".to_string()));
        // No exec result to attach pressure to in cold start; append as trailing message.
        messages.push(ChatMessage::user(format!("context filled to {fill_pct}%.")));
        serde_json::to_string(&messages).context("serialize cold-start context")?
    };
    let context_handle = ws.put(context_json);
    let thought_id = ufoid();
    let mut change = TribleSet::new();
    change += entity! { &thought_id @
        metadata::tag: playground_cog::kind_thought,
        playground_cog::context: context_handle,
        playground_cog::created_at: now,
    };
    if let Some(exec_result_id) = about_exec_result {
        change += entity! { &thought_id @ playground_cog::about_exec_result: exec_result_id };
    }

    let request_id = ufoid();
    change += entity! { &request_id @
        metadata::tag: model_chat::kind_request,
        model_chat::about_thought: *thought_id,
        model_chat::context: context_handle,
        model_chat::requested_at: now,
        model_chat::model: config.model.model.as_str(),
    };

    ws.commit(change, "create thought + model request");
    push_workspace(repo, &mut ws).context("push thought + request")?;

    Ok(ModelRequestInfo {
        id: *request_id,
        thought_id: Some(*thought_id),
    })
}


fn create_request_for_thought_from_catalog(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    thought_id: Id,
    config: &Config,
) -> Result<Id> {
    if let Some(request_id) = request_for_thought(catalog, thought_id) {
        return Ok(request_id);
    }

    let Some(context_handle) = thought_context_handle(catalog, thought_id) else {
        return Err(anyhow!("thought {thought_id:x} missing context"));
    };

    let now = epoch_interval(now_epoch());
    let request_id = ufoid();
    let mut change = TribleSet::new();
    change += entity! { &request_id @
        metadata::tag: model_chat::kind_request,
        model_chat::about_thought: thought_id,
        model_chat::context: context_handle,
        model_chat::requested_at: now,
        model_chat::model: config.model.model.as_str(),
    };
    ws.commit(change, "create model request");
    Ok(*request_id)
}

/// Re-submit a model request for the same thought after a transient failure.
/// Avoids bootstrapping a new orient cycle on every error.
fn retry_model_request(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    thought_id: Option<Id>,
    config: &Config,
    prev_cover: &mut Option<MemoryCoverState>,
) -> Result<ModelRequestInfo> {
    if let Some(thought_id) = thought_id {
        let mut ws = pull_workspace(repo, branch_id, "pull workspace for model retry")?;
        let catalog = ws.checkout(..).context("checkout workspace for retry")?.into_facts();

        let Some(context_handle) = thought_context_handle(&catalog, thought_id) else {
            return Err(anyhow!("thought {thought_id:x} missing context for retry"));
        };

        let now = epoch_interval(now_epoch());
        let request_id = ufoid();
        let mut change = TribleSet::new();
        change += entity! { &request_id @
            metadata::tag: model_chat::kind_request,
            model_chat::about_thought: thought_id,
            model_chat::context: context_handle,
            model_chat::requested_at: now,
            model_chat::model: config.model.model.as_str(),
        };
        ws.commit(change, "retry model request");
        push_workspace(repo, &mut ws).context("push model retry")?;
        Ok(ModelRequestInfo {
            id: *request_id,
            thought_id: Some(thought_id),
        })
    } else {
        // No thought to retry — fall back to the full discovery chain.
        ensure_model_request(repo, branch_id, config, prev_cover)
    }
}

#[derive(Debug)]
struct ModelResult {
    output_text: String,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct ModelResultInfo {
    id: Id,
    output_text: Option<Value<Handle<Blake3, LongString>>>,
    reasoning_text: Option<Value<Handle<Blake3, LongString>>>,
    error: Option<Value<Handle<Blake3, LongString>>>,
}

fn wait_for_model_result(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    request_id: Id,
    poll_ms: u64,
) -> Result<ModelResult> {
    let mut cached_head = None;
    let mut cached_catalog = TribleSet::new();
    loop {
        let branch_head = current_branch_head(repo, branch_id)?;
        if branch_head == cached_head {
            sleep(Duration::from_millis(poll_ms));
            continue;
        }

        let mut ws = pull_workspace(repo, branch_id, "pull workspace for model result")?;
        let delta = refresh_cached_checkout(&mut ws, &mut cached_head, &mut cached_catalog)?;
        if !delta_has_model_result(&cached_catalog, &delta, request_id) {
            sleep(Duration::from_millis(poll_ms));
            continue;
        }
        if let Some(result) = latest_model_result(&cached_catalog, request_id) {
            return load_model_result(&mut ws, result);
        }
        sleep(Duration::from_millis(poll_ms));
    }
}

fn load_model_result(ws: &mut Workspace<Pile>, result: ModelResultInfo) -> Result<ModelResult> {
    let output_text = result
        .output_text
        .map(|handle| load_text(ws, handle))
        .transpose()?
        .unwrap_or_default();
    let error = result
        .error
        .map(|handle| load_text(ws, handle))
        .transpose()?;

    Ok(ModelResult { output_text, error })
}

#[derive(Debug)]
struct ExecResult {
    stdout_text: Option<String>,
    stderr_text: Option<String>,
    stdout: Option<Bytes>,
    stderr: Option<Bytes>,
    exit_code: Option<u64>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct CommandResultInfo {
    id: Id,
    about_request: Id,
    finished_at: Option<Value<NsTAIInterval>>,
    attempt: Option<Value<U256BE>>,
    stdout: Option<Value<Handle<Blake3, UnknownBlob>>>,
    stderr: Option<Value<Handle<Blake3, UnknownBlob>>>,
    stdout_text: Option<Value<Handle<Blake3, LongString>>>,
    stderr_text: Option<Value<Handle<Blake3, LongString>>>,
    exit_code: Option<Value<U256BE>>,
    error: Option<Value<Handle<Blake3, LongString>>>,
}

fn has_pending_command_request(catalog: &TribleSet) -> bool {
    // Collect command request IDs that have a result.
    let done: Vec<Id> = find!(
        about_request: Id,
        pattern!(catalog, [{
            _?result_id @
            metadata::tag: playground_exec::kind_command_result,
            playground_exec::about_request: ?about_request,
        }])
    )
    .collect();

    // Check if any command request has no result.
    find!(
        request_id: Id,
        pattern!(catalog, [{
            ?request_id @ metadata::tag: playground_exec::kind_command_request
        }])
    )
    .any(|request_id| !done.contains(&request_id))
}

fn latest_unprocessed_exec_result(catalog: &TribleSet) -> Option<CommandResultInfo> {
    // Collect exec result IDs that are already referenced by a thought.
    let used: Vec<Id> = find!(
        exec_result_id: Id,
        pattern!(catalog, [{
            _?thought_id @
            metadata::tag: playground_cog::kind_thought,
            playground_cog::about_exec_result: ?exec_result_id,
        }])
    )
    .collect();

    let mut candidates: Vec<CommandResultInfo> = find!(
        (result_id: Id, about_request: Id),
        pattern!(catalog, [{
            ?result_id @
            metadata::tag: playground_exec::kind_command_result,
            playground_exec::about_request: ?about_request,
        }])
    )
    .filter(|(result_id, _)| !used.contains(result_id))
    .map(|(result_id, about_request)| {
        let mut info = CommandResultInfo {
            id: result_id,
            about_request,
            finished_at: None,
            attempt: None,
            stdout: None,
            stderr: None,
            stdout_text: None,
            stderr_text: None,
            exit_code: None,
            error: None,
        };
        fill_command_result_fields(catalog, &mut info);
        info
    })
    .collect();

    candidates.sort_by_key(|r| r.finished_at.map(interval_key).unwrap_or(i128::MIN));
    candidates.pop()
}

fn latest_pending_model_request(catalog: &TribleSet) -> Option<ModelRequestInfo> {
    // Collect request IDs that already have a result.
    let done: Vec<Id> = find!(
        about_request: Id,
        pattern!(catalog, [{
            _?result_id @
            metadata::tag: model_chat::kind_result,
            model_chat::about_request: ?about_request,
        }])
    )
    .collect();

    let mut candidates: Vec<(Id, i128, Option<Id>)> = find!(
        request_id: Id,
        pattern!(catalog, [{
            ?request_id @ metadata::tag: model_chat::kind_request
        }])
    )
    .filter(|request_id| !done.contains(request_id))
    .map(|request_id| {
        let requested_at = find!(
            ts: Value<NsTAIInterval>,
            pattern!(catalog, [{ request_id @ model_chat::requested_at: ?ts }])
        )
        .next()
        .map(|ts| interval_key(ts))
        .unwrap_or(i128::MIN);

        let thought_id = find!(
            thought_id: Id,
            pattern!(catalog, [{ request_id @ model_chat::about_thought: ?thought_id }])
        )
        .next();

        (request_id, requested_at, thought_id)
    })
    .collect();

    candidates.sort_by_key(|(id, ts, _)| (*ts, *id));
    candidates.pop().map(|(id, _, thought_id)| ModelRequestInfo {
        id,
        thought_id,
    })
}

fn latest_unrequested_thought(catalog: &TribleSet) -> Option<Id> {
    // Collect thought IDs that have a model request referencing them.
    let requested: Vec<Id> = find!(
        thought_id: Id,
        pattern!(catalog, [{
            _?request_id @
            metadata::tag: model_chat::kind_request,
            model_chat::about_thought: ?thought_id,
        }])
    )
    .collect();

    let mut candidates: Vec<(Id, i128)> = find!(
        thought_id: Id,
        pattern!(catalog, [{
            ?thought_id @ metadata::tag: playground_cog::kind_thought
        }])
    )
    .filter(|thought_id| !requested.contains(thought_id))
    .map(|thought_id| {
        let created_at = find!(
            ts: Value<NsTAIInterval>,
            pattern!(catalog, [{ thought_id @ playground_cog::created_at: ?ts }])
        )
        .next()
        .map(|ts| interval_key(ts))
        .unwrap_or(i128::MIN);
        (thought_id, created_at)
    })
    .collect();

    candidates.sort_by_key(|(id, ts)| (*ts, *id));
    candidates.pop().map(|(id, _)| id)
}

fn request_for_thought(catalog: &TribleSet, thought_id: Id) -> Option<Id> {
    find!(
        request_id: Id,
        pattern!(catalog, [{
            ?request_id @
            metadata::tag: model_chat::kind_request,
            model_chat::about_thought: thought_id,
        }])
    )
    .next()
}

fn thought_for_exec_result(catalog: &TribleSet, exec_result_id: Id) -> Option<Id> {
    find!(
        thought_id: Id,
        pattern!(catalog, [{
            ?thought_id @
            metadata::tag: playground_cog::kind_thought,
            playground_cog::about_exec_result: exec_result_id,
        }])
    )
    .next()
}

fn thought_context_handle(
    catalog: &TribleSet,
    thought_id: Id,
) -> Option<Value<Handle<Blake3, LongString>>> {
    find!(
        context: Value<Handle<Blake3, LongString>>,
        pattern!(catalog, [{ thought_id @ playground_cog::context: ?context }])
    )
    .next()
}

fn latest_model_result(catalog: &TribleSet, request_id: Id) -> Option<ModelResultInfo> {
    find!(
        result_id: Id,
        pattern!(catalog, [{
            ?result_id @
            metadata::tag: model_chat::kind_result,
            model_chat::about_request: request_id,
        }])
    )
    .map(|result_id| {
            let finished_at = find!(
                ts: Value<NsTAIInterval>,
                pattern!(catalog, [{ result_id @ model_chat::finished_at: ?ts }])
            )
            .next();

            let attempt = find!(
                a: Value<U256BE>,
                pattern!(catalog, [{ result_id @ model_chat::attempt: ?a }])
            )
            .next();

            let output_text = find!(
                t: Value<Handle<Blake3, LongString>>,
                pattern!(catalog, [{ result_id @ model_chat::output_text: ?t }])
            )
            .next();

            let reasoning_text = find!(
                t: Value<Handle<Blake3, LongString>>,
                pattern!(catalog, [{ result_id @ model_chat::reasoning_text: ?t }])
            )
            .next();

            let error = find!(
                t: Value<Handle<Blake3, LongString>>,
                pattern!(catalog, [{ result_id @ model_chat::error: ?t }])
            )
            .next();

            (result_id, attempt, finished_at, output_text, reasoning_text, error)
        })
        .max_by_key(|(_, attempt, finished_at, _, _, _)| model_result_rank(*attempt, *finished_at))
        .map(|(id, _, _, output_text, reasoning_text, error)| ModelResultInfo {
            id,
            output_text,
            reasoning_text,
            error,
        })
}

fn reason_events_for_turn(catalog: &TribleSet, turn_id: Id) -> Vec<ReasonEventInfo> {
    let mut events: Vec<(i128, Id, ReasonEventInfo)> = find!(
        reason_id: Id,
        pattern!(catalog, [{
            ?reason_id @
            reason_events::about_turn: turn_id,
        }])
    )
    .map(|reason_id| {
        let created_at = find!(
            ts: Value<NsTAIInterval>,
            pattern!(catalog, [{ reason_id @ reason_events::created_at: ?ts }])
        )
        .next()
        .map(|ts| interval_key(ts))
        .unwrap_or(i128::MIN);

        let text = find!(
            t: Value<Handle<Blake3, LongString>>,
            pattern!(catalog, [{ reason_id @ reason_events::text: ?t }])
        )
        .next();

        let command_text = find!(
            t: Value<Handle<Blake3, LongString>>,
            pattern!(catalog, [{ reason_id @ reason_events::command_text: ?t }])
        )
        .next();

        (created_at, reason_id, ReasonEventInfo { text, command_text })
    })
    .collect();

    events.sort_by_key(|(ts, id, _)| (*ts, *id));
    events.into_iter().map(|(_, _, info)| info).collect()
}

fn command_request_command_handle(
    catalog: &TribleSet,
    request_id: Id,
) -> Option<Value<Handle<Blake3, LongString>>> {
    find!(
        cmd: Value<Handle<Blake3, LongString>>,
        pattern!(catalog, [{ request_id @ playground_exec::command_text: ?cmd }])
    )
    .next()
}

fn command_request_for_thought(catalog: &TribleSet, thought_id: Id) -> Option<Id> {
    find!(
        request_id: Id,
        pattern!(catalog, [{
            ?request_id @
            metadata::tag: playground_exec::kind_command_request,
            playground_exec::about_thought: thought_id,
        }])
    )
    .next()
}

fn latest_command_result(catalog: &TribleSet, request_id: Id) -> Option<CommandResultInfo> {
    let results: Vec<CommandResultInfo> = find!(
        result_id: Id,
        pattern!(catalog, [{
            ?result_id @
            metadata::tag: playground_exec::kind_command_result,
            playground_exec::about_request: request_id,
        }])
    )
    .map(|result_id| {
        let mut info = CommandResultInfo {
            id: result_id,
            about_request: request_id,
            finished_at: None,
            attempt: None,
            stdout: None,
            stderr: None,
            stdout_text: None,
            stderr_text: None,
            exit_code: None,
            error: None,
        };
        fill_command_result_fields(catalog, &mut info);
        info
    })
    .collect();

    results.into_iter().max_by_key(command_result_rank)
}

fn latest_moment_boundary_turn_id(catalog: &TribleSet) -> Option<Id> {
    find!(
        (boundary_id: Id, turn_id: Id),
        pattern!(catalog, [{
            ?boundary_id @
            metadata::tag: playground_cog::kind_moment_boundary,
            playground_cog::moment_boundary_turn_id: ?turn_id,
        }])
    )
    .filter_map(|(boundary_id, turn_id)| {
        let created = find!(
            ts: Value<NsTAIInterval>,
            pattern!(catalog, [{ boundary_id @ playground_cog::created_at: ?ts }])
        )
        .next()
        .map(|ts| interval_key(ts))?;
        Some((created, boundary_id, turn_id))
    })
    .max_by_key(|(created, boundary_id, _)| (*created, *boundary_id))
    .map(|(_, _, turn_id)| turn_id)
}

fn sorted_finished_command_results(catalog: &TribleSet) -> Vec<CommandResultInfo> {
    let mut results: Vec<CommandResultInfo> = find!(
        (result_id: Id, about_request: Id),
        pattern!(catalog, [{
            ?result_id @
            metadata::tag: playground_exec::kind_command_result,
            playground_exec::about_request: ?about_request,
        }])
    )
    .map(|(result_id, about_request)| {
        let mut info = CommandResultInfo {
            id: result_id,
            about_request,
            finished_at: None,
            attempt: None,
            stdout: None,
            stderr: None,
            stdout_text: None,
            stderr_text: None,
            exit_code: None,
            error: None,
        };
        fill_command_result_fields(catalog, &mut info);
        info
    })
    .collect();
    results.retain(|result| result.finished_at.is_some());
    results.sort_by_key(|result| result.finished_at.map(interval_key).unwrap_or(i128::MIN));
    results
}

/// Fill optional fields of a CommandResultInfo from the catalog.
fn fill_command_result_fields(catalog: &TribleSet, info: &mut CommandResultInfo) {
    let result_id = info.id;

    info.finished_at = find!(
        ts: Value<NsTAIInterval>,
        pattern!(catalog, [{ result_id @ playground_exec::finished_at: ?ts }])
    )
    .next();

    info.attempt = find!(
        a: Value<U256BE>,
        pattern!(catalog, [{ result_id @ playground_exec::attempt: ?a }])
    )
    .next();

    info.stdout = find!(
        s: Value<Handle<Blake3, UnknownBlob>>,
        pattern!(catalog, [{ result_id @ playground_exec::stdout: ?s }])
    )
    .next();

    info.stderr = find!(
        s: Value<Handle<Blake3, UnknownBlob>>,
        pattern!(catalog, [{ result_id @ playground_exec::stderr: ?s }])
    )
    .next();

    info.stdout_text = find!(
        t: Value<Handle<Blake3, LongString>>,
        pattern!(catalog, [{ result_id @ playground_exec::stdout_text: ?t }])
    )
    .next();

    info.stderr_text = find!(
        t: Value<Handle<Blake3, LongString>>,
        pattern!(catalog, [{ result_id @ playground_exec::stderr_text: ?t }])
    )
    .next();

    info.exit_code = find!(
        c: Value<U256BE>,
        pattern!(catalog, [{ result_id @ playground_exec::exit_code: ?c }])
    )
    .next();

    info.error = find!(
        e: Value<Handle<Blake3, LongString>>,
        pattern!(catalog, [{ result_id @ playground_exec::error: ?e }])
    )
    .next();
}

fn model_result_rank(
    attempt: Option<Value<U256BE>>,
    finished_at: Option<Value<NsTAIInterval>>,
) -> (u64, i128) {
    (
        attempt.and_then(|v| v.try_from_value::<u64>().ok()).unwrap_or_default(),
        finished_at.map(interval_key).unwrap_or(i128::MIN),
    )
}

fn command_result_rank(result: &CommandResultInfo) -> (u64, i128) {
    (
        result.attempt.and_then(|v| v.try_from_value::<u64>().ok()).unwrap_or_default(),
        result.finished_at.map(interval_key).unwrap_or(i128::MIN),
    )
}

fn ensure_command_request(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    command: &str,
    thought_id: Option<Id>,
    default_cwd: Option<&str>,
    sandbox_profile: Option<Id>,
) -> Result<Id> {
    let mut ws = pull_workspace(repo, branch_id, "pull workspace for command request")?;
    let mut cached_head = None;
    let mut cached_catalog = TribleSet::new();
    let _delta = refresh_cached_checkout(&mut ws, &mut cached_head, &mut cached_catalog)?;

    if let Some(thought_id) = thought_id {
        if let Some(existing) = command_request_for_thought(&cached_catalog, thought_id) {
            return Ok(existing);
        }
    }

    let request_id = ufoid();
    let now = epoch_interval(now_epoch());
    let command_handle = ws.put(command.to_owned());
    let mut change = TribleSet::new();
    change += entity! { &request_id @
        metadata::tag: playground_exec::kind_command_request,
        playground_exec::command_text: command_handle,
        playground_exec::requested_at: now,
    };
    if let Some(thought_id) = thought_id {
        change += entity! { &request_id @ playground_exec::about_thought: thought_id };
    }
    if let Some(cwd) = default_cwd {
        let handle = ws.put(cwd.to_owned());
        change += entity! { &request_id @ playground_exec::cwd: handle };
    }
    if let Some(profile) = sandbox_profile {
        change += entity! { &request_id @ playground_exec::sandbox_profile: profile };
    }
    ws.commit(change, "playground_exec request");
    push_workspace(repo, &mut ws).context("push command request")?;
    Ok(*request_id)
}

fn wait_for_command_result(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    request_id: Id,
    poll_ms: u64,
) -> Result<Id> {
    let mut cached_head = None;
    let mut cached_catalog = TribleSet::new();
    loop {
        let branch_head = current_branch_head(repo, branch_id)?;
        if branch_head == cached_head {
            sleep(Duration::from_millis(poll_ms));
            continue;
        }

        let mut ws = pull_workspace(repo, branch_id, "pull workspace for command result")?;
        let delta = refresh_cached_checkout(&mut ws, &mut cached_head, &mut cached_catalog)?;
        if !delta_has_command_result(&cached_catalog, &delta, request_id) {
            sleep(Duration::from_millis(poll_ms));
            continue;
        }
        if let Some(result) = latest_command_result(&cached_catalog, request_id) {
            return Ok(result.id);
        }
        sleep(Duration::from_millis(poll_ms));
    }
}

fn delta_has_model_result(updated: &TribleSet, delta: &TribleSet, request_id: Id) -> bool {
    find!(
        about_request: Id,
        pattern_changes!(updated, delta, [{
            _?event @
            metadata::tag: model_chat::kind_result,
            model_chat::about_request: ?about_request,
        }])
    )
    .any(|about_request| about_request == request_id)
}

fn delta_has_command_result(updated: &TribleSet, delta: &TribleSet, request_id: Id) -> bool {
    find!(
        about_request: Id,
        pattern_changes!(updated, delta, [{
            _?event @
            metadata::tag: playground_exec::kind_command_result,
            playground_exec::about_request: ?about_request,
        }])
    )
    .any(|about_request| about_request == request_id)
}


#[derive(Debug, Clone)]
struct ContextChunk {
    id: Id,
    summary: Value<Handle<Blake3, LongString>>,
    start_at: Value<NsTAIInterval>,
    end_at: Value<NsTAIInterval>,
    children: Vec<Id>,
    about_exec_result: Option<Id>,
    about_archive_message: Option<Id>,
}

#[derive(Default)]
struct ContextChunkIndex {
    chunks: HashMap<Id, ContextChunk>,
    // Roots: chunks not referenced as children of any other chunk.
    roots: Vec<Id>,
}

fn context_for_exec_result_with_history(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    memory_catalog: &TribleSet,
    exec_result_id: Id,
    config: &Config,
    prev_cover: &mut Option<MemoryCoverState>,
) -> Result<String> {
    let mut messages = build_context_messages(
        ws,
        catalog,
        memory_catalog,
        exec_result_id,
        config,
        prev_cover,
    )?;
    messages.insert(0, ChatMessage::system(config.system_prompt.clone()));
    let context_json = serde_json::to_string(&messages).context("serialize context messages")?;
    Ok(context_json)
}

fn build_context_messages(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    memory_catalog: &TribleSet,
    exec_result_id: Id,
    config: &Config,
    prev_cover: &mut Option<MemoryCoverState>,
) -> Result<Vec<ChatMessage>> {
    let index = load_context_chunks(memory_catalog);
    let body_budget_chars = context_body_budget_chars(config);
    // Sort all command results in chronological order (oldest -> newest).
    let results = sorted_finished_command_results(catalog);

    let Some(current_pos) = results
        .iter()
        .position(|result| result.id == exec_result_id)
    else {
        return Err(anyhow!("exec result {exec_result_id:x} missing from index"));
    };
    let results = results[..=current_pos].to_vec();

    let moment_boundary_end_key = resolve_moment_boundary_end_key(
        results.as_slice(),
        latest_moment_boundary_turn_id(catalog),
    );
    let (new_messages, new_used_chars, new_breath_idx, new_cover_end_key) =
        build_memory_cover_messages(ws, &index, body_budget_chars, moment_boundary_end_key)?;

    // Memory cover delay: if the cover changed since the last turn, use the
    // old cover this turn (seeding the cache for the old prefix at the breath
    // breakpoint). Track the new cover for comparison next turn.
    let (mut messages, used_chars, breath_idx, cover_end_key) =
        if let Some(ref prev) = *prev_cover {
            if prev.messages != new_messages {
                // Memory changed — use old cover this turn, record new for next.
                let old = (
                    prev.messages.clone(),
                    prev.used_chars,
                    prev.breath_idx,
                    prev.cover_end_key,
                );
                *prev_cover = Some(MemoryCoverState {
                    messages: new_messages,
                    used_chars: new_used_chars,
                    breath_idx: new_breath_idx,
                    cover_end_key: new_cover_end_key,
                });
                old
            } else {
                // No change — use current, keep prev_cover as-is.
                (new_messages, new_used_chars, new_breath_idx, new_cover_end_key)
            }
        } else {
            // First call — record and use current.
            *prev_cover = Some(MemoryCoverState {
                messages: new_messages.clone(),
                used_chars: new_used_chars,
                breath_idx: new_breath_idx,
                cover_end_key: new_cover_end_key,
            });
            (new_messages, new_used_chars, new_breath_idx, new_cover_end_key)
        };

    // The moment floor is the later of: the breath boundary and the memory cover's end.
    // Turns at or before this point are already summarized in memory and should be skipped.
    let moment_floor = match (moment_boundary_end_key, cover_end_key) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };

    // Insert static breath boundary between memory and moment segments.
    // The breath content is fixed so it remains cacheable together with the
    // moment turns that follow. Context pressure is appended to the last
    // exec result output instead so only the tail changes.
    {
        messages.insert(breath_idx, ChatMessage::user(
            "present moment begins.".to_string(),
        ));
        messages.insert(breath_idx, ChatMessage::assistant("breath".to_string()));
    }

    // Project post-boundary exec results as raw shell interaction turns.
    // Budget-aware: keep the most recent turns that fit in the remaining body budget.
    {
        let breath_chars = messages.iter().map(|m| m.content.chars().count()).sum::<usize>();
        let moment_budget = body_budget_chars.saturating_sub(used_chars).saturating_sub(breath_chars);

        // Collect moment turns in chronological order with their cost.
        struct MomentTurn {
            messages: Vec<ChatMessage>,
            cost: usize,
        }
        let mut moment_turns: Vec<MomentTurn> = Vec::new();

        for result in &results {
            let Some(finished_at) = result.finished_at else {
                continue;
            };
            if let Some(floor) = moment_floor {
                if interval_key(finished_at) <= floor {
                    continue;
                }
            }
            let projection = load_exec_turn_projection(ws, catalog, result)?;
            let exec_output = load_exec_result(ws, result.clone())?;

            let mut turn_messages = Vec::new();
            let mut turn_cost = 0usize;

            for event in &projection.reason_events {
                if should_project_reason_event(event) {
                    let cmd = synthetic_reason_command(&event.text);
                    let out = synthetic_reason_output_brief(event);
                    turn_cost += cmd.chars().count() + out.chars().count();
                    turn_messages.push(ChatMessage::assistant(cmd));
                    turn_messages.push(ChatMessage::user(out));
                }
            }

            let timestamp = format_tai_interval_timestamp(finished_at);
            let output = format!("{timestamp}\n{}", format_moment_output(&exec_output));
            turn_cost += projection.command.chars().count() + output.chars().count();
            turn_messages.push(ChatMessage::assistant(projection.command));
            turn_messages.push(ChatMessage::user(output));

            moment_turns.push(MomentTurn { messages: turn_messages, cost: turn_cost });
        }

        // Drop oldest turns until total fits in budget, keeping the most recent.
        let mut total_cost: usize = moment_turns.iter().map(|t| t.cost).sum();
        while total_cost > moment_budget && moment_turns.len() > 1 {
            total_cost -= moment_turns.remove(0).cost;
        }

        for turn in moment_turns {
            messages.extend(turn.messages);
        }
    }

    if let Some(guard) = memory_loop_guard_message(ws, catalog, results.as_slice(), current_pos)?
    {
        messages.push(ChatMessage::user(guard));
    }

    // Append context pressure to the last user message so the model knows how
    // full the window is, without breaking the static breath cache boundary.
    {
        let total_chars: usize = messages.iter().map(|m| m.content.chars().count()).sum();
        let fill_pct = if body_budget_chars > 0 {
            (total_chars * 100) / body_budget_chars
        } else {
            0
        };
        if let Some(last_user) = messages.iter_mut().rev().find(|m| m.role == ChatRole::User) {
            last_user
                .content
                .push_str(&format!("\ncontext filled to {fill_pct}%."));
        }
    }

    Ok(messages)
}

fn context_body_budget_chars(config: &Config) -> usize {
    // This is an intentionally cheap heuristic: we approximate tokens->chars and reserve space
    // for model output plus a small safety margin.
    let reserved = config
        .model
        .max_output_tokens
        .saturating_add(config.model.context_safety_margin_tokens);
    let input_tokens = config.model.context_window_tokens.saturating_sub(reserved);
    let chars_per_token = config.model.chars_per_token.max(1);

    let input_chars = u128_to_usize_saturating((input_tokens as u128) * (chars_per_token as u128));
    let system_chars = config.system_prompt.chars().count();
    input_chars.saturating_sub(system_chars)
}

fn u128_to_usize_saturating(value: u128) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn resolve_moment_boundary_end_key(
    results: &[CommandResultInfo],
    moment_boundary_turn_id: Option<Id>,
) -> Option<i128> {
    let target = moment_boundary_turn_id?;
    results.iter().find_map(|result| {
        if result.id != target {
            return None;
        }
        result.finished_at.map(interval_key)
    })
}

#[derive(Debug, Clone)]
struct MemoryCoverTurn {
    command: String,
    output: String,
    cost: usize,
}

#[derive(Debug, Clone)]
struct SplitCandidate {
    index: usize,
    parent_id: Id,
    child_ids: Vec<Id>,
    extra_cost: usize,
    /// Width of the parent chunk's time range (end - start) in nanoseconds.
    /// Wider chunks are coarser summaries and benefit most from splitting.
    range_width: i128,
}

/// Returns (messages, used_chars, breath_insert_index, cover_end_key).
/// `cover_end_key` is the latest `end_at` across all selected cover chunks —
/// moment turns at or before this time are already summarized and should be skipped.
fn build_memory_cover_messages(
    ws: &mut Workspace<Pile>,
    index: &ContextChunkIndex,
    budget_chars: usize,
    moment_boundary_end_key: Option<i128>,
) -> Result<(Vec<ChatMessage>, usize, usize, Option<i128>)> {
    if budget_chars == 0 {
        return Ok((Vec::new(), 0, 0, None));
    }

    // Start from roots (already sorted by time). Exclude post-boundary chunks:
    // moment turns are projected as raw shell interaction, not memory cover entries.
    let mut cover: Vec<Id> = index
        .roots
        .iter()
        .copied()
        .filter(|id| {
            moment_boundary_end_key.is_none_or(|boundary| {
                index
                    .chunks
                    .get(id)
                    .is_some_and(|chunk| interval_key(chunk.end_at) <= boundary)
            })
        })
        .collect();
    if cover.is_empty() {
        return Ok((Vec::new(), 0, 0, None));
    }

    let mut turn_cache: HashMap<Id, MemoryCoverTurn> = HashMap::new();
    let mut used = 0usize;
    for chunk_id in &cover {
        let turn = memory_cover_turn(ws, index, &mut turn_cache, *chunk_id)?;
        used = used.saturating_add(turn.cost);
    }

    // If even the coarsest antichain exceeds budget, drop the oldest roots until the selected
    // cover fits.
    while used > budget_chars && !cover.is_empty() {
        let removed = cover.remove(0);
        let turn = memory_cover_turn(ws, index, &mut turn_cache, removed)?;
        used = used.saturating_sub(turn.cost);
    }
    if cover.is_empty() {
        return Ok((Vec::new(), 0, 0, None));
    }

    loop {
        let remaining = budget_chars.saturating_sub(used);
        if remaining == 0 {
            break;
        }

        let mut best: Option<SplitCandidate> = None;
        for (cover_index, parent_id) in cover.iter().enumerate() {
            let Some(parent_chunk) = index.chunks.get(parent_id) else {
                continue;
            };
            if parent_chunk.children.len() < 2 {
                continue;
            }

            let parent_turn = memory_cover_turn(ws, index, &mut turn_cache, *parent_id)?;
            let mut children_cost = 0usize;
            for child_id in &parent_chunk.children {
                let child_turn = memory_cover_turn(ws, index, &mut turn_cache, *child_id)?;
                children_cost = children_cost.saturating_add(child_turn.cost);
            }
            let extra_cost = children_cost.saturating_sub(parent_turn.cost);
            if extra_cost > remaining {
                continue;
            }

            let candidate = SplitCandidate {
                index: cover_index,
                parent_id: *parent_id,
                child_ids: parent_chunk.children.clone(),
                extra_cost,
                range_width: interval_width(parent_chunk.start_at, parent_chunk.end_at),
            };
            if is_better_split_candidate(&candidate, best.as_ref()) {
                best = Some(candidate);
            }
        }

        let Some(candidate) = best else {
            break;
        };

        cover.splice(
            candidate.index..=candidate.index,
            candidate.child_ids.clone(),
        );
        used = used.saturating_add(candidate.extra_cost);
    }

    // Find the end of continuous coverage: walk the sorted cover and stop
    // at the first gap. Only the contiguous prefix counts as "summarized" —
    // isolated future memories shouldn't advance the boundary and drop
    // unsummarized events between the continuous cover and the outlier.
    let cover_end_key = {
        let mut contiguous_end: Option<i128> = None;
        for chunk_id in &cover {
            let Some(chunk) = index.chunks.get(chunk_id) else {
                continue;
            };
            let chunk_start = interval_key(chunk.start_at);
            let chunk_end = interval_key(chunk.end_at);
            if let Some(prev_end) = contiguous_end {
                if chunk_start > prev_end {
                    // Gap detected — stop here; previous end is the boundary.
                    break;
                }
            }
            contiguous_end = Some(contiguous_end.map_or(chunk_end, |e| e.max(chunk_end)));
        }
        contiguous_end
    };

    let mut messages = Vec::new();
    for chunk_id in cover {
        let turn = memory_cover_turn(ws, index, &mut turn_cache, chunk_id)?;
        messages.push(ChatMessage::assistant(turn.command.clone()));
        messages.push(ChatMessage::user(turn.output.clone()));
    }

    // All cover entries are memory (post-boundary chunks are excluded above),
    // so breath goes at the end.
    let breath_insert_index = messages.len();
    Ok((messages, used, breath_insert_index, cover_end_key))
}

fn memory_cover_turn(
    ws: &mut Workspace<Pile>,
    index: &ContextChunkIndex,
    turn_cache: &mut HashMap<Id, MemoryCoverTurn>,
    chunk_id: Id,
) -> Result<MemoryCoverTurn> {
    if let Some(turn) = turn_cache.get(&chunk_id) {
        return Ok(turn.clone());
    }

    let chunk = index
        .chunks
        .get(&chunk_id)
        .with_context(|| format!("missing context chunk {:x}", chunk_id))?;
    let command = format!("memory {}", memory_ref(chunk));
    let output = load_text(ws, chunk.summary).context("load memory chunk summary")?;
    let cost = command
        .chars()
        .count()
        .saturating_add(output.chars().count());
    let turn = MemoryCoverTurn {
        command,
        output,
        cost,
    };
    turn_cache.insert(chunk_id, turn.clone());
    Ok(turn)
}

fn is_better_split_candidate(candidate: &SplitCandidate, current: Option<&SplitCandidate>) -> bool {
    let Some(current) = current else {
        return true;
    };
    // Prefer widest range — coarsest summary benefits most from splitting.
    if candidate.range_width != current.range_width {
        return candidate.range_width > current.range_width;
    }
    // Tiebreaker: prefer larger extra_cost (more detail gained).
    if candidate.extra_cost != current.extra_cost {
        return candidate.extra_cost > current.extra_cost;
    }
    // Arbitrary tiebreaker: later position in cover, then lower id.
    if candidate.index != current.index {
        return candidate.index > current.index;
    }
    candidate.parent_id < current.parent_id
}

fn memory_ref(chunk: &ContextChunk) -> String {
    format_time_range(chunk.start_at, chunk.end_at)
}

fn memory_command_id(command: &str) -> Option<&str> {
    let mut parts = command.split_whitespace();
    let first = parts.next()?;
    if first != "memory" && !first.ends_with("/memory.rs") && !first.ends_with("/memory") {
        return None;
    }
    parts.next()
}

fn memory_lookup_failed_text(stderr: &str, error: &str) -> bool {
    let failure_text = if error.is_empty() {
        stderr.to_string()
    } else if stderr.is_empty() {
        error.to_string()
    } else {
        format!("{stderr}\n{error}")
    };
    failure_text
        .to_ascii_lowercase()
        .contains("memory lookup failed")
}

fn memory_lookup_failed_result(command: &str, result: &ExecResult) -> bool {
    if memory_command_id(command).is_none() {
        return false;
    }

    let stderr = format_output_text(result.stderr_text.as_deref(), result.stderr.as_ref());
    let error = result.error.clone().unwrap_or_default();
    memory_lookup_failed_text(stderr.as_str(), error.as_str())
}

fn memory_loop_guard_message(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    results: &[CommandResultInfo],
    current_pos: usize,
) -> Result<Option<String>> {
    const MEMORY_FAILURE_LOOKBACK: usize = 3;

    let window_start = current_pos.saturating_sub(MEMORY_FAILURE_LOOKBACK - 1);
    let mut streak_len = 0usize;
    for result in results[window_start..=current_pos].iter().rev() {
        let command = load_command_for_result(ws, catalog, result)?;
        let Some(id_hint) = memory_command_id(command.as_str()) else {
            break;
        };
        let exec_output = load_exec_result(ws, result.clone())?;
        if !memory_lookup_failed_result(command.as_str(), &exec_output) {
            break;
        }
        streak_len = streak_len.saturating_add(1);
        if streak_len >= MEMORY_FAILURE_LOOKBACK {
            return Ok(Some(format!(
                "Memory lookup failed repeatedly on recent turns.\n\
                 Do not guess ids.\n\
                 Only run `memory <id>` for ids already visible in this context (`mem <id>` / `children=...`).\n\
                 If no valid id is available, stop memory lookups and run `orient show` or another concrete action.\n\
                 Last failed id hint: {id_hint}"
            )));
        }
    }
    Ok(None)
}

fn load_command_for_result(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    exec_result: &CommandResultInfo,
) -> Result<String> {
    let Some(command_handle) = command_request_command_handle(catalog, exec_result.about_request)
    else {
        return Err(anyhow!(
            "command request {id:x} missing command text",
            id = exec_result.about_request
        ));
    };
    load_text(ws, command_handle).context("load command for exec result")
}

fn load_reasoning_for_exec_result(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    exec_result: &CommandResultInfo,
) -> Result<Option<(Id, String)>> {
    // Multi-hop join: command_request → thought → model_request → result
    let Some(request_id) = find!(
        request_id: Id,
        pattern!(catalog, [{
            exec_result.about_request @ playground_exec::about_thought: _?mid,
        }, {
            ?request_id @
            metadata::tag: model_chat::kind_request,
            model_chat::about_thought: _?mid,
        }])
    )
    .next() else {
        return Ok(None);
    };
    let Some(result) = latest_model_result(catalog, request_id) else {
        return Ok(None);
    };
    let Some(reasoning_handle) = result.reasoning_text else {
        return Ok(None);
    };
    let reasoning_text = load_text(ws, reasoning_handle).context("load reasoning text")?;
    if reasoning_text.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some((result.id, reasoning_text)))
}

fn load_context_chunks(catalog: &TribleSet) -> ContextChunkIndex {
    let mut index = ContextChunkIndex::default();

    for (chunk_id, summary, start_at, end_at) in find!(
        (
            chunk_id: Id,
            summary: Value<Handle<Blake3, LongString>>,
            start_at: Value<NsTAIInterval>,
            end_at: Value<NsTAIInterval>
        ),
        pattern!(catalog, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::summary: ?summary,
            playground_context::start_at: ?start_at,
            playground_context::end_at: ?end_at,
        }])
    ) {
        index.chunks.insert(
            chunk_id,
            ContextChunk {
                id: chunk_id,
                summary,
                start_at,
                end_at,
                children: Vec::new(),
                about_exec_result: None,
                about_archive_message: None,
            },
        );
    }

    for (chunk_id, child_id) in find!(
        (chunk_id: Id, child_id: Id),
        pattern!(catalog, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::child: ?child_id,
        }])
    ) {
        if let Some(chunk) = index.chunks.get_mut(&chunk_id) {
            chunk.children.push(child_id);
        }
    }

    // Legacy two-child edges.
    for (chunk_id, child_id) in find!(
        (chunk_id: Id, child_id: Id),
        pattern!(catalog, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::left: ?child_id,
        }])
    ) {
        if let Some(chunk) = index.chunks.get_mut(&chunk_id) {
            chunk.children.push(child_id);
        }
    }

    for (chunk_id, child_id) in find!(
        (chunk_id: Id, child_id: Id),
        pattern!(catalog, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::right: ?child_id,
        }])
    ) {
        if let Some(chunk) = index.chunks.get_mut(&chunk_id) {
            chunk.children.push(child_id);
        }
    }

    let child_order: HashMap<Id, i128> = index
        .chunks
        .iter()
        .map(|(chunk_id, chunk)| (*chunk_id, interval_key(chunk.start_at)))
        .collect();
    for chunk in index.chunks.values_mut() {
        chunk.children.sort_by_key(|child_id| {
            (
                child_order.get(child_id).copied().unwrap_or(i128::MAX),
                *child_id,
            )
        });
        chunk.children.dedup();
    }

    for (chunk_id, exec_result_id) in find!(
        (chunk_id: Id, exec_result_id: Id),
        pattern!(catalog, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::about_exec_result: ?exec_result_id,
        }])
    ) {
        if let Some(chunk) = index.chunks.get_mut(&chunk_id) {
            chunk.about_exec_result = Some(exec_result_id);
        }
    }

    for (chunk_id, archive_message_id) in find!(
        (chunk_id: Id, archive_message_id: Id),
        pattern!(catalog, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::about_archive_message: ?archive_message_id,
        }])
    ) {
        if let Some(chunk) = index.chunks.get_mut(&chunk_id) {
            chunk.about_archive_message = Some(archive_message_id);
        }
    }

    // Roots: chunks not referenced as children.
    let mut child_set = HashSet::new();
    for chunk in index.chunks.values() {
        for child_id in &chunk.children {
            child_set.insert(*child_id);
        }
    }
    index.roots = index
        .chunks
        .values()
        .filter(|chunk| !child_set.contains(&chunk.id))
        .map(|chunk| chunk.id)
        .collect();
    index.roots.sort_by_key(|id| {
        index
            .chunks
            .get(id)
            .map(|chunk| (interval_key(chunk.start_at), *id))
            .unwrap_or((i128::MAX, *id))
    });

    index
}


#[derive(Debug, Clone)]
struct ReasonProjectionEvent {
    text: String,
    command_text: Option<String>,
    source: ReasonProjectionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReasonProjectionSource {
    Logged,
    Model,
}

#[derive(Debug, Clone)]
struct ExecTurnProjection {
    command: String,
    reason_events: Vec<ReasonProjectionEvent>,
}

fn load_exec_result(ws: &mut Workspace<Pile>, result: CommandResultInfo) -> Result<ExecResult> {
    let stdout_text = result
        .stdout_text
        .map(|handle| load_text(ws, handle))
        .transpose()?;
    let stderr_text = result
        .stderr_text
        .map(|handle| load_text(ws, handle))
        .transpose()?;
    let stdout = result
        .stdout
        .map(|handle| ws.get(handle).context("read stdout bytes"))
        .transpose()?;
    let stderr = result
        .stderr
        .map(|handle| ws.get(handle).context("read stderr bytes"))
        .transpose()?;
    let exit_code = result.exit_code.and_then(|v| v.try_from_value::<u64>().ok());
    let error = result
        .error
        .map(|handle| load_text(ws, handle))
        .transpose()?;

    Ok(ExecResult {
        stdout_text,
        stderr_text,
        stdout,
        stderr,
        exit_code,
        error,
    })
}

fn load_exec_turn_projection(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    exec_result: &CommandResultInfo,
) -> Result<ExecTurnProjection> {
    let mut reason_events_list = Vec::new();
    for event in reason_events_for_turn(catalog, exec_result.about_request) {
        let text = event
            .text
            .map(|handle| load_text(ws, handle))
            .transpose()
            .context("load reason event text")?
            .unwrap_or_default();
        let command_text = event
            .command_text
            .map(|handle| load_text(ws, handle))
            .transpose()
            .context("load reason event command text")?;
        reason_events_list.push(ReasonProjectionEvent {
            text,
            command_text,
            source: ReasonProjectionSource::Logged,
        });
    }

    if let Some((_result_id, reasoning_text)) =
        load_reasoning_for_exec_result(ws, catalog, exec_result)?
    {
        reason_events_list.push(ReasonProjectionEvent {
            text: reasoning_text,
            command_text: None,
            source: ReasonProjectionSource::Model,
        });
    }

    let command = if let Some(command) = command_override_from_reason_events(reason_events_list.as_slice()) {
        command
    } else {
        load_command_for_result(ws, catalog, exec_result)
            .context("load command for exec turn projection")?
    };
    Ok(ExecTurnProjection {
        command,
        reason_events: reason_events_list,
    })
}

fn command_override_from_reason_events(reason_events: &[ReasonProjectionEvent]) -> Option<String> {
    reason_events
        .iter()
        .rev()
        .find_map(|event| event.command_text.as_ref())
        .map(|command| command.clone())
}

fn should_project_reason_event(event: &ReasonProjectionEvent) -> bool {
    let reason_text = event.text.trim();
    if reason_text.is_empty() {
        return false;
    }
    if let Some(command_text) = event.command_text.as_deref() {
        if reason_text == command_text.trim() {
            return false;
        }
    }
    true
}

fn synthetic_reason_command(reason_text: &str) -> String {
    let compact = reason_text.split_whitespace().collect::<Vec<_>>().join(" ");
    let escaped = compact
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    format!("reason \"{escaped}\"")
}

fn synthetic_reason_output_brief(event: &ReasonProjectionEvent) -> String {
    let source = match event.source {
        ReasonProjectionSource::Logged => "logged",
        ReasonProjectionSource::Model => "model",
    };
    format!("source: {source}")
}


fn format_output_text(text: Option<&str>, bytes: Option<&Bytes>) -> String {
    if let Some(text) = text {
        return text.to_string();
    }
    if let Some(bytes) = bytes {
        return String::from_utf8_lossy(bytes.as_ref()).to_string();
    }
    String::new()
}

/// Formats an exec result as concise shell output for moment turns.
/// Produces raw output without section headers — just what the model would
/// see from an actual shell command.
fn format_moment_output(result: &ExecResult) -> String {
    let stdout = format_output_text(result.stdout_text.as_deref(), result.stdout.as_ref());
    let stderr = format_output_text(result.stderr_text.as_deref(), result.stderr.as_ref());
    let mut text = String::new();
    if !stdout.is_empty() {
        text.push_str(&stdout);
        if !stdout.ends_with('\n') {
            text.push('\n');
        }
    }
    if !stderr.is_empty() {
        text.push_str("stderr:\n");
        text.push_str(&stderr);
        if !stderr.ends_with('\n') {
            text.push('\n');
        }
    }
    if let Some(error) = &result.error {
        if !error.is_empty() {
            text.push_str("error: ");
            text.push_str(error);
            if !error.ends_with('\n') {
                text.push('\n');
            }
        }
    }
    if result.exit_code.is_some_and(|code| code != 0) {
        text.push_str(&format!("exit: {}\n", result.exit_code.unwrap()));
    }
    if text.is_empty() {
        text.push_str("[ok]\n");
    }
    text
}

