#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4.2.3"
//! rand_core = "0.6.4"
//! triblespace = "0.33"
//! ```

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use rand_core::OsRng;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::{attributes, find, id_hex, pattern};
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, GenId, Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

const DEFAULT_MODEL: &str = "gpt-oss:120b";
const DEFAULT_BASE_URL: &str = "http://localhost:11434/v1";
const DEFAULT_STREAM: bool = false;
const DEFAULT_CONTEXT_WINDOW_TOKENS: u64 = 32 * 1024;
const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 1024;
const DEFAULT_CONTEXT_SAFETY_MARGIN_TOKENS: u64 = 512;
const DEFAULT_CHARS_PER_TOKEN: u64 = 4;
const DEFAULT_SYSTEM_PROMPT: &str = include_str!("../prompts/system_prompt.md");

const DEFAULT_BRANCH: &str = "cognition";
const DEFAULT_AUTHOR: &str = "agent";
const DEFAULT_AUTHOR_ROLE: &str = "user";
const DEFAULT_POLL_MS: u64 = 1;
const CONFIG_BRANCH: &str = "config";
const KIND_CONFIG_ID: Id = id_hex!("A8DCBFD625F386AA7CDFD62A81183E82");
const KIND_MODEL_PROFILE_ID: Id = id_hex!("B08E356C4B08F44AB7EC177D47129447");

mod playground_config {
    use super::*;
    attributes! {
        "950B556A74F71AC7CB008AB23FBB6544" as system_prompt: Handle<Blake3, LongString>;
        "35E36AE7B60AD946661BD63B3CD64672" as branch: Handle<Blake3, LongString>;
        "F0F90572249284CD57E48580369DEB6D" as author: Handle<Blake3, LongString>;
        "98A194178CFD7CBB915C1BC9EB561A7F" as author_role: Handle<Blake3, LongString>;
        "D1DC11B303725409AB8A30C6B59DB2D7" as persona_id: GenId;
        "79E1B50756FB64A30916E9353225E179" as active_model_profile_id: GenId;
        "698519DFB681FABC3F06160ACAC9DA8E" as poll_ms: U256BE;
        "6691CF3F872C6107DCFAD0BCF7CDC1A0" as model_profile_id: GenId;
        "85BE7BDA465B3CB0F800F76EEF8FAC9B" as model_name: Handle<Blake3, LongString>;
        "B216CFBBF85AA1350B142D510E26268B" as model_base_url: Handle<Blake3, LongString>;
        "55F3FFD721AF7C1258E45BC91CDBF30F" as model_api_key: Handle<Blake3, LongString>;
        "328B29CE81665EE719C5A6E91695D4D4" as tavily_api_key: Handle<Blake3, LongString>;
        "AB0DF9F03F28A27A6DB95B693CC0EC53" as exa_api_key: Handle<Blake3, LongString>;
        "BA4E05799CA2ACDCF3F9350FC8742F2F" as model_reasoning_effort: Handle<Blake3, LongString>;
        "5F04F7A0EB4EBBE6161022B336F83513" as model_stream: U256BE;
        "F9CEA1A2E81D738BB125B4D144B7A746" as model_context_window_tokens: U256BE;
        "4200F6746B36F2784DEBA1555595D6AC" as model_max_output_tokens: U256BE;
        "1FF004BB48F7A4F8F72541F4D4FA75FF" as model_context_safety_margin_tokens: U256BE;
        "095FAECDB8FF205DF591DF594E593B01" as model_chars_per_token: U256BE;
        "120F9C6BBB103FAFFB31A66E2ABC15E6" as exec_default_cwd: Handle<Blake3, LongString>;
        "D18A351B6E03A460E4F400D97D285F96" as exec_sandbox_profile: GenId;
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "headspace",
    bin_name = "headspace",
    about = "Manage active headspace (profile/model/reasoning)."
)]
struct Cli {
    /// Path to the pile file to use
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Show active headspace settings and available profiles
    Show {
        #[arg(long, default_value_t = false)]
        show_secrets: bool,
    },
    /// List available profiles
    List,
    /// Switch active profile by id or name
    Use {
        #[arg(value_name = "PROFILE")]
        profile: String,
    },
    /// Add a new profile and make it active
    Add(AddArgs),
    /// Set one field on the active profile
    Set {
        #[arg(value_enum, value_name = "FIELD")]
        field: SetField,
        #[arg(
            value_name = "VALUE",
            help = "Value to set. Use @path for file input or @- for stdin."
        )]
        value: String,
    },
    /// Clear one optional field on the active profile
    Unset {
        #[arg(value_enum, value_name = "FIELD")]
        field: UnsetField,
    },
}

#[derive(Args, Debug, Clone)]
struct AddArgs {
    #[arg(value_name = "NAME")]
    name: String,
    #[arg(long)]
    model: Option<String>,
    #[arg(long = "base-url")]
    base_url: Option<String>,
    #[arg(long = "api-key")]
    api_key: Option<String>,
    #[arg(long = "reasoning-effort")]
    reasoning_effort: Option<String>,
    #[arg(long)]
    stream: Option<bool>,
    #[arg(long = "context-window-tokens")]
    context_window_tokens: Option<u64>,
    #[arg(long = "max-output-tokens")]
    max_output_tokens: Option<u64>,
    #[arg(long = "prompt-safety-margin-tokens")]
    context_safety_margin_tokens: Option<u64>,
    #[arg(long = "prompt-chars-per-token")]
    chars_per_token: Option<u64>,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "kebab-case")]
enum SetField {
    Model,
    BaseUrl,
    ApiKey,
    ReasoningEffort,
    Stream,
    ContextWindowTokens,
    MaxOutputTokens,
    PromptSafetyMarginTokens,
    PromptCharsPerToken,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
#[value(rename_all = "kebab-case")]
enum UnsetField {
    ApiKey,
    ReasoningEffort,
}

#[derive(Clone, Debug)]
struct Config {
    pile_path: PathBuf,
    model: ModelConfig,
    model_profile_id: Option<Id>,
    model_profile_name: String,
    tavily_api_key: Option<String>,
    exa_api_key: Option<String>,
    exec: ExecConfig,
    system_prompt: String,
    branch: String,
    author: String,
    author_role: String,
    persona_id: Option<Id>,
    poll_ms: u64,
}

#[derive(Clone, Debug)]
struct ModelConfig {
    model: String,
    base_url: String,
    api_key: Option<String>,
    reasoning_effort: Option<String>,
    stream: bool,
    context_window_tokens: u64,
    max_output_tokens: u64,
    context_safety_margin_tokens: u64,
    chars_per_token: u64,
}

#[derive(Clone, Debug)]
struct ExecConfig {
    default_cwd: Option<PathBuf>,
    sandbox_profile: Option<Id>,
}

#[derive(Clone, Debug)]
struct ModelProfileSummary {
    id: Id,
    name: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command.as_ref() else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };

    match command {
        Command::Show { show_secrets } => {
            let config = load_config(cli.pile.as_path())?;
            print_headspace(&config, *show_secrets)?;
        }
        Command::List => {
            let config = load_config(cli.pile.as_path())?;
            print_profile_list(&config)?;
        }
        Command::Use { profile } => {
            let mut config = load_config(cli.pile.as_path())?;
            let profile_id = resolve_profile_selector(cli.pile.as_path(), profile.as_str())?;
            let Some((model, name)) = load_model_profile(cli.pile.as_path(), profile_id)? else {
                return Err(anyhow!("unknown profile {profile_id:x}"));
            };
            config.model_profile_id = Some(profile_id);
            config.model_profile_name = name;
            config.model = model;
            store_config_to_pile(config)?;
            let config = load_config(cli.pile.as_path())?;
            print_headspace(&config, false)?;
        }
        Command::Add(args) => {
            let mut config = load_config(cli.pile.as_path())?;
            config.model_profile_id = Some(*genid());
            config.model_profile_name = args.name.clone();
            apply_add_overrides(&mut config, args)?;
            store_config_to_pile(config)?;
            let config = load_config(cli.pile.as_path())?;
            print_headspace(&config, false)?;
        }
        Command::Set { field, value } => {
            let mut config = load_config(cli.pile.as_path())?;
            apply_set(&mut config, *field, value.as_str())?;
            store_config_to_pile(config)?;
            let config = load_config(cli.pile.as_path())?;
            print_headspace(&config, false)?;
        }
        Command::Unset { field } => {
            let mut config = load_config(cli.pile.as_path())?;
            apply_unset(&mut config, *field)?;
            store_config_to_pile(config)?;
            let config = load_config(cli.pile.as_path())?;
            print_headspace(&config, false)?;
        }
    }

    Ok(())
}

fn apply_add_overrides(config: &mut Config, args: &AddArgs) -> Result<()> {
    if let Some(value) = args.model.as_deref() {
        config.model.model = value.to_string();
    }
    if let Some(value) = args.base_url.as_deref() {
        config.model.base_url = value.to_string();
    }
    if let Some(value) = args.api_key.as_deref() {
        config.model.api_key = Some(value.trim().to_string());
    }
    if let Some(value) = args.reasoning_effort.as_deref() {
        config.model.reasoning_effort = Some(value.trim().to_string());
    }
    if let Some(value) = args.stream {
        config.model.stream = value;
    }
    if let Some(value) = args.context_window_tokens {
        config.model.context_window_tokens = value;
    }
    if let Some(value) = args.max_output_tokens {
        config.model.max_output_tokens = value;
    }
    if let Some(value) = args.context_safety_margin_tokens {
        config.model.context_safety_margin_tokens = value;
    }
    if let Some(value) = args.chars_per_token {
        config.model.chars_per_token = value;
    }
    Ok(())
}

fn apply_set(config: &mut Config, field: SetField, value: &str) -> Result<()> {
    match field {
        SetField::Model => config.model.model = load_value_or_file(value, "model_name")?,
        SetField::BaseUrl => config.model.base_url = load_value_or_file(value, "model_base_url")?,
        SetField::ApiKey => {
            config.model.api_key = Some(load_value_or_file_trimmed(value, "model_api_key")?)
        }
        SetField::ReasoningEffort => {
            config.model.reasoning_effort =
                Some(load_value_or_file_trimmed(value, "model_reasoning_effort")?)
        }
        SetField::Stream => config.model.stream = parse_bool(value, "model_stream")?,
        SetField::ContextWindowTokens => {
            config.model.context_window_tokens = parse_u64(value, "model_context_window_tokens")?
        }
        SetField::MaxOutputTokens => {
            config.model.max_output_tokens = parse_u64(value, "model_max_output_tokens")?
        }
        SetField::PromptSafetyMarginTokens => {
            config.model.context_safety_margin_tokens =
                parse_u64(value, "model_context_safety_margin_tokens")?
        }
        SetField::PromptCharsPerToken => {
            config.model.chars_per_token = parse_u64(value, "model_chars_per_token")?
        }
    }
    Ok(())
}

fn apply_unset(config: &mut Config, field: UnsetField) -> Result<()> {
    match field {
        UnsetField::ApiKey => config.model.api_key = None,
        UnsetField::ReasoningEffort => config.model.reasoning_effort = None,
    }
    Ok(())
}

fn resolve_profile_selector(pile_path: &Path, raw: &str) -> Result<Id> {
    if let Ok(id) = parse_hex_id(raw, "profile_id") {
        return Ok(id);
    }

    let needle = raw.trim().to_lowercase();
    let profiles = list_model_profiles(pile_path)?;
    let mut matches = profiles
        .into_iter()
        .filter(|profile| profile.name.to_lowercase() == needle);
    let Some(first) = matches.next() else {
        return Err(anyhow!("unknown profile '{raw}'"));
    };
    if matches.next().is_some() {
        return Err(anyhow!("profile name '{raw}' is ambiguous; use the hex id"));
    }
    Ok(first.id)
}

fn format_option_quoted(value: Option<&str>) -> String {
    value
        .map(|v| format!("\"{v}\""))
        .unwrap_or_else(|| "null".to_string())
}

fn redact_option(value: Option<&str>) -> String {
    match value {
        Some(_) => "\"<redacted>\"".to_string(),
        None => "null".to_string(),
    }
}

fn print_headspace(config: &Config, show_secrets: bool) -> Result<()> {
    println!("active:");
    println!(
        "  profile_id = {}",
        config
            .model_profile_id
            .map(|id| format!("\"{id:x}\""))
            .unwrap_or_else(|| "null".to_string())
    );
    println!("  profile_name = \"{}\"", config.model_profile_name);
    println!("  model = \"{}\"", config.model.model);
    println!("  base_url = \"{}\"", config.model.base_url);
    println!(
        "  api_key = {}",
        if show_secrets {
            format_option_quoted(config.model.api_key.as_deref())
        } else {
            redact_option(config.model.api_key.as_deref())
        }
    );
    println!(
        "  reasoning_effort = {}",
        format_option_quoted(config.model.reasoning_effort.as_deref())
    );
    println!("  stream = {}", config.model.stream);
    println!(
        "  context_window_tokens = {}",
        config.model.context_window_tokens
    );
    println!("  max_output_tokens = {}", config.model.max_output_tokens);
    println!(
        "  context_safety_margin_tokens = {}",
        config.model.context_safety_margin_tokens
    );
    println!(
        "  chars_per_token = {}",
        config.model.chars_per_token
    );
    println!();
    println!("profiles:");
    print_profile_list(config)
}

fn print_profile_list(config: &Config) -> Result<()> {
    let profiles = list_model_profiles(config.pile_path.as_path())?;
    for profile in profiles {
        let active = (config.model_profile_id == Some(profile.id)).then_some("*");
        let active = active.unwrap_or(" ");
        println!("{active} {}\t{:x}", profile.name, profile.id);
    }
    Ok(())
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> Value<NsTAIInterval> {
    (epoch, epoch).try_to_value().unwrap()
}

fn interval_key(interval: Value<NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_value().unwrap();
    lower.to_tai_duration().total_nanoseconds()
}

fn push_workspace(
    repo: &mut Repository<Pile<Blake3>>,
    ws: &mut Workspace<Pile<Blake3>>,
) -> Result<()> {
    while let Some(mut conflict) = repo
        .try_push(ws)
        .map_err(|err| anyhow!("push workspace: {err:?}"))?
    {
        conflict
            .merge(ws)
            .map_err(|err| anyhow!("merge workspace: {err:?}"))?;
        *ws = conflict;
    }
    Ok(())
}

fn close_repo(repo: Repository<Pile<Blake3>>) -> Result<()> {
    repo.into_storage().close().context("close pile")
}

fn open_config_repo(pile_path: &Path) -> Result<(Repository<Pile<Blake3>>, Id)> {
    let mut pile = Pile::<Blake3>::open(pile_path).context("open pile")?;
    if let Err(err) = pile.restore().context("restore pile") {
        let close_res = pile.close().context("close pile after restore failure");
        if let Err(close_err) = close_res {
            eprintln!("warning: failed to close pile cleanly: {close_err:#}");
        }
        return Err(err);
    }

    let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .map_err(|err| anyhow!("create repository: {err:?}"))?;
    let branch_id = repo
        .ensure_branch(CONFIG_BRANCH, None)
        .map_err(|e| anyhow!("ensure config branch: {e:?}"))?;
    Ok((repo, branch_id))
}

fn load_config(pile_path: &Path) -> Result<Config> {
    let (mut repo, branch_id) = open_config_repo(pile_path)?;
    let result = (|| -> Result<Config> {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|err| anyhow!("pull config workspace: {err:?}"))?;
        let catalog = ws.checkout(..).context("checkout config workspace")?;

        let config = if let Some(config) = load_latest_config(&mut ws, &catalog, pile_path)? {
            config
        } else {
            default_config(pile_path.to_path_buf())
        };

        Ok(config)
    })();

    if let Err(err) = close_repo(repo).context("close config pile") {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }

    result
}

fn store_config_to_pile(config: Config) -> Result<()> {
    let (mut repo, branch_id) = open_config_repo(config.pile_path.as_path())?;
    let result = (|| -> Result<()> {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|err| anyhow!("pull config workspace: {err:?}"))?;
        store_config(&mut ws, &config).context("store config")?;
        push_workspace(&mut repo, &mut ws).context("push config")?;
        Ok(())
    })();

    if let Err(err) = close_repo(repo).context("close config pile") {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }

    result
}

fn list_model_profiles(pile_path: &Path) -> Result<Vec<ModelProfileSummary>> {
    let (mut repo, branch_id) = open_config_repo(pile_path)?;
    let result = (|| -> Result<Vec<ModelProfileSummary>> {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|err| anyhow!("pull config workspace: {err:?}"))?;
        let catalog = ws.checkout(..).context("checkout config workspace")?;

        let mut latest: HashMap<Id, (Id, i128)> = HashMap::new();
        for (entry_id, profile_id, updated_at) in find!(
            (entry_id: Id, profile_id: Id, updated_at: Value<NsTAIInterval>),
            pattern!(&catalog, [{
                ?entry_id @
                metadata::tag: KIND_MODEL_PROFILE_ID,
                metadata::updated_at: ?updated_at,
                playground_config::model_profile_id: ?profile_id,
            }])
        ) {
            let key = interval_key(updated_at);
            latest
                .entry(profile_id)
                .and_modify(|slot| {
                    if key > slot.1 {
                        *slot = (entry_id, key);
                    }
                })
                .or_insert((entry_id, key));
        }

        let mut profiles = Vec::new();
        for (profile_id, (entry_id, _updated_key)) in latest {
            let name = load_string_attr(&mut ws, &catalog, entry_id, metadata::name)?
                .unwrap_or_else(|| format!("profile-{profile_id:x}"));
            profiles.push(ModelProfileSummary {
                id: profile_id,
                name,
            });
        }
        profiles.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(profiles)
    })();

    if let Err(err) = close_repo(repo).context("close config pile") {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }

    result
}

fn load_model_profile(pile_path: &Path, profile_id: Id) -> Result<Option<(ModelConfig, String)>> {
    let (mut repo, branch_id) = open_config_repo(pile_path)?;
    let result = (|| -> Result<Option<(ModelConfig, String)>> {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|err| anyhow!("pull config workspace: {err:?}"))?;
        let catalog = ws.checkout(..).context("checkout config workspace")?;
        load_latest_model_profile(&mut ws, &catalog, profile_id)
    })();

    if let Err(err) = close_repo(repo).context("close config pile") {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }

    result
}

fn load_latest_config(
    ws: &mut Workspace<Pile<Blake3>>,
    catalog: &TribleSet,
    pile_path: &Path,
) -> Result<Option<Config>> {
    let mut latest: Option<(Id, i128)> = None;

    for (config_id, updated_at) in find!(
        (config_id: Id, updated_at: Value<NsTAIInterval>),
        pattern!(catalog, [{
            ?config_id @
            metadata::tag: KIND_CONFIG_ID,
            metadata::updated_at: ?updated_at,
        }])
    ) {
        let key = interval_key(updated_at);
        match latest {
            Some((current_id, current_key))
                if current_key > key || (current_key == key && current_id >= config_id) => {}
            _ => latest = Some((config_id, key)),
        }
    }

    let Some((config_id, _)) = latest else {
        return Ok(None);
    };

    let mut config = default_config(pile_path.to_path_buf());

    if let Some(prompt) =
        load_string_attr(ws, catalog, config_id, playground_config::system_prompt)?
    {
        config.system_prompt = prompt;
    }
    if let Some(branch) = load_string_attr(ws, catalog, config_id, playground_config::branch)? {
        config.branch = branch;
    }
    if let Some(author) = load_string_attr(ws, catalog, config_id, playground_config::author)? {
        config.author = author;
    }
    if let Some(role) = load_string_attr(ws, catalog, config_id, playground_config::author_role)? {
        config.author_role = role;
    }
    if let Some(id) = load_id_attr(catalog, config_id, playground_config::persona_id) {
        config.persona_id = Some(id);
    }
    if let Some(id) = load_id_attr(catalog, config_id, playground_config::active_model_profile_id) {
        config.model_profile_id = Some(id);
    }
    if let Some(model) = load_string_attr(ws, catalog, config_id, playground_config::model_name)? {
        config.model.model = model;
    }
    if let Some(url) = load_string_attr(ws, catalog, config_id, playground_config::model_base_url)? {
        config.model.base_url = url;
    }
    if let Some(effort) = load_string_attr(
        ws,
        catalog,
        config_id,
        playground_config::model_reasoning_effort,
    )? {
        config.model.reasoning_effort = Some(effort);
    }
    if let Some(key) = load_string_attr(ws, catalog, config_id, playground_config::model_api_key)? {
        config.model.api_key = Some(key);
    }
    if let Some(key) = load_string_attr(ws, catalog, config_id, playground_config::tavily_api_key)?
    {
        config.tavily_api_key = Some(key);
    }
    if let Some(key) = load_string_attr(ws, catalog, config_id, playground_config::exa_api_key)? {
        config.exa_api_key = Some(key);
    }
    if let Some(cwd) =
        load_string_attr(ws, catalog, config_id, playground_config::exec_default_cwd)?
    {
        config.exec.default_cwd = Some(PathBuf::from(cwd));
    }

    if let Some(id) = load_id_attr(catalog, config_id, playground_config::exec_sandbox_profile) {
        config.exec.sandbox_profile = Some(id);
    }
    if let Some(poll_ms) =
        load_u256_attr(catalog, config_id, playground_config::poll_ms).and_then(u256be_to_u64)
    {
        config.poll_ms = poll_ms;
    }
    if let Some(stream) =
        load_u256_attr(catalog, config_id, playground_config::model_stream).and_then(u256be_to_u64)
    {
        config.model.stream = stream != 0;
    }
    if let Some(tokens) = load_u256_attr(
        catalog,
        config_id,
        playground_config::model_context_window_tokens,
    )
    .and_then(u256be_to_u64)
    {
        config.model.context_window_tokens = tokens;
    }
    if let Some(tokens) =
        load_u256_attr(catalog, config_id, playground_config::model_max_output_tokens)
            .and_then(u256be_to_u64)
    {
        config.model.max_output_tokens = tokens;
    }
    if let Some(tokens) = load_u256_attr(
        catalog,
        config_id,
        playground_config::model_context_safety_margin_tokens,
    )
    .and_then(u256be_to_u64)
    {
        config.model.context_safety_margin_tokens = tokens;
    }
    if let Some(chars) = load_u256_attr(
        catalog,
        config_id,
        playground_config::model_chars_per_token,
    )
    .and_then(u256be_to_u64)
    {
        config.model.chars_per_token = chars;
    }
    if let Some(profile_id) = config.model_profile_id {
        if let Some((model, name)) = load_latest_model_profile(ws, catalog, profile_id)? {
            config.model = model;
            config.model_profile_name = name;
        }
    }

    Ok(Some(config))
}

fn load_latest_model_profile(
    ws: &mut Workspace<Pile<Blake3>>,
    catalog: &TribleSet,
    profile_id: Id,
) -> Result<Option<(ModelConfig, String)>> {
    let mut latest: Option<(Id, i128)> = None;

    for (entry_id, updated_at) in find!(
        (entry_id: Id, updated_at: Value<NsTAIInterval>),
        pattern!(catalog, [{
            ?entry_id @
            metadata::tag: KIND_MODEL_PROFILE_ID,
            metadata::updated_at: ?updated_at,
            playground_config::model_profile_id: profile_id,
        }])
    ) {
        let key = interval_key(updated_at);
        match latest {
            Some((current_id, current_key))
                if current_key > key || (current_key == key && current_id >= entry_id) => {}
            _ => latest = Some((entry_id, key)),
        }
    }

    let Some((entry_id, _)) = latest else {
        return Ok(None);
    };

    let mut mc = ModelConfig::default();
    if let Some(model) = load_string_attr(ws, catalog, entry_id, playground_config::model_name)? {
        mc.model = model;
    }
    if let Some(url) = load_string_attr(ws, catalog, entry_id, playground_config::model_base_url)? {
        mc.base_url = url;
    }
    if let Some(effort) = load_string_attr(
        ws,
        catalog,
        entry_id,
        playground_config::model_reasoning_effort,
    )? {
        mc.reasoning_effort = Some(effort);
    }
    if let Some(key) = load_string_attr(ws, catalog, entry_id, playground_config::model_api_key)? {
        mc.api_key = Some(key);
    }
    if let Some(stream) =
        load_u256_attr(catalog, entry_id, playground_config::model_stream).and_then(u256be_to_u64)
    {
        mc.stream = stream != 0;
    }
    if let Some(tokens) = load_u256_attr(
        catalog,
        entry_id,
        playground_config::model_context_window_tokens,
    )
    .and_then(u256be_to_u64)
    {
        mc.context_window_tokens = tokens;
    }
    if let Some(tokens) =
        load_u256_attr(catalog, entry_id, playground_config::model_max_output_tokens)
            .and_then(u256be_to_u64)
    {
        mc.max_output_tokens = tokens;
    }
    if let Some(tokens) = load_u256_attr(
        catalog,
        entry_id,
        playground_config::model_context_safety_margin_tokens,
    )
    .and_then(u256be_to_u64)
    {
        mc.context_safety_margin_tokens = tokens;
    }
    if let Some(chars) = load_u256_attr(
        catalog,
        entry_id,
        playground_config::model_chars_per_token,
    )
    .and_then(u256be_to_u64)
    {
        mc.chars_per_token = chars;
    }
    let name = load_string_attr(ws, catalog, entry_id, metadata::name)?
        .unwrap_or_else(|| format!("profile-{profile_id:x}"));
    Ok(Some((mc, name)))
}

fn store_config(ws: &mut Workspace<Pile<Blake3>>, config: &Config) -> Result<()> {
    let now = epoch_interval(now_epoch());
    let config_id = ufoid();
    let profile_id = config
        .model_profile_id
        .ok_or_else(|| anyhow!("config missing active model profile id"))?;

    let system_prompt = ws.put(config.system_prompt.clone());
    let branch = ws.put(config.branch.clone());
    let author = ws.put(config.author.clone());
    let author_role = ws.put(config.author_role.clone());
    let poll_ms: Value<U256BE> = config.poll_ms.to_value();

    let mut change = TribleSet::new();
    change += entity! { &config_id @
        metadata::tag: KIND_CONFIG_ID,
        metadata::updated_at: now,
        playground_config::system_prompt: system_prompt,
        playground_config::branch: branch,
        playground_config::author: author,
        playground_config::author_role: author_role,
        playground_config::poll_ms: poll_ms,
        playground_config::active_model_profile_id: profile_id,
    };

    if let Some(id) = config.persona_id {
        change += entity! { &config_id @ playground_config::persona_id: id };
    }
    if let Some(key) = config.tavily_api_key.as_ref() {
        let handle = ws.put(key.clone());
        change += entity! { &config_id @ playground_config::tavily_api_key: handle };
    }
    if let Some(key) = config.exa_api_key.as_ref() {
        let handle = ws.put(key.clone());
        change += entity! { &config_id @ playground_config::exa_api_key: handle };
    }
    if let Some(cwd) = config.exec.default_cwd.as_ref() {
        let handle = ws.put(cwd.to_string_lossy().to_string());
        change += entity! { &config_id @ playground_config::exec_default_cwd: handle };
    }
    if let Some(profile) = config.exec.sandbox_profile {
        change += entity! { &config_id @ playground_config::exec_sandbox_profile: profile };
    }

    let profile_entry_id = ufoid();
    let profile_name = ws.put(config.model_profile_name.clone());
    let model_name_handle = ws.put(config.model.model.clone());
    let model_base_url = ws.put(config.model.base_url.clone());
    let model_stream: Value<U256BE> = if config.model.stream { 1u64 } else { 0u64 }.to_value();
    let model_context_window_tokens: Value<U256BE> = config.model.context_window_tokens.to_value();
    let model_max_output_tokens: Value<U256BE> = config.model.max_output_tokens.to_value();
    let model_context_safety_margin_tokens: Value<U256BE> =
        config.model.context_safety_margin_tokens.to_value();
    let model_chars_per_token: Value<U256BE> = config.model.chars_per_token.to_value();

    change += entity! { &profile_entry_id @
        metadata::tag: KIND_MODEL_PROFILE_ID,
        metadata::updated_at: now,
        playground_config::model_profile_id: profile_id,
        metadata::name: profile_name,
        playground_config::model_name: model_name_handle,
        playground_config::model_base_url: model_base_url,
        playground_config::model_stream: model_stream,
        playground_config::model_context_window_tokens: model_context_window_tokens,
        playground_config::model_max_output_tokens: model_max_output_tokens,
        playground_config::model_context_safety_margin_tokens: model_context_safety_margin_tokens,
        playground_config::model_chars_per_token: model_chars_per_token,
    };

    if let Some(key) = config.model.api_key.as_ref() {
        let handle = ws.put(key.clone());
        change += entity! { &profile_entry_id @ playground_config::model_api_key: handle };
    }
    if let Some(effort) = config.model.reasoning_effort.as_ref() {
        let handle = ws.put(effort.clone());
        change += entity! { &profile_entry_id @ playground_config::model_reasoning_effort: handle };
    }

    ws.commit(change, "playground config");
    Ok(())
}

fn load_string_attr(
    ws: &mut Workspace<Pile<Blake3>>,
    catalog: &TribleSet,
    entity_id: Id,
    attr: Attribute<Handle<Blake3, LongString>>,
) -> Result<Option<String>> {
    let mut handles = find!(
        (handle: Value<Handle<Blake3, LongString>>),
        pattern!(catalog, [{ entity_id @ attr: ?handle }])
    );

    let Some((handle,)) = handles.next() else {
        return Ok(None);
    };
    if handles.next().is_some() {
        let attr_id = attr.id();
        return Err(anyhow!(
            "entity {entity_id:x} has multiple values for attribute {attr_id:x}"
        ));
    }

    let view: View<str> = ws.get(handle).context("read config text")?;
    Ok(Some(view.as_ref().to_string()))
}

fn load_id_attr(catalog: &TribleSet, entity_id: Id, attr: Attribute<GenId>) -> Option<Id> {
    find!(
        value: Id,
        pattern!(catalog, [{ entity_id @ attr: ?value }])
    )
    .next()
}

fn load_u256_attr(
    catalog: &TribleSet,
    entity_id: Id,
    attr: Attribute<U256BE>,
) -> Option<Value<U256BE>> {
    find!(
        value: Value<U256BE>,
        pattern!(catalog, [{ entity_id @ attr: ?value }])
    )
    .next()
}

fn u256be_to_u64(value: Value<U256BE>) -> Option<u64> {
    let raw = value.raw;
    if raw[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    let bytes: [u8; 8] = raw[24..32].try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            default_cwd: Some(PathBuf::from("/workspace")),
            sandbox_profile: None,
        }
    }
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            model: DEFAULT_MODEL.to_string(),
            base_url: DEFAULT_BASE_URL.to_string(),
            api_key: None,
            reasoning_effort: None,
            stream: DEFAULT_STREAM,
            context_window_tokens: DEFAULT_CONTEXT_WINDOW_TOKENS,
            max_output_tokens: DEFAULT_MAX_OUTPUT_TOKENS,
            context_safety_margin_tokens: DEFAULT_CONTEXT_SAFETY_MARGIN_TOKENS,
            chars_per_token: DEFAULT_CHARS_PER_TOKEN,
        }
    }
}

fn default_config(pile_path: PathBuf) -> Config {
    Config {
        pile_path,
        model: ModelConfig::default(),
        model_profile_id: None,
        model_profile_name: "default".to_string(),
        tavily_api_key: None,
        exa_api_key: None,
        exec: ExecConfig::default(),
        system_prompt: DEFAULT_SYSTEM_PROMPT.to_string(),
        branch: DEFAULT_BRANCH.to_string(),
        author: DEFAULT_AUTHOR.to_string(),
        author_role: DEFAULT_AUTHOR_ROLE.to_string(),
        persona_id: None,
        poll_ms: DEFAULT_POLL_MS,
    }
}

fn parse_hex_id(raw: &str, label: &str) -> Result<Id> {
    let raw = raw.trim();
    Id::from_hex(raw).ok_or_else(|| anyhow!("invalid {label} {raw}"))
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

fn parse_bool(raw: &str, label: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(anyhow!("invalid {label} {raw} (expected true/false)")),
    }
}
