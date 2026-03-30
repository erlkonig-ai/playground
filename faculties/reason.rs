#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4.2.3"
//! rand_core = "0.6.4"
//! triblespace = "0.29"
//! ```

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use rand_core::OsRng;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use triblespace::core::metadata;
use triblespace::core::repo::Repository;
use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

const DEFAULT_BRANCH: &str = "cognition";
const KIND_REASON_ID: Id = id_hex!("9D43BB36D8B4A6275CAF38A1D5DACF36");

mod reason_schema {
    use super::*;

    attributes! {
        "B10329D5D1087D15A3DAFF7A7CC50696" as text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "79C9CB4C48864D28B215D4264E1037BF" as created_at: valueschemas::NsTAIInterval;
        "E6B1C728F1AE9F46CAB4DBB60D1A9528" as about_turn: valueschemas::GenId;
        "721DED6DA776F2CF4FB91C54D9F82358" as worker: valueschemas::GenId;
        "514F4FE9F560FB155450462C8CF50749" as command_text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
    }
}

#[derive(Parser)]
#[command(
    name = "reason",
    about = "Record explicit reasoning notes linked to the current execution turn"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long)]
    pile: Option<PathBuf>,
    /// Target branch name for reason events.
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    /// Target branch id for reason events (hex). Overrides ensure_branch.
    #[arg(long)]
    branch_id: Option<String>,
    /// Turn id to annotate (hex). Defaults to $TURN_ID.
    #[arg(long)]
    turn_id: Option<String>,
    /// Worker id to annotate (hex). Defaults to $WORKER_ID.
    #[arg(long)]
    worker_id: Option<String>,
    /// Free-form reasoning text.
    #[arg(value_name = "TEXT", help = "Free-form reasoning text. Use @path for file input or @- for stdin.")]
    text: Option<String>,
    /// Optional command to run after logging the reason (pass after `--`).
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        allow_hyphen_values = true,
        last = true
    )]
    command: Vec<String>,
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> Value<valueschemas::NsTAIInterval> {
    (epoch, epoch).to_value()
}

fn resolve_pile_path(cli: &Cli) -> PathBuf {
    cli.pile
        .clone()
        .or_else(|| std::env::var("PILE").ok().map(PathBuf::from))
        .expect("--pile argument or PILE env var required")
}

fn parse_optional_hex_id(raw: Option<&str>, label: &str) -> Result<Option<Id>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("{label} is empty");
    }
    let Some(id) = Id::from_hex(trimmed) else {
        bail!("invalid {label} '{trimmed}'");
    };
    Ok(Some(id))
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
        return fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

fn open_repo(path: &Path) -> Result<Repository<Pile<valueschemas::Blake3>>> {
    let mut pile = Pile::<valueschemas::Blake3>::open(path)
        .map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        let _ = pile.close();
        return Err(anyhow!("restore pile {}: {err:?}", path.display()));
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(
    pile: &Path,
    f: impl FnOnce(&mut Repository<Pile<valueschemas::Blake3>>) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close_res = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

fn resolve_branch_id(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    explicit_hex: Option<&str>,
    branch_name: &str,
) -> Result<Id> {
    if let Some(hex) = explicit_hex {
        return Id::from_hex(hex.trim())
            .ok_or_else(|| anyhow!("invalid branch id '{hex}'"));
    }
    if let Ok(hex) = std::env::var("TRIBLESPACE_BRANCH_ID") {
        return Id::from_hex(hex.trim())
            .ok_or_else(|| anyhow!("invalid TRIBLESPACE_BRANCH_ID"));
    }
    repo.ensure_branch(branch_name, None)
        .map_err(|e| anyhow!("ensure {branch_name} branch: {e:?}"))
}

fn append_reason(
    pile: &Path,
    branch_id: Id,
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    text: &str,
    command_text: Option<&str>,
) -> Result<Id> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;

        let reason_id = ufoid();
        let now = epoch_interval(now_epoch());
        let text_handle = ws.put(text.to_string());
        let command_handle = command_text.map(|cmd| ws.put(cmd.to_string()));
        let change = entity! { &reason_id @
            metadata::tag: &KIND_REASON_ID,
            reason_schema::text: text_handle,
            reason_schema::created_at: now,
            reason_schema::about_turn?: turn_id,
            reason_schema::worker?: worker_id,
            reason_schema::command_text?: command_handle,
        };
        ws.commit(change, "reason");
        repo.push(&mut ws)
            .map_err(|e| anyhow!("push reason: {e:?}"))?;
        Ok(*reason_id)
    })
}

fn shell_quote(word: &str) -> String {
    if word
        .chars()
        .all(|ch| {
            ch.is_ascii_alphanumeric() || std::matches!(ch, '_' | '-' | '.' | '/' | ':' | '=')
        })
    {
        return word.to_string();
    }
    format!("'{}'", word.replace('\'', "'\\''"))
}

fn render_command(command: &[String]) -> String {
    command
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_command(command: &[String]) -> Result<i32> {
    let Some(bin) = command.first() else {
        bail!("missing command");
    };
    let status = ProcessCommand::new(bin)
        .args(command.iter().skip(1))
        .status()
        .with_context(|| format!("run command `{}`", render_command(command)))?;
    Ok(status.code().unwrap_or(1))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let pile_path = resolve_pile_path(&cli);

    let Some(text_raw) = cli.text.as_ref() else {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        return Ok(());
    };
    let text = load_value_or_file(text_raw, "reason text")?;

    let env_turn_id = std::env::var("TURN_ID").ok();
    let env_worker_id = std::env::var("WORKER_ID").ok();

    let branch_id = with_repo(&pile_path, |repo| {
        resolve_branch_id(repo, cli.branch_id.as_deref(), &cli.branch)
    })?;

    let turn_id = parse_optional_hex_id(cli.turn_id.as_deref().or(env_turn_id.as_deref()), "turn id")?;
    let worker_id =
        parse_optional_hex_id(cli.worker_id.as_deref().or(env_worker_id.as_deref()), "worker id")?;

    if text.trim().is_empty() {
        bail!("reason text is empty");
    }

    if cli.command.is_empty() {
        let reason_id = append_reason(
            &pile_path,
            branch_id,
            turn_id,
            worker_id,
            &text,
            None,
        )?;
        println!("reason_id: {reason_id:x}");
        return Ok(());
    }

    let command_text = render_command(&cli.command);
    let reason_id = append_reason(
        &pile_path,
        branch_id,
        turn_id,
        worker_id,
        &text,
        None,
    )?;
    let action_event_id = append_reason(
        &pile_path,
        branch_id,
        turn_id,
        worker_id,
        command_text.as_str(),
        Some(command_text.as_str()),
    )?;
    eprintln!("reason_id: {reason_id:x}");
    eprintln!("reason_action_id: {action_event_id:x}");
    let exit_code = run_command(&cli.command)?;
    std::process::exit(exit_code);
}
