#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4.2.3"
//! humantime = "2.3.0"
//! rand_core = "0.6.4"
//! triblespace = "0.29"
//! ```

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use humantime::parse_duration;
use rand_core::OsRng;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use triblespace::core::metadata;
use triblespace::core::repo::Repository;
use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::*;

const DEFAULT_BRANCH: &str = "cognition";
const KIND_TIMEOUT_EXTENSION_ID: Id = id_hex!("75BC66A1C39131B9A0975613AC9B59FD");

mod exec_schema {
    use super::*;

    attributes! {
        "AA2F34973589295FA70B538D92CD30F8" as kind: valueschemas::GenId;
        "C4C3870642CAB5F55E7E575B1A62E640" as about_request: valueschemas::GenId;
        "442A275ABC6834231FC65A4B89773ECD" as worker: valueschemas::GenId;
        "7FFF32386EBB2AE92094B7D88DE2743D" as timeout_ms: valueschemas::U256BE;
        "D8910A14B31096DF94DE9E807B87645F" as requested_at: valueschemas::NsTAIInterval;
    }
}

#[derive(Parser)]
#[command(
    name = "patience",
    about = "Extend the active turn timeout and optionally run a command"
)]
struct Cli {
    /// Path to the pile file.
    #[arg(long)]
    pile: Option<PathBuf>,
    /// Target branch name for timeout extension events.
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    /// Target branch id for timeout extension events (hex). Overrides ensure_branch.
    #[arg(long)]
    branch_id: Option<String>,
    /// Turn id to annotate (hex). Defaults to $TURN_ID.
    #[arg(long)]
    turn_id: Option<String>,
    /// Worker id to annotate (hex). Defaults to $WORKER_ID.
    #[arg(long)]
    worker_id: Option<String>,
    /// Timeout extension duration (e.g. 5m, 90s, 1h).
    #[arg(value_name = "DURATION")]
    duration: Option<String>,
    /// Optional command to run after extending timeout (pass after `--`).
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

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
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

fn parse_timeout_ms(raw: &str) -> Result<u64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("duration is empty");
    }
    if let Ok(ms) = trimmed.parse::<u64>() {
        return Ok(ms);
    }
    let duration = parse_duration(trimmed).with_context(|| format!("invalid duration '{trimmed}'"))?;
    let millis = duration.as_millis();
    if millis == 0 {
        bail!("duration must be greater than zero");
    }
    if millis > u128::from(u64::MAX) {
        bail!("duration exceeds maximum supported timeout");
    }
    Ok(millis as u64)
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

fn append_timeout_extension(
    pile: &Path,
    branch_id: Id,
    request_id: Id,
    worker_id: Id,
    timeout_ms: u64,
) -> Result<Id> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;

        let event_id = ufoid();
        let now = epoch_interval(now_epoch());
        let change = entity! { &event_id @
            metadata::tag: KIND_TIMEOUT_EXTENSION_ID,
            exec_schema::about_request: request_id,
            exec_schema::worker: worker_id,
            exec_schema::timeout_ms: timeout_ms,
            exec_schema::requested_at: now,
        };
        ws.commit(change, "playground_exec timeout_extension");
        repo.push(&mut ws)
            .map_err(|e| anyhow!("push timeout extension: {e:?}"))?;
        Ok(*event_id)
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
    let Some(duration_raw) = cli.duration.as_ref() else {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        return Ok(());
    };

    let timeout_ms = parse_timeout_ms(duration_raw)?;
    let env_turn_id = std::env::var("TURN_ID").ok();
    let env_worker_id = std::env::var("WORKER_ID").ok();

    let branch_id = with_repo(&pile_path, |repo| {
        resolve_branch_id(repo, cli.branch_id.as_deref(), &cli.branch)
    })?;

    let request_id = parse_optional_hex_id(
        cli.turn_id.as_deref().or(env_turn_id.as_deref()),
        "turn id",
    )?
    .ok_or_else(|| anyhow!("missing turn id (pass --turn-id or set TURN_ID)"))?;
    let worker_id = parse_optional_hex_id(
        cli.worker_id.as_deref().or(env_worker_id.as_deref()),
        "worker id",
    )?
    .ok_or_else(|| anyhow!("missing worker id (pass --worker-id or set WORKER_ID)"))?;

    let event_id = append_timeout_extension(
        &pile_path,
        branch_id,
        request_id,
        worker_id,
        timeout_ms,
    )?;

    eprintln!(
        "[{}] timeout extended by {} ms",
        fmt_id(event_id),
        timeout_ms
    );

    if cli.command.is_empty() {
        return Ok(());
    }

    let exit_code = run_command(&cli.command)?;
    std::process::exit(exit_code);
}
