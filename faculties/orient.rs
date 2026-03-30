#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! chrono = { version = "0.4.39", features = ["clock"] }
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4.2.3"
//! humantime = "2.1.0"
//! rand_core = "0.6.4"
//! triblespace = "0.31"
//! ```

use anyhow::{Result, anyhow, bail};
use chrono::{
    DateTime, Duration as ChronoDuration, Local, LocalResult, NaiveDateTime, NaiveTime, TimeZone,
};
use clap::{CommandFactory, Parser, Subcommand};
use hifitime::Epoch;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use triblespace::core::blob::schemas::simplearchive::SimpleArchive;
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::{attributes, find, id_hex, pattern};
use triblespace::prelude::*;

const CONFIG_BRANCH_ID: Id = id_hex!("6069A136254E1B87E4C0D2E0295DB382");

const KIND_MESSAGE_ID: Id = id_hex!("A3556A66B00276797FCE8A2742AB850F");
const KIND_READ_ID: Id = id_hex!("B663C15BB6F2BF591EA870386DD48537");
const KIND_PERSON_ID: Id = id_hex!("D8ADDE47121F4E7868017463EC860726");

const KIND_GOAL_ID: Id = id_hex!("83476541420F46402A6A9911F46FBA3B");
const KIND_STATUS_ID: Id = id_hex!("89602B3277495F4E214D4A417C8CF260");
const KIND_ORIENT_CHECKPOINT_ID: Id = id_hex!("163114E5F2272D15F21E1994EF418A31");

type TextHandle = Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>;
type CommitHandle = Value<valueschemas::Handle<valueschemas::Blake3, SimpleArchive>>;
type IntervalValue = Value<valueschemas::NsTAIInterval>;

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.from_value();
    lower.to_tai_duration().total_nanoseconds()
}

mod local {
    use super::*;
    attributes! {
        "42C4DB210F7EAFAF38F179ADCB4A9D5B" as from: valueschemas::GenId;
        "95D58D3E68A43979F8AA51415541414C" as to: valueschemas::GenId;
        "23075866B369B5F393D43B30649469F6" as body: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "5FA453867880877B613B7632A233419B" as created_at: valueschemas::NsTAIInterval;

        "2213B191326E9B99605FA094E516E50E" as about_message: valueschemas::GenId;
        "99E92F483731FA6D59115A8D6D187A37" as reader: valueschemas::GenId;
        "CFEF2E96BC66FF3BE0A39C34E70A5032" as read_at: valueschemas::NsTAIInterval;
    }
}

mod config_schema {
    use super::*;

    attributes! {
        "79F990573A9DCC91EF08A5F8CBA7AA25" as kind: valueschemas::GenId;
        "5E32E36AD28B0B1E035D2DFCC20A3DC5" as updated_at: valueschemas::NsTAIInterval;
        "D1DC11B303725409AB8A30C6B59DB2D7" as persona_id: valueschemas::GenId;
    }
}

const CONFIG_KIND_ID: Id = id_hex!("A8DCBFD625F386AA7CDFD62A81183E82");

mod board {
    use super::*;
    attributes! {
        "EE18CEC15C18438A2FAB670E2E46E00C" as title: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "E915C4D678D0F484B89B4E85E55DB442" as created_at: valueschemas::NsTAIInterval;
        "5FF4941DCC3F6C35E9B3FD57216F69ED" as tag: valueschemas::ShortString;
        "9D2B6EBDA67E9BB6BE6215959D182041" as parent: valueschemas::GenId;

        "C1EAAA039DA7F486E4A54CC87D42E72C" as task: valueschemas::GenId;
        "61C44E0F8A73443ED592A713151E99A4" as status: valueschemas::ShortString;
        "4FB34DB057497FB845B3816521A9A05E" as at: valueschemas::NsTAIInterval;
    }
}

mod orient_state {
    use super::*;
    attributes! {
        "077630536F9D01DBE64320D7044D55A5" as at: valueschemas::NsTAIInterval;
        "6F2D6C7C796B41C2DC7885E7E4D3D750" as local_head: valueschemas::Handle<valueschemas::Blake3, blobschemas::SimpleArchive>;
        "6E6A761126C5101CC69BE185A4B4EC4C" as compass_head: valueschemas::Handle<valueschemas::Blake3, blobschemas::SimpleArchive>;
        "3A58593A230497DEC735E92381C4C522" as relations_head: valueschemas::Handle<valueschemas::Blake3, blobschemas::SimpleArchive>;
        "789078EA4AA95F7B7AD047FF23E04C60" as config_head: valueschemas::Handle<valueschemas::Blake3, blobschemas::SimpleArchive>;
    }
}

#[derive(Parser)]
#[command(
    name = "orient",
    about = "Orient the agent with recent messages and goals"
)]
struct Cli {
    /// Path to the pile file to use
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show an orientation snapshot
    Show {
        /// Max local messages to show
        #[arg(long, default_value_t = 10)]
        message_limit: usize,
        /// Max doing goals to show
        #[arg(long, default_value_t = 5)]
        doing_limit: usize,
        /// Max todo goals to show
        #[arg(long, default_value_t = 5)]
        todo_limit: usize,
    },
    /// Wait until relevant branches change, then show orientation
    Wait {
        #[command(subcommand)]
        target: Option<WaitTarget>,
        /// Max local messages to show
        #[arg(long, default_value_t = 10)]
        message_limit: usize,
        /// Max doing goals to show
        #[arg(long, default_value_t = 5)]
        doing_limit: usize,
        /// Max todo goals to show
        #[arg(long, default_value_t = 5)]
        todo_limit: usize,
        /// Poll interval while waiting for branch changes
        #[arg(long, default_value_t = 1000)]
        poll_ms: u64,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum WaitTarget {
    /// Wait for a duration (e.g. 30s, 15m, 9h)
    For {
        /// Duration to wait
        duration: String,
    },
    /// Wait until a specific time (e.g. 09:00, 9am, or 2026-02-13T09:00:00+01:00)
    Until {
        /// Time to wake up
        when: String,
    },
}

#[derive(Debug, Clone)]
struct MessageRow {
    id: Id,
    from: Id,
    to: Id,
    created_at: i128,
}


#[derive(Debug, Clone, Default)]
struct ConfigIdentity {
    persona_id: Option<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchedHeads {
    local: Option<CommitHandle>,
    compass: Option<CommitHandle>,
    relations: Option<CommitHandle>,
    config: Option<CommitHandle>,
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> Value<valueschemas::NsTAIInterval> {
    (epoch, epoch).to_value()
}

fn interval_key(interval: Value<valueschemas::NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.from_value();
    lower.to_tai_duration().total_nanoseconds()
}

fn format_age(now_key: i128, past_key: i128) -> String {
    let delta_ns = now_key.saturating_sub(past_key);
    let delta_s = (delta_ns / 1_000_000_000).max(0) as i64;
    if delta_s < 60 {
        format!("{delta_s}s")
    } else if delta_s < 60 * 60 {
        format!("{}m", delta_s / 60)
    } else if delta_s < 60 * 60 * 24 {
        format!("{}h", delta_s / (60 * 60))
    } else {
        format!("{}d", delta_s / (60 * 60 * 24))
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn person_label(ws: &mut Workspace<Pile<valueschemas::Blake3>>, space: &TribleSet, person_id: Id) -> String {
    find!(h: TextHandle, pattern!(space, [{ person_id @ metadata::name: ?h }]))
        .next()
        .and_then(|h| read_text(ws, h).ok())
        .unwrap_or_else(|| fmt_id(person_id))
}

fn read_text(ws: &mut Workspace<Pile<valueschemas::Blake3>>, handle: TextHandle) -> Result<String> {
    let view: View<str> = ws
        .get::<View<str>, blobschemas::LongString>(handle)
        .map_err(|e| anyhow!("load longstring: {e:?}"))?;
    Ok(view.to_string())
}

/// Load messages without resolving body blobs — sorted newest first.
fn load_message_ids(space: &TribleSet) -> Vec<MessageRow> {
    let mut messages: Vec<MessageRow> = find!(
        (message_id: Id, from: Id, to: Id, created_at: Value<valueschemas::NsTAIInterval>),
        pattern!(space, [{
            ?message_id @
            metadata::tag: &KIND_MESSAGE_ID,
            local::from: ?from,
            local::to: ?to,
            local::created_at: ?created_at,
        }])
    )
    .map(|(id, from, to, created_at)| MessageRow {
        id, from, to, created_at: interval_key(created_at),
    })
    .collect();
    messages.sort_by_key(|msg| std::cmp::Reverse(msg.created_at));
    messages
}

fn resolve_message_body(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    space: &TribleSet,
    msg_id: Id,
) -> String {
    find!(h: TextHandle, pattern!(space, [{ msg_id @ local::body: ?h }]))
        .next()
        .and_then(|h| read_text(ws, h).ok())
        .unwrap_or_default()
}

fn load_reads(space: &TribleSet) -> HashMap<(Id, Id), i128> {
    let mut reads = HashMap::new();
    for (_read_id, message_id, reader_id, read_at) in find!(
        (
            read_id: Id,
            message_id: Id,
            reader_id: Id,
            read_at: Value<valueschemas::NsTAIInterval>
        ),
        pattern!(&space, [{
            ?read_id @
            metadata::tag: &KIND_READ_ID,
            local::about_message: ?message_id,
            local::reader: ?reader_id,
            local::read_at: ?read_at,
        }])
    ) {
        let key = (message_id, reader_id);
        let ts = interval_key(read_at);
        reads
            .entry(key)
            .and_modify(|existing| {
                if ts > *existing {
                    *existing = ts;
                }
            })
            .or_insert(ts);
    }
    reads
}

fn task_title(ws: &mut Workspace<Pile<valueschemas::Blake3>>, space: &TribleSet, task_id: Id) -> String {
    find!(h: TextHandle, pattern!(space, [{ task_id @ board::title: ?h }]))
        .next()
        .and_then(|h| read_text(ws, h).ok())
        .unwrap_or_default()
}

fn task_tags(space: &TribleSet, task_id: Id) -> Vec<String> {
    let mut tags: Vec<String> = find!(
        tag: String,
        pattern!(space, [{ task_id @ metadata::tag: &KIND_GOAL_ID, board::tag: ?tag }])
    ).collect();
    tags.sort();
    tags.dedup();
    tags
}

fn task_latest_status(space: &TribleSet, task_id: Id) -> Option<(String, IntervalValue)> {
    find!(
        (status: String, at: IntervalValue),
        pattern!(space, [{
            _?evt @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &task_id,
            board::status: ?status,
            board::at: ?at,
        }])
    )
    .max_by(|a, b| interval_key(a.1).cmp(&interval_key(b.1)))
}

fn load_config_identity(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
) -> Result<ConfigIdentity> {
    let Some(_config_head) = repo
        .storage_mut()
        .head(CONFIG_BRANCH_ID)
        .map_err(|e| anyhow!("config branch head: {e:?}"))?
    else {
        return Ok(ConfigIdentity::default());
    };
    let mut ws = repo
        .pull(CONFIG_BRANCH_ID)
        .map_err(|e| anyhow!("pull config workspace: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout config: {e:?}"))?;

    let mut latest: Option<(Id, Value<valueschemas::NsTAIInterval>)> = None;
    for (config_id, updated_at) in find!(
        (config_id: Id, updated_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            ?config_id @
            metadata::tag: &CONFIG_KIND_ID,
            config_schema::updated_at: ?updated_at,
        }])
    ) {
        let key = interval_key(updated_at);
        match latest {
            Some((_, current)) if interval_key(current) >= key => {}
            _ => latest = Some((config_id, updated_at)),
        }
    }

    let Some((config_id, _)) = latest else {
        return Ok(ConfigIdentity::default());
    };

    let persona_id = find!(
        value: Id,
        pattern!(&space, [{ config_id @ config_schema::persona_id: ?value }])
    )
    .next();

    Ok(ConfigIdentity {
        persona_id,
    })
}

fn cmd_show(pile: &Path, message_limit: usize, doing_limit: usize, todo_limit: usize) -> Result<()> {
    with_repo(pile, |repo| {
        let config_identity = load_config_identity(repo)?;
        let compass_branch_id = repo.ensure_branch("compass", None)
            .map_err(|e| anyhow::anyhow!("ensure compass branch: {e:?}"))?;
        let local_branch_id = repo.ensure_branch("local-messages", None)
            .map_err(|e| anyhow::anyhow!("ensure local-messages branch: {e:?}"))?;
        let relations_branch_id = repo.ensure_branch("relations", None)
            .map_err(|e| anyhow::anyhow!("ensure relations branch: {e:?}"))?;
        let orient_state_branch_id = repo.ensure_branch("orient-state", None)
            .map_err(|e| anyhow::anyhow!("ensure orient-state branch: {e:?}"))?;
        let current_heads =
            load_watched_heads(repo, local_branch_id, compass_branch_id, relations_branch_id)?;

        let mut local_ws = repo
            .pull(local_branch_id)
            .map_err(|e| anyhow!("pull local workspace: {e:?}"))?;
        let local_space = local_ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout local: {e:?}"))?;
        let reader_id = config_identity.persona_id.ok_or_else(|| {
            anyhow!(
                "missing persona_id in config (set via `playground config set persona-id <hex-id>`)"
            )
        })?;
        let mut relations_ws = repo
            .pull(relations_branch_id)
            .map_err(|e| anyhow!("pull relations workspace: {e:?}"))?;
        let relations_space = relations_ws.checkout(..).map_err(|e| anyhow!("checkout relations: {e:?}"))?;

        // Verify persona exists in relations.
        let reader_exists = find!(
            _id: Id,
            pattern!(&relations_space, [{ reader_id @ metadata::tag: &KIND_PERSON_ID }])
        ).next().is_some();
        if !reader_exists {
            bail!(
                "persona_id {:x} missing from relations (add via relations faculty)",
                reader_id
            );
        }

        let reads = load_reads(&local_space);
        let all_messages = load_message_ids(&local_space);

        let unread: Vec<&MessageRow> = all_messages
            .iter()
            .filter(|msg| msg.to == reader_id && !reads.contains_key(&(msg.id, reader_id)))
            .take(message_limit)
            .collect();

        let now_key = interval_key(epoch_interval(now_epoch()));

        println!("Orient");
        let reader_label = person_label(&mut relations_ws, &relations_space, reader_id);
        println!("Local messages (unread inbox for {}):", reader_label);
        if unread.is_empty() {
            println!("- None");
        } else {
            for msg in &unread {
                let from_label = person_label(&mut relations_ws, &relations_space, msg.from);
                let to_label = person_label(&mut relations_ws, &relations_space, msg.to);
                let age = format_age(now_key, msg.created_at);
                println!(
                    "- [{}] {} {} -> {} ({})",
                    fmt_id(msg.id),
                    age,
                    from_label,
                    to_label,
                    "unread",
                );
                // Resolve body lazily — only for displayed messages.
                let body = resolve_message_body(&mut local_ws, &local_space, msg.id);
                if body.is_empty() {
                    println!("    ");
                } else {
                    for line in body.lines() {
                        println!("    {}", line.trim_end_matches('\r'));
                    }
                }
            }
        }

        drop(local_ws);

        let mut compass_ws = repo
            .pull(compass_branch_id)
            .map_err(|e| anyhow!("pull compass workspace: {e:?}"))?;
        let compass_space = compass_ws.checkout(..).map_err(|e| anyhow!("checkout compass: {e:?}"))?;

        let mut doing: Vec<(i128, Id)> = Vec::new();
        let mut todo: Vec<(i128, Id)> = Vec::new();
        for task_id in find!(id: Id, pattern!(&compass_space, [{ ?id @ metadata::tag: &KIND_GOAL_ID }])) {
            let (status, status_at) = task_latest_status(&compass_space, task_id)
                .map(|(s, at)| (s.to_lowercase(), Some(interval_key(at))))
                .unwrap_or_else(|| ("todo".to_string(), None));
            let created_key: i128 = find!(s: IntervalValue, pattern!(&compass_space, [{ task_id @ board::created_at: ?s }]))
                .next().map(interval_key).unwrap_or(0);
            let sort_key = status_at.unwrap_or(created_key);
            if status == "doing" {
                doing.push((sort_key, task_id));
            } else if status == "todo" {
                todo.push((sort_key, task_id));
            }
        }

        doing.sort_by(|a, b| b.0.cmp(&a.0));
        todo.sort_by(|a, b| b.0.cmp(&a.0));

        println!();
        println!("Compass:");
        if doing.is_empty() && todo.is_empty() {
            println!("- No goals.");
        } else {
            println!("Doing:");
            if doing.is_empty() {
                println!("- None");
            } else {
                for (_key, task_id) in doing.into_iter().take(doing_limit) {
                    let title = task_title(&mut compass_ws, &compass_space, task_id);
                    let tag_suffix = render_tags(&task_tags(&compass_space, task_id));
                    println!("- [{}] {}{}", fmt_id(task_id), title, tag_suffix);
                }
            }
            println!("Todo:");
            if todo.is_empty() {
                println!("- None");
            } else {
                for (_key, task_id) in todo.into_iter().take(todo_limit) {
                    let title = task_title(&mut compass_ws, &compass_space, task_id);
                    let tag_suffix = render_tags(&task_tags(&compass_space, task_id));
                    println!("- [{}] {}{}", fmt_id(task_id), title, tag_suffix);
                }
            }
        }

        drop(compass_ws);
        save_checkpoint_heads(repo, orient_state_branch_id, &current_heads)?;
        Ok(())
    })
}

fn load_watched_heads(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    local_branch_id: Id,
    compass_branch_id: Id,
    relations_branch_id: Id,
) -> Result<WatchedHeads> {
    Ok(WatchedHeads {
        local: branch_head_by_id(repo, local_branch_id)?,
        compass: branch_head_by_id(repo, compass_branch_id)?,
        relations: branch_head_by_id(repo, relations_branch_id)?,
        config: branch_head_by_id(repo, CONFIG_BRANCH_ID)?,
    })
}

fn load_checkpoint_heads(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    orient_state_branch_id: Id,
) -> Result<Option<WatchedHeads>> {
    let Some(_head) = repo
        .storage_mut()
        .head(orient_state_branch_id)
        .map_err(|e| anyhow!("orient state branch head: {e:?}"))?
    else {
        return Ok(None);
    };
    let mut ws = repo
        .pull(orient_state_branch_id)
        .map_err(|e| anyhow!("pull orient state workspace: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout orient state: {e:?}"))?;

    let mut latest: Option<(Id, i128)> = None;
    for (checkpoint_id, at) in find!(
        (checkpoint_id: Id, at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            ?checkpoint_id @
            metadata::tag: &KIND_ORIENT_CHECKPOINT_ID,
            orient_state::at: ?at,
        }])
    ) {
        let key = interval_key(at);
        if latest.is_none_or(|(_, current)| key > current) {
            latest = Some((checkpoint_id, key));
        }
    }

    let Some((checkpoint_id, _)) = latest else {
        return Ok(None);
    };

    Ok(Some(WatchedHeads {
        local: load_optional_commit_head(&space, checkpoint_id, orient_state::local_head),
        compass: load_optional_commit_head(&space, checkpoint_id, orient_state::compass_head),
        relations: load_optional_commit_head(&space, checkpoint_id, orient_state::relations_head),
        config: load_optional_commit_head(&space, checkpoint_id, orient_state::config_head),
    }))
}

fn load_optional_commit_head(
    space: &TribleSet,
    checkpoint_id: Id,
    attr: Attribute<valueschemas::Handle<valueschemas::Blake3, blobschemas::SimpleArchive>>,
) -> Option<CommitHandle> {
    find!(
        value: CommitHandle,
        pattern!(space, [{ checkpoint_id @ attr: ?value }])
    )
    .next()
}

fn save_checkpoint_heads(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    orient_state_branch_id: Id,
    heads: &WatchedHeads,
) -> Result<()> {
    let mut ws = repo
        .pull(orient_state_branch_id)
        .map_err(|e| anyhow!("pull orient state workspace: {e:?}"))?;

    let checkpoint_id = ufoid();
    let now = epoch_interval(now_epoch());
    let change = entity! { &checkpoint_id @
        metadata::tag: &KIND_ORIENT_CHECKPOINT_ID,
        orient_state::at: now,
        orient_state::local_head?: heads.local,
        orient_state::compass_head?: heads.compass,
        orient_state::relations_head?: heads.relations,
        orient_state::config_head?: heads.config,
    };

    ws.commit(change, "orient checkpoint");
    repo.push(&mut ws)
        .map_err(|e| anyhow!("push orient checkpoint: {e:?}"))?;
    Ok(())
}

fn branch_head_by_id(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    branch_id: Id,
) -> Result<Option<CommitHandle>> {
    repo.storage_mut()
        .head(branch_id)
        .map_err(|e| anyhow!("branch head {:x}: {e:?}", branch_id))
}

fn parse_wait_target(target: Option<&WaitTarget>) -> Result<Option<Duration>> {
    let Some(target) = target else {
        return Ok(None);
    };
    match target {
        WaitTarget::For { duration } => {
            let duration = duration.trim();
            if duration.is_empty() {
                bail!("wait for requires a duration (e.g. 30s, 15m, 9h)");
            }
            let parsed = humantime::parse_duration(duration)
                .map_err(|e| anyhow!("invalid wait duration '{duration}': {e}"))?;
            if parsed.is_zero() {
                bail!("wait duration must be greater than zero");
            }
            Ok(Some(parsed))
        }
        WaitTarget::Until { when } => {
            let (parsed, _) = parse_until_spec(when)?;
            Ok(Some(parsed))
        }
    }
}

fn parse_until_spec(raw: &str) -> Result<(Duration, DateTime<Local>)> {
    let when = raw.trim();
    if when.is_empty() {
        bail!("wait until requires a time (e.g. 09:00, 9am, 2026-02-13T09:00:00+01:00)");
    }

    if let Ok(system_time) = humantime::parse_rfc3339_weak(when) {
        let target_local = DateTime::<Local>::from(system_time);
        let timeout = system_time
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        return Ok((timeout, target_local));
    }

    if let Some(local_datetime) = parse_local_datetime_spec(when)? {
        let timeout = chrono_duration_to_std(local_datetime.signed_duration_since(Local::now()));
        return Ok((timeout, local_datetime));
    }

    if let Some(local_time) = parse_local_time_spec(when) {
        let now = Local::now();
        let mut target_naive = now.date_naive().and_time(local_time);
        let mut target_local = localize_naive_datetime(target_naive)?;
        if target_local <= now {
            target_naive += ChronoDuration::days(1);
            target_local = localize_naive_datetime(target_naive)?;
        }
        let timeout = chrono_duration_to_std(target_local.signed_duration_since(now));
        return Ok((timeout, target_local));
    }

    bail!(
        "invalid wait until value '{when}'. Use HH:MM, 9am, local datetime, or RFC3339 timestamp"
    );
}

fn parse_local_datetime_spec(raw: &str) -> Result<Option<DateTime<Local>>> {
    for fmt in [
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(raw, fmt) {
            return Ok(Some(localize_naive_datetime(naive)?));
        }
    }
    Ok(None)
}

fn parse_local_time_spec(raw: &str) -> Option<NaiveTime> {
    for fmt in [
        "%H:%M", "%H:%M:%S", "%I:%M %P", "%I:%M%P", "%I %P", "%I%P", "%I:%M %p", "%I:%M%p",
        "%I %p", "%I%p",
    ] {
        if let Ok(time) = NaiveTime::parse_from_str(raw, fmt) {
            return Some(time);
        }
    }
    None
}

fn localize_naive_datetime(naive: NaiveDateTime) -> Result<DateTime<Local>> {
    match Local.from_local_datetime(&naive) {
        LocalResult::Single(dt) => Ok(dt),
        LocalResult::Ambiguous(a, b) => Ok(if a <= b { a } else { b }),
        LocalResult::None => bail!(
            "local time '{}' does not exist (likely DST transition)",
            naive.format("%Y-%m-%d %H:%M:%S")
        ),
    }
}

fn chrono_duration_to_std(duration: ChronoDuration) -> Duration {
    if duration <= ChronoDuration::zero() {
        Duration::ZERO
    } else {
        duration.to_std().unwrap_or(Duration::MAX)
    }
}

fn cmd_wait(
    pile: &Path,
    target: Option<WaitTarget>,
    message_limit: usize,
    doing_limit: usize,
    todo_limit: usize,
    poll_ms: u64,
) -> Result<()> {
    let timeout = parse_wait_target(target.as_ref())?;
    let (detected_change_before_wait, changed) = with_repo(pile, |repo| {
        let compass_branch_id = repo.ensure_branch("compass", None)
            .map_err(|e| anyhow::anyhow!("ensure compass branch: {e:?}"))?;
        let local_branch_id = repo.ensure_branch("local-messages", None)
            .map_err(|e| anyhow::anyhow!("ensure local-messages branch: {e:?}"))?;
        let relations_branch_id = repo.ensure_branch("relations", None)
            .map_err(|e| anyhow::anyhow!("ensure relations branch: {e:?}"))?;
        let orient_state_branch_id = repo.ensure_branch("orient-state", None)
            .map_err(|e| anyhow::anyhow!("ensure orient-state branch: {e:?}"))?;

        let mut detected_change_before_wait = false;
        let baseline = load_watched_heads(repo, local_branch_id, compass_branch_id, relations_branch_id)?;
        if let Some(last_seen) = load_checkpoint_heads(repo, orient_state_branch_id)? {
            if baseline != last_seen {
                detected_change_before_wait = true;
                return Ok((detected_change_before_wait, true));
            }
        }

        let poll = Duration::from_millis(poll_ms.max(1));
        let start = Instant::now();

        loop {
            if let Some(timeout) = timeout {
                if start.elapsed() >= timeout {
                    return Ok((detected_change_before_wait, false));
                }
            }
            std::thread::sleep(poll);
            let current = load_watched_heads(repo, local_branch_id, compass_branch_id, relations_branch_id)?;
            if current != baseline {
                return Ok((detected_change_before_wait, true));
            }
        }
    })?;
    if detected_change_before_wait {
        println!("Detected branch changes since last orientation snapshot; returning immediately.");
    }
    if !changed {
        println!("No change detected since wait started; showing current snapshot.");
    }
    cmd_show(
        pile,
        message_limit,
        doing_limit,
        todo_limit,
    )
}

fn render_tags(tags: &[String]) -> String {
    if tags.is_empty() {
        return String::new();
    }
    let mut sorted = tags.to_vec();
    sorted.sort();
    sorted.dedup();
    format!(
        " {}",
        sorted
            .iter()
            .map(|tag| {
                if tag.starts_with('#') {
                    tag.to_string()
                } else {
                    format!("#{}", tag)
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn open_repo(path: &Path) -> Result<Repository<Pile<valueschemas::Blake3>>> {
    let mut pile = Pile::<valueschemas::Blake3>::open(path)
        .map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        // Avoid Drop warnings on early errors.
        let _ = pile.close();
        return Err(anyhow!("restore pile {}: {err:?}", path.display()));
    }
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(cmd) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };
    match cmd {
        Command::Show {
            message_limit,
            doing_limit,
            todo_limit,
        } => cmd_show(&cli.pile, message_limit, doing_limit, todo_limit),
        Command::Wait {
            target,
            message_limit,
            doing_limit,
            todo_limit,
            poll_ms,
        } => cmd_wait(
            &cli.pile,
            target,
            message_limit,
            doing_limit,
            todo_limit,
            poll_ms,
        ),
    }
}
