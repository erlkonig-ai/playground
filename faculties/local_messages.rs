#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4.2.3"
//! rand_core = "0.6.4"
//! triblespace = "0.32"
//! ```

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::{attributes, find, id_hex, pattern};
use triblespace::prelude::*;

const DEFAULT_BRANCH: &str = "local-messages";
const DEFAULT_RELATIONS_BRANCH: &str = "relations";

const KIND_MESSAGE_LABEL: &str = "local_message";
const KIND_READ_LABEL: &str = "local_read";

const KIND_MESSAGE_ID: Id = id_hex!("A3556A66B00276797FCE8A2742AB850F");
const KIND_READ_ID: Id = id_hex!("B663C15BB6F2BF591EA870386DD48537");

const KIND_PERSON_ID: Id = id_hex!("D8ADDE47121F4E7868017463EC860726");

const KIND_SPECS: [(Id, &str); 2] = [
    (KIND_MESSAGE_ID, KIND_MESSAGE_LABEL),
    (KIND_READ_ID, KIND_READ_LABEL),
];

type TextHandle = Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>;

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

mod relations_schema {
    use super::*;
    attributes! {
        "299E28A10114DC8C3B1661CD90CB8DF6" as label_norm: valueschemas::ShortString;
        "3E8812F6D22B2C93E2BCF0CE3C8C1979" as alias_norm: valueschemas::ShortString;
    }
}

fn normalize_label(label: &str) -> Result<String> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        bail!("label is empty");
    }
    Ok(trimmed.to_string())
}

fn normalize_lookup_key(label: &str) -> Result<String> {
    Ok(normalize_label(label)?.to_ascii_lowercase())
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

#[derive(Parser)]
#[command(
    name = "local-messages",
    about = "Local messaging faculty for the agent"
)]
struct Cli {
    /// Path to the pile file to use
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name for local messages
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    /// Explicit branch id for local messages (hex). Overrides name-based lookup.
    #[arg(long)]
    branch_id: Option<String>,
    /// Branch name for relations
    #[arg(long, default_value = DEFAULT_RELATIONS_BRANCH)]
    relations_branch: String,
    /// Explicit branch id for relations (hex). Overrides name-based lookup.
    #[arg(long)]
    relations_branch_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Send a message
    Send {
        /// Sender label.
        from: String,
        /// Receiver label.
        to: String,
        /// Message text.
        #[arg(value_name = "TEXT", help = "Message text. Use @path for file input or @- for stdin.")]
        text: String,
    },
    /// List recent messages (latest first)
    List {
        /// Reader id or label.
        reader: String,
        /// Only show inbox messages unread by the reader.
        #[arg(long)]
        unread: bool,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Mark a message as read
    Ack {
        id: String,
        /// Reader id or label.
        by: String,
    },
}

#[derive(Debug, Clone)]
struct MessageRow {
    id: Id,
    from: Id,
    to: Id,
    body: String,
    created_at: i128,
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> Value<valueschemas::NsTAIInterval> {
    (epoch, epoch).try_to_value().unwrap()
}

fn interval_key(interval: Value<valueschemas::NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_value().unwrap();
    lower.to_tai_duration().total_nanoseconds()
}

fn format_age(now_key: i128, past_key: i128) -> String {
    let delta_ns = now_key.saturating_sub(past_key);
    let delta_s = (delta_ns / 1_000_000_000).max(0) as i64;
    if delta_s < 60 {
        format!("{delta_s}s")
    } else if delta_s < 60 * 60 {
        format!("{}m", delta_s / 60)
    } else if delta_s < 24 * 60 * 60 {
        format!("{}h", delta_s / 3600)
    } else {
        format!("{}d", delta_s / 86_400)
    }
}

fn truncate_single_line(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(max);
    for ch in text.chars() {
        if out.len() >= max {
            out.push_str("...");
            break;
        }
        if ch == '\n' || ch == '\r' {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

fn render_list_body(text: &str) -> String {
    text.replace('\r', "").replace('\n', "\\n")
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn load_relations(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    relations_branch_id: Id,
) -> Result<(TribleSet, Workspace<Pile<valueschemas::Blake3>>)> {
    if repo
        .storage_mut()
        .head(relations_branch_id)
        .map_err(|e| anyhow::anyhow!("relations branch head: {e:?}"))?
        .is_none()
    {
        bail!(
            "missing relations branch {:x} (create with relations faculty)",
            relations_branch_id
        );
    }
    let mut ws = repo
        .pull(relations_branch_id)
        .map_err(|e| anyhow::anyhow!("pull relations workspace: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout relations: {e:?}"))?;
    Ok((space, ws))
}

fn resolve_normalized_person_matches(relations_space: &TribleSet, key: &str) -> Vec<Id> {
    let mut matches = HashSet::new();

    for (person_id,) in find!(
        (person_id: Id),
        pattern!(&relations_space, [{
            ?person_id @
            metadata::tag: &KIND_PERSON_ID,
            relations_schema::label_norm: key,
        }])
    ) {
        matches.insert(person_id);
    }

    for (person_id,) in find!(
        (person_id: Id),
        pattern!(&relations_space, [{
            ?person_id @
            metadata::tag: &KIND_PERSON_ID,
            relations_schema::alias_norm: key,
        }])
    ) {
        matches.insert(person_id);
    }

    matches.into_iter().collect()
}

fn resolve_person_id(relations_space: &TribleSet, input: &str) -> Result<Id> {
    let trimmed = input.trim();
    if let Some(id) = Id::from_hex(trimmed) {
        return Ok(id);
    }
    let label = normalize_label(trimmed)?;
    let key = normalize_lookup_key(trimmed)?;
    let matches = resolve_normalized_person_matches(relations_space, &key);

    match matches.len() {
        0 => bail!(
            "unknown person label '{label}' (run playground/migrations/relations_backfill_norm.rs for older piles)"
        ),
        1 => Ok(matches[0]),
        _ => bail!("multiple people match label '{label}'"),
    }
}

fn person_label(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    space: &TribleSet,
    person_id: Id,
) -> String {
    find!(h: TextHandle, pattern!(space, [{ person_id @ metadata::name: ?h }]))
        .next()
        .and_then(|h| load_text(ws, h).ok())
        .unwrap_or_else(|| fmt_id(person_id))
}

fn open_repo(path: &Path) -> Result<Repository<Pile<valueschemas::Blake3>>> {
    let mut pile = Pile::<valueschemas::Blake3>::open(path)
        .map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        // Avoid Drop warnings on early errors.
        let _ = pile.close();
        return Err(anyhow::anyhow!("restore pile {}: {err:?}", path.display()));
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(
    pile: &Path,
    f: impl FnOnce(&mut Repository<Pile<valueschemas::Blake3>>) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let result = f(&mut repo);
    let close_res = repo
        .close()
        .map_err(|e| anyhow::anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

fn ensure_metadata(ws: &mut Workspace<Pile<valueschemas::Blake3>>) -> Result<TribleSet> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let mut change = TribleSet::new();

    let mut existing_kinds: HashSet<Id> = find!(
        (kind: Id),
        pattern!(&space, [{ ?kind @ metadata::name: _?name }])
    )
    .into_iter()
    .map(|(kind,)| kind)
    .collect();

    for (id, label) in KIND_SPECS {
        if !existing_kinds.contains(&id) {
            let name_handle = label
                .to_owned()
                .to_blob()
                .get_handle::<valueschemas::Blake3>();
            change += entity! { ExclusiveId::force_ref(&id) @ metadata::name: name_handle };
            existing_kinds.insert(id);
        }
    }

    Ok(change)
}

fn resolve_message_id(space: &TribleSet, prefix: &str) -> Result<Id> {
    let prefix = prefix.trim().to_lowercase();
    if prefix.is_empty() {
        bail!("message id prefix is empty");
    }
    if prefix.len() == 32 {
        if let Some(id) = Id::from_hex(&prefix) {
            return Ok(id);
        }
    }

    let mut matches = Vec::new();
    for (message_id,) in find!(
        (message_id: Id),
        pattern!(&space, [{ ?message_id @ metadata::tag: &KIND_MESSAGE_ID }])
    ) {
        let hex = format!("{message_id:x}");
        if hex.starts_with(&prefix) {
            matches.push(message_id);
        }
    }

    match matches.len() {
        0 => bail!("no message id matches prefix '{prefix}'"),
        1 => Ok(matches[0]),
        _ => bail!("multiple messages match prefix '{prefix}'"),
    }
}

fn load_text(ws: &mut Workspace<Pile<valueschemas::Blake3>>, handle: TextHandle) -> Result<String> {
    let view: View<str> = ws.get(handle).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok(view.as_ref().to_string())
}

fn cmd_send(
    pile: &Path,
    branch_id: Id,
    relations_branch_id: Id,
    text: String,
    from: String,
    to: String,
) -> Result<()> {
    with_repo(pile, |repo| {
        let (relations_space, _relations_ws) = load_relations(repo, relations_branch_id)?;
        let from_id = resolve_person_id(&relations_space, &from)?;
        let to_id = resolve_person_id(&relations_space, &to)?;

        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let mut change = ensure_metadata(&mut ws)?;

        let now = epoch_interval(now_epoch());
        let message_id = ufoid();
        let body_handle = ws.put(text.clone());
        change += entity! { &message_id @
            metadata::tag: &KIND_MESSAGE_ID,
            local::from: from_id,
            local::to: to_id,
            local::body: body_handle,
            local::created_at: now,
        };

        ws.commit(change, "local message");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push message: {e:?}"))?;
        drop(ws);
        println!(
            "[{}] {} -> {}: {}",
            fmt_id(*message_id),
            from_id,
            to_id,
            truncate_single_line(&text, 120)
        );
        Ok(())
    })
}

fn cmd_ack(
    pile: &Path,
    branch_id: Id,
    relations_branch_id: Id,
    id: String,
    by: String,
) -> Result<()> {
    with_repo(pile, |repo| {
        let (relations_space, _relations_ws) = load_relations(repo, relations_branch_id)?;
        let reader_id = resolve_person_id(&relations_space, &by)?;

        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let mut change = ensure_metadata(&mut ws)?;

        let space = ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let message_id = resolve_message_id(&space, &id)?;

        let now = epoch_interval(now_epoch());
        let read_id = ufoid();
        change += entity! { &read_id @
            metadata::tag: &KIND_READ_ID,
            local::about_message: message_id,
            local::reader: reader_id,
            local::read_at: now,
        };

        ws.commit(change, "local message read");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push read: {e:?}"))?;
        drop(ws);
        println!("Marked {} as read by {}.", fmt_id(message_id), reader_id);
        Ok(())
    })
}

fn cmd_list(
    pile: &Path,
    branch_id: Id,
    relations_branch_id: Id,
    reader: String,
    unread: bool,
    limit: usize,
) -> Result<()> {
    with_repo(pile, |repo| {
        let (relations_space, mut relations_ws) = load_relations(repo, relations_branch_id)?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

        let mut messages = Vec::new();
        for (message_id, from, to, body, created_at) in find!(
            (
                message_id: Id,
                from: Id,
                to: Id,
                body: TextHandle,
                created_at: Value<valueschemas::NsTAIInterval>
            ),
            pattern!(&space, [{
                ?message_id @
                metadata::tag: &KIND_MESSAGE_ID,
                local::from: ?from,
                local::to: ?to,
                local::body: ?body,
                local::created_at: ?created_at,
            }])
        ) {
            let body_text = load_text(&mut ws, body)?;
            messages.push(MessageRow {
                id: message_id,
                from,
                to,
                body: body_text,
                created_at: interval_key(created_at),
            });
        }

        let mut reads: HashMap<(Id, Id), i128> = HashMap::new();
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

        messages.sort_by_key(|msg| msg.created_at);
        messages.reverse();

        let now_key = interval_key(epoch_interval(now_epoch()));
        let reader_id = resolve_person_id(&relations_space, &reader)?;
        let mut shown = 0usize;

        for msg in messages {
            let incoming = msg.to == reader_id;
            let outgoing = msg.from == reader_id;
            if !incoming && !outgoing {
                continue;
            }

            let read = reads.get(&(msg.id, reader_id)).copied();
            if unread && !(incoming && read.is_none()) {
                continue;
            }

            let from_label = person_label(&mut relations_ws, &relations_space, msg.from);
            let to_label = person_label(&mut relations_ws, &relations_space, msg.to);
            let status = if incoming {
                if read.is_some() {
                    "read".to_string()
                } else {
                    "unread".to_string()
                }
            } else if reads.contains_key(&(msg.id, msg.to)) {
                format!("read-by:{to_label}")
            } else {
                "sent".to_string()
            };
            let age = format_age(now_key, msg.created_at);
            println!(
                "[{}] {} {} -> {} ({}) {}",
                fmt_id(msg.id),
                age,
                from_label,
                to_label,
                status,
                render_list_body(&msg.body)
            );
            shown += 1;
            if shown >= limit {
                break;
            }
        }

        if shown == 0 {
            println!("No messages.");
        }

        drop(ws);
        Ok(())
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(cmd) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };

    let local_messages_branch_id = with_repo(&cli.pile, |repo| {
        if let Some(hex) = cli.branch_id.as_deref() {
            return Id::from_hex(hex.trim())
                .ok_or_else(|| anyhow::anyhow!("invalid branch id '{hex}'"));
        }
        repo.ensure_branch(&cli.branch, None)
            .map_err(|e| anyhow::anyhow!("ensure local-messages branch: {e:?}"))
    })?;
    let relations_branch_id = with_repo(&cli.pile, |repo| {
        if let Some(hex) = cli.relations_branch_id.as_deref() {
            return Id::from_hex(hex.trim())
                .ok_or_else(|| anyhow::anyhow!("invalid relations branch id '{hex}'"));
        }
        repo.ensure_branch(&cli.relations_branch, None)
            .map_err(|e| anyhow::anyhow!("ensure relations branch: {e:?}"))
    })?;

    match cmd {
        Command::Send { text, from, to } => {
            let text = load_value_or_file(&text, "message text")?;
            cmd_send(
                &cli.pile,
                local_messages_branch_id,
                relations_branch_id,
                text,
                from,
                to,
            )
        }
        Command::List {
            reader,
            unread,
            limit,
        } => cmd_list(
            &cli.pile,
            local_messages_branch_id,
            relations_branch_id,
            reader,
            unread,
            limit,
        ),
        Command::Ack { id, by } => cmd_ack(
            &cli.pile,
            local_messages_branch_id,
            relations_branch_id,
            id,
            by,
        ),
    }
}

