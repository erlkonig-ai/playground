#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4.2.3"
//! rand_core = "0.6.4"
//! triblespace = "0.34.1"
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
use triblespace::macros::id_hex;
use triblespace::prelude::*;

const KIND_GOAL_LABEL: &str = "goal";
const KIND_STATUS_LABEL: &str = "status";
const KIND_NOTE_LABEL: &str = "note";
const KIND_PRIORITIZE_LABEL: &str = "prioritize";
const KIND_DEPRIORITIZE_LABEL: &str = "deprioritize";

const KIND_GOAL_ID: Id = id_hex!("83476541420F46402A6A9911F46FBA3B");
const KIND_STATUS_ID: Id = id_hex!("89602B3277495F4E214D4A417C8CF260");
const KIND_NOTE_ID: Id = id_hex!("D4E49A6F02A14E66B62076AE4C01715F");
const KIND_PRIORITIZE_ID: Id = id_hex!("6907A81922DA6DF79966616EA60DEC70");
const KIND_DEPRIORITIZE_ID: Id = id_hex!("86C4621538FB0E30CD63BB7A3B847E8B");

const DEFAULT_STATUSES: [&str; 4] = ["todo", "doing", "blocked", "done"];

type TextHandle = Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>;

const KIND_SPECS: [(Id, &str); 5] = [
    (KIND_GOAL_ID, KIND_GOAL_LABEL),
    (KIND_STATUS_ID, KIND_STATUS_LABEL),
    (KIND_NOTE_ID, KIND_NOTE_LABEL),
    (KIND_PRIORITIZE_ID, KIND_PRIORITIZE_LABEL),
    (KIND_DEPRIORITIZE_ID, KIND_DEPRIORITIZE_LABEL),
];

mod board {
    use super::*;

    attributes! {
        "EE18CEC15C18438A2FAB670E2E46E00C" as title: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        // TODO: migrate to metadata::tag (GenId) — tags should be entities with
        // their own ID + metadata::name, not inline strings. See wiki.rs TagIndex
        // for the correct pattern. This ShortString tag is a legacy design mistake.
        "5FF4941DCC3F6C35E9B3FD57216F69ED" as tag: valueschemas::ShortString;
        "9D2B6EBDA67E9BB6BE6215959D182041" as parent: valueschemas::GenId;

        "C1EAAA039DA7F486E4A54CC87D42E72C" as task: valueschemas::GenId;
        "61C44E0F8A73443ED592A713151E99A4" as status: valueschemas::ShortString;
        "47351DF00B3DDA96CB305157CD53D781" as note: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "B88842D9D00361A0F2728C478C79D75C" as higher: valueschemas::GenId;
        "18F3446C9E9281A248D370A56395A3F0" as lower: valueschemas::GenId;
    }
}

#[derive(Parser)]
#[command(name = "compass", about = "A small TribleSpace kanban faculty")]
struct Cli {
    /// Path to the pile file to use
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name for the board
    #[arg(long, default_value = "compass")]
    branch: String,
    /// Branch id for the board (hex). Overrides config.
    #[arg(long)]
    branch_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Add a new goal
    Add {
        #[arg(help = "Goal title. Use @path for file input or @- for stdin.")]
        title: String,
        #[arg(long, default_value = "todo")]
        status: String,
        /// Parent goal id (full 32-char hex id; use `compass resolve` to look up by prefix)
        #[arg(long)]
        parent: Option<String>,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long, help = "Initial note. Use @path for file input or @- for stdin.")]
        note: Option<String>,
    },
    /// List goals in kanban columns (hides done by default)
    List {
        /// Show done goals too
        #[arg(long)]
        all: bool,
        /// Filter by tag (repeatable, shows goals matching any)
        #[arg(long)]
        tag: Vec<String>,
        #[arg(value_name = "STATUS")]
        status: Vec<String>,
    },
    /// Move a goal to a new status
    Move {
        /// Full 32-char hex id
        id: String,
        status: String,
    },
    /// Add a note to a goal
    Note {
        /// Full 32-char hex id
        id: String,
        #[arg(help = "Note text. Use @path for file input or @- for stdin.")]
        note: String,
    },
    /// Show a goal with history and notes
    Show {
        /// Full 32-char hex id
        id: String,
    },
    /// Mark a goal as more important than another
    Prioritize {
        /// The more important goal (full 32-char hex id)
        higher: String,
        /// The less important goal (full 32-char hex id)
        #[arg(long)]
        over: String,
    },
    /// Remove a priority relationship
    Deprioritize {
        /// The goal that was marked more important (full 32-char hex id)
        higher: String,
        /// The goal it was prioritized over (full 32-char hex id)
        #[arg(long)]
        over: String,
    },
    /// Resolve a hex prefix to a full 64-char goal id
    Resolve {
        /// Hex prefix to search for
        prefix: String,
    },
}

// ── on-demand board queries ───────────────────────────────────────────
// All data lives in the TribleSet; we query directly via find!() instead
// of pre-materializing into Rust structs.

/// Query helpers that operate directly on the checked-out TribleSet + workspace.

type IntervalValue = Value<valueschemas::NsTAIInterval>;

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_interval(epoch: Epoch) -> IntervalValue {
    (epoch, epoch).try_to_value().unwrap()
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval.try_from_value().unwrap();
    lower
}

fn format_interval(interval: IntervalValue) -> String {
    let (lower, _): (Epoch, Epoch) = interval.try_from_value().unwrap();
    format!("{}", lower)
}

fn validate_short(label: &str, value: &str) -> Result<()> {
    if value.as_bytes().len() > 32 {
        bail!("{label} exceeds 32 bytes: {value}");
    }
    if value.as_bytes().iter().any(|b| *b == 0) {
        bail!("{label} contains NUL bytes: {value}");
    }
    Ok(())
}

fn normalize_status(status: String) -> String {
    status.trim().to_lowercase()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

/// Extract `[text](faculty:<hex>)` markdown link references from text.
/// Returns (faculty, hex_string) pairs.
fn extract_references(text: &str) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    let mut rest = text;
    while let Some(paren) = rest.find("](") {
        let after = &rest[paren + 2..];
        let end = after.find(')').unwrap_or(after.len());
        let link = &after[..end];
        if let Some(colon) = link.find(':') {
            let faculty = &link[..colon];
            let hex: String = link[colon + 1..]
                .chars()
                .take_while(|c| c.is_ascii_hexdigit())
                .collect();
            if hex.len() >= 4
                && !faculty.is_empty()
                && faculty
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                refs.push((faculty.to_string(), hex));
            }
        }
        rest = &after[end.min(after.len()).max(1)..];
    }
    refs.sort();
    refs.dedup();
    refs
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
        .map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        // Avoid Drop warnings on early errors.
        let _ = pile.close();
        return Err(anyhow::anyhow!(
            "restore pile {}: {err:?}",
            path.display()
        ));
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

fn task_parent(space: &TribleSet, task_id: Id) -> Option<Id> {
    find!(p: Id, pattern!(space, [{ task_id @ board::parent: ?p }])).next()
}

fn task_created_at(space: &TribleSet, task_id: Id) -> Option<IntervalValue> {
    find!(s: IntervalValue, pattern!(space, [{ task_id @ metadata::created_at: ?s }]))
        .next()
}

/// Latest status for a task.
fn task_latest_status(space: &TribleSet, task_id: Id) -> Option<(String, IntervalValue)> {
    find!(
        (status: String, at: IntervalValue),
        pattern!(space, [{
            _?evt @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &task_id,
            board::status: ?status,
            metadata::created_at: ?at,
        }])
    )
    .max_by(|a, b| interval_key(a.1).cmp(&interval_key(b.1)))
}

/// All goal IDs.
fn all_goal_ids(space: &TribleSet) -> Vec<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_GOAL_ID }])).collect()
}

fn read_text(ws: &mut Workspace<Pile<valueschemas::Blake3>>, handle: TextHandle) -> Result<String> {
    let view: View<str> = ws
        .get::<View<str>, blobschemas::LongString>(handle)
        .map_err(|e| anyhow::anyhow!("load longstring: {e:?}"))?;
    Ok(view.to_string())
}

/// Parse a full 64-char hex ID. Returns a helpful error pointing to `compass resolve` on failure.
fn parse_full_id(input: &str) -> Result<Id> {
    let trimmed = input.trim();
    Id::from_hex(trimmed).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid goal id '{}': expected a full 32-char hex id\n\
             Hint: use `compass resolve <prefix>` to look up the full id from a short prefix",
            trimmed
        )
    })
}

fn resolve_task_id(input: &str, space: &TribleSet) -> Result<Id> {
    let needle = input.trim().to_lowercase();
    if needle.is_empty() {
        bail!("goal id is empty");
    }
    let mut matches = Vec::new();
    for id in all_goal_ids(space) {
        let hex = format!("{id:x}");
        if hex.starts_with(&needle) {
            matches.push(id);
        }
    }
    match matches.len() {
        0 => bail!("no goal id matches '{input}'"),
        1 => Ok(matches[0]),
        _ => {
            let mut rendered: Vec<String> = matches.into_iter().map(|id| format!("{id:x}")).collect();
            rendered.sort();
            bail!("ambiguous goal id '{input}': {}", rendered.join(", "));
        }
    }
}

/// Compute active priority edges from the space.
fn active_priority_edges(space: &TribleSet) -> HashSet<(Id, Id)> {
    let mut latest: HashMap<(Id, Id), (i128, bool)> = HashMap::new();
    for (higher, lower, at) in find!(
        (higher: Id, lower: Id, at: IntervalValue),
        pattern!(space, [{
            _?evt @
            metadata::tag: &KIND_PRIORITIZE_ID,
            board::higher: ?higher,
            board::lower: ?lower,
            metadata::created_at: ?at,
        }])
    ) {
        let key = interval_key(at);
        latest.entry((higher, lower))
            .and_modify(|(cur_key, cur_active)| { if key > *cur_key { *cur_key = key; *cur_active = true; } })
            .or_insert((key, true));
    }
    for (higher, lower, at) in find!(
        (higher: Id, lower: Id, at: IntervalValue),
        pattern!(space, [{
            _?evt @
            metadata::tag: &KIND_DEPRIORITIZE_ID,
            board::higher: ?higher,
            board::lower: ?lower,
            metadata::created_at: ?at,
        }])
    ) {
        let key = interval_key(at);
        latest.entry((higher, lower))
            .and_modify(|(cur_key, cur_active)| { if key > *cur_key { *cur_key = key; *cur_active = false; } })
            .or_insert((key, false));
    }
    latest.into_iter().filter(|(_, (_, active))| *active).map(|(k, _)| k).collect()
}

/// Check if `to` is an ancestor of `from` (or `from` itself) in the parent tree.
fn is_ancestor(space: &TribleSet, from: Id, to: Id) -> bool {
    from == to || exists!(
        (_start: Id, _end: Id),
        and!(
            _start.is(from.to_value()),
            _end.is(to.to_value()),
            path!(space, _start board::parent+ _end)
        )
    )
}

/// Count notes for a task.
fn note_count(space: &TribleSet, task_id: Id) -> usize {
    find!(
        _n: TextHandle,
        pattern!(space, [{ _?evt @ metadata::tag: &KIND_NOTE_ID, board::task: &task_id, board::note: ?_n }])
    ).count()
}

/// Check if adding (higher, lower) would create a cycle in the priority DAG.
fn would_create_cycle(edges: &HashSet<(Id, Id)>, higher: Id, lower: Id) -> bool {
    let mut visited = HashSet::new();
    let mut queue = vec![lower];
    while let Some(node) = queue.pop() {
        if node == higher {
            return true;
        }
        if !visited.insert(node) {
            continue;
        }
        for &(h, l) in edges {
            if h == node && !visited.contains(&l) {
                queue.push(l);
            }
        }
    }
    false
}

/// Topological rank of tasks by priority edges (lower rank = more important).
fn priority_ranks(task_ids: &[Id], edges: &HashSet<(Id, Id)>) -> HashMap<Id, usize> {
    let id_set: HashSet<Id> = task_ids.iter().copied().collect();
    let mut adj: HashMap<Id, Vec<Id>> = HashMap::new();
    let mut in_degree: HashMap<Id, usize> = HashMap::new();
    for &id in task_ids {
        in_degree.entry(id).or_insert(0);
    }
    for &(h, l) in edges {
        if id_set.contains(&h) && id_set.contains(&l) {
            adj.entry(h).or_default().push(l);
            *in_degree.entry(l).or_insert(0) += 1;
        }
    }
    let mut queue: Vec<Id> = in_degree
        .iter()
        .filter(|(_, &deg)| deg == 0)
        .map(|(&id, _)| id)
        .collect();
    queue.sort_by(|a, b| a.cmp(b));
    let mut ranks = HashMap::new();
    let mut rank = 0;
    while let Some(node) = queue.pop() {
        ranks.insert(node, rank);
        rank += 1;
        if let Some(neighbors) = adj.get(&node) {
            for &next in neighbors {
                if let Some(deg) = in_degree.get_mut(&next) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(next);
                        queue.sort_by(|a, b| a.cmp(b));
                    }
                }
            }
        }
    }
    for &id in task_ids {
        ranks.entry(id).or_insert(rank);
    }
    ranks
}

fn render_board(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    space: &TribleSet,
    status_filter: &[String],
    tag_filter: &[String],
    show_done: bool,
) {
    let goal_ids = all_goal_ids(space);
    let mut priority_edges = active_priority_edges(space);
    // Implicit: children must be done before parents → child > parent
    for &id in &goal_ids {
        if let Some(parent) = task_parent(space, id) {
            priority_edges.insert((id, parent));
        }
    }

    let mut columns: HashMap<String, Vec<TaskRow>> = HashMap::new();

    for &task_id in &goal_ids {
        let (status, status_at) = task_latest_status(space, task_id)
            .map(|(s, at)| (s, Some(at)))
            .unwrap_or_else(|| ("todo".to_string(), None));

        if status_filter.is_empty() {
            if !show_done && status == "done" {
                continue;
            }
        } else if !status_filter.iter().any(|s| s == &status) {
            continue;
        }

        let tags = task_tags(space, task_id);
        if !tag_filter.is_empty() && !tags.iter().any(|t| tag_filter.contains(t)) {
            continue;
        }

        let title = task_title(ws, space, task_id);
        let created_at = task_created_at(space, task_id);
        let notes = note_count(space, task_id);
        let parent = task_parent(space, task_id);

        let sort_key = status_at.map(interval_key).or(created_at.map(interval_key)).unwrap_or(0);
        columns
            .entry(status)
            .or_default()
            .push(TaskRow { id: task_id, id_hex: fmt_id(task_id), title, tags, sort_key, note_count: notes, parent });
    }

    let mut ordered_statuses = Vec::new();
    for status in DEFAULT_STATUSES {
        if columns.contains_key(status) {
            ordered_statuses.push(status.to_string());
        }
    }
    let mut extras: Vec<String> = columns
        .keys()
        .filter(|s| !DEFAULT_STATUSES.contains(&s.as_str()))
        .cloned()
        .collect();
    extras.sort();
    ordered_statuses.extend(extras);

    if ordered_statuses.is_empty() {
        println!("No goals yet.");
        return;
    }

    for status in ordered_statuses {
        let rows = columns.remove(&status).unwrap_or_default();
        println!();
        println!("== {} ({}) ==", status.to_uppercase(), rows.len());
        let ordered = order_rows(rows, &priority_edges);
        for (row, depth) in ordered {
            let indent = "  ".repeat(depth);
            println!(
                "{}- [{}] {}{}{}",
                indent,
                row.id_hex,
                row.title,
                row.tag_suffix(),
                row.note_suffix()
            );
        }
    }
    println!();
}

#[derive(Debug, Clone)]
struct TaskRow {
    id: Id,
    id_hex: String,
    title: String,
    tags: Vec<String>,
    sort_key: i128,
    note_count: usize,
    parent: Option<Id>,
}

impl TaskRow {

    fn tag_suffix(&self) -> String {
        if self.tags.is_empty() {
            String::new()
        } else {
            format!(" {}", self.tags.iter().map(|t| format!("#{t}")).collect::<Vec<_>>().join(" "))
        }
    }

    fn note_suffix(&self) -> String {
        if self.note_count == 0 {
            String::new()
        } else if self.note_count == 1 {
            " (1 note)".to_string()
        } else {
            format!(" ({} notes)", self.note_count)
        }
    }
}

fn order_rows(rows: Vec<TaskRow>, priority_edges: &HashSet<(Id, Id)>) -> Vec<(TaskRow, usize)> {
    let mut by_id: HashMap<Id, TaskRow> = HashMap::new();
    for row in rows {
        by_id.insert(row.id, row);
    }
    let ids: HashSet<Id> = by_id.keys().copied().collect();
    let mut children: HashMap<Id, Vec<Id>> = HashMap::new();
    let mut roots = Vec::new();

    for (id, row) in &by_id {
        if let Some(parent) = row.parent {
            if ids.contains(&parent) {
                children.entry(parent).or_default().push(*id);
                continue;
            }
        }
        roots.push(*id);
    }

    let all_ids: Vec<Id> = by_id.keys().copied().collect();
    let ranks = priority_ranks(&all_ids, priority_edges);

    let sort_ids = |items: &mut Vec<Id>| {
        items.sort_by(|a, b| {
            let a_rank = ranks.get(a).copied().unwrap_or(usize::MAX);
            let b_rank = ranks.get(b).copied().unwrap_or(usize::MAX);
            match a_rank.cmp(&b_rank) {
                std::cmp::Ordering::Equal => {
                    // Fall back to timestamp (most recent first)
                    let a_key = by_id.get(a).map(|row| row.sort_key).unwrap_or(0);
                    let b_key = by_id.get(b).map(|row| row.sort_key).unwrap_or(0);
                    b_key.cmp(&a_key)
                }
                other => other,
            }
        });
    };

    sort_ids(&mut roots);
    for kids in children.values_mut() {
        sort_ids(kids);
    }

    let mut ordered = Vec::new();
    let mut visited = HashSet::new();

    fn walk(
        id: Id,
        depth: usize,
        by_id: &HashMap<Id, TaskRow>,
        children: &HashMap<Id, Vec<Id>>,
        visited: &mut HashSet<Id>,
        out: &mut Vec<(TaskRow, usize)>,
    ) {
        if !visited.insert(id) {
            return;
        }
        let Some(row) = by_id.get(&id) else {
            return;
        };
        out.push((row.clone(), depth));
        if let Some(kids) = children.get(&id) {
            for kid in kids {
                walk(*kid, depth + 1, by_id, children, visited, out);
            }
        }
    }

    for root in roots {
        walk(root, 0, &by_id, &children, &mut visited, &mut ordered);
    }

    for id in by_id.keys() {
        if !visited.contains(id) {
            walk(*id, 0, &by_id, &children, &mut visited, &mut ordered);
        }
    }

    ordered
}

fn ensure_kind_entities(ws: &mut Workspace<Pile<valueschemas::Blake3>>) -> Result<TribleSet> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout board: {e:?}"))?;
    let existing: HashSet<Id> = find!(
        (kind: Id),
        pattern!(&space, [{ ?kind @ metadata::name: _?handle }])
    )
    .map(|(kind,)| kind)
    .collect();

    let mut change = TribleSet::new();
    for (id, label) in KIND_SPECS {
        if existing.contains(&id) {
            continue;
        }
        let name_handle = label
            .to_owned()
            .to_blob()
            .get_handle::<valueschemas::Blake3>();
        change += entity! { ExclusiveId::force_ref(&id) @ metadata::name: name_handle };
    }
    Ok(change)
}

fn cmd_add(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    title: String,
    status: String,
    parent: Option<String>,
    tags: Vec<String>,
    note: Option<String>,
) -> Result<()> {
    let status = normalize_status(status);
    let tags: Vec<String> = tags.into_iter().map(|t| t.trim().to_string()).collect();
    validate_short("status", &status)?;
    for tag in &tags {
        validate_short("tag", tag)?;
    }

    let parent_id = parent.as_deref().map(parse_full_id).transpose()?;

    let task_ref = with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let task_id = ufoid();
        let task_ref = task_id.id;
        let now = epoch_interval(now_epoch());
        let title_handle = ws.put(title);

        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &task_id @
            metadata::tag: &KIND_GOAL_ID,
            board::title: title_handle,
            metadata::created_at: now,
            board::parent?: parent_id.as_ref(),
            board::tag*: tags.iter().map(|tag| tag.as_str()),
        };

        let status_id = ufoid();
        change += entity! { &status_id @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &task_ref,
            board::status: status.as_str(),
            metadata::created_at: now,
        };

        if let Some(note) = note {
            let note_id = ufoid();
            change += entity! { &note_id @
                metadata::tag: &KIND_NOTE_ID,
                board::task: &task_ref,
                board::note: ws.put(note),
                metadata::created_at: now,
            };
        }

        ws.commit(change, "add goal");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push goal: {e:?}"))?;
        Ok(task_ref)
    })?;
    println!("Added goal {:x}", task_ref);
    Ok(())
}

fn cmd_list(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    status_filter: Vec<String>,
    tag_filter: Vec<String>,
    show_done: bool,
) -> Result<()> {
    let status_filter: Vec<String> = status_filter.into_iter().map(normalize_status).collect();
    for status in &status_filter {
        validate_short("status", status)?;
    }

    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        render_board(&mut ws, &space, &status_filter, &tag_filter, show_done);
        Ok(())
    })
}

fn cmd_move(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    id: String,
    status: String,
) -> Result<()> {
    let status = normalize_status(status);
    validate_short("status", &status)?;
    let task_id = parse_full_id(&id)?;

    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let now = epoch_interval(now_epoch());

        let status_id = ufoid();
        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &status_id @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &task_id,
            board::status: status.as_str(),
            metadata::created_at: now,
        };

        ws.commit(change, "move goal");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push status: {e:?}"))?;
        Ok(())
    })?;
    println!("Moved goal {:x} to {}", task_id, status);
    Ok(())
}

fn cmd_note(pile: &Path, _branch_name: &str, branch_id: Id, id: String, note: String) -> Result<()> {
    let task_id = parse_full_id(&id)?;

    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let now = epoch_interval(now_epoch());

        let note_id = ufoid();
        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &note_id @
            metadata::tag: &KIND_NOTE_ID,
            board::task: &task_id,
            board::note: ws.put(note),
            metadata::created_at: now,
        };

        ws.commit(change, "add goal note");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push note: {e:?}"))?;
        Ok(())
    })?;
    println!("Noted goal {:x}", task_id);
    Ok(())
}

fn cmd_show(pile: &Path, _branch_name: &str, branch_id: Id, id: String) -> Result<()> {
    let task_id = parse_full_id(&id)?;

    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

        let title = task_title(&mut ws, &space, task_id);
        if title.is_empty() {
            bail!("goal missing");
        }

        println!("Goal {:x}", task_id);
        println!("Title: {}", title);
        if let Some(created) = task_created_at(&space, task_id) {
            println!("Created: {}", format_interval(created));
        }

        if let Some((status, at)) = task_latest_status(&space, task_id) {
            println!("Status: {} (since {})", status, format_interval(at));
        }

        let tags = task_tags(&space, task_id);
        if !tags.is_empty() {
            println!("Tags: {}", tags.join(", "));
        }

        if let Some(parent_id) = task_parent(&space, task_id) {
            let parent_hex = fmt_id(parent_id);
            let parent_title = task_title(&mut ws, &space, parent_id);
            if parent_title.is_empty() {
                println!("Parent: {parent_hex}");
            } else {
                println!("Parent: {parent_title} ({parent_hex})");
            }
        }

        // Status history for this task.
        let mut history: Vec<(String, i128, String)> = find!(
            (status: String, at: IntervalValue),
            pattern!(&space, [{
                _?evt @
                metadata::tag: &KIND_STATUS_ID,
                board::task: &task_id,
                board::status: ?status,
                metadata::created_at: ?at,
            }])
        ).map(|(status, at)| (status, interval_key(at), format_interval(at))).collect();
        if !history.is_empty() {
            history.sort_by(|a, b| a.1.cmp(&b.1));
            println!();
            println!("Status history:");
            for (status, _, at_str) in &history {
                println!("- {at_str} {status}");
            }
        }

        // Notes for this task.
        let mut notes: Vec<(String, i128, String)> = find!(
            (note_handle: TextHandle, at: IntervalValue),
            pattern!(&space, [{
                _?evt @
                metadata::tag: &KIND_NOTE_ID,
                board::task: &task_id,
                board::note: ?note_handle,
                metadata::created_at: ?at,
            }])
        )
        .filter_map(|(h, at)| read_text(&mut ws, h).ok().map(|text| (text, interval_key(at), format_interval(at))))
        .collect();
        if !notes.is_empty() {
            notes.sort_by(|a, b| a.1.cmp(&b.1));
            println!();
            println!("Notes:");
            for (text, _, at_str) in &notes {
                println!("- {at_str} {text}");
            }

            let mut all_refs = Vec::new();
            for (text, _, _) in &notes {
                all_refs.extend(extract_references(text));
            }
            all_refs.sort();
            all_refs.dedup();
            if !all_refs.is_empty() {
                println!();
                println!("References:");
                for (faculty, hex) in &all_refs {
                    println!("  ⇢ {faculty}:{hex}");
                }
            }
        }
        Ok(())
    })
}

fn cmd_prioritize(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    higher_input: String,
    lower_input: String,
) -> Result<()> {
    let higher_id = parse_full_id(&higher_input)?;
    let lower_id = parse_full_id(&lower_input)?;

    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

        if higher_id == lower_id {
            bail!("cannot prioritize a goal over itself");
        }

        // Build full edge set (explicit + implicit child→parent)
        let mut edges = active_priority_edges(&space);
        for id in all_goal_ids(&space) {
            if let Some(parent) = task_parent(&space, id) {
                edges.insert((id, parent));
            }
        }

        if would_create_cycle(&edges, higher_id, lower_id) {
            if is_ancestor(&space, higher_id, lower_id)
                || is_ancestor(&space, lower_id, higher_id)
            {
                bail!("children are implicitly prioritized over their parents");
            }
            bail!("would create a priority cycle");
        }

        let now = epoch_interval(now_epoch());
        let evt_id = ufoid();
        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &evt_id @
            metadata::tag: &KIND_PRIORITIZE_ID,
            board::higher: &higher_id,
            board::lower: &lower_id,
            metadata::created_at: now,
        };

        ws.commit(change, "prioritize goal");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;

        let h_title = task_title(&mut ws, &space, higher_id);
        let l_title = task_title(&mut ws, &space, lower_id);
        println!("{} > {}", if h_title.is_empty() { "?" } else { &h_title }, if l_title.is_empty() { "?" } else { &l_title });
        Ok(())
    })
}

fn cmd_deprioritize(
    pile: &Path,
    _branch_name: &str,
    branch_id: Id,
    higher_input: String,
    lower_input: String,
) -> Result<()> {
    let higher_id = parse_full_id(&higher_input)?;
    let lower_id = parse_full_id(&lower_input)?;

    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

        let edges = active_priority_edges(&space);
        if !edges.contains(&(higher_id, lower_id)) {
            bail!("no active priority relationship between these goals");
        }

        let now = epoch_interval(now_epoch());
        let evt_id = ufoid();
        let mut change = TribleSet::new();
        change += ensure_kind_entities(&mut ws)?;
        change += entity! { &evt_id @
            metadata::tag: &KIND_DEPRIORITIZE_ID,
            board::higher: &higher_id,
            board::lower: &lower_id,
            metadata::created_at: now,
        };

        ws.commit(change, "deprioritize goal");
        repo.push(&mut ws)
            .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;

        let h_title = task_title(&mut ws, &space, higher_id);
        let l_title = task_title(&mut ws, &space, lower_id);
        println!("Removed: {} > {}", if h_title.is_empty() { "?" } else { &h_title }, if l_title.is_empty() { "?" } else { &l_title });
        Ok(())
    })
}

fn cmd_resolve(pile: &Path, _branch_name: &str, branch_id: Id, prefix: String) -> Result<()> {
    with_repo(pile, |repo| {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow::anyhow!("pull workspace: {e:?}"))?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let id = resolve_task_id(&prefix, &space)?;
        println!("{:x}", id);
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
    let branch_id = with_repo(&cli.pile, |repo| {
        if let Some(hex) = cli.branch_id.as_deref() {
            return Id::from_hex(hex.trim())
                .ok_or_else(|| anyhow::anyhow!("invalid branch id '{hex}'"));
        }
        repo.ensure_branch(&cli.branch, None)
            .map_err(|e| anyhow::anyhow!("ensure branch '{}': {e:?}", cli.branch))
    })?;

    match cmd {
        Command::Add {
            title,
            status,
            parent,
            tag,
            note,
        } => {
            let title = load_value_or_file(&title, "goal title")?;
            let note = note
                .as_deref()
                .map(|value| load_value_or_file(value, "goal note"))
                .transpose()?;
            cmd_add(
                &cli.pile,
                &cli.branch,
                branch_id,
                title,
                status,
                parent,
                tag,
                note,
            )
        }
        Command::List { status, tag, all } => cmd_list(&cli.pile, &cli.branch, branch_id, status, tag, all),
        Command::Move { id, status } => cmd_move(&cli.pile, &cli.branch, branch_id, id, status),
        Command::Note { id, note } => {
            let note = load_value_or_file(&note, "goal note")?;
            cmd_note(&cli.pile, &cli.branch, branch_id, id, note)
        }
        Command::Show { id } => cmd_show(&cli.pile, &cli.branch, branch_id, id),
        Command::Prioritize { higher, over } => {
            cmd_prioritize(&cli.pile, &cli.branch, branch_id, higher, over)
        }
        Command::Deprioritize { higher, over } => {
            cmd_deprioritize(&cli.pile, &cli.branch, branch_id, higher, over)
        }
        Command::Resolve { prefix } => cmd_resolve(&cli.pile, &cli.branch, branch_id, prefix),
    }
}
