#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4.2.3"
//! rand_core = "0.6.4"
//! regex = "1"
//! triblespace = "0.22"
//! ```

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use hifitime::efmt::Formatter;
use hifitime::efmt::consts::ISO8601_DATE;
use rand_core::OsRng;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::id_hex;
use triblespace::prelude::*;

// ── wiki branch name ──────────────────────────────────────────────────────
const WIKI_BRANCH_NAME: &str = "wiki";

// ── kinds ──────────────────────────────────────────────────────────────────
const KIND_VERSION_ID: Id = id_hex!("1AA0310347EDFED7874E8BFECC6438CF");

// ── tag vocabulary ────────────────────────────────────────────────────────
const TAG_ARCHIVED_ID: Id = id_hex!("480CB6A663C709478A26A8B49F366C3F");

const TAG_SPECS: [(Id, &str); 9] = [
    (KIND_VERSION_ID, "version"),
    (id_hex!("1A7FB717FBFCA81CA3AA7D3D186ACC8F"), "hypothesis"),
    (id_hex!("72CE6B03E39A8AAC37BC0C4015ED54E2"), "critique"),
    (id_hex!("243AE22C5E020F61EBBC8C0481BF05A4"), "finding"),
    (id_hex!("8871C1709EBFCDD2588369003D3964DE"), "paper"),
    (id_hex!("7D58EBA4E1E4A1EF868C3C4A58AEC22E"), "source"),
    (id_hex!("C86BCF906D270403A0A2083BB95B3552"), "concept"),
    (id_hex!("F8172CC4E495817AB52D2920199EF4BD"), "experiment"),
    (TAG_ARCHIVED_ID, "archived"),
];

type TextHandle = Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>;

// ── wiki attributes ────────────────────────────────────────────────────────
mod wiki {
    use super::*;
    attributes! {
        "EBFC56D50B748E38A14F5FC768F1B9C1" as fragment: valueschemas::GenId;
        "6DBBE746B7DD7A4793CA098AB882F553" as content: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "476F6E26FCA65A0B49E38CC44CF31467" as created_at: valueschemas::NsTAIInterval;
        "78BABEF1792531A2E51A372D96FE5F3E" as title: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "DEAFB7E307DF72389AD95A850F24BAA5" as links_to: valueschemas::GenId;
    }
}

// ── CLI ────────────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(name = "wiki", about = "A TribleSpace knowledge wiki faculty")]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch id (hex). Overrides name-based lookup.
    #[arg(long)]
    branch_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new fragment with its first version
    Create {
        /// Fragment title
        title: String,
        /// Content text. Use @path for file input or @- for stdin.
        content: String,
        /// Tags (by name). Unknown tags are minted automatically.
        #[arg(long)]
        tag: Vec<String>,
    },
    /// Create a new version of an existing fragment
    Edit {
        /// Fragment or version id (full 32-char hex id)
        id: String,
        /// New content (optional; inherits previous if omitted). Use @path for file input or @- for stdin.
        content: Option<String>,
        /// New title (optional, inherits previous if omitted)
        #[arg(long)]
        title: Option<String>,
        /// Tags (replaces previous version's tags)
        #[arg(long)]
        tag: Vec<String>,
    },
    /// Show a fragment (latest version) or a specific version
    Show {
        /// Fragment or version id (full 32-char hex id)
        id: String,
        /// If id is a version, look up its fragment and show the latest version instead
        #[arg(long)]
        latest: bool,
    },
    /// Print raw content without metadata header
    Export {
        /// Fragment or version id (full 32-char hex id)
        id: String,
    },
    /// Compare two versions of a fragment
    Diff {
        /// Fragment id (full 32-char hex id)
        id: String,
        /// First version number (1-based, default: second-to-last)
        #[arg(long)]
        from: Option<usize>,
        /// Second version number (1-based, default: latest)
        #[arg(long)]
        to: Option<usize>,
    },
    /// Soft-delete a fragment (adds #archived tag)
    Archive {
        /// Fragment id (full 32-char hex id)
        id: String,
    },
    /// Restore an archived fragment (removes #archived tag)
    Restore {
        /// Fragment id (full 32-char hex id)
        id: String,
    },
    /// Revert a fragment to a previous version
    Revert {
        /// Fragment id (full 32-char hex id)
        id: String,
        /// Version number to revert to (1-based)
        #[arg(long)]
        to: usize,
    },
    /// Show links from/to a fragment (extracted from `[text](<faculty>:<hex>)` references)
    Links {
        /// Fragment id (full 32-char hex id)
        id: String,
    },
    /// List fragments, optionally filtered by tag
    List {
        /// Filter by tag name
        #[arg(long)]
        tag: Vec<String>,
        /// Include archived fragments
        #[arg(long)]
        all: bool,
    },
    /// Show version history for a fragment
    History {
        /// Fragment id (full 32-char hex id)
        id: String,
    },
    /// Tag management: add, remove, list, mint
    Tag {
        #[command(subcommand)]
        command: TagCommand,
    },
    /// Import a file or directory of .md files into the wiki
    Import {
        /// File or directory path
        path: PathBuf,
        /// Tags to apply to all imported fragments
        #[arg(long)]
        tag: Vec<String>,
    },
    /// Search fragment titles and content (substring, case-insensitive)
    Search {
        /// Search query
        query: String,
        /// Also show matching context lines
        #[arg(long, short = 'c')]
        context: bool,
        /// Include archived fragments
        #[arg(long)]
        all: bool,
    },
    /// Resolve a hex prefix to a full 64-character entity id
    Resolve {
        /// Hex prefix (any length)
        prefix: String,
    },
}

#[derive(Subcommand)]
enum TagCommand {
    /// Add a tag to a fragment (creates a new version)
    Add {
        /// Fragment id (full 32-char hex id)
        id: String,
        /// Tag name
        name: String,
    },
    /// Remove a tag from a fragment (creates a new version)
    Remove {
        /// Fragment id (full 32-char hex id)
        id: String,
        /// Tag name
        name: String,
    },
    /// List all tags with usage counts
    List,
    /// Mint and register a new tag name
    Mint {
        /// Tag name
        name: String,
    },
}

/// Bidirectional tag name / id index.
struct TagIndex {
    by_name: HashMap<String, Id>,
    by_id: HashMap<Id, String>,
}

impl TagIndex {
    fn load(ws: &mut Workspace<Pile<valueschemas::Blake3>>) -> Result<Self> {
        let space = ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout for tag names: {e:?}"))?;
        let mut by_name = HashMap::new();
        let mut by_id = HashMap::new();
        for (tag_id, handle) in find!(
            (tag_id: Id, handle: TextHandle),
            pattern!(&space, [{ ?tag_id @ metadata::name: ?handle }])
        ) {
            let view: View<str> = ws
                .get(handle)
                .map_err(|e| anyhow::anyhow!("read tag name: {e:?}"))?;
            let name = view.as_ref().to_string();
            by_name.insert(name.clone(), tag_id);
            by_id.insert(tag_id, name);
        }
        Ok(Self { by_name, by_id })
    }

    fn name(&self, id: Id) -> String {
        self.by_id
            .get(&id)
            .cloned()
            .unwrap_or_else(|| fmt_id(id))
    }

    fn format_tags(&self, tags: &[Id]) -> String {
        let names: Vec<String> = tags.iter().map(|t| self.name(*t)).collect();
        if names.is_empty() {
            String::new()
        } else {
            format!(" [{}]", names.join(", "))
        }
    }

    fn resolve_or_mint(
        &mut self,
        names: &[String],
        change: &mut TribleSet,
        ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    ) -> Result<Vec<Id>> {
        let mut ids = Vec::new();
        for raw in names {
            let name = raw.trim().to_lowercase();
            if name.is_empty() {
                continue;
            }
            if let Some(&id) = self.by_name.get(&name) {
                ids.push(id);
            } else {
                let tag_id = genid();
                let tag_ref = tag_id.id;
                let name_handle = ws.put(name.clone());
                *change += entity! { &tag_id @ metadata::name: name_handle };
                self.by_name.insert(name.clone(), tag_ref);
                self.by_id.insert(tag_ref, name);
                ids.push(tag_ref);
            }
        }
        Ok(ids)
    }
}

// ── triblespace query helpers ──────────────────────────────────────────────

/// Check if an ID is a version entity (has KIND_VERSION tag).
fn is_version(space: &TribleSet, id: Id) -> bool {
    exists!(
        (frag: Id),
        pattern!(space, [{ id @ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag }])
    )
}

/// Get the fragment ID that a version belongs to.
fn version_fragment(space: &TribleSet, version_id: Id) -> Option<Id> {
    find!(
        (frag: Id),
        pattern!(space, [{ version_id @ wiki::fragment: ?frag }])
    )
    .next()
    .map(|(frag,)| frag)
}

/// Find the latest version ID for a fragment (by created_at).
fn latest_version_of(space: &TribleSet, fragment_id: Id) -> Option<Id> {
    find!(
        (vid: Id, ts: Value<valueschemas::NsTAIInterval>),
        pattern!(space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki::fragment: &fragment_id,
            wiki::created_at: ?ts,
        }])
    )
    .max_by_key(|(_, ts)| interval_key(*ts))
    .map(|(vid, _)| vid)
}

/// All version IDs of a fragment, sorted oldest-first.
fn version_history_of(space: &TribleSet, fragment_id: Id) -> Vec<Id> {
    let mut versions: Vec<(Id, i128)> = find!(
        (vid: Id, ts: Value<valueschemas::NsTAIInterval>),
        pattern!(space, [{
            ?vid @
            metadata::tag: &KIND_VERSION_ID,
            wiki::fragment: &fragment_id,
            wiki::created_at: ?ts,
        }])
    )
    .map(|(vid, ts)| (vid, interval_key(ts)))
    .collect();
    versions.sort_by_key(|(_, ts)| *ts);
    versions.into_iter().map(|(vid, _)| vid).collect()
}

/// Read title string for a version entity.
fn read_title(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    vid: Id,
) -> Option<String> {
    let (h,) = find!(
        (h: TextHandle),
        pattern!(space, [{ vid @ wiki::title: ?h }])
    )
    .next()?;
    let view: View<str> = ws.get(h).ok()?;
    Some(view.as_ref().to_string())
}

/// Get the content handle for a version entity.
fn content_handle_of(space: &TribleSet, vid: Id) -> Option<TextHandle> {
    find!(
        (h: TextHandle),
        pattern!(space, [{ vid @ wiki::content: ?h }])
    )
    .next()
    .map(|(h,)| h)
}

/// Get created_at timestamp for a version entity.
fn created_at_of(space: &TribleSet, vid: Id) -> Option<i128> {
    find!(
        (ts: Value<valueschemas::NsTAIInterval>),
        pattern!(space, [{ vid @ wiki::created_at: ?ts }])
    )
    .next()
    .map(|(ts,)| interval_key(ts))
}

/// Get tags for a version entity (excluding KIND_VERSION).
fn tags_of(space: &TribleSet, vid: Id) -> Vec<Id> {
    find!(
        tag: Id,
        pattern!(space, [{ vid @ metadata::tag: ?tag }])
    )
    .filter(|t| *t != KIND_VERSION_ID)
    .collect()
}

/// Get stored links_to targets for a version entity.
fn links_of(space: &TribleSet, vid: Id) -> Vec<Id> {
    find!(
        target: Id,
        pattern!(space, [{ vid @ wiki::links_to: ?target }])
    )
    .collect()
}

/// Resolve a hex prefix to an ID. Matches both version and fragment IDs.
fn resolve_prefix(space: &TribleSet, input: &str) -> Result<Id> {
    let needle = input.trim().to_lowercase();
    let mut matches = Vec::new();
    let mut seen_frags = std::collections::HashSet::new();
    for (vid, frag) in find!(
        (vid: Id, frag: Id),
        pattern!(space, [{ ?vid @ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag }])
    ) {
        let vid_hex = format!("{vid:x}");
        let frag_hex = format!("{frag:x}");
        if vid_hex.starts_with(&needle) {
            matches.push(vid);
        }
        if seen_frags.insert(frag) && frag_hex.starts_with(&needle) {
            matches.push(frag);
        }
    }
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => bail!("no id matches '{input}'"),
        1 => Ok(matches[0]),
        n => bail!("ambiguous id '{input}' ({n} matches)"),
    }
}

/// Resolve a hex prefix to a fragment ID only (not version IDs).
/// Used for wiki: link resolution where the target is always a fragment.
fn resolve_fragment_prefix(space: &TribleSet, input: &str) -> Result<Id> {
    let needle = input.trim().to_lowercase();
    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (frag,) in find!(
        (frag: Id),
        pattern!(space, [{ _?vid @ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag }])
    ) {
        if seen.insert(frag) {
            let hex = format!("{frag:x}");
            if hex.starts_with(&needle) {
                matches.push(frag);
            }
        }
    }
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => bail!("no fragment matches '{input}'"),
        1 => Ok(matches[0]),
        n => bail!("ambiguous fragment prefix '{input}' ({n} matches)"),
    }
}

/// Parse a full 64-character hex ID. Returns an error for any other input.
fn parse_full_id(input: &str) -> Result<Id> {
    let trimmed = input.trim();
    Id::from_hex(trimmed)
        .ok_or_else(|| anyhow::anyhow!("invalid id '{trimmed}': expected a full 32-char hex id (use `wiki resolve` to expand a prefix)"))
}

/// Given an ID, resolve to the fragment it belongs to.
/// Identity for fragment IDs, lookup for version IDs.
fn to_fragment(space: &TribleSet, id: Id) -> Result<Id> {
    // Try as version first (direct entity lookup, O(1)).
    if let Some(frag) = version_fragment(space, id) {
        return Ok(frag);
    }
    // Check if it's a known fragment (reverse lookup via value index).
    let is_frag = exists!(
        (vid: Id),
        pattern!(space, [{ ?vid @ wiki::fragment: &id }])
    );
    if is_frag {
        return Ok(id);
    }
    bail!("no fragment for id {}", fmt_id(id))
}

/// Human-readable label for a link target (version or fragment).
fn link_label(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: Id,
) -> String {
    if is_version(space, id) {
        let title = read_title(space, ws, id).unwrap_or_else(|| "?".into());
        let frag = version_fragment(space, id);
        let frag_str = frag.map(|f| format!(" of {}", fmt_id(f))).unwrap_or_default();
        format!("{title} [version {}{}]", fmt_id(id), frag_str)
    } else {
        // Fragment — show its latest version's title.
        let title = latest_version_of(space, id)
            .and_then(|vid| read_title(space, ws, vid))
            .unwrap_or_else(|| "?".into());
        format!("{title} ({})", fmt_id(id))
    }
}

// ── helpers ────────────────────────────────────────────────────────────────
fn now_tai() -> Value<valueschemas::NsTAIInterval> {
    let now = Epoch::now().unwrap_or(Epoch::from_unix_seconds(0.0));
    (now, now).to_value()
}

fn interval_key(interval: Value<valueschemas::NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.from_value();
    lower.to_tai_duration().total_nanoseconds()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
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

/// Format TAI nanoseconds as ISO 8601 date (e.g. "2026-03-11").
fn format_date(tai_ns: i128) -> String {
    // Inverse of Duration::total_nanoseconds().
    const NANOS_PER_CENTURY: i128 = 3_155_760_000_000_000_000;
    let centuries = (tai_ns / NANOS_PER_CENTURY) as i16;
    let nanos = (tai_ns % NANOS_PER_CENTURY) as u64;
    let dur = hifitime::Duration::from_parts(centuries, nanos);
    let epoch = Epoch::from_tai_duration(dur);
    Formatter::new(epoch, ISO8601_DATE).to_string()
}

/// Extract `[text](<faculty>:<hex>)` markdown link references from content.
/// Wiki links resolve against the space — the stored ID is whatever matches
/// (could be a fragment or version). External links return faculty + raw hex.
fn extract_references(content: &str, space: &TribleSet) -> (Vec<Id>, Vec<(String, String)>) {
    use regex::Regex;
    // Matches both markdown [text](scheme:hex) and typst #link("scheme:hex")
    let re = Regex::new(r#"(?:\]\(|#link\(")([a-zA-Z_][a-zA-Z0-9_]*):([0-9a-fA-F]{4,})"#).unwrap();

    let mut internal = Vec::new();
    let mut external = Vec::new();
    for caps in re.captures_iter(content) {
        let faculty = &caps[1];
        let hex = &caps[2];
        if faculty == "wiki" {
            if let Ok(id) = resolve_fragment_prefix(space, hex) {
                internal.push(id);
            }
        } else {
            external.push((faculty.to_string(), hex.to_string()));
        }
    }
    internal.sort();
    internal.dedup();
    external.sort();
    external.dedup();
    (internal, external)
}

fn open_repo(path: &Path) -> Result<Repository<Pile<valueschemas::Blake3>>> {
    let mut pile = Pile::<valueschemas::Blake3>::open(path)
        .map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        let _ = pile.close();
        return Err(anyhow::anyhow!("restore pile {}: {err:?}", path.display()));
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

/// Open repo, resolve wiki branch, pull workspace, run closure, close.
fn with_wiki<T>(
    pile: &Path,
    explicit_branch: Option<&str>,
    f: impl FnOnce(
        &mut Repository<Pile<valueschemas::Blake3>>,
        &mut Workspace<Pile<valueschemas::Blake3>>,
    ) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let branch_id = if let Some(hex) = explicit_branch {
        Id::from_hex(hex.trim()).ok_or_else(|| anyhow::anyhow!("invalid branch id '{hex}'"))?
    } else {
        repo.ensure_branch(WIKI_BRANCH_NAME, None)
            .map_err(|e| anyhow::anyhow!("ensure wiki branch: {e:?}"))?
    };
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow::anyhow!("pull wiki workspace: {e:?}"))?;
    let result = f(&mut repo, &mut ws);
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

/// Ensure all built-in tag/kind IDs have metadata::name entries.
fn ensure_tag_vocabulary(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout for tag names: {e:?}"))?;
    let existing: std::collections::HashSet<Id> = find!(
        (kind: Id),
        pattern!(&space, [{ ?kind @ metadata::name: _?handle }])
    )
    .map(|(kind,)| kind)
    .collect();

    let mut change = TribleSet::new();
    for (id, label) in TAG_SPECS {
        if existing.contains(&id) {
            continue;
        }
        let name_handle = ws.put(label.to_owned());
        change += entity! { ExclusiveId::force_ref(&id) @ metadata::name: name_handle };
    }

    if !change.is_empty() {
        ws.commit(change, "wiki: register tag names");
        repo.push(ws)
            .map_err(|e| anyhow::anyhow!("push tag names: {e:?}"))?;
    }
    Ok(())
}

/// Create a new version entity, commit, and push.
fn commit_version(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    mut change: TribleSet,
    fragment_id: Id,
    title: &str,
    content: TextHandle,
    tags: &[Id],
    space: &TribleSet,
    message: &str,
) -> Result<Id> {
    let mut tag_ids = tags.to_vec();
    tag_ids.push(KIND_VERSION_ID);
    tag_ids.sort();
    tag_ids.dedup();

    // Read content text to extract outgoing wiki links.
    let content_text: View<str> = ws
        .get(content)
        .map_err(|e| anyhow::anyhow!("read content for link extraction: {e:?}"))?;
    let (internal_links, _external) = extract_references(content_text.as_ref(), space);
    let link_targets: Vec<Id> = internal_links
        .into_iter()
        .filter(|&id| id != fragment_id)
        .collect();

    let title_handle = ws.put(title.to_owned());

    let version = entity! { _ @
        wiki::fragment: &fragment_id,
        wiki::title: title_handle,
        wiki::content: content,
        wiki::created_at: now_tai(),
        metadata::tag*: tag_ids.iter(),
        wiki::links_to*: link_targets.iter(),
    };
    let version_id = version.root().expect("version should be rooted");
    change += version;

    ws.commit(change, message);
    repo.push(ws).map_err(|e| anyhow::anyhow!("push: {e:?}"))?;
    Ok(version_id)
}

/// Outgoing and incoming links for an ID (fragment or version).
/// Returns (outgoing targets, incoming sources, external references).
fn find_links(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: Id,
) -> Result<(Vec<Id>, Vec<Id>, Vec<(String, String)>)> {
    // Determine the version to read outgoing links from.
    let vid = if is_version(space, id) {
        id
    } else {
        latest_version_of(space, id)
            .ok_or_else(|| anyhow::anyhow!("no versions for {}", fmt_id(id)))?
    };

    // Outgoing: stored links_to on this version, with content-parse fallback.
    let mut outgoing = links_of(space, vid);
    if outgoing.is_empty() {
        if let Some(ch) = content_handle_of(space, vid) {
            let content: View<str> = ws.get(ch)
                .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
            let (internal, _) = extract_references(content.as_ref(), space);
            outgoing = internal.into_iter().filter(|&t| t != id).collect();
        }
    }
    outgoing.sort();
    outgoing.dedup();

    // Incoming: all entities that link_to this ID (direct conjunctive query).
    let mut incoming: Vec<Id> = find!(
        source: Id,
        pattern!(space, [{ ?source @ wiki::links_to: &id }])
    )
    .collect();
    // Also check for links to the fragment if id is a version (or vice versa).
    if is_version(space, id) {
        if let Some(frag) = version_fragment(space, id) {
            for s in find!(
                source: Id,
                pattern!(space, [{ ?source @ wiki::links_to: &frag }])
            ) {
                incoming.push(s);
            }
        }
    } else {
        // id is a fragment — also collect links to any of its versions.
        for vid in version_history_of(space, id) {
            for s in find!(
                source: Id,
                pattern!(space, [{ ?source @ wiki::links_to: &vid }])
            ) {
                incoming.push(s);
            }
        }
    }
    incoming.sort();
    incoming.dedup();

    // External references parsed from content.
    let mut external = Vec::new();
    if let Some(ch) = content_handle_of(space, vid) {
        let content: View<str> = ws.get(ch)
            .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
        let (_, ext) = extract_references(content.as_ref(), space);
        external = ext;
    }

    Ok((outgoing, incoming, external))
}

/// Determine the version to display for a given ID.
/// If `follow_latest` is true and id is a version, jump to the latest version
/// of its fragment instead.
fn resolve_to_show(space: &TribleSet, id: Id, follow_latest: bool) -> Result<Id> {
    if is_version(space, id) {
        if follow_latest {
            let frag = version_fragment(space, id)
                .ok_or_else(|| anyhow::anyhow!("version has no fragment"))?;
            latest_version_of(space, frag)
                .ok_or_else(|| anyhow::anyhow!("no versions for fragment"))
        } else {
            Ok(id)
        }
    } else {
        // Fragment — always show latest version.
        latest_version_of(space, id)
            .ok_or_else(|| anyhow::anyhow!("no versions for {}", fmt_id(id)))
    }
}

// ── commands ───────────────────────────────────────────────────────────────

fn cmd_resolve(pile: &Path, branch: Option<&str>, prefix: String) -> Result<()> {
    with_wiki(pile, branch, |_repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let id = resolve_fragment_prefix(&space, &prefix)?;
        println!("{}", fmt_id(id));
        Ok(())
    })
}

fn cmd_create(
    pile: &Path,
    branch: Option<&str>,
    title: String,
    content: String,
    tags: Vec<String>,
) -> Result<()> {
    let title = load_value_or_file(&title, "title")?;
    let content = load_value_or_file(&content, "content")?;

    with_wiki(pile, branch, |repo, ws| {
        ensure_tag_vocabulary(repo, ws)?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let mut change = TribleSet::new();
        let mut tag_index = TagIndex::load(ws)?;
        let tag_ids = tag_index.resolve_or_mint(&tags, &mut change, ws)?;

        let fragment_id = genid().id;
        let content_handle = ws.put(content);
        let vid = commit_version(
            repo, ws, change, fragment_id, &title, content_handle, &tag_ids, &space, "wiki create",
        )?;

        println!("fragment {}", fmt_id(fragment_id));
        println!("version  {}", fmt_id(vid));
        Ok(())
    })
}

fn cmd_edit(
    pile: &Path,
    branch: Option<&str>,
    id: String,
    content: Option<String>,
    new_title: Option<String>,
    tags: Vec<String>,
) -> Result<()> {
    let content = content.map(|c| load_value_or_file(&c, "content")).transpose()?;
    let new_title = new_title.map(|t| load_value_or_file(&t, "title")).transpose()?;
    if content.is_none() && new_title.is_none() && tags.is_empty() {
        bail!("nothing to change — provide content, --title, or --tag");
    }

    let resolved = parse_full_id(&id)?;
    with_wiki(pile, branch, |repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let fragment_id = to_fragment(&space, resolved)?;
        let prev_vid = latest_version_of(&space, fragment_id)
            .ok_or_else(|| anyhow::anyhow!("no versions for fragment {}", fmt_id(fragment_id)))?;

        ensure_tag_vocabulary(repo, ws)?;
        let mut change = TribleSet::new();
        let mut tag_index = TagIndex::load(ws)?;
        let tag_ids = if tags.is_empty() {
            tags_of(&space, prev_vid)
        } else {
            tag_index.resolve_or_mint(&tags, &mut change, ws)?
        };

        let title = new_title.unwrap_or_else(|| {
            read_title(&space, ws, prev_vid).unwrap_or_default()
        });
        let content_handle = match content {
            Some(text) => ws.put(text),
            None => content_handle_of(&space, prev_vid)
                .ok_or_else(|| anyhow::anyhow!("no content on previous version"))?,
        };
        let vid = commit_version(
            repo, ws, change, fragment_id, &title, content_handle, &tag_ids, &space, "wiki edit",
        )?;

        println!("fragment {}", fmt_id(fragment_id));
        println!("version  {}", fmt_id(vid));
        Ok(())
    })
}

fn cmd_show(pile: &Path, branch: Option<&str>, id: String, follow_latest: bool) -> Result<()> {
    let parsed_id = parse_full_id(&id)?;
    with_wiki(pile, branch, |_repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let tag_index = TagIndex::load(ws)?;
        let vid = resolve_to_show(&space, parsed_id, follow_latest)?;
        let fragment_id = version_fragment(&space, vid)
            .ok_or_else(|| anyhow::anyhow!("version has no fragment"))?;

        let content_h = content_handle_of(&space, vid)
            .ok_or_else(|| anyhow::anyhow!("no content"))?;
        let content: View<str> = ws.get(content_h)
            .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
        let title = read_title(&space, ws, vid).unwrap_or_default();
        let tags = tags_of(&space, vid);
        let created_at = created_at_of(&space, vid).unwrap_or(0);

        println!("# {title}");
        println!(
            "fragment: {}  version: {}  date: {}",
            fmt_id(fragment_id), fmt_id(vid), format_date(created_at),
        );
        let tag_str = tag_index.format_tags(&tags);
        if !tag_str.is_empty() {
            println!("tags:{tag_str}");
        }
        println!();
        print!("{}", content.as_ref());

        let (outgoing, incoming, external) = find_links(&space, ws, fragment_id)?;
        if !outgoing.is_empty() || !incoming.is_empty() || !external.is_empty() {
            println!("\n---");
        }
        for target in &outgoing {
            let label = link_label(&space, ws, *target);
            println!("→ {label}");
        }
        for source in &incoming {
            let label = link_label(&space, ws, *source);
            println!("← {label}");
        }
        for (faculty, hex) in &external {
            println!("⇢ {faculty}:{hex}");
        }

        Ok(())
    })
}

fn cmd_export(pile: &Path, branch: Option<&str>, id: String) -> Result<()> {
    let parsed_id = parse_full_id(&id)?;
    with_wiki(pile, branch, |_repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let vid = resolve_to_show(&space, parsed_id, false)?;
        let ch = content_handle_of(&space, vid)
            .ok_or_else(|| anyhow::anyhow!("no content"))?;
        let content: View<str> = ws.get(ch)
            .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
        print!("{}", content.as_ref());
        Ok(())
    })
}

fn cmd_diff(
    pile: &Path,
    branch: Option<&str>,
    id: String,
    from: Option<usize>,
    to: Option<usize>,
) -> Result<()> {
    let resolved = parse_full_id(&id)?;
    with_wiki(pile, branch, |_repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let tag_index = TagIndex::load(ws)?;
        let fragment_id = to_fragment(&space, resolved)?;
        let history = version_history_of(&space, fragment_id);
        let n = history.len();
        if n < 2 {
            bail!(
                "fragment {} has only {n} version(s), need at least 2 to diff",
                fmt_id(fragment_id)
            );
        }

        let from_idx = from.map(|v| v.saturating_sub(1)).unwrap_or(n - 2);
        let to_idx = to.map(|v| v.saturating_sub(1)).unwrap_or(n - 1);
        if from_idx >= n || to_idx >= n {
            bail!("version index out of range (fragment has {n} versions)");
        }

        let old_vid = history[from_idx];
        let new_vid = history[to_idx];

        let old_ch = content_handle_of(&space, old_vid).ok_or_else(|| anyhow::anyhow!("no content"))?;
        let new_ch = content_handle_of(&space, new_vid).ok_or_else(|| anyhow::anyhow!("no content"))?;
        let old_content: View<str> = ws.get(old_ch).map_err(|e| anyhow::anyhow!("read old content: {e:?}"))?;
        let new_content: View<str> = ws.get(new_ch).map_err(|e| anyhow::anyhow!("read new content: {e:?}"))?;

        let old_title = read_title(&space, ws, old_vid).unwrap_or_default();
        let new_title = read_title(&space, ws, new_vid).unwrap_or_default();

        println!("--- v{} {}  {}", from_idx + 1, fmt_id(old_vid), old_title);
        println!("+++ v{} {}  {}", to_idx + 1, fmt_id(new_vid), new_title);

        let old_tags = tag_index.format_tags(&tags_of(&space, old_vid));
        let new_tags = tag_index.format_tags(&tags_of(&space, new_vid));
        if old_tags != new_tags {
            println!("- tags:{old_tags}");
            println!("+ tags:{new_tags}");
        }

        let old_lines: Vec<&str> = old_content.as_ref().lines().collect();
        let new_lines: Vec<&str> = new_content.as_ref().lines().collect();
        let hunks = unified_diff(&old_lines, &new_lines, 3);

        if hunks.is_empty() && old_tags == new_tags && old_title == new_title {
            println!("(no changes)");
        }
        for line in hunks {
            println!("{line}");
        }

        Ok(())
    })
}

fn cmd_archive(pile: &Path, branch: Option<&str>, id: String) -> Result<()> {
    let resolved = parse_full_id(&id)?;
    with_wiki(pile, branch, |repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let fragment_id = to_fragment(&space, resolved)?;
        let prev_vid = latest_version_of(&space, fragment_id)
            .ok_or_else(|| anyhow::anyhow!("no versions for fragment {}", fmt_id(fragment_id)))?;
        let prev_tags = tags_of(&space, prev_vid);
        let prev_title = read_title(&space, ws, prev_vid).unwrap_or_default();

        if prev_tags.contains(&TAG_ARCHIVED_ID) {
            println!("already archived: {} ({})", prev_title, fmt_id(fragment_id));
            return Ok(());
        }

        ensure_tag_vocabulary(repo, ws)?;
        let mut tags = prev_tags;
        tags.push(TAG_ARCHIVED_ID);
        let prev_ch = content_handle_of(&space, prev_vid)
            .ok_or_else(|| anyhow::anyhow!("no content"))?;
        commit_version(
            repo, ws, TribleSet::new(), fragment_id, &prev_title, prev_ch, &tags,
            &space, "wiki archive",
        )?;

        println!("archived: {} ({})", prev_title, fmt_id(fragment_id));
        Ok(())
    })
}

fn cmd_restore(pile: &Path, branch: Option<&str>, id: String) -> Result<()> {
    let resolved = parse_full_id(&id)?;
    with_wiki(pile, branch, |repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let fragment_id = to_fragment(&space, resolved)?;
        let prev_vid = latest_version_of(&space, fragment_id)
            .ok_or_else(|| anyhow::anyhow!("no versions for fragment {}", fmt_id(fragment_id)))?;
        let prev_tags = tags_of(&space, prev_vid);
        let prev_title = read_title(&space, ws, prev_vid).unwrap_or_default();

        if !prev_tags.contains(&TAG_ARCHIVED_ID) {
            println!("not archived: {} ({})", prev_title, fmt_id(fragment_id));
            return Ok(());
        }

        let tags: Vec<Id> = prev_tags.into_iter().filter(|t| *t != TAG_ARCHIVED_ID).collect();
        let prev_ch = content_handle_of(&space, prev_vid)
            .ok_or_else(|| anyhow::anyhow!("no content"))?;
        commit_version(
            repo, ws, TribleSet::new(), fragment_id, &prev_title, prev_ch, &tags,
            &space, "wiki restore",
        )?;

        println!("restored: {} ({})", prev_title, fmt_id(fragment_id));
        Ok(())
    })
}

fn cmd_revert(pile: &Path, branch: Option<&str>, id: String, to: usize) -> Result<()> {
    if to == 0 {
        bail!("version number is 1-based");
    }

    let resolved = parse_full_id(&id)?;
    with_wiki(pile, branch, |repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let fragment_id = to_fragment(&space, resolved)?;
        let history = version_history_of(&space, fragment_id);

        let idx = to - 1;
        if idx >= history.len() {
            bail!(
                "fragment {} has {} version(s), cannot revert to v{to}",
                fmt_id(fragment_id), history.len(),
            );
        }

        let target_vid = history[idx];
        let target_title = read_title(&space, ws, target_vid).unwrap_or_default();
        let target_ch = content_handle_of(&space, target_vid)
            .ok_or_else(|| anyhow::anyhow!("no content"))?;
        let target_tags = tags_of(&space, target_vid);
        let vid = commit_version(
            repo, ws, TribleSet::new(), fragment_id, &target_title, target_ch,
            &target_tags, &space, "wiki revert",
        )?;

        println!("reverted {} ({}) to v{to}: {}", fmt_id(fragment_id), fmt_id(vid), target_title);
        Ok(())
    })
}

fn cmd_links(pile: &Path, branch: Option<&str>, id: String) -> Result<()> {
    let resolved = parse_full_id(&id)?;
    with_wiki(pile, branch, |_repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let title = if is_version(&space, resolved) {
            read_title(&space, ws, resolved).unwrap_or_else(|| "?".into())
        } else {
            latest_version_of(&space, resolved)
                .and_then(|vid| read_title(&space, ws, vid))
                .unwrap_or_else(|| "?".into())
        };
        let (outgoing, incoming, external) = find_links(&space, ws, resolved)?;

        println!("# Links for: {} ({})", title, fmt_id(resolved));

        if !outgoing.is_empty() {
            println!("\n→ outgoing:");
            for target in &outgoing {
                println!("  → {}", link_label(&space, ws, *target));
            }
        }
        if !incoming.is_empty() {
            println!("\n← incoming:");
            for source in &incoming {
                println!("  ← {}", link_label(&space, ws, *source));
            }
        }
        if !external.is_empty() {
            println!("\n⇢ external:");
            for (faculty, hex) in &external {
                println!("  ⇢ {faculty}:{hex}");
            }
        }
        if outgoing.is_empty() && incoming.is_empty() && external.is_empty() {
            println!("\n(no links)");
        }

        Ok(())
    })
}

fn cmd_list(
    pile: &Path,
    branch: Option<&str>,
    filter_tags: Vec<String>,
    show_all: bool,
) -> Result<()> {
    with_wiki(pile, branch, |_repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let tag_index = TagIndex::load(ws)?;

        let filter_ids: Vec<Id> = filter_tags
            .iter()
            .filter_map(|name| {
                let name = name.trim().to_lowercase();
                tag_index.by_name.get(&name).copied()
            })
            .collect();

        // Build latest version per fragment in a single pass.
        let mut latest: HashMap<Id, (Id, i128)> = HashMap::new(); // frag -> (vid, created_at)
        for (vid, frag, ts) in find!(
            (vid: Id, frag: Id, ts: Value<valueschemas::NsTAIInterval>),
            pattern!(&space, [{
                ?vid @ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag, wiki::created_at: ?ts,
            }])
        ) {
            let ts_key = interval_key(ts);
            let entry = latest.entry(frag).or_insert((vid, ts_key));
            if ts_key > entry.1 {
                *entry = (vid, ts_key);
            }
        }

        let mut entries: Vec<(Id, Id, i128)> = latest.into_iter()
            .map(|(frag, (vid, ts))| (frag, vid, ts))
            .collect();
        entries.sort_by(|a, b| b.2.cmp(&a.2));

        for (frag_id, vid, created_at) in &entries {
            let tags = tags_of(&space, *vid);
            if !show_all && tags.contains(&TAG_ARCHIVED_ID) {
                continue;
            }
            if !filter_ids.is_empty() && !filter_ids.iter().all(|ft| tags.contains(ft)) {
                continue;
            }

            let title = read_title(&space, ws, *vid).unwrap_or_default();
            let tag_str = tag_index.format_tags(&tags);
            let n_versions = version_history_of(&space, *frag_id).len();
            let ver_str = if n_versions > 1 {
                format!(" (v{})", n_versions)
            } else {
                String::new()
            };

            println!(
                "{}  {}  {}{}{}",
                fmt_id(*frag_id), format_date(*created_at), title, tag_str, ver_str,
            );

            if let Some(ch) = content_handle_of(&space, *vid) {
                if let Ok(view) = ws.get(ch) {
                    let view: View<str> = view;
                    if let Some(line) = view.as_ref().lines().find(|l| !l.trim().is_empty()) {
                        let preview = line.trim();
                        let truncated: String = preview.chars().take(77).collect();
                        if truncated.len() < preview.len() {
                            println!("    {truncated}...");
                        } else {
                            println!("    {preview}");
                        }
                    }
                }
            }
        }
        Ok(())
    })
}

fn cmd_history(pile: &Path, branch: Option<&str>, id: String) -> Result<()> {
    let resolved = parse_full_id(&id)?;
    with_wiki(pile, branch, |_repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let tag_index = TagIndex::load(ws)?;
        let fragment_id = to_fragment(&space, resolved)?;
        let history = version_history_of(&space, fragment_id);

        let latest_title = history.last()
            .and_then(|vid| read_title(&space, ws, *vid))
            .unwrap_or_else(|| "?".into());
        println!("# History: {} ({})", latest_title, fmt_id(fragment_id));
        println!();

        for (i, vid) in history.iter().enumerate() {
            let title = read_title(&space, ws, *vid).unwrap_or_default();
            let ts = created_at_of(&space, *vid).unwrap_or(0);
            let tags = tags_of(&space, *vid);
            println!(
                "  v{}  {}  {}  {}{}",
                i + 1, fmt_id(*vid), format_date(ts), title, tag_index.format_tags(&tags),
            );
        }
        Ok(())
    })
}

fn cmd_tag_add(pile: &Path, branch: Option<&str>, id: String, name: String) -> Result<()> {
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        bail!("tag name cannot be empty");
    }
    let resolved = parse_full_id(&id)?;

    with_wiki(pile, branch, |repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let fragment_id = to_fragment(&space, resolved)?;
        let prev_vid = latest_version_of(&space, fragment_id)
            .ok_or_else(|| anyhow::anyhow!("no versions for fragment {}", fmt_id(fragment_id)))?;

        ensure_tag_vocabulary(repo, ws)?;
        let mut change = TribleSet::new();
        let mut tag_index = TagIndex::load(ws)?;
        let new_tag = tag_index.resolve_or_mint(&[name.clone()], &mut change, ws)?[0];

        let prev_tags = tags_of(&space, prev_vid);
        if prev_tags.contains(&new_tag) {
            println!("already tagged: #{name}");
            return Ok(());
        }

        let mut tags = prev_tags;
        tags.push(new_tag);
        let prev_title = read_title(&space, ws, prev_vid).unwrap_or_default();
        let prev_ch = content_handle_of(&space, prev_vid)
            .ok_or_else(|| anyhow::anyhow!("no content"))?;
        commit_version(
            repo, ws, change, fragment_id, &prev_title, prev_ch, &tags,
            &space, "wiki tag add",
        )?;

        println!("added #{name} to {} ({})", prev_title, fmt_id(fragment_id));
        Ok(())
    })
}

fn cmd_tag_remove(pile: &Path, branch: Option<&str>, id: String, name: String) -> Result<()> {
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        bail!("tag name cannot be empty");
    }
    let resolved = parse_full_id(&id)?;

    with_wiki(pile, branch, |repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let fragment_id = to_fragment(&space, resolved)?;
        let prev_vid = latest_version_of(&space, fragment_id)
            .ok_or_else(|| anyhow::anyhow!("no versions for fragment {}", fmt_id(fragment_id)))?;

        let tag_index = TagIndex::load(ws)?;
        let tag_id = tag_index.by_name.get(&name)
            .ok_or_else(|| anyhow::anyhow!("unknown tag '{name}'"))?;
        let prev_tags = tags_of(&space, prev_vid);
        if !prev_tags.contains(tag_id) {
            println!("not tagged: #{name}");
            return Ok(());
        }

        let tags: Vec<Id> = prev_tags.into_iter().filter(|t| t != tag_id).collect();
        let prev_title = read_title(&space, ws, prev_vid).unwrap_or_default();
        let prev_ch = content_handle_of(&space, prev_vid)
            .ok_or_else(|| anyhow::anyhow!("no content"))?;
        commit_version(
            repo, ws, TribleSet::new(), fragment_id, &prev_title, prev_ch, &tags,
            &space, "wiki tag remove",
        )?;

        println!("removed #{name} from {} ({})", prev_title, fmt_id(fragment_id));
        Ok(())
    })
}

fn cmd_tag_list(pile: &Path, branch: Option<&str>) -> Result<()> {
    with_wiki(pile, branch, |_repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let tag_index = TagIndex::load(ws)?;

        let mut counts: HashMap<Id, usize> = HashMap::new();
        for (tag_id,) in find!(
            (tag_id: Id),
            pattern!(&space, [{ _?vid @ metadata::tag: &KIND_VERSION_ID, metadata::tag: ?tag_id }])
        ) {
            if tag_id != KIND_VERSION_ID {
                *counts.entry(tag_id).or_default() += 1;
            }
        }

        let mut entries: Vec<(String, Id, usize)> = tag_index
            .by_name
            .iter()
            .map(|(name, &id)| (name.clone(), id, counts.get(&id).copied().unwrap_or(0)))
            .collect();
        entries.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));

        for (name, id, count) in entries {
            println!("{}  {}  ({})", fmt_id(id), name, count);
        }
        Ok(())
    })
}

fn cmd_tag_mint(pile: &Path, branch: Option<&str>, name: String) -> Result<()> {
    let name = name.trim().to_lowercase();
    if name.is_empty() {
        bail!("tag name cannot be empty");
    }

    with_wiki(pile, branch, |repo, ws| {
        let tag_index = TagIndex::load(ws)?;
        if let Some(&existing) = tag_index.by_name.get(&name) {
            println!("tag '{}' already exists: {}", name, fmt_id(existing));
            return Ok(());
        }

        let tag_id = genid();
        let tag_ref = tag_id.id;
        let name_handle = ws.put(name.clone());
        let mut change = TribleSet::new();
        change += entity! { &tag_id @ metadata::name: name_handle };

        ws.commit(change, "wiki mint tag");
        repo.push(ws)
            .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;

        println!("{}  {}", fmt_id(tag_ref), name);
        Ok(())
    })
}

fn cmd_import(pile: &Path, branch: Option<&str>, path: PathBuf, tags: Vec<String>) -> Result<()> {
    let files = if path.is_dir() {
        let mut entries: Vec<PathBuf> = Vec::new();
        collect_md_files(&path, &mut entries)?;
        entries.sort();
        entries
    } else {
        vec![path]
    };

    if files.is_empty() {
        println!("no .md files found");
        return Ok(());
    }

    with_wiki(pile, branch, |repo, ws| {
        ensure_tag_vocabulary(repo, ws)?;
        let mut tag_index = TagIndex::load(ws)?;
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

        for file in &files {
            let content = fs::read_to_string(file)
                .with_context(|| format!("read {}", file.display()))?;

            let title = content
                .lines()
                .find(|l| l.starts_with("# "))
                .map(|l| l.trim_start_matches('#').trim().to_string())
                .unwrap_or_else(|| {
                    file.file_stem()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                });

            let mut change = TribleSet::new();
            let tag_ids = tag_index.resolve_or_mint(&tags, &mut change, ws)?;
            let fragment_id = genid().id;
            let content_handle = ws.put(content);
            let vid = commit_version(
                repo, ws, change, fragment_id, &title, content_handle, &tag_ids, &space, "wiki import",
            )?;

            println!("{}  {}  {}", fmt_id(fragment_id), fmt_id(vid), file.display());
        }

        Ok(())
    })
}

fn collect_md_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_md_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
    Ok(())
}

fn cmd_search(
    pile: &Path,
    branch: Option<&str>,
    query: String,
    show_context: bool,
    show_all: bool,
) -> Result<()> {
    let query_lower = query.to_lowercase();

    with_wiki(pile, branch, |_repo, ws| {
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let tag_index = TagIndex::load(ws)?;

        // Build latest version per fragment.
        let mut latest: HashMap<Id, (Id, i128)> = HashMap::new();
        for (vid, frag, ts) in find!(
            (vid: Id, frag: Id, ts: Value<valueschemas::NsTAIInterval>),
            pattern!(&space, [{
                ?vid @ metadata::tag: &KIND_VERSION_ID, wiki::fragment: ?frag, wiki::created_at: ?ts,
            }])
        ) {
            let ts_key = interval_key(ts);
            let entry = latest.entry(frag).or_insert((vid, ts_key));
            if ts_key > entry.1 {
                *entry = (vid, ts_key);
            }
        }

        let mut hits: Vec<(Id, Id, i128, String, Vec<Id>, Vec<String>)> = Vec::new();

        for (&frag_id, &(vid, created_at)) in &latest {
            let tags = tags_of(&space, vid);
            if !show_all && tags.contains(&TAG_ARCHIVED_ID) {
                continue;
            }
            let title = read_title(&space, ws, vid).unwrap_or_default();
            let ch = match content_handle_of(&space, vid) {
                Some(ch) => ch,
                None => continue,
            };
            let content: View<str> = ws.get(ch)
                .map_err(|e| anyhow::anyhow!("read content: {e:?}"))?;
            let content_str = content.as_ref();

            let title_match = title.to_lowercase().contains(&query_lower);
            let content_lower = content_str.to_lowercase();
            let content_match = content_lower.contains(&query_lower);

            if title_match || content_match {
                let mut context_lines = Vec::new();
                if show_context && content_match {
                    for line in content_str.lines() {
                        if line.to_lowercase().contains(&query_lower) {
                            context_lines.push(line.to_string());
                        }
                    }
                }
                hits.push((frag_id, vid, created_at, title, tags, context_lines));
            }
        }

        hits.sort_by(|a, b| b.2.cmp(&a.2));

        if hits.is_empty() {
            println!("no matches for '{query}'");
            return Ok(());
        }

        for (frag_id, _vid, created_at, title, tags, context_lines) in &hits {
            println!(
                "{}  {}  {}{}",
                fmt_id(*frag_id), format_date(*created_at), title, tag_index.format_tags(tags),
            );
            for line in context_lines {
                println!("    {}", line.trim());
            }
        }

        Ok(())
    })
}

// ── diff engine ────────────────────────────────────────────────────────────

enum DiffOp<'a> {
    Equal(&'a str),
    Add(&'a str),
    Remove(&'a str),
}

/// Produce unified-style diff lines with `context` lines of surrounding context.
fn unified_diff<'a>(old: &[&'a str], new: &[&'a str], context: usize) -> Vec<String> {
    let table = lcs_table(old, new);

    // Walk LCS table backwards to produce diff ops.
    let mut ops: Vec<DiffOp<'a>> = Vec::new();
    let (mut i, mut j) = (old.len(), new.len());
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            ops.push(DiffOp::Equal(old[i - 1]));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || table[i][j - 1] >= table[i - 1][j]) {
            ops.push(DiffOp::Add(new[j - 1]));
            j -= 1;
        } else {
            ops.push(DiffOp::Remove(old[i - 1]));
            i -= 1;
        }
    }
    ops.reverse();

    // Mark which ops are near a change and should be shown.
    let change_indices: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| !std::matches!(op, DiffOp::Equal(_)))
        .map(|(i, _)| i)
        .collect();

    if change_indices.is_empty() {
        return Vec::new();
    }

    let mut shown = vec![false; ops.len()];
    for &ci in &change_indices {
        let start = ci.saturating_sub(context);
        let end = (ci + context + 1).min(ops.len());
        for idx in start..end {
            shown[idx] = true;
        }
    }

    let mut lines = Vec::new();
    let mut in_hunk = false;
    for (idx, op) in ops.iter().enumerate() {
        if shown[idx] {
            if !in_hunk && idx > 0 {
                lines.push("---".to_string());
            }
            in_hunk = true;
            match op {
                DiffOp::Equal(line) => lines.push(format!(" {line}")),
                DiffOp::Add(line) => lines.push(format!("+{line}")),
                DiffOp::Remove(line) => lines.push(format!("-{line}")),
            }
        } else {
            in_hunk = false;
        }
    }

    lines
}

fn lcs_table(old: &[&str], new: &[&str]) -> Vec<Vec<usize>> {
    let (m, n) = (old.len(), new.len());
    let mut table = vec![vec![0usize; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            table[i][j] = if old[i - 1] == new[j - 1] {
                table[i - 1][j - 1] + 1
            } else {
                table[i - 1][j].max(table[i][j - 1])
            };
        }
    }
    table
}

// ── main ───────────────────────────────────────────────────────────────────
fn main() -> Result<()> {
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        return Ok(());
    };

    let branch = cli.branch_id.as_deref();

    match command {
        Command::Create { title, content, tag } => {
            cmd_create(&cli.pile, branch, title, content, tag)
        }
        Command::Edit {
            id,
            content,
            title,
            tag,
        } => cmd_edit(&cli.pile, branch, id, content, title, tag),
        Command::Show { id, latest } => cmd_show(&cli.pile, branch, id, latest),
        Command::Export { id } => cmd_export(&cli.pile, branch, id),
        Command::Diff { id, from, to } => cmd_diff(&cli.pile, branch, id, from, to),
        Command::Archive { id } => cmd_archive(&cli.pile, branch, id),
        Command::Restore { id } => cmd_restore(&cli.pile, branch, id),
        Command::Revert { id, to } => cmd_revert(&cli.pile, branch, id, to),
        Command::Links { id } => cmd_links(&cli.pile, branch, id),
        Command::List { tag, all } => cmd_list(&cli.pile, branch, tag, all),
        Command::History { id } => cmd_history(&cli.pile, branch, id),
        Command::Tag { command: tag_cmd } => match tag_cmd {
            TagCommand::Add { id, name } => cmd_tag_add(&cli.pile, branch, id, name),
            TagCommand::Remove { id, name } => cmd_tag_remove(&cli.pile, branch, id, name),
            TagCommand::List => cmd_tag_list(&cli.pile, branch),
            TagCommand::Mint { name } => cmd_tag_mint(&cli.pile, branch, name),
        },
        Command::Import { path, tag } => cmd_import(&cli.pile, branch, path, tag),
        Command::Search { query, context, all } => {
            cmd_search(&cli.pile, branch, query, context, all)
        }
        Command::Resolve { prefix } => cmd_resolve(&cli.pile, branch, prefix),
    }
}
