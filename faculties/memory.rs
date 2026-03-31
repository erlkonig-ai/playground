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

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use rand_core::OsRng;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::{attributes, find, id_hex, pattern};
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, GenId, Handle, NsTAIInterval, ShortString};
use triblespace::prelude::*;

const DEFAULT_MEMORY_BRANCH: &str = "memory";
const DEFAULT_COGNITION_BRANCH: &str = "cognition";
const DEFAULT_ARCHIVE_BRANCH: &str = "archive";

const KIND_CHUNK_ID: Id = id_hex!("40E6004417F9B767AFF1F138DE3D3AAC");

mod exec_schema {
    use super::*;
    attributes! {
        "3BB7917C5E41E494FECE36FFE79FEF23" as finished_at: NsTAIInterval;
    }
}

const KIND_EXEC_RESULT: Id = id_hex!("DF7165210F066E84D93E9A430BB0D4BD");

mod archive_schema {
    use super::*;
    attributes! {
        "59FA7C04A43B96F31414D1B4544FAEC2" as created_at: NsTAIInterval;
        "838CC157FFDD37C6AC7CC5A472E43ADB" as author: GenId;
        "E63EE961ABDB1D1BEC0789FDAFFB9501" as author_name: Handle<Blake3, LongString>;
    }
}

mod archive_import_schema {
    use super::*;
    attributes! {
        "E997DCAAF43BAA04790FCB0FA0FBFE3A" as source_format: ShortString;
        "87B587A3906056038FD767F4225274F9" as source_conversation_id: Handle<Blake3, LongString>;
    }
}

const KIND_ARCHIVE_MESSAGE: Id = id_hex!("1A0841C92BBDA0A26EA9A8252D6ECD9B");

mod ctx {
    use super::*;
    attributes! {
        "3292CF0B3B6077991D8ECE6E2973D4B6" as summary: Handle<Blake3, LongString>;
        "4036F38AB05D26764A1E5E456337F399" as created_at: NsTAIInterval;
        "502F7D33822A90366F0F0ADA0556177F" as start_at: NsTAIInterval;
        "DF84E872EB68FBFCA63D760F27FD8A6F" as end_at: NsTAIInterval;
        "9B83D68AECD6888AA9CE95E754494768" as child: GenId;
        "CB97C36A32DEC70E0D1149E7C5D88588" as left: GenId;
        "087D07E3D9D94F0C4E96813C7BC5E74C" as right: GenId;
        "316834CC6B0EA6F073BF5362D67AC530" as about_exec_result: GenId;
        "A4E2B712CA28AB1EED76C34DE72AFA39" as about_archive_message: GenId;
    }
}

#[derive(Parser)]
#[command(
    name = "memory",
    about = "Show compacted context chunks (drill down by narrowing the time range).\n\n\
             Subcommands:\n  \
             memory <from>..<to>              — show best summary covering a time range\n  \
             memory meta <from>..<to>         — show structural metadata for a time range\n  \
             memory create [<range>] <summary> — create a memory chunk\n\n\
             Time format: YYYY-MM-DDTHH:MM:SS..YYYY-MM-DDTHH:MM:SS (TAI)\n\
             Hex id prefixes also accepted as fallback."
)]
struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Optional explicit branch id (hex) to read chunks from (defaults to cognition branch).
    #[arg(long)]
    branch_id: Option<String>,
    /// One or more time ranges / id prefixes to show, or `turn <turn-id>`, or `create [<from>..<to>] <summary>`.
    #[arg(value_name = "ID")]
    ids: Vec<String>,
}

// ── on-demand chunk queries ───────────────────────────────────────────
// Chunks are queried directly from the TribleSet — no pre-materialization.

fn chunk_summary_handle(space: &TribleSet, id: Id) -> Option<Value<Handle<Blake3, LongString>>> {
    find!(h: Value<Handle<Blake3, LongString>>, pattern!(space, [{ id @ ctx::summary: ?h }])).next()
}

fn chunk_start_at(space: &TribleSet, id: Id) -> Option<Value<NsTAIInterval>> {
    find!(v: Value<NsTAIInterval>, pattern!(space, [{ id @ ctx::start_at: ?v }])).next()
}

fn chunk_end_at(space: &TribleSet, id: Id) -> Option<Value<NsTAIInterval>> {
    find!(v: Value<NsTAIInterval>, pattern!(space, [{ id @ ctx::end_at: ?v }])).next()
}

fn chunk_children(space: &TribleSet, id: Id) -> Vec<Id> {
    let mut children: Vec<Id> = Vec::new();
    children.extend(find!(c: Id, pattern!(space, [{ id @ ctx::child: ?c }])));
    children.extend(find!(c: Id, pattern!(space, [{ id @ ctx::left: ?c }])));
    children.extend(find!(c: Id, pattern!(space, [{ id @ ctx::right: ?c }])));
    // Sort children by their start_at time.
    children.sort_by_key(|child_id| {
        chunk_start_at(space, *child_id)
            .map(interval_key)
            .unwrap_or(i128::MAX)
    });
    children.dedup();
    children
}

fn chunk_about_exec_result(space: &TribleSet, id: Id) -> Option<Id> {
    find!(v: Id, pattern!(space, [{ id @ ctx::about_exec_result: ?v }])).next()
}

fn chunk_about_archive_message(space: &TribleSet, id: Id) -> Option<Id> {
    find!(v: Id, pattern!(space, [{ id @ ctx::about_archive_message: ?v }])).next()
}

fn all_chunk_ids(space: &TribleSet) -> Vec<Id> {
    find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_CHUNK_ID }])).collect()
}

// ---------------------------------------------------------------------------
// time-range helpers
// ---------------------------------------------------------------------------

fn format_time_range(start: Epoch, end: Epoch) -> String {
    let (y1, m1, d1, h1, mi1, s1, _) = start.to_gregorian_tai();
    let (y2, m2, d2, h2, mi2, s2, _) = end.to_gregorian_tai();
    format!(
        "{y1:04}-{m1:02}-{d1:02}T{h1:02}:{mi1:02}:{s1:02}..{y2:04}-{m2:02}-{d2:02}T{h2:02}:{mi2:02}:{s2:02}"
    )
}

fn parse_tai_timestamp(s: &str) -> Result<Epoch> {
    // Parse "YYYY-MM-DDTHH:MM:SS"
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        bail!("invalid timestamp: {s}");
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        bail!("invalid timestamp: {s}");
    }
    let y: i32 = date_parts[0].parse().context("year")?;
    let m: u8 = date_parts[1].parse().context("month")?;
    let d: u8 = date_parts[2].parse().context("day")?;
    let hh: u8 = time_parts[0].parse().context("hour")?;
    let mm: u8 = time_parts[1].parse().context("minute")?;
    let ss: u8 = time_parts[2].parse().context("second")?;
    Ok(Epoch::from_gregorian_tai(y, m, d, hh, mm, ss, 0))
}

fn parse_time_range(s: &str) -> Result<(Epoch, Epoch)> {
    let Some((from_str, to_str)) = s.split_once("..") else {
        bail!("invalid time range (expected `from..to`): {s}");
    };
    let from = parse_tai_timestamp(from_str).context("parsing range start")?;
    let to = parse_tai_timestamp(to_str).context("parsing range end")?;
    Ok((from, to))
}

fn epoch_from_interval(interval: Value<NsTAIInterval>) -> Epoch {
    let (lower, _): (Epoch, Epoch) = interval.try_from_value().unwrap();
    lower
}

fn epoch_end_from_interval(interval: Value<NsTAIInterval>) -> Epoch {
    let (_, upper): (Epoch, Epoch) = interval.try_from_value().unwrap();
    upper
}

/// Find the best chunk covering a query time range.
/// Prefers: narrowest chunk that fully contains the query (most specific).
/// Fallback: best partial overlap.
fn find_chunk_by_time_range(
    space: &TribleSet,
    query_start: Epoch,
    query_end: Epoch,
) -> Option<Id> {
    let query_start_ns = query_start.to_tai_duration().total_nanoseconds();
    let query_end_ns = query_end.to_tai_duration().total_nanoseconds();

    let mut best_cover: Option<(Id, i128)> = None;
    let mut best_overlap: Option<(Id, i128)> = None;

    for chunk_id in all_chunk_ids(space) {
        let start_val = chunk_start_at(space, chunk_id);
        let end_val = chunk_end_at(space, chunk_id);
        let (Some(start_v), Some(end_v)) = (start_val, end_val) else { continue };

        let chunk_start = epoch_from_interval(start_v).to_tai_duration().total_nanoseconds();
        let chunk_end = epoch_end_from_interval(end_v).to_tai_duration().total_nanoseconds();

        if chunk_start > query_end_ns || chunk_end < query_start_ns {
            continue;
        }

        if chunk_start <= query_start_ns && chunk_end >= query_end_ns {
            let width = chunk_end - chunk_start;
            match best_cover {
                Some((_, prev_width)) if prev_width <= width => {}
                _ => best_cover = Some((chunk_id, width)),
            }
        }

        let overlap_start = chunk_start.max(query_start_ns);
        let overlap_end = chunk_end.min(query_end_ns);
        let overlap = overlap_end.saturating_sub(overlap_start);
        match best_overlap {
            Some((_, prev_overlap)) if prev_overlap >= overlap => {}
            _ => best_overlap = Some((chunk_id, overlap)),
        }
    }

    best_cover.map(|(id, _)| id).or(best_overlap.map(|(id, _)| id))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.ids.is_empty() {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    }

    // Dispatch to subcommand handlers.
    if cli.ids.first().is_some_and(|value| value == "create") {
        return cmd_create(&cli.pile, &cli.ids[1..]);
    }
    if cli.ids.first().is_some_and(|value| value == "meta") {
        return cmd_meta(&cli.pile, cli.branch_id.as_deref(), &cli.ids[1..]);
    }

    let explicit_branch_id = parse_optional_hex_id(cli.branch_id.as_deref())?;
    with_repo(&cli.pile, |repo| {
        let branch_id = match explicit_branch_id {
            Some(id) => id,
            None => repo
                .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
                .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?,
        };

        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull branch {branch_id:x}: {e:?}"))?;
        let space = ws.checkout(..).context("checkout branch")?;

        if cli.ids.first().is_some_and(|value| value == "turn") {
            if cli.ids.len() != 2 {
                bail!("usage: memory turn <turn-id>");
            }
            return print_turn_facets(&mut ws, &space, &cli.ids[1]);
        }

        let mut first = true;
        for raw in &cli.ids {
            let chunk_id = if raw.contains("..") {
                let (start, end) = parse_time_range(raw)?;
                find_chunk_by_time_range(&space, start, end)
                    .ok_or_else(|| anyhow!("no memory covers range {raw}"))?
            } else {
                match resolve_chunk_id(&space, raw) {
                    Ok(id) => id,
                    Err(err) => {
                        return Err(invalid_memory_id_error(raw, err));
                    }
                }
            };
            if !first {
                println!();
            }
            first = false;
            print_chunk(&mut ws, &space, chunk_id)?;
        }

        Ok(())
    })
}

// ---------------------------------------------------------------------------
// create subcommand
// ---------------------------------------------------------------------------

fn cmd_create(pile_path: &Path, args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!(
            "usage: memory create [<from>..<to>] <summary...>\n\
             \n\
             Create a memory chunk and store it in the pile.\n\
             Scans summary for (memory:<range>) links to infer children.\n\
             An optional time range as the first argument grounds the\n\
             memory in that period. Without it, defaults to now."
        );
    }

    // If the first argument looks like a time range, parse it.
    let mut explicit_range: Option<(Epoch, Epoch)> = None;
    let summary_start_idx;
    if args[0].contains("..") {
        if let Ok(range) = parse_time_range(&args[0]) {
            explicit_range = Some(range);
            summary_start_idx = 1;
        } else {
            summary_start_idx = 0;
        }
    } else {
        summary_start_idx = 0;
    }

    let summary_text: String = args[summary_start_idx..].join(" ");
    if summary_text.is_empty() {
        bail!("summary text is required: memory create [<from>..<to>] <summary...>");
    }

    // Scan summary for (memory:<range>) references.
    let memory_refs = scan_memory_links(&summary_text);

    with_repo(pile_path, |repo| {
        let branch_id = repo
            .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
            .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?;

        // Resolve memory: references against memory branch chunks.
        let mut child_ids: Vec<Id> = Vec::new();
        let mut children_start: Option<Value<NsTAIInterval>> = None;
        let mut children_end: Option<Value<NsTAIInterval>> = None;
        let mut about_exec: Option<(Id, Value<NsTAIInterval>)> = None;
        let mut about_archive: Option<(Id, Value<NsTAIInterval>)> = None;

        if !memory_refs.is_empty() {
            let ctx_catalog = {
                let mut ws = repo
                    .pull(branch_id)
                    .map_err(|e| anyhow!("pull memory branch: {e:?}"))?;
                ws.checkout(..).context("checkout memory branch")?
            };
            for link in &memory_refs {
                let chunk_id = match link {
                    MemoryLink::TimeRange(raw, start, end) => {
                        find_chunk_by_time_range(&ctx_catalog, *start, *end)
                            .ok_or_else(|| anyhow!("memory link (memory:{raw}) does not match any chunk"))?
                    }
                    MemoryLink::HexId(hex) => {
                        resolve_chunk_id(&ctx_catalog, hex)
                            .map_err(|e| anyhow!("memory link (memory:{hex}): {e}"))?
                    }
                };
                child_ids.push(chunk_id);
                // Track union time span of children.
                if let Some(start_v) = chunk_start_at(&ctx_catalog, chunk_id) {
                    match children_start {
                        Some(prev) if interval_key(prev) <= interval_key(start_v) => {}
                        _ => children_start = Some(start_v),
                    }
                }
                if let Some(end_v) = chunk_end_at(&ctx_catalog, chunk_id) {
                    match children_end {
                        Some(prev) if interval_key(prev) >= interval_key(end_v) => {}
                        _ => children_end = Some(end_v),
                    }
                }
            }
        }

        // For memories without children and with a range, resolve provenance.
        if child_ids.is_empty() {
            if let Some((range_start, range_end)) = explicit_range {
                // Try exec branch (cognition).
                if let Ok(exec_bid) = repo.ensure_branch(DEFAULT_COGNITION_BRANCH, None) {
                    if let Some(exec_catalog) = repo.pull(exec_bid)
                        .ok()
                        .and_then(|mut ws| ws.checkout(..).ok())
                    {
                        about_exec = find_exec_by_time_range(&exec_catalog, range_start, range_end);
                    }
                }
                if about_exec.is_none() {
                    // Try archive branch.
                    if let Ok(archive_bid) = repo.ensure_branch(DEFAULT_ARCHIVE_BRANCH, None) {
                        if let Some(archive_catalog) = repo.pull(archive_bid)
                            .ok()
                            .and_then(|mut ws| ws.checkout(..).ok())
                        {
                            about_archive =
                                find_archive_by_time_range(&archive_catalog, range_start, range_end);
                        }
                    }
                }
            }
        }

        // Infer time span.
        let (start_at, end_at) = if let (Some(s), Some(e)) = (children_start, children_end) {
            (s, e)
        } else if let Some((range_start, range_end)) = explicit_range {
            let start_val: Value<NsTAIInterval> = (range_start, range_start).try_to_value().unwrap();
            let end_val: Value<NsTAIInterval> = (range_end, range_end).try_to_value().unwrap();
            (start_val, end_val)
        } else if let Some((_, time)) = about_exec {
            (time, time)
        } else if let Some((_, time)) = about_archive {
            (time, time)
        } else {
            let now = Epoch::now()
                .unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
            let t: Value<NsTAIInterval> = (now, now).try_to_value().unwrap();
            (t, t)
        };

        // Write chunk entity.
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull memory branch for write: {e:?}"))?;

        let summary_handle = ws.put(summary_text.clone());
        let chunk_id = ufoid();
        let now = Epoch::now()
            .unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0));
        let created_at: Value<NsTAIInterval> = (now, now).try_to_value().unwrap();

        let mut change = TribleSet::new();
        change += entity! { &chunk_id @
            metadata::tag: KIND_CHUNK_ID,
            ctx::summary: summary_handle,
            ctx::created_at: created_at,
            ctx::start_at: start_at,
            ctx::end_at: end_at,
        };

        if let Some((exec_id, _)) = about_exec {
            change += entity! { &chunk_id @ ctx::about_exec_result: exec_id };
        }
        if let Some((archive_id, _)) = about_archive {
            change += entity! { &chunk_id @ ctx::about_archive_message: archive_id };
        }
        for child_id in &child_ids {
            change += entity! { &chunk_id @ ctx::child: *child_id };
        }

        ws.commit(change, "memory create");
        repo.push(&mut ws)
            .map_err(|e| anyhow!("push failed: {e:?}"))?;

        let range_str = format_time_range(
            epoch_from_interval(start_at),
            epoch_end_from_interval(end_at),
        );
        println!("range: {range_str}");
        println!("id: {:x}", chunk_id.id);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// meta subcommand
// ---------------------------------------------------------------------------

fn cmd_meta(pile_path: &Path, branch_id_raw: Option<&str>, args: &[String]) -> Result<()> {
    if args.len() != 1 {
        bail!("usage: memory meta <id>");
    }

    let explicit_branch_id = parse_optional_hex_id(branch_id_raw)?;

    with_repo(pile_path, |repo| {
        let branch_id = match explicit_branch_id {
            Some(id) => id,
            None => repo
                .ensure_branch(DEFAULT_MEMORY_BRANCH, None)
                .map_err(|e| anyhow!("ensure memory branch: {e:?}"))?,
        };

        // Load memory branch.
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull branch {branch_id:x}: {e:?}"))?;
        let space = ws.checkout(..).context("checkout branch")?;

        // Resolve chunk (time range or hex fallback).
        let raw = &args[0];
        let chunk_id = if raw.contains("..") {
            let (start, end) = parse_time_range(raw)?;
            find_chunk_by_time_range(&space, start, end)
                .ok_or_else(|| anyhow!("no memory covers range {raw}"))?
        } else {
            resolve_chunk_id(&space, raw)
                .map_err(|e| invalid_memory_id_error(raw, e))?
        };

        // Print structural metadata.
        if let (Some(start_v), Some(end_v)) = (chunk_start_at(&space, chunk_id), chunk_end_at(&space, chunk_id)) {
            let range = format_time_range(
                epoch_from_interval(start_v),
                epoch_end_from_interval(end_v),
            );
            println!("range: {}", range);
        }
        println!("id: {:x}", chunk_id);

        let children = chunk_children(&space, chunk_id);
        if !children.is_empty() {
            let child_ranges: Vec<String> = children
                .iter()
                .filter_map(|cid| {
                    let s = chunk_start_at(&space, *cid)?;
                    let e = chunk_end_at(&space, *cid)?;
                    Some(format_time_range(epoch_from_interval(s), epoch_end_from_interval(e)))
                })
                .collect();
            println!("children: {}", child_ranges.join(", "));
        }

        if let Some(exec_id) = chunk_about_exec_result(&space, chunk_id) {
            println!("about_exec_result: {exec_id:x}");
        }

        if let Some(archive_id) = chunk_about_archive_message(&space, chunk_id) {
            println!("about_archive_message: {archive_id:x}");
            print_archive_meta(repo, &mut ws, archive_id)?;
        }

        Ok(())
    })
}

fn print_archive_meta(
    repo: &mut Repository<Pile<Blake3>>,
    ws: &mut Workspace<Pile<Blake3>>,
    archive_msg_id: Id,
) -> Result<()> {
    let archive_branch_id = match repo.ensure_branch(DEFAULT_ARCHIVE_BRANCH, None) {
        Ok(id) => id,
        Err(_) => return Ok(()),
    };

    // Pull archive branch.
    let archive_catalog = match repo.pull(archive_branch_id) {
        Ok(mut archive_ws) => match archive_ws.checkout(..) {
            Ok(cat) => cat,
            Err(_) => return Ok(()),
        },
        Err(_) => return Ok(()),
    };

    // Author (as id prefix).
    if let Some((author_id,)) = find!(
        (author_id: Id),
        pattern!(&archive_catalog, [{
            archive_msg_id @
            archive_schema::author: ?author_id,
        }])
    ).next() {
        // Try to resolve author name.
        let author_name: Option<String> = find!(
            (name: Value<Handle<Blake3, LongString>>),
            pattern!(&archive_catalog, [{
                archive_msg_id @
                archive_schema::author_name: ?name,
            }])
        ).next().and_then(|(name_handle,)| {
            ws.get::<View<str>, LongString>(name_handle).ok().map(|v| v.as_ref().to_string())
        });
        match author_name {
            Some(name) => println!("  author: {} ({:x})", name, author_id),
            None => println!("  author: {:x}", author_id),
        }
    }

    // Source format.
    if let Some((fmt,)) = find!(
        (fmt: String),
        pattern!(&archive_catalog, [{
            archive_msg_id @
            archive_import_schema::source_format: ?fmt,
        }])
    ).next() {
        println!("  source_format: {}", fmt);
    }

    // Source conversation id.
    if let Some((conv_handle,)) = find!(
        (conv: Value<Handle<Blake3, LongString>>),
        pattern!(&archive_catalog, [{
            archive_msg_id @
            archive_import_schema::source_conversation_id: ?conv,
        }])
    ).next() {
        if let Ok(view) = ws.get::<View<str>, LongString>(conv_handle) {
            println!("  conversation: {}", view.as_ref());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// memory link scanning and time-range entity resolution
// ---------------------------------------------------------------------------

/// A parsed memory link — either a time range or a hex ID prefix.
enum MemoryLink {
    TimeRange(String, Epoch, Epoch),
    HexId(String),
}

/// Scan text for memory references in two formats:
/// - `(memory:<value>)` — legacy parenthesized format
/// - `[text](memory:<value>)` — markdown link format (preferred)
/// Value can be a time range (`from..to`) or a hex ID prefix.
fn scan_memory_links(text: &str) -> Vec<MemoryLink> {
    let mut refs = Vec::new();
    let mut remaining = text;

    // Match both `](memory:` (markdown link) and `(memory:` (legacy).
    // The markdown form `](memory:...)` is a superset — the `(memory:` scan
    // catches both, since `](memory:` contains `(memory:`.
    while let Some(start) = remaining.find("(memory:") {
        let after = &remaining[start + 8..];
        if let Some(end) = after.find(')') {
            let value = after[..end].trim();
            if value.contains("..") {
                if let Ok((from, to)) = parse_time_range(value) {
                    refs.push(MemoryLink::TimeRange(value.to_string(), from, to));
                }
            } else if !value.is_empty()
                && value.chars().all(|c| c.is_ascii_hexdigit())
            {
                refs.push(MemoryLink::HexId(value.to_string()));
            }
        }
        remaining = &remaining[start + 8..];
    }
    refs
}

/// Extract `[text](faculty:<hex>)` markdown link references from text.
/// Returns (faculty, raw_value) pairs for non-memory faculties.
/// Memory links are handled by `scan_memory_links` instead.
#[allow(dead_code)]
fn extract_references(text: &str) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    let mut rest = text;
    while let Some(paren) = rest.find("](") {
        let after = &rest[paren + 2..];
        let end = after.find(')').unwrap_or(after.len());
        let link = &after[..end];
        if let Some(colon) = link.find(':') {
            let faculty = &link[..colon];
            let value = &link[colon + 1..];
            if !faculty.is_empty()
                && faculty
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && faculty != "memory"  // memory links handled separately
                && !value.is_empty()
            {
                refs.push((faculty.to_string(), value.to_string()));
            }
        }
        rest = &after[end.min(after.len()).max(1)..];
    }
    refs.sort();
    refs.dedup();
    refs
}

/// Find the exec result whose finished_at falls within the given time range.
fn find_exec_by_time_range(
    catalog: &TribleSet,
    query_start: Epoch,
    query_end: Epoch,
) -> Option<(Id, Value<NsTAIInterval>)> {
    let qs = query_start.to_tai_duration().total_nanoseconds();
    let qe = query_end.to_tai_duration().total_nanoseconds();
    let mut best: Option<(Id, Value<NsTAIInterval>, i128)> = None;

    for (result_id, finished_at) in find!(
        (result_id: Id, finished_at: Value<NsTAIInterval>),
        pattern!(catalog, [{
            ?result_id @
            metadata::tag: &KIND_EXEC_RESULT,
            exec_schema::finished_at: ?finished_at,
        }])
    ) {
        let t = interval_key(finished_at);
        if t >= qs && t <= qe {
            // Prefer the closest to query_start.
            let dist = (t - qs).abs();
            match best {
                Some((_, _, prev_dist)) if prev_dist <= dist => {}
                _ => best = Some((result_id, finished_at, dist)),
            }
        }
    }
    best.map(|(id, t, _)| (id, t))
}

/// Find the archive message whose created_at falls within the given time range.
fn find_archive_by_time_range(
    catalog: &TribleSet,
    query_start: Epoch,
    query_end: Epoch,
) -> Option<(Id, Value<NsTAIInterval>)> {
    let qs = query_start.to_tai_duration().total_nanoseconds();
    let qe = query_end.to_tai_duration().total_nanoseconds();
    let mut best: Option<(Id, Value<NsTAIInterval>, i128)> = None;

    for (msg_id, created_at) in find!(
        (msg_id: Id, created_at: Value<NsTAIInterval>),
        pattern!(catalog, [{
            ?msg_id @
            metadata::tag: &KIND_ARCHIVE_MESSAGE,
            archive_schema::created_at: ?created_at,
        }])
    ) {
        let t = interval_key(created_at);
        if t >= qs && t <= qe {
            let dist = (t - qs).abs();
            match best {
                Some((_, _, prev_dist)) if prev_dist <= dist => {}
                _ => best = Some((msg_id, created_at, dist)),
            }
        }
    }
    best.map(|(id, t, _)| (id, t))
}

// ---------------------------------------------------------------------------
// show / turn subcommands
// ---------------------------------------------------------------------------


fn print_chunk(ws: &mut Workspace<Pile<Blake3>>, space: &TribleSet, chunk_id: Id) -> Result<()> {
    let handle = chunk_summary_handle(space, chunk_id)
        .ok_or_else(|| anyhow!("chunk {:x} has no summary", chunk_id))?;
    let summary: View<str> = ws.get(handle).context("read chunk summary")?;
    print!("{}", summary.trim_end());
    println!();
    Ok(())
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn resolve_chunk_id(space: &TribleSet, raw: &str) -> Result<Id> {
    let prefix = normalize_prefix(raw)?;

    let mut chunk_matches = Vec::new();
    for chunk_id in all_chunk_ids(space) {
        if id_starts_with(chunk_id, prefix.as_str()) {
            chunk_matches.push(chunk_id);
        }
    }
    match chunk_matches.len() {
        1 => return Ok(chunk_matches[0]),
        n if n > 1 => {
            bail!("multiple chunk ids match prefix '{prefix}' (use a longer prefix)")
        }
        _ => {}
    }

    for chunk_id in all_chunk_ids(space) {
        if let Some(turn_id) = chunk_about_exec_result(space, chunk_id) {
            if id_starts_with(turn_id, prefix.as_str()) {
                bail!("turn id `{prefix}` is not a chunk id; use `memory turn {prefix}`");
            }
        }
    }

    bail!("no chunk id matches prefix '{prefix}'")
}

fn print_turn_facets(ws: &mut Workspace<Pile<Blake3>>, space: &TribleSet, raw: &str) -> Result<()> {
    let prefix = normalize_prefix(raw)?;
    let mut turn_matches = Vec::new();
    for chunk_id in all_chunk_ids(space) {
        if let Some(turn_id) = chunk_about_exec_result(space, chunk_id) {
            if id_starts_with(turn_id, prefix.as_str()) {
                turn_matches.push((turn_id, chunk_id));
            }
        }
    }
    match turn_matches.len() {
        0 => bail!("no turn_id matches prefix '{prefix}'"),
        _ => {}
    }

    turn_matches.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    turn_matches.dedup();

    let first_turn = turn_matches[0].0;
    if turn_matches.iter().any(|(turn_id, _)| *turn_id != first_turn) {
        bail!("multiple turn_id values match prefix '{prefix}' (use a longer prefix)");
    }

    let mut chunk_ids: Vec<Id> = turn_matches.iter().map(|(_, cid)| *cid).collect();
    chunk_ids.sort_unstable_by(|a, b| {
        let a_width = chunk_end_at(space, *a).map(|v| epoch_end_from_interval(v).to_tai_duration().total_nanoseconds()).unwrap_or(0)
            - chunk_start_at(space, *a).map(|v| epoch_from_interval(v).to_tai_duration().total_nanoseconds()).unwrap_or(0);
        let b_width = chunk_end_at(space, *b).map(|v| epoch_end_from_interval(v).to_tai_duration().total_nanoseconds()).unwrap_or(0)
            - chunk_start_at(space, *b).map(|v| epoch_from_interval(v).to_tai_duration().total_nanoseconds()).unwrap_or(0);
        a_width.cmp(&b_width).then(a.cmp(b))
    });

    println!(
        "turn {} has {} memory facet(s)",
        fmt_id(first_turn),
        chunk_ids.len()
    );
    for (i, chunk_id) in chunk_ids.iter().enumerate() {
        if i > 0 {
            println!();
        }
        print_chunk(ws, space, *chunk_id)?;
    }

    Ok(())
}

fn invalid_memory_id_error(raw: &str, cause: anyhow::Error) -> anyhow::Error {
    anyhow!(
        "memory lookup failed for id `{raw}`: {cause}\n\
         hint: that id is wrong here.\n\
         hint: only call `memory <id>` when you want to inspect an id that already appeared in prior output.\n\
         hint: do not guess memory ids or loop lookups; switch to a concrete non-memory action if no valid id is available."
    )
}

// ---------------------------------------------------------------------------
// utilities
// ---------------------------------------------------------------------------

fn normalize_prefix(raw: &str) -> Result<String> {
    let mut prefix = raw.trim().to_ascii_lowercase();
    if let Some(rest) = prefix.strip_prefix("0x") {
        prefix = rest.to_string();
    }
    if prefix.is_empty() {
        bail!("id prefix is empty");
    }
    Ok(prefix)
}

fn id_starts_with(id: Id, prefix: &str) -> bool {
    format!("{id:x}").starts_with(prefix)
}

fn parse_optional_hex_id(raw: Option<&str>) -> Result<Option<Id>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let id = Id::from_hex(trimmed).ok_or_else(|| anyhow!("invalid id {trimmed}"))?;
    Ok(Some(id))
}

fn interval_key(interval: Value<NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_value().unwrap();
    lower.to_tai_duration().total_nanoseconds()
}

fn open_repo(path: &Path) -> Result<Repository<Pile<Blake3>>> {
    let mut pile =
        Pile::<Blake3>::open(path).map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        let _ = pile.close();
        return Err(anyhow!("restore pile {}: {err:?}", path.display()));
    }
    Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .map_err(|err| anyhow!("create repository: {err:?}"))
}

fn with_repo<T>(
    pile: &Path,
    f: impl FnOnce(&mut Repository<Pile<Blake3>>) -> Result<T>,
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
