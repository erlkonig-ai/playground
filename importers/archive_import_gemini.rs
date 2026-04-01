use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use crate::common;
use anyhow::{Context, Result, anyhow};
use hifitime::{Duration, Epoch};
use scraper::{Html, Selector};
use tracing::info_span;
use triblespace::prelude::*;

#[derive(Debug, Default, Clone)]
struct ImportStats {
    files: usize,
    conversations: usize,
    messages: usize,
    commits: usize,
}

#[derive(Debug, Clone)]
struct MessageRecord {
    source_message_id: String,
    role: String,
    author: String,
    content: String,
    created_at: Option<Epoch>,
    order: usize,
}

fn import_gemini_path(
    path: &std::path::Path,
    repo: &mut common::Repo,
    branch_id: Id,
) -> Result<ImportStats> {
    let start = Instant::now();
    println!("gemini phase pull: {}", path.display());
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
    let mut catalog = ws.checkout(..).context("checkout workspace")?.into_facts();
    let mut catalog_head = ws.head();
    println!("gemini phase pull: done in {:?}", start.elapsed());

    if path.is_dir() {
        let scan_start = Instant::now();
        println!("gemini phase scan: {}", path.display());
        let mut files = Vec::new();
        collect_gemini_files(path, &mut files)
            .with_context(|| format!("scan {}", path.display()))?;
        files.sort();
        let total_files = files.len();
        println!(
            "gemini phase scan: found {} html file(s) under {} in {:?}",
            total_files,
            path.display(),
            scan_start.elapsed()
        );
        let parsed_files: Vec<(PathBuf, Result<Vec<MessageRecord>>)> =
            common::parse_paths_parallel("gemini", &files, parse_gemini_file)?;

        let mut total = ImportStats::default();
        for (index, (file, parsed_records)) in parsed_files.into_iter().enumerate() {
            let file_start = Instant::now();
            println!(
                "gemini file {}/{}: {}",
                index + 1,
                total_files,
                file.display()
            );
            let stats = import_gemini_parsed_file(
                file.as_path(),
                parsed_records.with_context(|| format!("parse {}", file.display()))?,
                repo,
                &mut ws,
                &mut catalog,
                &mut catalog_head,
            )
            .with_context(|| format!("import {}", file.display()))?;
            total.files += stats.files;
            total.conversations += stats.conversations;
            total.messages += stats.messages;
            total.commits += stats.commits;
            println!(
                "gemini progress files {}/{} (conversations {}, messages {}, commits {}) in {:?}",
                index + 1,
                total_files,
                total.conversations,
                total.messages,
                total.commits,
                file_start.elapsed()
            );
        }
        return Ok(total);
    }
    let parse_start = Instant::now();
    println!("gemini phase parse: {}", path.display());
    let records = parse_gemini_file(path)?;
    println!(
        "gemini {}: parsed {} activity message(s) in {:?}",
        path.display(),
        records.len(),
        parse_start.elapsed()
    );
    import_gemini_parsed_file(
        path,
        records,
        repo,
        &mut ws,
        &mut catalog,
        &mut catalog_head,
    )
}

fn import_gemini_parsed_file(
    _path: &std::path::Path,
    mut records: Vec<MessageRecord>,
    repo: &mut common::Repo,
    ws: &mut common::Ws,
    catalog: &mut TribleSet,
    catalog_head: &mut Option<common::CommitHandle>,
) -> Result<ImportStats> {
    let mut stats = ImportStats {
        files: 1,
        ..ImportStats::default()
    };

    records.sort_by_key(|r| r.order);
    if records.is_empty() {
        return Ok(stats);
    }
    stats.conversations = 1;
    let conversation_id = build_gemini_conversation_id(&records);

    let mut change = TribleSet::new();
    let mut author_cache: HashMap<String, Id> = HashMap::new();
    let conversation_fragment = entity! { _ @
        common::metadata::tag: common::import_schema::kind_conversation,
        common::import_schema::source_format: "gemini",
        common::import_schema::source_conversation_id: ws.put(conversation_id),
    };
    let conversation_id = conversation_fragment
        .root()
        .expect("entity! must export a single root id");
    change += conversation_fragment;

    let mut previous: Option<(Id, String)> = None;
    let semantic_start = Instant::now();
    let total_records = records.len();
    for (index, message) in records.into_iter().enumerate() {
        let source_message_id_handle = ws.put(message.source_message_id.clone());
        let message_fragment = entity! { _ @
            common::import_schema::conversation: conversation_id,
            common::import_schema::source_message_id: source_message_id_handle,
        };
        let message_id = message_fragment
            .root()
            .expect("entity! must export a single root id");
        let message_entity = message_id
            .aquire()
            .expect("entity! root ids should be acquired in current thread");
        change += message_fragment;
        let author_key = format!("{}::{}", message.author, message.role);
        let author_id = if let Some(id) = author_cache.get(&author_key).copied() {
            id
        } else {
            let (id, author_change) =
                common::ensure_author(ws, catalog, &message.author, &message.role)?;
            change += author_change;
            author_cache.insert(author_key, id);
            id
        };
        let created_at =
            common::epoch_interval(message.created_at.unwrap_or_else(common::unknown_epoch));
        let reply_to = previous.as_ref().map(|(parent_id, _)| *parent_id);
        let source_parent_id = previous
            .as_ref()
            .map(|(_, parent_source_id)| ws.put(parent_source_id.clone()));
        let content_handle = ws.put(message.content.clone());
        change += entity! { &message_entity @
            common::metadata::tag: common::archive::kind_message,
            common::archive::author: author_id,
            common::archive::content: content_handle,
            common::metadata::created_at: created_at,
            common::import_schema::source_author: ws.put(message.author.clone()),
            common::import_schema::source_role: ws.put(message.role.clone()),
            common::import_schema::source_created_at: created_at,
            common::archive::reply_to?: reply_to,
            common::import_schema::source_parent_id?: source_parent_id,
        };
        previous = Some((message_id, message.source_message_id.clone()));
        stats.messages += 1;
        let processed = index + 1;
        if processed % 250 == 0 || processed == total_records {
            println!(
                "gemini progress records {}/{} (messages {}, staged commits {})",
                processed, total_records, stats.messages, stats.commits
            );
        }
    }
    println!(
        "gemini phase semantic-build: {} message(s) in {:?}",
        stats.messages,
        semantic_start.elapsed()
    );

    let commit_start = Instant::now();
    if common::commit_delta(
        repo,
        ws,
        catalog,
        catalog_head,
        change,
        "import gemini",
    )? {
        stats.commits += 1;
    }
    println!(
        "gemini phase semantic-commit: done in {:?} (total commits {})",
        commit_start.elapsed(),
        stats.commits
    );
    Ok(stats)
}

fn parse_gemini_file(path: &std::path::Path) -> Result<Vec<MessageRecord>> {
    let extension = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    if extension != "html" && extension != "htm" {
        return Err(anyhow!(
            "Gemini importer currently supports only HTML exports; got {}",
            path.display()
        ));
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(parse_gemini_activity_html(&raw))
}

fn hash_prefix(input: &str) -> String {
    use triblespace::core::value::schemas::hash::Blake3 as Blake3Hasher;

    let mut hasher = Blake3Hasher::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in digest.as_bytes().iter().take(8) {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn build_gemini_conversation_id(records: &[MessageRecord]) -> String {
    let mut seed = String::from("gemini|");
    for record in records {
        seed.push_str(&record.source_message_id);
        seed.push('|');
    }
    format!("gemini:{}", hash_prefix(seed.as_str()))
}

fn collect_gemini_files(path: &std::path::Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry.context("read dir entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("entry type")?;
        if file_type.is_dir() {
            collect_gemini_files(&entry_path, out)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        match entry_path.extension().and_then(|s| s.to_str()) {
            Some("html") | Some("htm") => out.push(entry_path),
            _ => {}
        }
    }
    Ok(())
}

fn parse_gemini_activity_html(html: &str) -> Vec<MessageRecord> {
    let document = Html::parse_document(html);
    let outer_selector =
        Selector::parse("div.outer-cell.mdl-cell.mdl-cell--12-col.mdl-shadow--2dp")
            .expect("valid Gemini outer-cell selector");
    let left_selector =
        Selector::parse("div.content-cell.mdl-cell.mdl-cell--6-col.mdl-typography--body-1")
            .expect("valid Gemini left-cell selector");

    let mut out = Vec::new();
    let mut index = 0usize;

    for outer in document.select(&outer_selector) {
        let Some(left_cell) = outer.select(&left_selector).find(|cell| {
            let classes = cell.value().attr("class").unwrap_or("");
            !classes
                .split_whitespace()
                .any(|class| class == "mdl-typography--text-right")
        }) else {
            continue;
        };
        let left_html = left_cell.inner_html();
        let left_text = html_to_text(&left_html);
        let lines: Vec<String> = left_text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
        if lines.is_empty() {
            continue;
        }

        let timestamp_idx = lines
            .iter()
            .position(|line| parse_gemini_activity_timestamp(line).is_some());
        let (pre, timestamp, post) = match timestamp_idx {
            Some(idx) => {
                let ts = parse_gemini_activity_timestamp(&lines[idx]);
                (&lines[..idx], ts, &lines[idx + 1..])
            }
            None => (lines.as_slice(), None, &[][..]),
        };

        if pre.is_empty() {
            continue;
        }

        let prompted = pre[0].starts_with("Prompted");
        let mut user_lines = Vec::new();
        for (idx, line) in pre.iter().enumerate() {
            let mut line = line.as_str();
            if idx == 0 && prompted {
                line = line
                    .trim_start_matches("Prompted")
                    .trim_start_matches('\u{00a0}')
                    .trim();
            }
            if is_gemini_meta_line(line) {
                continue;
            }
            if !line.is_empty() {
                user_lines.push(line.to_string());
            }
        }

        let assistant_lines: Vec<String> = post
            .iter()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || is_gemini_meta_line(line) {
                    None
                } else {
                    Some(line.to_string())
                }
            })
            .collect();

        let created_at = timestamp;
        if !user_lines.is_empty() {
            let user_content = user_lines.join("\n");
            out.push(MessageRecord {
                source_message_id: build_activity_source_message_id(
                    "user",
                    created_at,
                    user_content.as_str(),
                    index,
                ),
                role: "user".to_string(),
                author: "user".to_string(),
                content: user_content,
                created_at,
                order: index * 2,
            });
        }
        if !assistant_lines.is_empty() {
            let assistant_content = assistant_lines.join("\n\n");
            out.push(MessageRecord {
                source_message_id: build_activity_source_message_id(
                    "assistant",
                    created_at,
                    assistant_content.as_str(),
                    index,
                ),
                role: "assistant".to_string(),
                author: "assistant".to_string(),
                content: assistant_content,
                created_at,
                order: index * 2 + 1,
            });
        }
        index += 1;
    }

    out
}

fn build_activity_source_message_id(
    role: &str,
    created_at: Option<Epoch>,
    content: &str,
    index: usize,
) -> String {
    let ts = created_at
        .map(|epoch| epoch.to_tai_duration().total_nanoseconds().to_string())
        .unwrap_or_else(|| "-".to_string());
    let seed = format!("activity|{role}|{ts}|{}", content.trim());
    let hash = hash_prefix(seed.as_str());
    format!("activity:{hash}:{index:08}:{role}")
}

fn is_gemini_meta_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.starts_with("Attached ") {
        return true;
    }
    if trimmed.starts_with("- ") {
        return true;
    }
    if trimmed.ends_with(" generated image.") || trimmed.ends_with(" generated images.") {
        return true;
    }
    false
}

fn parse_gemini_activity_timestamp(input: &str) -> Option<Epoch> {
    let text = input.trim();
    let (datetime, tz) = text.rsplit_once(' ')?;
    let (date_part, time_part) = datetime.split_once(", ")?;
    let mut date_tokens = date_part.split_whitespace();
    let day: u8 = date_tokens.next()?.parse().ok()?;
    let month = match date_tokens.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i32 = date_tokens.next()?.parse().ok()?;
    if date_tokens.next().is_some() {
        return None;
    }

    let mut time_tokens = time_part.split(':');
    let hour: u8 = time_tokens.next()?.parse().ok()?;
    let minute: u8 = time_tokens.next()?.parse().ok()?;
    let second: u8 = time_tokens.next()?.parse().ok()?;
    if time_tokens.next().is_some() {
        return None;
    }

    let local = Epoch::from_gregorian_utc(year, month, day, hour, minute, second, 0);
    let offset_hours = match tz {
        "UTC" | "GMT" => 0.0,
        "CET" => 1.0,
        "CEST" => 2.0,
        "PST" => -8.0,
        "PDT" => -7.0,
        "MST" => -7.0,
        "MDT" => -6.0,
        "CST" => -6.0,
        "CDT" => -5.0,
        "EST" => -5.0,
        "EDT" => -4.0,
        _ => return None,
    };
    Some(local - Duration::from_hours(offset_hours))
}

fn html_to_text(input: &str) -> String {
    let mut text = input
        .replace("<br>", "\n")
        .replace("<br/>", "\n")
        .replace("<br />", "\n")
        .replace("</p>", "\n")
        .replace("<p>", "");

    let mut stripped = String::with_capacity(text.len());
    let mut in_tag = false;
    for ch in text.drain(..) {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => stripped.push(ch),
            _ => {}
        }
    }
    decode_html_entities(&stripped)
}

fn decode_html_entities(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        let rest = &input[i..];
        if rest.starts_with('&') {
            if let Some(end_rel) = rest.find(';') {
                let entity = &rest[1..end_rel];
                if let Some(decoded) = decode_entity(entity) {
                    out.push(decoded);
                    i += end_rel + 1;
                    continue;
                }
            }
        }
        if let Some(ch) = rest.chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn decode_entity(entity: &str) -> Option<char> {
    match entity {
        "nbsp" => Some(' '),
        "amp" => Some('&'),
        "lt" => Some('<'),
        "gt" => Some('>'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "#39" => Some('\''),
        _ => {
            if let Some(hex) = entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
            {
                let value = u32::from_str_radix(hex, 16).ok()?;
                return char::from_u32(value);
            }
            if let Some(dec) = entity.strip_prefix('#') {
                let value = dec.parse::<u32>().ok()?;
                return char::from_u32(value);
            }
            None
        }
    }
}

pub fn import_into_archive(
    path: &std::path::Path,
    pile_path: &std::path::Path,
    branch_name: &str,
    branch_id: Id,
) -> Result<()> {
    let _span = info_span!(
        "gemini_import",
        path = %path.display(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}")
    )
    .entered();
    let import_start = Instant::now();
    let (mut repo, branch_id) = common::open_repo_for_write(pile_path, branch_id, branch_name)?;
    let res = import_gemini_path(path, &mut repo, branch_id);
    tracing::info!(
        ok = res.is_ok(),
        elapsed_ms = import_start.elapsed().as_millis() as u64,
        "gemini import finished"
    );
    let close_res = repo
        .close()
        .map_err(|e| anyhow!("close pile {}: {e:?}", pile_path.display()));
    match (res, close_res) {
        (Ok(stats), Ok(())) => {
            println!(
                "Imported {} file(s), {} conversation(s), {} message(s) in {} new commit(s).",
                stats.files, stats.conversations, stats.messages, stats.commits
            );
            Ok(())
        }
        (Ok(_), Err(err)) => Err(err),
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(close_err)) => {
            eprintln!("warning: close pile after error: {close_err:#}");
            Err(err)
        }
    }
}
