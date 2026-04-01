use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::common;
use anyhow::{Context, Result, anyhow};
use hifitime::Epoch;
use serde_json::{Map, Value as JsonValue};
use tracing::info_span;
use triblespace::core::import::json_tree::JsonTreeImporter;
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
    conversation_id: String,
    source_message_id: String,
    role: String,
    author: String,
    content: String,
    created_at: Option<Epoch>,
    order: usize,
}

fn import_codex_path(path: &Path, repo: &mut common::Repo, branch_id: Id) -> Result<ImportStats> {
    let start = Instant::now();
    println!("codex phase pull: {}", path.display());
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
    let mut catalog = ws.checkout(..).context("checkout workspace")?.into_facts();
    let mut catalog_head = ws.head();
    println!("codex phase pull: done in {:?}", start.elapsed());

    if path.is_dir() {
        let scan_start = Instant::now();
        println!("codex phase scan: {}", path.display());
        let mut paths = Vec::new();
        collect_jsonl_files(path, &mut paths)
            .with_context(|| format!("scan {}", path.display()))?;
        paths.sort();
        println!(
            "codex phase scan: found {} jsonl file(s) under {} in {:?}",
            paths.len(),
            path.display(),
            scan_start.elapsed()
        );
        let mut total = ImportStats::default();
        let total_files = paths.len();
        let parsed_files: Vec<(PathBuf, Result<Vec<JsonValue>>)> =
            common::parse_paths_parallel("codex", &paths, parse_codex_jsonl)?;

        for (index, (file, parsed_records)) in parsed_files.into_iter().enumerate() {
            let processed = index + 1;
            let file_start = Instant::now();
            println!(
                "import codex file {processed}/{total_files}: {}",
                file.display()
            );
            let raw_records =
                parsed_records.with_context(|| format!("parse {}", file.display()))?;
            println!("codex phase parse: {} line record(s)", raw_records.len());
            let stats = import_codex_records(
                &file,
                raw_records,
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
                "codex progress files {}/{} (conversations {}, messages {}, commits {}) in {:?}",
                processed,
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
    println!("codex phase parse: {}", path.display());
    let raw_records = parse_codex_jsonl(path)?;
    println!(
        "codex phase parse: {} line record(s) in {:?}",
        raw_records.len(),
        parse_start.elapsed()
    );
    import_codex_records(
        path,
        raw_records,
        repo,
        &mut ws,
        &mut catalog,
        &mut catalog_head,
    )
}

fn import_codex_records(
    path: &Path,
    raw_records: Vec<JsonValue>,
    repo: &mut common::Repo,
    ws: &mut common::Ws,
    catalog: &mut TribleSet,
    catalog_head: &mut Option<common::CommitHandle>,
) -> Result<ImportStats> {
    let mut stats = ImportStats {
        files: 1,
        ..ImportStats::default()
    };

    if raw_records.is_empty() {
        return Ok(stats);
    }

    let raw_root = {
        let raw_tree_start = Instant::now();
        println!("codex phase raw-tree: {}", path.display());
        let raw_payload = serde_json::to_string(&raw_records).context("serialize codex jsonl")?;
        let mut importer = JsonTreeImporter::<_, triblespace::prelude::valueschemas::Blake3>::new(
            repo.storage_mut(),
            None,
        );
        let fragment = importer
            .import_str(&raw_payload)
            .context("import codex raw json tree")?;
        let root = fragment
            .root()
            .ok_or_else(|| anyhow!("json tree importer did not return a single root"))?;
        if common::commit_delta(
            repo,
            ws,
            catalog,
            catalog_head,
            fragment.facts().clone(),
            "import codex json tree",
        )? {
            stats.commits += 1;
        }
        println!(
            "codex phase raw-tree: done in {:?}",
            raw_tree_start.elapsed()
        );
        root
    };

    let semantic_start = Instant::now();
    let conversation_hint = detect_file_conversation_hint(&raw_records, raw_root);
    let mut messages = collect_codex_messages(&raw_records, &conversation_hint);
    messages.sort_by_key(|m| m.order);

    let mut by_conversation: BTreeMap<String, Vec<MessageRecord>> = BTreeMap::new();
    for message in messages {
        by_conversation
            .entry(message.conversation_id.clone())
            .or_default()
            .push(message);
    }
    println!(
        "codex {}: parsed {} message(s) across {} conversation(s)",
        path.display(),
        by_conversation
            .values()
            .map(|records| records.len())
            .sum::<usize>(),
        by_conversation.len()
    );

    let mut change = TribleSet::new();
    let mut author_cache: HashMap<String, Id> = HashMap::new();
    let total_conversations = by_conversation.len();

    for (index, (conversation_id, mut convo_messages)) in by_conversation.into_iter().enumerate() {
        convo_messages.sort_by_key(|m| m.order);
        let conversation_fragment = entity! { _ @
            common::metadata::tag: common::import_schema::kind_conversation,
            common::import_schema::source_format: "codex",
            common::import_schema::source_conversation_id: ws.put(conversation_id.clone()),
            common::import_schema::source_raw_root: raw_root,
        };
        let conversation_id = conversation_fragment
            .root()
            .expect("entity! must export a single root id");

        change += conversation_fragment;

        let mut previous: Option<(Id, String)> = None;
        for message in convo_messages {
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
            let content_handle = ws.put(message.content.clone());

            let author_key = format!("{}::{}", message.author, message.role);
            let author_id = if let Some(id) = author_cache.get(&author_key).copied() {
                id
            } else {
                let (id, author_change) =
                    common::ensure_author(ws, &catalog, &message.author, &message.role)?;
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
        }

        stats.conversations += 1;
        let processed = index + 1;
        if processed % 50 == 0 || processed == total_conversations {
            println!(
                "codex progress conversations {}/{} (messages {}, staged commits {})",
                processed, total_conversations, stats.messages, stats.commits
            );
        }
    }

    println!(
        "codex phase semantic-build: {} conversation(s), {} message(s) in {:?}",
        stats.conversations,
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
        "import codex",
    )? {
        stats.commits += 1;
    }
    println!(
        "codex phase semantic-commit: done in {:?} (total commits {})",
        commit_start.elapsed(),
        stats.commits
    );

    Ok(stats)
}

fn parse_codex_jsonl(path: &Path) -> Result<Vec<JsonValue>> {
    let raw_text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut raw_records = Vec::new();
    for (line_idx, line) in raw_text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: JsonValue = serde_json::from_str(trimmed)
            .with_context(|| format!("parse jsonl line {}", line_idx + 1))?;
        raw_records.push(value);
    }
    Ok(raw_records)
}

fn collect_jsonl_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry.context("read dir entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("entry type")?;
        if file_type.is_dir() {
            collect_jsonl_files(&entry_path, out)?;
        } else if file_type.is_file()
            && entry_path.extension().and_then(|ext| ext.to_str()) == Some("jsonl")
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn collect_codex_messages(records: &[JsonValue], conversation_hint: &str) -> Vec<MessageRecord> {
    let history_messages = collect_history_messages(records);
    if !history_messages.is_empty() {
        return history_messages;
    }

    let event_messages = collect_event_messages(records, conversation_hint);
    if !event_messages.is_empty() {
        return event_messages;
    }

    collect_response_messages(records, conversation_hint)
}

fn collect_history_messages(records: &[JsonValue]) -> Vec<MessageRecord> {
    let mut out = Vec::new();
    for (idx, record) in records.iter().enumerate() {
        let Some(object) = record.as_object() else {
            continue;
        };
        let Some(session_id) = object.get("session_id").and_then(JsonValue::as_str) else {
            continue;
        };
        let Some(text) = object.get("text").and_then(JsonValue::as_str) else {
            continue;
        };
        if text.trim().is_empty() {
            continue;
        }
        let created_at = object
            .get("ts")
            .and_then(json_f64)
            .and_then(common::epoch_from_seconds);
        out.push(MessageRecord {
            conversation_id: session_id.to_string(),
            source_message_id: format!("history-{idx:08}"),
            role: "user".to_string(),
            author: "user".to_string(),
            content: text.to_string(),
            created_at,
            order: idx,
        });
    }
    out
}

fn collect_event_messages(records: &[JsonValue], conversation_hint: &str) -> Vec<MessageRecord> {
    let mut out = Vec::new();
    for (idx, record) in records.iter().enumerate() {
        let Some(object) = record.as_object() else {
            continue;
        };
        if object.get("type").and_then(JsonValue::as_str) != Some("event_msg") {
            continue;
        }
        let Some(payload) = object.get("payload").and_then(JsonValue::as_object) else {
            continue;
        };
        let Some(payload_type) = payload.get("type").and_then(JsonValue::as_str) else {
            continue;
        };

        let (role, author, content) = match payload_type {
            "user_message" => (
                "user".to_string(),
                "user".to_string(),
                payload.get("message").and_then(JsonValue::as_str),
            ),
            "agent_message" => (
                "assistant".to_string(),
                "assistant".to_string(),
                payload.get("message").and_then(JsonValue::as_str),
            ),
            _ => continue,
        };
        let Some(content) = content.map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        let created_at = object
            .get("timestamp")
            .and_then(JsonValue::as_str)
            .and_then(parse_epoch_str);
        let conversation_id = extract_conversation_id(object).unwrap_or(conversation_hint);
        out.push(MessageRecord {
            conversation_id: conversation_id.to_string(),
            source_message_id: format!("event-{idx:08}"),
            role,
            author,
            content: content.to_string(),
            created_at,
            order: idx,
        });
    }
    out
}

fn collect_response_messages(records: &[JsonValue], conversation_hint: &str) -> Vec<MessageRecord> {
    let mut out = Vec::new();

    for (idx, record) in records.iter().enumerate() {
        let Some(object) = record.as_object() else {
            continue;
        };
        let record_type = object.get("type").and_then(JsonValue::as_str);
        match record_type {
            Some("response_item") => {
                let Some(payload) = object.get("payload").and_then(JsonValue::as_object) else {
                    continue;
                };
                if payload.get("type").and_then(JsonValue::as_str) != Some("message") {
                    continue;
                }
                let role = payload
                    .get("role")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("assistant")
                    .to_string();
                let author = canonical_author_name(&role).to_string();
                let Some(content) = payload
                    .get("content")
                    .and_then(extract_codex_content_text)
                    .filter(|s| !s.trim().is_empty())
                else {
                    continue;
                };
                let created_at = object
                    .get("timestamp")
                    .and_then(JsonValue::as_str)
                    .and_then(parse_epoch_str);
                let conversation_id = extract_conversation_id(payload)
                    .or_else(|| extract_conversation_id(object))
                    .unwrap_or(conversation_hint)
                    .to_string();
                out.push(MessageRecord {
                    conversation_id,
                    source_message_id: format!("response-item-{idx:08}-{role}"),
                    role,
                    author,
                    content,
                    created_at,
                    order: idx,
                });
            }
            Some("message") => {
                let role = object
                    .get("role")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("user")
                    .to_string();
                let author = canonical_author_name(&role).to_string();
                let Some(content) = object
                    .get("content")
                    .and_then(extract_codex_content_text)
                    .filter(|s| !s.trim().is_empty())
                else {
                    continue;
                };
                let created_at = object
                    .get("timestamp")
                    .and_then(JsonValue::as_str)
                    .and_then(parse_epoch_str);
                let conversation_id = extract_conversation_id(object)
                    .unwrap_or(conversation_hint)
                    .to_string();
                out.push(MessageRecord {
                    conversation_id,
                    source_message_id: format!("message-{idx:08}-{role}"),
                    role,
                    author,
                    content,
                    created_at,
                    order: idx,
                });
            }
            _ => {}
        }
    }

    out
}

fn detect_file_conversation_hint(records: &[JsonValue], raw_root: Id) -> String {
    for record in records {
        let Some(object) = record.as_object() else {
            continue;
        };
        if let Some(conversation_id) = extract_conversation_id(object) {
            return conversation_id.to_string();
        }
        if object.get("timestamp").is_some() {
            if let Some(id) = object.get("id").and_then(JsonValue::as_str) {
                return id.to_string();
            }
        }
    }
    format!("codex:{raw_root:x}")
}

fn extract_conversation_id(object: &Map<String, JsonValue>) -> Option<&str> {
    object
        .get("conversation_id")
        .and_then(JsonValue::as_str)
        .or_else(|| object.get("session_id").and_then(JsonValue::as_str))
        .or_else(|| object.get("conversationId").and_then(JsonValue::as_str))
}

fn extract_codex_content_text(value: &JsonValue) -> Option<String> {
    let Some(items) = value.as_array() else {
        return value
            .as_str()
            .map(|s| s.to_string())
            .filter(|s| !s.trim().is_empty());
    };
    let mut parts = Vec::new();
    for item in items {
        if let Some(text) = item.as_str() {
            if !text.trim().is_empty() {
                parts.push(text.to_string());
            }
            continue;
        }
        let Some(obj) = item.as_object() else {
            continue;
        };
        if let Some(text) = obj.get("text").and_then(JsonValue::as_str) {
            if !text.trim().is_empty() {
                parts.push(text.to_string());
            }
            continue;
        }
        if let Some(text) = obj.get("value").and_then(JsonValue::as_str) {
            if !text.trim().is_empty() {
                parts.push(text.to_string());
            }
            continue;
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

fn canonical_author_name(role: &str) -> &str {
    match role {
        "user" => "user",
        "assistant" | "agent" | "model" => "assistant",
        "developer" => "developer",
        "system" => "system",
        _ => role,
    }
}

fn parse_epoch_str(value: &str) -> Option<Epoch> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(epoch) = trimmed.parse::<Epoch>() {
        return Some(epoch);
    }
    if let Ok(seconds) = trimmed.parse::<f64>() {
        return parse_epoch_number(seconds);
    }
    None
}

fn parse_epoch_number(value: f64) -> Option<Epoch> {
    if !value.is_finite() {
        return None;
    }
    // Heuristic: values above 10^11 are usually milliseconds since unix epoch.
    let seconds = if value.abs() > 1.0e11 {
        value / 1000.0
    } else {
        value
    };
    common::epoch_from_seconds(seconds)
}

fn json_f64(value: &JsonValue) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|v| v as f64))
        .or_else(|| value.as_u64().map(|v| v as f64))
}

pub fn import_into_archive(
    path: &Path,
    pile_path: &Path,
    branch_name: &str,
    branch_id: Id,
) -> Result<()> {
    let _span = info_span!(
        "codex_import",
        path = %path.display(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}")
    )
    .entered();
    let import_start = Instant::now();
    let (mut repo, branch_id) = common::open_repo_for_write(pile_path, branch_id, branch_name)?;
    let res = import_codex_path(path, &mut repo, branch_id);
    tracing::info!(
        ok = res.is_ok(),
        elapsed_ms = import_start.elapsed().as_millis() as u64,
        "codex import finished"
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
