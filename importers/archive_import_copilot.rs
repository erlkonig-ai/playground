use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
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
struct ParsedCopilotFile {
    raw: String,
    root: JsonValue,
    records: Vec<MessageRecord>,
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

fn import_copilot_path(
    path: &std::path::Path,
    repo: &mut common::Repo,
    branch_id: Id,
) -> Result<ImportStats> {
    let start = Instant::now();
    println!("copilot phase pull: {}", path.display());
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
    let mut catalog = ws.checkout(..).context("checkout workspace")?.into_facts();
    let mut catalog_head = ws.head();
    println!("copilot phase pull: done in {:?}", start.elapsed());

    if path.is_dir() {
        let scan_start = Instant::now();
        println!("copilot phase scan: {}", path.display());
        let mut files = Vec::new();
        collect_copilot_files(path, &mut files)
            .with_context(|| format!("scan {}", path.display()))?;
        files.sort();
        let total_files = files.len();
        println!(
            "copilot phase scan: found {} file(s) under {} in {:?}",
            total_files,
            path.display(),
            scan_start.elapsed()
        );
        let parsed_files: Vec<(PathBuf, Result<ParsedCopilotFile>)> =
            common::parse_paths_parallel("copilot", &files, parse_copilot_file)?;

        let mut total = ImportStats::default();
        for (index, (file, parsed_file)) in parsed_files.into_iter().enumerate() {
            let file_start = Instant::now();
            println!(
                "copilot file {}/{}: {}",
                index + 1,
                total_files,
                file.display()
            );
            let stats = import_copilot_parsed_file(
                file.as_path(),
                parsed_file.with_context(|| format!("parse {}", file.display()))?,
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
                "copilot progress files {}/{} (conversations {}, messages {}, commits {}) in {:?}",
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
    println!("copilot phase parse: {}", path.display());
    let parsed = parse_copilot_file(path)?;
    println!(
        "copilot {}: parsed {} message record(s) in {:?}",
        path.display(),
        parsed.records.len(),
        parse_start.elapsed()
    );
    import_copilot_parsed_file(
        path,
        parsed,
        repo,
        &mut ws,
        &mut catalog,
        &mut catalog_head,
    )
}

fn import_copilot_parsed_file(
    path: &std::path::Path,
    parsed: ParsedCopilotFile,
    repo: &mut common::Repo,
    ws: &mut common::Ws,
    catalog: &mut TribleSet,
    catalog_head: &mut Option<common::CommitHandle>,
) -> Result<ImportStats> {
    let ParsedCopilotFile {
        raw,
        root,
        mut records,
    } = parsed;
    let object = root
        .as_object()
        .ok_or_else(|| anyhow!("copilot export must be a JSON object"))?;

    let mut stats = ImportStats {
        files: 1,
        ..ImportStats::default()
    };

    let raw_root = {
        let raw_tree_start = Instant::now();
        println!("copilot phase raw-tree: {}", path.display());
        let mut importer = JsonTreeImporter::<_, triblespace::prelude::valueschemas::Blake3>::new(
            repo.storage_mut(),
            None,
        );
        let fragment = importer
            .import_str(&raw)
            .context("import copilot raw json tree")?;
        let root = fragment
            .root()
            .ok_or_else(|| anyhow!("json tree importer did not return a single root"))?;
        if common::commit_delta(
            repo,
            ws,
            catalog,
            catalog_head,
            fragment.facts().clone(),
            "import copilot json tree",
        )? {
            stats.commits += 1;
        }
        println!(
            "copilot phase raw-tree: done in {:?}",
            raw_tree_start.elapsed()
        );
        root
    };

    let conversation_id = resolve_copilot_conversation_id(object, raw_root);

    records.sort_by_key(|m| m.order);

    let conversation_fragment = entity! { _ @
        common::metadata::tag: common::import_schema::kind_conversation,
        common::import_schema::source_format: "copilot",
        common::import_schema::source_conversation_id: ws.put(conversation_id.clone()),
        common::import_schema::source_raw_root: raw_root,
    };
    let conversation_id = conversation_fragment
        .root()
        .expect("entity! must export a single root id");
    let mut change = TribleSet::new();

    change += conversation_fragment;

    let mut author_cache: HashMap<String, Id> = HashMap::new();
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
            .acquire()
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
                "copilot progress records {}/{} (messages {}, staged commits {})",
                processed, total_records, stats.messages, stats.commits
            );
        }
    }
    println!(
        "copilot phase semantic-build: {} message(s) in {:?}",
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
        "import copilot",
    )? {
        stats.commits += 1;
    }
    println!(
        "copilot phase semantic-commit: done in {:?} (total commits {})",
        commit_start.elapsed(),
        stats.commits
    );
    if stats.messages > 0 {
        stats.conversations = 1;
    }

    Ok(stats)
}

fn parse_copilot_file(path: &std::path::Path) -> Result<ParsedCopilotFile> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let root: JsonValue = serde_json::from_str(&raw).context("parse copilot json")?;
    let object = root
        .as_object()
        .ok_or_else(|| anyhow!("copilot export must be a JSON object"))?;
    let records = parse_copilot_records(object)?;
    Ok(ParsedCopilotFile { raw, root, records })
}

fn collect_copilot_files(path: &std::path::Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry.context("read dir entry")?;
        let file_type = entry.file_type().context("entry type")?;
        let entry_path = entry.path();
        if file_type.is_dir() {
            collect_copilot_files(&entry_path, out)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        if entry_path.extension().and_then(|s| s.to_str()) == Some("json") {
            out.push(entry_path);
        }
    }
    Ok(())
}

fn parse_copilot_records(object: &Map<String, JsonValue>) -> Result<Vec<MessageRecord>> {
    if let Some(requests) = object.get("requests").and_then(JsonValue::as_array) {
        return Ok(parse_copilot_requests(requests));
    }
    if let Some(messages) = object.get("messages").and_then(JsonValue::as_array) {
        return Ok(parse_copilot_messages(messages));
    }
    Err(anyhow!("copilot export missing requests[] or messages[]"))
}

fn parse_copilot_requests(requests: &[JsonValue]) -> Vec<MessageRecord> {
    let mut records = Vec::new();
    for (idx, request) in requests.iter().enumerate() {
        let Some(req_obj) = request.as_object() else {
            continue;
        };
        let request_id = req_obj
            .get("requestId")
            .and_then(JsonValue::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("request-{idx:08}"));
        let created_at = req_obj.get("timestamp").and_then(parse_epoch_value);

        if let Some(user_text) = extract_copilot_user_text(req_obj) {
            records.push(MessageRecord {
                source_message_id: format!("{request_id}:user"),
                role: "user".to_string(),
                author: "user".to_string(),
                content: user_text,
                created_at,
                order: idx * 2,
            });
        }

        if let Some(assistant_text) = extract_copilot_assistant_text(req_obj) {
            records.push(MessageRecord {
                source_message_id: format!("{request_id}:assistant"),
                role: "assistant".to_string(),
                author: "assistant".to_string(),
                content: assistant_text,
                created_at,
                order: idx * 2 + 1,
            });
        }
    }
    records
}

fn parse_copilot_messages(messages: &[JsonValue]) -> Vec<MessageRecord> {
    let mut records = Vec::new();
    for (idx, message) in messages.iter().enumerate() {
        let Some(msg_obj) = message.as_object() else {
            continue;
        };
        let role = msg_obj
            .get("role")
            .and_then(JsonValue::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("assistant")
            .to_string();
        let Some(content) = extract_message_content(msg_obj) else {
            continue;
        };
        let source_message_id = msg_obj
            .get("id")
            .and_then(JsonValue::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("message-{idx:08}"));
        let created_at = msg_obj
            .get("createdAt")
            .or_else(|| msg_obj.get("created_at"))
            .or_else(|| msg_obj.get("timestamp"))
            .and_then(parse_epoch_value);
        records.push(MessageRecord {
            source_message_id,
            author: canonical_author_name(&role).to_string(),
            role,
            content,
            created_at,
            order: idx,
        });
    }
    records
}

fn resolve_copilot_conversation_id(object: &Map<String, JsonValue>, raw_root: Id) -> String {
    for key in ["conversationId", "threadID", "threadUrl", "threadName"] {
        if let Some(value) = object.get(key).and_then(JsonValue::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    format!("copilot:{raw_root:x}")
}

fn extract_message_content(message: &Map<String, JsonValue>) -> Option<String> {
    if let Some(text) = message.get("content").and_then(JsonValue::as_str) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(parts) = message
        .get("content")
        .and_then(JsonValue::as_object)
        .and_then(|obj| obj.get("parts"))
        .and_then(JsonValue::as_array)
    {
        let mut out = Vec::new();
        for part in parts {
            if let Some(text) = part.as_str() {
                let trimmed = text.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
            }
        }
        if !out.is_empty() {
            return Some(out.join("\n\n"));
        }
    }
    None
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

fn parse_epoch_value(value: &JsonValue) -> Option<Epoch> {
    if let Some(seconds) = json_f64(value) {
        return parse_epoch_number(seconds);
    }
    value.as_str().and_then(parse_epoch_str)
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

fn extract_copilot_user_text(req: &Map<String, JsonValue>) -> Option<String> {
    let message = req.get("message")?.as_object()?;
    if let Some(text) = message.get("text").and_then(JsonValue::as_str) {
        if !text.trim().is_empty() {
            return Some(text.to_string());
        }
    }
    if let Some(parts) = message.get("parts").and_then(JsonValue::as_array) {
        let mut segments = Vec::new();
        for part in parts {
            match part {
                JsonValue::String(s) if !s.trim().is_empty() => segments.push(s.clone()),
                JsonValue::Object(obj) => {
                    if let Some(text) = obj.get("text").and_then(JsonValue::as_str) {
                        if !text.trim().is_empty() {
                            segments.push(text.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        if !segments.is_empty() {
            return Some(segments.join("\n\n"));
        }
    }
    None
}

fn extract_copilot_assistant_text(req: &Map<String, JsonValue>) -> Option<String> {
    if let Some(text) = extract_assistant_from_metadata_messages(req) {
        return Some(text);
    }
    if let Some(text) = extract_assistant_from_tool_rounds(req) {
        return Some(text);
    }
    if let Some(text) = extract_assistant_from_response_blocks(req) {
        return Some(text);
    }
    req.get("response")
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn extract_assistant_from_metadata_messages(req: &Map<String, JsonValue>) -> Option<String> {
    let metadata = req
        .get("result")
        .and_then(JsonValue::as_object)?
        .get("metadata")
        .and_then(JsonValue::as_object)?;
    let messages = metadata.get("messages")?.as_array()?;
    for item in messages.iter().rev() {
        let Some(message) = item.as_object() else {
            continue;
        };
        if message.get("role").and_then(JsonValue::as_str) != Some("assistant") {
            continue;
        }
        if let Some(content) = message.get("content").and_then(JsonValue::as_str) {
            if !content.trim().is_empty() {
                return Some(content.to_string());
            }
        }
    }
    None
}

fn extract_assistant_from_tool_rounds(req: &Map<String, JsonValue>) -> Option<String> {
    let metadata = req
        .get("result")
        .and_then(JsonValue::as_object)?
        .get("metadata")
        .and_then(JsonValue::as_object)?;
    let rounds = metadata.get("toolCallRounds")?.as_array()?;
    let mut segments = Vec::new();
    for round in rounds {
        let Some(round_obj) = round.as_object() else {
            continue;
        };
        let Some(response) = round_obj.get("response") else {
            continue;
        };
        if let Some(text) = response.as_str() {
            if !text.trim().is_empty() {
                segments.push(text.to_string());
            }
        }
    }
    if segments.is_empty() {
        None
    } else {
        Some(segments.join("\n\n"))
    }
}

fn extract_assistant_from_response_blocks(req: &Map<String, JsonValue>) -> Option<String> {
    let response_items = req.get("response")?.as_array()?;
    let mut segments = Vec::new();
    for item in response_items {
        let Some(item_obj) = item.as_object() else {
            continue;
        };
        let Some(value) = item_obj.get("value").and_then(JsonValue::as_str) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() || value == "````" {
            continue;
        }
        segments.push(value.to_string());
    }
    if segments.is_empty() {
        None
    } else {
        Some(segments.join(""))
    }
}

fn json_f64(value: &JsonValue) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_i64().map(|v| v as f64))
        .or_else(|| value.as_u64().map(|v| v as f64))
}

fn parse_epoch_number(value: f64) -> Option<Epoch> {
    if !value.is_finite() {
        return None;
    }
    let seconds = if value.abs() > 1.0e11 {
        value / 1000.0
    } else {
        value
    };
    common::epoch_from_seconds(seconds)
}

pub fn import_into_archive(
    path: &std::path::Path,
    pile_path: &std::path::Path,
    branch_name: &str,
    branch_id: Id,
) -> Result<()> {
    let _span = info_span!(
        "copilot_import",
        path = %path.display(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}")
    )
    .entered();
    let import_start = Instant::now();
    let (mut repo, branch_id) = common::open_repo_for_write(pile_path, branch_id, branch_name)?;
    let res = import_copilot_path(path, &mut repo, branch_id);
    tracing::info!(
        ok = res.is_ok(),
        elapsed_ms = import_start.elapsed().as_millis() as u64,
        "copilot import finished"
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
