use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::common;
use anyhow::{Context, Result, anyhow};
use hifitime::Epoch;
use serde_json::Value as JsonValue;
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

/// A parsed message from a Claude Code JSONL conversation.
#[derive(Debug, Clone)]
struct MessageRecord {
    conversation_id: String,
    source_message_id: String,
    parent_source_id: Option<String>,
    role: String,
    author: String,
    model: Option<String>,
    content: String,
    created_at: Option<Epoch>,
    order: usize,
}

fn import_claude_code_path(
    path: &Path,
    repo: &mut common::Repo,
    branch_id: Id,
) -> Result<ImportStats> {
    let start = Instant::now();
    println!("claude-code phase pull: {}", path.display());
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
    let mut catalog = ws.checkout(..).context("checkout workspace")?.into_facts();
    let mut catalog_head = ws.head();
    println!("claude-code phase pull: done in {:?}", start.elapsed());

    if path.is_dir() {
        let scan_start = Instant::now();
        println!("claude-code phase scan: {}", path.display());
        let mut paths = Vec::new();
        collect_jsonl_files(path, &mut paths)
            .with_context(|| format!("scan {}", path.display()))?;
        paths.sort();
        println!(
            "claude-code phase scan: found {} jsonl file(s) under {} in {:?}",
            paths.len(),
            path.display(),
            scan_start.elapsed()
        );
        let mut total = ImportStats::default();
        let total_files = paths.len();
        let parsed_files: Vec<(PathBuf, Result<Vec<JsonValue>>)> =
            common::parse_paths_parallel("claude-code", &paths, parse_jsonl)?;

        for (index, (file, parsed_records)) in parsed_files.into_iter().enumerate() {
            let processed = index + 1;
            let file_start = Instant::now();
            println!(
                "claude-code file {processed}/{total_files}: {}",
                file.display()
            );
            let raw_records =
                parsed_records.with_context(|| format!("parse {}", file.display()))?;
            if raw_records.is_empty() {
                continue;
            }
            let stats = import_claude_code_records(
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
                "claude-code progress files {}/{} (conversations {}, messages {}, commits {}) in {:?}",
                processed, total_files, total.conversations, total.messages, total.commits,
                file_start.elapsed()
            );
        }
        return Ok(total);
    }

    let parse_start = Instant::now();
    println!("claude-code phase parse: {}", path.display());
    let raw_records = parse_jsonl(path)?;
    println!(
        "claude-code phase parse: {} line record(s) in {:?}",
        raw_records.len(),
        parse_start.elapsed()
    );
    import_claude_code_records(
        path,
        raw_records,
        repo,
        &mut ws,
        &mut catalog,
        &mut catalog_head,
    )
}

fn import_claude_code_records(
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

    // Store the raw JSON tree for provenance.
    let raw_root = {
        let raw_tree_start = Instant::now();
        let raw_payload =
            serde_json::to_string(&raw_records).context("serialize claude-code jsonl")?;
        let mut importer = JsonTreeImporter::<_, triblespace::prelude::valueschemas::Blake3>::new(
            repo.storage_mut(),
            None,
        );
        let fragment = importer
            .import_str(&raw_payload)
            .context("import claude-code raw json tree")?;
        let root = fragment
            .root()
            .ok_or_else(|| anyhow!("json tree importer did not return a single root"))?;
        if common::commit_delta(
            repo,
            ws,
            catalog,
            catalog_head,
            fragment.facts().clone(),
            "import claude-code json tree",
        )? {
            stats.commits += 1;
        }
        println!(
            "claude-code phase raw-tree: done in {:?}",
            raw_tree_start.elapsed()
        );
        root
    };

    let semantic_start = Instant::now();
    let messages = collect_messages(&raw_records);
    println!(
        "claude-code {}: parsed {} message(s) across {} conversation(s)",
        path.display(),
        messages.len(),
        {
            let mut ids: Vec<&str> = messages.iter().map(|m| m.conversation_id.as_str()).collect();
            ids.sort_unstable();
            ids.dedup();
            ids.len()
        }
    );

    // Group by conversation (sessionId).
    let by_conversation: Vec<(String, Vec<MessageRecord>)> = {
        let mut map: HashMap<String, Vec<MessageRecord>> = HashMap::new();
        for msg in messages {
            map.entry(msg.conversation_id.clone())
                .or_default()
                .push(msg);
        }
        let mut pairs: Vec<_> = map.into_iter().collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        pairs
    };

    let mut change = TribleSet::new();
    let mut author_cache: HashMap<String, Id> = HashMap::new();
    let total_conversations = by_conversation.len();

    for (index, (conversation_id_str, mut convo_messages)) in
        by_conversation.into_iter().enumerate()
    {
        convo_messages.sort_by_key(|m| m.order);

        // --- Pass 1: create message entities (identity = source_format + source_message_id). ---
        // Message IDs are content-derived and stable across re-imports.
        let mut uuid_to_message_id: HashMap<String, Id> = HashMap::new();
        let mut message_ids: Vec<(Id, &MessageRecord)> = Vec::new();

        for msg in &convo_messages {
            let source_message_id_handle = ws.put(msg.source_message_id.clone());
            let message_fragment = entity! { _ @
                common::import_schema::source_format: "claude-code",
                common::import_schema::source_message_id: source_message_id_handle,
            };
            let message_id = message_fragment
                .root()
                .expect("entity! must export a single root id");
            change += message_fragment;
            uuid_to_message_id.insert(msg.source_message_id.clone(), message_id);
            message_ids.push((message_id, msg));
        }

        // --- Pass 2: create conversation entity (identity = format + session id). ---
        // The conversation is a stable g-set: message edges accumulate monotonically.
        let conversation_fragment = entity! { _ @
            common::metadata::tag: common::import_schema::kind_conversation,
            common::import_schema::source_format: "claude-code",
            common::import_schema::source_conversation_id: ws.put(conversation_id_str.clone()),
        };
        let conversation_id = conversation_fragment
            .root()
            .expect("entity! must export a single root id");
        change += conversation_fragment;

        // Attach message edges and raw provenance as non-identity attributes.
        {
            let conversation_entity = conversation_id
                .acquire()
                .expect("entity! root ids should be acquired in current thread");
            let msg_id_list: Vec<Id> = message_ids.iter().map(|(id, _)| *id).collect();
            change += entity! { &conversation_entity @
                common::import_schema::message*: msg_id_list,
                common::import_schema::source_raw_root: raw_root,
            };
        }

        // --- Pass 3: attach content attributes to messages. ---
        for (message_id, msg) in &message_ids {
            let message_entity = message_id
                .acquire()
                .expect("entity! root ids should be acquired in current thread");

            let author_key = format!("{}::{}", msg.author, msg.role);
            let author_id = if let Some(id) = author_cache.get(&author_key).copied() {
                id
            } else {
                let (id, author_change) =
                    common::ensure_author(ws, catalog, &msg.author, &msg.role)?;
                change += author_change;
                author_cache.insert(author_key, id);
                id
            };

            let created_at =
                common::epoch_interval(msg.created_at.unwrap_or_else(common::unknown_epoch));
            let content_handle = ws.put(msg.content.clone());

            // Resolve reply_to from parentUuid.
            let reply_to = msg
                .parent_source_id
                .as_ref()
                .and_then(|parent| uuid_to_message_id.get(parent).copied());
            let source_parent_id = msg
                .parent_source_id
                .as_ref()
                .map(|parent| ws.put(parent.clone()));

            let model_handle = msg.model.as_ref().map(|m| ws.put(m.clone()));

            change += entity! { &message_entity @
                common::metadata::tag: common::archive::kind_message,
                common::archive::author: author_id,
                common::archive::content: content_handle,
                common::metadata::created_at: created_at,
                common::archive::author_model?: model_handle,
                common::import_schema::source_author: ws.put(msg.author.clone()),
                common::import_schema::source_role: ws.put(msg.role.clone()),
                common::import_schema::source_created_at: created_at,
                common::archive::reply_to?: reply_to,
                common::import_schema::source_parent_id?: source_parent_id,
            };

            stats.messages += 1;
        }

        stats.conversations += 1;
        let processed = index + 1;
        if processed % 50 == 0 || processed == total_conversations {
            println!(
                "claude-code progress conversations {}/{} (messages {}, staged commits {})",
                processed, total_conversations, stats.messages, stats.commits
            );
        }
    }

    println!(
        "claude-code phase semantic-build: {} conversation(s), {} message(s) in {:?}",
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
        "import claude-code",
    )? {
        stats.commits += 1;
    }
    println!(
        "claude-code phase semantic-commit: done in {:?} (total commits {})",
        commit_start.elapsed(),
        stats.commits
    );

    Ok(stats)
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn parse_jsonl(path: &Path) -> Result<Vec<JsonValue>> {
    let raw_text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut records = Vec::new();
    for (line_idx, line) in raw_text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: JsonValue = serde_json::from_str(trimmed)
            .with_context(|| format!("parse jsonl line {}", line_idx + 1))?;
        records.push(value);
    }
    Ok(records)
}

fn collect_jsonl_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry.context("read dir entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("entry type")?;
        if file_type.is_dir() {
            // Recurse into subdirectories (projects/*/subagents/, etc).
            collect_jsonl_files(&entry_path, out)?;
        } else if file_type.is_file()
            && entry_path.extension().and_then(|ext| ext.to_str()) == Some("jsonl")
        {
            out.push(entry_path);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Message extraction
// ---------------------------------------------------------------------------

/// Extract importable messages from Claude Code JSONL records.
///
/// Claude Code stores conversations as JSONL with these line types:
/// - `user`: user messages (content is string or content blocks)
/// - `assistant`: model responses (content blocks: text, thinking, tool_use)
/// - `system`, `progress`, `file-history-snapshot`, `queue-operation`: metadata (skipped)
///
/// We import `user` and `assistant` lines. For assistant messages, we build a
/// composite content string that includes thinking blocks (as `reason "..."`
/// synthetic notation) and text blocks. Tool use blocks are included as
/// `<tool-name> <args-summary>` so they're visible in memory summaries.
fn collect_messages(records: &[JsonValue]) -> Vec<MessageRecord> {
    let mut out = Vec::new();
    for (idx, record) in records.iter().enumerate() {
        let Some(object) = record.as_object() else {
            continue;
        };
        let record_type = object.get("type").and_then(JsonValue::as_str).unwrap_or("");
        match record_type {
            "user" => {
                if let Some(msg) = extract_user_message(object, idx) {
                    out.push(msg);
                }
            }
            "assistant" => {
                if let Some(msg) = extract_assistant_message(object, idx) {
                    out.push(msg);
                }
            }
            _ => {}
        }
    }
    out
}

fn extract_user_message(
    object: &serde_json::Map<String, JsonValue>,
    order: usize,
) -> Option<MessageRecord> {
    let session_id = object.get("sessionId").and_then(JsonValue::as_str)?;
    let uuid = object.get("uuid").and_then(JsonValue::as_str)?;
    let parent_uuid = object
        .get("parentUuid")
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    let timestamp = object
        .get("timestamp")
        .and_then(JsonValue::as_str)
        .and_then(parse_iso_timestamp);

    let message = object.get("message").and_then(JsonValue::as_object)?;
    let content = extract_user_content(message)?;
    if content.trim().is_empty() {
        return None;
    }

    Some(MessageRecord {
        conversation_id: session_id.to_string(),
        source_message_id: uuid.to_string(),
        parent_source_id: parent_uuid,
        role: "user".to_string(),
        author: "user".to_string(),
        model: None,
        content,
        created_at: timestamp,
        order,
    })
}

fn extract_assistant_message(
    object: &serde_json::Map<String, JsonValue>,
    order: usize,
) -> Option<MessageRecord> {
    let session_id = object.get("sessionId").and_then(JsonValue::as_str)?;
    let uuid = object.get("uuid").and_then(JsonValue::as_str)?;
    let parent_uuid = object
        .get("parentUuid")
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    let timestamp = object
        .get("timestamp")
        .and_then(JsonValue::as_str)
        .and_then(parse_iso_timestamp);

    let message = object.get("message").and_then(JsonValue::as_object)?;
    let model = message
        .get("model")
        .and_then(JsonValue::as_str)
        .map(str::to_string);
    let content = extract_assistant_content(message)?;
    if content.trim().is_empty() {
        return None;
    }

    let author = model.as_deref().unwrap_or("assistant").to_string();

    Some(MessageRecord {
        conversation_id: session_id.to_string(),
        source_message_id: uuid.to_string(),
        parent_source_id: parent_uuid,
        role: "assistant".to_string(),
        author,
        model,
        content,
        created_at: timestamp,
        order,
    })
}

// ---------------------------------------------------------------------------
// Content extraction
// ---------------------------------------------------------------------------

/// Extract text content from a user message.
///
/// User messages have either:
/// - `content: "string"` (plain text)
/// - `content: [{ type: "text", text: "..." }, { type: "tool_result", content: "...", tool_use_id: "..." }]`
fn extract_user_content(message: &serde_json::Map<String, JsonValue>) -> Option<String> {
    let content = message.get("content")?;

    // Simple string content.
    if let Some(text) = content.as_str() {
        return Some(text.to_string());
    }

    // Content block array.
    let blocks = content.as_array()?;
    let mut parts = Vec::new();
    for block in blocks {
        let Some(obj) = block.as_object() else {
            continue;
        };
        let block_type = obj.get("type").and_then(JsonValue::as_str).unwrap_or("");
        match block_type {
            "text" => {
                if let Some(text) = obj.get("text").and_then(JsonValue::as_str) {
                    if !text.trim().is_empty() {
                        parts.push(text.to_string());
                    }
                }
            }
            "tool_result" => {
                let tool_id = obj
                    .get("tool_use_id")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("unknown");
                let result_text = obj
                    .get("content")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                let is_error = obj
                    .get("is_error")
                    .and_then(JsonValue::as_bool)
                    .unwrap_or(false);
                let status = if is_error { "error" } else { "ok" };
                // Truncate long tool results for the archive content.
                let truncated = truncate(result_text, 2000);
                parts.push(format!("[tool_result {tool_id} {status}] {truncated}"));
            }
            _ => {}
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

/// Extract composite content from an assistant message.
///
/// Assistant content blocks:
/// - `thinking`: extended thinking (mapped to `reason "..."` notation)
/// - `text`: response text
/// - `tool_use`: tool invocations (mapped to `<tool> <input-summary>` notation)
fn extract_assistant_content(message: &serde_json::Map<String, JsonValue>) -> Option<String> {
    let blocks = message.get("content").and_then(JsonValue::as_array)?;
    let mut parts = Vec::new();

    for block in blocks {
        let Some(obj) = block.as_object() else {
            continue;
        };
        let block_type = obj.get("type").and_then(JsonValue::as_str).unwrap_or("");
        match block_type {
            "thinking" => {
                if let Some(thinking) = obj.get("thinking").and_then(JsonValue::as_str) {
                    let trimmed = thinking.trim();
                    if !trimmed.is_empty() {
                        // Represent thinking as reason notation for archive content.
                        let truncated = truncate(trimmed, 4000);
                        parts.push(format!("[thinking] {truncated}"));
                    }
                }
            }
            "text" => {
                if let Some(text) = obj.get("text").and_then(JsonValue::as_str) {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        parts.push(trimmed.to_string());
                    }
                }
            }
            "tool_use" => {
                let tool_name = obj
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("unknown_tool");
                let input_summary = summarize_tool_input(
                    obj.get("input").and_then(JsonValue::as_object),
                );
                parts.push(format!("[tool_use {tool_name}] {input_summary}"));
            }
            _ => {}
        }
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

/// Produce a short summary of tool input parameters.
fn summarize_tool_input(input: Option<&serde_json::Map<String, JsonValue>>) -> String {
    let Some(input) = input else {
        return String::new();
    };

    // For common tools, extract the most informative field.
    if let Some(path) = input.get("file_path").and_then(JsonValue::as_str) {
        return path.to_string();
    }
    if let Some(command) = input.get("command").and_then(JsonValue::as_str) {
        return truncate(command, 200);
    }
    if let Some(pattern) = input.get("pattern").and_then(JsonValue::as_str) {
        return format!("pattern={pattern}");
    }
    if let Some(query) = input.get("query").and_then(JsonValue::as_str) {
        return truncate(query, 200);
    }
    if let Some(prompt) = input.get("prompt").and_then(JsonValue::as_str) {
        return truncate(prompt, 200);
    }

    // Fallback: list keys.
    let keys: Vec<&str> = input.keys().map(String::as_str).collect();
    if keys.is_empty() {
        String::new()
    } else {
        keys.join(", ")
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        let truncated: String = text.chars().take(max_chars).collect();
        format!("{truncated}...")
    }
}

// ---------------------------------------------------------------------------
// Timestamp parsing
// ---------------------------------------------------------------------------

/// Parse an ISO 8601 timestamp like "2026-03-01T15:34:01.542Z".
fn parse_iso_timestamp(value: &str) -> Option<Epoch> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    // hifitime's Epoch parser handles ISO 8601 / RFC 3339.
    trimmed.parse::<Epoch>().ok()
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn import_into_archive(
    path: &Path,
    pile_path: &Path,
    branch_name: &str,
    branch_id: Id,
) -> Result<()> {
    let _span = info_span!(
        "claude_code_import",
        path = %path.display(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}")
    )
    .entered();
    let import_start = Instant::now();
    let (mut repo, branch_id) = common::open_repo_for_write(pile_path, branch_id, branch_name)?;
    let res = import_claude_code_path(path, &mut repo, branch_id);
    tracing::info!(
        ok = res.is_ok(),
        elapsed_ms = import_start.elapsed().as_millis() as u64,
        "claude-code import finished"
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
