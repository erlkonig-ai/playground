use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::common;
use anyhow::{Context, Result, anyhow};
use serde_json::Value as JsonValue;
use tracing::info_span;
use triblespace::core::blob::Bytes;
use triblespace::core::import::json_tree::JsonTreeImporter;
use triblespace::prelude::*;

#[derive(Debug, Default, Clone)]
struct ImportStats {
    conversations: usize,
    messages: usize,
    attachments: usize,
    commits: usize,
}

#[derive(Debug, Clone)]
struct ParsedChatgptFile {
    conversations: Vec<JsonValue>,
}

fn import_chatgpt_path(path: &Path, repo: &mut common::Repo, branch_id: Id) -> Result<ImportStats> {
    let start = Instant::now();
    println!("chatgpt phase pull: {}", path.display());
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
    let mut catalog = ws.checkout(..).context("checkout workspace")?.into_facts();
    let mut catalog_head = ws.head();
    println!("chatgpt phase pull: done in {:?}", start.elapsed());

    if path.is_dir() {
        let scan_start = Instant::now();
        println!("chatgpt phase scan: {}", path.display());
        let mut paths = Vec::new();
        collect_conversation_files(path, &mut paths)
            .with_context(|| format!("scan {}", path.display()))?;
        paths.sort();
        let total_files = paths.len();
        println!(
            "chatgpt phase scan: found {} conversations.json file(s) under {} in {:?}",
            total_files,
            path.display(),
            scan_start.elapsed()
        );
        let parsed_files: Vec<(PathBuf, Result<ParsedChatgptFile>)> =
            common::parse_paths_parallel("chatgpt", &paths, parse_chatgpt_file)?;

        let mut total = ImportStats::default();
        for (index, (convo_path, parsed_file)) in parsed_files.into_iter().enumerate() {
            let file_start = Instant::now();
            println!(
                "chatgpt file {}/{}: {}",
                index + 1,
                total_files,
                convo_path.display()
            );
            let stats = import_chatgpt_parsed_file(
                convo_path.as_path(),
                parsed_file.with_context(|| format!("parse {}", convo_path.display()))?,
                repo,
                &mut ws,
                &mut catalog,
                &mut catalog_head,
            )
            .with_context(|| format!("import {}", convo_path.display()))?;
            total.conversations += stats.conversations;
            total.messages += stats.messages;
            total.attachments += stats.attachments;
            total.commits += stats.commits;
            println!(
                "chatgpt progress files {}/{} (conversations {}, messages {}, attachments {}, commits {}) in {:?}",
                index + 1,
                total_files,
                total.conversations,
                total.messages,
                total.attachments,
                total.commits,
                file_start.elapsed()
            );
        }
        return Ok(total);
    }

    let parse_start = Instant::now();
    println!("chatgpt phase parse: {}", path.display());
    let parsed = parse_chatgpt_file(path)?;
    println!(
        "chatgpt {}: {} conversation(s) in export (parsed in {:?})",
        path.display(),
        parsed.conversations.len(),
        parse_start.elapsed()
    );
    import_chatgpt_parsed_file(
        path,
        parsed,
        repo,
        &mut ws,
        &mut catalog,
        &mut catalog_head,
    )
}

fn import_chatgpt_parsed_file(
    path: &Path,
    parsed: ParsedChatgptFile,
    repo: &mut common::Repo,
    ws: &mut common::Ws,
    catalog: &mut TribleSet,
    catalog_head: &mut Option<common::CommitHandle>,
) -> Result<ImportStats> {
    let ParsedChatgptFile { conversations } = parsed;
    let total_conversations = conversations.len();

    let index_start = Instant::now();
    let export_root = path.parent().unwrap_or_else(|| Path::new("."));
    let export_files = index_export_files(export_root)
        .with_context(|| format!("index {}", export_root.display()))?;
    println!(
        "chatgpt phase index-attachments: {} file(s) indexed in {:?}",
        export_files.len(),
        index_start.elapsed()
    );
    let mut stats = ImportStats::default();
    let semantic_start = Instant::now();
    for (index, convo) in conversations.iter().enumerate() {
        let processed = index + 1;
        let convo_id = convo
            .get("id")
            .and_then(JsonValue::as_str)
            .unwrap_or("unknown");

        let convo_raw = serde_json::to_string(convo).context("serialize conversation json")?;
        let (raw_root, raw_fragment) = {
            let raw_tree_start = Instant::now();
            let mut raw_importer =
                JsonTreeImporter::<_, triblespace::prelude::valueschemas::Blake3>::new(
                    repo.storage_mut(),
                    None,
                );
            let raw_fragment = raw_importer
                .import_str(&convo_raw)
                .with_context(|| format!("import json tree for conversation {convo_id}"))?;
            let raw_root = raw_fragment
                .root()
                .ok_or_else(|| anyhow!("json tree importer did not return a single root"))?;
            if processed % 100 == 0 || processed == total_conversations {
                println!(
                    "chatgpt raw-tree progress {}/{} (latest {}, {:?})",
                    processed,
                    total_conversations,
                    convo_id,
                    raw_tree_start.elapsed()
                );
            }
            (raw_root, raw_fragment)
        };
        if common::commit_delta(
            repo,
            ws,
            catalog,
            catalog_head,
            raw_fragment.facts().clone(),
            "import chatgpt json tree",
        )? {
            stats.commits += 1;
        }

        let created_epoch = convo
            .get("create_time")
            .and_then(JsonValue::as_f64)
            .and_then(common::epoch_from_seconds);

        let mapping = convo
            .get("mapping")
            .and_then(JsonValue::as_object)
            .ok_or_else(|| anyhow!("conversation {convo_id} missing mapping"))?;

        let conversation_fragment = entity! { _ @
            common::metadata::tag: common::import_schema::kind_conversation,
            common::import_schema::source_format: "chatgpt",
            common::import_schema::source_conversation_id: ws.put(convo_id.to_string()),
            common::import_schema::source_raw_root: raw_root,
        };
        let conversation_id = conversation_fragment
            .root()
            .expect("entity! must export a single root id");

        let mut change = TribleSet::new();
        change += conversation_fragment;
        let mut author_cache: HashMap<String, Id> = HashMap::new();

        let mut node_to_message = HashMap::new();
        for (node_id, node) in mapping {
            let message = node.get("message").and_then(JsonValue::as_object);
            let should_import = message.is_some_and(should_import_message);
            if should_import {
                let source_message_id_handle = ws.put(node_id.to_string());
                let message_fragment = entity! { _ @
                    common::import_schema::conversation: conversation_id,
                    common::import_schema::source_message_id: source_message_id_handle,
                };
                let message_id = message_fragment
                    .root()
                    .expect("entity! must export a single root id");
                change += message_fragment;
                node_to_message.insert(node_id.as_str(), message_id);
            }
        }

        let mut attachment_data_loaded: HashSet<Id> = HashSet::new();
        for (node_id, node) in mapping {
            let message = match node.get("message").and_then(JsonValue::as_object) {
                Some(msg) => msg,
                None => continue,
            };
            if !should_import_message(message) {
                continue;
            }
            let content = extract_message_text(message).unwrap_or_default();
            let Some(message_id) = node_to_message.get(node_id.as_str()).copied() else {
                continue;
            };
            let message_entity = message_id
                .acquire()
                .expect("entity! root ids should be acquired in current thread");

            let role = message
                .get("author")
                .and_then(JsonValue::as_object)
                .and_then(|author| author.get("role"))
                .and_then(JsonValue::as_str)
                .unwrap_or("unknown");
            let name = message
                .get("author")
                .and_then(JsonValue::as_object)
                .and_then(|author| author.get("name"))
                .and_then(JsonValue::as_str)
                .unwrap_or(role);

            let author_key = format!("{name}::{role}");
            let author_id = if let Some(id) = author_cache.get(&author_key).copied() {
                id
            } else {
                let (id, author_change) = common::ensure_author(ws, catalog, name, role)?;
                change += author_change;
                author_cache.insert(author_key, id);
                id
            };

            let created_at_epoch = message
                .get("create_time")
                .and_then(JsonValue::as_f64)
                .and_then(common::epoch_from_seconds)
                .or_else(|| created_epoch.clone())
                .unwrap_or_else(common::unknown_epoch);
            let created_at = common::epoch_interval(created_at_epoch);
            let content_handle = ws.put(content);
            let content_type = message_content_type(message).filter(|value| !value.is_empty());
            let mut attachment_ids = Vec::new();

            // Import attachments referenced by this message (images, files, etc).
            for attachment in collect_attachments(message) {
                let AttachmentFields {
                    source_id,
                    source_pointer,
                    name,
                    mime,
                    size_bytes,
                    width_px,
                    height_px,
                } = attachment;
                let source_id_handle = ws.put(source_id.clone());
                let attachment_fragment = entity! { _ @
                    common::metadata::tag: common::archive::kind_attachment,
                    common::archive::attachment_source_id: source_id_handle,
                };
                let attachment_id = attachment_fragment
                    .root()
                    .expect("entity! must export a single root id");
                let attachment_entity = attachment_id
                    .acquire()
                    .expect("entity! root ids should be acquired in current thread");
                attachment_ids.push(attachment_id);

                let source_pointer_handle = source_pointer.map(|pointer| ws.put(pointer));
                let attachment_name = name.map(|value| ws.put(value));
                let attachment_mime = mime.as_deref();
                let attachment_size = size_bytes;
                let attachment_width = width_px;
                let attachment_height = height_px;
                let mut attachment_data = None;

                let needs_data = attachment_data_handle(catalog, attachment_id).is_none()
                    && attachment_data_handle(&change, attachment_id).is_none();
                if needs_data {
                    if let Some(path) = export_files.get(&source_id) {
                        if attachment_data_loaded.insert(attachment_id) {
                            let bytes = fs::read(path)
                                .with_context(|| format!("read attachment {}", path.display()))?;
                            attachment_data = Some(ws.put(Bytes::from_source(bytes)));
                            stats.attachments += 1;
                        }
                    }
                }

                change += entity! { &attachment_entity @
                    common::metadata::tag: common::archive::kind_attachment,
                    common::archive::attachment_source_id: source_id_handle,
                    common::archive::attachment_source_pointer?: source_pointer_handle,
                    common::archive::attachment_name?: attachment_name,
                    common::archive::attachment_mime?: attachment_mime,
                    common::archive::attachment_size_bytes?: attachment_size,
                    common::archive::attachment_width_px?: attachment_width,
                    common::archive::attachment_height_px?: attachment_height,
                    common::archive::attachment_data?: attachment_data,
                };
            }

            let (reply_to, source_parent_id) = node
                .get("parent")
                .and_then(JsonValue::as_str)
                .and_then(|parent| {
                    node_to_message
                        .get(parent)
                        .copied()
                        .map(|parent_id| (Some(parent_id), Some(ws.put(parent.to_string()))))
                })
                .unwrap_or((None, None));

            change += entity! { &message_entity @
                common::metadata::tag: common::archive::kind_message,
                common::archive::author: author_id,
                common::archive::content: content_handle,
                common::metadata::created_at: created_at,
                common::archive::content_type?: content_type,
                common::archive::attachment*: attachment_ids,
                common::archive::reply_to?: reply_to,
                common::import_schema::source_author: ws.put(name.to_string()),
                common::import_schema::source_role: ws.put(role.to_string()),
                common::import_schema::source_created_at: created_at,
                common::import_schema::source_parent_id?: source_parent_id,
            };

            stats.messages += 1;
        }

        if common::commit_delta(
            repo,
            ws,
            catalog,
            catalog_head,
            change,
            "import chatgpt",
        )? {
            stats.commits += 1;
        }
        stats.conversations += 1;
        if processed % 100 == 0 || processed == total_conversations {
            println!(
                "chatgpt progress {}/{} conversations (messages {}, attachments {}, commits {})",
                processed, total_conversations, stats.messages, stats.attachments, stats.commits
            );
        }
    }
    println!(
        "chatgpt phase semantic-build: {} conversation(s), {} message(s), {} attachment(s) in {:?}",
        stats.conversations,
        stats.messages,
        stats.attachments,
        semantic_start.elapsed()
    );

    Ok(stats)
}

fn parse_chatgpt_file(path: &Path) -> Result<ParsedChatgptFile> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let conversations = serde_json::from_str::<Vec<JsonValue>>(&raw).with_context(|| {
        format!(
            "parse chatgpt json array from {}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<unknown>")
        )
    })?;
    Ok(ParsedChatgptFile { conversations })
}

#[derive(Debug, Default, Clone)]
struct AttachmentFields {
    source_id: String,
    source_pointer: Option<String>,
    name: Option<String>,
    mime: Option<String>,
    size_bytes: Option<u64>,
    width_px: Option<u64>,
    height_px: Option<u64>,
}

fn collect_conversation_files(path: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path).with_context(|| format!("read dir {}", path.display()))? {
        let entry = entry.context("read dir entry")?;
        let entry_path = entry.path();
        let file_type = entry.file_type().context("entry type")?;
        if file_type.is_dir() {
            collect_conversation_files(&entry_path, out)?;
        } else if file_type.is_file() {
            if entry_path.file_name().and_then(|name| name.to_str()) == Some("conversations.json") {
                out.push(entry_path);
            }
        }
    }
    Ok(())
}

fn index_export_files(root: &Path) -> Result<HashMap<String, PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).with_context(|| format!("read dir {}", dir.display()))? {
            let entry = entry.context("read dir entry")?;
            let entry_path = entry.path();
            let file_type = entry.file_type().context("entry type")?;
            if file_type.is_dir() {
                stack.push(entry_path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(file_id) = chatgpt_file_id_from_filename(name) else {
                continue;
            };
            files.push((file_id, entry_path));
        }
    }

    files.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut out = HashMap::new();
    for (file_id, path) in files {
        out.entry(file_id).or_insert(path);
    }
    Ok(out)
}

fn chatgpt_file_id_from_filename(filename: &str) -> Option<String> {
    // ChatGPT exports commonly store attachments as:
    // - file-<id>-image.png
    // - file-<id>-Screenshot ... .png
    // - file-<id>-<uuid>.jpeg
    // We key by the "file-<id>" prefix.
    if !filename.starts_with("file-") {
        return None;
    }
    let mut it = filename.splitn(3, '-');
    let first = it.next()?;
    let second = it.next()?;
    if first != "file" || second.is_empty() {
        return None;
    }
    Some(format!("{first}-{second}"))
}

fn message_content_type(message: &serde_json::Map<String, JsonValue>) -> Option<&str> {
    message
        .get("content")
        .and_then(JsonValue::as_object)
        .and_then(|c| c.get("content_type"))
        .and_then(JsonValue::as_str)
}

fn should_import_message(message: &serde_json::Map<String, JsonValue>) -> bool {
    let text = extract_message_text(message).unwrap_or_default();
    if !text.is_empty() {
        return true;
    }

    // Import messages that carry file pointers even if they have no caption text.
    if has_message_attachments(message) {
        return true;
    }

    false
}

fn has_message_attachments(message: &serde_json::Map<String, JsonValue>) -> bool {
    let meta_attachments = message
        .get("metadata")
        .and_then(JsonValue::as_object)
        .and_then(|m| m.get("attachments"))
        .and_then(JsonValue::as_array)
        .is_some_and(|arr| !arr.is_empty());
    if meta_attachments {
        return true;
    }

    let Some(parts) = message
        .get("content")
        .and_then(JsonValue::as_object)
        .and_then(|c| c.get("parts"))
        .and_then(JsonValue::as_array)
    else {
        return false;
    };

    for part in parts {
        let Some(obj) = part.as_object() else {
            continue;
        };
        if let Some(pointer) = obj.get("asset_pointer").and_then(JsonValue::as_str) {
            if file_id_from_asset_pointer(pointer).is_some() {
                return true;
            }
        }
    }
    false
}

fn file_id_from_asset_pointer(pointer: &str) -> Option<&str> {
    // Typical pointer: "file-service://file-<id>"
    let prefix = "file-service://";
    if pointer.starts_with(prefix) {
        let rest = &pointer[prefix.len()..];
        if rest.starts_with("file-") {
            return Some(rest);
        }
    }
    None
}

fn collect_attachments(message: &serde_json::Map<String, JsonValue>) -> Vec<AttachmentFields> {
    let mut by_id: HashMap<String, AttachmentFields> = HashMap::new();

    // 1) metadata.attachments
    if let Some(attachments) = message
        .get("metadata")
        .and_then(JsonValue::as_object)
        .and_then(|m| m.get("attachments"))
        .and_then(JsonValue::as_array)
    {
        for att in attachments {
            let Some(obj) = att.as_object() else {
                continue;
            };
            let Some(id) = obj.get("id").and_then(JsonValue::as_str) else {
                continue;
            };
            let entry = by_id
                .entry(id.to_string())
                .or_insert_with(|| AttachmentFields {
                    source_id: id.to_string(),
                    ..Default::default()
                });

            if let Some(name) = obj.get("name").and_then(JsonValue::as_str) {
                entry.name.get_or_insert_with(|| name.to_string());
            }
            if let Some(mime) = obj.get("mime_type").and_then(JsonValue::as_str) {
                entry.mime.get_or_insert_with(|| mime.to_string());
            }

            // The export uses `size` in metadata.attachments.
            if let Some(size) = json_u64(obj.get("size")) {
                entry.size_bytes.get_or_insert(size);
            }
            if let Some(width) = json_u64(obj.get("width")) {
                entry.width_px.get_or_insert(width);
            }
            if let Some(height) = json_u64(obj.get("height")) {
                entry.height_px.get_or_insert(height);
            }
        }
    }

    // 2) content.parts objects (contains asset_pointer + size_bytes, etc)
    if let Some(parts) = message
        .get("content")
        .and_then(JsonValue::as_object)
        .and_then(|c| c.get("parts"))
        .and_then(JsonValue::as_array)
    {
        for part in parts {
            let Some(obj) = part.as_object() else {
                continue;
            };
            let Some(pointer) = obj.get("asset_pointer").and_then(JsonValue::as_str) else {
                continue;
            };
            let Some(file_id) = file_id_from_asset_pointer(pointer) else {
                continue;
            };

            let entry = by_id
                .entry(file_id.to_string())
                .or_insert_with(|| AttachmentFields {
                    source_id: file_id.to_string(),
                    ..Default::default()
                });

            entry
                .source_pointer
                .get_or_insert_with(|| pointer.to_string());

            // The parts use `size_bytes`.
            if let Some(size) = json_u64(obj.get("size_bytes")) {
                entry.size_bytes.get_or_insert(size);
            }
            if let Some(width) = json_u64(obj.get("width")) {
                entry.width_px.get_or_insert(width);
            }
            if let Some(height) = json_u64(obj.get("height")) {
                entry.height_px.get_or_insert(height);
            }
        }
    }

    let mut out: Vec<_> = by_id.into_values().collect();
    out.sort_by(|a, b| a.source_id.cmp(&b.source_id));
    out
}

fn json_u64(v: Option<&JsonValue>) -> Option<u64> {
    let v = v?;
    if let Some(u) = v.as_u64() {
        return Some(u);
    }
    if let Some(i) = v.as_i64() {
        if i >= 0 {
            return Some(i as u64);
        }
    }
    if let Some(f) = v.as_f64() {
        if f.is_finite() && f >= 0.0 && f.fract() == 0.0 {
            return Some(f as u64);
        }
    }
    None
}

fn extract_message_text(message: &serde_json::Map<String, JsonValue>) -> Option<String> {
    let content = message.get("content")?.as_object()?;
    let parts = content.get("parts")?.as_array()?;
    let mut out = String::new();
    for part in parts {
        if let Some(text) = part.as_str() {
            if !out.is_empty() {
                out.push_str("\n\n");
            }
            out.push_str(text);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn attachment_data_handle(
    catalog: &TribleSet,
    attachment_id: Id,
) -> Option<
    Value<
        triblespace::prelude::valueschemas::Handle<
            triblespace::prelude::valueschemas::Blake3,
            common::archive_schema::FileBytes,
        >,
    >,
> {
    find!(
        (handle: Value<triblespace::prelude::valueschemas::Handle<triblespace::prelude::valueschemas::Blake3, common::archive_schema::FileBytes>>),
        pattern!(catalog, [{ attachment_id @ common::archive::attachment_data: ?handle }])
    )
    .into_iter()
    .next()
    .map(|(h,)| h)
}

pub fn import_into_archive(
    path: &Path,
    pile_path: &Path,
    branch_name: &str,
    branch_id: Id,
) -> Result<()> {
    let _span = info_span!(
        "chatgpt_import",
        path = %path.display(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}")
    )
    .entered();
    let import_start = Instant::now();
    let (mut repo, branch_id) = common::open_repo_for_write(pile_path, branch_id, branch_name)?;
    let res = import_chatgpt_path(path, &mut repo, branch_id);
    tracing::info!(
        ok = res.is_ok(),
        elapsed_ms = import_start.elapsed().as_millis() as u64,
        "chatgpt import finished"
    );
    let close_res = repo
        .close()
        .map_err(|e| anyhow!("close pile {}: {e:?}", pile_path.display()));
    match (res, close_res) {
        (Ok(stats), Ok(())) => {
            println!(
                "Imported {} conversation(s), {} message(s), {} attachment(s) in {} new commit(s).",
                stats.conversations, stats.messages, stats.attachments, stats.commits
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
