use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine as _;
use ureq;
use serde_json::Value as JsonValue;
use triblespace::core::blob::Bytes;
use triblespace::core::blob::schemas::UnknownBlob;
use triblespace::core::metadata;
use triblespace::core::import::json::JsonObjectImporter;
use triblespace::core::repo::Workspace;
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, Handle, NsTAIInterval, ShortString};
use triblespace::prelude::*;

use crate::blob_refs::{PromptChunk, split_blob_refs, unknown_blob_handle_from_hex};
use crate::chat_prompt::{ChatMessage, ChatRole};
use crate::config::Config;
use crate::repo_util::{
    close_repo, current_branch_head, ensure_worker_name, init_repo, load_text, pull_workspace,
    push_workspace, refresh_cached_checkout,
};
use crate::schema::model_chat;
use crate::time_util::{epoch_interval, interval_key, now_epoch, ordered_epoch_interval};

#[derive(Debug, Clone)]
struct ModelRequest {
    id: Id,
    context: Value<Handle<Blake3, LongString>>,
    model: Option<Value<ShortString>>,
}

#[derive(Debug)]
struct ModelResult {
    output_text: String,
    reasoning_text: Option<String>,
    raw: String,
    response_id: Option<String>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
}

enum ModelBackend {
    OpenAI { endpoint_url: String },
    Anthropic { endpoint_url: String },
}

impl ModelBackend {
    fn from_config(config: &Config) -> Self {
        let base = config.model.base_url.trim().trim_end_matches('/');
        if base.contains("anthropic.com") {
            Self::Anthropic {
                endpoint_url: format!("{base}/v1/messages"),
            }
        } else {
            Self::OpenAI {
                endpoint_url: chat_completions_url(base),
            }
        }
    }

    fn endpoint_url(&self) -> &str {
        match self {
            Self::OpenAI { endpoint_url } | Self::Anthropic { endpoint_url } => endpoint_url,
        }
    }

    fn build_payload(
        &self,
        config: &Config,
        ws: &mut Workspace<Pile>,
        model: &str,
        messages: &[ChatMessage],
    ) -> JsonValue {
        match self {
            Self::OpenAI { .. } => build_openai_payload(config, ws, model, messages),
            Self::Anthropic { .. } => build_anthropic_payload(config, ws, model, messages),
        }
    }

    fn parse_response(
        &self,
        response: ureq::http::Response<ureq::Body>,
        stream: bool,
    ) -> Result<ModelResult> {
        match self {
            Self::OpenAI { .. } => {
                if stream {
                    parse_openai_stream(response)
                } else {
                    parse_openai_response(response)
                }
            }
            Self::Anthropic { .. } => {
                if stream {
                    parse_anthropic_stream(response)
                } else {
                    parse_anthropic_response(response)
                }
            }
        }
    }
}

struct ModelHttpClient {
    agent: ureq::Agent,
    backend: ModelBackend,
    api_key: Option<String>,
    stream: bool,
}

const SEND_MAX_ATTEMPTS: usize = 8;
const SEND_RETRY_BASE_MS: u64 = 1_000;
const SEND_RETRY_MAX_MS: u64 = 30_000;
const MODEL_CONNECT_TIMEOUT_SECS: u64 = 20;
const MODEL_REQUEST_TIMEOUT_SECS: u64 = 240;

fn chat_completions_url(api_base_url: &str) -> String {
    let base = api_base_url.trim().trim_end_matches('/');
    if base.ends_with("/chat/completions") || base.ends_with("/completions") {
        return base.to_string();
    }
    if let Some(base) = base.strip_suffix("/responses") {
        return format!("{base}/chat/completions");
    }
    format!("{base}/chat/completions")
}

impl ModelHttpClient {
    fn new(config: &Config) -> Result<Self> {
        let agent_config = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(MODEL_CONNECT_TIMEOUT_SECS)))
            .timeout_global(Some(Duration::from_secs(MODEL_REQUEST_TIMEOUT_SECS)))
            .http_status_as_error(false)
            .build();
        let agent = ureq::Agent::new_with_config(agent_config);
        let backend = ModelBackend::from_config(config);
        Ok(Self {
            agent,
            backend,
            api_key: config.model.api_key.clone(),
            stream: config.model.stream,
        })
    }

    fn send_payload(&self, payload: &JsonValue) -> Result<ModelResult> {
        let mut last_error: Option<anyhow::Error> = None;
        let endpoint = self.backend.endpoint_url();
        for attempt in 1..=SEND_MAX_ATTEMPTS {
            match self.send_payload_once(payload) {
                Ok(result) => return Ok(result),
                Err(failure) => {
                    eprintln!(
                        "warning: model send attempt {attempt}/{SEND_MAX_ATTEMPTS} to {endpoint} failed: {err:#}",
                        err = failure.error
                    );
                    last_error = Some(failure.error);
                    if !failure.retryable {
                        break;
                    }
                    if attempt < SEND_MAX_ATTEMPTS {
                        let exp = u32::try_from(attempt.saturating_sub(1)).unwrap_or(u32::MAX);
                        let scale = 1_u64.checked_shl(exp).unwrap_or(u64::MAX);
                        let backoff_ms = SEND_RETRY_BASE_MS
                            .saturating_mul(scale)
                            .min(SEND_RETRY_MAX_MS);
                        sleep(Duration::from_millis(backoff_ms.max(1)));
                    }
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("request failed without error detail")))
    }

    fn send_payload_once(
        &self,
        payload: &JsonValue,
    ) -> std::result::Result<ModelResult, SendFailure> {
        let response = self.send_request(payload).map_err(|err| {
            let retryable = is_retryable_request_error(&err);
            SendFailure {
                retryable,
                error: anyhow::Error::new(err).context("send http request"),
            }
        })?;

        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            return self
                .backend
                .parse_response(response, self.stream)
                .map_err(|err| SendFailure {
                    retryable: false,
                    error: err,
                });
        }

        let endpoint = self.backend.endpoint_url();
        let body = response
            .into_body()
            .read_to_string()
            .unwrap_or_else(|_| "<failed to read error body>".to_string());

        let error = anyhow::anyhow!(
            "request failed: HTTP {} for url ({}){}",
            status,
            endpoint,
            if body.trim().is_empty() {
                "".to_string()
            } else {
                format!(": {}", body.trim())
            }
        );
        Err(SendFailure {
            retryable: is_retryable_http_status(status),
            error,
        })
    }

    fn send_request(&self, payload: &JsonValue) -> std::result::Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        let endpoint = self.backend.endpoint_url();
        let mut request = self.agent.post(endpoint);
        if let Some(ref key) = self.api_key {
            match &self.backend {
                ModelBackend::OpenAI { .. } => {
                    request = request.header("Authorization", &format!("Bearer {key}"));
                }
                ModelBackend::Anthropic { .. } => {
                    request = request
                        .header("x-api-key", key)
                        .header("anthropic-version", "2023-06-01");
                }
            }
        }
        request.send_json(payload)
    }
}

#[derive(Debug)]
struct SendFailure {
    retryable: bool,
    error: anyhow::Error,
}

fn is_retryable_http_status(status: u16) -> bool {
    status == 408 // REQUEST_TIMEOUT
        || status == 429 // TOO_MANY_REQUESTS
        || status == 529 // Anthropic "overloaded"
        || (500..600).contains(&status)
}

fn is_retryable_request_error(err: &ureq::Error) -> bool {
    matches!(err, ureq::Error::Timeout(_) | ureq::Error::ConnectionFailed)
}

pub(crate) fn run_model_loop(
    config: Config,
    worker_id: Id,
    poll_ms: u64,
    stop: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let (mut repo, branch_id) = init_repo(&config).context("open triblespace repo")?;
    let result = (|| -> Result<()> {
        let label = format!("model-{}", id_prefix(worker_id));
        ensure_worker_name(&mut repo, branch_id, worker_id, &label)?;
        let mut cached_head = None;
        let mut cached_catalog = TribleSet::new();

        let client = ModelHttpClient::new(&config)?;

        loop {
            if stop_requested(&stop) {
                break;
            }

            let branch_head = current_branch_head(&mut repo, branch_id)?;
            if branch_head == cached_head {
                sleep(Duration::from_millis(poll_ms));
                continue;
            }

            let mut ws = pull_workspace(&mut repo, branch_id, "pull workspace")?;
            refresh_cached_checkout(&mut ws, &mut cached_head, &mut cached_catalog)?;
            let Some(request) = next_pending_model_request(&cached_catalog, worker_id) else {
                sleep(Duration::from_millis(poll_ms));
                continue;
            };

            if stop_requested(&stop) {
                break;
            }

            let context_text = load_text(&mut ws, request.context).context("load context")?;
            let model = request
                .model
                .and_then(|value| value.try_from_value::<String>().ok())
                .unwrap_or_else(|| config.model.model.clone());

            let attempt: u64 = 1;
            let messages: Vec<ChatMessage> = match serde_json::from_str(context_text.as_str()) {
                Ok(messages) => messages,
                Err(err) => {
                    let finished_e = now_epoch();
                    let finished_at = epoch_interval(finished_e);
                    let ordered_finished_at = ordered_epoch_interval(finished_e);
                    let result_id = ufoid();
                    let handle = ws.put(format!("parse chat context: {err}"));
                    let mut change = TribleSet::new();
                    change += entity! { &result_id @
                        metadata::tag: model_chat::kind_result,
                        model_chat::about_request: request.id,
                        model_chat::finished_at: finished_at,
                        model_chat::ordered_finished_at: ordered_finished_at,
                        model_chat::attempt: attempt,
                        model_chat::error: handle,
                    };
                    ws.commit(change, "model_chat result (context parse error)");
                    push_workspace(&mut repo, &mut ws).context("push context parse error")?;
                    sleep(Duration::from_millis(poll_ms));
                    continue;
                }
            };
            let payload = client.backend.build_payload(&config, &mut ws, model.as_str(), &messages);
            let request_raw =
                serde_json::to_string(&payload).context("serialize request payload")?;

            let started_e = now_epoch();
            let started_at = epoch_interval(started_e);
            let ordered_started_at = ordered_epoch_interval(started_e);
            let in_progress_id = ufoid();
            let request_raw_handle = ws.put(request_raw);

            let mut change = TribleSet::new();
            change += entity! { ExclusiveId::force_ref(&request.id) @
                model_chat::request_raw: request_raw_handle,
            };
            change += entity! { &in_progress_id @
                metadata::tag: model_chat::kind_in_progress,
                model_chat::about_request: request.id,
                model_chat::started_at: started_at,
                model_chat::ordered_started_at: ordered_started_at,
                model_chat::worker: worker_id,
                model_chat::attempt: attempt,
            };
            ws.commit(change, "model_chat in_progress");
            push_workspace(&mut repo, &mut ws).context("push in_progress")?;

            let result = client.send_payload(&payload);

            let finished_e = now_epoch();
            let finished_at = epoch_interval(finished_e);
            let ordered_finished_at = ordered_epoch_interval(finished_e);
            let result_id = ufoid();
            let mut change = TribleSet::new();
            change += entity! { &result_id @
                metadata::tag: model_chat::kind_result,
                model_chat::about_request: request.id,
                model_chat::finished_at: finished_at,
                model_chat::ordered_finished_at: ordered_finished_at,
                model_chat::attempt: attempt,
            };

            let mut import_data = None;

            match result {
                Ok(result) => {
                    let response_id = result.response_id.clone();
                    let raw_blob = result.raw.clone().to_blob();
                    let output_handle = ws.put(result.output_text);
                    let raw_handle = ws.put(result.raw);
                    change += entity! { &result_id @
                        model_chat::output_text: output_handle,
                        model_chat::response_raw: raw_handle,
                    };
                    if let Some(reasoning_text) = result.reasoning_text {
                        let handle = ws.put(reasoning_text);
                        change += entity! { &result_id @
                            model_chat::reasoning_text: handle,
                        };
                    }
                    if let Some(response_id) = response_id {
                        let response_id_handle = ws.put(response_id);
                        change += entity! { &result_id @
                            model_chat::response_id: response_id_handle,
                        };
                    }
                    if let Some(n) = result.input_tokens {
                        change += entity! { &result_id @ model_chat::input_tokens: n };
                    }
                    if let Some(n) = result.output_tokens {
                        change += entity! { &result_id @ model_chat::output_tokens: n };
                    }
                    if let Some(n) = result.cache_creation_input_tokens {
                        change += entity! { &result_id @ model_chat::cache_creation_input_tokens: n };
                    }
                    if let Some(n) = result.cache_read_input_tokens {
                        change += entity! { &result_id @ model_chat::cache_read_input_tokens: n };
                    }

                    let mut import_blobs = MemoryBlobStore::<Blake3>::new();
                    let mut importer =
                        JsonObjectImporter::<_, Blake3>::new(&mut import_blobs, None);
                    match importer.import_blob(raw_blob) {
                        Ok(fragment) => {
                            let import_reader = import_blobs
                                .reader()
                                .context("read response import blobs")?;
                            for (_, blob) in import_reader.iter() {
                                ws.put::<UnknownBlob, _>(blob.bytes.clone());
                            }

                            for root in fragment.exports() {
                                change += entity! { &result_id @
                                    model_chat::response_json_root: root,
                                };
                            }

                            import_data = Some(fragment);
                        }
                        Err(err) => {
                            eprintln!("Failed to import response JSON: {err}");
                        }
                    }
                }
                Err(err) => {
                    let handle = ws.put(format!("{err:#}"));
                    change += entity! { &result_id @
                        model_chat::error: handle,
                    };
                }
            }

            if let Some(data) = import_data {
                ws.commit(data, "import response json");
            }
            ws.commit(change, "model_chat result");
            push_workspace(&mut repo, &mut ws).context("push result")?;
        }

        Ok(())
    })();

    if let Err(err) = close_repo(repo) {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }

    result
}

fn stop_requested(stop: &Option<Arc<AtomicBool>>) -> bool {
    stop.as_ref()
        .map(|flag| flag.load(Ordering::Relaxed))
        .unwrap_or(false)
}

fn next_pending_model_request(catalog: &TribleSet, worker_id: Id) -> Option<ModelRequest> {
    let done: HashSet<Id> = find!(
        (request_id: Id),
        pattern!(catalog, [{
            _?event @
            metadata::tag: model_chat::kind_result,
            model_chat::about_request: ?request_id,
        }])
    )
    .map(|(id,)| id)
    .collect();

    let in_progress: HashSet<Id> = find!(
        (request_id: Id),
        pattern!(catalog, [{
            _?event @
            metadata::tag: model_chat::kind_in_progress,
            model_chat::about_request: ?request_id,
            model_chat::worker: &worker_id,
        }])
    )
    .map(|(id,)| id)
    .collect();

    let mut candidates: Vec<_> = find!(
        (request_id: Id, context: Value<Handle<Blake3, LongString>>),
        pattern!(catalog, [{
            ?request_id @
            metadata::tag: model_chat::kind_request,
            model_chat::context: ?context,
        }])
    )
    .filter(|(id, _)| !done.contains(id) && !in_progress.contains(id))
    .collect();

    candidates.sort_by_key(|(id, _)| {
        find!(
            (ts: Value<NsTAIInterval>),
            pattern!(catalog, [{ *id @ model_chat::requested_at: ?ts }])
        )
        .next()
        .map(|(ts,)| interval_key(ts))
        .unwrap_or(i128::MIN)
    });

    let (id, context) = candidates.into_iter().next()?;

    let model = find!(
        (m: Value<ShortString>),
        pattern!(catalog, [{ id @ model_chat::model: ?m }])
    )
    .next()
    .map(|(m,)| m);

    Some(ModelRequest { id, context, model })
}

fn build_openai_messages(
    config: &Config,
    ws: &mut Workspace<Pile>,
    model: &str,
    messages: &[ChatMessage],
) -> Vec<JsonValue> {
    let supports_images = config.model.vision;
    let mut out = Vec::new();

    for message in messages {
        let role = match message.role {
            ChatRole::System => "system",
            ChatRole::User => "user",
            ChatRole::Assistant => "assistant",
        };

        if message.role == ChatRole::User && supports_images {
            let chunks = split_blob_refs(message.content.as_str());
            let has_blob = chunks.iter().any(|chunk| {
                if let PromptChunk::Blob(_) = chunk {
                    true
                } else {
                    false
                }
            });
            if has_blob {
                let content = build_openai_input_content(&config, ws, model, message.content.as_str());
                out.push(serde_json::json!({ "role": role, "content": content }));
                continue;
            }
        }

        out.push(serde_json::json!({ "role": role, "content": message.content.as_str() }));
    }

    out
}

fn build_openai_payload(
    config: &Config,
    ws: &mut Workspace<Pile>,
    model: &str,
    messages: &[ChatMessage],
) -> JsonValue {
    let messages = build_openai_messages(&config, ws, model, messages);
    let max_tokens = config.model.max_output_tokens.max(1);
    serde_json::json!({
        "model": model,
        "messages": messages,
        "stream": config.model.stream,
        "max_tokens": max_tokens,
    })
}

fn build_openai_input_content(
    config: &Config,
    ws: &mut Workspace<Pile>,
    _model: &str,
    prompt: &str,
) -> Vec<JsonValue> {
    let supports_images = config.model.vision;
    let mut content = Vec::new();
    let mut images_added = 0usize;

    for chunk in split_blob_refs(prompt) {
        match chunk {
            PromptChunk::Text(text) => {
                if !text.is_empty() {
                    content.push(serde_json::json!({
                        "type": "text",
                        "text": text,
                    }));
                }
            }
            PromptChunk::Blob(blob_ref) => {
                if !supports_images {
                    content.push(serde_json::json!({
                        "type": "text",
                        "text": format_blob_fallback(blob_ref.raw.as_str(), "vision unavailable for current model"),
                    }));
                    continue;
                }
                if images_added >= config.model.max_inline_images as usize {
                    content.push(serde_json::json!({
                        "type": "text",
                        "text": format_blob_fallback(blob_ref.raw.as_str(), "image limit reached"),
                    }));
                    continue;
                }
                match resolve_blob_image(&config,
                    ws,
                    &blob_ref.digest_hex,
                    None,
                ) {
                    Ok((mime, b64)) => {
                        let data_url = format!("data:{mime};base64,{b64}");
                        content.push(serde_json::json!({
                            "type": "image_url",
                            "image_url": {"url": data_url},
                        }));
                        images_added += 1;
                    }
                    Err(reason) => {
                        content.push(serde_json::json!({
                            "type": "text",
                            "text": format_blob_fallback(blob_ref.raw.as_str(), reason.as_str()),
                        }));
                    }
                }
            }
        }
    }

    if content.is_empty() {
        content.push(serde_json::json!({
            "type": "text",
            "text": prompt,
        }));
    }
    content
}

/// Resolves a blob image to its (mime_type, base64_data) components.
fn resolve_blob_image(
    config: &Config,
    ws: &mut Workspace<Pile>,
    digest_hex: &str,
    mime_hint: Option<&str>,
) -> std::result::Result<(String, String), String> {
    let handle =
        unknown_blob_handle_from_hex(digest_hex).ok_or_else(|| "bad blob digest".to_string())?;
    let bytes: Bytes = ws
        .get(handle)
        .map_err(|_| "blob not found in pile".to_string())?;
    const MIN_IMAGE_BYTES: usize = 200;
    if bytes.len() < MIN_IMAGE_BYTES {
        return Err(format!(
            "image too small ({} bytes < {} bytes)",
            bytes.len(),
            MIN_IMAGE_BYTES
        ));
    }
    if bytes.len() > config.model.max_inline_image_bytes as usize {
        return Err(format!(
            "image too large ({} bytes > {} bytes)",
            bytes.len(),
            config.model.max_inline_image_bytes as usize
        ));
    }
    let mime = match mime_hint.filter(|mime| is_supported_image_mime(mime)) {
        Some(mime) => mime.to_owned(),
        None => sniff_image_mime(bytes.as_ref())
            .map(str::to_owned)
            .ok_or_else(|| "blob is not a supported image format".to_string())?,
    };
    eprintln!(
        "resolve_blob_image: digest={} size={} mime={}",
        digest_hex,
        bytes.len(),
        mime,
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes.as_ref());
    Ok((mime, encoded))
}

fn is_supported_image_mime(mime: &str) -> bool {
    match mime {
        "image/jpeg" | "image/png" | "image/gif" | "image/webp" => true,
        _ => false,
    }
}

fn sniff_image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 8 && bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }
    if bytes.len() >= 3 && bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if bytes.len() >= 6 && (bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    None
}

fn format_blob_fallback(raw_marker: &str, reason: &str) -> String {
    format!("[blob omitted: {reason}] {raw_marker}")
}

// ---------------------------------------------------------------------------
// Anthropic Messages API
// ---------------------------------------------------------------------------

fn build_anthropic_payload(
    config: &Config,
    ws: &mut Workspace<Pile>,
    model: &str,
    messages: &[ChatMessage],
) -> JsonValue {
    let supports_images = config.model.vision;

    // Extract system messages into a top-level "system" content array with cache_control.
    let system_parts: Vec<&str> = messages
        .iter()
        .filter(|m| m.role == ChatRole::System)
        .map(|m| m.content.as_str())
        .collect();

    let mut api_messages = Vec::new();
    for message in messages {
        if message.role == ChatRole::System {
            continue;
        }
        let role = match message.role {
            ChatRole::User => "user",
            ChatRole::Assistant => "assistant",
            ChatRole::System => unreachable!(),
        };

        if message.role == ChatRole::User && supports_images {
            let chunks = split_blob_refs(message.content.as_str());
            let has_blob = chunks
                .iter()
                .any(|c| if let PromptChunk::Blob(_) = c { true } else { false });
            if has_blob {
                let content = build_anthropic_input_content(&config, ws, model, message.content.as_str());
                api_messages.push(serde_json::json!({ "role": role, "content": content }));
                continue;
            }
        }

        api_messages.push(serde_json::json!({
            "role": role,
            "content": message.content.as_str(),
        }));
    }

    // Strategic cache_control breakpoint placement (max 4 per request).
    // We place 2 on messages (no system prompt breakpoint needed — it's always
    // the prefix start and is implicitly covered by any message cache hit):
    //   1. Breath user message ("present moment begins.") — stable memory boundary.
    //      The 20-block lookback from this breakpoint finds the longest cached
    //      memory prefix, even after compaction (memory cover delay in main.rs
    //      ensures the old prefix gets one more cached turn before switching).
    //   2. Second-to-last user message — growing conversation edge.
    //      The last message has a changing fill_pct suffix and is intentionally
    //      uncached. When the next turn arrives, it becomes second-to-last
    //      (clean, without fill_pct), naturally extending the cached prefix.
    // NOTE: must happen BEFORE building the payload (json!() deep-copies).
    {
        let breath_idx = api_messages.iter().position(|m| {
            m.get("role").and_then(|r| r.as_str()) == Some("user")
                && m.get("content")
                    .and_then(|c| c.as_str())
                    .map_or(false, |t| t == "present moment begins.")
        });

        let user_indices: Vec<usize> = api_messages
            .iter()
            .enumerate()
            .filter(|(_, m)| m.get("role").and_then(|r| r.as_str()) == Some("user"))
            .map(|(i, _)| i)
            .collect();
        let second_to_last_user_idx = if user_indices.len() >= 2 {
            Some(user_indices[user_indices.len() - 2])
        } else {
            None
        };

        let mut breakpoints: Vec<usize> = Vec::new();
        if let Some(idx) = breath_idx {
            breakpoints.push(idx);
        }
        if let Some(idx) = second_to_last_user_idx {
            if !breakpoints.contains(&idx) {
                breakpoints.push(idx);
            }
        }

        for idx in breakpoints {
            apply_message_cache_control(&mut api_messages[idx]);
        }
    }

    let max_tokens = config.model.max_output_tokens.max(1);
    let mut payload = serde_json::json!({
        "model": model,
        "messages": api_messages,
        "stream": config.model.stream,
        "max_tokens": max_tokens,
    });

    if !system_parts.is_empty() {
        payload["system"] = serde_json::Value::String(system_parts.join("\n\n"));
    }

    // Extended thinking support.
    // The Anthropic API requires max_tokens > budget_tokens, where max_tokens
    // is the total envelope (thinking + output). So we set budget_tokens based
    // on reasoning effort and then raise max_tokens to fit both.
    if let Some(ref effort) = config.model.reasoning_effort {
        let budget = match effort.as_str() {
            "low" => max_tokens.max(1024),
            "medium" => max_tokens.saturating_mul(2).max(2048),
            _ => max_tokens.saturating_mul(4).max(4096),
        };
        payload["max_tokens"] = serde_json::json!(budget + max_tokens);
        payload["thinking"] = serde_json::json!({
            "type": "enabled",
            "budget_tokens": budget,
        });
    }

    payload
}

/// Adds `cache_control` to a message's content.
/// String content is wrapped in a content array; array content gets the tag on its last element.
fn apply_message_cache_control(msg: &mut JsonValue) {
    if let Some(text) = msg.get("content").and_then(|c| c.as_str()).map(String::from) {
        msg["content"] = serde_json::json!([{
            "type": "text",
            "text": text,
            "cache_control": { "type": "ephemeral" },
        }]);
    } else if let Some(content) = msg.get_mut("content").and_then(|c| c.as_array_mut()) {
        if let Some(last) = content.last_mut() {
            last["cache_control"] = serde_json::json!({ "type": "ephemeral" });
        }
    }
}

fn build_anthropic_input_content(
    config: &Config,
    ws: &mut Workspace<Pile>,
    _model: &str,
    prompt: &str,
) -> Vec<JsonValue> {
    let supports_images = config.model.vision;
    let mut content = Vec::new();
    let mut images_added = 0usize;

    for chunk in split_blob_refs(prompt) {
        match chunk {
            PromptChunk::Text(text) => {
                if !text.is_empty() {
                    content.push(serde_json::json!({
                        "type": "text",
                        "text": text,
                    }));
                }
            }
            PromptChunk::Blob(blob_ref) => {
                if !supports_images {
                    content.push(serde_json::json!({
                        "type": "text",
                        "text": format_blob_fallback(blob_ref.raw.as_str(), "vision unavailable for current model"),
                    }));
                    continue;
                }
                if images_added >= config.model.max_inline_images as usize {
                    content.push(serde_json::json!({
                        "type": "text",
                        "text": format_blob_fallback(blob_ref.raw.as_str(), "image limit reached"),
                    }));
                    continue;
                }
                match resolve_blob_image(&config,
                    ws,
                    &blob_ref.digest_hex,
                    None,
                ) {
                    Ok((mime, b64)) => {
                        content.push(serde_json::json!({
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": mime,
                                "data": b64,
                            },
                        }));
                        images_added += 1;
                    }
                    Err(reason) => {
                        content.push(serde_json::json!({
                            "type": "text",
                            "text": format_blob_fallback(blob_ref.raw.as_str(), reason.as_str()),
                        }));
                    }
                }
            }
        }
    }

    if content.is_empty() {
        content.push(serde_json::json!({
            "type": "text",
            "text": prompt,
        }));
    }
    content
}

fn parse_anthropic_response(response: ureq::http::Response<ureq::Body>) -> Result<ModelResult> {
    let body = response.into_body().read_to_string().context("read response body")?;
    let parsed: JsonValue = serde_json::from_str(&body).context("parse response JSON")?;

    let response_id = parsed.get("id").and_then(JsonValue::as_str).map(str::to_string);

    let mut output_text = String::new();
    let mut reasoning_parts = Vec::new();

    if let Some(content) = parsed.get("content").and_then(JsonValue::as_array) {
        for block in content {
            match block.get("type").and_then(JsonValue::as_str) {
                Some("text") => {
                    if let Some(text) = block.get("text").and_then(JsonValue::as_str) {
                        output_text.push_str(text);
                    }
                }
                Some("thinking") => {
                    if let Some(text) = block.get("thinking").and_then(JsonValue::as_str) {
                        push_clean(&mut reasoning_parts, text);
                    }
                }
                _ => {}
            }
        }
    }

    let reasoning_text = normalized_join(reasoning_parts);
    let (input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens) =
        extract_anthropic_usage(&parsed);
    Ok(ModelResult {
        output_text,
        reasoning_text,
        raw: body,
        response_id,
        input_tokens,
        output_tokens,
        cache_creation_input_tokens,
        cache_read_input_tokens,
    })
}

fn parse_anthropic_stream(response: ureq::http::Response<ureq::Body>) -> Result<ModelResult> {
    let mut output_text = String::new();
    let mut raw_events = Vec::new();
    let mut response_id = None;
    let mut reasoning_parts = Vec::new();
    let mut input_tokens = None;
    let mut output_tokens = None;
    let mut cache_creation_input_tokens = None;
    let mut cache_read_input_tokens = None;

    let reader = BufReader::new(response.into_body().into_reader());
    let mut current_event_type = String::new();

    for line in reader.lines() {
        let line = line.context("read stream")?;

        // SSE event type line.
        if let Some(event_type) = line.strip_prefix("event: ") {
            current_event_type = event_type.trim().to_string();
            continue;
        }

        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };

        raw_events.push(data.to_owned());
        let Ok(event) = serde_json::from_str::<JsonValue>(data) else {
            continue;
        };

        match current_event_type.as_str() {
            "message_start" => {
                if let Some(message) = event.get("message") {
                    response_id = message
                        .get("id")
                        .and_then(JsonValue::as_str)
                        .map(str::to_string);
                    let (it, ot, ccit, crit) = extract_anthropic_usage(message);
                    input_tokens = input_tokens.or(it);
                    output_tokens = output_tokens.or(ot);
                    cache_creation_input_tokens = cache_creation_input_tokens.or(ccit);
                    cache_read_input_tokens = cache_read_input_tokens.or(crit);
                }
            }
            "content_block_delta" => {
                if let Some(delta) = event.get("delta") {
                    match delta.get("type").and_then(JsonValue::as_str) {
                        Some("text_delta") => {
                            if let Some(text) = delta.get("text").and_then(JsonValue::as_str) {
                                output_text.push_str(text);
                            }
                        }
                        Some("thinking_delta") => {
                            if let Some(text) = delta.get("thinking").and_then(JsonValue::as_str) {
                                reasoning_parts.push(text.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            "message_delta" => {
                // Final usage stats arrive here in streaming mode.
                let (_, ot, _, _) = extract_anthropic_usage(&event);
                output_tokens = output_tokens.or(ot);
            }
            "message_stop" => {
                break;
            }
            _ => {}
        }

        current_event_type.clear();
    }

    let raw = raw_events.join("\n");
    let reasoning_text = normalized_join(reasoning_parts);
    Ok(ModelResult {
        output_text,
        reasoning_text,
        raw,
        response_id,
        input_tokens,
        output_tokens,
        cache_creation_input_tokens,
        cache_read_input_tokens,
    })
}

// ---------------------------------------------------------------------------
// OpenAI Chat Completions API
// ---------------------------------------------------------------------------

fn parse_openai_response(response: ureq::http::Response<ureq::Body>) -> Result<ModelResult> {
    let body = response.into_body().read_to_string().context("read response body")?;
    let parsed: JsonValue = serde_json::from_str(&body).context("parse response JSON")?;
    let output_text = extract_output_text(&parsed);
    let reasoning_text = extract_reasoning_text(&parsed);
    let response_id = extract_response_id(&parsed);
    let (input_tokens, output_tokens) = extract_openai_usage(&parsed);
    Ok(ModelResult {
        output_text,
        reasoning_text,
        raw: body,
        response_id,
        input_tokens,
        output_tokens,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    })
}

fn parse_openai_stream(response: ureq::http::Response<ureq::Body>) -> Result<ModelResult> {
    let mut output_text = String::new();
    let mut raw_events = Vec::new();
    let mut response_id = None;
    let mut reasoning_parts = Vec::new();
    let mut input_tokens = None;
    let mut output_tokens = None;

    let reader = BufReader::new(response.into_body().into_reader());
    for line in reader.lines() {
        let line = line.context("read stream")?;
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };

        if data == "[DONE]" {
            break;
        }

        raw_events.push(data.to_owned());
        let Ok(event) = serde_json::from_str::<JsonValue>(data) else {
            continue;
        };

        if response_id.is_none() {
            response_id = extract_response_id(&event);
        }

        // Usage may arrive in any chunk (typically the last).
        let (it, ot) = extract_openai_usage(&event);
        input_tokens = input_tokens.or(it);
        output_tokens = output_tokens.or(ot);

        if let Some(choices) = event.get("choices").and_then(JsonValue::as_array) {
            for choice in choices {
                if let Some(delta) = choice.get("delta") {
                    if let Some(content) = delta.get("content").and_then(JsonValue::as_str) {
                        output_text.push_str(content);
                    }
                    collect_chat_reasoning_chunks(delta, &mut reasoning_parts);
                }
            }
        }
    }

    let raw = raw_events.join("\n");
    let reasoning_text = normalized_join(reasoning_parts);
    Ok(ModelResult {
        output_text,
        reasoning_text,
        raw,
        response_id,
        input_tokens,
        output_tokens,
        cache_creation_input_tokens: None,
        cache_read_input_tokens: None,
    })
}

fn extract_response_id(response: &JsonValue) -> Option<String> {
    response
        .get("id")
        .and_then(JsonValue::as_str)
        .map(str::to_string)
}

/// Extract usage statistics from an Anthropic API response.
fn extract_anthropic_usage(parsed: &JsonValue) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    let usage = parsed.get("usage");
    (
        usage.and_then(|u| u.get("input_tokens")).and_then(JsonValue::as_u64),
        usage.and_then(|u| u.get("output_tokens")).and_then(JsonValue::as_u64),
        usage.and_then(|u| u.get("cache_creation_input_tokens")).and_then(JsonValue::as_u64),
        usage.and_then(|u| u.get("cache_read_input_tokens")).and_then(JsonValue::as_u64),
    )
}

/// Extract usage statistics from an OpenAI-compatible API response.
fn extract_openai_usage(parsed: &JsonValue) -> (Option<u64>, Option<u64>) {
    let usage = parsed.get("usage");
    (
        usage.and_then(|u| u.get("prompt_tokens")).and_then(JsonValue::as_u64),
        usage.and_then(|u| u.get("completion_tokens")).and_then(JsonValue::as_u64),
    )
}

fn extract_output_text(response: &JsonValue) -> String {
    let Some(choices) = response.get("choices").and_then(JsonValue::as_array) else {
        return String::new();
    };

    let Some(first) = choices.first() else {
        return String::new();
    };

    // OpenAI-compatible chat completions: choices[0].message.content
    if let Some(message) = first.get("message") {
        if let Some(content) = message.get("content") {
            if let Some(text) = content.as_str() {
                return text.to_string();
            }
            if let Some(parts) = content.as_array() {
                let mut out = String::new();
                for part in parts {
                    if part.get("type").and_then(JsonValue::as_str) == Some("text")
                        && let Some(text) = part.get("text").and_then(JsonValue::as_str)
                    {
                        out.push_str(text);
                    }
                }
                return out;
            }
        }
    }

    // Legacy completions-style fallback: choices[0].text
    first
        .get("text")
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .to_string()
}

fn extract_reasoning_text(response: &JsonValue) -> Option<String> {
    let mut out = Vec::new();

    // Chat-completions style (including Mistral thinking chunks where present).
    if let Some(choices) = response.get("choices").and_then(JsonValue::as_array) {
        for choice in choices {
            if let Some(message) = choice.get("message") {
                collect_chat_reasoning_chunks(message, &mut out);
            }
            if let Some(delta) = choice.get("delta") {
                collect_chat_reasoning_chunks(delta, &mut out);
            }
        }
    }

    normalized_join(out)
}

fn collect_chat_reasoning_chunks(node: &JsonValue, out: &mut Vec<String>) {
    for key in ["thinking", "reasoning", "reasoning_content"] {
        if let Some(value) = node.get(key) {
            collect_reasoning_value(value, out);
        }
    }

    if let Some(content) = node.get("content") {
        if let Some(parts) = content.as_array() {
            for part in parts {
                let kind = part
                    .get("type")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default();
                if kind == "thinking"
                    || kind == "reasoning"
                    || kind == "reasoning_content"
                    || kind == "summary_text"
                {
                    if let Some(text) = part
                        .get("text")
                        .and_then(JsonValue::as_str)
                        .or_else(|| part.get("content").and_then(JsonValue::as_str))
                    {
                        push_clean(out, text);
                    }
                    for key in ["thinking", "reasoning", "reasoning_content"] {
                        if let Some(value) = part.get(key) {
                            collect_reasoning_value(value, out);
                        }
                    }
                }
            }
        }
    }

    if let Some(summary_items) = node.get("summary").and_then(JsonValue::as_array) {
        for entry in summary_items {
            if entry.get("type").and_then(JsonValue::as_str) == Some("summary_text")
                && let Some(text) = entry.get("text").and_then(JsonValue::as_str)
            {
                push_clean(out, text);
            }
        }
    }
}

fn collect_reasoning_value(value: &JsonValue, out: &mut Vec<String>) {
    if let Some(text) = value.as_str() {
        push_clean(out, text);
        return;
    }
    if let Some(array) = value.as_array() {
        for item in array {
            collect_reasoning_value(item, out);
        }
        return;
    }
    if let Some(object) = value.as_object() {
        if let Some(text) = object.get("text").and_then(JsonValue::as_str) {
            push_clean(out, text);
        }
        if let Some(content) = object.get("content") {
            collect_reasoning_value(content, out);
        }
    }
}

fn push_clean(out: &mut Vec<String>, text: &str) {
    let trimmed = text.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
}

fn normalized_join(chunks: Vec<String>) -> Option<String> {
    if chunks.is_empty() {
        return None;
    }
    let joined = chunks.join("\n\n");
    if joined.trim().is_empty() {
        None
    } else {
        Some(joined)
    }
}

fn id_prefix(id: Id) -> String {
    let raw: [u8; 16] = id.into();
    let mut out = String::with_capacity(8);
    for byte in raw.iter().take(4) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use triblespace::core::blob::Blob;
    use triblespace::core::repo::Repository;
    use triblespace::core::repo::Workspace;
    use triblespace::core::repo::pile::Pile;
    use triblespace::prelude::valueschemas::{Blake3, Handle};
    use triblespace::prelude::*;

    use crate::chat_prompt::ChatMessage;
    use crate::config::Config;

    use super::{
        Bytes, JsonValue, ModelBackend, UnknownBlob, build_anthropic_payload,
        build_openai_input_content, build_openai_payload, extract_reasoning_text,
    };

    fn test_repo_path() -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "playground-model-worker-test-{}-{ts}.pile",
            std::process::id()
        ))
    }

    fn put_test_png(ws: &mut Workspace<Pile<Blake3>>) -> String {
        // 1x1 PNG (black), padded above MIN_IMAGE_BYTES with a comment chunk.
        let mut png = vec![
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, b'I', b'H',
            b'D', b'R', 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x04, 0x00, 0x00,
            0x00, 0xB5, 0x1C, 0x0C, 0x02, 0x00, 0x00, 0x00, 0x0B, b'I', b'D', b'A', b'T', 0x78,
            0xDA, 0x63, 0xFC, 0xFF, 0x1F, 0x00, 0x03, 0x03, 0x02, 0x00, 0xED, 0x29, 0xEB, 0x14,
        ];
        // Pad with zeros to exceed MIN_IMAGE_BYTES, then close with IEND.
        png.resize(210, 0x00);
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82]);
        let blob: Blob<UnknownBlob> = Blob::new(Bytes::from(png));
        let handle: Value<Handle<Blake3, UnknownBlob>> = ws.put(blob);
        handle
            .raw
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect()
    }

    fn with_test_workspace<T>(f: impl FnOnce(&mut Workspace<Pile<Blake3>>) -> T) -> T {
        let path = test_repo_path();
        let mut pile = Pile::<Blake3>::open(path.as_path()).expect("open test pile");
        pile.restore().expect("restore test pile");
        let mut repo = Repository::new(pile, SigningKey::from_bytes(&[7u8; 32]), TribleSet::new())
            .expect("create test repository");
        let branch_id = repo
            .create_branch("test", None)
            .expect("create test branch")
            .release();
        let mut ws = repo.pull(branch_id).expect("pull test workspace");
        let output = f(&mut ws);
        let _ = repo.close();
        let _ = std::fs::remove_file(path);
        output
    }

    fn test_config() -> Config {
        let path = test_repo_path();
        let mut config = Config::load(Some(path.as_path())).expect("load default config");
        config.model.model = "gpt-5".to_string();
        let _ = std::fs::remove_file(path);
        config
    }

    #[test]
    fn extracts_chat_thinking_chunks() {
        let response = json!({
            "choices": [
                {
                    "message": {
                        "content": [
                            {"type": "thinking", "text": "Need to inspect config first"},
                            {"type": "text", "text": "/workspace/faculties/orient.rs show"}
                        ]
                    }
                }
            ]
        });
        let reasoning = extract_reasoning_text(&response).expect("reasoning");
        assert_eq!(reasoning, "Need to inspect config first");
    }

    #[test]
    fn extracts_nested_chat_thinking_chunks() {
        let response = json!({
            "choices": [
                {
                    "message": {
                        "content": [
                            {
                                "type": "thinking",
                                "thinking": [
                                    {"type": "text", "text": "Step 1"},
                                    {"type": "text", "text": "Step 2"}
                                ]
                            },
                            {"type": "text", "text": "memory 1234"}
                        ]
                    }
                }
            ]
        });
        let reasoning = extract_reasoning_text(&response).expect("reasoning");
        assert_eq!(reasoning, "Step 1\n\nStep 2");
    }

    #[test]
    fn ignores_plain_assistant_text_without_thinking_fields() {
        let response = json!({
            "choices": [
                {
                    "message": {
                        "content": "echo hello"
                    }
                }
            ]
        });
        assert!(extract_reasoning_text(&response).is_none());
    }

    #[test]
    fn chat_payload_uses_message_array() {
        with_test_workspace(|ws| {
            let config = test_config();
            let messages = vec![
                ChatMessage::system("sys"),
                ChatMessage::assistant("orient show"),
                ChatMessage::user("stdout:\nok\n"),
            ];
            let payload = build_openai_payload(&config, ws, "gpt-5", &messages);
            let payload_messages = payload
                .get("messages")
                .and_then(JsonValue::as_array)
                .expect("chat payload messages array");
            assert_eq!(payload_messages.len(), 3);
            assert!(payload.get("input").is_none());
        });
    }

    #[test]
    fn blob_marker_becomes_image_part_for_vision_models() {
        with_test_workspace(|ws| {
            let mut config = test_config();
            config.model.vision = true;
            let digest_hex = put_test_png(ws);
            let prompt = format!(
                "inspect this image ![sample](files:{digest_hex})"
            );
            let content = build_openai_input_content(&config, ws, "gpt-4.1", prompt.as_str());
            assert!(
                content
                    .iter()
                    .any(|part| part.get("type").and_then(JsonValue::as_str) == Some("image_url")),
                "expected one image_url part in prompt content"
            );
        });
    }

    #[test]
    fn blob_marker_falls_back_to_text_for_non_vision_models() {
        with_test_workspace(|ws| {
            let mut config = test_config();
            config.model.vision = false;
            let digest_hex = put_test_png(ws);
            let prompt = format!("![sample](files:{digest_hex})");
            let content = build_openai_input_content(&config, ws, "gpt-oss-120b", prompt.as_str());
            assert_eq!(content.len(), 1);
            assert_eq!(
                content[0].get("type").and_then(JsonValue::as_str),
                Some("text")
            );
            let text = content[0]
                .get("text")
                .and_then(JsonValue::as_str)
                .unwrap_or_default();
            assert!(text.contains("vision unavailable"));
        });
    }

    #[test]
    fn anthropic_payload_extracts_system_prompt() {
        with_test_workspace(|ws| {
            let config = test_config();
            let messages = vec![
                ChatMessage::system("You are helpful."),
                ChatMessage::user("Hello"),
                ChatMessage::assistant("Hi there"),
                ChatMessage::user("How are you?"),
            ];
            let payload = build_anthropic_payload(&config, ws, "claude-sonnet-4-6", &messages);

            // System prompt should be a plain string (no cache_control — implicitly
            // covered by message-level cache hits).
            assert_eq!(
                payload.get("system").and_then(JsonValue::as_str),
                Some("You are helpful.")
            );

            // Messages should only contain user/assistant, no system.
            let msgs = payload
                .get("messages")
                .and_then(JsonValue::as_array)
                .expect("messages array");
            assert_eq!(msgs.len(), 3);
            for msg in msgs {
                let role = msg.get("role").and_then(JsonValue::as_str).unwrap();
                assert_ne!(role, "system");
            }
        });
    }

    #[test]
    fn anthropic_cache_control_strategic_breakpoints() {
        with_test_workspace(|ws| {
            let config = test_config();
            // Simulate: system, memory turns, breath, moment turns.
            let messages = vec![
                ChatMessage::system("You are helpful."),
                ChatMessage::user("memory block 1"),
                ChatMessage::assistant("ack"),
                ChatMessage::assistant("breath"),
                ChatMessage::user("present moment begins."),
                ChatMessage::user("turn 1"),
                ChatMessage::assistant("response 1"),
                ChatMessage::user("turn 2"),
                ChatMessage::assistant("response 2"),
                ChatMessage::user("turn 3\ncontext filled to 42%."),
            ];
            let payload = build_anthropic_payload(&config, ws, "claude-sonnet-4-6", &messages);
            let msgs = payload
                .get("messages")
                .and_then(JsonValue::as_array)
                .expect("messages array");

            // Helper: check if a message has cache_control in its content array.
            let has_cache = |m: &JsonValue| -> bool {
                m.get("content")
                    .and_then(|c| c.as_array())
                    .map_or(false, |arr| arr.iter().any(|b| b.get("cache_control").is_some()))
            };

            // Count cache_control blocks in messages.
            let cached_count = msgs.iter().filter(|m| has_cache(m)).count();
            assert!(
                cached_count <= 3,
                "expected at most 3 message breakpoints, got {cached_count}"
            );

            // Breath user message (index 3 after removing system) should have a breakpoint.
            assert!(
                has_cache(&msgs[3]),
                "breath user message should have cache_control"
            );

            // Second-to-last user message ("turn 2", index 6) should have a breakpoint.
            assert!(
                has_cache(&msgs[6]),
                "second-to-last user message should have cache_control"
            );

            // Last user message (with fill_pct) should NOT have a breakpoint.
            assert!(
                !has_cache(&msgs[msgs.len() - 1]),
                "last user message should not have cache_control"
            );
        });
    }

    #[test]
    fn anthropic_image_uses_source_format() {
        with_test_workspace(|ws| {
            let digest_hex = put_test_png(ws);
            let prompt = format!(
                "inspect ![img](files:{digest_hex})"
            );
            let mut config = test_config();
            config.model.vision = true;
            let content =
                super::build_anthropic_input_content(&config, ws, "claude-sonnet-4-6", prompt.as_str());
            let image_part = content
                .iter()
                .find(|p| p.get("type").and_then(JsonValue::as_str) == Some("image"))
                .expect("expected image part");
            let source = image_part.get("source").expect("source field");
            assert_eq!(
                source.get("type").and_then(JsonValue::as_str),
                Some("base64")
            );
            assert_eq!(
                source.get("media_type").and_then(JsonValue::as_str),
                Some("image/png")
            );
            assert!(source.get("data").and_then(JsonValue::as_str).is_some());
        });
    }

    #[test]
    fn anthropic_response_extracts_text_and_thinking() {
        // Simulate an Anthropic Messages API non-streaming response body.
        let body = json!({
            "id": "msg_01abc",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "Let me consider this carefully"},
                {"type": "text", "text": "orient show"}
            ],
            "model": "claude-sonnet-4-6",
            "stop_reason": "end_turn"
        });
        let body_str = serde_json::to_string(&body).unwrap();
        let parsed: JsonValue = serde_json::from_str(&body_str).unwrap();

        // Test extraction logic directly (parse_anthropic_response takes a Response,
        // so we test the content extraction pattern here).
        let mut output_text = String::new();
        let mut reasoning_parts = Vec::new();
        if let Some(content) = parsed.get("content").and_then(JsonValue::as_array) {
            for block in content {
                match block.get("type").and_then(JsonValue::as_str) {
                    Some("text") => {
                        if let Some(text) = block.get("text").and_then(JsonValue::as_str) {
                            output_text.push_str(text);
                        }
                    }
                    Some("thinking") => {
                        if let Some(text) = block.get("thinking").and_then(JsonValue::as_str) {
                            super::push_clean(&mut reasoning_parts, text);
                        }
                    }
                    _ => {}
                }
            }
        }
        let response_id = parsed
            .get("id")
            .and_then(JsonValue::as_str)
            .map(str::to_string);

        assert_eq!(output_text, "orient show");
        assert_eq!(
            super::normalized_join(reasoning_parts),
            Some("Let me consider this carefully".to_string())
        );
        assert_eq!(response_id.as_deref(), Some("msg_01abc"));
    }

    #[test]
    fn backend_from_config_detects_anthropic() {
        let mut config = test_config();
        config.model.base_url = "https://api.anthropic.com".to_string();
        let backend = ModelBackend::from_config(&config);
        assert!(
            backend.endpoint_url().contains("/v1/messages"),
            "Anthropic backend should use /v1/messages endpoint"
        );

        config.model.base_url = "http://localhost:11434/v1".to_string();
        let backend = ModelBackend::from_config(&config);
        assert!(
            backend.endpoint_url().contains("/chat/completions"),
            "Non-Anthropic backend should use /chat/completions endpoint"
        );
    }
}
