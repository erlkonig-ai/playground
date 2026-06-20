//! In-process local text-generation seam.
//!
//! `ModelBackend::Local` runs the playground cognition loop on an in-substrate
//! LLM (gemma4 in mary/Burn) instead of the ollama HTTP scaffold — no HTTP, no
//! OpenAI shim, the brain in the substrate. Seam contract:
//! wiki:B32401609B520AE56DAEE352049F33EC.
//!
//! With the `local-model` feature the trait + types come straight from
//! `mary::local` (mary owns the trait, tokenizer, chat template, decode loop).
//! Without it, an identical stub set keeps the default build + tests compiling
//! and `StubEngine` exercises the wiring.

use crate::chat_prompt::{ChatMessage, ChatRole};

#[cfg(feature = "local-model")]
pub use mary::local::{LocalChatTurn, LocalGenParams, LocalRole, LocalTextEngine};

#[cfg(not(feature = "local-model"))]
pub use stub::{LocalChatTurn, LocalGenParams, LocalGeneration, LocalRole, LocalTextEngine};

// Stub mirror of `mary::local`'s public types so the default (HTTP-only) build
// and unit tests compile without pulling in Burn. Field-for-field identical to
// mary's so the model worker constructs params the same way either way.
#[cfg(not(feature = "local-model"))]
mod stub {
    use anyhow::Result;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LocalRole {
        System,
        User,
        Assistant,
    }

    #[derive(Debug, Clone)]
    pub struct LocalChatTurn {
        pub role: LocalRole,
        pub content: String,
    }

    #[derive(Debug, Clone)]
    pub struct LocalGenParams {
        pub max_tokens: usize,
        pub temperature: f32,
        pub top_p: Option<f32>,
        pub stop: Vec<String>,
        pub seed: Option<u64>,
    }

    impl Default for LocalGenParams {
        fn default() -> Self {
            Self { max_tokens: 128, temperature: 0.0, top_p: None, stop: vec![], seed: None }
        }
    }

    #[derive(Debug, Clone)]
    pub struct LocalGeneration {
        pub text: String,
        pub reasoning: Option<String>,
        pub prompt_tokens: usize,
        pub completion_tokens: usize,
    }

    pub trait LocalTextEngine: Send {
        fn generate(
            &mut self,
            turns: &[LocalChatTurn],
            params: &LocalGenParams,
        ) -> Result<LocalGeneration>;
    }
}

/// Map playground `ChatMessage`s onto the backend-agnostic turn list.
pub fn turns_from_messages(messages: &[ChatMessage]) -> Vec<LocalChatTurn> {
    messages
        .iter()
        .map(|m| LocalChatTurn {
            role: match m.role {
                ChatRole::System => LocalRole::System,
                ChatRole::User => LocalRole::User,
                ChatRole::Assistant => LocalRole::Assistant,
            },
            content: m.content.clone(),
        })
        .collect()
}

/// Placeholder engine for the default build (no `local-model` feature). Emits a
/// fixed protocol-valid command so the loop + tests run without a real brain.
#[cfg(not(feature = "local-model"))]
pub struct StubEngine;

#[cfg(not(feature = "local-model"))]
impl LocalTextEngine for StubEngine {
    fn generate(
        &mut self,
        turns: &[LocalChatTurn],
        _params: &LocalGenParams,
    ) -> anyhow::Result<LocalGeneration> {
        let prompt_tokens = turns.iter().map(|t| t.content.len() / 4).sum();
        Ok(LocalGeneration {
            text: "orient show".to_string(),
            reasoning: Some("[stub engine] no mary backend linked yet".to_string()),
            prompt_tokens,
            completion_tokens: 2,
        })
    }
}

/// Build a warm in-process gemma engine from a model directory (the v1 path).
/// `spec` is the part after `mary://` / `local://` in base_url and must be a
/// directory containing `config.json`, `tokenizer.json`, and `*.safetensors`.
///
/// The config/tokenizer/shard resolution lives in mary (Burn/HF plumbing stays
/// on its side of the seam). For the 31B split-snapshot HF case — where
/// config.json and the shards land in *different* HF snapshots — `from_dir`
/// can't see the cross-snapshot shards; symlink them into one dir, or call
/// `mary::local::load_gemma4_f16(config, tokenizer, &explicit_shard_paths, …)`
/// with shard paths resolved from `model.safetensors.index.json`.
///
/// Auto-detects how the weights are stored in `spec`:
/// - if `<dir>/weights.pile` exists, the weights are *persisted as tribles* in a
///   standalone pile — load directly from it with NO safetensors on disk (the
///   true shell-is-physics endpoint, `mary::local::load_gemma4_from_persisted_pile_f16`,
///   produced once by `gemma_persist <model-dir> <dir>/weights.pile`);
/// - otherwise load f16 directly from the dir's `*.safetensors`
///   (`load_gemma4_from_dir_f16`) — direct and light, so the dense 31B's ~60 GB
///   fits without the transient ingest a pile round-trip would cost at load.
/// Either way only `config.json` + `tokenizer.json` stay as plain files.
#[cfg(feature = "local-model")]
pub fn load_local_engine(spec: &str) -> anyhow::Result<Box<dyn LocalTextEngine>> {
    let dir = std::path::Path::new(spec);
    anyhow::ensure!(
        dir.is_dir(),
        "mary:// model spec must be a directory with config.json/tokenizer.json and either weights.pile or *.safetensors: {spec}"
    );
    // Raise wgpu's max_storage_buffer_binding_size cap (default 4 GiB) to 16 GiB:
    // the dense 31B's embedding is ~5.6 GB even at f16 and overflows the default
    // cap (a cubecl panic). Harmless for small models (verified).
    let device = mary::local::init_metal_device_16gb();
    let persisted = dir.join("weights.pile");
    if persisted.is_file() {
        mary::local::load_gemma4_from_persisted_pile_f16(
            &persisted,
            &dir.join("config.json"),
            &dir.join("tokenizer.json"),
            device,
        )
    } else {
        mary::local::load_gemma4_from_dir_f16(dir, device)
    }
}
