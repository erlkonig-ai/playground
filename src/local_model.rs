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

/// Default pile the gemma weights load from when neither `<dir>/weights.pile`
/// nor `GEMMA_PILE` points elsewhere (written once by `gemma_persist`).
#[cfg(feature = "local-model")]
const DEFAULT_GEMMA_PILE: &str = "/Users/jp/Desktop/chatbot/liora/models/gemma_e4b.pile";

/// Build a warm in-process gemma engine. `spec` is the part after `mary://` /
/// `local://` in base_url and must be a directory containing `config.json` and
/// `tokenizer.json` (small plain files; the HF snapshot dir works).
///
/// The WEIGHTS load exclusively from a persisted pile — mary's runtime is
/// pile-only, there is no safetensors path
/// (`mary::local::load_gemma4_from_persisted_pile_f16`, streaming f16 so the
/// dense 31B fits 128 GB). The pile is resolved in order:
/// - `<dir>/weights.pile` if present (a self-contained model dir,
///   produced once by `gemma_persist <model-dir> <dir>/weights.pile`);
/// - else the `GEMMA_PILE` env var (same knob `gemma_gen` honors);
/// - else [`DEFAULT_GEMMA_PILE`].
#[cfg(feature = "local-model")]
pub fn load_local_engine(spec: &str) -> anyhow::Result<Box<dyn LocalTextEngine>> {
    let dir = std::path::Path::new(spec);
    anyhow::ensure!(
        dir.is_dir(),
        "mary:// model spec must be a directory with config.json/tokenizer.json: {spec}"
    );
    // Raise wgpu's max_storage_buffer_binding_size cap (default 4 GiB) to 16 GiB:
    // the dense 31B's embedding is ~5.6 GB even at f16 and overflows the default
    // cap (a cubecl panic). Harmless for small models (verified).
    let device = mary::local::init_metal_device_16gb();
    let local = dir.join("weights.pile");
    let pile = if local.is_file() {
        local
    } else {
        std::env::var("GEMMA_PILE").unwrap_or_else(|_| DEFAULT_GEMMA_PILE.into()).into()
    };
    anyhow::ensure!(
        pile.is_file(),
        "gemma weights pile not found at {} (persist one with gemma_persist, or set GEMMA_PILE)",
        pile.display()
    );
    mary::local::load_gemma4_from_persisted_pile_f16(
        &pile,
        &dir.join("config.json"),
        &dir.join("tokenizer.json"),
        device,
    )
}
