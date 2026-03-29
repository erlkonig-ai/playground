use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, GenId, Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

use crate::repo_ops::push_workspace;
use crate::schema::playground_config;
use crate::time_util::{epoch_interval, interval_key, now_epoch, ordered_epoch_interval};

const DEFAULT_MODEL: &str = "gpt-oss:120b";
const DEFAULT_BASE_URL: &str = "http://localhost:11434/v1";
const DEFAULT_STREAM: bool = false;
const DEFAULT_CONTEXT_WINDOW_TOKENS: u64 = 32 * 1024;
const DEFAULT_MAX_OUTPUT_TOKENS: u64 = 1024;
const DEFAULT_PROMPT_SAFETY_MARGIN_TOKENS: u64 = 512;
const DEFAULT_PROMPT_CHARS_PER_TOKEN: u64 = 4;
const DEFAULT_SYSTEM_PROMPT: &str = include_str!("../prompts/system_prompt.md");
// The branch that carries the core cognition loop + exec/LLM request state.
const DEFAULT_BRANCH: &str = "cognition";
const DEFAULT_AUTHOR: &str = "agent";
const DEFAULT_AUTHOR_ROLE: &str = "user";
const DEFAULT_POLL_MS: u64 = 1;
const DEFAULT_PILE_PATH: &str = "self.pile";
#[derive(Clone, Debug)]
pub struct Config {
    pub pile_path: PathBuf,
    pub model: ModelConfig,
    pub model_profile_id: Option<Id>,
    pub model_profile_name: String,
    pub tavily_api_key: Option<String>,
    pub exa_api_key: Option<String>,
    pub exec: ExecConfig,
    pub system_prompt: String,
    pub branch: String,
    pub author: String,
    pub author_role: String,
    pub persona_id: Option<Id>,
    pub poll_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ModelConfig {
    pub model: String,
    pub base_url: String,
    pub api_key: Option<String>,
    pub reasoning_effort: Option<String>,
    pub stream: bool,
    pub context_window_tokens: u64,
    pub max_output_tokens: u64,
    pub context_safety_margin_tokens: u64,
    pub chars_per_token: u64,
    pub max_inline_images: u64,
    pub max_inline_image_bytes: u64,
    pub vision: bool,
}

#[derive(Clone, Debug)]
pub struct ExecConfig {
    pub default_cwd: Option<PathBuf>,
    pub sandbox_profile: Option<Id>,
}

impl Default for ExecConfig {
    fn default() -> Self {
        Self {
            default_cwd: Some(PathBuf::from("/workspace")),
            sandbox_profile: None,
        }
    }
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            model: default_model(),
            base_url: default_base_url(),
            api_key: None,
            reasoning_effort: None,
            stream: default_stream(),
            context_window_tokens: default_context_window_tokens(),
            max_output_tokens: default_max_output_tokens(),
            context_safety_margin_tokens: default_context_safety_margin_tokens(),
            chars_per_token: default_chars_per_token(),
            max_inline_images: 4,
            max_inline_image_bytes: 5 * 1024 * 1024,
            vision: true,
        }
    }
}

impl Config {
    pub fn load(explicit: Option<&Path>) -> Result<Self> {
        let pile_path = explicit
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_PILE_PATH));
        let mut config = load_from_pile(&pile_path)?;
        config.pile_path = pile_path;
        Ok(config)
    }

    #[allow(dead_code)]
    pub fn store(&self) -> Result<()> {
        let (mut repo, branch_id) = open_config_repo(&self.pile_path)?;
        let result = (|| -> Result<()> {
            let mut ws = repo
                .pull(branch_id)
                .map_err(|err| anyhow!("pull config workspace: {err:?}"))?;
            store_config(&mut ws, self).context("store config")?;
            push_workspace(&mut repo, &mut ws).context("push config")?;
            Ok(())
        })();

        if let Err(err) = crate::repo_util::close_repo(repo).context("close config pile") {
            if result.is_ok() {
                return Err(err);
            }
            eprintln!("warning: failed to close pile cleanly: {err:#}");
        }

        result
    }
}

fn default_config(pile_path: PathBuf) -> Config {
    Config {
        pile_path,
        model: ModelConfig::default(),
        model_profile_id: None,
        model_profile_name: "default".to_string(),
        tavily_api_key: None,
        exa_api_key: None,
        exec: ExecConfig::default(),
        system_prompt: default_system_prompt(),
        branch: default_branch(),
        author: default_author(),
        author_role: default_author_role(),
        persona_id: None,
        poll_ms: default_poll_ms(),
    }
}

fn load_from_pile(pile_path: &Path) -> Result<Config> {
    let (mut repo, branch_id) = open_config_repo(pile_path)?;
    let result = (|| -> Result<Config> {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|err| anyhow!("pull config workspace: {err:?}"))?;
        let catalog = ws.checkout(..).context("checkout config workspace")?;

        let mut config = if let Some(config) = load_latest_config(&mut ws, &catalog, pile_path)? {
            config
        } else {
            default_config(pile_path.to_path_buf())
        };

        let profile_changed = ensure_registered_model_profile_id(&mut config.model_profile_id);
        if profile_changed {
            store_config(&mut ws, &config).context("store config with profile id")?;
            push_workspace(&mut repo, &mut ws).context("push config with profile id")?;
        }
        Ok(config)
    })();

    if let Err(err) = crate::repo_util::close_repo(repo).context("close config pile") {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }

    result
}

fn open_config_repo(pile_path: &Path) -> Result<(Repository<Pile>, Id)> {
    if let Some(parent) = pile_path.parent() {
        fs::create_dir_all(parent).context("create pile directory")?;
    }
    let mut pile = Pile::open(pile_path).context("open pile")?;
    if let Err(err) = pile.restore().context("restore pile") {
        let close_res = pile.close().context("close pile after restore failure");
        if let Err(close_err) = close_res {
            eprintln!("warning: failed to close pile cleanly: {close_err:#}");
        }
        return Err(err);
    }

    let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .map_err(|err| anyhow!("create repository: {err:?}"))?;
    let config_branch_id = repo
        .ensure_branch("config", None)
        .map_err(|e| anyhow!("ensure config branch: {e:?}"))?;
    Ok((repo, config_branch_id))
}

fn ensure_registered_model_profile_id(slot: &mut Option<Id>) -> bool {
    if slot.is_some() {
        return false;
    }
    *slot = Some(*genid());
    true
}

fn load_latest_config(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    pile_path: &Path,
) -> Result<Option<Config>> {
    let mut latest: Option<(Id, i128)> = None;

    for (config_id, updated_at) in find!(
        (config_id: Id, updated_at: Value<NsTAIInterval>),
        pattern!(catalog, [{
            ?config_id @
            metadata::tag: playground_config::kind_config,
            playground_config::updated_at: ?updated_at,
        }])
    ) {
        let key = interval_key(updated_at);
        match latest {
            Some((current_id, current_key))
                if current_key > key || (current_key == key && current_id >= config_id) => {}
            _ => latest = Some((config_id, key)),
        }
    }

    let Some((config_id, _)) = latest else {
        return Ok(None);
    };

    let mut config = default_config(pile_path.to_path_buf());

    if let Some(prompt) =
        load_string_attr(ws, catalog, config_id, playground_config::system_prompt)?
    {
        config.system_prompt = prompt;
    }
    if let Some(branch) = load_string_attr(ws, catalog, config_id, playground_config::branch)? {
        config.branch = branch;
    }
    if let Some(author) = load_string_attr(ws, catalog, config_id, playground_config::author)? {
        config.author = author;
    }
    if let Some(role) = load_string_attr(ws, catalog, config_id, playground_config::author_role)? {
        config.author_role = role;
    }
    if let Some(id) = load_id_attr(catalog, config_id, playground_config::persona_id) {
        config.persona_id = Some(id);
    }
    if let Some(id) = load_id_attr(catalog, config_id, playground_config::active_model_profile_id) {
        config.model_profile_id = Some(id);
    }
    if let Some(model) = load_string_attr(ws, catalog, config_id, playground_config::model_name)? {
        config.model.model = model;
    }
    if let Some(url) = load_string_attr(ws, catalog, config_id, playground_config::model_base_url)? {
        config.model.base_url = url;
    }
    if let Some(effort) = load_string_attr(
        ws,
        catalog,
        config_id,
        playground_config::model_reasoning_effort,
    )? {
        config.model.reasoning_effort = Some(effort);
    }
    if let Some(key) = load_string_attr(ws, catalog, config_id, playground_config::model_api_key)? {
        config.model.api_key = Some(key);
    }
    if let Some(key) = load_string_attr(ws, catalog, config_id, playground_config::tavily_api_key)?
    {
        config.tavily_api_key = Some(key);
    }
    if let Some(key) = load_string_attr(ws, catalog, config_id, playground_config::exa_api_key)? {
        config.exa_api_key = Some(key);
    }
    if let Some(cwd) =
        load_string_attr(ws, catalog, config_id, playground_config::exec_default_cwd)?
    {
        config.exec.default_cwd = Some(PathBuf::from(cwd));
    }

    if let Some(id) = load_id_attr(catalog, config_id, playground_config::exec_sandbox_profile) {
        config.exec.sandbox_profile = Some(id);
    }
    if let Some(poll_ms) =
        load_u256_attr(catalog, config_id, playground_config::poll_ms).and_then(|v| v.try_from_value::<u64>().ok())
    {
        config.poll_ms = poll_ms;
    }
    if let Some(stream) =
        load_u256_attr(catalog, config_id, playground_config::model_stream).and_then(|v| v.try_from_value::<u64>().ok())
    {
        config.model.stream = stream != 0;
    }
    if let Some(tokens) = load_u256_attr(
        catalog,
        config_id,
        playground_config::model_context_window_tokens,
    )
    .and_then(|v| v.try_from_value::<u64>().ok())
    {
        config.model.context_window_tokens = tokens;
    }
    if let Some(tokens) =
        load_u256_attr(catalog, config_id, playground_config::model_max_output_tokens)
            .and_then(|v| v.try_from_value::<u64>().ok())
    {
        config.model.max_output_tokens = tokens;
    }
    if let Some(tokens) = load_u256_attr(
        catalog,
        config_id,
        playground_config::model_context_safety_margin_tokens,
    )
    .and_then(|v| v.try_from_value::<u64>().ok())
    {
        config.model.context_safety_margin_tokens = tokens;
    }
    if let Some(chars) = load_u256_attr(
        catalog,
        config_id,
        playground_config::model_chars_per_token,
    )
    .and_then(|v| v.try_from_value::<u64>().ok())
    {
        config.model.chars_per_token = chars;
    }
    if let Some(v) = load_u256_attr(catalog, config_id, playground_config::model_max_inline_images)
        .and_then(|v| v.try_from_value::<u64>().ok())
    {
        config.model.max_inline_images = v;
    }
    if let Some(v) = load_u256_attr(catalog, config_id, playground_config::model_max_inline_image_bytes)
        .and_then(|v| v.try_from_value::<u64>().ok())
    {
        config.model.max_inline_image_bytes = v;
    }
    if let Some(v) = load_u256_attr(catalog, config_id, playground_config::model_vision)
        .and_then(|v| v.try_from_value::<u64>().ok())
    {
        config.model.vision = v != 0;
    }
    if let Some(profile_id) = config.model_profile_id {
        if let Some((model_cfg, name)) = load_latest_model_profile(ws, catalog, profile_id)? {
            config.model = model_cfg;
            config.model_profile_name = name;
        }
    }

    Ok(Some(config))
}

fn load_latest_model_profile(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    profile_id: Id,
) -> Result<Option<(ModelConfig, String)>> {
    let mut latest: Option<(Id, i128)> = None;

    for (entry_id, updated_at) in find!(
        (entry_id: Id, updated_at: Value<NsTAIInterval>),
        pattern!(catalog, [{
            ?entry_id @
            metadata::tag: playground_config::kind_model_profile,
            playground_config::updated_at: ?updated_at,
            playground_config::model_profile_id: profile_id,
        }])
    ) {
        let key = interval_key(updated_at);
        match latest {
            Some((current_id, current_key))
                if current_key > key || (current_key == key && current_id >= entry_id) => {}
            _ => latest = Some((entry_id, key)),
        }
    }

    let Some((entry_id, _)) = latest else {
        return Ok(None);
    };

    let mut model = ModelConfig::default();
    if let Some(name) = load_string_attr(ws, catalog, entry_id, playground_config::model_name)? {
        model.model = name;
    }
    if let Some(url) = load_string_attr(ws, catalog, entry_id, playground_config::model_base_url)? {
        model.base_url = url;
    }
    if let Some(effort) = load_string_attr(
        ws,
        catalog,
        entry_id,
        playground_config::model_reasoning_effort,
    )? {
        model.reasoning_effort = Some(effort);
    }
    if let Some(key) = load_string_attr(ws, catalog, entry_id, playground_config::model_api_key)? {
        model.api_key = Some(key);
    }
    if let Some(stream) =
        load_u256_attr(catalog, entry_id, playground_config::model_stream).and_then(|v| v.try_from_value::<u64>().ok())
    {
        model.stream = stream != 0;
    }
    if let Some(tokens) = load_u256_attr(
        catalog,
        entry_id,
        playground_config::model_context_window_tokens,
    )
    .and_then(|v| v.try_from_value::<u64>().ok())
    {
        model.context_window_tokens = tokens;
    }
    if let Some(tokens) =
        load_u256_attr(catalog, entry_id, playground_config::model_max_output_tokens)
            .and_then(|v| v.try_from_value::<u64>().ok())
    {
        model.max_output_tokens = tokens;
    }
    if let Some(tokens) = load_u256_attr(
        catalog,
        entry_id,
        playground_config::model_context_safety_margin_tokens,
    )
    .and_then(|v| v.try_from_value::<u64>().ok())
    {
        model.context_safety_margin_tokens = tokens;
    }
    if let Some(chars) = load_u256_attr(
        catalog,
        entry_id,
        playground_config::model_chars_per_token,
    )
    .and_then(|v| v.try_from_value::<u64>().ok())
    {
        model.chars_per_token = chars;
    }
    if let Some(v) = load_u256_attr(catalog, entry_id, playground_config::model_max_inline_images)
        .and_then(|v| v.try_from_value::<u64>().ok())
    {
        model.max_inline_images = v;
    }
    if let Some(v) = load_u256_attr(catalog, entry_id, playground_config::model_max_inline_image_bytes)
        .and_then(|v| v.try_from_value::<u64>().ok())
    {
        model.max_inline_image_bytes = v;
    }
    if let Some(v) = load_u256_attr(catalog, entry_id, playground_config::model_vision)
        .and_then(|v| v.try_from_value::<u64>().ok())
    {
        model.vision = v != 0;
    }
    let name = load_string_attr(ws, catalog, entry_id, metadata::name)?
        .unwrap_or_else(|| format!("profile-{profile_id:x}"));
    Ok(Some((model, name)))
}

fn store_config(ws: &mut Workspace<Pile>, config: &Config) -> Result<()> {
    let now_e = now_epoch();
    let now = epoch_interval(now_e);
    let now_ordered = ordered_epoch_interval(now_e);
    let config_id = ufoid();
    let profile_id = config
        .model_profile_id
        .ok_or_else(|| anyhow!("config missing active model profile id"))?;

    let system_prompt = ws.put(config.system_prompt.clone());
    let branch = ws.put(config.branch.clone());
    let author = ws.put(config.author.clone());
    let author_role = ws.put(config.author_role.clone());
    let poll_ms: Value<U256BE> = config.poll_ms.to_value();

    let mut change = TribleSet::new();
    change += entity! { &config_id @
        metadata::tag: playground_config::kind_config,
        playground_config::updated_at: now,
        playground_config::ordered_updated_at: now_ordered,
        playground_config::system_prompt: system_prompt,
        playground_config::branch: branch,
        playground_config::author: author,
        playground_config::author_role: author_role,
        playground_config::poll_ms: poll_ms,
        playground_config::active_model_profile_id: profile_id,
    };
    if let Some(id) = config.persona_id {
        change += entity! { &config_id @ playground_config::persona_id: id };
    }
    if let Some(key) = config.tavily_api_key.as_ref() {
        let handle = ws.put(key.clone());
        change += entity! { &config_id @ playground_config::tavily_api_key: handle };
    }
    if let Some(key) = config.exa_api_key.as_ref() {
        let handle = ws.put(key.clone());
        change += entity! { &config_id @ playground_config::exa_api_key: handle };
    }
    if let Some(cwd) = config.exec.default_cwd.as_ref() {
        let handle = ws.put(cwd.to_string_lossy().to_string());
        change += entity! { &config_id @ playground_config::exec_default_cwd: handle };
    }
    if let Some(profile) = config.exec.sandbox_profile {
        change += entity! { &config_id @ playground_config::exec_sandbox_profile: profile };
    }

    let profile_entry_id = ufoid();
    let profile_name = ws.put(config.model_profile_name.clone());
    let model_name = ws.put(config.model.model.clone());
    let model_base_url = ws.put(config.model.base_url.clone());
    let model_stream: Value<U256BE> = if config.model.stream { 1u64 } else { 0u64 }.to_value();
    let model_context_window_tokens: Value<U256BE> = config.model.context_window_tokens.to_value();
    let model_max_output_tokens: Value<U256BE> = config.model.max_output_tokens.to_value();
    let model_context_safety_margin_tokens: Value<U256BE> =
        config.model.context_safety_margin_tokens.to_value();
    let model_chars_per_token: Value<U256BE> = config.model.chars_per_token.to_value();
    let model_max_inline_images: Value<U256BE> = config.model.max_inline_images.to_value();
    let model_max_inline_image_bytes: Value<U256BE> = config.model.max_inline_image_bytes.to_value();
    let model_vision: Value<U256BE> = if config.model.vision { 1u64 } else { 0u64 }.to_value();

    change += entity! { &profile_entry_id @
        metadata::tag: playground_config::kind_model_profile,
        playground_config::updated_at: now,
        playground_config::ordered_updated_at: now_ordered,
        playground_config::model_profile_id: profile_id,
        metadata::name: profile_name,
        playground_config::model_name: model_name,
        playground_config::model_base_url: model_base_url,
        playground_config::model_stream: model_stream,
        playground_config::model_context_window_tokens: model_context_window_tokens,
        playground_config::model_max_output_tokens: model_max_output_tokens,
        playground_config::model_context_safety_margin_tokens: model_context_safety_margin_tokens,
        playground_config::model_chars_per_token: model_chars_per_token,
        playground_config::model_max_inline_images: model_max_inline_images,
        playground_config::model_max_inline_image_bytes: model_max_inline_image_bytes,
        playground_config::model_vision: model_vision,
    };

    if let Some(key) = config.model.api_key.as_ref() {
        let handle = ws.put(key.clone());
        change += entity! { &profile_entry_id @ playground_config::model_api_key: handle };
    }
    if let Some(effort) = config.model.reasoning_effort.as_ref() {
        let handle = ws.put(effort.clone());
        change += entity! { &profile_entry_id @ playground_config::model_reasoning_effort: handle };
    }

    ws.commit(change, "playground config");
    Ok(())
}

fn load_string_attr(
    ws: &mut Workspace<Pile>,
    catalog: &TribleSet,
    config_id: Id,
    attr: Attribute<Handle<Blake3, LongString>>,
) -> Result<Option<String>> {
    let mut handles = find!(
        (entity: Id, handle: Value<Handle<Blake3, LongString>>),
        pattern!(catalog, [{ ?entity @ attr: ?handle }])
    )
    .filter(|(entity, _)| *entity == config_id);
    let Some((_, handle)) = handles.next() else {
        return Ok(None);
    };
    if handles.next().is_some() {
        let attr_id = attr.id();
        return Err(anyhow!(
            "config {config_id:x} has multiple values for attribute {attr_id:x}"
        ));
    }
    let view: View<str> = ws.get(handle).context("read config text")?;
    Ok(Some(view.as_ref().to_string()))
}

fn load_id_attr(catalog: &TribleSet, config_id: Id, attr: Attribute<GenId>) -> Option<Id> {
    find!(
        (entity: Id, value: Value<GenId>),
        pattern!(catalog, [{ ?entity @ attr: ?value }])
    )
    .find_map(|(entity, value)| (entity == config_id).then(|| value.try_from_value::<Id>().ok())?)
}

fn load_u256_attr(
    catalog: &TribleSet,
    config_id: Id,
    attr: Attribute<U256BE>,
) -> Option<Value<U256BE>> {
    find!(
        (entity: Id, value: Value<U256BE>),
        pattern!(catalog, [{ ?entity @ attr: ?value }])
    )
    .find_map(|(entity, value)| (entity == config_id).then_some(value))
}


fn default_system_prompt() -> String {
    DEFAULT_SYSTEM_PROMPT.to_string()
}

fn default_model() -> String {
    DEFAULT_MODEL.to_string()
}

fn default_base_url() -> String {
    DEFAULT_BASE_URL.to_string()
}

fn default_stream() -> bool {
    DEFAULT_STREAM
}

fn default_context_window_tokens() -> u64 {
    DEFAULT_CONTEXT_WINDOW_TOKENS
}

fn default_max_output_tokens() -> u64 {
    DEFAULT_MAX_OUTPUT_TOKENS
}

fn default_context_safety_margin_tokens() -> u64 {
    DEFAULT_PROMPT_SAFETY_MARGIN_TOKENS
}

fn default_chars_per_token() -> u64 {
    DEFAULT_PROMPT_CHARS_PER_TOKEN
}

fn default_branch() -> String {
    DEFAULT_BRANCH.to_string()
}

fn default_author() -> String {
    DEFAULT_AUTHOR.to_string()
}

fn default_author_role() -> String {
    DEFAULT_AUTHOR_ROLE.to_string()
}

fn default_poll_ms() -> u64 {
    DEFAULT_POLL_MS
}
