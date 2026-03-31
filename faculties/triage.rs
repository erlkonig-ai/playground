#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4.2.3"
//! rand_core = "0.6.4"
//! serde = { version = "1.0", features = ["derive"] }
//! serde_json = "1.0"
//! triblespace = "0.32"
//! ```

use anyhow::{Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, ReadError};
use triblespace::core::repo::{BlobStoreMeta, PullError, PushResult, Repository, Workspace};
use triblespace::macros::{attributes, find, id_hex, pattern};
use triblespace::prelude::*;

const KIND_PERSON_ID: Id = id_hex!("D8ADDE47121F4E7868017463EC860726");
const KIND_LOCAL_MESSAGE_ID: Id = id_hex!("A3556A66B00276797FCE8A2742AB850F");
const KIND_LOCAL_READ_ID: Id = id_hex!("B663C15BB6F2BF591EA870386DD48537");
const KIND_EXEC_REQUEST_ID: Id = id_hex!("3D2512DAE86B14B9049930F3146A3188");
const KIND_EXEC_IN_PROGRESS_ID: Id = id_hex!("2D81A8D840822CF082DE5DE569B53730");
const KIND_EXEC_RESULT_ID: Id = id_hex!("DF7165210F066E84D93E9A430BB0D4BD");
const KIND_MODEL_REQUEST_ID: Id = id_hex!("1524B4C030D4F10365D9DCEE801A09C8");
const KIND_MODEL_IN_PROGRESS_ID: Id = id_hex!("16C69FC4928D54BF93E6F3222B4685A7");
const KIND_MODEL_RESULT_ID: Id = id_hex!("DE498E4697F9F01219C75E7BC183DB91");
const KIND_REASON_EVENT_ID: Id = id_hex!("9D43BB36D8B4A6275CAF38A1D5DACF36");
const KIND_CONTEXT_CHUNK_ID: Id = id_hex!("40E6004417F9B767AFF1F138DE3D3AAC");
const REPO_HEAD_ATTR: Id = id_hex!("272FBC56108F336C4D2E17289468C35F");
const REPO_PARENT_ATTR: Id = id_hex!("317044B612C690000D798CA660ECFD2A");
const REPO_CONTENT_ATTR: Id = id_hex!("4DD4DDD05CC31734B03ABB4E43188B1F");

type TextHandle = Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>;

mod config {
    use super::*;
    attributes! {
        "5E32E36AD28B0B1E035D2DFCC20A3DC5" as updated_at: valueschemas::NsTAIInterval;
        "D1DC11B303725409AB8A30C6B59DB2D7" as persona_id: valueschemas::GenId;
        "950B556A74F71AC7CB008AB23FBB6544" as system_prompt: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "79E1B50756FB64A30916E9353225E179" as active_model_profile_id: valueschemas::GenId;
        "6691CF3F872C6107DCFAD0BCF7CDC1A0" as model_profile_id: valueschemas::GenId;
        "F9CEA1A2E81D738BB125B4D144B7A746" as model_context_window_tokens: valueschemas::U256BE;
        "4200F6746B36F2784DEBA1555595D6AC" as model_max_output_tokens: valueschemas::U256BE;
        "1FF004BB48F7A4F8F72541F4D4FA75FF" as model_context_safety_margin_tokens: valueschemas::U256BE;
        "095FAECDB8FF205DF591DF594E593B01" as model_chars_per_token: valueschemas::U256BE;
    }
}

mod local {
    use super::*;
    attributes! {
        "95D58D3E68A43979F8AA51415541414C" as to: valueschemas::GenId;
        "5FA453867880877B613B7632A233419B" as created_at: valueschemas::NsTAIInterval;
        "2213B191326E9B99605FA094E516E50E" as about_message: valueschemas::GenId;
        "99E92F483731FA6D59115A8D6D187A37" as reader: valueschemas::GenId;
    }
}

mod relations {
    use super::*;
    attributes! {
        "8F162B593D390E1424394DBF6883A72C" as alias: valueschemas::ShortString;
    }
}

mod exec {
    use super::*;
    attributes! {
        "AA2F34973589295FA70B538D92CD30F8" as kind: valueschemas::GenId;
        "79DD6A1A02E598033EDCE5C667E8E3E6" as command_text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "D8910A14B31096DF94DE9E807B87645F" as requested_at: valueschemas::NsTAIInterval;
        "C4C3870642CAB5F55E7E575B1A62E640" as about_request: valueschemas::GenId;
        "CCFAE38E0C70AFBBF7223D2DA28A93C7" as started_at: valueschemas::NsTAIInterval;
        "3BB7917C5E41E494FECE36FFE79FEF23" as finished_at: valueschemas::NsTAIInterval;
        "B68F9025545C7E616EB90C6440220348" as exit_code: valueschemas::U256BE;
        "CA7AF66AAF5105EC15625ED14E1A2AC0" as stdout_text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "BE4D1876B22EAF93AAD1175DB76D1C72" as stderr_text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "E9C77284C7DDCF522A8AC4622FE3FB11" as error: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "90307D583A8F085828E1007AE432BF86" as about_thought: valueschemas::GenId;
    }
}

mod model_chat {
    use super::*;
    attributes! {
        "5F10520477A04E5FB322C85CC78C6762" as kind: valueschemas::GenId;
        "5A14A02113CE43A59881D0717726F465" as about_request: valueschemas::GenId;
        "DA8E31E47919337B3E00724EBE32D14E" as about_thought: valueschemas::GenId;
        "59FA7C04A43B96F31414D1B4544FAEC2" as requested_at: valueschemas::NsTAIInterval;
        "D1384E835F1C325249A603D93CA2701D" as started_at: valueschemas::NsTAIInterval;
        "2A98AB108752C0C0C6355B84871932DA" as finished_at: valueschemas::NsTAIInterval;
        "B1B904590F0FA70AD1BA247F3D23A6CC" as output_text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "567E35DACDB00C799E75AEED0B6EFDF7" as reasoning_text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "9E9B829C473E416E9150D4B94A6A2DC4" as error: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "115637F43C28E6ABE3A1B0C4095CAC03" as input_tokens: valueschemas::U256BE;
        "F17EB3EABC10A0210403B807BEB25D08" as output_tokens: valueschemas::U256BE;
        "B680DCFAB2E8D1413E450C89AB156197" as cache_creation_input_tokens: valueschemas::U256BE;
        "0A9C7D70295A65413375842916821032" as cache_read_input_tokens: valueschemas::U256BE;
    }
}

mod reason {
    use super::*;
    attributes! {
        "B10329D5D1087D15A3DAFF7A7CC50696" as text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "79C9CB4C48864D28B215D4264E1037BF" as created_at: valueschemas::NsTAIInterval;
        "E6B1C728F1AE9F46CAB4DBB60D1A9528" as about_turn: valueschemas::GenId;
        "514F4FE9F560FB155450462C8CF50749" as command_text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
    }
}

mod context {
    use super::*;
    attributes! {
        "81E520987033BE71EB0AFFA8297DE613" as kind: valueschemas::GenId;
        "3292CF0B3B6077991D8ECE6E2973D4B6" as summary: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "4036F38AB05D26764A1E5E456337F399" as created_at: valueschemas::NsTAIInterval;
        "502F7D33822A90366F0F0ADA0556177F" as start_at: valueschemas::NsTAIInterval;
        "DF84E872EB68FBFCA63D760F27FD8A6F" as end_at: valueschemas::NsTAIInterval;
        "CB97C36A32DEC70E0D1149E7C5D88588" as left: valueschemas::GenId;
        "087D07E3D9D94F0C4E96813C7BC5E74C" as right: valueschemas::GenId;
        "9B83D68AECD6888AA9CE95E754494768" as child: valueschemas::GenId;
        "316834CC6B0EA6F073BF5362D67AC530" as about_exec_result: valueschemas::GenId;
    }
}

mod cog {
    use super::*;
    attributes! {
        "07F063ECF1DC9FB3C1984BDB10B98BFA" as kind: valueschemas::GenId;
        "FA6090FB00EEE2F5EF1E51F1F68EA5B8" as context: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "1AE17985F2AE74631CE16FD84DC97FB4" as created_at: valueschemas::NsTAIInterval;
    }
}

#[derive(Parser)]
#[command(
    name = "triage",
    about = "Doctor-style cross-instance diagnostics for playground agent piles"
)]
struct Cli {
    /// Path to the pile file to inspect
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Target branch name
    #[arg(long, default_value = "cognition")]
    branch: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Full health scan with queue + loop heuristics
    Scan {
        /// Max recent exec attempts used for loop diagnostics
        #[arg(long, default_value_t = 40)]
        recent: usize,
        /// Minimum repeated attempts to report as a probable loop
        #[arg(long, default_value_t = 3)]
        loop_min: usize,
        /// Mark in-progress requests older than this as stale
        #[arg(long, default_value_t = 15)]
        stale_min: i64,
    },
    /// Show recent exec attempts and repeated failure patterns
    Loops {
        #[arg(long, default_value_t = 40)]
        recent: usize,
        #[arg(long, default_value_t = 3)]
        min_repeat: usize,
    },
    /// Show an interleaved recent activity timeline (exec/model/reason)
    Timeline {
        /// Max events to print (newest first)
        #[arg(long, default_value_t = 80)]
        recent: usize,
    },
    /// Inspect commit-chain integrity for the target branch
    Chain,
    /// Show memory cover structure (chunks, hierarchy, budget)
    Cover {
        /// Show full summary text instead of truncated
        #[arg(long, default_value_t = false)]
        full: bool,
        /// Show children indented under parents
        #[arg(long, default_value_t = false)]
        tree: bool,
    },
    /// Inspect a specific memory chunk by ID prefix
    Chunk {
        /// Hex ID prefix of the chunk to inspect
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Inspect a full turn cycle: context in, model output, command, exec result
    Turn {
        /// Nth most recent turn (1 = latest)
        #[arg(long, default_value_t = 1)]
        turn: usize,
        /// Show full content (context messages, stdout, reasoning)
        #[arg(long, default_value_t = false)]
        full: bool,
    },
    /// Show the assembled context for a recent turn
    Context {
        /// Nth most recent turn (1 = latest)
        #[arg(long, default_value_t = 1)]
        turn: usize,
        /// Show full message content
        #[arg(long, default_value_t = false)]
        full: bool,
        /// Dump raw JSON
        #[arg(long, default_value_t = false)]
        raw: bool,
    },
    /// Repair branch-level consistency issues
    Repair {
        #[command(subcommand)]
        command: RepairCommand,
    },
}

#[derive(Subcommand)]
enum RepairCommand {
    /// Merge duplicate named branches into canonical config-registered IDs
    BranchDuplicates {
        /// Preview actions without writing changes
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

/// Lightweight config snapshot — only non-branch fields that triage still needs.
#[derive(Debug, Clone, Default)]
struct ConfigSnapshot {
    updated_at: Option<i128>,
    persona_id: Option<Id>,
}

#[derive(Debug, Clone)]
struct ExecRequestRow {
    id: Id,
    command: String,
    requested_at: i128,
}

#[derive(Debug, Clone)]
struct ExecInProgressRow {
    about_request: Id,
    started_at: i128,
}

#[derive(Debug, Clone)]
struct ExecResultRow {
    id: Id,
    about_request: Id,
    finished_at: i128,
    exit_code: Option<i64>,
    stderr_text: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct ExecState {
    requests: HashMap<Id, ExecRequestRow>,
    in_progress: Vec<ExecInProgressRow>,
    results: Vec<ExecResultRow>,
}

#[derive(Debug, Clone)]
struct ModelRequestRow {
    requested_at: i128,
}

#[derive(Debug, Clone)]
struct ModelInProgressRow {
    about_request: Id,
    started_at: i128,
}

#[derive(Debug, Clone)]
struct ModelResultRow {
    about_request: Id,
    finished_at: i128,
    error: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct ModelChatState {
    requests: HashMap<Id, ModelRequestRow>,
    in_progress: Vec<ModelInProgressRow>,
    results: Vec<ModelResultRow>,
}

#[derive(Debug, Clone)]
struct ReasonEventRow {
    created_at: Option<i128>,
    text: Option<String>,
    about_turn: Option<Id>,
    command_text: Option<String>,
}

#[derive(Debug, Clone)]
struct TimelineRow {
    at: i128,
    source: &'static str,
    detail: String,
}

#[derive(Debug, Clone)]
struct ExecAttempt {
    request_id: Id,
    result_id: Id,
    finished_at: i128,
    command: String,
    exit_code: Option<i64>,
    fingerprint: String,
}

#[derive(Debug, Clone)]
struct PatternSummary {
    command: String,
    exit_code: Option<i64>,
    fingerprint: String,
    count: usize,
    latest: i128,
}

#[derive(Debug, Clone)]
struct LoopReport {
    recent: Vec<ExecAttempt>,
    top_patterns: Vec<PatternSummary>,
    contiguous_head: Option<PatternSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ChatRole {
    System,
    User,
    Assistant,
}

impl std::fmt::Display for ChatRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChatRole::System => write!(f, "system"),
            ChatRole::User => write!(f, "user"),
            ChatRole::Assistant => write!(f, "assistant"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    role: ChatRole,
    content: String,
}

#[derive(Debug, Clone)]
struct ContextChunkRow {
    id: Id,
    summary: Option<String>,
    created_at: Option<i128>,
    start_at: Option<i128>,
    end_at: Option<i128>,
    children: Vec<Id>,
    about_exec_result: Option<Id>,
}

#[derive(Debug, Clone)]
struct BudgetInfo {
    context_window_tokens: u64,
    max_output_tokens: u64,
    safety_margin_tokens: u64,
    chars_per_token: u64,
    system_prompt_chars: usize,
    body_budget_chars: i64,
}

#[derive(Debug, Clone)]
struct ChainIssue {
    commit_hash: String,
    depth_from_head: usize,
    reason: String,
}

#[derive(Debug, Clone)]
struct ChainReport {
    commit_head: String,
    checked_commits: usize,
    issue: Option<ChainIssue>,
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn interval_key(interval: Value<valueschemas::NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.try_from_value().unwrap();
    lower.to_tai_duration().total_nanoseconds()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn format_age(now_key: i128, past_key: i128) -> String {
    let delta_ns = now_key.saturating_sub(past_key);
    let delta_s = (delta_ns / 1_000_000_000).max(0) as i64;
    if delta_s < 60 {
        format!("{delta_s}s")
    } else if delta_s < 3600 {
        format!("{}m", delta_s / 60)
    } else if delta_s < 86_400 {
        format!("{}h", delta_s / 3600)
    } else {
        format!("{}d", delta_s / 86_400)
    }
}

fn truncate_single_line(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(max);
    for ch in text.chars() {
        if out.len() >= max {
            out.push_str("...");
            break;
        }
        if ch == '\n' || ch == '\r' {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

fn first_line(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or(text)
        .trim()
        .to_string()
}

fn format_duration_ns(delta_ns: i128) -> String {
    let secs = (delta_ns / 1_000_000_000).max(0) as u64;
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        let m = secs / 60;
        let s = secs % 60;
        if s == 0 { format!("{m}m") } else { format!("{m}m {s}s") }
    } else if secs < 86_400 {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        if m == 0 { format!("{h}h") } else { format!("{h}h {m}m") }
    } else {
        let d = secs / 86_400;
        let h = (secs % 86_400) / 3600;
        if h == 0 { format!("{d}d") } else { format!("{d}d {h}h") }
    }
}

fn format_tai_ns(ns: i128) -> String {
    let ns_i64 = ns.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    let epoch = Epoch::from_tai_duration(hifitime::Duration::from_truncated_nanoseconds(ns_i64));
    let (y, m, d, hh, mm, ss, _) = epoch.to_gregorian_utc();
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}")
}

fn u256be_to_u64(value: Value<valueschemas::U256BE>) -> Option<u64> {
    let raw = value.raw;
    if raw[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    let bytes: [u8; 8] = raw[24..32].try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn read_text(ws: &mut Workspace<Pile<valueschemas::Blake3>>, handle: TextHandle) -> Result<String> {
    let view: View<str> = ws
        .get::<View<str>, blobschemas::LongString>(handle)
        .map_err(|e| anyhow!("load longstring: {e:?}"))?;
    Ok(view.to_string())
}

fn open_repo(path: &Path) -> Result<Repository<Pile<valueschemas::Blake3>>> {
    let mut pile = Pile::<valueschemas::Blake3>::open(path)
        .map_err(|e| anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        // Avoid Drop warnings on early errors.
        let _ = pile.close();
        return Err(anyhow!("restore pile {}: {err:?}", path.display()));
    }
    Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())
        .map_err(|err| anyhow!("create repository: {err:?}"))
}

fn pull_workspace(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    branch_id: Id,
    context: &str,
) -> Result<Workspace<Pile<valueschemas::Blake3>>> {
    match repo.pull(branch_id) {
        Ok(ws) => Ok(ws),
        Err(err) => {
            let Some(valid_length) = pull_corrupt_valid_length(&err) else {
                return Err(anyhow!("{context}: {err:?}"));
            };
            eprintln!(
                "warning: {context}: corrupt pile tail (valid_length={valid_length}), restoring and retrying"
            );
            repo.storage_mut()
                .restore()
                .map_err(|restore_err| anyhow!("{context}: restore pile: {restore_err:?}"))?;
            repo.pull(branch_id)
                .map_err(|retry_err| anyhow!("{context} after restore: {retry_err:?}"))
        }
    }
}

fn pull_corrupt_valid_length<B: std::error::Error>(
    err: &PullError<ReadError, ReadError, B>,
) -> Option<usize> {
    match err {
        PullError::BlobReader(ReadError::CorruptPile { valid_length })
        | PullError::BranchStorage(ReadError::CorruptPile { valid_length }) => Some(*valid_length),
        _ => None,
    }
}

fn find_branch_ids_by_name(
    pile: &mut Pile<valueschemas::Blake3>,
    branch_name: &str,
) -> Result<Vec<Id>> {
    let name_handle = branch_name
        .to_owned()
        .to_blob()
        .get_handle::<valueschemas::Blake3>();
    let reader = pile.reader().map_err(|e| anyhow!("pile reader: {e:?}"))?;
    let iter = pile
        .branches()
        .map_err(|e| anyhow!("list branches: {e:?}"))?;
    let mut matches = Vec::new();
    for branch_entry in iter {
        let branch_id = branch_entry.map_err(|e| anyhow!("branch id: {e:?}"))?;
        let Some(head) = pile
            .head(branch_id)
            .map_err(|e| anyhow!("branch head: {e:?}"))?
        else {
            continue;
        };
        let metadata_set: TribleSet = reader
            .get(head)
            .map_err(|e| anyhow!("branch metadata: {e:?}"))?;
        let mut names = find!(
            handle: TextHandle,
            pattern!(&metadata_set, [{ metadata::name: ?handle }])
        )
        .into_iter();
        let Some(name) = names.next() else {
            continue;
        };
        if names.next().is_some() {
            continue;
        }
        if name != name_handle {
            continue;
        }
        let head_ts = reader
            .metadata(head)
            .ok()
            .flatten()
            .map(|meta| meta.timestamp)
            .unwrap_or(0);
        matches.push((branch_id, head_ts));
    }
    matches.sort_by_key(|(id, ts)| (Reverse(*ts), format!("{id:x}")));
    Ok(matches.into_iter().map(|(id, _)| id).collect())
}

fn push_workspace(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
) -> Result<()> {
    while let Some(mut conflict) = repo
        .try_push(ws)
        .map_err(|e| anyhow!("push workspace: {e:?}"))?
    {
        conflict
            .merge(ws)
            .map_err(|e| anyhow!("merge workspace: {e:?}"))?;
        *ws = conflict;
    }
    Ok(())
}

/// Use ensure_branch to resolve a named branch, creating it if absent.
fn ensure_branch_id(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    name: &str,
) -> Result<Id> {
    repo.ensure_branch(name, None)
        .map_err(|e| anyhow!("ensure branch '{name}': {e:?}"))
}

/// Resolve target branch: explicit --branch-id wins, then config branch_id,
/// then ensure_branch by name as last resort.
fn resolve_target_branch(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    cli: &Cli,
) -> Result<Id> {
    ensure_branch_id(repo, &cli.branch)
}

/// Load lightweight config snapshot (persona_id + updated_at) from the config branch.
fn load_latest_config(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
) -> Result<Option<ConfigSnapshot>> {
    let branch_id = ensure_branch_id(repo, "config")?;
    let mut ws = pull_workspace(repo, branch_id, "pull config workspace")?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout config workspace: {e:?}"))?;

    let mut latest: Option<(Id, i128)> = None;
    for (config_id, updated_at) in find!(
        (config_id: Id, updated_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            ?config_id @
            config::updated_at: ?updated_at,
        }])
    ) {
        let key = interval_key(updated_at);
        match latest {
            Some((_, best)) if best >= key => {}
            _ => latest = Some((config_id, key)),
        }
    }

    let Some((config_id, updated_at)) = latest else {
        return Ok(None);
    };

    let mut snapshot = ConfigSnapshot {
        updated_at: Some(updated_at),
        ..Default::default()
    };

    if let Some(value) = find!(
        value: Id,
        pattern!(&space, [{ config_id @ config::persona_id: ?value }])
    ).next() {
        snapshot.persona_id = Some(value);
    }

    Ok(Some(snapshot))
}

fn collect_exec_state(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    space: &TribleSet,
) -> Result<ExecState> {
    let mut state = ExecState::default();

    for (request_id, handle, requested_at) in find!(
        (request_id: Id, handle: TextHandle, requested_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            ?request_id @
            metadata::tag: &KIND_EXEC_REQUEST_ID,
            exec::command_text: ?handle,
            exec::requested_at: ?requested_at,
        }])
    ) {
        state.requests.insert(
            request_id,
            ExecRequestRow {
                id: request_id,
                command: read_text(ws, handle)?,
                requested_at: interval_key(requested_at),
            },
        );
    }

    for (about_request, started_at) in find!(
        (about_request: Id, started_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            _?event_id @
            metadata::tag: &KIND_EXEC_IN_PROGRESS_ID,
            exec::about_request: ?about_request,
            exec::started_at: ?started_at,
        }])
    ) {
        state.in_progress.push(ExecInProgressRow {
            about_request,
            started_at: interval_key(started_at),
        });
    }

    let mut result_map: HashMap<Id, ExecResultRow> = HashMap::new();
    for (result_id, about_request, finished_at) in find!(
        (result_id: Id, about_request: Id, finished_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            ?result_id @
            metadata::tag: &KIND_EXEC_RESULT_ID,
            exec::about_request: ?about_request,
            exec::finished_at: ?finished_at,
        }])
    ) {
        result_map.insert(
            result_id,
            ExecResultRow {
                id: result_id,
                about_request,
                finished_at: interval_key(finished_at),
                exit_code: None,
                stderr_text: None,
                error: None,
            },
        );
    }

    for (result_id, value) in find!(
        (result_id: Id, value: Value<valueschemas::U256BE>),
        pattern!(&space, [{ ?result_id @ exec::exit_code: ?value }])
    ) {
        if let Some(entry) = result_map.get_mut(&result_id) {
            entry.exit_code = u256be_to_u64(value).map(|n| n as i64);
        }
    }

    for (result_id, handle) in find!(
        (result_id: Id, handle: TextHandle),
        pattern!(&space, [{ ?result_id @ exec::stderr_text: ?handle }])
    ) {
        if let Some(entry) = result_map.get_mut(&result_id) {
            entry.stderr_text = Some(read_text(ws, handle)?);
        }
    }

    for (result_id, handle) in find!(
        (result_id: Id, handle: TextHandle),
        pattern!(&space, [{ ?result_id @ exec::error: ?handle }])
    ) {
        if let Some(entry) = result_map.get_mut(&result_id) {
            entry.error = Some(read_text(ws, handle)?);
        }
    }

    state.results = result_map.into_values().collect();
    Ok(state)
}

fn collect_model_chat_state(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    space: &TribleSet,
) -> Result<ModelChatState> {
    let mut state = ModelChatState::default();

    for (request_id, requested_at) in find!(
        (request_id: Id, requested_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            ?request_id @
            metadata::tag: &KIND_MODEL_REQUEST_ID,
            model_chat::requested_at: ?requested_at,
        }])
    ) {
        state
            .requests
            .insert(request_id, ModelRequestRow { requested_at: interval_key(requested_at) });
    }

    for (about_request, started_at) in find!(
        (about_request: Id, started_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            _?event_id @
            metadata::tag: &KIND_MODEL_IN_PROGRESS_ID,
            model_chat::about_request: ?about_request,
            model_chat::started_at: ?started_at,
        }])
    ) {
        state.in_progress.push(ModelInProgressRow {
            about_request,
            started_at: interval_key(started_at),
        });
    }

    let mut result_map: HashMap<Id, ModelResultRow> = HashMap::new();
    for (result_id, about_request, finished_at) in find!(
        (result_id: Id, about_request: Id, finished_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            ?result_id @
            metadata::tag: &KIND_MODEL_RESULT_ID,
            model_chat::about_request: ?about_request,
            model_chat::finished_at: ?finished_at,
        }])
    ) {
        result_map.insert(
            result_id,
            ModelResultRow {
                about_request,
                finished_at: interval_key(finished_at),
                error: None,
            },
        );
    }

    for (result_id, handle) in find!(
        (result_id: Id, handle: TextHandle),
        pattern!(&space, [{ ?result_id @ model_chat::error: ?handle }])
    ) {
        if let Some(entry) = result_map.get_mut(&result_id) {
            entry.error = Some(read_text(ws, handle)?);
        }
    }

    state.results = result_map.into_values().collect();
    Ok(state)
}

fn collect_reason_state(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    space: &TribleSet,
) -> Result<Vec<ReasonEventRow>> {
    let mut rows: HashMap<Id, ReasonEventRow> = HashMap::new();

    for reason_id in find!(
        reason_id: Id,
        pattern!(&space, [{ ?reason_id @ metadata::tag: &KIND_REASON_EVENT_ID }])
    ) {
        rows.insert(
            reason_id,
            ReasonEventRow {
                created_at: None,
                text: None,
                about_turn: None,
                command_text: None,
            },
        );
    }

    for (reason_id, created_at) in find!(
        (reason_id: Id, created_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{ ?reason_id @ reason::created_at: ?created_at }])
    ) {
        if let Some(row) = rows.get_mut(&reason_id) {
            row.created_at = Some(interval_key(created_at));
        }
    }

    for (reason_id, handle) in find!(
        (reason_id: Id, handle: TextHandle),
        pattern!(&space, [{ ?reason_id @ reason::text: ?handle }])
    ) {
        if let Some(row) = rows.get_mut(&reason_id) {
            row.text = Some(read_text(ws, handle)?);
        }
    }

    for (reason_id, about_turn) in find!(
        (reason_id: Id, about_turn: Id),
        pattern!(&space, [{ ?reason_id @ reason::about_turn: ?about_turn }])
    ) {
        if let Some(row) = rows.get_mut(&reason_id) {
            row.about_turn = Some(about_turn);
        }
    }

    for (reason_id, handle) in find!(
        (reason_id: Id, handle: TextHandle),
        pattern!(&space, [{ ?reason_id @ reason::command_text: ?handle }])
    ) {
        if let Some(row) = rows.get_mut(&reason_id) {
            row.command_text = Some(read_text(ws, handle)?);
        }
    }

    let mut list: Vec<ReasonEventRow> = rows.into_values().collect();
    list.sort_by_key(|row| row.created_at.unwrap_or(i128::MIN));
    list.reverse();
    Ok(list)
}

fn pending_exec_count(state: &ExecState) -> usize {
    let done: HashSet<Id> = state.results.iter().map(|row| row.about_request).collect();
    let running: HashSet<Id> = state
        .in_progress
        .iter()
        .map(|row| row.about_request)
        .filter(|id| !done.contains(id))
        .collect();
    state
        .requests
        .keys()
        .filter(|id| !done.contains(*id) && !running.contains(*id))
        .count()
}

fn pending_model_count(state: &ModelChatState) -> usize {
    let done: HashSet<Id> = state.results.iter().map(|row| row.about_request).collect();
    let running: HashSet<Id> = state
        .in_progress
        .iter()
        .map(|row| row.about_request)
        .filter(|id| !done.contains(id))
        .collect();
    state
        .requests
        .keys()
        .filter(|id| !done.contains(*id) && !running.contains(*id))
        .count()
}

fn stale_exec_in_progress_count(state: &ExecState, now_key: i128, stale_ns: i128) -> usize {
    let done: HashSet<Id> = state.results.iter().map(|row| row.about_request).collect();
    state
        .in_progress
        .iter()
        .filter(|row| !done.contains(&row.about_request))
        .filter(|row| now_key.saturating_sub(row.started_at) >= stale_ns)
        .count()
}

fn stale_model_in_progress_count(state: &ModelChatState, now_key: i128, stale_ns: i128) -> usize {
    let done: HashSet<Id> = state.results.iter().map(|row| row.about_request).collect();
    state
        .in_progress
        .iter()
        .filter(|row| !done.contains(&row.about_request))
        .filter(|row| now_key.saturating_sub(row.started_at) >= stale_ns)
        .count()
}

fn active_exec_running_count(state: &ExecState) -> usize {
    let done: HashSet<Id> = state.results.iter().map(|row| row.about_request).collect();
    state
        .in_progress
        .iter()
        .map(|row| row.about_request)
        .filter(|id| !done.contains(id))
        .collect::<HashSet<_>>()
        .len()
}

fn active_model_running_count(state: &ModelChatState) -> usize {
    let done: HashSet<Id> = state.results.iter().map(|row| row.about_request).collect();
    state
        .in_progress
        .iter()
        .map(|row| row.about_request)
        .filter(|id| !done.contains(id))
        .collect::<HashSet<_>>()
        .len()
}

fn collect_exec_attempts(state: &ExecState, recent: usize) -> Vec<ExecAttempt> {
    let mut rows: Vec<ExecAttempt> = state
        .results
        .iter()
        .filter_map(|result| {
            let finished_at = result.finished_at;
            let request = state.requests.get(&result.about_request)?;
            let command = request.command.clone();
            let fingerprint = result
                .error
                .as_ref()
                .map(|s| first_line(s))
                .or_else(|| result.stderr_text.as_ref().map(|s| first_line(s)))
                .unwrap_or_else(|| {
                    if result.exit_code == Some(0) {
                        "<ok>".to_string()
                    } else {
                        "<no stderr text>".to_string()
                    }
                });
            Some(ExecAttempt {
                request_id: request.id,
                result_id: result.id,
                finished_at,
                command,
                exit_code: result.exit_code,
                fingerprint,
            })
        })
        .collect();
    rows.sort_by_key(|row| row.finished_at);
    rows.reverse();
    rows.truncate(recent);
    rows
}

fn build_loop_report(state: &ExecState, recent: usize, min_repeat: usize) -> LoopReport {
    let recent_rows = collect_exec_attempts(state, recent);

    let mut by_pattern: HashMap<(String, Option<i64>, String), PatternSummary> = HashMap::new();
    for row in &recent_rows {
        let key = (row.command.clone(), row.exit_code, row.fingerprint.clone());
        let entry = by_pattern.entry(key).or_insert_with(|| PatternSummary {
            command: row.command.clone(),
            exit_code: row.exit_code,
            fingerprint: row.fingerprint.clone(),
            count: 0,
            latest: row.finished_at,
        });
        entry.count += 1;
        entry.latest = entry.latest.max(row.finished_at);
    }
    let mut top_patterns: Vec<PatternSummary> = by_pattern.into_values().collect();
    top_patterns.sort_by_key(|pat| (pat.count, pat.latest));
    top_patterns.reverse();

    let contiguous_head = recent_rows.first().and_then(|head| {
        let mut count = 0usize;
        for row in &recent_rows {
            if row.command == head.command
                && row.exit_code == head.exit_code
                && row.fingerprint == head.fingerprint
            {
                count += 1;
            } else {
                break;
            }
        }
        (count >= min_repeat).then_some(PatternSummary {
            command: head.command.clone(),
            exit_code: head.exit_code,
            fingerprint: head.fingerprint.clone(),
            count,
            latest: head.finished_at,
        })
    });

    LoopReport {
        recent: recent_rows,
        top_patterns,
        contiguous_head,
    }
}

fn pattern_is_failure(pattern: &PatternSummary) -> bool {
    if pattern.exit_code.unwrap_or(1) != 0 {
        return true;
    }
    let normalized = pattern.fingerprint.trim();
    !normalized.is_empty() && normalized != "<ok>"
}

fn load_relation_terms(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
) -> Result<Vec<String>> {
    let branch_id = ensure_branch_id(repo, "relations")?;
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull relations workspace: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout relations workspace: {e:?}"))?;

    let mut terms: HashSet<String> = HashSet::new();
    for (_person_id, handle) in find!(
        (_person_id: Id, handle: TextHandle),
        pattern!(&space, [{
            ?_person_id @
            metadata::tag: &KIND_PERSON_ID,
            metadata::name: ?handle,
        }])
    ) {
        terms.insert(read_text(&mut ws, handle)?);
    }
    for alias in find!(
        alias: String,
        pattern!(&space, [{ relations::alias: ?alias }])
    ) {
        terms.insert(alias);
    }

    let mut out: Vec<String> = terms.into_iter().collect();
    out.sort();
    Ok(out)
}

fn find_case_variant(terms: &[String], label: &str) -> Option<String> {
    terms
        .iter()
        .find(|term| term.eq_ignore_ascii_case(label) && *term != label)
        .cloned()
}

fn extract_unknown_person_label(text: &str) -> Option<String> {
    let marker = "unknown person label '";
    let start = text.find(marker)?;
    let rest = &text[start + marker.len()..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

fn count_unread_local_messages(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    reader_id: Id,
) -> Result<Option<usize>> {
    let branch_id = ensure_branch_id(repo, "local-messages")?;
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull local-messages workspace: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout local-messages workspace: {e:?}"))?;

    let mut incoming: HashSet<Id> = HashSet::new();
    for (message_id, to_id) in find!(
        (message_id: Id, to_id: Id),
        pattern!(&space, [{
            ?message_id @
            metadata::tag: &KIND_LOCAL_MESSAGE_ID,
            local::to: ?to_id,
        }])
    ) {
        if to_id == reader_id {
            incoming.insert(message_id);
        }
    }

    let mut read: HashSet<Id> = HashSet::new();
    for (about_message, ack_reader) in find!(
        (about_message: Id, ack_reader: Id),
        pattern!(&space, [{
            _?read_id @
            metadata::tag: &KIND_LOCAL_READ_ID,
            local::about_message: ?about_message,
            local::reader: ?ack_reader,
        }])
    ) {
        if ack_reader == reader_id {
            read.insert(about_message);
        }
    }

    Ok(Some(incoming.difference(&read).count()))
}

fn cmd_scan(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    cli: &Cli,
    recent: usize,
    loop_min: usize,
    stale_min: i64,
) -> Result<()> {
    let config = load_latest_config(repo)?;
    let branch_id = resolve_target_branch(repo, cli)?;
    let mut ws = pull_workspace(repo, branch_id, "pull target workspace")?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout target workspace: {e:?}"))?;
    let exec_state = collect_exec_state(&mut ws, &space)?;
    let model_state = collect_model_chat_state(&mut ws, &space)?;

    let now_key = now_epoch().to_tai_duration().total_nanoseconds();
    let stale_ns = (stale_min.max(0) as i128) * 60 * 1_000_000_000;

    let exec_pending = pending_exec_count(&exec_state);
    let model_pending = pending_model_count(&model_state);
    let stale_exec = stale_exec_in_progress_count(&exec_state, now_key, stale_ns);
    let stale_model = stale_model_in_progress_count(&model_state, now_key, stale_ns);
    let exec_running = active_exec_running_count(&exec_state);
    let model_running = active_model_running_count(&model_state);
    let loop_report = build_loop_report(&exec_state, recent, loop_min);

    let unread_local = if let Some(persona_id) = config.as_ref().and_then(|cfg| cfg.persona_id) {
        count_unread_local_messages(repo, persona_id)?
    } else {
        None
    };

    println!("Triage scan");
    println!("- pile: {}", cli.pile.display());
    println!("- target branch: {branch_id:x}");
    if let Some(cfg) = config.as_ref() {
        if let Some(updated_at) = cfg.updated_at {
            println!("- config age: {}", format_age(now_key, updated_at));
        }
        if let Some(persona_id) = cfg.persona_id {
            println!("- persona id: {persona_id:x}");
        }
    } else {
        println!("- config: missing");
    }

    println!();
    println!("Queues");
    println!(
        "- exec: requests={} pending={} running={} results={}",
        exec_state.requests.len(),
        exec_pending,
        exec_running,
        exec_state.results.len()
    );
    println!(
        "- model: requests={} pending={} running={} results={}",
        model_state.requests.len(),
        model_pending,
        model_running,
        model_state.results.len()
    );
    println!("- stale in-progress (>{stale_min}m): exec={stale_exec}, model={stale_model}");
    match unread_local {
        Some(count) => println!("- local unread (persona inbox): {count}"),
        None => println!("- local unread (persona inbox): unavailable"),
    }

    println!();
    println!("Loop heuristics");
    let probable_pattern = loop_report.contiguous_head.as_ref().or_else(|| {
        loop_report
            .top_patterns
            .iter()
            .find(|pat| pat.count >= loop_min && pattern_is_failure(pat))
    });
    if let Some(head) = probable_pattern {
        println!(
            "- probable loop: {} repeated {}x (exit={}): {}",
            truncate_single_line(&head.command, 80),
            head.count,
            head.exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_string()),
            truncate_single_line(&head.fingerprint, 120)
        );
    } else {
        println!("- no contiguous failure loop >= {loop_min} in recent exec results");
    }

    let recent_model_failures = collect_recent_model_failures(&model_state, recent);
    println!();
    println!("Recent model failures");
    if recent_model_failures.is_empty() {
        println!("- none in recent window");
    } else {
        for row in recent_model_failures {
            let age = format_age(now_key, row.finished_at);
            let detail = row
                .error
                .as_deref()
                .map(first_line)
                .unwrap_or_else(|| "<missing error text>".to_string());
            println!("- {age} | {}", truncate_single_line(detail.as_str(), 140));
        }
    }

    println!();
    println!("Suggested next checks");
    if model_pending > 0 && model_state.in_progress.is_empty() {
        println!("- Model worker might be down: pending requests exist without in-progress events.");
    }
    if exec_pending > 0 && exec_state.in_progress.is_empty() {
        println!(
            "- Exec worker might be down: pending command requests exist without in-progress events."
        );
    }
    if stale_exec > 0 || stale_model > 0 {
        println!("- One or more workers appear stale; inspect service logs and process health.");
    }
    if let Some(head) = probable_pattern {
        if let Some(label) = extract_unknown_person_label(&head.fingerprint) {
            let terms = load_relation_terms(repo)?;
            if let Some(case_variant) = find_case_variant(&terms, label.as_str()) {
                println!(
                    "- local_messages label mismatch: '{}' failed; try '{}' or add '{}' as alias in relations.",
                    label, case_variant, label
                );
            } else {
                println!(
                    "- local_messages unknown label '{}': add it to relations or use a known label/id.",
                    label
                );
            }
        }
        if head.fingerprint.contains("rust-script")
            && head.fingerprint.contains("No such file or directory")
        {
            println!(
                "- rust-script is missing in the VM: install it (or invoke faculties via `rust-script <file>` fallback)."
            );
        }
        if head.fingerprint.contains("commentary: not found") {
            println!(
                "- command emission includes markdown fence/preamble; harden command extraction to strip wrappers."
            );
        }
    }
    if model_pending == 0
        && exec_pending == 0
        && stale_exec == 0
        && stale_model == 0
        && unread_local.unwrap_or(0) == 0
    {
        println!("- system looks healthy; no obvious blockers detected.");
    }

    Ok(())
}

fn collect_recent_model_failures(state: &ModelChatState, recent: usize) -> Vec<ModelResultRow> {
    let mut failures: Vec<ModelResultRow> = state
        .results
        .iter()
        .filter(|row| row.error.is_some())
        .cloned()
        .collect();
    failures.sort_by_key(|row| row.finished_at);
    failures.reverse();
    failures.into_iter().take(recent.min(5)).collect()
}

fn verify_commit_chain(
    reader: &triblespace::core::repo::pile::PileReader<valueschemas::Blake3>,
    start: Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::SimpleArchive>>,
) -> ChainReport {
    let head_hash: Value<valueschemas::Hash<valueschemas::Blake3>> =
        valueschemas::Handle::to_hash(start);
    let commit_head: String = head_hash.from_value();

    let mut queue: VecDeque<(
        Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::SimpleArchive>>,
        usize,
    )> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();
    queue.push_back((start, 0));

    let mut checked_commits = 0usize;
    while let Some((commit, depth)) = queue.pop_front() {
        let commit_hash_value: Value<valueschemas::Hash<valueschemas::Blake3>> =
            valueschemas::Handle::to_hash(commit);
        let commit_hash: String = commit_hash_value.from_value();
        if !visited.insert(commit_hash.clone()) {
            continue;
        }

        match reader.metadata(commit) {
            Ok(Some(_)) => {}
            Ok(None) => {
                return ChainReport {
                    commit_head,
                    checked_commits,
                    issue: Some(ChainIssue {
                        commit_hash,
                        depth_from_head: depth,
                        reason: "commit blob missing".to_string(),
                    }),
                };
            }
            Err(err) => {
                return ChainReport {
                    commit_head,
                    checked_commits,
                    issue: Some(ChainIssue {
                        commit_hash,
                        depth_from_head: depth,
                        reason: format!("commit metadata error: {err:?}"),
                    }),
                };
            }
        }

        let commit_meta: TribleSet = match reader.get(commit) {
            Ok(meta) => meta,
            Err(err) => {
                return ChainReport {
                    commit_head,
                    checked_commits,
                    issue: Some(ChainIssue {
                        commit_hash,
                        depth_from_head: depth,
                        reason: format!("commit decode failed: {err:?}"),
                    }),
                };
            }
        };

        let mut saw_content_attr = false;
        let mut missing_content_ref = false;
        let mut parents = Vec::new();
        for trible in commit_meta.iter() {
            if trible.a() == &REPO_CONTENT_ATTR {
                saw_content_attr = true;
                let content = *trible
                    .v::<valueschemas::Handle<valueschemas::Blake3, blobschemas::SimpleArchive>>();
                match reader.metadata(content) {
                    Ok(Some(_)) => {}
                    Ok(None) => missing_content_ref = true,
                    Err(err) => {
                        return ChainReport {
                            commit_head,
                            checked_commits,
                            issue: Some(ChainIssue {
                                commit_hash,
                                depth_from_head: depth,
                                reason: format!("content metadata error: {err:?}"),
                            }),
                        };
                    }
                }
            } else if trible.a() == &REPO_PARENT_ATTR {
                parents.push(
                    *trible.v::<
                        valueschemas::Handle<valueschemas::Blake3, blobschemas::SimpleArchive>,
                    >(),
                );
            }
        }

        // Commits may intentionally omit repo::content (for example merge-only
        // commits). Only treat missing content as corruption when the commit
        // explicitly references repo::content blobs and one of those blobs is
        // unavailable.
        if saw_content_attr && missing_content_ref {
            return ChainReport {
                commit_head,
                checked_commits,
                issue: Some(ChainIssue {
                    commit_hash,
                    depth_from_head: depth,
                    reason: "referenced content blob missing".to_string(),
                }),
            };
        }

        checked_commits += 1;
        for parent in parents {
            queue.push_back((parent, depth + 1));
        }
    }

    ChainReport {
        commit_head,
        checked_commits,
        issue: None,
    }
}

fn cmd_chain(repo: &mut Repository<Pile<valueschemas::Blake3>>, cli: &Cli) -> Result<()> {
    let branch_id = resolve_target_branch(repo, cli)?;
    let Some(branch_meta_handle) = repo
        .storage_mut()
        .head(branch_id)
        .map_err(|err| anyhow!("read branch metadata head: {err:?}"))?
    else {
        bail!("target branch {branch_id:x} has no branch metadata head");
    };

    let reader = repo
        .storage_mut()
        .reader()
        .map_err(|err| anyhow!("open pile reader: {err:?}"))?;
    let branch_meta: TribleSet = reader
        .get(branch_meta_handle)
        .map_err(|err| anyhow!("decode branch metadata: {err:?}"))?;

    let mut branch_name = None;
    let mut commit_head = None;
    for trible in branch_meta.iter() {
        if trible.a() == &metadata::name.id() {
            let handle =
                *trible.v::<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>();
            if let Ok(view) = reader.get::<View<str>, _>(handle) {
                branch_name = Some(view.as_ref().to_string());
            }
        } else if trible.a() == &REPO_HEAD_ATTR {
            commit_head = Some(
                *trible
                    .v::<valueschemas::Handle<valueschemas::Blake3, blobschemas::SimpleArchive>>(),
            );
        }
    }

    let Some(commit_head) = commit_head else {
        bail!("branch metadata for {branch_id:x} has no repo head");
    };

    let report = verify_commit_chain(&reader, commit_head);
    println!("Commit-chain integrity");
    println!("- pile: {}", cli.pile.display());
    println!(
        "- branch: {} ({branch_id:x})",
        branch_name.unwrap_or_else(|| "<unnamed>".to_string())
    );
    println!("- current commit head: {}", report.commit_head);
    match report.issue {
        Some(issue) => {
            println!("- status: broken");
            println!("- issue: {}", issue.reason);
            println!("- issue commit: {}", issue.commit_hash);
            println!("- depth from head: {}", issue.depth_from_head);
            println!(
                "- commits verified before failure: {}",
                report.checked_commits
            );
        }
        None => {
            println!("- status: healthy");
            println!("- commits verified: {}", report.checked_commits);
        }
    }

    Ok(())
}

fn cmd_loops(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    cli: &Cli,
    recent: usize,
    min_repeat: usize,
) -> Result<()> {
    let branch_id = resolve_target_branch(repo, cli)?;
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull target workspace: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout target workspace: {e:?}"))?;
    let exec_state = collect_exec_state(&mut ws, &space)?;
    let report = build_loop_report(&exec_state, recent, min_repeat);
    let now_key = now_epoch().to_tai_duration().total_nanoseconds();

    println!("Triage loops");
    println!("- branch: {branch_id:x}");
    println!("- recent attempts: {}", report.recent.len());

    if let Some(head) = report.contiguous_head.as_ref() {
        println!(
            "- contiguous head loop: {}x, exit={}, command={}",
            head.count,
            head.exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_string()),
            truncate_single_line(&head.command, 90)
        );
    } else {
        println!("- contiguous head loop: none (threshold {min_repeat})");
    }

    println!();
    println!("Top patterns");
    for pattern in report.top_patterns.iter().take(5) {
        println!(
            "- {}x | exit={} | {} | {}",
            pattern.count,
            pattern
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_string()),
            truncate_single_line(&pattern.command, 70),
            truncate_single_line(&pattern.fingerprint, 80)
        );
    }

    println!();
    println!("Recent attempts");
    for row in &report.recent {
        println!(
            "- [{}:{}] {} | exit={} | {} | {}",
            fmt_id(row.request_id),
            fmt_id(row.result_id),
            format_age(now_key, row.finished_at),
            row.exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "-".to_string()),
            truncate_single_line(&row.command, 70),
            truncate_single_line(&row.fingerprint, 90)
        );
    }

    Ok(())
}

fn build_timeline_rows(
    exec_state: &ExecState,
    model_state: &ModelChatState,
    reason_rows: &[ReasonEventRow],
    recent: usize,
) -> Vec<TimelineRow> {
    let mut rows = Vec::<TimelineRow>::new();

    for request in exec_state.requests.values() {
        {
            let (at, command) = (request.requested_at, &request.command);
            rows.push(TimelineRow {
                at,
                source: "exec",
                detail: format!(
                    "[{}] {}",
                    fmt_id(request.id),
                    truncate_single_line(command, 120)
                ),
            });
        }
    }

    let request_commands: HashMap<Id, String> = exec_state
        .requests
        .values()
        .map(|request| (request.id, request.command.clone()))
        .collect();

    for result in &exec_state.results {
        let at = result.finished_at;
        let command = request_commands
            .get(&result.about_request)
            .cloned()
            .unwrap_or_else(|| "<missing command>".to_string());
        let status = if let Some(error) = result.error.as_ref() {
            format!("error {}", truncate_single_line(error, 72))
        } else if let Some(stderr) = result.stderr_text.as_ref() {
            let line = first_line(stderr);
            if line == "<ok>" {
                format!("exit {}", result.exit_code.unwrap_or(0))
            } else {
                format!(
                    "exit {} stderr {}",
                    result.exit_code.unwrap_or(-1),
                    truncate_single_line(line.as_str(), 72)
                )
            }
        } else {
            format!("exit {}", result.exit_code.unwrap_or(-1))
        };
        rows.push(TimelineRow {
            at,
            source: "exec-result",
            detail: format!(
                "[{}:{}] {} | {}",
                fmt_id(result.about_request),
                fmt_id(result.id),
                truncate_single_line(command.as_str(), 100),
                status
            ),
        });
    }

    for (request_id, entry) in &model_state.requests {
        rows.push(TimelineRow {
            at: entry.requested_at,
            source: "model",
            detail: format!("[{}] request", fmt_id(*request_id)),
        });
    }
    for result in &model_state.results {
        if let Some(error) = result.error.as_ref() {
            rows.push(TimelineRow {
                at: result.finished_at,
                source: "model-error",
                detail: truncate_single_line(error, 130),
            });
        }
    }

    for row in reason_rows {
        let text = row.text.as_deref().unwrap_or("<missing>");
        let mut detail = String::new();
        if let Some(turn_id) = row.about_turn {
            detail.push_str(format!("[turn {}] ", fmt_id(turn_id)).as_str());
        }
        detail.push_str(truncate_single_line(text, 120).as_str());
        if let Some(command) = row.command_text.as_ref() {
            detail.push_str(" | ");
            detail.push_str(truncate_single_line(command, 96).as_str());
        }
        rows.push(TimelineRow {
            at: row.created_at.unwrap_or(i128::MIN),
            source: "reason",
            detail,
        });
    }

    rows.sort_by_key(|row| row.at);
    rows.reverse();
    if rows.len() > recent {
        rows.truncate(recent);
    }
    rows
}

fn cmd_timeline(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    cli: &Cli,
    recent: usize,
) -> Result<()> {
    let branch_id = resolve_target_branch(repo, cli)?;
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow!("pull target workspace: {e:?}"))?;
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow!("checkout target workspace: {e:?}"))?;
    let exec_state = collect_exec_state(&mut ws, &space)?;
    let model_state = collect_model_chat_state(&mut ws, &space)?;
    let reason_state = collect_reason_state(&mut ws, &space)?;
    let rows = build_timeline_rows(&exec_state, &model_state, &reason_state, recent);
    let now_key = now_epoch().to_tai_duration().total_nanoseconds();

    println!("Triage timeline");
    println!("- pile: {}", cli.pile.display());
    println!("- branch: {branch_id:x}");
    println!("- rows: {}", rows.len());
    println!();
    for row in rows {
        println!(
            "- {:>5} {:>11} | {}",
            format_age(now_key, row.at),
            row.source,
            row.detail
        );
    }
    Ok(())
}

#[derive(Debug)]
struct BranchRepairOutcome {
    name: String,
    canonical_id: Id,
    duplicate_ids: Vec<Id>,
    merged_facts: usize,
    merged_branches: usize,
    deleted_branches: usize,
    skipped_branches: usize,
}

fn insert_canonical_branch(
    map: &mut HashMap<String, Id>,
    name: &str,
    id: Option<Id>,
) -> Result<()> {
    let Some(id) = id else {
        return Ok(());
    };
    match map.get(name).copied() {
        Some(existing) if existing != id => {
            bail!("conflicting canonical ids for branch name '{name}': {existing:x} vs {id:x}");
        }
        _ => {
            map.insert(name.to_owned(), id);
            Ok(())
        }
    }
}

fn delete_branch(repo: &mut Repository<Pile<valueschemas::Blake3>>, branch_id: Id) -> Result<()> {
    let mut expected = repo
        .storage_mut()
        .head(branch_id)
        .map_err(|err| anyhow!("read branch {branch_id:x} head: {err:?}"))?;
    if expected.is_none() {
        return Ok(());
    }

    for _ in 0..3 {
        let result = repo
            .storage_mut()
            .update(branch_id, expected, None)
            .map_err(|err| anyhow!("delete branch {branch_id:x}: {err:?}"))?;
        match result {
            PushResult::Success() => return Ok(()),
            PushResult::Conflict(current) => {
                if current.is_none() {
                    return Ok(());
                }
                expected = current;
            }
        }
    }
    bail!("delete branch {branch_id:x}: conflict after retries")
}

fn repair_named_duplicates(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    branch_name: &str,
    canonical_id: Id,
    dry_run: bool,
) -> Result<BranchRepairOutcome> {
    let duplicate_ids = find_branch_ids_by_name(repo.storage_mut(), branch_name)?
        .into_iter()
        .filter(|id| *id != canonical_id)
        .collect::<Vec<_>>();

    let mut outcome = BranchRepairOutcome {
        name: branch_name.to_owned(),
        canonical_id,
        duplicate_ids: duplicate_ids.clone(),
        merged_facts: 0,
        merged_branches: 0,
        deleted_branches: 0,
        skipped_branches: 0,
    };
    if duplicate_ids.is_empty() {
        return Ok(outcome);
    }

    if dry_run {
        let canonical_exists = repo
            .storage_mut()
            .head(canonical_id)
            .map_err(|e| anyhow!("read canonical branch {canonical_id:x} head: {e:?}"))?
            .is_some();
        if !canonical_exists {
            outcome.skipped_branches = outcome.duplicate_ids.len();
            return Ok(outcome);
        }
    }

    let mut canonical_ws = repo
        .pull(canonical_id)
        .map_err(|err| anyhow!("pull canonical branch {canonical_id:x}: {err:?}"))?;
    let mut canonical_data = canonical_ws
        .checkout(..)
        .map_err(|err| anyhow!("checkout canonical branch {canonical_id:x}: {err:?}"))?;

    for duplicate_id in duplicate_ids {
        let mut duplicate_ws = match repo.pull(duplicate_id) {
            Ok(ws) => ws,
            Err(err) => {
                outcome.skipped_branches += 1;
                eprintln!(
                    "warning: skip duplicate branch {duplicate_id:x} ({branch_name}): pull failed ({err:?})"
                );
                continue;
            }
        };
        let duplicate_data = match duplicate_ws.checkout(..) {
            Ok(set) => set,
            Err(err) => {
                outcome.skipped_branches += 1;
                eprintln!(
                    "warning: skip duplicate branch {duplicate_id:x} ({branch_name}): checkout failed ({err:?})"
                );
                continue;
            }
        };

        let delta = duplicate_data.difference(&canonical_data);
        if !delta.is_empty() {
            outcome.merged_facts += delta.len();
            outcome.merged_branches += 1;
            if !dry_run {
                canonical_ws.commit(delta.clone(), "triage repair branch duplicates");
                push_workspace(repo, &mut canonical_ws)?;
                canonical_data += delta;
            }
        }

        if !dry_run {
            match delete_branch(repo, duplicate_id) {
                Ok(()) => outcome.deleted_branches += 1,
                Err(err) => {
                    outcome.skipped_branches += 1;
                    eprintln!(
                        "warning: failed to delete duplicate branch {duplicate_id:x} ({branch_name}): {err:#}"
                    );
                }
            }
        }
    }

    Ok(outcome)
}

/// All well-known branch names used across the system.
const KNOWN_BRANCH_NAMES: &[&str] = &[
    "archive",
    "cognition",
    "compass",
    "config",
    "exec",
    "local-messages",
    "media",
    "relations",
    "teams",
    "web",
    "workspace",
];

fn cmd_repair_branch_duplicates(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    cli: &Cli,
    dry_run: bool,
) -> Result<()> {
    let mut canonical = HashMap::<String, Id>::new();
    for &name in KNOWN_BRANCH_NAMES {
        let id = ensure_branch_id(repo, name)?;
        insert_canonical_branch(&mut canonical, name, Some(id))?;
    }
    // Also include the target branch if it differs from the well-known names.
    if !canonical.contains_key(cli.branch.as_str()) {
        let id = ensure_branch_id(repo, &cli.branch)?;
        insert_canonical_branch(&mut canonical, &cli.branch, Some(id))?;
    }

    let mut names: Vec<String> = canonical.keys().cloned().collect();
    names.sort();

    println!(
        "Repair duplicate named branches{}",
        if dry_run { " (dry-run)" } else { "" }
    );
    println!("- pile: {}", cli.pile.display());
    println!("- canonical branch entries: {}", names.len());

    let mut outcomes = Vec::new();
    for name in names {
        let canonical_id = canonical[&name];
        let outcome = repair_named_duplicates(repo, name.as_str(), canonical_id, dry_run)?;
        outcomes.push(outcome);
    }

    let touched = outcomes
        .iter()
        .filter(|o| !o.duplicate_ids.is_empty())
        .count();
    let merged_branches: usize = outcomes.iter().map(|o| o.merged_branches).sum();
    let merged_facts: usize = outcomes.iter().map(|o| o.merged_facts).sum();
    let deleted: usize = outcomes.iter().map(|o| o.deleted_branches).sum();
    let skipped: usize = outcomes.iter().map(|o| o.skipped_branches).sum();

    println!();
    println!("Summary");
    println!("- names with duplicates: {touched}");
    println!("- merged duplicate branches: {merged_branches}");
    println!("- merged facts: {merged_facts}");
    if dry_run {
        println!(
            "- branches to delete: {}",
            outcomes
                .iter()
                .map(|o| o.duplicate_ids.len())
                .sum::<usize>()
        );
    } else {
        println!("- deleted duplicate branches: {deleted}");
    }
    if skipped > 0 {
        println!("- skipped branches: {skipped}");
    }

    println!();
    println!("Details");
    for outcome in outcomes {
        if outcome.duplicate_ids.is_empty() {
            continue;
        }
        let duplicate_list = outcome
            .duplicate_ids
            .iter()
            .map(|id| format!("{id:x}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "- {} -> {:x} | duplicates: [{}] | merged_facts={} | {}",
            outcome.name,
            outcome.canonical_id,
            duplicate_list,
            outcome.merged_facts,
            if dry_run {
                "would_delete=true".to_string()
            } else {
                format!("deleted={}", outcome.deleted_branches)
            }
        );
    }

    Ok(())
}

fn collect_context_chunks(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    space: &TribleSet,
) -> Result<Vec<ContextChunkRow>> {
    let mut chunks: HashMap<Id, ContextChunkRow> = HashMap::new();

    for chunk_id in find!(
        chunk_id: Id,
        pattern!(&space, [{ ?chunk_id @ metadata::tag: &KIND_CONTEXT_CHUNK_ID }])
    ) {
        chunks.insert(chunk_id, ContextChunkRow {
            id: chunk_id,
            summary: None,
            created_at: None,
            start_at: None,
            end_at: None,
            children: Vec::new(),
            about_exec_result: None,
        });
    }

    for (chunk_id, handle) in find!(
        (chunk_id: Id, handle: TextHandle),
        pattern!(&space, [{ ?chunk_id @ context::summary: ?handle }])
    ) {
        if let Some(row) = chunks.get_mut(&chunk_id) {
            row.summary = Some(read_text(ws, handle)?);
        }
    }

    for (chunk_id, value) in find!(
        (chunk_id: Id, value: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{ ?chunk_id @ context::created_at: ?value }])
    ) {
        if let Some(row) = chunks.get_mut(&chunk_id) {
            row.created_at = Some(interval_key(value));
        }
    }

    for (chunk_id, value) in find!(
        (chunk_id: Id, value: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{ ?chunk_id @ context::start_at: ?value }])
    ) {
        if let Some(row) = chunks.get_mut(&chunk_id) {
            row.start_at = Some(interval_key(value));
        }
    }

    for (chunk_id, value) in find!(
        (chunk_id: Id, value: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{ ?chunk_id @ context::end_at: ?value }])
    ) {
        if let Some(row) = chunks.get_mut(&chunk_id) {
            row.end_at = Some(interval_key(value));
        }
    }

    for (parent_id, child_id) in find!(
        (parent_id: Id, child_id: Id),
        pattern!(&space, [{ ?parent_id @ context::child: ?child_id }])
    ) {
        if let Some(row) = chunks.get_mut(&parent_id) {
            row.children.push(child_id);
        }
    }

    for (chunk_id, exec_id) in find!(
        (chunk_id: Id, exec_id: Id),
        pattern!(&space, [{ ?chunk_id @ context::about_exec_result: ?exec_id }])
    ) {
        if let Some(row) = chunks.get_mut(&chunk_id) {
            row.about_exec_result = Some(exec_id);
        }
    }

    let mut list: Vec<ContextChunkRow> = chunks.into_values().collect();
    list.sort_by_key(|row| row.start_at.unwrap_or(i128::MAX));
    Ok(list)
}

fn find_root_chunks(chunks: &[ContextChunkRow]) -> Vec<usize> {
    let child_ids: HashSet<Id> = chunks.iter().flat_map(|c| c.children.iter().copied()).collect();
    // A root is any chunk that is not a child of another chunk
    chunks.iter().enumerate()
        .filter(|(_, c)| !child_ids.contains(&c.id))
        .map(|(i, _)| i)
        .collect()
}

fn load_budget_from_config(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
) -> Result<Option<BudgetInfo>> {
    let branch_id = ensure_branch_id(repo, "config")?;
    let mut ws = pull_workspace(repo, branch_id, "pull config for budget")?;
    let space = ws.checkout(..).map_err(|e| anyhow!("checkout config: {e:?}"))?;

    // Find latest config
    let mut latest_config: Option<(Id, i128)> = None;
    for (config_id, updated_at) in find!(
        (config_id: Id, updated_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            ?config_id @
            config::updated_at: ?updated_at,
        }])
    ) {
        let key = interval_key(updated_at);
        match latest_config {
            Some((_, best)) if best >= key => {}
            _ => latest_config = Some((config_id, key)),
        }
    }
    let Some((config_id, _)) = latest_config else {
        return Ok(None);
    };

    // Get active model profile id
    let mut active_profile_id: Option<Id> = None;
    if let Some(value) = find!(
        value: Id,
        pattern!(&space, [{ config_id @ config::active_model_profile_id: ?value }])
    ).next() {
        active_profile_id = Some(value);
    }

    // Get system prompt length
    let system_prompt_chars: usize = if let Some(handle) = find!(
        handle: TextHandle,
        pattern!(&space, [{ config_id @ config::system_prompt: ?handle }])
    ).next() {
        read_text(&mut ws, handle)?.len()
    } else {
        0
    };

    // Find model profile
    let Some(profile_id) = active_profile_id else {
        return Ok(None);
    };

    let mut context_window: u64 = 0;
    let mut max_output: u64 = 0;
    let mut safety_margin: u64 = 0;
    let mut chars_per_token: u64 = 4;

    if let Some(value) = find!(
        value: Value<valueschemas::U256BE>,
        pattern!(&space, [{ profile_id @ config::model_context_window_tokens: ?value }])
    ).next() {
        context_window = u256be_to_u64(value).unwrap_or(0);
    }
    if let Some(value) = find!(
        value: Value<valueschemas::U256BE>,
        pattern!(&space, [{ profile_id @ config::model_max_output_tokens: ?value }])
    ).next() {
        max_output = u256be_to_u64(value).unwrap_or(0);
    }
    if let Some(value) = find!(
        value: Value<valueschemas::U256BE>,
        pattern!(&space, [{ profile_id @ config::model_context_safety_margin_tokens: ?value }])
    ).next() {
        safety_margin = u256be_to_u64(value).unwrap_or(0);
    }
    if let Some(value) = find!(
        value: Value<valueschemas::U256BE>,
        pattern!(&space, [{ profile_id @ config::model_chars_per_token: ?value }])
    ).next() {
        chars_per_token = u256be_to_u64(value).unwrap_or(4).max(1);
    }

    let body_budget_chars = ((context_window as i64) - (max_output as i64) - (safety_margin as i64))
        * (chars_per_token as i64)
        - (system_prompt_chars as i64);

    Ok(Some(BudgetInfo {
        context_window_tokens: context_window,
        max_output_tokens: max_output,
        safety_margin_tokens: safety_margin,
        chars_per_token,
        system_prompt_chars,
        body_budget_chars,
    }))
}

fn load_turn_context(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    exec_branch_id: Id,
    turn_offset: usize,
) -> Result<Option<(Id, String, Vec<ChatMessage>)>> {
    let mut ws = pull_workspace(repo, exec_branch_id, "pull exec for context")?;
    let space = ws.checkout(..).map_err(|e| anyhow!("checkout exec: {e:?}"))?;

    // Collect exec requests with timestamps
    let mut requests: Vec<(Id, i128, Option<String>)> = Vec::new();
    for (request_id, requested_at) in find!(
        (request_id: Id, requested_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            ?request_id @
            metadata::tag: &KIND_EXEC_REQUEST_ID,
            exec::requested_at: ?requested_at,
        }])
    ) {
        requests.push((request_id, interval_key(requested_at), None));
    }
    // Load command text
    for (request_id, handle) in find!(
        (request_id: Id, handle: TextHandle),
        pattern!(&space, [{ ?request_id @ exec::command_text: ?handle }])
    ) {
        for entry in requests.iter_mut() {
            if entry.0 == request_id {
                entry.2 = Some(read_text(&mut ws, handle)?);
                break;
            }
        }
    }

    requests.sort_by_key(|r| r.1);
    requests.reverse();

    if turn_offset == 0 || turn_offset > requests.len() {
        return Ok(None);
    }
    let (request_id, _, command) = &requests[turn_offset - 1];
    let request_id = *request_id;
    let command = command.clone().unwrap_or_else(|| "<unknown>".to_string());

    // Find result for this request
    let mut result_id: Option<Id> = None;
    for (rid, about_request) in find!(
        (rid: Id, about_request: Id),
        pattern!(&space, [{
            ?rid @
            metadata::tag: &KIND_EXEC_RESULT_ID,
            exec::about_request: ?about_request,
        }])
    ) {
        if about_request == request_id {
            result_id = Some(rid);
            break;
        }
    }

    let Some(result_id) = result_id else {
        return Ok(None);
    };

    // result -> about_thought -> thought -> context blob
    let mut thought_id: Option<Id> = None;
    for (rid, tid) in find!(
        (rid: Id, tid: Id),
        pattern!(&space, [{ ?rid @ exec::about_thought: ?tid }])
    ) {
        if rid == result_id {
            thought_id = Some(tid);
            break;
        }
    }

    let Some(thought_id) = thought_id else {
        return Ok(None);
    };

    // Load context blob from thought
    let mut context_json: Option<String> = None;
    for (tid, handle) in find!(
        (tid: Id, handle: TextHandle),
        pattern!(&space, [{ ?tid @ cog::context: ?handle }])
    ) {
        if tid == thought_id {
            context_json = Some(read_text(&mut ws, handle)?);
            break;
        }
    }

    let Some(json) = context_json else {
        return Ok(None);
    };

    let messages: Vec<ChatMessage> = serde_json::from_str(&json)
        .map_err(|e| anyhow!("parse context JSON: {e}"))?;

    Ok(Some((request_id, command, messages)))
}

fn cmd_cover(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    cli: &Cli,
    full: bool,
    tree: bool,
) -> Result<()> {
    // Memory chunks live on the "memory" branch, not cognition.
    let branch_id = ensure_branch_id(repo, "memory")?;
    let mut ws = pull_workspace(repo, branch_id, "pull target for cover")?;
    let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;

    let chunks = collect_context_chunks(&mut ws, &space)?;
    let root_indices = find_root_chunks(&chunks);

    let chunk_map: HashMap<Id, &ContextChunkRow> = chunks.iter().map(|c| (c.id, c)).collect();

    // Compute max depth
    fn max_depth(chunk: &ContextChunkRow, map: &HashMap<Id, &ContextChunkRow>, depth: usize) -> usize {
        if chunk.children.is_empty() {
            return depth;
        }
        chunk.children.iter()
            .filter_map(|cid| map.get(cid))
            .map(|child| max_depth(child, map, depth + 1))
            .max()
            .unwrap_or(depth)
    }

    let depth = root_indices.iter()
        .filter_map(|i| chunks.get(*i))
        .map(|c| max_depth(c, &chunk_map, 0))
        .max()
        .unwrap_or(0);

    println!("Memory cover");
    println!("- pile: {}", cli.pile.display());
    println!("- branch: {branch_id:x}");
    println!("- chunks: {} total, {} roots, max depth {depth}", chunks.len(), root_indices.len());

    // Budget
    let budget = load_budget_from_config(repo)?;
    if let Some(ref b) = budget {
        let cover_chars: usize = chunks.iter()
            .filter_map(|c| c.summary.as_ref())
            .map(|s| s.len())
            .sum();
        let fill_pct = if b.body_budget_chars > 0 {
            (cover_chars as f64 / b.body_budget_chars as f64 * 100.0) as u32
        } else {
            0
        };
        println!();
        println!("Budget");
        println!(
            "  context_window={} max_output={} safety={} chars/tok={}",
            b.context_window_tokens, b.max_output_tokens, b.safety_margin_tokens, b.chars_per_token
        );
        println!(
            "  system_prompt={} chars  body_budget={} chars",
            b.system_prompt_chars, b.body_budget_chars
        );
        println!("  cover_chars={cover_chars}  fill={fill_pct}%");
    }

    println!();
    if tree {
        println!("Tree (oldest -> newest)");
        fn print_tree(
            chunk: &ContextChunkRow,
            map: &HashMap<Id, &ContextChunkRow>,
            indent: usize,
            full: bool,
        ) {
            let prefix = "  ".repeat(indent);
            let range = match (chunk.start_at, chunk.end_at) {
                (Some(s), Some(e)) => format!(
                    "{}..{}  ({})",
                    format_tai_ns(s),
                    format_tai_ns(e),
                    format_duration_ns(e.saturating_sub(s))
                ),
                (Some(s), None) => format!("{}..?", format_tai_ns(s)),
                _ => "?..?".to_string(),
            };
            let children_label = if chunk.children.is_empty() {
                "leaf".to_string()
            } else {
                format!("{} children", chunk.children.len())
            };
            let summary = chunk.summary.as_deref().unwrap_or("<no summary>");
            let summary_text = if full {
                summary.to_string()
            } else {
                truncate_single_line(summary, 60)
            };
            println!(
                "{prefix}{}  {range}  {children_label}  \"{summary_text}\"",
                fmt_id(chunk.id)
            );
            let mut sorted_children: Vec<&ContextChunkRow> = chunk.children.iter()
                .filter_map(|cid| map.get(cid).copied())
                .collect();
            sorted_children.sort_by_key(|c| c.start_at.unwrap_or(i128::MAX));
            for child in sorted_children {
                print_tree(child, map, indent + 1, full);
            }
        }
        for &idx in &root_indices {
            if let Some(chunk) = chunks.get(idx) {
                print_tree(chunk, &chunk_map, 1, full);
            }
        }
    } else {
        println!("Roots (oldest -> newest)");
        for &idx in &root_indices {
            if let Some(chunk) = chunks.get(idx) {
                let range = match (chunk.start_at, chunk.end_at) {
                    (Some(s), Some(e)) => format!(
                        "{}..{}  ({})",
                        format_tai_ns(s),
                        format_tai_ns(e),
                        format_duration_ns(e.saturating_sub(s))
                    ),
                    (Some(s), None) => format!("{}..?", format_tai_ns(s)),
                    _ => "?..?".to_string(),
                };
                let children_label = if chunk.children.is_empty() {
                    "leaf".to_string()
                } else {
                    format!("{} children", chunk.children.len())
                };
                let summary = chunk.summary.as_deref().unwrap_or("<no summary>");
                let summary_text = if full {
                    summary.to_string()
                } else {
                    truncate_single_line(summary, 60)
                };
                println!(
                    "  {}  {range}  {children_label}  \"{summary_text}\"",
                    fmt_id(chunk.id)
                );
            }
        }
    }

    Ok(())
}

fn cmd_chunk(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    _cli: &Cli,
    id_prefix_str: &str,
) -> Result<()> {
    let branch_id = ensure_branch_id(repo, "memory")?;
    let mut ws = pull_workspace(repo, branch_id, "pull target for chunk")?;
    let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;

    let chunks = collect_context_chunks(&mut ws, &space)?;
    let prefix = id_prefix_str.to_uppercase();

    let matches: Vec<&ContextChunkRow> = chunks.iter()
        .filter(|c| format!("{:X}", c.id).starts_with(&prefix))
        .collect();

    if matches.is_empty() {
        bail!("no chunk found matching prefix '{id_prefix_str}'");
    }
    if matches.len() > 1 {
        println!("Ambiguous prefix '{id_prefix_str}' matches {} chunks:", matches.len());
        for c in &matches {
            let range = match (c.start_at, c.end_at) {
                (Some(s), Some(e)) => format!("{}..{}", format_tai_ns(s), format_tai_ns(e)),
                _ => "?..?".to_string(),
            };
            println!("  {:X}  {range}", c.id);
        }
        return Ok(());
    }

    let chunk = matches[0];
    let chunk_map: HashMap<Id, &ContextChunkRow> = chunks.iter().map(|c| (c.id, c)).collect();

    println!("Chunk {:X}", chunk.id);
    match (chunk.start_at, chunk.end_at) {
        (Some(s), Some(e)) => {
            println!(
                "  range: {}..{}  ({})",
                format_tai_ns(s),
                format_tai_ns(e),
                format_duration_ns(e.saturating_sub(s))
            );
        }
        (Some(s), None) => println!("  range: {}..?", format_tai_ns(s)),
        _ => println!("  range: unknown"),
    }
    if let Some(created) = chunk.created_at {
        println!("  created: {}", format_tai_ns(created));
    }
    if let Some(exec_id) = chunk.about_exec_result {
        println!("  origin: exec:{}", fmt_id(exec_id));
    }
    println!("  children: {}", chunk.children.len());

    println!();
    println!("Summary:");
    match chunk.summary.as_deref() {
        Some(text) => {
            for line in text.lines() {
                println!("  {line}");
            }
        }
        None => println!("  <no summary>"),
    }

    if !chunk.children.is_empty() {
        println!();
        println!("Children:");
        let mut sorted_children: Vec<&ContextChunkRow> = chunk.children.iter()
            .filter_map(|cid| chunk_map.get(cid).copied())
            .collect();
        sorted_children.sort_by_key(|c| c.start_at.unwrap_or(i128::MAX));
        for child in sorted_children {
            let range = match (child.start_at, child.end_at) {
                (Some(s), Some(e)) => format!(
                    "{}..{}  ({})",
                    format_tai_ns(s),
                    format_tai_ns(e),
                    format_duration_ns(e.saturating_sub(s))
                ),
                _ => "?..?".to_string(),
            };
            let kind = if child.children.is_empty() { "leaf" } else { "node" };
            let summary = child.summary.as_deref().unwrap_or("<no summary>");
            println!(
                "  {}  {range}  {kind}  \"{}\"",
                fmt_id(child.id),
                truncate_single_line(summary, 60)
            );
        }
    }

    Ok(())
}

fn cmd_turn(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    cli: &Cli,
    turn_offset: usize,
    full: bool,
) -> Result<()> {
    let branch_id = resolve_target_branch(repo, cli)?;
    let mut ws = pull_workspace(repo, branch_id, "pull target for turn")?;
    let space = ws.checkout(..).map_err(|e| anyhow!("checkout: {e:?}"))?;

    // Collect exec requests with timestamps
    let mut requests: Vec<(Id, i128, Option<String>)> = Vec::new();
    for (request_id, requested_at) in find!(
        (request_id: Id, requested_at: Value<valueschemas::NsTAIInterval>),
        pattern!(&space, [{
            ?request_id @
            metadata::tag: &KIND_EXEC_REQUEST_ID,
            exec::requested_at: ?requested_at,
        }])
    ) {
        requests.push((request_id, interval_key(requested_at), None));
    }
    for (request_id, handle) in find!(
        (request_id: Id, handle: TextHandle),
        pattern!(&space, [{ ?request_id @ exec::command_text: ?handle }])
    ) {
        for entry in requests.iter_mut() {
            if entry.0 == request_id {
                entry.2 = Some(read_text(&mut ws, handle)?);
                break;
            }
        }
    }
    requests.sort_by_key(|r| r.1);
    requests.reverse();

    if turn_offset == 0 || turn_offset > requests.len() {
        bail!("turn #{turn_offset} not found ({} total turns)", requests.len());
    }
    let (request_id, requested_at, command) = &requests[turn_offset - 1];
    let request_id = *request_id;
    let requested_at = *requested_at;
    let command = command.clone().unwrap_or_else(|| "<unknown>".to_string());

    let now_key = now_epoch().to_tai_duration().total_nanoseconds();

    println!("Turn #{turn_offset}");
    println!("- request: {}", fmt_id(request_id));
    println!("- requested: {} ({})", format_tai_ns(requested_at), format_age(now_key, requested_at));
    println!("- command: {}", if full { command.clone() } else { truncate_single_line(&command, 100) });

    // Find exec result for this request
    let mut result_id: Option<Id> = None;
    for (rid, about_request) in find!(
        (rid: Id, about_request: Id),
        pattern!(&space, [{
            ?rid @
            metadata::tag: &KIND_EXEC_RESULT_ID,
            exec::about_request: ?about_request,
        }])
    ) {
        if about_request == request_id {
            result_id = Some(rid);
            break;
        }
    }

    // Exec result details
    if let Some(rid) = result_id {
        let mut exit_code: Option<i64> = None;
        let mut finished_at: Option<i128> = None;
        let mut stdout_text: Option<String> = None;
        let mut stderr_text: Option<String> = None;
        let mut error_text: Option<String> = None;

        if let Some(value) = find!(
            value: Value<valueschemas::U256BE>,
            pattern!(&space, [{ rid @ exec::exit_code: ?value }])
        ).next() {
            exit_code = u256be_to_u64(value).map(|n| n as i64);
        }
        if let Some(value) = find!(
            value: Value<valueschemas::NsTAIInterval>,
            pattern!(&space, [{ rid @ exec::finished_at: ?value }])
        ).next() {
            finished_at = Some(interval_key(value));
        }
        if let Some(handle) = find!(
            handle: TextHandle,
            pattern!(&space, [{ rid @ exec::stdout_text: ?handle }])
        ).next() {
            stdout_text = Some(read_text(&mut ws, handle)?);
        }
        if let Some(handle) = find!(
            handle: TextHandle,
            pattern!(&space, [{ rid @ exec::stderr_text: ?handle }])
        ).next() {
            stderr_text = Some(read_text(&mut ws, handle)?);
        }
        if let Some(handle) = find!(
            handle: TextHandle,
            pattern!(&space, [{ rid @ exec::error: ?handle }])
        ).next() {
            error_text = Some(read_text(&mut ws, handle)?);
        }

        println!();
        println!("Exec result [{}]", fmt_id(rid));
        println!(
            "- exit: {}",
            exit_code.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string())
        );
        if let Some(at) = finished_at {
            let latency = at.saturating_sub(requested_at);
            println!("- finished: {} (latency {})", format_tai_ns(at), format_duration_ns(latency));
        }
        if let Some(ref err) = error_text {
            println!("- error: {}", if full { err.clone() } else { truncate_single_line(err, 120) });
        }
        if let Some(ref stderr) = stderr_text {
            let display = if full { stderr.clone() } else { truncate_single_line(stderr, 120) };
            if display != "<ok>" && !display.is_empty() {
                println!("- stderr: {display}");
            }
        }
        if let Some(ref stdout) = stdout_text {
            if full {
                println!("- stdout ({} chars):", stdout.len());
                for line in stdout.lines() {
                    println!("    {line}");
                }
            } else {
                println!("- stdout: {} chars \"{}\"", stdout.len(), truncate_single_line(stdout, 80));
            }
        }

        // Find thought via exec result -> about_thought
        let thought_id: Option<Id> = find!(
            tid: Id,
            pattern!(&space, [{ &rid @ exec::about_thought: ?tid }])
        ).next();

        // Find model result via: thought -> model request -> model result
        let model_result_id: Option<Id> = thought_id
            .and_then(|tid| find!(
                mreq: Id,
                pattern!(&space, [{
                    ?mreq @
                    metadata::tag: &KIND_MODEL_REQUEST_ID,
                    model_chat::about_thought: &tid,
                }])
            ).next())
            .and_then(|mreq_id| find!(
                mid: Id,
                pattern!(&space, [{
                    ?mid @
                    metadata::tag: &KIND_MODEL_RESULT_ID,
                    model_chat::about_request: &mreq_id,
                }])
            ).next());

        if let Some(mid) = model_result_id {
            let output_text: Option<String> = find!(
                handle: TextHandle,
                pattern!(&space, [{ &mid @ model_chat::output_text: ?handle }])
            ).next().map(|h| read_text(&mut ws, h)).transpose()?;

            let reasoning_text: Option<String> = find!(
                handle: TextHandle,
                pattern!(&space, [{ &mid @ model_chat::reasoning_text: ?handle }])
            ).next().map(|h| read_text(&mut ws, h)).transpose()?;

            let model_error: Option<String> = find!(
                handle: TextHandle,
                pattern!(&space, [{ &mid @ model_chat::error: ?handle }])
            ).next().map(|h| read_text(&mut ws, h)).transpose()?;

            let model_finished: Option<i128> = find!(
                value: Value<valueschemas::NsTAIInterval>,
                pattern!(&space, [{ &mid @ model_chat::finished_at: ?value }])
            ).next().map(interval_key);

            let input_tokens: Option<u64> = find!(
                value: Value<valueschemas::U256BE>,
                pattern!(&space, [{ &mid @ model_chat::input_tokens: ?value }])
            ).next().and_then(u256be_to_u64);

            let output_tokens: Option<u64> = find!(
                value: Value<valueschemas::U256BE>,
                pattern!(&space, [{ &mid @ model_chat::output_tokens: ?value }])
            ).next().and_then(u256be_to_u64);

            let cache_creation_tokens: Option<u64> = find!(
                value: Value<valueschemas::U256BE>,
                pattern!(&space, [{ &mid @ model_chat::cache_creation_input_tokens: ?value }])
            ).next().and_then(u256be_to_u64);

            let cache_read_tokens: Option<u64> = find!(
                value: Value<valueschemas::U256BE>,
                pattern!(&space, [{ &mid @ model_chat::cache_read_input_tokens: ?value }])
            ).next().and_then(u256be_to_u64);

            println!();
            println!("Model result [{}]", fmt_id(mid));
            if let Some(at) = model_finished {
                println!("- finished: {}", format_tai_ns(at));
            }
            if let Some(ref err) = model_error {
                println!("- error: {}", if full { err.clone() } else { truncate_single_line(err, 120) });
            }
            if input_tokens.is_some() || output_tokens.is_some() {
                let f = |v: Option<u64>| -> String { v.map_or("-".into(), |n| n.to_string()) };
                println!("- tokens: in={} out={} cache_create={} cache_read={}",
                    f(input_tokens), f(output_tokens),
                    f(cache_creation_tokens), f(cache_read_tokens));
            }
            if let Some(ref reasoning) = reasoning_text {
                if full {
                    println!("- reasoning ({} chars):", reasoning.len());
                    for line in reasoning.lines() {
                        println!("    {line}");
                    }
                } else {
                    println!("- reasoning: {} chars \"{}\"", reasoning.len(), truncate_single_line(reasoning, 80));
                }
            }
            if let Some(ref output) = output_text {
                if full {
                    println!("- output ({} chars):", output.len());
                    for line in output.lines() {
                        println!("    {line}");
                    }
                } else {
                    println!("- output: {} chars \"{}\"", output.len(), truncate_single_line(output, 80));
                }
            }
        } else {
            println!();
            println!("Model result: not found");
        }

        // Context summary
        if let Some(tid) = thought_id {
            let context_json: Option<String> = if let Some(handle) = find!(
                handle: TextHandle,
                pattern!(&space, [{ tid @ cog::context: ?handle }])
            ).next() {
                Some(read_text(&mut ws, handle)?)
            } else {
                None
            };
            if let Some(ref json) = context_json {
                let messages: Vec<ChatMessage> = serde_json::from_str(json)
                    .unwrap_or_default();
                let total_chars: usize = messages.iter().map(|m| m.content.len()).sum();
                println!();
                println!("Context ({} messages, {} chars)", messages.len(), total_chars);
                if full {
                    for (i, msg) in messages.iter().enumerate() {
                        println!(
                            "  #{i:<3} [{}] ({} chars)",
                            msg.role, msg.content.len()
                        );
                        for line in msg.content.lines() {
                            println!("    {line}");
                        }
                    }
                } else {
                    for (i, msg) in messages.iter().enumerate() {
                        println!(
                            "  #{i:<3} [{:<9}] ({:>5} chars) \"{}\"",
                            msg.role.to_string(),
                            msg.content.len(),
                            truncate_single_line(&msg.content, 60)
                        );
                    }
                }
            }
        }
    } else {
        println!();
        println!("Exec result: not found (turn may still be in progress)");
    }

    Ok(())
}

fn cmd_context(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    cli: &Cli,
    turn: usize,
    full: bool,
    raw: bool,
) -> Result<()> {
    let branch_id = resolve_target_branch(repo, cli)?;

    let result = load_turn_context(repo, branch_id, turn)?;
    let Some((request_id, command, messages)) = result else {
        if turn > 1 {
            bail!("turn #{turn} not found (not enough turns or no context recorded)");
        } else {
            bail!("no turn context found (no exec results with thought/context chain)");
        }
    };

    if raw {
        let json = serde_json::to_string_pretty(&messages)
            .map_err(|e| anyhow!("serialize context: {e}"))?;
        println!("{json}");
        return Ok(());
    }

    let total_chars: usize = messages.iter().map(|m| m.content.len()).sum();

    let budget = load_budget_from_config(repo)?;
    let fill_str = if let Some(ref b) = budget {
        if b.body_budget_chars > 0 {
            let pct = (total_chars as f64 / b.body_budget_chars as f64 * 100.0) as u32;
            format!("  fill={pct}%")
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    println!(
        "Context for turn #{turn} [{}] ({})",
        fmt_id(request_id),
        truncate_single_line(&command, 60)
    );
    println!("- messages: {}", messages.len());
    println!("- estimated chars: {total_chars}{fill_str}");
    println!();

    for (i, msg) in messages.iter().enumerate() {
        let role_str = format!("[{}]", msg.role);
        if full {
            println!("  #{i:<3} {role_str:<12} ({} chars)", msg.content.len());
            for line in msg.content.lines() {
                println!("    {line}");
            }
            println!();
        } else {
            println!(
                "  #{i:<3} {role_str:<12} ({:>5} chars) \"{}\"",
                msg.content.len(),
                truncate_single_line(&msg.content, 70)
            );
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let Some(command) = cli.command.as_ref() else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };

    let mut repo = open_repo(&cli.pile)?;
    let command_result = match command {
        Command::Scan {
            recent,
            loop_min,
            stale_min,
        } => cmd_scan(&mut repo, &cli, *recent, *loop_min, *stale_min),
        Command::Loops { recent, min_repeat } => cmd_loops(&mut repo, &cli, *recent, *min_repeat),
        Command::Timeline { recent } => cmd_timeline(&mut repo, &cli, *recent),
        Command::Chain => cmd_chain(&mut repo, &cli),
        Command::Turn { turn, full } => cmd_turn(&mut repo, &cli, *turn, *full),
        Command::Cover { full, tree } => cmd_cover(&mut repo, &cli, *full, *tree),
        Command::Chunk { id } => cmd_chunk(&mut repo, &cli, id.as_str()),
        Command::Context { turn, full, raw } => cmd_context(&mut repo, &cli, *turn, *full, *raw),
        Command::Repair { command } => match command {
            RepairCommand::BranchDuplicates { dry_run } => {
                cmd_repair_branch_duplicates(&mut repo, &cli, *dry_run)
            }
        },
    };
    let close_result = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
    command_result?;
    close_result?;
    Ok(())
}
