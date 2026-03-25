use ed25519_dalek::{SecretKey, SigningKey};
use eframe::egui;
use hifitime::Epoch;
use rand::rngs::OsRng;
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use triblespace::core::blob::schemas::longstring::LongString;
use triblespace::core::blob::schemas::simplearchive::SimpleArchive;
use triblespace::core::id::{ExclusiveId, Id};
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{BlobStoreMeta, Repository, Workspace};
use triblespace::core::trible::TribleSet;
use triblespace::core::value::Value;
use triblespace::core::value::schemas::hash::{Blake3, Handle};
use triblespace::core::value::schemas::time::NsTAIInterval;
use triblespace::macros::{entity, find, id_hex, pattern, pattern_changes};
use triblespace::prelude::valueschemas::{GenId, U256BE};
use triblespace::prelude::{
    Attribute, BlobStore, BlobStoreGet, BranchStore, ToBlob, ToValue, TryFromValue, TryToValue,
    View,
};

use GORBIE::NotebookConfig;
use GORBIE::NotebookCtx;
use GORBIE::cards::DEFAULT_CARD_PADDING;
use GORBIE::md;
use GORBIE::themes::colorhash;
use GORBIE::widgets::{Button, TextField};

use crate::blob_refs::{PromptChunk, split_blob_refs};
use crate::chat_prompt::{ChatMessage, ChatRole};
use crate::schema::model_chat;
use crate::schema::playground_cog;
use crate::schema::playground_config;
use crate::schema::playground_context;
use crate::schema::playground_exec;

mod archive {
    use triblespace::macros::id_hex;
    use triblespace::prelude::blobschemas::LongString;
    use triblespace::prelude::valueschemas::{Blake3, GenId, Handle, NsTAIInterval};
    use triblespace::prelude::*;

    attributes! {
        "5F10520477A04E5FB322C85CC78C6762" as pub kind: GenId;
        "838CC157FFDD37C6AC7CC5A472E43ADB" as pub author: GenId;
        "E63EE961ABDB1D1BEC0789FDAFFB9501" as pub author_name: Handle<Blake3, LongString>;
        "ACF09FF3D62B73983A222313FF0C52D2" as pub content: Handle<Blake3, LongString>;
        "0DA5DD275AA34F86B0297CC35F1B7395" as pub created_at: NsTAIInterval;
    }

    #[allow(non_upper_case_globals)]
    pub const kind_message: Id = id_hex!("1A0841C92BBDA0A26EA9A8252D6ECD9B");
}

mod teams {
    use triblespace::prelude::blobschemas::LongString;
    use triblespace::prelude::valueschemas::{Blake3, GenId, Handle};
    use triblespace::prelude::*;

    attributes! {
        "1E525B603A0060D9FA132B3D4EE9538A" as pub chat: GenId;
        "B6089037C04529F55D2A2D1A668DBE95" as pub chat_id: Handle<Blake3, LongString>;
    }
}

mod compass {
    use triblespace::prelude::blobschemas::LongString;
    use triblespace::prelude::valueschemas::{Blake3, GenId, Handle, ShortString};
    use triblespace::prelude::*;

    attributes! {
        "EE18CEC15C18438A2FAB670E2E46E00C" as pub title: Handle<Blake3, LongString>;
        "F9B56611861316B31A6C510B081C30B3" as pub created_at: ShortString;
        "5FF4941DCC3F6C35E9B3FD57216F69ED" as pub tag: ShortString;
        "9D2B6EBDA67E9BB6BE6215959D182041" as pub parent: GenId;

        "C1EAAA039DA7F486E4A54CC87D42E72C" as pub task: GenId;
        "61C44E0F8A73443ED592A713151E99A4" as pub status: ShortString;
        "8200ADEDC8D4D3D6D01CDC7396DF9AEC" as pub at: ShortString;
        "47351DF00B3DDA96CB305157CD53D781" as pub note: Handle<Blake3, LongString>;
    }
}

mod reason_events {
    use triblespace::prelude::attributes;
    use triblespace::prelude::blobschemas;
    use triblespace::prelude::valueschemas;

    attributes! {
        "B10329D5D1087D15A3DAFF7A7CC50696" as text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "FBA9BC32A457C7BFFDB7E0181D3E82A4" as created_at: valueschemas::NsTAIInterval;
        "E6B1C728F1AE9F46CAB4DBB60D1A9528" as about_turn: valueschemas::GenId;
        "721DED6DA776F2CF4FB91C54D9F82358" as worker: valueschemas::GenId;
        "514F4FE9F560FB155450462C8CF50749" as command_text: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
    }
}

type CommitHandle = Value<Handle<Blake3, SimpleArchive>>;
const ACTIVITY_TIMELINE_HEIGHT: f32 = 980.0;
const TURN_MEMORY_MAX_ROWS: usize = 160;
const TIMELINE_DEFAULT_LIMIT: usize = 300;
const TIMELINE_LIMIT_PRESETS: [usize; 4] = [100, 300, 1000, 3000];
const TIMELINE_LIMIT_MIN: usize = 10;
const TIMELINE_LIMIT_MAX: usize = 50_000;
const CONTEXT_TREE_HEIGHT: f32 = 720.0;
const CONTEXT_ORIGIN_LIMIT: usize = 64;
const LOCAL_COMPOSE_HEIGHT: f32 = 80.0;
const RELATIONS_SCROLL_HEIGHT: f32 = 260.0;
const TEAMS_SCROLL_HEIGHT: f32 = 520.0;
const TEAMS_CHAT_LIST_WIDTH: f32 = 220.0;
const SNAPSHOT_REFRESH_MS: u64 = 1000;

static DIAGNOSTICS_PILE_OVERRIDE: OnceLock<Option<PathBuf>> = OnceLock::new();
static DIAGNOSTICS_HEADLESS: AtomicBool = AtomicBool::new(false);

pub fn set_default_pile(path: Option<PathBuf>) {
    let _ = DIAGNOSTICS_PILE_OVERRIDE.set(path);
}

fn diagnostics_default_pile() -> Option<PathBuf> {
    DIAGNOSTICS_PILE_OVERRIDE
        .get()
        .and_then(|path| path.as_ref().cloned())
}

fn diagnostics_is_headless() -> bool {
    DIAGNOSTICS_HEADLESS.load(Ordering::Relaxed)
}

const LOCAL_KIND_MESSAGE_ID: Id = id_hex!("A3556A66B00276797FCE8A2742AB850F");
const LOCAL_KIND_READ_ID: Id = id_hex!("B663C15BB6F2BF591EA870386DD48537");
const RELATIONS_KIND_PERSON_ID: Id = id_hex!("D8ADDE47121F4E7868017463EC860726");
const COMPASS_KIND_GOAL_ID: Id = id_hex!("83476541420F46402A6A9911F46FBA3B");
const COMPASS_KIND_STATUS_ID: Id = id_hex!("89602B3277495F4E214D4A417C8CF260");
const COMPASS_KIND_NOTE_ID: Id = id_hex!("D4E49A6F02A14E66B62076AE4C01715F");
const REASON_KIND_EVENT_ID: Id = id_hex!("9D43BB36D8B4A6275CAF38A1D5DACF36");

const COMPASS_DEFAULT_STATUSES: [&str; 4] = ["todo", "doing", "blocked", "done"];

const LOCAL_KIND_SPECS: [(Id, &str); 2] = [
    (LOCAL_KIND_MESSAGE_ID, "local_message"),
    (LOCAL_KIND_READ_ID, "local_read"),
];

mod local_messages {
    use triblespace::prelude::attributes;
    use triblespace::prelude::blobschemas;
    use triblespace::prelude::valueschemas;

    attributes! {
        "42C4DB210F7EAFAF38F179ADCB4A9D5B" as from: valueschemas::GenId;
        "95D58D3E68A43979F8AA51415541414C" as to: valueschemas::GenId;
        "23075866B369B5F393D43B30649469F6" as body: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "53ECCC7489AF8D30EF385ED12073F4A3" as created_at: valueschemas::NsTAIInterval;

        "2213B191326E9B99605FA094E516E50E" as about_message: valueschemas::GenId;
        "99E92F483731FA6D59115A8D6D187A37" as reader: valueschemas::GenId;
        "934C5AD3DA8F7A2EB467460E50D17A4F" as read_at: valueschemas::NsTAIInterval;
    }
}

mod relations {
    use triblespace::prelude::attributes;
    use triblespace::prelude::blobschemas;
    use triblespace::prelude::valueschemas;

    attributes! {
        "8F162B593D390E1424394DBF6883A72C" as alias: valueschemas::ShortString;
        "32B22FBA3EC2ADC3FFEB48483FE8961F" as affinity: valueschemas::ShortString;
        "9B3329149D54CB9A8E8075E4AA862649" as teams_user_id: valueschemas::ShortString;
        "B563A063474CBE62ED25A8D0E9A1853C" as email: valueschemas::ShortString;
        "DC0916CB5F640984EFE359A33105CA9A" as display_name: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "F0AD0BBFAC4C4C899637573DC965622E" as first_name: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "764DD765142B3F4725B614BD3B9118EC" as last_name: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
    }
}

#[derive(Clone, Debug)]
struct DashboardConfig {
    pile_path: String,
    config_branches: String,
    exec_branches: String,
    compass_branches: String,
    local_message_branches: String,
    relations_branches: String,
    local_me: String,
    local_peer: String,
    teams_branches: String,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        let default_pile = diagnostics_default_pile().unwrap_or_else(|| {
            let repo_root = repo_root();
            repo_root.join("self.pile")
        });
        Self {
            pile_path: default_pile.to_string_lossy().to_string(),
            config_branches: "config".to_string(),
            exec_branches: "main".to_string(),
            compass_branches: "compass".to_string(),
            local_message_branches: "local-messages".to_string(),
            relations_branches: "relations".to_string(),
            local_me: "jp".to_string(),
            local_peer: "agent".to_string(),
            teams_branches: "teams".to_string(),
        }
    }
}

struct DashboardState {
    config: DashboardConfig,
    repo: Option<Repository<Pile>>,
    repo_open_path: Option<PathBuf>,
    signing_key: SigningKey,
    snapshot: Option<Result<DashboardSnapshot, String>>,
    show_extra_branches: bool,
    local_draft: String,
    local_send_error: Option<String>,
    local_send_notice: Option<String>,
    config_reveal_secrets: bool,
    config_last_applied_id: Option<Id>,
    compass_expanded_goal: Option<Id>,
    teams_selected_chat: Option<Id>,
    context_selected_chunk: Option<Id>,
    context_float_request_id: Option<Id>,
    context_selection_stack: Vec<Id>,
    context_show_children: bool,
    context_show_origins: bool,
    timeline_limit: usize,
    last_snapshot_refresh_at: Option<Instant>,
}

impl Drop for DashboardState {
    fn drop(&mut self) {
        if let Some(repo) = self.repo.take() {
            let pile = repo.into_storage();
            if let Err(err) = pile.close() {
                eprintln!("warning: failed to close pile cleanly: {err:?}");
            }
        }
    }
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            config: DashboardConfig::default(),
            repo: None,
            repo_open_path: None,
            signing_key: random_signing_key(),
            snapshot: None,
            show_extra_branches: false,
            local_draft: String::new(),
            local_send_error: None,
            local_send_notice: None,
            config_reveal_secrets: false,
            config_last_applied_id: None,
            compass_expanded_goal: None,
            teams_selected_chat: None,
            context_selected_chunk: None,
            context_float_request_id: None,
            context_selection_stack: Vec::new(),
            context_show_children: false,
            context_show_origins: false,
            timeline_limit: TIMELINE_DEFAULT_LIMIT,
            last_snapshot_refresh_at: None,
        }
    }
}

#[derive(Debug, Clone)]
struct BranchEntry {
    id: Id,
    name: Option<String>,
    head_timestamp: Option<u64>,
}

#[derive(Debug, Clone)]
struct ExecRow {
    request_id: Id,
    command: String,
    status: ExecStatus,
    requested_at: Option<i128>,
    started_at: Option<i128>,
    finished_at: Option<i128>,
    exit_code: Option<u64>,
    worker: Option<Id>,
    stdout_text: Option<String>,
    stderr_text: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecStatus {
    Pending,
    Running,
    Done,
    Failed,
}

#[derive(Debug, Clone)]
struct LocalMessageRow {
    id: Id,
    created_at: Option<i128>,
    from_id: Id,
    to_id: Id,
    body: String,
    readers: Vec<Id>,
}

#[derive(Debug, Clone)]
enum LocalMessageStatus {
    Unread,
    Read,
    Sent,
    ReadBy(String),
    Other,
}

#[derive(Debug, Clone)]
struct TeamsMessageRow {
    chat_id: Id,
    created_at: Option<i128>,
    author_name: Option<String>,
    content: String,
}

#[derive(Debug, Clone)]
struct TeamsChatRow {
    id: Id,
    label: String,
    last_at: Option<i128>,
    message_count: usize,
}

#[derive(Debug, Clone)]
struct ReasoningSummaryRow {
    result_id: Id,
    created_at: Option<i128>,
    summary: String,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cache_creation_input_tokens: Option<u64>,
    cache_read_input_tokens: Option<u64>,
}

#[derive(Debug, Clone)]
struct ReasonRow {
    id: Id,
    created_at: Option<i128>,
    text: String,
    turn_id: Option<Id>,
    worker_id: Option<Id>,
    command_text: Option<String>,
}

#[derive(Debug, Clone)]
struct TurnMemoryRow {
    request_id: Id,
    command: String,
    requested_at: Option<i128>,
    thought_id: Option<Id>,
    context_messages: Vec<ChatMessage>,
    context_error: Option<String>,
}

#[derive(Debug, Clone)]
struct ContextChunkRow {
    id: Id,
    summary: Value<Handle<Blake3, LongString>>,
    start_at: Option<i128>,
    end_at: Option<i128>,
    children: Vec<Id>,
    about_exec_result: Option<Id>,
}

#[derive(Debug, Clone)]
struct ContextLeafOriginRow {
    chunk_id: Id,
    exec_result_id: Option<Id>,
    end_at: Option<i128>,
    summary: Option<String>,
}

#[derive(Debug, Clone)]
struct ContextSelectedRow {
    chunk_id: Id,
    summary: Option<String>,
    children: Vec<ContextChildRow>,
    origins_total: usize,
    origins: Vec<ContextLeafOriginRow>,
}

#[derive(Debug, Clone)]
struct ContextChildRow {
    index: usize,
    chunk_id: Id,
    summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimelineSource {
    Shell,
    Cognition,
    Teams,
    LocalMessages,
    Goals,
}

#[derive(Debug, Clone)]
enum TimelineEvent {
    Shell {
        request_id: Id,
        status: ExecStatus,
        command: String,
        worker_label: Option<String>,
        exit_code: Option<u64>,
        stdout_text: Option<String>,
        stderr_text: Option<String>,
        error: Option<String>,
    },
    Cognition {
        summary: String,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cache_creation_input_tokens: Option<u64>,
        cache_read_input_tokens: Option<u64>,
    },
    Reason {
        text: String,
        turn_id: Option<Id>,
        worker_label: Option<String>,
        command_text: Option<String>,
    },
    Teams {
        author: String,
        chat_label: String,
        content: String,
    },
    LocalMessage {
        from_id: Id,
        to_id: Id,
        from_label: String,
        to_label: String,
        status: LocalMessageStatus,
        body: String,
        is_sender: bool,
    },
    GoalCreated {
        goal: CompassTaskRow,
    },
    GoalStatus {
        goal: CompassTaskRow,
        to_status: String,
    },
    GoalNote {
        goal: CompassTaskRow,
        note: String,
    },
}

#[derive(Debug, Clone)]
struct TimelineRow {
    at: Option<i128>,
    source: TimelineSource,
    event: TimelineEvent,
}

#[derive(Debug, Clone)]
struct CompassTaskRow {
    id: Id,
    id_prefix: String,
    title: String,
    tags: Vec<String>,
    created_at: String,
    status: String,
    status_at: Option<String>,
    note_count: usize,
    parent: Option<Id>,
}

impl CompassTaskRow {
    fn sort_key(&self) -> &str {
        self.status_at.as_deref().unwrap_or(&self.created_at)
    }
}

#[derive(Debug, Clone)]
struct CompassNoteRow {
    at: String,
    body: String,
}

#[derive(Debug, Clone)]
struct CompassStatusRow {
    task: Id,
    status: String,
    at: String,
}

#[derive(Debug, Clone)]
struct RelationRow {
    id: Id,
    label: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    display_name: Option<String>,
    affinity: Option<String>,
    teams_user_id: Option<String>,
    email: Option<String>,
    note: Option<String>,
    aliases: Vec<String>,
}

#[derive(Debug, Clone)]
struct AgentConfigRow {
    id: Id,
    updated_at: Option<i128>,
    persona_id: Option<Id>,
    branch: Option<String>,
    author: Option<String>,
    author_role: Option<String>,
    poll_ms: Option<u64>,
    model_profile_id: Option<Id>,
    model_profile_name: Option<String>,
    model_name: Option<String>,
    model_base_url: Option<String>,
    model_reasoning_effort: Option<String>,
    model_stream: Option<bool>,
    model_context_window_tokens: Option<u64>,
    model_max_output_tokens: Option<u64>,
    model_context_safety_margin_tokens: Option<u64>,
    model_chars_per_token: Option<u64>,
    model_api_key: Option<String>,
    tavily_api_key: Option<String>,
    exa_api_key: Option<String>,
    exec_default_cwd: Option<String>,
    exec_sandbox_profile: Option<Id>,
    system_prompt: Option<String>,
}

#[derive(Debug, Clone)]
struct DashboardSnapshot {
    pile_path: PathBuf,
    branches: Vec<BranchEntry>,
    branch_data: HashMap<Id, BranchSnapshot>,
    exec_error: Option<String>,
    agent_config: Option<AgentConfigRow>,
    agent_config_error: Option<String>,
    context_chunks: Vec<ContextChunkRow>,
    context_selected: Option<ContextSelectedRow>,
    exec_rows: Vec<ExecRow>,
    reasoning_summaries: Vec<ReasoningSummaryRow>,
    reason_rows: Vec<ReasonRow>,
    turn_memory_rows: Vec<TurnMemoryRow>,
    local_message_rows: Vec<LocalMessageRow>,
    compass_status_rows: Vec<CompassStatusRow>,
    timeline_rows: Vec<TimelineRow>,
    timeline_total_rows: usize,
    compass_rows: Vec<(CompassTaskRow, usize)>,
    compass_notes: HashMap<Id, Vec<CompassNoteRow>>,
    compass_error: Option<String>,
    local_message_error: Option<String>,
    local_me_id: Option<Id>,
    local_peer_id: Option<Id>,
    relations_people: Vec<RelationRow>,
    relations_error: Option<String>,
    relations_labels: HashMap<Id, String>,
    teams_messages: Vec<TeamsMessageRow>,
    teams_chats: Vec<TeamsChatRow>,
    teams_error: Option<String>,
    labels: HashMap<Id, String>,
    now_key: i128,
}

#[derive(Debug, Clone)]
struct BranchSnapshot {
    head: Option<CommitHandle>,
    data: TribleSet,
    delta: TribleSet,
}

fn diagnostics_ui(nb: &mut NotebookCtx) {
    let padding = DEFAULT_CARD_PADDING;
    let dashboard = nb.state(
        "playground-diagnostics",
        DashboardState::default(),
        move |ui, state| {
            ui.with_padding(padding, |ui| {
                md!(
                    ui,
                    "# Playground Diagnostics\n\
_Live view of the agent pile, exec queue, and message activity._"
                );

                ui.separator();
                ui.heading("Config");
                ui.horizontal(|ui| {
                    ui.label("Pile");
                    ui.add(TextField::singleline(&mut state.config.pile_path));
                });
                let mut picker_branches = Vec::new();
                let repo_open_result = ensure_repo_open(state);
                if repo_open_result.is_ok() {
                    if let Some(repo) = state.repo.as_mut() {
                        picker_branches = list_branches(repo.storage_mut()).unwrap_or_default();
                        picker_branches
                            .sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
                    }
                }
                ui.horizontal(|ui| {
                    ui.label("Config branches");
                    render_branch_picker(
                        ui,
                        "config_branch_picker",
                        &picker_branches,
                        &mut state.config.config_branches,
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Exec branches");
                    render_branch_picker(
                        ui,
                        "exec_branch_picker",
                        &picker_branches,
                        &mut state.config.exec_branches,
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Compass branches");
                    render_branch_picker(
                        ui,
                        "compass_branch_picker",
                        &picker_branches,
                        &mut state.config.compass_branches,
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Local message branches");
                    render_branch_picker(
                        ui,
                        "local_message_branch_picker",
                        &picker_branches,
                        &mut state.config.local_message_branches,
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Relations branches");
                    render_branch_picker(
                        ui,
                        "relations_branch_picker",
                        &picker_branches,
                        &mut state.config.relations_branches,
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Teams branches");
                    render_branch_picker(
                        ui,
                        "teams_branch_picker",
                        &picker_branches,
                        &mut state.config.teams_branches,
                    );
                });

                if let Err(err) = repo_open_result {
                    state.snapshot = Some(Err(err.to_string()));
                } else {
                    if should_refresh_snapshot(&state) {
                        refresh_snapshot(state);
                        state.last_snapshot_refresh_at = Some(Instant::now());
                    }
                }
                if diagnostics_is_headless() {
                    // In headless capture we only need one snapshot.
                } else {
                    ui.ctx()
                        .request_repaint_after(Duration::from_millis(SNAPSHOT_REFRESH_MS));
                }
            });
        },
    );

    // ── Card 2: Main view (Activity timeline + context float) ──────
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);
        ui.with_padding(padding, |ui| {
            ui.heading("Activity timeline");
            let mut timeline_limit_changed = false;
            ui.horizontal_wrapped(|ui| {
                ui.small("Recent events:");
                for preset in TIMELINE_LIMIT_PRESETS {
                    let selected = state.timeline_limit == preset;
                    let label = if selected {
                        format!("[{preset}]")
                    } else {
                        preset.to_string()
                    };
                    if ui.add(Button::new(label)).clicked() && !selected {
                        state.timeline_limit = preset;
                        timeline_limit_changed = true;
                    }
                }
                ui.small("custom");
                let mut custom_limit = state.timeline_limit as u64;
                if ui
                    .add(
                        egui::DragValue::new(&mut custom_limit)
                            .range(TIMELINE_LIMIT_MIN as u64..=TIMELINE_LIMIT_MAX as u64),
                    )
                    .changed()
                {
                    state.timeline_limit = custom_limit as usize;
                    timeline_limit_changed = true;
                }
            });
            if timeline_limit_changed {
                refresh_snapshot(&mut state);
                state.last_snapshot_refresh_at = Some(Instant::now());
            }

            let snapshot = {
                let Some(snapshot) = snapshot_or_message(ui, &state.snapshot) else {
                    return;
                };
                snapshot.clone()
            };

            if snapshot.timeline_rows.is_empty() {
                ui.small("No activity yet.");
            } else if snapshot.timeline_rows.len() < snapshot.timeline_total_rows {
                ui.small(format!(
                    "Showing latest {} of {} events.",
                    snapshot.timeline_rows.len(),
                    snapshot.timeline_total_rows
                ));
            } else {
                ui.small(format!("{} events.", snapshot.timeline_total_rows));
            }

            if let Some(err) = &snapshot.exec_error {
                ui.colored_label(egui::Color32::RED, format!("Exec branch: {err}"));
            }
            if snapshot.timeline_rows.is_empty() {
                ui.label("No activity yet.");
                return;
            }
            if let Some(request_id) = render_activity_timeline(ui, snapshot.now_key, &snapshot.timeline_rows) {
                state.context_float_request_id = Some(request_id);
            }

            // Render context float if one is open.
            if let Some(request_id) = state.context_float_request_id {
                if let Some(row) = snapshot.turn_memory_rows.iter().find(|r| r.request_id == request_id) {
                    let row = row.clone();
                    ui.push_id(request_id, |ui| {
                        let resp = ui.float(|ui| {
                            ui.heading(&format!("Context · turn {}", id_prefix(request_id)));
                            if row.context_messages.is_empty() {
                                if let Some(err) = row.context_error.as_deref() {
                                    ui.colored_label(egui::Color32::LIGHT_RED, err);
                                } else {
                                    ui.label("No context messages.");
                                }
                            } else {
                                ui.label(&format!("{} messages", row.context_messages.len()));
                                for (idx, message) in row.context_messages.iter().enumerate() {
                                    let (label, fill) = turn_memory_role_style(message.role);
                                    let chars = message.content.chars().count();
                                    ui.horizontal_wrapped(|ui| {
                                        render_timeline_source_chip(ui, label, fill);
                                        ui.small(format!("msg {idx} · {chars}c"));
                                    });
                                    egui::Frame::NONE
                                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_gray(190)))
                                        .inner_margin(egui::Margin::symmetric(8, 6))
                                        .show(ui, |ui| {
                                            render_blob_aware_text(ui, message.content.as_str(), None, None);
                                        });
                                    ui.add_space(4.0);
                                }
                            }
                        });
                        if resp.closed {
                            state.context_float_request_id = None;
                        }
                    });
                }
            }
        });
    });

    // ── Overview ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);
        ui.section("Overview", |ui| {
            let (pile_path, branches) = {
                let Some(snapshot) = snapshot_or_message(ui, &state.snapshot) else {
                    return;
                };
                (snapshot.pile_path.clone(), snapshot.branches.clone())
            };

            ui.horizontal(|ui| {
                ui.label(format!("Pile: {}", pile_path.display()));
            });

            if branches.is_empty() {
                return;
            }

            let mut primary: Vec<BranchEntry> = Vec::new();
            let mut extra: Vec<BranchEntry> = Vec::new();
            for branch in branches {
                let label = branch.name.as_deref().unwrap_or("<unnamed>");
                if label.contains("--orphan-") || label.starts_with('<') {
                    extra.push(branch);
                } else {
                    primary.push(branch);
                }
            }

            ui.label(format!(
                "Branches: {} primary, {} extra",
                primary.len(),
                extra.len()
            ));

            ui.label("Primary:");
            for branch in &primary {
                let label = branch.name.as_deref().unwrap_or("<unnamed>");
                ui.label(format!("- {label} ({})", id_prefix(branch.id)));
            }

            if !extra.is_empty() {
                let button_label = if state.show_extra_branches {
                    "Hide extra branches"
                } else {
                    "Show extra branches"
                };
                if ui.add(Button::new(button_label)).clicked() {
                    state.show_extra_branches = !state.show_extra_branches;
                }

                if state.show_extra_branches {
                    ui.add_space(8.0);
                    ui.label("Extra:");
                    for branch in &extra {
                        let label = branch.name.as_deref().unwrap_or("<unnamed>");
                        ui.label(format!("- {label} ({})", id_prefix(branch.id)));
                    }
                }
            }
        });
    });

    // ── Agent Config ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);
        ui.section("Agent Config", |ui| {
            let snapshot = {
                let Some(snapshot) = snapshot_or_message(ui, &state.snapshot) else {
                    return;
                };
                snapshot.clone()
            };
            if let Some(err) = &snapshot.agent_config_error {
                ui.colored_label(egui::Color32::RED, err);
            } else {
                render_agent_config(
                    ui,
                    &mut state,
                    snapshot.now_key,
                    snapshot.agent_config.as_ref(),
                );
            }
        });
    });

    // ── Context Compaction ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);
        ui.section("Context Compaction", |ui| {
            let snapshot = {
                let Some(snapshot) = snapshot_or_message(ui, &state.snapshot) else {
                    return;
                };
                snapshot.clone()
            };
            if snapshot.context_chunks.is_empty() {
                ui.label("No context chunks yet.");
                return;
            }
            render_context_compaction(
                ui,
                &mut state,
                snapshot.now_key,
                &snapshot.context_chunks,
                snapshot.context_selected.as_ref(),
            );
        });
    });

    // ── Compass ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);
        ui.section("Compass", |ui| {
            let snapshot = {
                let Some(snapshot) = snapshot_or_message(ui, &state.snapshot) else {
                    return;
                };
                snapshot.clone()
            };
            if let Some(err) = &snapshot.compass_error {
                ui.colored_label(egui::Color32::RED, err);
                return;
            }

            if snapshot.compass_rows.is_empty() {
                ui.label("No goals yet.");
                return;
            }
            render_compass_swimlanes(
                ui,
                &mut state.compass_expanded_goal,
                &snapshot.compass_rows,
                &snapshot.compass_notes,
            );
        });
    });

    // ── Messages ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);
        ui.section("Messages", |ui| {
            let snapshot = {
                let Some(snapshot) = snapshot_or_message(ui, &state.snapshot) else {
                    return;
                };
                snapshot.clone()
            };
            if let Some(err) = &snapshot.local_message_error {
                ui.colored_label(egui::Color32::RED, err);
            }
            render_local_composer(ui, &mut state, &snapshot.branches, &snapshot);
        });
    });

    // ── Relations ─
    nb.view(move |ui| {
        let state = dashboard.read_mut(ui);
        ui.section("Relations", |ui| {
            let Some(snapshot) = snapshot_or_message(ui, &state.snapshot) else {
                return;
            };
            if let Some(err) = &snapshot.relations_error {
                ui.colored_label(egui::Color32::RED, err);
            } else {
                render_relations(ui, &snapshot.relations_people);
            }
        });
    });

    // ── Teams ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);
        ui.section("Teams", |ui| {
            let snapshot = {
                let Some(snapshot) = snapshot_or_message(ui, &state.snapshot) else {
                    return;
                };
                snapshot.clone()
            };
            if let Some(err) = &snapshot.teams_error {
                ui.colored_label(egui::Color32::RED, err);
            } else {
                render_teams_conversations(
                    ui,
                    &mut state,
                    snapshot.now_key,
                    &snapshot.teams_chats,
                    &snapshot.teams_messages,
                );
            }
        });
    });

}

pub fn run_diagnostics(
    headless: bool,
    out_dir: Option<PathBuf>,
    scale: Option<f32>,
    headless_wait_ms: Option<u64>,
) -> anyhow::Result<()> {
    DIAGNOSTICS_HEADLESS.store(headless, Ordering::Relaxed);

    let mut cfg = NotebookConfig::new("Playground Diagnostics");
    if headless {
        let out_dir = out_dir.unwrap_or_else(|| PathBuf::from("gorbie_capture"));
        cfg = if let Some(scale) = scale {
            cfg.with_headless_capture_scaled(out_dir, scale)
        } else {
            cfg.with_headless_capture(out_dir)
        };
        if let Some(wait_ms) = headless_wait_ms {
            cfg = cfg.with_headless_settle_timeout(Duration::from_millis(wait_ms));
        }
    }

    cfg.run(|nb| diagnostics_ui(nb))
        .map_err(|err| anyhow::anyhow!("diagnostics failed: {err:?}"))?;
    Ok(())
}

fn snapshot_or_message<'a>(
    ui: &mut egui::Ui,
    snapshot: &'a Option<Result<DashboardSnapshot, String>>,
) -> Option<&'a DashboardSnapshot> {
    match snapshot {
        None => {
            ui.label("No snapshot yet.");
            None
        }
        Some(Err(err)) => {
            ui.colored_label(egui::Color32::RED, err);
            None
        }
        Some(Ok(snapshot)) => Some(snapshot),
    }
}

fn ensure_repo_open(state: &mut DashboardState) -> Result<(), String> {
    let open_path = PathBuf::from(state.config.pile_path.trim());
    let path_changed = state
        .repo_open_path
        .as_ref()
        .map_or(true, |path| path != &open_path);
    if path_changed || state.repo.is_none() {
        if let Some(repo) = state.repo.take() {
            let pile = repo.into_storage();
            if let Err(err) = pile.close() {
                eprintln!("warning: failed to close pile cleanly: {err:?}");
            }
        }
        let mut pile = Pile::open(&open_path).map_err(|err| err.to_string())?;
        if let Err(err) = pile.restore() {
            if let Err(close_err) = pile.close() {
                eprintln!("warning: failed to close pile cleanly: {close_err:?}");
            }
            return Err(err.to_string());
        }
        let repo = Repository::new(pile, state.signing_key.clone(), TribleSet::new())
            .map_err(|err| format!("create repository: {err:?}"))?;
        state.repo = Some(repo);
        state.repo_open_path = Some(open_path);
    }
    Ok(())
}

fn refresh_snapshot(state: &mut DashboardState) {
    let previous = state
        .snapshot
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .cloned();
    let config = state.config.clone();
    let context_selected = state.context_selected_chunk;
    let context_show_children = state.context_show_children;
    let context_show_origins = state.context_show_origins;
    let timeline_limit = state.timeline_limit;
    let repo = match state.repo.as_mut() {
        Some(repo) => repo,
        None => {
            state.snapshot = Some(Err("Repository not open.".to_string()));
            return;
        }
    };
    let result = load_snapshot(
        repo,
        &config,
        previous,
        context_selected,
        context_show_children,
        context_show_origins,
        timeline_limit,
    );
    if let Ok(snapshot) = &result {
        if let Some(agent_config) = snapshot.agent_config.as_ref() {
            apply_branch_defaults_from_agent_config(state, agent_config);
        }
    }
    state.snapshot = Some(result);
}

fn should_refresh_snapshot(state: &DashboardState) -> bool {
    if diagnostics_is_headless() {
        return true;
    }
    match state.last_snapshot_refresh_at {
        None => true,
        Some(last) => last.elapsed() >= Duration::from_millis(SNAPSHOT_REFRESH_MS),
    }
}

fn apply_branch_defaults_from_agent_config(state: &mut DashboardState, config: &AgentConfigRow) {
    if state.config_last_applied_id == Some(config.id) {
        return;
    }

    // Use well-known branch names as defaults for diagnostics selectors.
    if let Some(branch) = config.branch.as_deref() {
        state.config.exec_branches = branch.to_string();
    }
    if state.config.compass_branches.is_empty() {
        state.config.compass_branches = "compass".to_string();
    }
    if state.config.local_message_branches.is_empty() {
        state.config.local_message_branches = "local-messages".to_string();
    }
    if state.config.relations_branches.is_empty() {
        state.config.relations_branches = "relations".to_string();
    }
    if state.config.teams_branches.is_empty() {
        state.config.teams_branches = "teams".to_string();
    }

    state.config_last_applied_id = Some(config.id);
}

fn load_snapshot(
    repo: &mut Repository<Pile>,
    config: &DashboardConfig,
    previous: Option<DashboardSnapshot>,
    context_selected_chunk: Option<Id>,
    context_show_children: bool,
    context_show_origins: bool,
    timeline_limit: usize,
) -> Result<DashboardSnapshot, String> {
    let pile_path = PathBuf::from(&config.pile_path);
    let previous_for_reuse = previous
        .as_ref()
        .filter(|snapshot| snapshot.pile_path == pile_path);

    // Auto-create well-known branches so the dashboard never errors on a missing name.
    for name in [
        "config",
        "cognition",
        "compass",
        "local-messages",
        "relations",
        "teams",
        "archive",
        "web",
        "media",
    ] {
        let _ = repo.ensure_branch(name, None);
    }

    let branches = list_branches(repo.storage_mut())?;
    let mut previous_map = previous_for_reuse
        .map(|snapshot| snapshot.branch_data.clone())
        .unwrap_or_default();

    let config_refs = parse_branch_list(&config.config_branches);
    let exec_refs = parse_branch_list(&config.exec_branches);
    let compass_refs = parse_branch_list(&config.compass_branches);
    let local_refs = parse_branch_list(&config.local_message_branches);
    let relations_refs = parse_branch_list(&config.relations_branches);
    let teams_refs = parse_branch_list(&config.teams_branches);

    let branch_lookup = BranchLookup::new(&branches);
    let config_res = resolve_branch_ids(&branch_lookup, &config_refs);
    let exec_res = resolve_branch_ids(&branch_lookup, &exec_refs);
    let compass_res = resolve_branch_ids(&branch_lookup, &compass_refs);
    let local_res = resolve_branch_ids(&branch_lookup, &local_refs);
    let relations_res = resolve_branch_ids(&branch_lookup, &relations_refs);
    let teams_res = resolve_branch_ids(&branch_lookup, &teams_refs);

    let agent_config_error = config_res.as_ref().err().cloned();
    let exec_error = exec_res.as_ref().err().cloned();
    let compass_error = compass_res.as_ref().err().cloned();
    let local_message_error = local_res.as_ref().err().cloned();
    let relations_error = relations_res.as_ref().err().cloned();
    let teams_error = teams_res.as_ref().err().cloned();

    let config_ids = config_res.unwrap_or_default();
    let exec_ids = exec_res.unwrap_or_default();
    let compass_ids = compass_res.unwrap_or_default();
    let local_ids = local_res.unwrap_or_default();
    let relations_ids = relations_res.unwrap_or_default();
    let teams_ids = teams_res.unwrap_or_default();

    let mut needed_ids: Vec<Id> = Vec::new();
    extend_unique(&mut needed_ids, &config_ids);
    extend_unique(&mut needed_ids, &exec_ids);
    extend_unique(&mut needed_ids, &compass_ids);
    extend_unique(&mut needed_ids, &local_ids);
    extend_unique(&mut needed_ids, &relations_ids);
    extend_unique(&mut needed_ids, &teams_ids);

    let mut branch_data: HashMap<Id, BranchSnapshot> = HashMap::new();
    let mut reader_ws: Option<Workspace<Pile>> = None;

    for branch_id in &needed_ids {
        let snapshot = load_branch_snapshot(repo, *branch_id, previous_map.remove(branch_id))?;
        if reader_ws.is_none() {
            reader_ws = Some(
                repo.pull(*branch_id)
                    .map_err(|err| format!("pull branch: {err:?}"))?,
            );
        }
        branch_data.insert(*branch_id, snapshot);
    }

    let config_data = union_branches(&branch_data, &config_ids);
    let exec_data = union_branches(&branch_data, &exec_ids);
    let compass_data = union_branches(&branch_data, &compass_ids);
    let local_data = union_branches(&branch_data, &local_ids);
    let relations_data = union_branches(&branch_data, &relations_ids);
    let teams_data = union_branches(&branch_data, &teams_ids);
    let config_delta = union_branch_deltas(&branch_data, &config_ids);
    let exec_delta = union_branch_deltas(&branch_data, &exec_ids);
    let compass_delta = union_branch_deltas(&branch_data, &compass_ids);
    let local_delta = union_branch_deltas(&branch_data, &local_ids);
    let relations_delta = union_branch_deltas(&branch_data, &relations_ids);
    let teams_delta = union_branch_deltas(&branch_data, &teams_ids);

    let mut reader_ws = if let Some(ws) = reader_ws {
        ws
    } else {
        let now_key = epoch_key(now_epoch());
        return Ok(DashboardSnapshot {
            pile_path,
            branches,
            branch_data,
            exec_error,
            agent_config: None,
            agent_config_error,
            context_chunks: Vec::new(),
            context_selected: None,
            exec_rows: Vec::new(),
            reasoning_summaries: Vec::new(),
            reason_rows: Vec::new(),
            turn_memory_rows: Vec::new(),
            local_message_rows: Vec::new(),
            compass_status_rows: Vec::new(),
            timeline_rows: Vec::new(),
            timeline_total_rows: 0,
            compass_rows: Vec::new(),
            compass_notes: HashMap::new(),
            compass_error,
            local_message_error,
            local_me_id: None,
            local_peer_id: None,
            relations_people: Vec::new(),
            relations_error,
            relations_labels: HashMap::new(),
            teams_messages: Vec::new(),
            teams_chats: Vec::new(),
            teams_error,
            labels: HashMap::new(),
            now_key,
        });
    };

    Ok(build_snapshot(
        config_data,
        exec_data,
        compass_data,
        local_data,
        relations_data,
        teams_data,
        pile_path,
        branches,
        branch_data,
        agent_config_error,
        exec_error,
        compass_error,
        local_message_error,
        relations_error,
        teams_error,
        config,
        &mut reader_ws,
        previous_for_reuse,
        &config_delta,
        &exec_delta,
        &compass_delta,
        &local_delta,
        &relations_delta,
        &teams_delta,
        context_selected_chunk,
        context_show_children,
        context_show_origins,
        timeline_limit,
    ))
}

fn build_snapshot(
    config_data: TribleSet,
    exec_data: TribleSet,
    compass_data: TribleSet,
    local_data: TribleSet,
    relations_data: TribleSet,
    teams_data: TribleSet,
    pile_path: PathBuf,
    branches: Vec<BranchEntry>,
    branch_data: HashMap<Id, BranchSnapshot>,
    agent_config_error: Option<String>,
    exec_error: Option<String>,
    compass_error: Option<String>,
    local_message_error: Option<String>,
    relations_error: Option<String>,
    teams_error: Option<String>,
    config: &DashboardConfig,
    ws: &mut Workspace<Pile>,
    previous: Option<&DashboardSnapshot>,
    config_delta: &TribleSet,
    exec_delta: &TribleSet,
    compass_delta: &TribleSet,
    local_delta: &TribleSet,
    relations_delta: &TribleSet,
    teams_delta: &TribleSet,
    context_selected_chunk: Option<Id>,
    context_show_children: bool,
    context_show_origins: bool,
    timeline_limit: usize,
) -> DashboardSnapshot {
    let now_key = epoch_key(now_epoch());
    let (relations_people, relations_labels) = if relations_delta.is_empty() {
        if let Some(previous) = previous {
            (
                previous.relations_people.clone(),
                previous.relations_labels.clone(),
            )
        } else {
            let rows = collect_relations_people(&relations_data, ws);
            let labels = collect_relations_labels(&rows);
            (rows, labels)
        }
    } else {
        let rows = collect_relations_people(&relations_data, ws);
        let labels = collect_relations_labels(&rows);
        (rows, labels)
    };
    let local_me_id = resolve_person_ref(&relations_people, &config.local_me);
    let local_peer_id = resolve_person_ref(&relations_people, &config.local_peer);
    let agent_config = if config_delta.is_empty() {
        previous.and_then(|snapshot| snapshot.agent_config.clone())
    } else {
        collect_agent_config(&config_data, ws)
    };
    let exec_rows = collect_exec_rows_incremental(
        &exec_data,
        exec_delta,
        previous.map(|snapshot| snapshot.exec_rows.as_slice()),
        ws,
    );
    let reasoning_summaries = collect_reasoning_summaries_incremental(
        &exec_data,
        exec_delta,
        previous.map(|snapshot| snapshot.reasoning_summaries.as_slice()),
        ws,
    );
    let reason_rows = collect_reason_rows_incremental(
        &exec_data,
        exec_delta,
        previous.map(|snapshot| snapshot.reason_rows.as_slice()),
        ws,
    );
    let turn_memory_rows = if exec_delta.is_empty() {
        previous
            .map(|snapshot| snapshot.turn_memory_rows.clone())
            .unwrap_or_else(|| collect_turn_memory_rows(&exec_data, &exec_rows, ws))
    } else {
        collect_turn_memory_rows(&exec_data, &exec_rows, ws)
    };
    let context_chunks = if exec_delta.is_empty() {
        previous
            .map(|snapshot| snapshot.context_chunks.clone())
            .unwrap_or_else(|| collect_context_chunks(&exec_data))
    } else {
        collect_context_chunks(&exec_data)
    };
    let context_selected = build_context_selected(
        ws,
        &context_chunks,
        context_selected_chunk,
        context_show_children,
        context_show_origins,
    );
    let (compass_rows, compass_status_rows, compass_notes) = if compass_delta.is_empty() {
        if let Some(previous) = previous {
            (
                previous.compass_rows.clone(),
                previous.compass_status_rows.clone(),
                previous.compass_notes.clone(),
            )
        } else {
            (
                collect_compass_rows(&compass_data, ws),
                collect_compass_status_rows(&compass_data),
                collect_compass_notes(&compass_data, ws),
            )
        }
    } else {
        (
            collect_compass_rows(&compass_data, ws),
            collect_compass_status_rows(&compass_data),
            collect_compass_notes(&compass_data, ws),
        )
    };
    let local_message_rows = collect_local_messages_incremental(
        &local_data,
        local_delta,
        previous.map(|snapshot| snapshot.local_message_rows.as_slice()),
        ws,
    );
    let (teams_messages, teams_chats) = if teams_delta.is_empty() {
        if let Some(previous) = previous {
            (
                previous.teams_messages.clone(),
                previous.teams_chats.clone(),
            )
        } else {
            collect_teams_messages(&teams_data, ws)
        }
    } else {
        collect_teams_messages(&teams_data, ws)
    };
    let labels = if exec_delta.is_empty() {
        previous
            .map(|snapshot| snapshot.labels.clone())
            .unwrap_or_else(|| collect_labels(&exec_data, ws))
    } else {
        collect_labels(&exec_data, ws)
    };
    let (timeline_rows, timeline_total_rows) = build_activity_timeline(
        &exec_rows,
        &reasoning_summaries,
        &reason_rows,
        &local_message_rows,
        local_me_id,
        &relations_labels,
        &teams_messages,
        &teams_chats,
        &compass_rows,
        &compass_status_rows,
        &compass_notes,
        &labels,
        timeline_limit,
    );

    DashboardSnapshot {
        pile_path,
        branches,
        branch_data,
        exec_error,
        agent_config,
        agent_config_error,
        context_chunks,
        context_selected,
        exec_rows,
        reasoning_summaries,
        reason_rows,
        turn_memory_rows,
        local_message_rows,
        compass_status_rows,
        timeline_rows,
        timeline_total_rows,
        compass_rows,
        compass_notes,
        compass_error,
        local_message_error,
        local_me_id,
        local_peer_id,
        relations_people,
        relations_error,
        relations_labels,
        teams_messages,
        teams_chats,
        teams_error,
        labels,
        now_key,
    }
}

fn list_branches(pile: &mut Pile<Blake3>) -> Result<Vec<BranchEntry>, String> {
    let reader = pile.reader().map_err(|err| err.to_string())?;
    let iter = pile.branches().map_err(|err| err.to_string())?;
    let mut branches = Vec::new();
    for branch in iter {
        let branch_id = branch.map_err(|err| err.to_string())?;
        let (name, head_timestamp) = match pile.head(branch_id).map_err(|err| err.to_string())? {
            None => (Some("<unnamed>".to_string()), None),
            Some(meta_handle) => {
                let timestamp = reader
                    .metadata(meta_handle)
                    .ok()
                    .flatten()
                    .map(|metadata| metadata.timestamp);
                let name = match reader.get::<TribleSet, _>(meta_handle) {
                    Ok(metadata_set) => {
                        let mut names = find!(
                            handle: Value<Handle<Blake3, LongString>>,
                            pattern!(&metadata_set, [{ metadata::name: ?handle }])
                        );
                        match (names.next(), names.next()) {
                            (Some(handle), None) => reader
                                .get::<View<str>, _>(handle)
                                .ok()
                                .map(|view| view.as_ref().to_string())
                                .or_else(|| {
                                    Some(format!(
                                        "<name blob missing ({})>",
                                        longstring_handle_prefix(handle)
                                    ))
                                }),
                            _ => Some("<unnamed>".to_string()),
                        }
                    }
                    Err(_) => Some(format!(
                        "<metadata blob missing ({})>",
                        archive_handle_prefix(meta_handle)
                    )),
                };
                (name, timestamp)
            }
        };
        branches.push(BranchEntry {
            id: branch_id,
            name,
            head_timestamp,
        });
    }
    Ok(branches)
}

struct BranchLookup {
    by_id: HashSet<Id>,
    by_name: HashMap<String, Vec<BranchNameCandidate>>,
}

#[derive(Debug, Clone, Copy)]
struct BranchNameCandidate {
    id: Id,
    head_timestamp: Option<u64>,
}

impl BranchLookup {
    fn new(branches: &[BranchEntry]) -> Self {
        let mut by_id = HashSet::new();
        let mut by_name: HashMap<String, Vec<BranchNameCandidate>> = HashMap::new();
        for branch in branches {
            by_id.insert(branch.id);
            if let Some(name) = branch.name.clone() {
                by_name.entry(name).or_default().push(BranchNameCandidate {
                    id: branch.id,
                    head_timestamp: branch.head_timestamp,
                });
            }
        }
        for candidates in by_name.values_mut() {
            // Prefer most recently updated branch head for duplicate names.
            candidates.sort_by(|a, b| {
                b.head_timestamp
                    .cmp(&a.head_timestamp)
                    .then_with(|| format!("{:x}", b.id).cmp(&format!("{:x}", a.id)))
            });
        }
        Self { by_id, by_name }
    }

    fn resolve_name(&self, name: &str) -> Option<Id> {
        let candidates = self.by_name.get(name)?;
        candidates.first().map(|candidate| candidate.id)
    }
}

fn candidate_count_for_name(lookup: &BranchLookup, name: &str) -> usize {
    lookup.by_name.get(name).map_or(0, Vec::len)
}

fn maybe_disambiguation_note(lookup: &BranchLookup, name: &str) -> Option<String> {
    let count = candidate_count_for_name(lookup, name);
    if count <= 1 {
        None
    } else {
        Some(format!(
            "Branch name '{name}' has {count} matches; using the most recently updated head."
        ))
    }
}

fn resolve_branch_ids_with_notes(
    lookup: &BranchLookup,
    refs: &[String],
) -> Result<(Vec<Id>, Vec<String>), String> {
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    let mut notes = Vec::new();
    for raw in refs {
        let trimmed = raw.trim();
        let id = if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let id = Id::from_hex(trimmed).ok_or_else(|| "invalid branch id".to_string())?;
            if !lookup.by_id.contains(&id) {
                return Err(format!("Branch id {} not found.", trimmed));
            }
            id
        } else if let Some(id) = lookup.resolve_name(trimmed) {
            if let Some(note) = maybe_disambiguation_note(lookup, trimmed) {
                notes.push(note);
            }
            id
        } else {
            return Err(format!("Branch '{}' not found.", trimmed));
        };
        if seen.insert(id) {
            ids.push(id);
        }
    }
    Ok((ids, notes))
}

fn parse_branch_list(raw: &str) -> Vec<String> {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn resolve_branch_ids(lookup: &BranchLookup, refs: &[String]) -> Result<Vec<Id>, String> {
    let (ids, _) = resolve_branch_ids_with_notes(lookup, refs)?;
    Ok(ids)
}

fn extend_unique(out: &mut Vec<Id>, ids: &[Id]) {
    for id in ids {
        if !out.contains(id) {
            out.push(*id);
        }
    }
}

fn load_branch_snapshot(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    previous: Option<BranchSnapshot>,
) -> Result<BranchSnapshot, String> {
    let mut ws = repo
        .pull(branch_id)
        .map_err(|err| format!("pull branch: {err:?}"))?;
    let head = ws.head();
    let (data, delta) = if let Some(prev_snapshot) = previous {
        if prev_snapshot.head == head {
            (prev_snapshot.data, TribleSet::new())
        } else if let (Some(prev_head), Some(_)) = (prev_snapshot.head, head) {
            match ws.checkout(prev_head..) {
                Ok(delta) => {
                    let mut data = prev_snapshot.data;
                    if !delta.is_empty() {
                        data += delta.clone();
                    }
                    (data, delta)
                }
                Err(_) => {
                    let data = ws.checkout(..).map_err(|err| format!("checkout: {err}"))?;
                    let delta = data.difference(&prev_snapshot.data);
                    (data, delta)
                }
            }
        } else if head.is_none() {
            (TribleSet::new(), TribleSet::new())
        } else {
            let data = ws.checkout(..).map_err(|err| format!("checkout: {err}"))?;
            (data.clone(), data)
        }
    } else if head.is_none() {
        (TribleSet::new(), TribleSet::new())
    } else {
        let data = ws.checkout(..).map_err(|err| format!("checkout: {err}"))?;
        (data.clone(), data)
    };

    Ok(BranchSnapshot { head, data, delta })
}

fn union_branches(branch_data: &HashMap<Id, BranchSnapshot>, ids: &[Id]) -> TribleSet {
    let mut union = TribleSet::new();
    for id in ids {
        if let Some(snapshot) = branch_data.get(id) {
            union += snapshot.data.clone();
        }
    }
    union
}

fn union_branch_deltas(branch_data: &HashMap<Id, BranchSnapshot>, ids: &[Id]) -> TribleSet {
    let mut union = TribleSet::new();
    for id in ids {
        if let Some(snapshot) = branch_data.get(id) {
            union += snapshot.delta.clone();
        }
    }
    union
}

fn collect_agent_config(data: &TribleSet, ws: &mut Workspace<Pile>) -> Option<AgentConfigRow> {
    let mut latest: Option<(Id, i128)> = None;
    for (config_id, updated_at) in find!(
        (config_id: Id, updated_at: Value<NsTAIInterval>),
        pattern!(data, [{
            ?config_id @
            metadata::tag: playground_config::kind_config,
            playground_config::updated_at: ?updated_at,
        }])
    ) {
        let key = interval_key(updated_at);
        if latest.map_or(true, |(_, current)| key > current) {
            latest = Some((config_id, key));
        }
    }

    let Some((config_id, updated_key)) = latest else {
        return None;
    };

    let persona_id = load_optional_id_attr(data, config_id, playground_config::persona_id);
    let branch = load_optional_string_attr(data, ws, config_id, playground_config::branch);
    let author = load_optional_string_attr(data, ws, config_id, playground_config::author);
    let author_role =
        load_optional_string_attr(data, ws, config_id, playground_config::author_role);
    let poll_ms = load_optional_u64_attr(data, config_id, playground_config::poll_ms);
    let model_profile_id =
        load_optional_id_attr(data, config_id, playground_config::active_model_profile_id);
    let (model_entity_id, model_profile_name) = if let Some(profile_id) = model_profile_id {
        if let Some(entry_id) = latest_model_profile_entry_id(data, profile_id) {
            (
                entry_id,
                load_optional_string_attr(data, ws, entry_id, metadata::name),
            )
        } else {
            (config_id, None)
        }
    } else {
        (config_id, None)
    };

    let model_name =
        load_optional_string_attr(data, ws, model_entity_id, playground_config::model_name);
    let model_base_url =
        load_optional_string_attr(data, ws, model_entity_id, playground_config::model_base_url);
    let model_reasoning_effort = load_optional_string_attr(
        data,
        ws,
        model_entity_id,
        playground_config::model_reasoning_effort,
    );
    let model_stream = load_optional_u64_attr(data, model_entity_id, playground_config::model_stream)
        .map(|value| value != 0);
    let model_context_window_tokens = load_optional_u64_attr(
        data,
        model_entity_id,
        playground_config::model_context_window_tokens,
    );
    let model_max_output_tokens = load_optional_u64_attr(
        data,
        model_entity_id,
        playground_config::model_max_output_tokens,
    );
    let model_context_safety_margin_tokens = load_optional_u64_attr(
        data,
        model_entity_id,
        playground_config::model_context_safety_margin_tokens,
    );
    let model_chars_per_token = load_optional_u64_attr(
        data,
        model_entity_id,
        playground_config::model_chars_per_token,
    );
    let model_api_key =
        load_optional_string_attr(data, ws, model_entity_id, playground_config::model_api_key);
    let tavily_api_key =
        load_optional_string_attr(data, ws, config_id, playground_config::tavily_api_key);
    let exa_api_key =
        load_optional_string_attr(data, ws, config_id, playground_config::exa_api_key);
    let exec_default_cwd =
        load_optional_string_attr(data, ws, config_id, playground_config::exec_default_cwd);
    let exec_sandbox_profile =
        load_optional_id_attr(data, config_id, playground_config::exec_sandbox_profile);
    let system_prompt =
        load_optional_string_attr(data, ws, config_id, playground_config::system_prompt);

    Some(AgentConfigRow {
        id: config_id,
        updated_at: Some(updated_key),
        persona_id,
        branch,
        author,
        author_role,
        poll_ms,
        model_profile_id,
        model_profile_name,
        model_name,
        model_base_url,
        model_reasoning_effort,
        model_stream,
        model_context_window_tokens,
        model_max_output_tokens,
        model_context_safety_margin_tokens,
        model_chars_per_token,
        model_api_key,
        tavily_api_key,
        exa_api_key,
        exec_default_cwd,
        exec_sandbox_profile,
        system_prompt,
    })
}

fn latest_model_profile_entry_id(data: &TribleSet, profile_id: Id) -> Option<Id> {
    let mut latest: Option<(Id, i128)> = None;
    for (entry_id, updated_at) in find!(
        (entry_id: Id, updated_at: Value<NsTAIInterval>),
        pattern!(data, [{
            ?entry_id @
            metadata::tag: playground_config::kind_model_profile,
            playground_config::updated_at: ?updated_at,
            playground_config::model_profile_id: profile_id,
        }])
    ) {
        let key = interval_key(updated_at);
        if latest.map_or(true, |(_, current)| key > current) {
            latest = Some((entry_id, key));
        }
    }
    latest.map(|(entry_id, _)| entry_id)
}

fn load_optional_id_attr(data: &TribleSet, entity_id: Id, attr: Attribute<GenId>) -> Option<Id> {
    find!(
        value: Value<GenId>,
        pattern!(data, [{ entity_id @ attr: ?value }])
    )
    .find_map(|value| Id::try_from_value(&value).ok())
}

fn load_optional_u64_attr(data: &TribleSet, entity_id: Id, attr: Attribute<U256BE>) -> Option<u64> {
    find!(
        value: Value<U256BE>,
        pattern!(data, [{ entity_id @ attr: ?value }])
    )
    .next()
    .and_then(|v| v.try_from_value::<u64>().ok())
}

fn load_optional_interval_attr(
    data: &TribleSet,
    entity_id: Id,
    attr: Attribute<NsTAIInterval>,
) -> Option<i128> {
    find!(
        value: Value<NsTAIInterval>,
        pattern!(data, [{ entity_id @ attr: ?value }])
    )
    .next()
    .map(|value| interval_key(value))
}

fn collect_exec_rows_incremental(
    data: &TribleSet,
    delta: &TribleSet,
    previous: Option<&[ExecRow]>,
    ws: &mut Workspace<Pile>,
) -> Vec<ExecRow> {
    let Some(previous_rows) = previous else {
        return collect_exec_rows(data, ws);
    };
    if delta.is_empty() {
        return previous_rows.to_vec();
    }

    let changed_request_ids = collect_changed_exec_request_ids(data, delta);
    if changed_request_ids.is_empty() {
        return previous_rows.to_vec();
    }

    let mut rows: HashMap<Id, ExecRow> = previous_rows
        .iter()
        .cloned()
        .map(|row| (row.request_id, row))
        .collect();
    for request_id in changed_request_ids {
        if let Some(row) = collect_exec_row(data, ws, request_id) {
            rows.insert(request_id, row);
        }
    }
    sort_exec_rows(rows)
}

fn collect_changed_exec_request_ids(data: &TribleSet, delta: &TribleSet) -> HashSet<Id> {
    let mut ids = HashSet::new();
    for request_id in find!(
        request_id: Id,
        pattern_changes!(data, delta, [{
            ?request_id @
            metadata::tag: playground_exec::kind_command_request,
        }])
    ) {
        ids.insert(request_id);
    }
    for request_id in find!(
        request_id: Id,
        pattern_changes!(data, delta, [{ ?request_id @ playground_exec::requested_at: _?requested_at }])
    ) {
        ids.insert(request_id);
    }
    for request_id in find!(
        request_id: Id,
        pattern_changes!(data, delta, [{ _?event_id @ playground_exec::about_request: ?request_id }])
    ) {
        ids.insert(request_id);
    }
    ids
}

fn collect_exec_row(data: &TribleSet, ws: &mut Workspace<Pile>, request_id: Id) -> Option<ExecRow> {
    let command_handle = find!(
        command: Value<Handle<Blake3, LongString>>,
        pattern!(data, [{
            request_id @
            metadata::tag: playground_exec::kind_command_request,
            playground_exec::command_text: ?command,
        }])
    )
    .next()?;
    let command = load_text(ws, command_handle).unwrap_or_else(|| "<missing>".to_string());
    let requested_at = load_optional_interval_attr(data, request_id, playground_exec::requested_at);

    let mut progress: Option<ProgressInfo> = None;
    for event_id in find!(
        event_id: Id,
        pattern!(data, [{
            ?event_id @
            metadata::tag: playground_exec::kind_in_progress,
            playground_exec::about_request: request_id,
        }])
    ) {
        let info = ProgressInfo {
            attempt: load_optional_u64_attr(data, event_id, playground_exec::attempt).unwrap_or(0),
            started_at: load_optional_interval_attr(data, event_id, playground_exec::started_at),
            worker: load_optional_id_attr(data, event_id, playground_exec::worker),
        };
        let replace = progress.as_ref().is_none_or(|existing| {
            info.attempt > existing.attempt
                || (info.attempt == existing.attempt
                    && info.started_at.unwrap_or(i128::MIN)
                        > existing.started_at.unwrap_or(i128::MIN))
        });
        if replace {
            progress = Some(info);
        }
    }

    let mut result: Option<ResultInfo> = None;
    for event_id in find!(
        event_id: Id,
        pattern!(data, [{
            ?event_id @
            metadata::tag: playground_exec::kind_command_result,
            playground_exec::about_request: request_id,
        }])
    ) {
        let info = ResultInfo {
            attempt: load_optional_u64_attr(data, event_id, playground_exec::attempt).unwrap_or(0),
            finished_at: load_optional_interval_attr(data, event_id, playground_exec::finished_at),
            exit_code: load_optional_u64_attr(data, event_id, playground_exec::exit_code),
            stdout_text: load_optional_string_attr(
                data,
                ws,
                event_id,
                playground_exec::stdout_text,
            ),
            stderr_text: load_optional_string_attr(
                data,
                ws,
                event_id,
                playground_exec::stderr_text,
            ),
            error: load_optional_string_attr(data, ws, event_id, playground_exec::error),
        };
        let replace = result.as_ref().is_none_or(|existing| {
            info.attempt > existing.attempt
                || (info.attempt == existing.attempt
                    && info.finished_at.unwrap_or(i128::MIN)
                        > existing.finished_at.unwrap_or(i128::MIN))
        });
        if replace {
            result = Some(info);
        }
    }

    let status = if let Some(result) = result.as_ref() {
        if result.error.is_some() {
            ExecStatus::Failed
        } else {
            ExecStatus::Done
        }
    } else if progress.is_some() {
        ExecStatus::Running
    } else {
        ExecStatus::Pending
    };

    Some(ExecRow {
        request_id,
        command,
        status,
        requested_at,
        started_at: progress.as_ref().and_then(|info| info.started_at),
        finished_at: result.as_ref().and_then(|info| info.finished_at),
        exit_code: result.as_ref().and_then(|info| info.exit_code),
        worker: progress.as_ref().and_then(|info| info.worker),
        stdout_text: result.as_ref().and_then(|info| info.stdout_text.clone()),
        stderr_text: result.as_ref().and_then(|info| info.stderr_text.clone()),
        error: result.as_ref().and_then(|info| info.error.clone()),
    })
}

fn sort_exec_rows(rows: HashMap<Id, ExecRow>) -> Vec<ExecRow> {
    let mut list: Vec<ExecRow> = rows.into_values().collect();
    list.sort_by_key(|row| row.requested_at.unwrap_or(i128::MIN));
    list.reverse();
    list
}

fn collect_exec_rows(data: &TribleSet, ws: &mut Workspace<Pile>) -> Vec<ExecRow> {
    let mut rows: HashMap<Id, ExecRow> = HashMap::new();
    for (request_id, command) in find!(
        (request_id: Id, command: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{
            ?request_id @
            metadata::tag: playground_exec::kind_command_request,
            playground_exec::command_text: ?command,
        }])
    ) {
        let command_text = load_text(ws, command).unwrap_or_else(|| "<missing>".to_string());
        rows.insert(
            request_id,
            ExecRow {
                request_id,
                command: command_text,
                status: ExecStatus::Pending,
                requested_at: None,
                started_at: None,
                finished_at: None,
                exit_code: None,
                worker: None,
                stdout_text: None,
                stderr_text: None,
                error: None,
            },
        );
    }

    for (request_id, requested_at) in find!(
        (request_id: Id, requested_at: Value<NsTAIInterval>),
        pattern!(data, [{ ?request_id @ playground_exec::requested_at: ?requested_at }])
    ) {
        if let Some(row) = rows.get_mut(&request_id) {
            row.requested_at = Some(interval_key(requested_at));
        }
    }

    let attempts = load_attempts(data);
    let started_at = load_started_at(data);
    let finished_at = load_finished_at(data);
    let workers = load_workers(data);
    let exit_codes = load_exit_codes(data);
    let stdout_text = load_output_text(data, ws, playground_exec::stdout_text);
    let stderr_text = load_output_text(data, ws, playground_exec::stderr_text);
    let errors = load_errors(data, ws);

    let progress = latest_progress(data, &attempts, &started_at, &workers);
    let results = latest_results(
        data,
        &attempts,
        &finished_at,
        &exit_codes,
        &stdout_text,
        &stderr_text,
        &errors,
    );

    for (request_id, row) in rows.iter_mut() {
        let progress_info = progress.get(request_id);
        let result_info = results.get(request_id);
        row.started_at = progress_info.and_then(|info| info.started_at);
        row.worker = progress_info.and_then(|info| info.worker);
        row.finished_at = result_info.and_then(|info| info.finished_at);
        row.exit_code = result_info.and_then(|info| info.exit_code);
        row.stdout_text = result_info.and_then(|info| info.stdout_text.clone());
        row.stderr_text = result_info.and_then(|info| info.stderr_text.clone());
        row.error = result_info.and_then(|info| info.error.clone());

        row.status = if let Some(result) = result_info {
            if result.error.is_some() {
                ExecStatus::Failed
            } else {
                ExecStatus::Done
            }
        } else if progress_info.is_some() {
            ExecStatus::Running
        } else {
            ExecStatus::Pending
        };
    }

    sort_exec_rows(rows)
}

fn collect_turn_memory_rows(
    data: &TribleSet,
    exec_rows: &[ExecRow],
    ws: &mut Workspace<Pile>,
) -> Vec<TurnMemoryRow> {
    let mut thought_by_request: HashMap<Id, Id> = HashMap::new();
    for (request_id, thought_id) in find!(
        (request_id: Id, thought_id: Id),
        pattern!(data, [{
            ?request_id @
            metadata::tag: playground_exec::kind_command_request,
            playground_exec::about_thought: ?thought_id,
        }])
    ) {
        thought_by_request.insert(request_id, thought_id);
    }

    let mut context_by_thought: HashMap<Id, Value<Handle<Blake3, LongString>>> = HashMap::new();
    for (thought_id, context_handle) in find!(
        (thought_id: Id, context_handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{
            ?thought_id @
            metadata::tag: playground_cog::kind_thought,
            playground_cog::context: ?context_handle,
        }])
    ) {
        context_by_thought.insert(thought_id, context_handle);
    }

    let mut rows = Vec::new();
    for exec in exec_rows.iter().take(TURN_MEMORY_MAX_ROWS) {
        let thought_id = thought_by_request.get(&exec.request_id).copied();
        let mut context_messages = Vec::new();
        let mut context_error = None;
        if let Some(thought_id) = thought_id {
            if let Some(context_handle) = context_by_thought.get(&thought_id).copied() {
                match load_text(ws, context_handle) {
                    Some(context_json) => match serde_json::from_str::<Vec<ChatMessage>>(&context_json) {
                        Ok(messages) => context_messages = messages,
                        Err(err) => {
                            context_error = Some(format!("context parse error: {err}"));
                        }
                    },
                    None => {
                        context_error = Some("context blob missing".to_string());
                    }
                }
            } else {
                context_error = Some("thought has no context handle".to_string());
            }
        } else {
            context_error = Some("request has no thought link".to_string());
        }

        rows.push(TurnMemoryRow {
            request_id: exec.request_id,
            command: exec.command.clone(),
            requested_at: exec.requested_at,
            thought_id,
            context_messages,
            context_error,
        });
    }
    rows
}

fn collect_local_messages_incremental(
    data: &TribleSet,
    delta: &TribleSet,
    previous: Option<&[LocalMessageRow]>,
    ws: &mut Workspace<Pile>,
) -> Vec<LocalMessageRow> {
    let Some(previous_rows) = previous else {
        return collect_local_messages(data, ws);
    };
    if delta.is_empty() {
        return previous_rows.to_vec();
    }
    let changed_message_ids = collect_changed_local_message_ids(data, delta);
    if changed_message_ids.is_empty() {
        return previous_rows.to_vec();
    }
    let mut rows: HashMap<Id, LocalMessageRow> = previous_rows
        .iter()
        .cloned()
        .map(|row| (row.id, row))
        .collect();
    for message_id in changed_message_ids {
        if let Some(row) = collect_local_message_row(data, ws, message_id) {
            rows.insert(message_id, row);
        }
    }
    let mut list: Vec<LocalMessageRow> = rows.into_values().collect();
    list.sort_by_key(|row| row.created_at.unwrap_or(i128::MIN));
    list
}

fn collect_changed_local_message_ids(data: &TribleSet, delta: &TribleSet) -> HashSet<Id> {
    let mut ids = HashSet::new();
    for message_id in find!(
        message_id: Id,
        pattern_changes!(data, delta, [{
            ?message_id @
            metadata::tag: &LOCAL_KIND_MESSAGE_ID,
        }])
    ) {
        ids.insert(message_id);
    }
    for message_id in find!(
        message_id: Id,
        pattern_changes!(data, delta, [{
            _?read_id @
            metadata::tag: &LOCAL_KIND_READ_ID,
            local_messages::about_message: ?message_id,
        }])
    ) {
        ids.insert(message_id);
    }
    ids
}

fn collect_local_message_row(
    data: &TribleSet,
    ws: &mut Workspace<Pile>,
    message_id: Id,
) -> Option<LocalMessageRow> {
    let message = find!(
        (
            from: Id,
            to: Id,
            body_handle: Value<Handle<Blake3, LongString>>,
            created_at: Value<NsTAIInterval>
        ),
        pattern!(&data, [{
            message_id @
            metadata::tag: &LOCAL_KIND_MESSAGE_ID,
            local_messages::from: ?from,
            local_messages::to: ?to,
            local_messages::body: ?body_handle,
            local_messages::created_at: ?created_at,
        }])
    )
    .next()?;
    let (from, to, body_handle, created_at) = message;
    let body = load_text(ws, body_handle).unwrap_or_else(|| "<missing>".to_string());

    let mut readers: HashSet<Id> = HashSet::new();
    for reader_id in find!(
        reader_id: Id,
        pattern!(&data, [{
            _?read_id @
            metadata::tag: &LOCAL_KIND_READ_ID,
            local_messages::about_message: message_id,
            local_messages::reader: ?reader_id,
            local_messages::read_at: _?read_at,
        }])
    ) {
        readers.insert(reader_id);
    }

    let mut reader_list: Vec<Id> = readers.into_iter().collect();
    reader_list.sort_by_key(|id| format!("{id:x}"));
    Some(LocalMessageRow {
        id: message_id,
        created_at: Some(interval_key(created_at)),
        from_id: from,
        to_id: to,
        body,
        readers: reader_list,
    })
}

fn collect_local_messages(data: &TribleSet, ws: &mut Workspace<Pile>) -> Vec<LocalMessageRow> {
    let mut rows = Vec::new();
    for (message_id, from, to, body_handle, created_at) in find!(
        (
            message_id: Id,
            from: Id,
            to: Id,
            body_handle: Value<Handle<Blake3, LongString>>,
            created_at: Value<NsTAIInterval>
        ),
        pattern!(&data, [{
            ?message_id @
            metadata::tag: &LOCAL_KIND_MESSAGE_ID,
            local_messages::from: ?from,
            local_messages::to: ?to,
            local_messages::body: ?body_handle,
            local_messages::created_at: ?created_at,
        }])
    ) {
        let body = load_text(ws, body_handle).unwrap_or_else(|| "<missing>".to_string());
        rows.push(LocalMessageRow {
            id: message_id,
            created_at: Some(interval_key(created_at)),
            from_id: from,
            to_id: to,
            body,
            readers: Vec::new(),
        });
    }

    let mut reads: HashMap<Id, HashSet<Id>> = HashMap::new();
    for (_read_id, message_id, reader_id, read_at) in find!(
        (
            read_id: Id,
            message_id: Id,
            reader_id: Id,
            read_at: Value<NsTAIInterval>
        ),
        pattern!(&data, [{
            ?read_id @
            metadata::tag: &LOCAL_KIND_READ_ID,
            local_messages::about_message: ?message_id,
            local_messages::reader: ?reader_id,
            local_messages::read_at: ?read_at,
        }])
    ) {
        let _ = read_at;
        reads.entry(message_id).or_default().insert(reader_id);
    }

    for row in &mut rows {
        if let Some(readers) = reads.get(&row.id) {
            let mut reader_list: Vec<Id> = readers.iter().copied().collect();
            reader_list.sort_by_key(|id| format!("{id:x}"));
            row.readers = reader_list;
        }
    }

    rows.sort_by_key(|row| row.created_at.unwrap_or(i128::MIN));
    rows
}

fn collect_relations_people(data: &TribleSet, ws: &mut Workspace<Pile>) -> Vec<RelationRow> {
    let mut people: HashMap<Id, RelationRow> = HashMap::new();

    for person_id in find!(
        person_id: Id,
        pattern!(data, [{ ?person_id @ metadata::tag: &RELATIONS_KIND_PERSON_ID }])
    ) {
        people.insert(
            person_id,
            RelationRow {
                id: person_id,
                label: None,
                first_name: None,
                last_name: None,
                display_name: None,
                affinity: None,
                teams_user_id: None,
                email: None,
                note: None,
                aliases: Vec::new(),
            },
        );
    }

    for (person_id, handle) in find!(
        (person_id: Id, handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{ ?person_id @ metadata::name: ?handle }])
    ) {
        if let Some(person) = people.get_mut(&person_id) {
            if person.label.is_none() {
                if let Some(value) = load_text(ws, handle) {
                    person.label = Some(value);
                }
            }
        }
    }

    for (person_id, handle) in find!(
        (person_id: Id, handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{ ?person_id @ relations::display_name: ?handle }])
    ) {
        if let Some(person) = people.get_mut(&person_id) {
            if person.display_name.is_none() {
                if let Some(value) = load_text(ws, handle) {
                    person.display_name = Some(value);
                }
            }
        }
    }

    for (person_id, handle) in find!(
        (person_id: Id, handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{ ?person_id @ relations::first_name: ?handle }])
    ) {
        if let Some(person) = people.get_mut(&person_id) {
            if person.first_name.is_none() {
                if let Some(value) = load_text(ws, handle) {
                    person.first_name = Some(value);
                }
            }
        }
    }

    for (person_id, handle) in find!(
        (person_id: Id, handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{ ?person_id @ relations::last_name: ?handle }])
    ) {
        if let Some(person) = people.get_mut(&person_id) {
            if person.last_name.is_none() {
                if let Some(value) = load_text(ws, handle) {
                    person.last_name = Some(value);
                }
            }
        }
    }

    for (person_id, handle) in find!(
        (person_id: Id, handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{ ?person_id @ metadata::description: ?handle }])
    ) {
        if let Some(person) = people.get_mut(&person_id) {
            if person.note.is_none() {
                if let Some(value) = load_text(ws, handle) {
                    person.note = Some(value);
                }
            }
        }
    }

    for (person_id, value) in find!(
        (person_id: Id, value: String),
        pattern!(data, [{ ?person_id @ relations::affinity: ?value }])
    ) {
        if let Some(person) = people.get_mut(&person_id) {
            if person.affinity.is_none() {
                person.affinity = Some(value);
            }
        }
    }

    for (person_id, value) in find!(
        (person_id: Id, value: String),
        pattern!(data, [{ ?person_id @ relations::teams_user_id: ?value }])
    ) {
        if let Some(person) = people.get_mut(&person_id) {
            if person.teams_user_id.is_none() {
                person.teams_user_id = Some(value);
            }
        }
    }

    for (person_id, value) in find!(
        (person_id: Id, value: String),
        pattern!(data, [{ ?person_id @ relations::email: ?value }])
    ) {
        if let Some(person) = people.get_mut(&person_id) {
            if person.email.is_none() {
                person.email = Some(value);
            }
        }
    }

    for (person_id, value) in find!(
        (person_id: Id, value: String),
        pattern!(data, [{ ?person_id @ relations::alias: ?value }])
    ) {
        if let Some(person) = people.get_mut(&person_id) {
            person.aliases.push(value);
        }
    }

    let mut list: Vec<RelationRow> = people.into_values().collect();
    list.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.id.cmp(&b.id)));
    list
}

fn collect_relations_labels(people: &[RelationRow]) -> HashMap<Id, String> {
    let mut map = HashMap::new();
    for person in people {
        if let Some(label) = person.label.as_ref() {
            map.insert(person.id, label.clone());
        } else if let (Some(first), Some(last)) =
            (person.first_name.as_ref(), person.last_name.as_ref())
        {
            map.insert(person.id, format!("{first} {last}"));
        } else if let Some(first) = person.first_name.as_ref() {
            map.insert(person.id, first.clone());
        } else if let Some(last) = person.last_name.as_ref() {
            map.insert(person.id, last.clone());
        } else if let Some(name) = person.display_name.as_ref() {
            map.insert(person.id, name.clone());
        }
    }
    map
}

fn resolve_person_ref(people: &[RelationRow], raw: &str) -> Option<Id> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(id) = Id::from_hex(trimmed) {
        return Some(id);
    }
    for person in people {
        if let Some(label) = person.label.as_ref() {
            if label == trimmed {
                return Some(person.id);
            }
        }
        if let (Some(first), Some(last)) = (person.first_name.as_ref(), person.last_name.as_ref()) {
            let full = format!("{first} {last}");
            if full == trimmed {
                return Some(person.id);
            }
        }
        if let Some(first) = person.first_name.as_ref() {
            if first == trimmed {
                return Some(person.id);
            }
        }
        if let Some(last) = person.last_name.as_ref() {
            if last == trimmed {
                return Some(person.id);
            }
        }
        if let Some(name) = person.display_name.as_ref() {
            if name == trimmed {
                return Some(person.id);
            }
        }
        if person.aliases.iter().any(|alias| alias == trimmed) {
            return Some(person.id);
        }
    }
    None
}

fn collect_teams_messages(
    data: &TribleSet,
    ws: &mut Workspace<Pile>,
) -> (Vec<TeamsMessageRow>, Vec<TeamsChatRow>) {
    let mut author_names: HashMap<Id, String> = HashMap::new();
    for (author_id, name_handle) in find!(
        (author_id: Id, name_handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{ ?author_id @ archive::author_name: ?name_handle }])
    ) {
        if let Some(name) = load_text(ws, name_handle) {
            author_names.insert(author_id, name);
        }
    }

    let mut chat_labels: HashMap<Id, String> = HashMap::new();
    for (chat_id, chat_handle) in find!(
        (chat_id: Id, chat_handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{ ?chat_id @ teams::chat_id: ?chat_handle }])
    ) {
        if let Some(label) = load_text(ws, chat_handle) {
            chat_labels.insert(chat_id, label);
        }
    }

    let mut messages = Vec::new();
    for (_message_id, chat_id, author_id, content_handle, created_at) in find!(
        (
            message_id: Id,
            chat_id: Id,
            author_id: Id,
            content_handle: Value<Handle<Blake3, LongString>>,
            created_at: Value<NsTAIInterval>
        ),
        pattern!(data, [{
            ?message_id @
            metadata::tag: archive::kind_message,
            teams::chat: ?chat_id,
            archive::author: ?author_id,
            archive::content: ?content_handle,
            archive::created_at: ?created_at,
        }])
    ) {
        let content = load_text(ws, content_handle).unwrap_or_else(|| "<missing>".to_string());
        let created_key = interval_key(created_at);
        let author_name = author_names.get(&author_id).cloned();
        messages.push(TeamsMessageRow {
            chat_id,
            created_at: Some(created_key),
            author_name,
            content,
        });
    }

    messages.sort_by_key(|row| row.created_at.unwrap_or(i128::MIN));
    messages.reverse();

    let mut chats: HashMap<Id, TeamsChatRow> = HashMap::new();
    for row in &messages {
        let entry = chats.entry(row.chat_id).or_insert_with(|| TeamsChatRow {
            id: row.chat_id,
            label: chat_labels
                .get(&row.chat_id)
                .cloned()
                .unwrap_or_else(|| id_prefix(row.chat_id)),
            last_at: None,
            message_count: 0,
        });
        entry.message_count += 1;
        if entry.last_at.map_or(true, |current| {
            row.created_at.unwrap_or(i128::MIN) > current
        }) {
            entry.last_at = row.created_at;
        }
    }

    let mut chat_list: Vec<TeamsChatRow> = chats.into_values().collect();
    chat_list.sort_by_key(|row| row.last_at.unwrap_or(i128::MIN));
    chat_list.reverse();

    (messages, chat_list)
}

fn load_optional_string_attr(
    data: &TribleSet,
    ws: &mut Workspace<Pile>,
    entity_id: Id,
    attr: Attribute<Handle<Blake3, LongString>>,
) -> Option<String> {
    find!(
        handle: Value<Handle<Blake3, LongString>>,
        pattern!(data, [{
            entity_id @
            attr: ?handle,
        }])
    )
    .next()
    .and_then(|handle| load_text(ws, handle))
}

fn sort_reasoning_summaries(rows: HashMap<Id, ReasoningSummaryRow>) -> Vec<ReasoningSummaryRow> {
    let mut list: Vec<ReasoningSummaryRow> = rows.into_values().collect();
    list.sort_by_key(|row| row.created_at.unwrap_or(i128::MIN));
    list.reverse();
    list
}

fn collect_reasoning_summaries_incremental(
    data: &TribleSet,
    delta: &TribleSet,
    previous: Option<&[ReasoningSummaryRow]>,
    ws: &mut Workspace<Pile>,
) -> Vec<ReasoningSummaryRow> {
    let Some(previous_rows) = previous else {
        return collect_reasoning_summaries(data, ws);
    };
    if delta.is_empty() {
        return previous_rows.to_vec();
    }
    let changed_result_ids = collect_changed_result_ids(data, delta);
    if changed_result_ids.is_empty() {
        return previous_rows.to_vec();
    }

    let mut rows: HashMap<Id, ReasoningSummaryRow> = previous_rows
        .iter()
        .cloned()
        .map(|row| (row.result_id, row))
        .collect();
    for result_id in changed_result_ids {
        if let Some(row) = collect_reasoning_summary_row(data, ws, result_id) {
            rows.insert(result_id, row);
        }
    }
    sort_reasoning_summaries(rows)
}

fn collect_changed_result_ids(data: &TribleSet, delta: &TribleSet) -> HashSet<Id> {
    let mut ids = HashSet::new();
    for result_id in find!(
        result_id: Id,
        pattern_changes!(data, delta, [{ ?result_id @ metadata::tag: model_chat::kind_result }])
    ) {
        ids.insert(result_id);
    }
    for result_id in find!(
        result_id: Id,
        pattern_changes!(data, delta, [{ ?result_id @ model_chat::reasoning_text: _?reasoning_handle }])
    ) {
        ids.insert(result_id);
    }
    for result_id in find!(
        result_id: Id,
        pattern_changes!(data, delta, [{ ?result_id @ model_chat::response_raw: _?raw_handle }])
    ) {
        ids.insert(result_id);
    }
    for result_id in find!(
        result_id: Id,
        pattern_changes!(data, delta, [{ ?result_id @ model_chat::finished_at: _?finished_at }])
    ) {
        ids.insert(result_id);
    }
    for result_id in find!(
        result_id: Id,
        pattern_changes!(data, delta, [{ ?result_id @ model_chat::input_tokens: _?v }])
    ) {
        ids.insert(result_id);
    }
    ids
}

fn collect_reasoning_summary_row(
    data: &TribleSet,
    ws: &mut Workspace<Pile>,
    result_id: Id,
) -> Option<ReasoningSummaryRow> {
    let finished_at = find!(
        finished_at: Value<NsTAIInterval>,
        pattern!(data, [{
            result_id @
            metadata::tag: model_chat::kind_result,
            model_chat::finished_at: ?finished_at,
        }])
    )
    .next()
    .map(|finished_at| interval_key(finished_at))?;

    let summary = if let Some(reasoning_handle) = find!(
        reasoning_handle: Value<Handle<Blake3, LongString>>,
        pattern!(data, [{
            result_id @
            metadata::tag: model_chat::kind_result,
            model_chat::reasoning_text: ?reasoning_handle,
        }])
    )
    .next()
    {
        load_text(ws, reasoning_handle).unwrap_or_default()
    } else if let Some(raw_handle) = find!(
        raw_handle: Value<Handle<Blake3, LongString>>,
        pattern!(data, [{
            result_id @
            metadata::tag: model_chat::kind_result,
            model_chat::response_raw: ?raw_handle,
        }])
    )
    .next()
    {
        let raw = load_text(ws, raw_handle).unwrap_or_default();
        let response_json = parse_response_json(&raw)?;
        let summaries = extract_reasoning_summaries(&response_json);
        summaries.join("\n")
    } else {
        String::new()
    };

    let input_tokens = find!(
        v: Value<U256BE>,
        pattern!(data, [{ result_id @ model_chat::input_tokens: ?v }])
    ).next().and_then(|v| u256be_to_u64(v));

    let output_tokens = find!(
        v: Value<U256BE>,
        pattern!(data, [{ result_id @ model_chat::output_tokens: ?v }])
    ).next().and_then(|v| u256be_to_u64(v));

    let cache_creation_input_tokens = find!(
        v: Value<U256BE>,
        pattern!(data, [{ result_id @ model_chat::cache_creation_input_tokens: ?v }])
    ).next().and_then(|v| u256be_to_u64(v));

    let cache_read_input_tokens = find!(
        v: Value<U256BE>,
        pattern!(data, [{ result_id @ model_chat::cache_read_input_tokens: ?v }])
    ).next().and_then(|v| u256be_to_u64(v));

    let has_content = !summary.trim().is_empty()
        || input_tokens.is_some()
        || output_tokens.is_some();
    if !has_content {
        return None;
    }

    Some(ReasoningSummaryRow {
        result_id,
        created_at: Some(finished_at),
        summary,
        input_tokens,
        output_tokens,
        cache_creation_input_tokens,
        cache_read_input_tokens,
    })
}

fn collect_reasoning_summaries(
    data: &TribleSet,
    ws: &mut Workspace<Pile>,
) -> Vec<ReasoningSummaryRow> {
    let mut rows = Vec::new();
    let mut reasoning_by_result: HashMap<Id, Value<Handle<Blake3, LongString>>> = HashMap::new();
    for (result_id, reasoning_handle) in find!(
        (
            result_id: Id,
            reasoning_handle: Value<Handle<Blake3, LongString>>
        ),
        pattern!(data, [{
            ?result_id @
            metadata::tag: model_chat::kind_result,
            model_chat::reasoning_text: ?reasoning_handle,
        }])
    ) {
        reasoning_by_result.insert(result_id, reasoning_handle);
    }

    let mut raw_by_result: HashMap<Id, Value<Handle<Blake3, LongString>>> = HashMap::new();
    for (result_id, raw_handle) in find!(
        (
            result_id: Id,
            raw_handle: Value<Handle<Blake3, LongString>>
        ),
        pattern!(data, [{
            ?result_id @
            metadata::tag: model_chat::kind_result,
            model_chat::response_raw: ?raw_handle,
        }])
    ) {
        raw_by_result.insert(result_id, raw_handle);
    }

    let mut input_tok: HashMap<Id, u64> = HashMap::new();
    let mut output_tok: HashMap<Id, u64> = HashMap::new();
    let mut cache_create_tok: HashMap<Id, u64> = HashMap::new();
    let mut cache_read_tok: HashMap<Id, u64> = HashMap::new();
    for (id, v) in find!((id: Id, v: Value<U256BE>), pattern!(data, [{ ?id @ model_chat::input_tokens: ?v }])) {
        if let Some(n) = u256be_to_u64(v) { input_tok.insert(id, n); }
    }
    for (id, v) in find!((id: Id, v: Value<U256BE>), pattern!(data, [{ ?id @ model_chat::output_tokens: ?v }])) {
        if let Some(n) = u256be_to_u64(v) { output_tok.insert(id, n); }
    }
    for (id, v) in find!((id: Id, v: Value<U256BE>), pattern!(data, [{ ?id @ model_chat::cache_creation_input_tokens: ?v }])) {
        if let Some(n) = u256be_to_u64(v) { cache_create_tok.insert(id, n); }
    }
    for (id, v) in find!((id: Id, v: Value<U256BE>), pattern!(data, [{ ?id @ model_chat::cache_read_input_tokens: ?v }])) {
        if let Some(n) = u256be_to_u64(v) { cache_read_tok.insert(id, n); }
    }

    for (result_id, finished_at) in find!(
        (result_id: Id, finished_at: Value<NsTAIInterval>),
        pattern!(data, [{
            ?result_id @
            metadata::tag: model_chat::kind_result,
            model_chat::finished_at: ?finished_at,
        }])
    ) {
        let summary = if let Some(handle) = reasoning_by_result.get(&result_id).copied() {
            load_text(ws, handle).unwrap_or_default()
        } else if let Some(handle) = raw_by_result.get(&result_id).copied() {
            let raw = load_text(ws, handle).unwrap_or_default();
            match parse_response_json(&raw) {
                Some(response_json) => extract_reasoning_summaries(&response_json).join("\n"),
                None => String::new(),
            }
        } else {
            String::new()
        };

        let it = input_tok.get(&result_id).copied();
        let ot = output_tok.get(&result_id).copied();
        let has_content = !summary.trim().is_empty() || it.is_some() || ot.is_some();
        if !has_content {
            continue;
        }

        rows.push(ReasoningSummaryRow {
            result_id,
            created_at: Some(interval_key(finished_at)),
            summary,
            input_tokens: it,
            output_tokens: ot,
            cache_creation_input_tokens: cache_create_tok.get(&result_id).copied(),
            cache_read_input_tokens: cache_read_tok.get(&result_id).copied(),
        });
    }
    rows.sort_by_key(|row| row.created_at.unwrap_or(i128::MIN));
    rows.reverse();
    rows
}

fn sort_reason_rows(rows: HashMap<Id, ReasonRow>) -> Vec<ReasonRow> {
    let mut list: Vec<ReasonRow> = rows.into_values().collect();
    list.sort_by_key(|row| row.created_at.unwrap_or(i128::MIN));
    list.reverse();
    list
}

fn collect_reason_rows_incremental(
    data: &TribleSet,
    delta: &TribleSet,
    previous: Option<&[ReasonRow]>,
    ws: &mut Workspace<Pile>,
) -> Vec<ReasonRow> {
    let Some(previous_rows) = previous else {
        return collect_reason_rows(data, ws);
    };
    if delta.is_empty() {
        return previous_rows.to_vec();
    }
    let changed_reason_ids = collect_changed_reason_ids(data, delta);
    if changed_reason_ids.is_empty() {
        return previous_rows.to_vec();
    }
    let mut rows: HashMap<Id, ReasonRow> = previous_rows
        .iter()
        .cloned()
        .map(|row| (row.id, row))
        .collect();
    for reason_id in changed_reason_ids {
        if let Some(row) = collect_reason_row(data, ws, reason_id) {
            rows.insert(reason_id, row);
        }
    }
    sort_reason_rows(rows)
}

fn collect_changed_reason_ids(data: &TribleSet, delta: &TribleSet) -> HashSet<Id> {
    let mut ids = HashSet::new();
    for reason_id in find!(
        reason_id: Id,
        pattern_changes!(data, delta, [{ ?reason_id @ metadata::tag: &REASON_KIND_EVENT_ID }])
    ) {
        ids.insert(reason_id);
    }
    for reason_id in find!(
        reason_id: Id,
        pattern_changes!(data, delta, [{ ?reason_id @ reason_events::text: _?text }])
    ) {
        ids.insert(reason_id);
    }
    for reason_id in find!(
        reason_id: Id,
        pattern_changes!(data, delta, [{ ?reason_id @ reason_events::created_at: _?at }])
    ) {
        ids.insert(reason_id);
    }
    for reason_id in find!(
        reason_id: Id,
        pattern_changes!(data, delta, [{ ?reason_id @ reason_events::about_turn: _?turn_id }])
    ) {
        ids.insert(reason_id);
    }
    for reason_id in find!(
        reason_id: Id,
        pattern_changes!(data, delta, [{ ?reason_id @ reason_events::worker: _?worker_id }])
    ) {
        ids.insert(reason_id);
    }
    for reason_id in find!(
        reason_id: Id,
        pattern_changes!(data, delta, [{ ?reason_id @ reason_events::command_text: _?command_handle }])
    ) {
        ids.insert(reason_id);
    }
    ids
}

fn collect_reason_row(
    data: &TribleSet,
    ws: &mut Workspace<Pile>,
    reason_id: Id,
) -> Option<ReasonRow> {
    let (text_handle, created_at) = find!(
        (
            text_handle: Value<Handle<Blake3, LongString>>,
            created_at: Value<NsTAIInterval>
        ),
        pattern!(data, [{
            reason_id @
            metadata::tag: &REASON_KIND_EVENT_ID,
            reason_events::text: ?text_handle,
            reason_events::created_at: ?created_at,
        }])
    )
    .next()?;
    let text = load_text(ws, text_handle)?;
    let turn_id = find!(
        turn_id: Id,
        pattern!(data, [{
            reason_id @
            metadata::tag: &REASON_KIND_EVENT_ID,
            reason_events::about_turn: ?turn_id,
        }])
    )
    .next();
    let worker_id = find!(
        worker_id: Id,
        pattern!(data, [{
            reason_id @
            metadata::tag: &REASON_KIND_EVENT_ID,
            reason_events::worker: ?worker_id,
        }])
    )
    .next();
    let command_text = find!(
        command_handle: Value<Handle<Blake3, LongString>>,
        pattern!(data, [{
            reason_id @
            metadata::tag: &REASON_KIND_EVENT_ID,
            reason_events::command_text: ?command_handle,
        }])
    )
    .next()
    .and_then(|command_handle| load_text(ws, command_handle));

    Some(ReasonRow {
        id: reason_id,
        created_at: Some(interval_key(created_at)),
        text,
        turn_id,
        worker_id,
        command_text,
    })
}

fn collect_reason_rows(data: &TribleSet, ws: &mut Workspace<Pile>) -> Vec<ReasonRow> {
    let mut rows = Vec::new();
    let mut turn_by_reason: HashMap<Id, Id> = HashMap::new();
    let mut worker_by_reason: HashMap<Id, Id> = HashMap::new();
    let mut command_by_reason: HashMap<Id, String> = HashMap::new();

    for (reason_id, turn_id) in find!(
        (reason_id: Id, turn_id: Id),
        pattern!(data, [{
            ?reason_id @
            metadata::tag: &REASON_KIND_EVENT_ID,
            reason_events::about_turn: ?turn_id,
        }])
    ) {
        turn_by_reason.insert(reason_id, turn_id);
    }

    for (reason_id, worker_id) in find!(
        (reason_id: Id, worker_id: Id),
        pattern!(data, [{
            ?reason_id @
            metadata::tag: &REASON_KIND_EVENT_ID,
            reason_events::worker: ?worker_id,
        }])
    ) {
        worker_by_reason.insert(reason_id, worker_id);
    }

    for (reason_id, command_handle) in find!(
        (reason_id: Id, command_handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{
            ?reason_id @
            metadata::tag: &REASON_KIND_EVENT_ID,
            reason_events::command_text: ?command_handle,
        }])
    ) {
        let Some(command_text) = load_text(ws, command_handle) else {
            continue;
        };
        command_by_reason.insert(reason_id, command_text);
    }

    for (reason_id, text_handle, created_at) in find!(
        (
            reason_id: Id,
            text_handle: Value<Handle<Blake3, LongString>>,
            created_at: Value<NsTAIInterval>
        ),
        pattern!(data, [{
            ?reason_id @
            metadata::tag: &REASON_KIND_EVENT_ID,
            reason_events::text: ?text_handle,
            reason_events::created_at: ?created_at,
        }])
    ) {
        let Some(text) = load_text(ws, text_handle) else {
            continue;
        };
        rows.push(ReasonRow {
            id: reason_id,
            created_at: Some(interval_key(created_at)),
            text,
            turn_id: turn_by_reason.get(&reason_id).copied(),
            worker_id: worker_by_reason.get(&reason_id).copied(),
            command_text: command_by_reason.get(&reason_id).cloned(),
        });
    }
    rows.sort_by_key(|row| row.created_at.unwrap_or(i128::MIN));
    rows.reverse();
    rows
}

fn collect_context_chunks(data: &TribleSet) -> Vec<ContextChunkRow> {
    let mut rows: HashMap<Id, ContextChunkRow> = HashMap::new();

    for (chunk_id, summary, start_at, end_at) in find!(
        (
            chunk_id: Id,
            summary: Value<Handle<Blake3, LongString>>,
            start_at: Value<NsTAIInterval>,
            end_at: Value<NsTAIInterval>
        ),
        pattern!(data, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::summary: ?summary,
            playground_context::start_at: ?start_at,
            playground_context::end_at: ?end_at,
        }])
    ) {
        rows.insert(
            chunk_id,
            ContextChunkRow {
                id: chunk_id,
                summary,
                start_at: Some(interval_key(start_at)),
                end_at: Some(interval_key(end_at)),
                children: Vec::new(),
                about_exec_result: None,
            },
        );
    }

    for (chunk_id, child_id) in find!(
        (chunk_id: Id, child_id: Id),
        pattern!(data, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::child: ?child_id,
        }])
    ) {
        if let Some(row) = rows.get_mut(&chunk_id) {
            row.children.push(child_id);
        }
    }

    // Legacy two-child edges.
    for (chunk_id, child_id) in find!(
        (chunk_id: Id, child_id: Id),
        pattern!(data, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::left: ?child_id,
        }])
    ) {
        if let Some(row) = rows.get_mut(&chunk_id) {
            row.children.push(child_id);
        }
    }

    for (chunk_id, child_id) in find!(
        (chunk_id: Id, child_id: Id),
        pattern!(data, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::right: ?child_id,
        }])
    ) {
        if let Some(row) = rows.get_mut(&chunk_id) {
            row.children.push(child_id);
        }
    }

    for (chunk_id, exec_result_id) in find!(
        (chunk_id: Id, exec_result_id: Id),
        pattern!(data, [{
            ?chunk_id @
            metadata::tag: playground_context::kind_chunk,
            playground_context::about_exec_result: ?exec_result_id,
        }])
    ) {
        if let Some(row) = rows.get_mut(&chunk_id) {
            row.about_exec_result = Some(exec_result_id);
        }
    }

    let mut list: Vec<ContextChunkRow> = rows.into_values().collect();
    let start_by_id: HashMap<Id, i128> = list
        .iter()
        .map(|row| (row.id, row.start_at.unwrap_or(i128::MAX)))
        .collect();
    for row in &mut list {
        row.children.sort_by_key(|child_id| {
            (
                start_by_id.get(child_id).copied().unwrap_or(i128::MAX),
                *child_id,
            )
        });
        row.children.dedup();
    }
    list.sort_by_key(|row| row.start_at.unwrap_or(i128::MIN));
    list
}

fn build_context_selected(
    ws: &mut Workspace<Pile>,
    chunks: &[ContextChunkRow],
    selected_chunk: Option<Id>,
    show_children: bool,
    show_origins: bool,
) -> Option<ContextSelectedRow> {
    let selected_chunk = selected_chunk?;
    let by_id: HashMap<Id, &ContextChunkRow> = chunks.iter().map(|row| (row.id, row)).collect();
    let row = by_id.get(&selected_chunk)?;

    let summary = load_text(ws, row.summary);
    let mut children = Vec::new();
    if show_children {
        for (child_index, child_id) in row.children.iter().copied().enumerate() {
            children.push(ContextChildRow {
                index: child_index,
                chunk_id: child_id,
                summary: by_id
                    .get(&child_id)
                    .and_then(|child| load_text(ws, child.summary)),
            });
        }
    }

    let mut origins = Vec::new();
    let mut origins_total = 0usize;
    if show_origins {
        let mut stack = vec![selected_chunk];
        let mut seen = HashSet::new();
        let mut leaves: Vec<Id> = Vec::new();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(node) = by_id.get(&id) else {
                continue;
            };
            let is_leaf = node.about_exec_result.is_some() || node.children.is_empty();
            if is_leaf {
                leaves.push(id);
                continue;
            }
            for child_id in &node.children {
                stack.push(*child_id);
            }
        }

        leaves.sort_by_key(|id| {
            by_id
                .get(id)
                .and_then(|row| row.start_at)
                .unwrap_or(i128::MIN)
        });
        origins_total = leaves.len();

        for leaf_id in leaves.into_iter().take(CONTEXT_ORIGIN_LIMIT) {
            let Some(leaf) = by_id.get(&leaf_id) else {
                continue;
            };
            origins.push(ContextLeafOriginRow {
                chunk_id: leaf_id,
                exec_result_id: leaf.about_exec_result,
                end_at: leaf.end_at,
                summary: load_text(ws, leaf.summary),
            });
        }
    }

    Some(ContextSelectedRow {
        chunk_id: selected_chunk,
        summary,
        children,
        origins_total,
        origins,
    })
}

fn build_activity_timeline(
    exec_rows: &[ExecRow],
    reasoning_rows: &[ReasoningSummaryRow],
    reason_rows: &[ReasonRow],
    local_rows: &[LocalMessageRow],
    local_me_id: Option<Id>,
    relation_labels: &HashMap<Id, String>,
    teams_rows: &[TeamsMessageRow],
    teams_chats: &[TeamsChatRow],
    compass_rows: &[(CompassTaskRow, usize)],
    compass_status_rows: &[CompassStatusRow],
    compass_notes: &HashMap<Id, Vec<CompassNoteRow>>,
    labels: &HashMap<Id, String>,
    limit: usize,
) -> (Vec<TimelineRow>, usize) {
    let limit = limit.max(1);
    let mut rows = Vec::new();

    for row in exec_rows {
        rows.push(TimelineRow {
            at: row.finished_at.or(row.started_at).or(row.requested_at),
            source: TimelineSource::Shell,
            event: TimelineEvent::Shell {
                request_id: row.request_id,
                status: row.status,
                command: row.command.clone(),
                worker_label: row.worker.map(|worker_id| format_id(labels, worker_id)),
                exit_code: row.exit_code,
                stdout_text: row.stdout_text.clone(),
                stderr_text: row.stderr_text.clone(),
                error: row.error.clone(),
            },
        });
    }

    for row in reasoning_rows {
        rows.push(TimelineRow {
            at: row.created_at,
            source: TimelineSource::Cognition,
            event: TimelineEvent::Cognition {
                summary: row.summary.clone(),
                input_tokens: row.input_tokens,
                output_tokens: row.output_tokens,
                cache_creation_input_tokens: row.cache_creation_input_tokens,
                cache_read_input_tokens: row.cache_read_input_tokens,
            },
        });
    }

    for row in reason_rows {
        rows.push(TimelineRow {
            at: row.created_at,
            source: TimelineSource::Cognition,
            event: TimelineEvent::Reason {
                text: row.text.clone(),
                turn_id: row.turn_id,
                worker_label: row.worker_id.map(|worker_id| format_id(labels, worker_id)),
                command_text: row.command_text.clone(),
            },
        });
    }

    for row in local_rows {
        let from_label = format_id(relation_labels, row.from_id);
        let to_label = format_id(relation_labels, row.to_id);
        let status = local_message_status(row, local_me_id, relation_labels);
        rows.push(TimelineRow {
            at: row.created_at,
            source: TimelineSource::LocalMessages,
            event: TimelineEvent::LocalMessage {
                from_id: row.from_id,
                to_id: row.to_id,
                from_label,
                to_label,
                status,
                body: row.body.clone(),
                is_sender: local_me_id == Some(row.from_id),
            },
        });
    }

    let mut team_chat_labels: HashMap<Id, String> = HashMap::new();
    for row in teams_chats {
        team_chat_labels.insert(row.id, row.label.clone());
    }
    for row in teams_rows {
        let author = row.author_name.as_deref().unwrap_or("unknown");
        let chat = team_chat_labels
            .get(&row.chat_id)
            .cloned()
            .unwrap_or_else(|| id_prefix(row.chat_id));
        rows.push(TimelineRow {
            at: row.created_at,
            source: TimelineSource::Teams,
            event: TimelineEvent::Teams {
                author: author.to_string(),
                chat_label: chat,
                content: row.content.clone(),
            },
        });
    }

    let mut goal_rows: HashMap<Id, CompassTaskRow> = HashMap::new();
    for (goal, _depth) in compass_rows {
        goal_rows.insert(goal.id, goal.clone());
        rows.push(TimelineRow {
            at: parse_compass_stamp(&goal.created_at),
            source: TimelineSource::Goals,
            event: TimelineEvent::GoalCreated { goal: goal.clone() },
        });
    }

    let fallback_goal = |task_id: Id| CompassTaskRow {
        id: task_id,
        id_prefix: id_prefix(task_id),
        title: format!("[{}]", id_prefix(task_id)),
        tags: Vec::new(),
        created_at: String::new(),
        status: "todo".to_string(),
        status_at: None,
        note_count: 0,
        parent: None,
    };

    for status in compass_status_rows {
        let mut goal = goal_rows
            .get(&status.task)
            .cloned()
            .unwrap_or_else(|| fallback_goal(status.task));
        goal.status = status.status.clone();
        goal.status_at = Some(status.at.clone());
        rows.push(TimelineRow {
            at: parse_compass_stamp(&status.at),
            source: TimelineSource::Goals,
            event: TimelineEvent::GoalStatus {
                goal,
                to_status: status.status.clone(),
            },
        });
    }

    for (task_id, notes) in compass_notes {
        let goal = goal_rows
            .get(task_id)
            .cloned()
            .unwrap_or_else(|| fallback_goal(*task_id));
        for note in notes {
            rows.push(TimelineRow {
                at: parse_compass_stamp(&note.at),
                source: TimelineSource::Goals,
                event: TimelineEvent::GoalNote {
                    goal: goal.clone(),
                    note: note.body.clone(),
                },
            });
        }
    }

    rows.sort_by_key(|row| row.at.unwrap_or(i128::MIN));
    rows.reverse();
    let total_rows = rows.len();
    if rows.len() > limit {
        rows.truncate(limit);
    }
    (rows, total_rows)
}

fn parse_compass_stamp(stamp: &str) -> Option<i128> {
    Epoch::from_gregorian_str(stamp).ok().map(epoch_key)
}

fn collect_compass_rows(
    data: &TribleSet,
    ws: &mut Workspace<Pile>,
) -> Vec<(CompassTaskRow, usize)> {
    let mut tasks: HashMap<Id, CompassTaskRow> = HashMap::new();

    for (task_id, title_handle, created_at) in find!(
        (
            task_id: Id,
            title_handle: Value<Handle<Blake3, LongString>>,
            created_at: String
        ),
        pattern!(&data, [{
            ?task_id @
            metadata::tag: &COMPASS_KIND_GOAL_ID,
            compass::title: ?title_handle,
            compass::created_at: ?created_at,
        }])
    ) {
        if tasks.contains_key(&task_id) {
            continue;
        }
        let title = load_text(ws, title_handle).unwrap_or_else(|| "<missing>".to_string());
        tasks.insert(
            task_id,
            CompassTaskRow {
                id: task_id,
                id_prefix: id_prefix(task_id),
                title,
                tags: Vec::new(),
                created_at,
                status: "todo".to_string(),
                status_at: None,
                note_count: 0,
                parent: None,
            },
        );
    }

    for (task_id, tag) in find!(
        (task_id: Id, tag: String),
        pattern!(&data, [{ ?task_id @ metadata::tag: &COMPASS_KIND_GOAL_ID, compass::tag: ?tag }])
    ) {
        if let Some(task) = tasks.get_mut(&task_id) {
            task.tags.push(tag);
        }
    }

    for (task_id, parent_id) in find!(
        (task_id: Id, parent_id: Id),
        pattern!(&data, [{
            ?task_id @
            metadata::tag: &COMPASS_KIND_GOAL_ID,
            compass::parent: ?parent_id,
        }])
    ) {
        if let Some(task) = tasks.get_mut(&task_id) {
            task.parent = Some(parent_id);
        }
    }

    let mut status_map: HashMap<Id, (String, String)> = HashMap::new();
    for (task_id, status, at) in find!(
        (task_id: Id, status: String, at: String),
        pattern!(&data, [{
            _?event @
            metadata::tag: &COMPASS_KIND_STATUS_ID,
            compass::task: ?task_id,
            compass::status: ?status,
            compass::at: ?at,
        }])
    ) {
        status_map
            .entry(task_id)
            .and_modify(|current| {
                if at > current.1 {
                    *current = (status.clone(), at.clone());
                }
            })
            .or_insert_with(|| (status, at));
    }

    let mut note_counts: HashMap<Id, usize> = HashMap::new();
    for task_id in find!(
        task_id: Id,
        pattern!(&data, [{
            _?event @
            metadata::tag: &COMPASS_KIND_NOTE_ID,
            compass::task: ?task_id,
        }])
    ) {
        *note_counts.entry(task_id).or_insert(0) += 1;
    }

    for task in tasks.values_mut() {
        if let Some((status, at)) = status_map.get(&task.id) {
            task.status = status.clone();
            task.status_at = Some(at.clone());
        }
        if let Some(count) = note_counts.get(&task.id) {
            task.note_count = *count;
        }
        task.tags.sort();
        task.tags.dedup();
    }

    order_compass_rows(tasks.into_values().collect())
}

fn collect_compass_status_rows(data: &TribleSet) -> Vec<CompassStatusRow> {
    let mut rows = Vec::new();
    for (task_id, status, at) in find!(
        (task_id: Id, status: String, at: String),
        pattern!(&data, [{
            _?event @
            metadata::tag: &COMPASS_KIND_STATUS_ID,
            compass::task: ?task_id,
            compass::status: ?status,
            compass::at: ?at,
        }])
    ) {
        rows.push(CompassStatusRow {
            task: task_id,
            status,
            at,
        });
    }
    rows.sort_by(|a, b| b.at.cmp(&a.at));
    rows
}

fn collect_compass_notes(
    data: &TribleSet,
    ws: &mut Workspace<Pile>,
) -> HashMap<Id, Vec<CompassNoteRow>> {
    let mut map: HashMap<Id, Vec<CompassNoteRow>> = HashMap::new();

    for (task_id, note_handle, at) in find!(
        (task_id: Id, note_handle: Value<Handle<Blake3, LongString>>, at: String),
        pattern!(&data, [{
            _?event @
            metadata::tag: &COMPASS_KIND_NOTE_ID,
            compass::task: ?task_id,
            compass::note: ?note_handle,
            compass::at: ?at,
        }])
    ) {
        let body = load_text(ws, note_handle).unwrap_or_else(|| "<missing>".to_string());
        map.entry(task_id)
            .or_default()
            .push(CompassNoteRow { at, body });
    }

    for notes in map.values_mut() {
        // ISO-like timestamps sort lexicographically.
        notes.sort_by(|a, b| b.at.cmp(&a.at));
    }

    map
}

fn order_compass_rows(rows: Vec<CompassTaskRow>) -> Vec<(CompassTaskRow, usize)> {
    let mut by_id: HashMap<Id, CompassTaskRow> = HashMap::new();
    for row in rows {
        by_id.insert(row.id, row);
    }
    let ids: HashSet<Id> = by_id.keys().copied().collect();
    let mut children: HashMap<Id, Vec<Id>> = HashMap::new();
    let mut roots = Vec::new();

    for (id, row) in &by_id {
        if let Some(parent) = row.parent {
            if ids.contains(&parent) {
                children.entry(parent).or_default().push(*id);
                continue;
            }
        }
        roots.push(*id);
    }

    // Ensure deterministic ordering even when multiple goals share the same
    // timestamp (created_at/status_at). Without a tie-breaker, stable sort will
    // preserve HashMap iteration order, which is intentionally randomized.
    let sort_ids = |items: &mut Vec<Id>| {
        items.sort_by(|a, b| {
            let a_row = by_id.get(a);
            let b_row = by_id.get(b);
            let a_key = a_row.map(|row| row.sort_key()).unwrap_or("");
            let b_key = b_row.map(|row| row.sort_key()).unwrap_or("");
            b_key
                .cmp(a_key)
                .then_with(|| {
                    let a_title = a_row.map(|row| row.title.as_str()).unwrap_or("");
                    let b_title = b_row.map(|row| row.title.as_str()).unwrap_or("");
                    a_title.cmp(b_title)
                })
                .then_with(|| a.cmp(b))
        });
    };

    sort_ids(&mut roots);
    for kids in children.values_mut() {
        sort_ids(kids);
    }

    let mut ordered = Vec::new();
    let mut visited = HashSet::new();

    fn walk(
        id: Id,
        depth: usize,
        by_id: &HashMap<Id, CompassTaskRow>,
        children: &HashMap<Id, Vec<Id>>,
        visited: &mut HashSet<Id>,
        out: &mut Vec<(CompassTaskRow, usize)>,
    ) {
        if !visited.insert(id) {
            return;
        }
        let Some(row) = by_id.get(&id) else {
            return;
        };
        out.push((row.clone(), depth));
        if let Some(kids) = children.get(&id) {
            for kid in kids {
                walk(*kid, depth + 1, by_id, children, visited, out);
            }
        }
    }

    for root in roots {
        walk(root, 0, &by_id, &children, &mut visited, &mut ordered);
    }

    let mut leftovers: Vec<Id> = by_id
        .keys()
        .copied()
        .filter(|id| !visited.contains(id))
        .collect();
    sort_ids(&mut leftovers);
    for id in leftovers {
        walk(id, 0, &by_id, &children, &mut visited, &mut ordered);
    }

    ordered
}

fn collect_labels(data: &TribleSet, ws: &mut Workspace<Pile>) -> HashMap<Id, String> {
    let mut map = HashMap::new();
    for (entity_id, handle) in find!(
        (entity_id: Id, handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{ ?entity_id @ metadata::name: ?handle }])
    ) {
        if let Some(label) = load_text(ws, handle) {
            map.entry(entity_id).or_insert(label);
        }
    }
    map
}

fn render_local_composer(
    ui: &mut egui::Ui,
    state: &mut DashboardState,
    branches: &[BranchEntry],
    snapshot: &DashboardSnapshot,
) {
    let me_label = snapshot
        .local_me_id
        .and_then(|id| snapshot.relations_labels.get(&id).cloned())
        .unwrap_or_else(|| state.config.local_me.clone());
    let peer_label = snapshot
        .local_peer_id
        .and_then(|id| snapshot.relations_labels.get(&id).cloned())
        .unwrap_or_else(|| state.config.local_peer.clone());

    ui.horizontal(|ui| {
        ui.label("Me");
        render_person_picker(
            ui,
            "local_me_picker",
            &snapshot.relations_people,
            snapshot.local_me_id,
            &mut state.config.local_me,
        );
        ui.add_space(10.0);
        ui.label("Peer");
        render_person_picker(
            ui,
            "local_peer_picker",
            &snapshot.relations_people,
            snapshot.local_peer_id,
            &mut state.config.local_peer,
        );
    });

    ui.small(format!("{me_label} → {peer_label}"));
    let me_known = snapshot.local_me_id.is_some();
    let peer_known = snapshot.local_peer_id.is_some();
    if !(me_known && peer_known) {
        ui.small("Select Me and Peer from Relations to enable sending.");
    }

    let response = ui.add_sized(
        [ui.available_width(), LOCAL_COMPOSE_HEIGHT],
        TextField::multiline(&mut state.local_draft),
    );
    if state.local_draft.trim().is_empty() && !response.has_focus() {
        let hint_pos = response.rect.left_top() + egui::vec2(10.0, 6.0);
        ui.painter().text(
            hint_pos,
            egui::Align2::LEFT_TOP,
            "Type a message...",
            egui::TextStyle::Small.resolve(ui.style()),
            ui.visuals().weak_text_color(),
        );
    }
    if response.changed() {
        state.local_send_error = None;
        state.local_send_notice = None;
    }

    ui.horizontal(|ui| {
        let can_send = me_known && peer_known && !state.local_draft.trim().is_empty();
        if ui.add_enabled(can_send, Button::new("Send")).clicked() {
            send_local_message_from_ui(state, branches, snapshot);
        }
        if ui.add(Button::new("Clear")).clicked() {
            state.local_draft.clear();
            state.local_send_error = None;
            state.local_send_notice = None;
        }
        if let Some(note) = &state.local_send_notice {
            ui.label(note);
        }
    });
    if let Some(err) = &state.local_send_error {
        ui.colored_label(egui::Color32::RED, err);
    }
}

fn render_person_picker(
    ui: &mut egui::Ui,
    id_salt: &'static str,
    people: &[RelationRow],
    selected: Option<Id>,
    raw: &mut String,
) {
    let selected_text = selected
        .and_then(|id| people.iter().find(|person| person.id == id))
        .map(|person| {
            let label = person.label.as_deref().unwrap_or("<unnamed>");
            format!("{label} ({})", id_prefix(person.id))
        })
        .unwrap_or_else(|| raw.trim().to_string());
    egui::ComboBox::from_id_salt(id_salt)
        .selected_text(selected_text)
        .show_ui(ui, |ui| {
            for person in people {
                let label = person.label.as_deref().unwrap_or("<unnamed>");
                let display = format!("{label} ({})", id_prefix(person.id));
                if ui
                    .selectable_label(selected == Some(person.id), display)
                    .clicked()
                {
                    // Persist a stable reference; labels/aliases can change.
                    *raw = format!("{:x}", person.id);
                }
            }
        });
}

fn render_branch_picker(
    ui: &mut egui::Ui,
    id_salt: &'static str,
    branches: &[BranchEntry],
    raw: &mut String,
) {
    if branches.is_empty() {
        return;
    }

    let mut name_counts: HashMap<String, usize> = HashMap::new();
    for branch in branches {
        if let Some(name) = branch.name.as_ref() {
            *name_counts.entry(name.clone()).or_insert(0) += 1;
        }
    }

    let refs = parse_branch_list(raw);
    let lookup = BranchLookup::new(branches);
    let selected_ids = resolve_branch_ids(&lookup, &refs).unwrap_or_default();

    let selected_text = if selected_ids.is_empty() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            "Pick...".to_string()
        } else {
            trimmed.to_string()
        }
    } else if selected_ids.len() == 1 {
        let id = selected_ids[0];
        branches
            .iter()
            .find(|branch| branch.id == id)
            .map(branch_display)
            .unwrap_or_else(|| format!("{} ({})", "<branch>", id_prefix(id)))
    } else {
        format!("{} branches", selected_ids.len())
    };

    let mut selected: HashSet<Id> = selected_ids.iter().copied().collect();
    let mut changed = false;
    egui::ComboBox::from_id_salt(id_salt)
        .selected_text(selected_text)
        .show_ui(ui, |ui| {
            if ui.button("Clear").clicked() {
                selected.clear();
                changed = true;
            }
            ui.separator();
            for branch in branches {
                let display = branch_display(branch);
                let mut is_selected = selected.contains(&branch.id);
                if ui.checkbox(&mut is_selected, display).changed() {
                    changed = true;
                    if is_selected {
                        selected.insert(branch.id);
                    } else {
                        selected.remove(&branch.id);
                    }
                }
            }
        });

    if changed {
        let mut parts = Vec::new();
        for branch in branches {
            if selected.contains(&branch.id) {
                parts.push(branch_ref(branch, &name_counts));
            }
        }
        *raw = parts.join(",");
    }
}

fn branch_display(branch: &BranchEntry) -> String {
    let name = branch.name.as_deref().unwrap_or("<unnamed>");
    format!("{name} ({})", id_prefix(branch.id))
}

fn branch_ref(branch: &BranchEntry, name_counts: &HashMap<String, usize>) -> String {
    if let Some(name) = branch.name.as_ref() {
        if !name.starts_with('<') && name_counts.get(name).copied().unwrap_or(0) == 1 {
            return name.clone();
        }
    }
    format!("{:x}", branch.id)
}

fn render_teams_conversations(
    ui: &mut egui::Ui,
    state: &mut DashboardState,
    now_key: i128,
    chats: &[TeamsChatRow],
    messages: &[TeamsMessageRow],
) {
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_min_width(TEAMS_CHAT_LIST_WIDTH);
            ui.set_min_height(TEAMS_SCROLL_HEIGHT);
            ui.label("Chats");
            let all_selected = state.teams_selected_chat.is_none();
            if ui.selectable_label(all_selected, "All chats").clicked() {
                state.teams_selected_chat = None;
            }
            ui.add_space(6.0);
            for chat in chats {
                let selected = state.teams_selected_chat == Some(chat.id);
                let label = format!("{} ({})", chat.label, chat.message_count);
                if ui.selectable_label(selected, label).clicked() {
                    state.teams_selected_chat = Some(chat.id);
                }
                ui.small(format_age(now_key, chat.last_at));
                ui.add_space(4.0);
            }
        });

        ui.add_space(12.0);

        ui.vertical(|ui| {
            ui.set_min_height(TEAMS_SCROLL_HEIGHT);
            let selected_chat = state.teams_selected_chat;
            let title = match selected_chat {
                Some(chat_id) => chats
                    .iter()
                    .find(|chat| chat.id == chat_id)
                    .map(|chat| chat.label.as_str())
                    .unwrap_or("Chat"),
                None => "All chats",
            };
            ui.label(title);

            for row in messages {
                if let Some(chat_id) = selected_chat {
                    if row.chat_id != chat_id {
                        continue;
                    }
                }
                let author = row.author_name.as_deref().unwrap_or("<unknown>");
                let age = format_age(now_key, row.created_at);
                let chat_label = chats
                    .iter()
                    .find(|chat| chat.id == row.chat_id)
                    .map(|chat| chat.label.as_str())
                    .unwrap_or("<chat>");

                let meta = if selected_chat.is_some() {
                    format!("{author} · {age}")
                } else {
                    format!("{chat_label} · {author} · {age}")
                };
                ui.small(meta);
                render_blob_aware_text(ui, row.content.as_str(), None, None);
                ui.add_space(8.0);
            }
        });
    });
}

fn render_blob_aware_text(
    ui: &mut egui::Ui,
    text: &str,
    text_color: Option<egui::Color32>,
    max_width: Option<f32>,
) {
    if text.is_empty() {
        return;
    }
    if let Some(max_width) = max_width {
        ui.set_max_width(max_width);
    }
    ui.horizontal_wrapped(|ui| {
        for chunk in split_blob_refs(text) {
            match chunk {
                PromptChunk::Text(text) => {
                    if text.is_empty() {
                        continue;
                    }
                    let mut rich = egui::RichText::new(text);
                    if let Some(color) = text_color {
                        rich = rich.color(color);
                    }
                    ui.add(egui::Label::new(rich).wrap_mode(egui::TextWrapMode::Wrap));
                }
                PromptChunk::Blob(blob) => {
                    render_blob_chip(ui, &blob, text_color);
                }
            }
        }
    });
}

fn render_blob_chip(
    ui: &mut egui::Ui,
    blob: &crate::blob_refs::BlobRef,
    text_color: Option<egui::Color32>,
) {
    let label = format!("files:{}", short_digest(blob.digest_hex.as_str()));
    let fill = colorhash::ral_categorical(blob.digest_hex.as_bytes());
    let chip_text = text_color.unwrap_or_else(|| colorhash::text_color_on(fill));
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).small().color(chip_text));
        });
}

fn short_digest(hex: &str) -> String {
    if hex.len() <= 12 {
        return hex.to_owned();
    }
    format!("{}…{}", &hex[..6], &hex[hex.len() - 4..])
}

fn send_local_message_from_ui(
    state: &mut DashboardState,
    branches: &[BranchEntry],
    snapshot: &DashboardSnapshot,
) {
    state.local_send_error = None;
    state.local_send_notice = None;

    let Some(repo) = state.repo.as_mut() else {
        state.local_send_error = Some("Repository not open.".to_string());
        return;
    };

    let body = state.local_draft.trim();
    if body.is_empty() {
        state.local_send_error = Some("Message is empty.".to_string());
        return;
    }

    let branch_lookup = BranchLookup::new(branches);
    let refs = parse_branch_list(&state.config.local_message_branches);
    let branch_id = match resolve_single_branch(&branch_lookup, &refs) {
        Ok(branch_id) => branch_id,
        Err(err) => {
            state.local_send_error = Some(err);
            return;
        }
    };

    let Some(from_id) = snapshot.local_me_id else {
        state.local_send_error = Some(format!(
            "Unknown me '{}' (check Relations branch).",
            state.config.local_me
        ));
        return;
    };
    let Some(to_id) = snapshot.local_peer_id else {
        state.local_send_error = Some(format!(
            "Unknown peer '{}' (check Relations branch).",
            state.config.local_peer
        ));
        return;
    };

    match send_local_message(repo, branch_id, from_id, to_id, body) {
        Ok(()) => {
            state.local_draft.clear();
            state.local_send_notice = Some("Message sent.".to_string());
        }
        Err(err) => {
            state.local_send_error = Some(err);
        }
    }
}

fn resolve_single_branch(lookup: &BranchLookup, refs: &[String]) -> Result<Id, String> {
    let ids = resolve_branch_ids(lookup, refs)?;
    if ids.is_empty() {
        return Err("Local message branch not found.".to_string());
    }
    if ids.len() > 1 {
        return Err("Select a single local message branch to send.".to_string());
    }
    Ok(ids[0])
}

fn send_local_message(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    from: Id,
    to: Id,
    body: &str,
) -> Result<(), String> {
    let mut ws = repo
        .pull(branch_id)
        .map_err(|err| format!("pull branch: {err:?}"))?;
    let mut change = ensure_local_metadata(&mut ws)?;

    let now = now_epoch();
    let now_interval: Value<NsTAIInterval> = (now, now).try_to_value().unwrap();
    let message_id = triblespace::prelude::ufoid();
    let body_handle = ws.put(body.to_string());
    change += entity! { &message_id @
        metadata::tag: &LOCAL_KIND_MESSAGE_ID,
        local_messages::from: from,
        local_messages::to: to,
        local_messages::body: body_handle,
        local_messages::created_at: now_interval,
    };

    ws.commit(change, "local message");
    repo.push(&mut ws)
        .map_err(|err| format!("push message: {err:?}"))?;
    Ok(())
}

fn ensure_local_metadata(ws: &mut Workspace<Pile>) -> Result<TribleSet, String> {
    let space = if ws.head().is_none() {
        TribleSet::new()
    } else {
        ws.checkout(..).map_err(|err| format!("checkout: {err}"))?
    };
    let mut change = TribleSet::new();

    let mut existing_kinds: HashSet<Id> = find!(
        kind: Id,
        pattern!(&space, [{ ?kind @ metadata::name: _?handle }])
    )
    .collect();

    for (id, label) in LOCAL_KIND_SPECS {
        if !existing_kinds.contains(&id) {
            let name_handle = label.to_owned().to_blob().get_handle::<Blake3>();
            change += entity! { ExclusiveId::force_ref(&id) @ metadata::name: name_handle };
            existing_kinds.insert(id);
        }
    }

    Ok(change)
}

#[derive(Debug, Clone)]
struct ProgressInfo {
    attempt: u64,
    started_at: Option<i128>,
    worker: Option<Id>,
}

#[derive(Debug, Clone)]
struct ResultInfo {
    attempt: u64,
    finished_at: Option<i128>,
    exit_code: Option<u64>,
    stdout_text: Option<String>,
    stderr_text: Option<String>,
    error: Option<String>,
}

fn load_attempts(data: &TribleSet) -> HashMap<Id, u64> {
    let mut attempts = HashMap::new();
    for (event_id, attempt) in find!(
        (event_id: Id, attempt: Value<U256BE>),
        pattern!(data, [{ ?event_id @ playground_exec::attempt: ?attempt }])
    ) {
        if let Some(value) = attempt.try_from_value::<u64>().ok() {
            attempts.insert(event_id, value);
        }
    }
    attempts
}

fn load_started_at(data: &TribleSet) -> HashMap<Id, i128> {
    let mut intervals = HashMap::new();
    for (event_id, interval) in find!(
        (event_id: Id, interval: Value<NsTAIInterval>),
        pattern!(data, [{ ?event_id @ playground_exec::started_at: ?interval }])
    ) {
        intervals.insert(event_id, interval_key(interval));
    }
    intervals
}

fn load_finished_at(data: &TribleSet) -> HashMap<Id, i128> {
    let mut intervals = HashMap::new();
    for (event_id, interval) in find!(
        (event_id: Id, interval: Value<NsTAIInterval>),
        pattern!(data, [{ ?event_id @ playground_exec::finished_at: ?interval }])
    ) {
        intervals.insert(event_id, interval_key(interval));
    }
    intervals
}

fn load_workers(data: &TribleSet) -> HashMap<Id, Id> {
    let mut workers = HashMap::new();
    for (event_id, worker) in find!(
        (event_id: Id, worker: Id),
        pattern!(data, [{ ?event_id @ playground_exec::worker: ?worker }])
    ) {
        workers.insert(event_id, worker);
    }
    workers
}

fn load_exit_codes(data: &TribleSet) -> HashMap<Id, u64> {
    let mut codes = HashMap::new();
    for (event_id, exit_code) in find!(
        (event_id: Id, exit_code: Value<U256BE>),
        pattern!(data, [{ ?event_id @ playground_exec::exit_code: ?exit_code }])
    ) {
        if let Some(code) = exit_code.try_from_value::<u64>().ok() {
            codes.insert(event_id, code);
        }
    }
    codes
}

fn load_output_text(
    data: &TribleSet,
    ws: &mut Workspace<Pile>,
    attr: Attribute<Handle<Blake3, LongString>>,
) -> HashMap<Id, String> {
    let mut outputs = HashMap::new();
    for (event_id, output_handle) in find!(
        (event_id: Id, output_handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{ ?event_id @ attr: ?output_handle }])
    ) {
        if let Some(text) = load_text(ws, output_handle) {
            outputs.insert(event_id, text);
        }
    }
    outputs
}

fn load_errors(data: &TribleSet, ws: &mut Workspace<Pile>) -> HashMap<Id, String> {
    let mut errors = HashMap::new();
    for (event_id, error_handle) in find!(
        (event_id: Id, error_handle: Value<Handle<Blake3, LongString>>),
        pattern!(data, [{ ?event_id @ playground_exec::error: ?error_handle }])
    ) {
        if let Some(text) = load_text(ws, error_handle) {
            errors.insert(event_id, text);
        }
    }
    errors
}

fn latest_progress(
    data: &TribleSet,
    attempts: &HashMap<Id, u64>,
    started_at: &HashMap<Id, i128>,
    workers: &HashMap<Id, Id>,
) -> HashMap<Id, ProgressInfo> {
    let mut progress: HashMap<Id, ProgressInfo> = HashMap::new();
    for (event_id, request_id) in find!(
        (event_id: Id, request_id: Id),
        pattern!(data, [{
            ?event_id @
            metadata::tag: playground_exec::kind_in_progress,
            playground_exec::about_request: ?request_id,
        }])
    ) {
        let attempt = attempts.get(&event_id).copied().unwrap_or(0);
        let started_at = started_at.get(&event_id).copied();
        let worker = workers.get(&event_id).copied();
        let info = ProgressInfo {
            attempt,
            started_at,
            worker,
        };
        progress
            .entry(request_id)
            .and_modify(|existing| {
                if info.attempt > existing.attempt
                    || (info.attempt == existing.attempt
                        && info.started_at.unwrap_or(i128::MIN)
                            > existing.started_at.unwrap_or(i128::MIN))
                {
                    *existing = info.clone();
                }
            })
            .or_insert(info);
    }
    progress
}

fn latest_results(
    data: &TribleSet,
    attempts: &HashMap<Id, u64>,
    finished_at: &HashMap<Id, i128>,
    exit_codes: &HashMap<Id, u64>,
    stdout_text: &HashMap<Id, String>,
    stderr_text: &HashMap<Id, String>,
    errors: &HashMap<Id, String>,
) -> HashMap<Id, ResultInfo> {
    let mut results: HashMap<Id, ResultInfo> = HashMap::new();
    for (event_id, request_id) in find!(
        (event_id: Id, request_id: Id),
        pattern!(data, [{
            ?event_id @
            metadata::tag: playground_exec::kind_command_result,
            playground_exec::about_request: ?request_id,
        }])
    ) {
        let attempt = attempts.get(&event_id).copied().unwrap_or(0);
        let finished_at = finished_at.get(&event_id).copied();
        let exit_code = exit_codes.get(&event_id).copied();
        let stdout_text = stdout_text.get(&event_id).cloned();
        let stderr_text = stderr_text.get(&event_id).cloned();
        let error = errors.get(&event_id).cloned();
        let info = ResultInfo {
            attempt,
            finished_at,
            exit_code,
            stdout_text,
            stderr_text,
            error,
        };
        results
            .entry(request_id)
            .and_modify(|existing| {
                if info.attempt > existing.attempt
                    || (info.attempt == existing.attempt
                        && info.finished_at.unwrap_or(i128::MIN)
                            > existing.finished_at.unwrap_or(i128::MIN))
                {
                    *existing = info.clone();
                }
            })
            .or_insert(info);
    }
    results
}

fn render_agent_config(
    ui: &mut egui::Ui,
    state: &mut DashboardState,
    now_key: i128,
    config: Option<&AgentConfigRow>,
) {
    let Some(config) = config else {
        ui.label("No config entries.");
        return;
    };

    let updated = format_age(now_key, config.updated_at);
    ui.label(format!(
        "Latest config: {} (updated {updated})",
        id_prefix(config.id)
    ));
    ui.add_space(8.0);

    egui::Grid::new("agent_config_grid")
        .striped(true)
        .spacing(egui::Vec2::new(12.0, 6.0))
        .show(ui, |ui| {
            ui.label("config_id");
            ui.monospace(format!("{:x}", config.id));
            ui.end_row();

            ui.label("persona_id");
            ui.monospace(
                config
                    .persona_id
                    .map(|id| format!("{id:x}"))
                    .unwrap_or_else(|| "-".to_string()),
            );
            ui.end_row();

            ui.label("branch");
            ui.label(config.branch.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label("author");
            ui.label(config.author.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label("author_role");
            ui.label(config.author_role.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label("poll_ms");
            ui.monospace(
                config
                    .poll_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
            ui.end_row();

            ui.label("model.profile");
            ui.horizontal(|ui| {
                ui.label(config.model_profile_name.as_deref().unwrap_or("-"));
                if let Some(id) = config.model_profile_id {
                    ui.monospace(format!("({id:x})"));
                }
            });
            ui.end_row();

            ui.label("model.model");
            ui.label(config.model_name.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label("model.base_url");
            ui.label(config.model_base_url.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label("model.reasoning_effort");
            ui.label(config.model_reasoning_effort.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label("model.stream");
            ui.monospace(
                config
                    .model_stream
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
            ui.end_row();

            ui.label("model.context_window_tokens");
            ui.monospace(
                config
                    .model_context_window_tokens
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
            ui.end_row();

            ui.label("model.max_output_tokens");
            ui.monospace(
                config
                    .model_max_output_tokens
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
            ui.end_row();

            ui.label("model.context_safety_margin_tokens");
            ui.monospace(
                config
                    .model_context_safety_margin_tokens
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
            ui.end_row();

            ui.label("model.chars_per_token");
            ui.monospace(
                config
                    .model_chars_per_token
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
            ui.end_row();

            ui.label("model.api_key");
            ui.horizontal(|ui| {
                let Some(key) = config.model_api_key.as_deref() else {
                    ui.label("-");
                    return;
                };
                if state.config_reveal_secrets {
                    ui.monospace(key);
                } else {
                    ui.monospace(mask_secret(key));
                }
                let button = if state.config_reveal_secrets {
                    "Hide"
                } else {
                    "Reveal"
                };
                if ui.add(Button::new(button)).clicked() {
                    state.config_reveal_secrets = !state.config_reveal_secrets;
                    ui.ctx().request_repaint();
                }
            });
            ui.end_row();

            ui.label("integrations.tavily_api_key");
            ui.horizontal(|ui| {
                let Some(key) = config.tavily_api_key.as_deref() else {
                    ui.label("-");
                    return;
                };
                if state.config_reveal_secrets {
                    ui.monospace(key);
                } else {
                    ui.monospace(mask_secret(key));
                }
                let button = if state.config_reveal_secrets {
                    "Hide"
                } else {
                    "Reveal"
                };
                if ui.add(Button::new(button)).clicked() {
                    state.config_reveal_secrets = !state.config_reveal_secrets;
                    ui.ctx().request_repaint();
                }
            });
            ui.end_row();

            ui.label("integrations.exa_api_key");
            ui.horizontal(|ui| {
                let Some(key) = config.exa_api_key.as_deref() else {
                    ui.label("-");
                    return;
                };
                if state.config_reveal_secrets {
                    ui.monospace(key);
                } else {
                    ui.monospace(mask_secret(key));
                }
                let button = if state.config_reveal_secrets {
                    "Hide"
                } else {
                    "Reveal"
                };
                if ui.add(Button::new(button)).clicked() {
                    state.config_reveal_secrets = !state.config_reveal_secrets;
                    ui.ctx().request_repaint();
                }
            });
            ui.end_row();

            ui.label("exec.default_cwd");
            ui.label(config.exec_default_cwd.as_deref().unwrap_or("-"));
            ui.end_row();

            ui.label("exec.sandbox_profile");
            ui.monospace(
                config
                    .exec_sandbox_profile
                    .map(|id| format!("{id:x}"))
                    .unwrap_or_else(|| "-".to_string()),
            );
            ui.end_row();
        });

    if let Some(prompt) = config.system_prompt.as_deref() {
        ui.add_space(8.0);
        ui.label(egui::RichText::new("System prompt").monospace());
        egui::Frame::NONE
            .fill(egui::Color32::from_gray(55))
            .corner_radius(egui::CornerRadius::same(6))
            .inner_margin(egui::Margin::symmetric(10, 8))
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(egui::RichText::new(prompt).monospace())
                        .wrap_mode(egui::TextWrapMode::Wrap),
                );
            });
    }
}

fn mask_secret(secret: &str) -> String {
    let len = secret.chars().count();
    if len == 0 {
        return "<empty>".to_string();
    }
    if len <= 8 {
        return "*".repeat(len);
    }
    let prefix: String = secret.chars().take(4).collect();
    let suffix: String = secret
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{prefix}…{suffix}")
}

fn render_activity_timeline(ui: &mut egui::Ui, now_key: i128, rows: &[TimelineRow]) -> Option<Id> {
    let mut context_clicked = None;
    let max_height = if diagnostics_is_headless() {
        1800.0
    } else {
        ACTIVITY_TIMELINE_HEIGHT
    };
    let min_scrolled_height = if diagnostics_is_headless() {
        320.0
    } else {
        ACTIVITY_TIMELINE_HEIGHT
    };
    egui::ScrollArea::vertical()
        .id_salt("activity_timeline_scroll")
        .auto_shrink([false, false])
        .min_scrolled_height(min_scrolled_height)
        .max_height(max_height)
        .show(ui, |ui| {
            for row in rows {
                if let Some(id) = render_timeline_row(ui, now_key, row) {
                    context_clicked = Some(id);
                }
                ui.add_space(8.0);
            }
        });
    context_clicked
}

fn turn_memory_role_style(role: ChatRole) -> (&'static str, egui::Color32) {
    match role {
        ChatRole::System => ("system", egui::Color32::from_rgb(104, 122, 151)),
        ChatRole::User => ("user", egui::Color32::from_rgb(82, 138, 118)),
        ChatRole::Assistant => ("assistant", egui::Color32::from_rgb(120, 108, 166)),
    }
}

fn render_context_compaction(
    ui: &mut egui::Ui,
    state: &mut DashboardState,
    now_key: i128,
    chunks: &[ContextChunkRow],
    selected: Option<&ContextSelectedRow>,
) {
    let by_id: HashMap<Id, &ContextChunkRow> = chunks.iter().map(|row| (row.id, row)).collect();

    let mut children: HashSet<Id> = HashSet::new();
    for row in chunks {
        for child_id in &row.children {
            children.insert(*child_id);
        }
    }

    let mut roots: Vec<&ContextChunkRow> = chunks
        .iter()
        .filter(|row| !children.contains(&row.id))
        .collect();
    roots.sort_by_key(|row| row.start_at.unwrap_or(i128::MIN));

    let mut leaf_counts: HashMap<Id, usize> = HashMap::new();

    ui.horizontal_wrapped(|ui| {
        ui.label("Frontier:");
        for root in &roots {
            let count = context_leaf_count(root.id, &by_id, &mut leaf_counts);
            let label = format!("{} ({})", id_prefix(root.id), count);
            if ui.add(Button::new(label)).clicked() {
                state.context_selection_stack.clear();
                state.context_selected_chunk = Some(root.id);
                state.context_show_origins = false;
                ui.ctx().request_repaint();
            }
        }
    });
    ui.add_space(8.0);

    let max_height = if diagnostics_is_headless() {
        1200.0
    } else {
        CONTEXT_TREE_HEIGHT
    };
    egui::ScrollArea::vertical()
        .id_salt("context_compaction_scroll")
        .auto_shrink([false, false])
        .max_height(max_height)
        .show(ui, |ui| {
            for root in roots {
                render_context_chunk_node(ui, state, now_key, &by_id, root.id, &mut leaf_counts);
                ui.add_space(6.0);
            }
        });

    ui.add_space(8.0);
    render_context_selected_details(ui, state, now_key, &by_id, &mut leaf_counts, selected);
}

fn context_leaf_count(
    node_id: Id,
    by_id: &HashMap<Id, &ContextChunkRow>,
    memo: &mut HashMap<Id, usize>,
) -> usize {
    if let Some(count) = memo.get(&node_id) {
        return *count;
    }
    let Some(node) = by_id.get(&node_id) else {
        memo.insert(node_id, 0);
        return 0;
    };
    let is_leaf = node.about_exec_result.is_some() || node.children.is_empty();
    if is_leaf {
        memo.insert(node_id, 1);
        return 1;
    }

    let mut count = 0usize;
    for child_id in &node.children {
        count = count.saturating_add(context_leaf_count(*child_id, by_id, memo));
    }
    memo.insert(node_id, count);
    count
}

fn render_context_chunk_node(
    ui: &mut egui::Ui,
    state: &mut DashboardState,
    now_key: i128,
    by_id: &HashMap<Id, &ContextChunkRow>,
    node_id: Id,
    leaf_counts: &mut HashMap<Id, usize>,
) {
    let Some(node) = by_id.get(&node_id) else {
        ui.monospace(format!("<missing chunk {}>", id_prefix(node_id)));
        return;
    };
    let selected = state.context_selected_chunk == Some(node_id);
    let count = context_leaf_count(node_id, by_id, leaf_counts);
    let start = format_age(now_key, node.start_at);
    let end = format_age(now_key, node.end_at);

    let mut label = format!(
        "{}{} {start}..{end} leaves:{count}",
        if selected { "*" } else { " " },
        id_prefix(node.id),
    );
    if let Some(exec_id) = node.about_exec_result {
        label.push_str(&format!("  exec:{}", id_prefix(exec_id)));
    }

    let response = egui::CollapsingHeader::new(egui::RichText::new(label).monospace())
        .id_salt(format!("context_chunk::{node_id:x}"))
        .show(ui, |ui| {
            for child_id in &node.children {
                render_context_chunk_node(ui, state, now_key, by_id, *child_id, leaf_counts);
            }
        });

    if response.header_response.clicked() {
        state.context_selection_stack.clear();
        state.context_selected_chunk = Some(node_id);
        state.context_show_origins = false;
        ui.ctx().request_repaint();
    }
}

fn render_context_selected_details(
    ui: &mut egui::Ui,
    state: &mut DashboardState,
    now_key: i128,
    by_id: &HashMap<Id, &ContextChunkRow>,
    leaf_counts: &mut HashMap<Id, usize>,
    selected: Option<&ContextSelectedRow>,
) {
    let Some(selected_id) = state.context_selected_chunk else {
        ui.small("Tip: click a chunk header to inspect its summary and leaf origins.");
        return;
    };

    let Some(node) = by_id.get(&selected_id) else {
        ui.colored_label(
            egui::Color32::RED,
            format!(
                "Selected chunk {} is missing from catalog.",
                id_prefix(selected_id)
            ),
        );
        return;
    };

    let count = context_leaf_count(selected_id, by_id, leaf_counts);
    let start = format_age(now_key, node.start_at);
    let end = format_age(now_key, node.end_at);
    ui.monospace(format!(
        "selected: {} {start}..{end} leaves:{count}",
        id_prefix(node.id)
    ));

    ui.horizontal(|ui| {
        if !state.context_selection_stack.is_empty() {
            if ui.add(Button::new("Back")).clicked() {
                if let Some(prev) = state.context_selection_stack.pop() {
                    state.context_selected_chunk = Some(prev);
                    state.context_show_origins = false;
                    ui.ctx().request_repaint();
                }
            }
        }

        let children_button = if state.context_show_children {
            "Hide split"
        } else {
            "Split"
        };
        if ui.add(Button::new(children_button)).clicked() {
            state.context_show_children = !state.context_show_children;
            ui.ctx().request_repaint();
        }

        let button = if state.context_show_origins {
            "Hide leaves"
        } else {
            "List leaves"
        };
        if ui.add(Button::new(button)).clicked() {
            state.context_show_origins = !state.context_show_origins;
            ui.ctx().request_repaint();
        }
        if ui.add(Button::new("Clear selection")).clicked() {
            state.context_selected_chunk = None;
            state.context_selection_stack.clear();
            state.context_show_children = false;
            state.context_show_origins = false;
            ui.ctx().request_repaint();
        }
    });

    let selected = match selected {
        Some(row) if row.chunk_id == selected_id => Some(row),
        _ => None,
    };

    if let Some(summary) = selected.and_then(|row| row.summary.as_deref()) {
        ui.add(
            egui::Label::new(egui::RichText::new(summary).monospace())
                .wrap()
                .selectable(false),
        );
    } else {
        ui.small("<no summary loaded>");
    }

    if state.context_show_children {
        ui.add_space(8.0);
        let Some(selected) = selected else {
            ui.small("Loading split…");
            return;
        };
        if selected.children.is_empty() {
            ui.small("No children (leaf chunk).");
        }
        for child in &selected.children {
            let Some(child_node) = by_id.get(&child.chunk_id) else {
                ui.colored_label(
                    egui::Color32::RED,
                    format!(
                        "missing child[{}] {}",
                        child.index,
                        id_prefix(child.chunk_id)
                    ),
                );
                continue;
            };
            let child_count = context_leaf_count(child.chunk_id, by_id, leaf_counts);
            let child_start = format_age(now_key, child_node.start_at);
            let child_end = format_age(now_key, child_node.end_at);

            egui::Frame::NONE
                .stroke(egui::Stroke::new(
                    1.0,
                    egui::Color32::from_rgb(210, 210, 210),
                ))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.monospace(format!(
                            "child[{}]: {} {child_start}..{child_end} leaves:{child_count}",
                            child.index,
                            id_prefix(child.chunk_id),
                        ));
                        if ui.add(Button::new("Focus")).clicked() {
                            state.context_selection_stack.push(selected_id);
                            state.context_selected_chunk = Some(child.chunk_id);
                            state.context_show_origins = false;
                            ui.ctx().request_repaint();
                        }
                    });

                    let summary = child
                        .summary
                        .as_deref()
                        .unwrap_or("<missing child summary>");
                    ui.add(
                        egui::Label::new(egui::RichText::new(summary).monospace())
                            .wrap()
                            .selectable(false),
                    );
                });
            ui.add_space(6.0);
        }
    }

    if !state.context_show_origins {
        return;
    }

    let Some(selected) = selected else {
        ui.small("Loading leaves…");
        return;
    };
    ui.add_space(8.0);
    ui.small(format!(
        "leaves: {} leaf chunk(s) (showing up to {})",
        selected.origins_total, CONTEXT_ORIGIN_LIMIT
    ));

    for origin in &selected.origins {
        let age = format_age(now_key, origin.end_at);
        let exec = origin
            .exec_result_id
            .map(id_prefix)
            .unwrap_or_else(|| "-".to_string());
        let title = format!("{age}  leaf {}  exec:{exec}", id_prefix(origin.chunk_id));
        egui::CollapsingHeader::new(egui::RichText::new(title).monospace())
            .id_salt(format!("context_origin::{:x}", origin.chunk_id))
            .default_open(false)
            .show(ui, |ui| {
                if ui.add(Button::new("Focus")).clicked() {
                    state.context_selection_stack.push(selected_id);
                    state.context_selected_chunk = Some(origin.chunk_id);
                    ui.ctx().request_repaint();
                }
                let summary = origin
                    .summary
                    .as_deref()
                    .unwrap_or("<missing leaf summary>");
                ui.add(
                    egui::Label::new(egui::RichText::new(summary).monospace())
                        .wrap()
                        .selectable(false),
                );
            });
    }
}

fn render_timeline_row(ui: &mut egui::Ui, now_key: i128, row: &TimelineRow) -> Option<Id> {
    let mut context_clicked = None;
    let (source_label, source_color) = timeline_source_style(row.source);
    ui.horizontal_wrapped(|ui| {
        ui.small(format_age(now_key, row.at));
        render_timeline_source_chip(ui, source_label, source_color);
    });

    match &row.event {
        TimelineEvent::Shell {
            request_id,
            status,
            command,
            worker_label,
            exit_code,
            stdout_text,
            stderr_text,
            error,
        } => {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("{}: {}", exec_status_text(*status), command));
                if ui.small_button("ctx").on_hover_text("Show model context for this turn").clicked() {
                    context_clicked = Some(*request_id);
                }
            });
            let mut details = Vec::new();
            details.push(format!("req {}", id_prefix(*request_id)));
            if let Some(worker_label) = worker_label.as_deref() {
                details.push(format!("worker {worker_label}"));
            }
            if let Some(code) = exit_code {
                details.push(format!("exit {code}"));
            }
            if !details.is_empty() {
                ui.small(details.join(" · "));
            }

            let has_stdout = stdout_text
                .as_deref()
                .is_some_and(|text| !text.trim().is_empty());
            let has_stderr = stderr_text
                .as_deref()
                .is_some_and(|text| !text.trim().is_empty());
            let has_error = error.as_deref().is_some_and(|text| !text.trim().is_empty());
            if has_stdout || has_stderr || has_error {
                let mut output_meta = Vec::new();
                if let Some(text) = stdout_text.as_deref() {
                    let chars = text.chars().count();
                    if chars > 0 {
                        output_meta.push(format!("stdout {chars}c"));
                    }
                }
                if let Some(text) = stderr_text.as_deref() {
                    let chars = text.chars().count();
                    if chars > 0 {
                        output_meta.push(format!("stderr {chars}c"));
                    }
                }
                if has_error {
                    output_meta.push("error".to_string());
                }
                let title = if output_meta.is_empty() {
                    "Output".to_string()
                } else {
                    format!("Output ({})", output_meta.join(" · "))
                };
                egui::CollapsingHeader::new(title)
                    .id_salt(format!("timeline_shell_output_{request_id:x}"))
                    .default_open(false)
                    .show(ui, |ui| {
                        if let Some(text) = stdout_text
                            .as_deref()
                            .filter(|text| !text.trim().is_empty())
                        {
                            ui.small("stdout");
                            render_blob_aware_text(ui, text, None, None);
                        }
                        if let Some(text) = stderr_text
                            .as_deref()
                            .filter(|text| !text.trim().is_empty())
                        {
                            ui.small("stderr");
                            render_blob_aware_text(ui, text, Some(egui::Color32::LIGHT_RED), None);
                        }
                        if let Some(text) = error.as_deref().filter(|text| !text.trim().is_empty())
                        {
                            ui.small("error");
                            ui.colored_label(egui::Color32::LIGHT_RED, text);
                        }
                    });
            }
        }
        TimelineEvent::Cognition {
            summary,
            input_tokens,
            output_tokens,
            cache_creation_input_tokens,
            cache_read_input_tokens,
        } => {
            ui.add(
                egui::Label::new(egui::RichText::new(summary).monospace())
                    .wrap_mode(egui::TextWrapMode::Wrap),
            );
            if input_tokens.is_some() || output_tokens.is_some() {
                let f = |v: &Option<u64>| -> String {
                    v.map_or("-".into(), |n| n.to_string())
                };
                ui.small(format!(
                    "in={} out={} cache_r={} cache_w={}",
                    f(input_tokens),
                    f(output_tokens),
                    f(cache_read_input_tokens),
                    f(cache_creation_input_tokens),
                ));
            }
        }
        TimelineEvent::Reason {
            text,
            turn_id,
            worker_label,
            command_text,
        } => {
            ui.small("reason");
            ui.add(
                egui::Label::new(egui::RichText::new(text).monospace())
                    .wrap_mode(egui::TextWrapMode::Wrap),
            );
            let mut details = Vec::new();
            if let Some(turn_id) = turn_id {
                details.push(format!("turn {}", id_prefix(*turn_id)));
            }
            if let Some(worker_label) = worker_label.as_deref() {
                details.push(format!("worker {worker_label}"));
            }
            if !details.is_empty() {
                ui.small(details.join(" · "));
            }
            if let Some(command_text) = command_text {
                ui.small(format!("act: {command_text}"));
            }
        }
        TimelineEvent::Teams {
            author,
            chat_label,
            content,
        } => {
            ui.small(format!("{author} in {chat_label}"));
            render_blob_aware_text(ui, content, None, None);
        }
        TimelineEvent::LocalMessage {
            from_id,
            to_id,
            from_label,
            to_label,
            status,
            body,
            is_sender,
        } => {
            render_timeline_local_message(
                ui, *from_id, *to_id, from_label, to_label, status, body, *is_sender, now_key,
                row.at,
            );
        }
        TimelineEvent::GoalCreated { goal } => {
            render_timeline_goal_event(ui, goal, None);
        }
        TimelineEvent::GoalStatus { goal, to_status } => {
            render_timeline_goal_event(ui, goal, Some(format!("status -> {to_status}")));
        }
        TimelineEvent::GoalNote { goal, note } => {
            render_timeline_goal_event(ui, goal, Some(format!("note: {note}")));
        }
    }
    context_clicked
}

fn timeline_source_style(source: TimelineSource) -> (&'static str, egui::Color32) {
    match source {
        TimelineSource::Shell => ("shell", egui::Color32::from_rgb(92, 132, 201)),
        TimelineSource::Cognition => ("mind", egui::Color32::from_rgb(123, 107, 168)),
        TimelineSource::Teams => ("teams", egui::Color32::from_rgb(69, 124, 184)),
        TimelineSource::LocalMessages => ("local", egui::Color32::from_rgb(67, 149, 112)),
        TimelineSource::Goals => ("goals", egui::Color32::from_rgb(202, 168, 68)),
    }
}

fn render_timeline_source_chip(ui: &mut egui::Ui, label: &str, fill: egui::Color32) {
    let text_color = colorhash::text_color_on(fill);
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(5))
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).small().color(text_color));
        });
}

#[allow(clippy::too_many_arguments)]
fn render_timeline_local_message(
    ui: &mut egui::Ui,
    from_id: Id,
    to_id: Id,
    from_label: &str,
    to_label: &str,
    status: &LocalMessageStatus,
    body: &str,
    is_sender: bool,
    now_key: i128,
    at: Option<i128>,
) {
    let bubble_width = (ui.available_width() * 0.75).max(220.0);
    let age = format_age(now_key, at);
    let meta = format!("{age} · {}", local_message_status_text(status));
    let align = if is_sender {
        egui::Layout::right_to_left(egui::Align::TOP)
    } else {
        egui::Layout::left_to_right(egui::Align::TOP)
    };
    let from_chip_color = colorhash::ral_categorical(from_id.as_ref());
    let to_chip_color = colorhash::ral_categorical(to_id.as_ref());
    let bubble_color = from_chip_color;
    let text_color = colorhash::text_color_on(bubble_color);

    ui.with_layout(align, |ui| {
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                render_person_chip(ui, from_label, from_chip_color);
                ui.small("→");
                render_person_chip(ui, to_label, to_chip_color);
                ui.add_space(6.0);
                render_local_status_chip(ui, status);
            });
            egui::Frame::NONE
                .fill(bubble_color)
                .corner_radius(egui::CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    ui.set_max_width(bubble_width);
                    render_blob_aware_text(ui, body, Some(text_color), Some(bubble_width));
                });
            ui.small(meta);
        });
    });
}

fn render_timeline_goal_event(ui: &mut egui::Ui, goal: &CompassTaskRow, detail: Option<String>) {
    render_goal_card(ui, goal, 0.0);
    if let Some(detail) = detail {
        ui.add(
            egui::Label::new(egui::RichText::new(detail).monospace())
                .wrap_mode(egui::TextWrapMode::Wrap),
        );
    }
}

fn render_compass_swimlanes(
    ui: &mut egui::Ui,
    expanded_goal: &mut Option<Id>,
    rows: &[(CompassTaskRow, usize)],
    notes: &HashMap<Id, Vec<CompassNoteRow>>,
) {
    if rows.is_empty() {
        ui.label("No goals yet.");
        return;
    }

    let render_lanes = |ui: &mut egui::Ui| {
        ui.spacing_mut().item_spacing.y = 0.0;

        let mut counts: HashMap<&str, usize> = HashMap::new();
        let mut extra_statuses: HashSet<&str> = HashSet::new();
        for (row, _) in rows {
            *counts.entry(row.status.as_str()).or_insert(0) += 1;
            if !COMPASS_DEFAULT_STATUSES.contains(&row.status.as_str()) {
                extra_statuses.insert(row.status.as_str());
            }
        }

        // Always show the canonical lanes (including done) so the UI keeps its shape.
        let mut statuses: Vec<String> = COMPASS_DEFAULT_STATUSES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let mut extras: Vec<&str> = extra_statuses.into_iter().collect();
        extras.sort();
        statuses.extend(extras.into_iter().map(|s| s.to_string()));

        for status in statuses {
            let count = counts.get(status.as_str()).copied().unwrap_or(0);
            render_compass_swimlane(ui, expanded_goal, notes, rows, &status, count);
        }
    };

    // Headless captures render each card into a GPU texture; clamp height to avoid
    // exceeding backend texture limits when there are many goals.
    if diagnostics_is_headless() {
        egui::ScrollArea::vertical()
            .id_salt("compass_headless_scroll")
            .max_height(1600.0)
            .show(ui, |ui| ui.scope(render_lanes));
    } else {
        ui.scope(render_lanes);
    }
}

fn render_compass_swimlane(
    ui: &mut egui::Ui,
    expanded_goal: &mut Option<Id>,
    notes: &HashMap<Id, Vec<CompassNoteRow>>,
    rows: &[(CompassTaskRow, usize)],
    status: &str,
    count: usize,
) {
    egui::Frame::NONE
        .inner_margin(egui::Margin {
            left: 12,
            right: 12,
            top: 10,
            bottom: 10,
        })
        .show(ui, |ui| {
            // Fill the full card width; otherwise Frames can shrink to content.
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new(format!("{} ({count})", status.to_uppercase()))
                    .monospace()
                    .strong()
                    .color(status_color(status)),
            );
            ui.add_space(6.0);

            if count == 0 {
                ui.small("(empty)");
                return;
            }

            for (row, depth) in rows {
                if row.status != status {
                    continue;
                }
                render_compass_swimlane_row(ui, expanded_goal, notes, row, *depth);
                ui.add_space(6.0);
            }
        });
}

fn status_color(status: &str) -> egui::Color32 {
    match status {
        // Status colors: ready (green), caution (yellow), danger (red), ice (blue).
        "todo" => egui::Color32::from_rgb(70, 150, 95),
        "doing" => egui::Color32::from_rgb(200, 170, 60),
        "blocked" => egui::Color32::from_rgb(170, 70, 70),
        "done" => egui::Color32::from_rgb(65, 110, 170),
        _ => egui::Color32::from_rgb(95, 95, 95),
    }
}

fn draw_goal_status_bar(ui: &egui::Ui, rect: egui::Rect, color: egui::Color32) {
    // Draw inside the border so the thin outline stays crisp.
    let inset = 1.0;
    let bar_height = 4.0;
    let min = egui::pos2(rect.left() + inset, rect.top() + inset);
    let max = egui::pos2(rect.right() - inset, rect.top() + inset + bar_height);
    ui.painter()
        .rect_filled(egui::Rect::from_min_max(min, max), 0.0, color);
}

fn goal_right_text(row: &CompassTaskRow) -> String {
    let mut right_parts: Vec<String> = Vec::new();
    if !row.tags.is_empty() {
        right_parts.push(
            row.tags
                .iter()
                .map(|tag| format!("#{tag}"))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }
    if row.note_count > 0 {
        right_parts.push(format!("{}n", row.note_count));
    }
    if let Some(parent) = row.parent {
        right_parts.push(format!("^{}", id_prefix(parent)));
    }
    right_parts.push(format!("[{}]", row.id_prefix));
    right_parts.join(" · ")
}

fn render_goal_card(ui: &mut egui::Ui, row: &CompassTaskRow, dep_indent: f32) -> egui::Response {
    let right_text = goal_right_text(row);
    let outline = ui.visuals().widgets.noninteractive.bg_stroke;
    let bar_color = status_color(&row.status);
    let inner = ui
        .horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            if dep_indent > 0.0 {
                ui.add_space(dep_indent);
            }

            egui::Frame::NONE
                .fill(egui::Color32::TRANSPARENT)
                .stroke(outline)
                .corner_radius(egui::CornerRadius::same(0))
                .inner_margin(egui::Margin {
                    left: 10,
                    right: 10,
                    top: 6,
                    bottom: 6,
                })
                .show(ui, |ui| {
                    // Fill the full remaining width so cards don't shrink to just their text.
                    let available_width = ui.available_width();
                    ui.set_min_width(available_width);

                    let title = row.title.clone();
                    ui.horizontal(|ui| {
                        let right_width = if right_text.is_empty() {
                            0.0
                        } else {
                            let font_id = egui::TextStyle::Monospace.resolve(ui.style());
                            ui.fonts_mut(|fonts| {
                                fonts
                                    .layout_no_wrap(
                                        right_text.clone(),
                                        font_id,
                                        egui::Color32::WHITE,
                                    )
                                    .size()
                                    .x
                            })
                        };
                        let gap = 12.0;
                        let title_width = (ui.available_width() - right_width - gap).max(40.0);
                        ui.add_sized(
                            [title_width, 0.0],
                            egui::Label::new(egui::RichText::new(title).monospace())
                                .halign(egui::Align::LEFT)
                                .wrap_mode(egui::TextWrapMode::Truncate),
                        );
                        ui.allocate_ui_with_layout(
                            egui::vec2(ui.available_width(), 0.0),
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if !right_text.is_empty() {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&right_text).monospace(),
                                        )
                                        .halign(egui::Align::RIGHT)
                                        .wrap_mode(egui::TextWrapMode::Truncate),
                                    );
                                }
                            },
                        );
                    });
                })
        })
        .inner;

    draw_goal_status_bar(ui, inner.response.rect, bar_color);
    inner.response
}

fn render_compass_swimlane_row(
    ui: &mut egui::Ui,
    expanded_goal: &mut Option<Id>,
    notes: &HashMap<Id, Vec<CompassNoteRow>>,
    row: &CompassTaskRow,
    depth: usize,
) {
    // Show hierarchy via left-side lines (outside the goal box). Deeper goals
    // shift right a bit so the box "shrinks" from the left.
    const DEP_LINE_STEP: f32 = 6.0;
    const DEP_LINE_BASE: f32 = 8.0;
    let dep_lines = depth.min(3);
    let dep_indent = if dep_lines == 0 {
        0.0
    } else {
        (dep_lines as f32 * DEP_LINE_STEP) + DEP_LINE_BASE
    };

    let is_expanded = *expanded_goal == Some(row.id);
    let outline = ui.visuals().widgets.noninteractive.bg_stroke;
    let response_rect = render_goal_card(ui, row, dep_indent).rect;

    // Make the whole row clickable to toggle note display.
    let click_id = ui.make_persistent_id(("compass_goal", row.id));
    let response = ui.interact(response_rect, click_id, egui::Sense::click());
    if response.clicked() {
        if *expanded_goal == Some(row.id) {
            *expanded_goal = None;
        } else {
            *expanded_goal = Some(row.id);
        }
    }

    if depth == 0 {
        // still allow expansion
    }

    if is_expanded {
        let task_notes = notes.get(&row.id).map(Vec::as_slice).unwrap_or(&[]);
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            if dep_indent > 0.0 {
                ui.add_space(dep_indent);
            }
            egui::Frame::NONE
                .fill(egui::Color32::TRANSPARENT)
                .stroke(outline)
                .corner_radius(egui::CornerRadius::same(0))
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    let available_width = ui.available_width();
                    ui.set_min_width(available_width);
                    ui.set_max_width(available_width);

                    // Frame::show inherits the current layout; force a vertical stack for notes.
                    ui.with_layout(egui::Layout::top_down(egui::Align::LEFT), |ui| {
                        if task_notes.is_empty() {
                            ui.small("(no notes)");
                            return;
                        }
                        for note in task_notes {
                            ui.small(&note.at);
                            ui.add(
                                egui::Label::new(egui::RichText::new(&note.body))
                                    .wrap_mode(egui::TextWrapMode::Wrap),
                            );
                            ui.add_space(6.0);
                        }
                    });
                });
        });
        ui.add_space(6.0);
    }

    // Draw a small "dependency gutter" to the left of the goal box.
    let rect = response_rect;
    let painter = ui.painter();
    let stroke = egui::Stroke::new(1.2, egui::Color32::from_gray(130));
    for idx in 0..dep_lines {
        let x = rect.left() - dep_indent + 4.0 + (idx as f32 * DEP_LINE_STEP);
        let y1 = rect.top() + 0.5;
        let y2 = rect.bottom() - 0.5;
        painter.line_segment([egui::pos2(x, y1), egui::pos2(x, y2)], stroke);
    }
}

fn local_message_status(
    row: &LocalMessageRow,
    me_id: Option<Id>,
    labels: &HashMap<Id, String>,
) -> LocalMessageStatus {
    let read_by = |reader_id: Id| row.readers.iter().any(|id| *id == reader_id);
    match me_id {
        Some(me) if row.to_id == me => {
            if read_by(me) {
                LocalMessageStatus::Read
            } else {
                LocalMessageStatus::Unread
            }
        }
        Some(me) if row.from_id == me => {
            if read_by(row.to_id) {
                let to_label = format_id(labels, row.to_id);
                LocalMessageStatus::ReadBy(to_label)
            } else {
                LocalMessageStatus::Sent
            }
        }
        Some(me) if read_by(me) => LocalMessageStatus::Read,
        Some(_) => LocalMessageStatus::Other,
        None => {
            if read_by(row.to_id) {
                let to_label = format_id(labels, row.to_id);
                LocalMessageStatus::ReadBy(to_label)
            } else {
                LocalMessageStatus::Sent
            }
        }
    }
}

fn local_message_status_text(status: &LocalMessageStatus) -> String {
    match status {
        LocalMessageStatus::Unread => "unread".to_string(),
        LocalMessageStatus::Read => "read".to_string(),
        LocalMessageStatus::Sent => "sent".to_string(),
        LocalMessageStatus::ReadBy(label) => format!("read-by:{label}"),
        LocalMessageStatus::Other => "other".to_string(),
    }
}

fn local_message_status_color(status: &LocalMessageStatus) -> egui::Color32 {
    match status {
        LocalMessageStatus::Unread => egui::Color32::from_rgb(202, 118, 45),
        LocalMessageStatus::Read => egui::Color32::from_rgb(69, 141, 92),
        LocalMessageStatus::Sent => egui::Color32::from_rgb(107, 118, 130),
        LocalMessageStatus::ReadBy(_) => egui::Color32::from_rgb(74, 126, 183),
        LocalMessageStatus::Other => egui::Color32::from_rgb(122, 104, 164),
    }
}

fn render_local_status_chip(ui: &mut egui::Ui, status: &LocalMessageStatus) {
    let fill = local_message_status_color(status);
    let text_color = colorhash::text_color_on(fill);
    let label = truncate_single_line(&local_message_status_text(status), 40);
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(5))
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).color(text_color).small());
        });
}

fn render_person_chip(ui: &mut egui::Ui, label: &str, fill: egui::Color32) {
    let text_color = colorhash::text_color_on(fill);
    let label = truncate_single_line(label, 48);
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(5))
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).color(text_color).small());
        });
}

fn render_relations(ui: &mut egui::Ui, people: &[RelationRow]) {
    if people.is_empty() {
        ui.label("No relations.");
        return;
    }
    ui.set_min_height(RELATIONS_SCROLL_HEIGHT);
    for person in people {
        let label = person.label.as_deref().unwrap_or("<unnamed>");
        ui.label(format!("[{}] {}", id_prefix(person.id), label));
        let full_name = match (&person.first_name, &person.last_name) {
            (Some(first), Some(last)) => Some(format!("{first} {last}")),
            (Some(first), None) => Some(first.clone()),
            (None, Some(last)) => Some(last.clone()),
            (None, None) => None,
        };
        if let Some(name) = person.display_name.as_ref().or(full_name.as_ref()) {
            ui.small(name);
        }
        if let Some(affinity) = &person.affinity {
            ui.small(format!("affinity: {affinity}"));
        }
        if let Some(teams) = &person.teams_user_id {
            ui.small(format!("teams: {teams}"));
        }
        if let Some(email) = &person.email {
            ui.small(format!("email: {email}"));
        }
        if !person.aliases.is_empty() {
            ui.small(format!("aliases: {}", person.aliases.join(", ")));
        }
        if let Some(note) = &person.note {
            ui.small(format!("note: {}", truncate_single_line(note, 120)));
        }
        ui.add_space(8.0);
    }
}

fn parse_response_json(raw: &str) -> Option<JsonValue> {
    if let Ok(value) = serde_json::from_str::<JsonValue>(raw) {
        return Some(value);
    }

    for line in raw.lines().rev() {
        if let Ok(event) = serde_json::from_str::<JsonValue>(line) {
            if event.get("type").and_then(JsonValue::as_str) == Some("response.completed") {
                if let Some(response) = event.get("response") {
                    return Some(response.clone());
                }
            }
        }
    }

    None
}

fn extract_reasoning_summaries(response: &JsonValue) -> Vec<String> {
    let mut summaries = Vec::new();
    if let Some(output) = response.get("output").and_then(JsonValue::as_array) {
        for item in output {
            let Some(item_type) = item.get("type").and_then(JsonValue::as_str) else {
                continue;
            };
            if item_type != "reasoning" {
                continue;
            }

            let Some(summary_items) = item.get("summary").and_then(JsonValue::as_array) else {
                continue;
            };
            for entry in summary_items {
                if entry.get("type").and_then(JsonValue::as_str) != Some("summary_text") {
                    continue;
                }
                if let Some(text) = entry.get("text").and_then(JsonValue::as_str) {
                    summaries.push(text.to_string());
                }
            }
        }
    }

    if let Some(choices) = response.get("choices").and_then(JsonValue::as_array) {
        for choice in choices {
            if let Some(message) = choice.get("message") {
                collect_chat_reasoning_chunks(message, &mut summaries);
            }
            if let Some(delta) = choice.get("delta") {
                collect_chat_reasoning_chunks(delta, &mut summaries);
            }
        }
    }

    summaries
}

fn collect_chat_reasoning_chunks(node: &JsonValue, out: &mut Vec<String>) {
    for key in ["thinking", "reasoning", "reasoning_content"] {
        if let Some(value) = node.get(key) {
            collect_reasoning_value(value, out);
        }
    }
    if let Some(content) = node.get("content").and_then(JsonValue::as_array) {
        for part in content {
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
                    push_reasoning(out, text);
                }
                for key in ["thinking", "reasoning", "reasoning_content"] {
                    if let Some(value) = part.get(key) {
                        collect_reasoning_value(value, out);
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
                push_reasoning(out, text);
            }
        }
    }
}

fn collect_reasoning_value(value: &JsonValue, out: &mut Vec<String>) {
    if let Some(text) = value.as_str() {
        push_reasoning(out, text);
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
            push_reasoning(out, text);
        }
        if let Some(content) = object.get("content") {
            collect_reasoning_value(content, out);
        }
    }
}

fn push_reasoning(out: &mut Vec<String>, text: &str) {
    let trimmed = text.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
}

fn exec_status_text(status: ExecStatus) -> &'static str {
    match status {
        ExecStatus::Pending => "pending",
        ExecStatus::Running => "running",
        ExecStatus::Done => "done",
        ExecStatus::Failed => "failed",
    }
}

fn format_age(now_key: i128, maybe_key: Option<i128>) -> String {
    let Some(key) = maybe_key else {
        return "-".to_string();
    };
    let delta_ns = now_key.saturating_sub(key);
    let delta_s = (delta_ns / 1_000_000_000).max(0) as i64;
    if delta_s < 60 {
        format!("{delta_s}s")
    } else if delta_s < 60 * 60 {
        format!("{}m", delta_s / 60)
    } else if delta_s < 24 * 60 * 60 {
        format!("{}h", delta_s / 3600)
    } else {
        format!("{}d", delta_s / 86_400)
    }
}

fn truncate_single_line(text: &str, max: usize) -> String {
    let mut out = String::with_capacity(max);
    for ch in text.chars() {
        if out.len() >= max {
            out.push_str("…");
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

fn load_text(
    ws: &mut Workspace<Pile>,
    handle: Value<Handle<Blake3, LongString>>,
) -> Option<String> {
    ws.get::<View<str>, LongString>(handle)
        .ok()
        .map(|view| view.as_ref().to_string())
}

fn now_epoch() -> Epoch {
    Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
}

fn epoch_key(epoch: Epoch) -> i128 {
    epoch.to_tai_duration().total_nanoseconds()
}

fn interval_key(interval: Value<NsTAIInterval>) -> i128 {
    let (lower_ns, _): (i128, i128) = interval.try_from_value().unwrap();
    lower_ns
}

fn u256be_to_u64(value: Value<U256BE>) -> Option<u64> {
    let raw = value.raw;
    if raw[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    let bytes: [u8; 8] = raw[24..32].try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn id_prefix(id: Id) -> String {
    let raw: [u8; 16] = id.into();
    let mut out = String::with_capacity(8);
    for byte in raw.iter().take(4) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn longstring_handle_prefix(handle: Value<Handle<Blake3, LongString>>) -> String {
    let raw = handle.raw;
    let mut out = String::with_capacity(8);
    for byte in raw.iter().take(4) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn archive_handle_prefix(handle: Value<Handle<Blake3, SimpleArchive>>) -> String {
    let raw = handle.raw;
    let mut out = String::with_capacity(8);
    for byte in raw.iter().take(4) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn format_id(labels: &HashMap<Id, String>, id: Id) -> String {
    labels.get(&id).cloned().unwrap_or_else(|| id_prefix(id))
}

fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().map(PathBuf::from).unwrap_or(manifest)
}

fn random_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}
