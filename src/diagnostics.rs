use eframe::egui;
use hifitime::Epoch;
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
use triblespace::core::repo::{
    BlobStoreMeta, Checkout, CommitSelector, CommitSet, Repository, Workspace, nth_ancestors,
};
use triblespace::core::trible::TribleSet;
use triblespace::core::value::Value;
use triblespace::core::value::schemas::hash::{Blake3, Handle};
use triblespace::macros::{entity, find, id_hex, pattern};
use triblespace::prelude::valueschemas::{GenId, NsTAIInterval, U256BE};
use triblespace::prelude::{
    Attribute, BlobStore, BlobStoreGet, BranchStore, ToBlob, TryFromValue, TryToValue,
    View, and,
};

use GORBIE::NotebookConfig;
use GORBIE::NotebookCtx;
use GORBIE::cards::DEFAULT_CARD_PADDING;
use GORBIE::themes::{self, colorhash};
use GORBIE::widgets::triblespace::PileRepoState;
use GORBIE::widgets::{Button, TextField};

use crate::blob_refs::{PromptChunk, split_blob_refs};
use crate::schema::model_chat;
use crate::schema::playground_config;
use crate::schema::playground_context;
use crate::schema::playground_exec;

mod archive {
    use triblespace::macros::id_hex;
    use triblespace::prelude::blobschemas::LongString;
    use triblespace::prelude::valueschemas::{Blake3, GenId, Handle};
    use triblespace::prelude::*;

    attributes! {
        "5F10520477A04E5FB322C85CC78C6762" as pub kind: GenId;
        "838CC157FFDD37C6AC7CC5A472E43ADB" as pub author: GenId;
        "E63EE961ABDB1D1BEC0789FDAFFB9501" as pub author_name: Handle<Blake3, LongString>;
        "2D15150501ACCD9DFD96CB4BF19D1883" as pub author_role: Handle<Blake3, LongString>;
        "4FE6A8A43658BC2F61FEDF5CFB29EEFC" as pub author_model: Handle<Blake3, LongString>;
        "ACF09FF3D62B73983A222313FF0C52D2" as pub content: Handle<Blake3, LongString>;
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
    use triblespace::prelude::valueschemas::{Blake3, GenId, Handle, NsTAIInterval, ShortString};
    use triblespace::prelude::*;

    attributes! {
        "EE18CEC15C18438A2FAB670E2E46E00C" as pub title: Handle<Blake3, LongString>;
        "5FF4941DCC3F6C35E9B3FD57216F69ED" as pub tag: ShortString;
        "9D2B6EBDA67E9BB6BE6215959D182041" as pub parent: GenId;

        "C1EAAA039DA7F486E4A54CC87D42E72C" as pub task: GenId;
        "61C44E0F8A73443ED592A713151E99A4" as pub status: ShortString;
        "4FB34DB057497FB845B3816521A9A05E" as pub at: NsTAIInterval;
        "47351DF00B3DDA96CB305157CD53D781" as pub note: Handle<Blake3, LongString>;
    }
}

mod wiki {
    use triblespace::macros::id_hex;
    use triblespace::prelude::blobschemas::LongString;
    use triblespace::prelude::valueschemas::{Blake3, GenId, Handle};
    use triblespace::prelude::*;

    attributes! {
        "EBFC56D50B748E38A14F5FC768F1B9C1" as pub fragment: GenId;
        "78BABEF1792531A2E51A372D96FE5F3E" as pub title: Handle<Blake3, LongString>;
        "6DBBE746B7DD7A4793CA098AB882F553" as pub content: Handle<Blake3, LongString>;
    }

    #[allow(non_upper_case_globals)]
    pub const kind_version: Id = id_hex!("1AA0310347EDFED7874E8BFECC6438CF");
}

// ── Layout constants ────────────────────────────────────────────────
const ACTIVITY_TIMELINE_HEIGHT: f32 = 980.0;
const CONTEXT_TREE_HEIGHT: f32 = 720.0;
const CONTEXT_ORIGIN_LIMIT: usize = 64;
const LOCAL_COMPOSE_HEIGHT: f32 = 80.0;
const TEAMS_SCROLL_HEIGHT: f32 = 520.0;
const CATALOG_REFRESH_MS: u64 = 1000;
const HISTORY_CHUNK_SIZE: usize = 64;

/// Per-branch catalog state with progressive history loading.
///
/// On first load, only the most recent `HISTORY_CHUNK_SIZE` commits are
/// checked out. Each subsequent frame extends backwards by another chunk
/// until the full history is loaded, then switches to incremental mode.
struct BranchCatalog {
    co: Option<Checkout>,
    /// The frontier: commits just beyond our loaded range.
    /// `nth_ancestors(frontier, chunk)` gives the next boundary.
    /// Empty = fully loaded (reached root).
    frontier: CommitSet,
    fully_loaded: bool,
}

impl Default for BranchCatalog {
    fn default() -> Self {
        Self {
            co: None,
            frontier: CommitSet::new(),
            fully_loaded: false,
        }
    }
}

impl BranchCatalog {
    fn catalog(&self) -> &TribleSet {
        static EMPTY: std::sync::LazyLock<TribleSet> = std::sync::LazyLock::new(TribleSet::new);
        self.co.as_ref().map(|c| c.facts()).unwrap_or(&EMPTY)
    }

    fn reset(&mut self) {
        self.co = None;
        self.frontier = CommitSet::new();
        self.fully_loaded = false;
    }
}

// ── RAL color palette ──────────────────────────────────────────────
// All colors drawn from the industrial RAL palette for visual consistency.

fn color_shell() -> egui::Color32 { themes::ral(5024) }      // pastel blue
fn color_cognition() -> egui::Color32 { themes::ral(4011) }   // pearl violet
fn color_teams() -> egui::Color32 { themes::ral(5012) }       // light blue
fn color_local_msg() -> egui::Color32 { themes::ral(6032) }   // signal green
fn color_goals() -> egui::Color32 { themes::ral(1012) }       // lemon yellow
fn color_wiki() -> egui::Color32 { themes::ral(3012) }        // beige red

fn color_system() -> egui::Color32 { themes::ral(5014) }      // pigeon blue
fn color_user() -> egui::Color32 { themes::ral(6033) }        // mint turquoise
fn color_assistant() -> egui::Color32 { themes::ral(4005) }   // blue lilac

fn color_todo() -> egui::Color32 { themes::ral(6018) }        // yellow green
fn color_doing() -> egui::Color32 { themes::ral(1003) }       // signal yellow
fn color_blocked() -> egui::Color32 { themes::ral(3020) }     // traffic red
fn color_done() -> egui::Color32 { themes::ral(5005) }        // signal blue

fn color_read() -> egui::Color32 { themes::ral(6017) }        // may green

fn color_muted() -> egui::Color32 { themes::ral(7012) }       // basalt grey
fn color_frame() -> egui::Color32 { themes::ral(7016) }       // anthracite grey

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

        "2213B191326E9B99605FA094E516E50E" as about_message: valueschemas::GenId;
        "99E92F483731FA6D59115A8D6D187A37" as reader: valueschemas::GenId;
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
    /// Exec branch name — set from agent config, defaults to "cognition".
    exec_branch: String,
    local_me: String,
    local_peer: String,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            exec_branch: "cognition".to_string(),
            local_me: "jp".to_string(),
            local_peer: "agent".to_string(),
        }
    }
}

// Fixed branch names — no configuration needed.
const BRANCH_CONFIG: &str = "config";
const BRANCH_COMPASS: &str = "compass";
const BRANCH_LOCAL_MESSAGES: &str = "local-messages";
const BRANCH_RELATIONS: &str = "relations";
const BRANCH_TEAMS: &str = "teams";
const BRANCH_WIKI: &str = "wiki";

fn default_pile_path() -> String {
    let default_pile = diagnostics_default_pile().unwrap_or_else(|| {
        let repo_root = repo_root();
        repo_root.join("self.pile")
    });
    default_pile.to_string_lossy().to_string()
}

struct DashboardState {
    config: DashboardConfig,
    pile: PileRepoState,
    config_cat: BranchCatalog,
    exec_cat: BranchCatalog,
    compass_cat: BranchCatalog,
    local_messages_cat: BranchCatalog,
    relations_cat: BranchCatalog,
    teams_cat: BranchCatalog,
    wiki_cat: BranchCatalog,
    branches: Vec<BranchEntry>,
    now_key: i128,
    local_draft: String,
    local_send_error: Option<String>,
    local_send_notice: Option<String>,
    config_reveal_secrets: bool,
    config_last_applied_id: Option<Id>,
    compass_expanded_goal: Option<Id>,
    teams_selected_chat: Option<Id>,
    context_selected_chunk: Option<Id>,
    context_float_request_id: Option<(Id, TimelineSource)>,
    context_selection_stack: Vec<Id>,
    context_show_children: bool,
    context_show_origins: bool,
    /// Timeline viewport: top edge = this timestamp (newest visible).
    /// Scrolling pans this value. Initialized to now_key.
    timeline_start: i128,
    /// Timeline zoom: pixels per minute of wall time.
    timeline_scale: f32,
    last_refresh_at: Option<Instant>,
}

impl Default for DashboardState {
    fn default() -> Self {
        Self {
            config: DashboardConfig::default(),
            pile: PileRepoState::new(default_pile_path()),
            config_cat: BranchCatalog::default(),
            exec_cat: BranchCatalog::default(),
            compass_cat: BranchCatalog::default(),
            local_messages_cat: BranchCatalog::default(),
            relations_cat: BranchCatalog::default(),
            teams_cat: BranchCatalog::default(),
            wiki_cat: BranchCatalog::default(),
            branches: Vec::new(),
            now_key: 0,
            local_draft: String::new(),
            local_send_error: None,
            local_send_notice: None,
            config_reveal_secrets: false,
            config_last_applied_id: None,
            compass_expanded_goal: None,
            teams_selected_chat: None,
            context_selected_chunk: None,
            context_float_request_id: None, // (Id, TimelineSource)
            context_selection_stack: Vec::new(),
            context_show_children: false,
            context_show_origins: false,
            timeline_start: 0, // initialized to now_key on first refresh
            timeline_scale: TIMELINE_DEFAULT_SCALE,
            last_refresh_at: None,
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
    Wiki,
}

#[derive(Debug, Clone)]
struct CompassTaskRow {
    id: Id,
    id_prefix: String,
    title: String,
    tags: Vec<String>,
    created_at: Option<i128>,
    status: String,
    status_at: Option<i128>,
    note_count: usize,
    parent: Option<Id>,
}

impl CompassTaskRow {
    fn sort_key(&self) -> i128 {
        self.status_at.unwrap_or(self.created_at.unwrap_or(i128::MIN))
    }
}

#[derive(Debug, Clone)]
struct CompassNoteRow {
    at: Option<i128>,
    body: String,
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

fn diagnostics_ui(nb: &mut NotebookCtx) {
    let _padding = DEFAULT_CARD_PADDING;
    let dashboard = nb.state(
        "playground-diagnostics",
        DashboardState::default(),
        move |ui, state| {
            // Poll the background pile opener; if it just finished, clear cached checkouts.
            let was_opening = state.pile.is_opening();
            state.pile.poll();
            if was_opening && !state.pile.is_opening() && state.pile.is_open() {
                state.config_cat.reset();
                state.exec_cat.reset();
                state.compass_cat.reset();
                state.local_messages_cat.reset();
                state.relations_cat.reset();
                state.teams_cat.reset();
                state.wiki_cat.reset();
                state.branches.clear();
            }

            // Detect path change: if the edited path differs from the open path, close and reopen.
            let edited_path = PathBuf::from(state.pile.pile_path().trim());
            let path_changed = state.pile.open_path().map_or(false, |p| p != edited_path);
            if path_changed {
                state.pile.close();
                state.config_cat.reset();
                state.exec_cat.reset();
                state.compass_cat.reset();
                state.local_messages_cat.reset();
                state.relations_cat.reset();
                state.teams_cat.reset();
                state.wiki_cat.reset();
                state.branches.clear();
            }

            // Auto-open: if the pile is not open and not opening and no error,
            // and the path looks like it exists, start opening.
            if !state.pile.is_open() && !state.pile.is_opening() && state.pile.last_error().is_none() {
                let path = PathBuf::from(state.pile.pile_path().trim());
                if path.exists() {
                    state.pile.open();
                }
            }

            if state.pile.is_opening() {
                ui.ctx().request_repaint();
            }

            ui.section("Overview", |ui| {
                ui.grid(|g| {
                    // Editable pile path with loading indicator.
                    g.full(|ui| {
                        let progress = if state.pile.is_opening() {
                            let t = ui.input(|i| i.time) as f32;
                            let pos = (t * 1.5).sin() * 0.5 + 0.5;
                            let width = 0.2;
                            Some((pos - width * 0.5).max(0.0)..(pos + width * 0.5).min(1.0))
                        } else {
                            None
                        };
                        ui.add(TextField::singleline(state.pile.pile_path_mut()).progress(progress));
                    });

                    // Branch listing.
                    let branches = &state.branches;
                    if !branches.is_empty() {
                        let mut primary: Vec<&BranchEntry> = Vec::new();
                        let mut extra: Vec<&BranchEntry> = Vec::new();
                        for branch in branches {
                            let label = branch.name.as_deref().unwrap_or("<unnamed>");
                            if label.contains("--orphan-") || label.starts_with('<') {
                                extra.push(branch);
                            } else {
                                primary.push(branch);
                            }
                        }


                        for branch in &primary {
                            let name = branch.name.as_deref().unwrap_or("<unnamed>");
                            let fill = colorhash::ral_categorical(name.as_bytes());
                            let text_color = colorhash::text_color_on(fill);
                            g.third(|ui| {
                                egui::Frame::NONE
                                    .fill(fill)
                                    .corner_radius(egui::CornerRadius::same(5))
                                    .inner_margin(egui::Margin::symmetric(8, 2))
                                    .show(ui, |ui| {
                                        ui.set_min_width(ui.available_width());
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing.x = 4.0;
                                            ui.label(egui::RichText::new(name).color(text_color).small());
                                            ui.label(
                                                egui::RichText::new(format!("{:x}", branch.id))
                                                    .monospace()
                                                    .color(text_color)
                                                    .small(),
                                            );
                                        });
                                    });
                            });
                        }

                        if !extra.is_empty() {
                            g.full(|ui| {
                                ui.section_collapsed(&format!("{} extra branches", extra.len()), |ui| {
                                    ui.grid(|g| {
                                        for branch in &extra {
                                            let name = branch.name.as_deref().unwrap_or("<unnamed>");
                                            let fill = colorhash::ral_categorical(name.as_bytes());
                                            let text_color = colorhash::text_color_on(fill);
                                            g.third(|ui| {
                                                egui::Frame::NONE
                                                    .fill(fill)
                                                    .corner_radius(egui::CornerRadius::same(5))
                                                    .inner_margin(egui::Margin::symmetric(8, 2))
                                                    .show(ui, |ui| {
                                                        ui.set_min_width(ui.available_width());
                                                        ui.horizontal(|ui| {
                                                            ui.spacing_mut().item_spacing.x = 4.0;
                                                            ui.label(
                                                                egui::RichText::new(name).color(text_color).small(),
                                                            );
                                                            ui.label(
                                                                egui::RichText::new(id_prefix(branch.id))
                                                                    .monospace()
                                                                    .color(color_muted())
                                                                    .small(),
                                                            );
                                                        });
                                                    });
                                            });
                                        }
                                    });
                                });
                            });
                        }
                    }
                });
            });

            if state.pile.is_open() {
                let all_loaded = state.config_cat.fully_loaded
                    && state.exec_cat.fully_loaded
                    && state.compass_cat.fully_loaded
                    && state.local_messages_cat.fully_loaded
                    && state.relations_cat.fully_loaded
                    && state.teams_cat.fully_loaded
                    && state.wiki_cat.fully_loaded;

                // While history is still loading, refresh every frame.
                // Once fully loaded, switch to timer-based incremental refresh.
                if !all_loaded || should_refresh(&state) {
                    refresh_catalogs(state);
                    apply_branch_defaults(state);
                    state.last_refresh_at = Some(Instant::now());
                }

                if !all_loaded {
                    ui.ctx().request_repaint();
                } else if !diagnostics_is_headless() {
                    ui.ctx()
                        .request_repaint_after(Duration::from_millis(CATALOG_REFRESH_MS));
                }
            } else if !diagnostics_is_headless() {
                ui.ctx()
                    .request_repaint_after(Duration::from_millis(CATALOG_REFRESH_MS));
            }
        },
    );

    // ── Card 2: Main view (Activity timeline + context float) ──────
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);

        // Pull workspace for blob reads.
        let exec_branch = state.config.exec_branch.clone();
        let mut ws = state.pile.repo_mut().and_then(|repo| {
            let branch_entries = list_branches(repo.storage_mut()).ok()?;
            let lookup = BranchLookup::new(&branch_entries);
            let refs = parse_branch_list(&exec_branch);
            let ids = resolve_branch_ids(&lookup, &refs).ok()?;
            repo.pull(*ids.first()?).ok()
        });

        // Clone all catalogs needed for the timeline.
        let exec_data = state.exec_cat.catalog().clone();
        let local_data = state.local_messages_cat.catalog().clone();
        let teams_data = state.teams_cat.catalog().clone();
        let compass_data = state.compass_cat.catalog().clone();
        let relations_data = state.relations_cat.catalog().clone();
        let wiki_data = state.wiki_cat.catalog().clone();
        let now_key = state.now_key;

        // Initialize timeline_start to "now" if not yet set.
        if state.timeline_start == 0 {
            state.timeline_start = now_key;
        }

        let exec_branch_err =
            if state.exec_cat.co.is_none() && !state.config.exec_branch.trim().is_empty() {
                let branch_lookup = BranchLookup::new(&state.branches);
                let refs = parse_branch_list(&state.config.exec_branch);
                resolve_branch_ids(&branch_lookup, &refs).err()
            } else {
                None
            };

        ui.section("Activity", |ui| {

            if let Some(err) = &exec_branch_err {
                ui.colored_label(egui::Color32::RED, format!("Exec branch: {err}"));
            }

            // The timeline viewport: full-width painted region as a time axis.
            let viewport_height = ACTIVITY_TIMELINE_HEIGHT;
            let scroll_speed = 3.0;

            // Allocate the viewport rect.
            let viewport_width = ui.available_width();
            let (viewport_rect, viewport_response) = ui.allocate_exact_size(
                egui::vec2(viewport_width, viewport_height),
                egui::Sense::click_and_drag(),
            );

            // Input handling — compute ns_per_px from CURRENT scale for input.
            {
                let ns_per_px = 60_000_000_000.0 / state.timeline_scale as f64;

                if viewport_response.hovered() {
                    let (scroll_y, scroll_x, ctrl, pointer_pos) = ui.input(|i| {
                        (i.smooth_scroll_delta.y, i.smooth_scroll_delta.x,
                         i.modifiers.command || i.modifiers.ctrl,
                         i.pointer.hover_pos())
                    });

                    let cursor_rel_y = pointer_pos
                        .map(|p| (p.y - viewport_rect.top()).max(0.0))
                        .unwrap_or(viewport_height * 0.5);

                    let cursor_time = state.timeline_start - (cursor_rel_y as f64 * ns_per_px) as i128;

                    if !ctrl && scroll_y != 0.0 {
                        let pan_ns = (scroll_y as f64 * scroll_speed * ns_per_px) as i128;
                        state.timeline_start += pan_ns;
                    }

                    let zoom_factor = if ctrl && scroll_y != 0.0 {
                        if scroll_y > 0.0 { 1.15 } else { 1.0 / 1.15 }
                    } else if scroll_x != 0.0 {
                        if scroll_x > 0.0 { 1.08 } else { 1.0 / 1.08 }
                    } else {
                        1.0
                    };

                    if zoom_factor != 1.0 {
                        let new_scale = (state.timeline_scale * zoom_factor).clamp(0.01, 1000.0);
                        let new_ns_per_px = 60_000_000_000.0 / new_scale as f64;
                        state.timeline_start = cursor_time + (cursor_rel_y as f64 * new_ns_per_px) as i128;
                        state.timeline_scale = new_scale;
                    }

                    ui.ctx().input_mut(|i| {
                        i.smooth_scroll_delta = egui::Vec2::ZERO;
                    });
                }

                if viewport_response.dragged() {
                    let drag_delta = viewport_response.drag_delta().y;
                    let pan_ns = (drag_delta as f64 * ns_per_px) as i128;
                    state.timeline_start += pan_ns;
                }

                if viewport_response.double_clicked() {
                    state.timeline_start = now_key;
                }
            }

            // Recompute viewport bounds AFTER all input with final scale.
            let ns_per_px = 60_000_000_000.0 / state.timeline_scale as f64;
            let viewport_ns = (viewport_height as f64 * ns_per_px) as i128;
            let view_start = state.timeline_start;
            let view_end = view_start - viewport_ns;

            // Clip painting to viewport.
            let painter = ui.painter_at(viewport_rect);

            // Background.
            painter.rect_filled(viewport_rect, 0.0, color_frame());

            // Four-sine ruler: one sine per natural time unit.
            // Constructive interference at "nice" times → tall peaks.
            // Scroll = phase shift, zoom = wavelength rescaling.
            let muted = color_muted();
            let max_len = 80.0;
            let tick_spacing_px = GORBIE::card_ctx::GRID_ROW_MODULE;
            let tau = std::f64::consts::TAU;

            // The four natural time periods.
            let ns = 1_000_000_000.0f64;
            let periods = [60.0 * ns, 3600.0 * ns, 86400.0 * ns];

            // Significance: sum of cosines, equal weight per visible period.
            // Periods whose wavelength is < 2 tick spacings fade out smoothly.
            let significance = |t: f64| -> f32 {
                let mut sig = 0.0f32;
                let mut n = 0.0f32;
                for &period in &periods {
                    let px_wave = period / ns_per_px;
                    // Smooth fade: fully in at 4× tick spacing, gone at 1×.
                    let vis = ((px_wave as f32 / tick_spacing_px - 1.0) / 3.0).clamp(0.0, 1.0);
                    if vis < 0.001 { continue; }
                    sig += vis * (0.5 + 0.5 * (tau * t / period).cos() as f32);
                    n += vis;
                }
                if n > 0.0 { sig / n } else { 0.0 }
            };

            // Draw the sine ruler.
            let n_samples = (viewport_height / tick_spacing_px) as usize + 1;
            for i in 0..=n_samples {
                let y = viewport_rect.top() + i as f32 * tick_spacing_px;
                if y > viewport_rect.bottom() { break; }

                let t = view_start as f64 - (i as f64 * tick_spacing_px as f64 * ns_per_px);
                let sig = significance(t);
                let tick_len = 2.0 + (max_len - 2.0) * sig;

                painter.line_segment(
                    [egui::pos2(viewport_rect.left(), y),
                     egui::pos2(viewport_rect.left() + tick_len, y)],
                    egui::Stroke::new(0.5, muted),
                );
            }

            // Labels: independent of sine, placed at the coarsest time
            // interval that gives ~6-10 labels in the viewport.
            let label_min_spacing_px = 100.0;
            let label_min_ns = (label_min_spacing_px as f64 * ns_per_px) as i128;
            let label_interval = TICK_INTERVALS.iter()
                .copied()
                .find(|&iv| iv >= label_min_ns)
                .unwrap_or(*TICK_INTERVALS.last().unwrap());

            if label_interval > 0 {
                let first = (view_start / label_interval) * label_interval;
                let mut tick = first;
                while tick > view_end {
                    let y = viewport_rect.top()
                        + ((view_start - tick) as f64 / ns_per_px) as f32;
                    if y >= viewport_rect.top() && y <= viewport_rect.bottom() {
                        let label = format_time_marker(tick);
                        painter.text(
                            egui::pos2(viewport_rect.left() + max_len + 4.0, y),
                            egui::Align2::LEFT_CENTER,
                            &label,
                            egui::FontId::monospace(9.0),
                            muted,
                        );
                    }
                    tick -= label_interval;
                }
            }

            // Query events directly from catalogs for the visible time range.
            // No shadow datamodel — just find! queries with value_in_range.
            let Some(ref mut ws) = ws else {
                return;
            };

            // Build range bounds as NsTAIInterval values.
            let ts_min = Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(view_end));
            let ts_max = Epoch::from_tai_duration(hifitime::Duration::from_total_nanoseconds(view_start));
            let min_ts: Value<NsTAIInterval> = (ts_min, ts_min).try_to_value().unwrap();
            let max_ts: Value<NsTAIInterval> = (ts_max, ts_max).try_to_value().unwrap();

            // Direct rendering: each event painted at its exact timestamp position.
            struct VisibleEvent {
                y: f32,
                id: Id,
                source: TimelineSource,
                summary: String,
            }
            let mut events: Vec<VisibleEvent> = Vec::new();

            let push_event = |events: &mut Vec<VisibleEvent>, id: Id, ts: Value<NsTAIInterval>, source: TimelineSource, summary: String| {
                let key = interval_key(ts);
                let y = viewport_rect.top() + ((view_start - key) as f64 / ns_per_px) as f32;
                events.push(VisibleEvent { y, id, source, summary });
            };

            // Shell exec events.
            for (id, ts, command) in find!(
                (id: Id, ts: Value<NsTAIInterval>, command: Value<Handle<Blake3, LongString>>),
                and!(
                    pattern!(&exec_data, [{ ?id @ metadata::created_at: ?ts, playground_exec::command_text: ?command }]),
                    exec_data.value_in_range(ts, min_ts, max_ts),
                )
            ) {
                if let Some(text) = load_text(ws, command) {
                    push_event(&mut events, id, ts, TimelineSource::Shell, truncate_single_line(&text, 80).to_string());
                }
            }

            // Cognition.
            for (id, ts, reasoning) in find!(
                (id: Id, ts: Value<NsTAIInterval>, reasoning: Value<Handle<Blake3, LongString>>),
                and!(
                    pattern!(&exec_data, [{ ?id @ metadata::finished_at: ?ts, model_chat::reasoning_text: ?reasoning }]),
                    exec_data.value_in_range(ts, min_ts, max_ts),
                )
            ) {
                if let Some(text) = load_text(ws, reasoning) {
                    push_event(&mut events, id, ts, TimelineSource::Cognition, truncate_single_line(&text, 80).to_string());
                }
            }

            // Local messages.
            for (id, ts, body) in find!(
                (id: Id, ts: Value<NsTAIInterval>, body: Value<Handle<Blake3, LongString>>),
                and!(
                    pattern!(&local_data, [{ ?id @ metadata::created_at: ?ts, local_messages::body: ?body }]),
                    local_data.value_in_range(ts, min_ts, max_ts),
                )
            ) {
                if let Some(text) = load_text(ws, body) {
                    push_event(&mut events, id, ts, TimelineSource::LocalMessages, truncate_single_line(&text, 80).to_string());
                }
            }

            // Teams messages.
            for (id, ts, content) in find!(
                (id: Id, ts: Value<NsTAIInterval>, content: Value<Handle<Blake3, LongString>>),
                and!(
                    pattern!(&teams_data, [{ ?id @ metadata::created_at: ?ts, archive::content: ?content }]),
                    teams_data.value_in_range(ts, min_ts, max_ts),
                )
            ) {
                if let Some(text) = load_text(ws, content) {
                    push_event(&mut events, id, ts, TimelineSource::Teams, truncate_single_line(&text, 80).to_string());
                }
            }

            // Compass goals.
            for (id, ts, title) in find!(
                (id: Id, ts: Value<NsTAIInterval>, title: Value<Handle<Blake3, LongString>>),
                and!(
                    pattern!(&compass_data, [{ ?id @ metadata::created_at: ?ts, compass::title: ?title }]),
                    compass_data.value_in_range(ts, min_ts, max_ts),
                )
            ) {
                if let Some(text) = load_text(ws, title) {
                    push_event(&mut events, id, ts, TimelineSource::Goals, truncate_single_line(&text, 80).to_string());
                }
            }

            // Compass status/note events.
            for (id, ts) in find!(
                (id: Id, ts: Value<NsTAIInterval>),
                and!(
                    pattern!(&compass_data, [{ ?id @ compass::at: ?ts }]),
                    compass_data.value_in_range(ts, min_ts, max_ts),
                )
            ) {
                // Build a more descriptive summary.
                let status: Option<String> = find!(
                    v: String,
                    pattern!(&compass_data, [{ &id @ compass::status: ?v }])
                ).next();
                let note_preview: Option<String> = find!(
                    handle: Value<Handle<Blake3, LongString>>,
                    pattern!(&compass_data, [{ &id @ compass::note: ?handle }])
                ).next().and_then(|h| load_text(ws, h)).map(|t| truncate_single_line(&t, 60).to_string());
                let summary = match (status, note_preview) {
                    (Some(s), Some(n)) => format!("[{s}] {n}"),
                    (Some(s), None) => format!("[{s}]"),
                    (None, Some(n)) => n,
                    (None, None) => "event".to_string(),
                };
                push_event(&mut events, id, ts, TimelineSource::Goals, summary);
            }

            // Wiki version events.
            for (id, ts, title) in find!(
                (id: Id, ts: Value<NsTAIInterval>, title: Value<Handle<Blake3, LongString>>),
                and!(
                    pattern!(&wiki_data, [{
                        ?id @
                        metadata::tag: &wiki::kind_version,
                        metadata::created_at: ?ts,
                        wiki::title: ?title,
                    }]),
                    wiki_data.value_in_range(ts, min_ts, max_ts),
                )
            ) {
                if let Some(text) = load_text(ws, title) {
                    push_event(&mut events, id, ts, TimelineSource::Wiki, truncate_single_line(&text, 80).to_string());
                }
            }

            // Render each event as a clickable chip.
            let event_left = viewport_rect.left() + 120.0;
            let event_width = viewport_rect.width() - 130.0;
            let text_color = colorhash::text_color_on(color_frame());

            for ev in &events {
                let (source_label, source_color) = timeline_source_style(ev.source);

                // Chip background.
                let chip_rect = egui::Rect::from_min_size(
                    egui::pos2(event_left, ev.y - 8.0),
                    egui::vec2(event_width, 16.0),
                );
                painter.rect_filled(chip_rect, 3.0, color_frame());

                // Source tag.
                let tag_text = colorhash::text_color_on(source_color);
                let tag_rect = egui::Rect::from_min_size(
                    egui::pos2(event_left + 2.0, ev.y - 7.0),
                    egui::vec2(36.0, 14.0),
                );
                painter.rect_filled(tag_rect, 3.0, source_color);
                painter.text(
                    tag_rect.center(),
                    egui::Align2::CENTER_CENTER,
                    source_label,
                    egui::FontId::proportional(9.0),
                    tag_text,
                );

                // Summary text.
                painter.text(
                    egui::pos2(event_left + 42.0, ev.y),
                    egui::Align2::LEFT_CENTER,
                    &ev.summary,
                    egui::FontId::monospace(10.0),
                    text_color,
                );

                // Click to open details float.
                let click_id = ui.id().with(("timeline_event", ev.id));
                let resp = ui.interact(chip_rect, click_id, egui::Sense::click());
                if resp.clicked() {
                    state.context_float_request_id = Some((ev.id, ev.source));
                }
                if resp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                    // Highlight on hover.
                    painter.rect_stroke(chip_rect, 3.0, egui::Stroke::new(1.0, source_color), egui::StrokeKind::Outside);
                }
            }

            // Details float: bespoke rendering per event type.
            if let Some((selected_id, selected_source)) = state.context_float_request_id {
                let (source_label, source_color) = timeline_source_style(selected_source);

                let mut load_blob_of = |data: &TribleSet, eid: &Id, attr: Attribute<Handle<Blake3, LongString>>| -> Option<String> {
                    find!(
                        handle: Value<Handle<Blake3, LongString>>,
                        pattern!(data, [{ eid @ attr: ?handle }])
                    ).next().and_then(|h| load_text(ws, h))
                };
                // Convenience: default to selected_id.
                // (macro because closures can't reborrow)
                macro_rules! load_blob {
                    ($data:expr, $attr:expr) => { load_blob_of($data, &selected_id, $attr) }
                }
                let load_u256 = |data: &TribleSet, attr: Attribute<U256BE>| -> Option<u64> {
                    find!(
                        v: Value<U256BE>,
                        pattern!(data, [{ &selected_id @ attr: ?v }])
                    ).next().and_then(u256be_to_u64)
                };
                let load_short = |data: &TribleSet, attr: Attribute<triblespace::prelude::valueschemas::ShortString>| -> Option<String> {
                    find!(
                        v: String,
                        pattern!(data, [{ &selected_id @ attr: ?v }])
                    ).next()
                };
                let load_ts = |data: &TribleSet, attr: Attribute<NsTAIInterval>| -> Option<i128> {
                    find!(
                        v: Value<NsTAIInterval>,
                        pattern!(data, [{ &selected_id @ attr: ?v }])
                    ).next().map(interval_key)
                };

                // Resolve timestamp per source type.
                let event_ts = match selected_source {
                    TimelineSource::Shell => load_ts(&exec_data, metadata::created_at),
                    TimelineSource::Cognition => load_ts(&exec_data, metadata::finished_at),
                    TimelineSource::LocalMessages => load_ts(&local_data, metadata::created_at),
                    TimelineSource::Teams => load_ts(&teams_data, metadata::created_at),
                    TimelineSource::Goals => load_ts(&compass_data, metadata::created_at)
                        .or_else(|| load_ts(&compass_data, compass::at)),
                    TimelineSource::Wiki => {
                        find!(
                            v: Value<NsTAIInterval>,
                            pattern!(&wiki_data, [{ &selected_id @ metadata::created_at: ?v }])
                        ).next().map(interval_key)
                    }
                };

                ui.push_id(selected_id, |ui| {
                    let resp = ui.float(|ui| {
                        // Full-bleed colored header bar.
                        let header_text = colorhash::text_color_on(source_color);
                        let header_width = ui.available_width();
                        egui::Frame::NONE
                            .fill(source_color)
                            .inner_margin(egui::Margin::symmetric(8, 4))
                            .show(ui, |ui| {
                                ui.set_min_width(header_width);
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(source_label).small().strong().color(header_text));
                                    ui.label(egui::RichText::new(id_prefix(selected_id)).monospace().small().color(
                                        header_text.linear_multiply(0.7),
                                    ));
                                    if let Some(ts) = event_ts {
                                        ui.label(egui::RichText::new(format_time_marker(ts)).monospace().small().color(
                                            header_text.linear_multiply(0.7),
                                        ));
                                    }
                                });
                            });

                        // Body in a grid for proper margins.
                        ui.grid(|g| { g.full(|ui| {
                            let text_block = |ui: &mut egui::Ui, label: &str, text: &str, label_color: egui::Color32| {
                                ui.label(egui::RichText::new(label).small().color(label_color));
                                egui::Frame::NONE
                                    .fill(color_frame())
                                    .corner_radius(egui::CornerRadius::same(4))
                                    .inner_margin(egui::Margin::symmetric(8, 4))
                                    .show(ui, |ui| {
                                        egui::ScrollArea::vertical()
                                            .id_salt(label)
                                            .min_scrolled_height(200.0)
                                            .max_height(200.0)
                                            .show(ui, |ui| {
                                                ui.add(
                                                    egui::Label::new(egui::RichText::new(text).monospace().small())
                                                        .wrap_mode(egui::TextWrapMode::Wrap),
                                                );
                                            });
                                    });
                                ui.add_space(4.0);
                            };

                            let inline_pill = |ui: &mut egui::Ui, label: &str, value: &str, fill: egui::Color32| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(label).small().color(color_muted()));
                                    egui::Frame::NONE
                                        .fill(fill)
                                        .corner_radius(egui::CornerRadius::same(3))
                                        .inner_margin(egui::Margin::symmetric(6, 2))
                                        .show(ui, |ui| {
                                            ui.label(egui::RichText::new(value).monospace().small().color(
                                                colorhash::text_color_on(fill),
                                            ));
                                        });
                                });
                            };

                            let muted = color_muted();
                            let red = egui::Color32::LIGHT_RED;

                            match selected_source {
                                TimelineSource::Shell => {
                                    // The timeline event id is the request entity.
                                    // Result attributes live on a separate entity with about_request → selected_id.
                                    let result_id: Option<Id> = find!(
                                        rid: Id,
                                        pattern!(&exec_data, [{ ?rid @ playground_exec::about_request: &selected_id }])
                                    ).next();

                                    // Metadata row: exit code + duration + cwd.
                                    let exit_code = result_id.and_then(|rid| {
                                        find!(v: Value<U256BE>, pattern!(&exec_data, [{ &rid @ playground_exec::exit_code: ?v }]))
                                            .next().and_then(u256be_to_u64)
                                    });
                                    let duration = result_id.and_then(|rid| {
                                        find!(v: Value<U256BE>, pattern!(&exec_data, [{ &rid @ playground_exec::duration_ms: ?v }]))
                                            .next().and_then(u256be_to_u64)
                                    });
                                    let cwd = load_blob!(&exec_data, playground_exec::cwd);
                                    if exit_code.is_some() || duration.is_some() || cwd.is_some() {
                                        ui.horizontal_wrapped(|ui| {
                                            if let Some(code) = exit_code {
                                                let (label, fill) = if code == 0 {
                                                    ("exit 0", color_done())
                                                } else {
                                                    ("exit err", color_blocked())
                                                };
                                                inline_pill(ui, "", &format!("{label} ({code})"), fill);
                                            }
                                            if let Some(ms) = duration {
                                                let text = if ms >= 1000 { format!("{:.1}s", ms as f64 / 1000.0) } else { format!("{ms}ms") };
                                                inline_pill(ui, "", &text, color_frame());
                                            }
                                            if let Some(ref dir) = cwd {
                                                ui.label(egui::RichText::new(dir).monospace().small().color(muted));
                                            }
                                        });
                                        ui.add_space(4.0);
                                    }
                                    if let Some(cmd) = load_blob!(&exec_data, playground_exec::command_text) {
                                        text_block(ui, "command", &cmd, muted);
                                    }
                                    if let Some(stdin) = load_blob!(&exec_data, playground_exec::stdin_text) {
                                        if !stdin.trim().is_empty() {
                                            text_block(ui, "stdin", &stdin, muted);
                                        }
                                    }
                                    // stdout/stderr/error live on the result entity.
                                    if let Some(rid) = result_id {
                                        if let Some(stdout) = load_blob_of(&exec_data, &rid, playground_exec::stdout_text) {
                                            if !stdout.trim().is_empty() {
                                                text_block(ui, "stdout", &stdout, muted);
                                            }
                                        }
                                        if let Some(stderr) = load_blob_of(&exec_data, &rid, playground_exec::stderr_text) {
                                            if !stderr.trim().is_empty() {
                                                text_block(ui, "stderr", &stderr, red);
                                            }
                                        }
                                        if let Some(err) = load_blob_of(&exec_data, &rid, playground_exec::error) {
                                            if !err.trim().is_empty() {
                                                text_block(ui, "error", &err, red);
                                            }
                                        }
                                    }
                                }
                                TimelineSource::Cognition => {
                                    // selected_id is the result entity (has metadata::finished_at).
                                    // Request entity (model, context) linked via about_request.
                                    let request_id: Option<Id> = find!(
                                        rid: Id,
                                        pattern!(&exec_data, [{ &selected_id @ model_chat::about_request: ?rid }])
                                    ).next();

                                    // Model name lives on the request entity.
                                    let model = request_id.and_then(|rid| {
                                        find!(v: String, pattern!(&exec_data, [{ &rid @ model_chat::model: ?v }])).next()
                                    });
                                    // Token counts live on the result entity.
                                    let input_tok = load_u256(&exec_data, model_chat::input_tokens);
                                    let output_tok = load_u256(&exec_data, model_chat::output_tokens);
                                    let cache_create = load_u256(&exec_data, model_chat::cache_creation_input_tokens);
                                    let cache_read = load_u256(&exec_data, model_chat::cache_read_input_tokens);
                                    if model.is_some() || input_tok.is_some() {
                                        ui.horizontal_wrapped(|ui| {
                                            if let Some(ref m) = model {
                                                inline_pill(ui, "", m, color_cognition());
                                            }
                                            if let Some(i) = input_tok {
                                                inline_pill(ui, "in", &format!("{i}"), color_frame());
                                            }
                                            if let Some(o) = output_tok {
                                                inline_pill(ui, "out", &format!("{o}"), color_frame());
                                            }
                                            if let Some(c) = cache_read {
                                                if c > 0 {
                                                    inline_pill(ui, "cache", &format!("{c}"), color_done());
                                                }
                                            }
                                            if let Some(c) = cache_create {
                                                if c > 0 {
                                                    inline_pill(ui, "+cache", &format!("{c}"), color_doing());
                                                }
                                            }
                                        });
                                        ui.add_space(4.0);
                                    }
                                    // Context/memory lives on the request entity.
                                    if let Some(rid) = request_id {
                                        if let Some(context) = load_blob_of(&exec_data, &rid, model_chat::context) {
                                            text_block(ui, "memory", &context, muted);
                                        }
                                    }
                                    // Output, reasoning, error live on the result entity.
                                    if let Some(output) = load_blob!(&exec_data, model_chat::output_text) {
                                        text_block(ui, "output", &output, muted);
                                    }
                                    if let Some(reasoning) = load_blob!(&exec_data, model_chat::reasoning_text) {
                                        text_block(ui, "reasoning", &reasoning, muted);
                                    }
                                    if let Some(err) = load_blob!(&exec_data, model_chat::error) {
                                        if !err.trim().is_empty() {
                                            text_block(ui, "error", &err, red);
                                        }
                                    }
                                }
                                TimelineSource::LocalMessages => {
                                    // From/to IDs.
                                    let from_id: Option<Id> = find!(
                                        v: Id,
                                        pattern!(&local_data, [{ &selected_id @ local_messages::from: ?v }])
                                    ).next();
                                    let to_id: Option<Id> = find!(
                                        v: Id,
                                        pattern!(&local_data, [{ &selected_id @ local_messages::to: ?v }])
                                    ).next();
                                    // Resolve names from relations branch.
                                    let resolve_name = |pid: Id| -> String {
                                        find!(
                                            name: String,
                                            pattern!(&relations_data, [{ &pid @ relations::alias: ?name }])
                                        ).next().unwrap_or_else(|| id_prefix(pid))
                                    };
                                    if from_id.is_some() || to_id.is_some() {
                                        ui.horizontal_wrapped(|ui| {
                                            if let Some(fid) = from_id {
                                                inline_pill(ui, "from", &resolve_name(fid), color_local_msg());
                                            }
                                            if let Some(tid) = to_id {
                                                inline_pill(ui, "to", &resolve_name(tid), color_frame());
                                            }
                                        });
                                        ui.add_space(4.0);
                                    }
                                    if let Some(body) = load_blob!(&local_data, local_messages::body) {
                                        text_block(ui, "message", &body, muted);
                                    }
                                    // Read receipts: entities with about_message → selected_id.
                                    let read_receipts: Vec<(String, i128)> = find!(
                                        (reader_id: Id, read_at: Value<NsTAIInterval>),
                                        pattern!(&local_data, [{
                                            _?receipt @
                                            local_messages::about_message: &selected_id,
                                            local_messages::reader: ?reader_id,
                                            metadata::updated_at: ?read_at,
                                        }])
                                    ).map(|(rid, ts)| (resolve_name(rid), interval_key(ts))).collect();
                                    if !read_receipts.is_empty() {
                                        ui.horizontal_wrapped(|ui| {
                                            for (name, ts) in &read_receipts {
                                                inline_pill(ui, "read by", name, color_read());
                                                ui.label(egui::RichText::new(format_time_marker(*ts)).monospace().small().color(muted));
                                            }
                                        });
                                        ui.add_space(4.0);
                                    }
                                }
                                TimelineSource::Teams => {
                                    // Chat name.
                                    let chat_id: Option<Id> = find!(
                                        v: Id,
                                        pattern!(&teams_data, [{ &selected_id @ teams::chat: ?v }])
                                    ).next();
                                    let chat_name = chat_id.and_then(|cid| {
                                        load_blob_of(&teams_data, &cid, teams::chat_id)
                                    });
                                    // Author metadata.
                                    let author_name = load_blob!(&teams_data, archive::author_name);
                                    let author_role = load_blob!(&teams_data, archive::author_role);
                                    let author_model = load_blob!(&teams_data, archive::author_model);
                                    if author_name.is_some() || author_role.is_some() || chat_name.is_some() {
                                        ui.horizontal_wrapped(|ui| {
                                            if let Some(ref chat) = chat_name {
                                                inline_pill(ui, "chat", chat, color_frame());
                                            }
                                            if let Some(ref name) = author_name {
                                                inline_pill(ui, "", name, color_teams());
                                            }
                                            if let Some(ref role) = author_role {
                                                let role_color = match role.as_str() {
                                                    "user" => color_user(),
                                                    "assistant" => color_assistant(),
                                                    "system" => color_system(),
                                                    _ => color_frame(),
                                                };
                                                inline_pill(ui, "", role, role_color);
                                            }
                                            if let Some(ref m) = author_model {
                                                ui.label(egui::RichText::new(m).monospace().small().color(muted));
                                            }
                                        });
                                        ui.add_space(4.0);
                                    }
                                    if let Some(content) = load_blob!(&teams_data, archive::content) {
                                        text_block(ui, "content", &content, muted);
                                    }
                                }
                                TimelineSource::Goals => {
                                    // Could be a goal entity or a status/note event.
                                    let title = load_blob!(&compass_data, compass::title);
                                    let status = load_short(&compass_data, compass::status);
                                    let note = load_blob!(&compass_data, compass::note);

                                    // If it's a status/note event, resolve parent goal.
                                    let goal_id: Option<Id> = find!(
                                        v: Id,
                                        pattern!(&compass_data, [{ &selected_id @ compass::task: ?v }])
                                    ).next();
                                    let goal_title = goal_id.and_then(|gid| {
                                        load_blob_of(&compass_data, &gid, compass::title)
                                    });

                                    // Tags on the goal (or on this entity if it is the goal).
                                    let tag_target = goal_id.unwrap_or(selected_id);
                                    let tags: Vec<String> = find!(
                                        v: String,
                                        pattern!(&compass_data, [{ &tag_target @ compass::tag: ?v }])
                                    ).collect();

                                    // Pill row.
                                    if status.is_some() || !tags.is_empty() {
                                        ui.horizontal_wrapped(|ui| {
                                            if let Some(ref s) = status {
                                                let status_color = match s.as_str() {
                                                    "todo" => color_todo(),
                                                    "doing" => color_doing(),
                                                    "blocked" => color_blocked(),
                                                    "done" => color_done(),
                                                    _ => color_frame(),
                                                };
                                                inline_pill(ui, "", s, status_color);
                                            }
                                            for t in &tags {
                                                inline_pill(ui, "", t, colorhash::ral_categorical(t.as_bytes()));
                                            }
                                        });
                                        ui.add_space(4.0);
                                    }

                                    // Goal title (own title or parent goal).
                                    if let Some(ref t) = title {
                                        text_block(ui, "goal", t, muted);
                                    } else if let Some(ref t) = goal_title {
                                        text_block(ui, "goal", t, muted);
                                    }

                                    // Parent goal hierarchy.
                                    let actual_goal = goal_id.unwrap_or(selected_id);
                                    let parent_id: Option<Id> = find!(
                                        v: Id,
                                        pattern!(&compass_data, [{ &actual_goal @ compass::parent: ?v }])
                                    ).next();
                                    if let Some(pid) = parent_id {
                                        let parent_title = load_blob_of(&compass_data, &pid, compass::title);
                                        if let Some(ref pt) = parent_title {
                                            ui.horizontal(|ui| {
                                                ui.label(egui::RichText::new("parent").small().color(muted));
                                                ui.label(egui::RichText::new(pt).small());
                                            });
                                            ui.add_space(4.0);
                                        }
                                    }

                                    // Note body (if this is a note event).
                                    if let Some(ref n) = note {
                                        text_block(ui, "note", n, muted);
                                    }
                                }
                                TimelineSource::Wiki => {
                                    // Wiki tags (excluding the kind_version tag).
                                    let tags: Vec<Id> = find!(
                                        tag: Id,
                                        pattern!(&wiki_data, [{ &selected_id @ metadata::tag: ?tag }])
                                    ).filter(|t| *t != wiki::kind_version).collect();
                                    // Resolve tag names upfront via load_blob_of.
                                    let tag_names: Vec<(Id, String)> = tags.iter().map(|tag| {
                                        let name = load_blob_of(&wiki_data, tag, metadata::name)
                                            .unwrap_or_else(|| id_prefix(*tag));
                                        (*tag, name)
                                    }).collect();
                                    if !tag_names.is_empty() {
                                        ui.horizontal_wrapped(|ui| {
                                            for (_tag, name) in &tag_names {
                                                inline_pill(ui, "", name, colorhash::ral_categorical(name.as_bytes()));
                                            }
                                        });
                                        ui.add_space(4.0);
                                    }
                                    // Title.
                                    if let Some(title) = load_blob!(&wiki_data, wiki::title) {
                                        ui.label(egui::RichText::new(&title).strong());
                                        ui.add_space(4.0);
                                    }
                                    // Typst content.
                                    if let Some(content) = load_blob!(&wiki_data, wiki::content) {
                                        ui.typst(&content);
                                    }
                                }
                            }
                        }); });
                    });
                    if resp.closed {
                        state.context_float_request_id = None;
                    }
                });
            }
        });
    });

    // ── Agent Config ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);

        // Pull a workspace for blob reads before entering the section closure.
        let mut ws = state.pile.repo_mut().and_then(|repo| {
            let branch_entries = list_branches(repo.storage_mut()).ok()?;
            let lookup = BranchLookup::new(&branch_entries);
            let refs = parse_branch_list(BRANCH_CONFIG);
            let ids = resolve_branch_ids(&lookup, &refs).ok()?;
            repo.pull(*ids.first()?).ok()
        });

        ui.section("Agent Config", |ui| {
            ui.grid(|g| g.full(|ui| {
            // Show branch resolution error when the configured branch can't be found.
            if state.config_cat.co.is_none() {
                let branch_lookup = BranchLookup::new(&state.branches);
                let refs = parse_branch_list(BRANCH_CONFIG);
                if let Err(err) = resolve_branch_ids(&branch_lookup, &refs) {
                    ui.colored_label(egui::Color32::RED, err);
                    return;
                }
            }

            let data = state.config_cat.catalog().clone();
            let now_key = state.now_key;
            render_agent_config(ui, &mut state.config_reveal_secrets, now_key, &data, &mut ws);
            }));
        });
    });

    // ── Context Compaction ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);

        // Pull workspace for blob reads.
        let exec_branch = state.config.exec_branch.clone();
        let mut ws = state.pile.repo_mut().and_then(|repo| {
            let branch_entries = list_branches(repo.storage_mut()).ok()?;
            let lookup = BranchLookup::new(&branch_entries);
            let refs = parse_branch_list(&exec_branch);
            let ids = resolve_branch_ids(&lookup, &refs).ok()?;
            repo.pull(*ids.first()?).ok()
        });

        let exec_data = state.exec_cat.catalog().clone();
        let now_key = state.now_key;
        let context_selected_chunk = state.context_selected_chunk;
        let context_show_children = state.context_show_children;
        let context_show_origins = state.context_show_origins;

        ui.section("Context Compaction", |ui| {
            ui.grid(|g| g.full(|ui| {
            let chunks = collect_context_chunks(&exec_data);
            if chunks.is_empty() {
                ui.label("No context chunks yet.");
                return;
            }
            let selected = ws.as_mut().map(|ws| {
                build_context_selected(
                    ws,
                    &chunks,
                    context_selected_chunk,
                    context_show_children,
                    context_show_origins,
                )
            }).flatten();
            render_context_compaction(ui, &mut state, now_key, &chunks, selected.as_ref());
            }));
        });
    });

    // ── Compass ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);

        // Pull workspace before entering the section closure to avoid borrow conflicts.
        let mut ws = state.pile.repo_mut().and_then(|repo| {
            let branch_entries = list_branches(repo.storage_mut()).ok()?;
            let lookup = BranchLookup::new(&branch_entries);
            let refs = parse_branch_list(BRANCH_COMPASS);
            let ids = resolve_branch_ids(&lookup, &refs).ok()?;
            repo.pull(*ids.first()?).ok()
        });

        // Resolve branch error and clone the catalog before the section closure
        // so we don't hold an immutable borrow on state while also borrowing it mutably.
        let compass_branch_err =
            if state.compass_cat.co.is_none() {
                let branch_lookup = BranchLookup::new(&state.branches);
                let refs = parse_branch_list(BRANCH_COMPASS);
                resolve_branch_ids(&branch_lookup, &refs).err()
            } else {
                None
            };
        let compass_data = state.compass_cat.catalog().clone();

        ui.section("Compass", |ui| {
            ui.grid(|g| g.full(|ui| {
            if let Some(err) = compass_branch_err {
                ui.colored_label(egui::Color32::RED, err);
                return;
            }

            render_compass_swimlanes_live(
                ui,
                &mut state.compass_expanded_goal,
                &compass_data,
                &mut ws,
            );
            }));
        });
    });

    // ── Messages ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);

        // Pull workspace for relations blob reads (person labels).
        let mut ws = state.pile.repo_mut().and_then(|repo| {
            let branch_entries = list_branches(repo.storage_mut()).ok()?;
            let lookup = BranchLookup::new(&branch_entries);
            let refs = parse_branch_list(BRANCH_RELATIONS);
            let ids = resolve_branch_ids(&lookup, &refs).ok()?;
            repo.pull(*ids.first()?).ok()
        });

        // Collect relations for person picker.
        let relations_data = state.relations_cat.catalog().clone();
        let people = if let Some(ref mut ws) = ws {
            collect_relations_people(&relations_data, ws)
        } else {
            Vec::new()
        };
        let relations_labels = collect_relations_labels(&people);
        let local_me_id = resolve_person_ref(&people, &state.config.local_me);
        let local_peer_id = resolve_person_ref(&people, &state.config.local_peer);
        let branches = state.branches.clone();

        let local_message_err =
            if state.local_messages_cat.co.is_none() {
                let branch_lookup = BranchLookup::new(&state.branches);
                let refs = parse_branch_list(BRANCH_LOCAL_MESSAGES);
                resolve_branch_ids(&branch_lookup, &refs).err()
            } else {
                None
            };

        ui.section("Messages", |ui| {
            ui.grid(|g| g.full(|ui| {
            if let Some(err) = local_message_err {
                ui.colored_label(egui::Color32::RED, err);
            }
            render_local_composer(ui, &mut state, &branches, &people, &relations_labels, local_me_id, local_peer_id);
            }));
        });
    });

    // ── Relations ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);

        // Pull a workspace for blob reads before entering the section closure.
        let mut ws = state.pile.repo_mut().and_then(|repo| {
            let branch_entries = list_branches(repo.storage_mut()).ok()?;
            let lookup = BranchLookup::new(&branch_entries);
            let refs = parse_branch_list(BRANCH_RELATIONS);
            let ids = resolve_branch_ids(&lookup, &refs).ok()?;
            repo.pull(*ids.first()?).ok()
        });

        ui.section("Relations", |ui| {
            // Show branch resolution error when the configured branch can't be found.
            if state.relations_cat.co.is_none() {
                let branch_lookup = BranchLookup::new(&state.branches);
                let refs = parse_branch_list(BRANCH_RELATIONS);
                if let Err(err) = resolve_branch_ids(&branch_lookup, &refs) {
                    ui.colored_label(egui::Color32::RED, err);
                    return;
                }
            }

            let data = state.relations_cat.catalog();
            if data.is_empty() {
                ui.label("No relations.");
                return;
            }

            let person_ids: Vec<Id> = find!(
                person_id: Id,
                pattern!(data, [{ ?person_id @ metadata::tag: &RELATIONS_KIND_PERSON_ID }])
            )
            .collect();

            if person_ids.is_empty() {
                ui.label("No relations.");
                return;
            }

            // Collect and sort people by label for stable ordering.
            struct PersonEntry {
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

            let mut people: Vec<PersonEntry> = person_ids
                .into_iter()
                .map(|id| PersonEntry {
                    id,
                    label: None,
                    first_name: None,
                    last_name: None,
                    display_name: None,
                    affinity: None,
                    teams_user_id: None,
                    email: None,
                    note: None,
                    aliases: Vec::new(),
                })
                .collect();

            // Resolve blob-backed attributes.
            for person in &mut people {
                let pid = person.id;

                for handle in find!(
                    handle: Value<Handle<Blake3, LongString>>,
                    pattern!(data, [{ &pid @ metadata::name: ?handle }])
                ) {
                    if person.label.is_none() {
                        person.label = ws.as_mut().and_then(|w| load_text(w, handle));
                    }
                }
                for handle in find!(
                    handle: Value<Handle<Blake3, LongString>>,
                    pattern!(data, [{ &pid @ relations::display_name: ?handle }])
                ) {
                    if person.display_name.is_none() {
                        person.display_name = ws.as_mut().and_then(|w| load_text(w, handle));
                    }
                }
                for handle in find!(
                    handle: Value<Handle<Blake3, LongString>>,
                    pattern!(data, [{ &pid @ relations::first_name: ?handle }])
                ) {
                    if person.first_name.is_none() {
                        person.first_name = ws.as_mut().and_then(|w| load_text(w, handle));
                    }
                }
                for handle in find!(
                    handle: Value<Handle<Blake3, LongString>>,
                    pattern!(data, [{ &pid @ relations::last_name: ?handle }])
                ) {
                    if person.last_name.is_none() {
                        person.last_name = ws.as_mut().and_then(|w| load_text(w, handle));
                    }
                }
                for handle in find!(
                    handle: Value<Handle<Blake3, LongString>>,
                    pattern!(data, [{ &pid @ metadata::description: ?handle }])
                ) {
                    if person.note.is_none() {
                        person.note = ws.as_mut().and_then(|w| load_text(w, handle));
                    }
                }

                // ShortString attributes — no blob read needed.
                for value in find!(
                    value: String,
                    pattern!(data, [{ &pid @ relations::affinity: ?value }])
                ) {
                    if person.affinity.is_none() {
                        person.affinity = Some(value);
                    }
                }
                for value in find!(
                    value: String,
                    pattern!(data, [{ &pid @ relations::teams_user_id: ?value }])
                ) {
                    if person.teams_user_id.is_none() {
                        person.teams_user_id = Some(value);
                    }
                }
                for value in find!(
                    value: String,
                    pattern!(data, [{ &pid @ relations::email: ?value }])
                ) {
                    if person.email.is_none() {
                        person.email = Some(value);
                    }
                }
                for value in find!(
                    value: String,
                    pattern!(data, [{ &pid @ relations::alias: ?value }])
                ) {
                    person.aliases.push(value);
                }
            }

            people.sort_by(|a, b| a.label.cmp(&b.label).then_with(|| a.id.cmp(&b.id)));

            // Render person cards.
            ui.small(format!("{} people", people.len()));
            ui.grid(|g| {
                for person in &people {
                    let label = person.label.as_deref().unwrap_or("<unnamed>");
                    let fill = colorhash::ral_categorical(label.as_bytes());
                    let full_name = match (&person.first_name, &person.last_name) {
                        (Some(first), Some(last)) => Some(format!("{first} {last}")),
                        (Some(first), None) => Some(first.clone()),
                        (None, Some(last)) => Some(last.clone()),
                        (None, None) => None,
                    };

                    g.half(|ui| {
                        let w = ui.available_width();
                        egui::Frame::NONE
                            .fill(color_frame())
                            .corner_radius(egui::CornerRadius::same(4))
                            .inner_margin(egui::Margin::symmetric(10, 8))
                            .show(ui, |ui| {
                                ui.set_min_width(w - 20.0);
                                // Header: colored name chip + ID
                                ui.horizontal(|ui| {
                                    render_person_chip(ui, label, fill);
                                    ui.small(
                                        egui::RichText::new(id_prefix(person.id))
                                            .monospace()
                                            .color(color_muted()),
                                    );
                                    if let Some(affinity) = &person.affinity {
                                        render_person_chip(ui, affinity, color_muted());
                                    }
                                });

                                // Details row
                                let mut details = Vec::new();
                                if let Some(name) = person.display_name.as_ref().or(full_name.as_ref()) {
                                    details.push(name.clone());
                                }
                                if let Some(email) = &person.email {
                                    details.push(email.clone());
                                }
                                if let Some(teams) = &person.teams_user_id {
                                    details.push(format!("teams: {teams}"));
                                }
                                if !details.is_empty() {
                                    ui.small(details.join(" · "));
                                }
                                if !person.aliases.is_empty() {
                                    ui.small(format!("aliases: {}", person.aliases.join(", ")));
                                }
                                if let Some(note) = &person.note {
                                    ui.small(
                                        egui::RichText::new(truncate_single_line(note, 120))
                                            .color(color_muted()),
                                    );
                                }
                            });
                    });
                }
            });
        });
    });

    // ── Teams ─
    nb.view(move |ui| {
        let mut state = dashboard.read_mut(ui);

        // Pull workspace for blob reads.
        let mut ws = state.pile.repo_mut().and_then(|repo| {
            let branch_entries = list_branches(repo.storage_mut()).ok()?;
            let lookup = BranchLookup::new(&branch_entries);
            let refs = parse_branch_list(BRANCH_TEAMS);
            let ids = resolve_branch_ids(&lookup, &refs).ok()?;
            repo.pull(*ids.first()?).ok()
        });

        let teams_branch_err =
            if state.teams_cat.co.is_none() {
                let branch_lookup = BranchLookup::new(&state.branches);
                let refs = parse_branch_list(BRANCH_TEAMS);
                resolve_branch_ids(&branch_lookup, &refs).err()
            } else {
                None
            };
        let teams_data = state.teams_cat.catalog().clone();
        let now_key = state.now_key;

        ui.section("Teams", |ui| {
            ui.grid(|g| g.full(|ui| {
            if let Some(err) = teams_branch_err {
                ui.colored_label(egui::Color32::RED, err);
            } else if let Some(ref mut ws) = ws {
                let (messages, chats) = collect_teams_messages(&teams_data, ws);
                render_teams_conversations(ui, &mut state, now_key, &chats, &messages);
            } else if !teams_data.is_empty() {
                ui.label("No workspace available for blob reads.");
            }
            }));
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


fn should_refresh(state: &DashboardState) -> bool {
    if diagnostics_is_headless() {
        return true;
    }
    match state.last_refresh_at {
        None => true,
        Some(last) => last.elapsed() >= Duration::from_millis(CATALOG_REFRESH_MS),
    }
}

/// Apply branch name defaults from the latest agent config in the config catalog.
fn apply_branch_defaults(state: &mut DashboardState) {
    let config_data = state.config_cat.catalog();
    if config_data.is_empty() {
        return;
    }

    // Find the latest config entity by metadata::updated_at.
    let mut latest: Option<(Id, i128)> = None;
    for (config_id, updated_at) in find!(
        (config_id: Id, updated_at: Value<NsTAIInterval>),
        pattern!(config_data, [{
            ?config_id @
            metadata::tag: playground_config::kind_config,
            metadata::updated_at: ?updated_at,
        }])
    ) {
        let key = interval_key(updated_at);
        if latest.map_or(true, |(_, current)| key > current) {
            latest = Some((config_id, key));
        }
    }

    let Some((config_id, _)) = latest else {
        return;
    };

    if state.config_last_applied_id == Some(config_id) {
        return;
    }

    // Extract the exec branch name from the agent config.
    // The branch field is a blob handle — pull a workspace for the read.
    let branch = state.pile.repo_mut().and_then(|repo| {
        let branch_entries = list_branches(repo.storage_mut()).ok()?;
        let lookup = BranchLookup::new(&branch_entries);
        let refs = parse_branch_list(BRANCH_CONFIG);
        let ids = resolve_branch_ids(&lookup, &refs).ok()?;
        let mut ws = repo.pull(*ids.first()?).ok()?;
        load_optional_string_attr(config_data, &mut ws, config_id, playground_config::branch)
    });

    if let Some(branch) = branch {
        state.config.exec_branch = branch;
    }

    state.config_last_applied_id = Some(config_id);
}

/// Refresh per-branch workspace + catalog state from the repository.
fn refresh_catalogs(state: &mut DashboardState) {
    let repo = match state.pile.repo_mut() {
        Some(r) => r,
        None => return,
    };

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

    state.branches = list_branches(repo.storage_mut()).unwrap_or_default();

    let branch_lookup = BranchLookup::new(&state.branches);

    /// Resolve branch names, pull workspace, and update the checkout in place.
    /// Progressive history loading for a single branch.
    ///
    /// - First call: initialize frontier to HEAD, then checkout the first
    ///   chunk (nth_ancestors(head, chunk)..head).
    /// - Subsequent calls while `!fully_loaded`: compute new_frontier =
    ///   nth_ancestors(frontier, chunk), checkout new_frontier..frontier,
    ///   merge into existing checkout, advance frontier.
    /// - Once fully loaded: incremental delta from HEAD (new commits only).
    fn refresh_role(
        repo: &mut Repository<Pile>,
        branch_lookup: &BranchLookup,
        branch_names: &str,
        cat: &mut BranchCatalog,
        chunk_size: usize,
    ) {
        let refs = parse_branch_list(branch_names);
        let ids = match resolve_branch_ids(branch_lookup, &refs) {
            Ok(ids) if !ids.is_empty() => ids,
            _ => return,
        };

        if ids.len() == 1 {
            let mut ws = match repo.pull(ids[0]) {
                Ok(ws) => ws,
                Err(_) => return,
            };
            let Some(head) = ws.head() else {
                cat.reset();
                return;
            };

            if cat.fully_loaded {
                // Incremental: pick up new commits at HEAD.
                if let Some(ref mut existing) = cat.co {
                    if let Ok(delta) = ws.checkout(existing.commits()..) {
                        if !delta.facts().is_empty() {
                            *existing += &delta;
                        }
                    }
                }
                return;
            }

            if cat.frontier.is_empty() && cat.co.is_none() {
                // First call: set frontier to HEAD.
                let mut f = CommitSet::new();
                f.insert(&triblespace::core::patch::Entry::new(&head.raw));
                cat.frontier = f;
            }

            // Compute new frontier by walking back chunk_size steps.
            let new_frontier = match nth_ancestors(cat.frontier.clone(), chunk_size).select(&mut ws) {
                Ok(f) => f,
                Err(_) => {
                    cat.fully_loaded = true;
                    return;
                }
            };

            // Checkout the chunk between new_frontier (exclusive) and frontier (inclusive).
            match ws.checkout(new_frontier.clone()..cat.frontier.clone()) {
                Ok(chunk) => {
                    match &mut cat.co {
                        Some(existing) => *existing += &chunk,
                        None => cat.co = Some(chunk),
                    }
                }
                Err(_) => {
                    cat.fully_loaded = true;
                    return;
                }
            }

            if new_frontier.is_empty() {
                cat.fully_loaded = true;
            } else {
                cat.frontier = new_frontier;
            }
        } else {
            // Multi-branch: full checkout (progressive loading not yet supported).
            let mut merged: Option<Checkout> = None;
            for branch_id in &ids {
                let mut ws = match repo.pull(*branch_id) {
                    Ok(ws) => ws,
                    Err(_) => continue,
                };
                if ws.head().is_some() {
                    if let Ok(checkout) = ws.checkout(..) {
                        match &mut merged {
                            Some(m) => *m += &checkout,
                            None => merged = Some(checkout),
                        }
                    }
                }
            }
            cat.co = merged;
            cat.fully_loaded = true;
        }
    }

    let chunk = HISTORY_CHUNK_SIZE;
    refresh_role(repo, &branch_lookup, BRANCH_CONFIG, &mut state.config_cat, chunk);
    refresh_role(repo, &branch_lookup, &state.config.exec_branch, &mut state.exec_cat, chunk);
    refresh_role(repo, &branch_lookup, BRANCH_COMPASS, &mut state.compass_cat, chunk);
    refresh_role(repo, &branch_lookup, BRANCH_LOCAL_MESSAGES, &mut state.local_messages_cat, chunk);
    refresh_role(repo, &branch_lookup, BRANCH_RELATIONS, &mut state.relations_cat, chunk);
    refresh_role(repo, &branch_lookup, BRANCH_TEAMS, &mut state.teams_cat, chunk);
    refresh_role(repo, &branch_lookup, BRANCH_WIKI, &mut state.wiki_cat, chunk);

    state.now_key = epoch_key(now_epoch());
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

fn latest_model_profile_entry_id(data: &TribleSet, profile_id: Id) -> Option<Id> {
    let mut latest: Option<(Id, i128)> = None;
    for (entry_id, updated_at) in find!(
        (entry_id: Id, updated_at: Value<NsTAIInterval>),
        pattern!(data, [{
            ?entry_id @
            metadata::tag: playground_config::kind_model_profile,
            metadata::updated_at: ?updated_at,
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
            metadata::created_at: ?created_at,
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
            let a_key = a_row.map(|row| row.sort_key()).unwrap_or(i128::MIN);
            let b_key = b_row.map(|row| row.sort_key()).unwrap_or(i128::MIN);
            b_key
                .cmp(&a_key)
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

fn render_local_composer(
    ui: &mut egui::Ui,
    state: &mut DashboardState,
    branches: &[BranchEntry],
    people: &[RelationRow],
    labels: &HashMap<Id, String>,
    me_id: Option<Id>,
    peer_id: Option<Id>,
) {
    let me_label = me_id
        .and_then(|id| labels.get(&id).cloned())
        .unwrap_or_else(|| state.config.local_me.clone());
    let peer_label = peer_id
        .and_then(|id| labels.get(&id).cloned())
        .unwrap_or_else(|| state.config.local_peer.clone());

    let accent = color_local_msg();
    let me_fill = me_id
        .map(|id| colorhash::ral_categorical(id.as_ref()))
        .unwrap_or(color_muted());
    let peer_fill = peer_id
        .map(|id| colorhash::ral_categorical(id.as_ref()))
        .unwrap_or(color_muted());

    ui.horizontal(|ui| {
        render_person_chip(ui, "Me", me_fill);
        render_person_picker(
            ui,
            "local_me_picker",
            people,
            me_id,
            &mut state.config.local_me,
        );
        ui.add_space(10.0);
        render_person_chip(ui, "Peer", peer_fill);
        render_person_picker(
            ui,
            "local_peer_picker",
            people,
            peer_id,
            &mut state.config.local_peer,
        );
    });

    // Direction indicator: colored chips for me → peer.
    ui.horizontal(|ui| {
        render_person_chip(ui, &me_label, me_fill);
        ui.label(egui::RichText::new("\u{2192}").color(color_muted()).small());
        render_person_chip(ui, &peer_label, peer_fill);
    });

    let me_known = me_id.is_some();
    let peer_known = peer_id.is_some();
    if !(me_known && peer_known) {
        ui.small("Select Me and Peer from Relations to enable sending.");
    }

    // Compose area with subtle accent frame.
    egui::Frame::NONE
        .stroke(egui::Stroke::new(1.0, themes::blend(accent, color_frame(), 0.5)))
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::same(4))
        .show(ui, |ui| {
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
        });

    ui.horizontal(|ui| {
        let can_send = me_known && peer_known && !state.local_draft.trim().is_empty();
        if ui
            .add_enabled(can_send, Button::new("Send").fill(accent))
            .clicked()
        {
            send_local_message_from_ui(state, branches, me_id, peer_id);
        }
        if ui.add(Button::new("Clear").fill(color_frame())).clicked() {
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
        .width(ui.available_width())
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

fn render_teams_conversations(
    ui: &mut GORBIE::CardCtx<'_>,
    state: &mut DashboardState,
    now_key: i128,
    chats: &[TeamsChatRow],
    messages: &[TeamsMessageRow],
) {
    ui.grid(|g| {
        // ── Chat list pane (4 cols) ──
        g.third(|ui| {
            ui.set_min_height(TEAMS_SCROLL_HEIGHT);
            ui.label("Chats");
            ui.add_space(6.0);

            // "All chats" entry — distinct style: Teams accent border, no count chip.
            let all_selected = state.teams_selected_chat.is_none();
            let all_bg = if all_selected {
                color_frame()
            } else {
                egui::Color32::TRANSPARENT
            };
            let resp = egui::Frame::NONE
                .fill(all_bg)
                .stroke(egui::Stroke::new(1.0, color_teams()))
                .corner_radius(egui::CornerRadius::same(4))
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("All chats")
                            .color(color_teams())
                            .strong(),
                    );
                })
                .response;
            if resp.interact(egui::Sense::click()).clicked() {
                state.teams_selected_chat = None;
            }

            ui.add_space(6.0);

            for chat in chats {
                let selected = state.teams_selected_chat == Some(chat.id);
                let card_bg = if selected {
                    color_frame()
                } else {
                    egui::Color32::TRANSPARENT
                };
                let resp = egui::Frame::NONE
                    .fill(card_bg)
                    .corner_radius(egui::CornerRadius::same(4))
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(&chat.label);
                            // Message count chip
                            render_goal_chip(
                                ui,
                                &chat.message_count.to_string(),
                                color_muted(),
                            );
                        });
                        // Age in muted text
                        ui.label(
                            egui::RichText::new(format_age(now_key, chat.last_at))
                                .small()
                                .color(color_muted()),
                        );
                    })
                    .response;
                if resp.interact(egui::Sense::click()).clicked() {
                    state.teams_selected_chat = Some(chat.id);
                }
                ui.add_space(6.0);
            }
        });

        // ── Message pane (8 cols) ──
        g.two_thirds(|ui| {
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
            ui.add_space(6.0);

            for row in messages {
                if let Some(chat_id) = selected_chat {
                    if row.chat_id != chat_id {
                        continue;
                    }
                }
                let author = row.author_name.as_deref().unwrap_or("<unknown>");
                let age = format_age(now_key, row.created_at);
                let author_color = colorhash::ral_categorical(author.as_bytes());

                egui::Frame::NONE
                    .fill(color_frame())
                    .corner_radius(egui::CornerRadius::same(4))
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        // Header: author chip · chat label (when showing all) · age
                        ui.horizontal(|ui| {
                            render_person_chip(ui, author, author_color);
                            if selected_chat.is_none() {
                                let chat_label = chats
                                    .iter()
                                    .find(|chat| chat.id == row.chat_id)
                                    .map(|chat| chat.label.as_str())
                                    .unwrap_or("<chat>");
                                ui.label(
                                    egui::RichText::new(chat_label)
                                        .small()
                                        .color(color_muted()),
                                );
                            }
                            ui.label(
                                egui::RichText::new(age).small().color(color_muted()),
                            );
                        });
                        // Message body
                        render_blob_aware_text(ui, row.content.as_str(), None, None);
                    });
                ui.add_space(6.0);
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
    me_id: Option<Id>,
    peer_id: Option<Id>,
) {
    state.local_send_error = None;
    state.local_send_notice = None;

    let Some(repo) = state.pile.repo_mut() else {
        state.local_send_error = Some("Repository not open.".to_string());
        return;
    };

    let body = state.local_draft.trim();
    if body.is_empty() {
        state.local_send_error = Some("Message is empty.".to_string());
        return;
    }

    let branch_lookup = BranchLookup::new(branches);
    let refs = parse_branch_list(BRANCH_LOCAL_MESSAGES);
    let branch_id = match resolve_single_branch(&branch_lookup, &refs) {
        Ok(branch_id) => branch_id,
        Err(err) => {
            state.local_send_error = Some(err);
            return;
        }
    };

    let Some(from_id) = me_id else {
        state.local_send_error = Some(format!(
            "Unknown me '{}' (check Relations branch).",
            state.config.local_me
        ));
        return;
    };
    let Some(to_id) = peer_id else {
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
        metadata::created_at: now_interval,
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
        ws.checkout(..).map_err(|err| format!("checkout: {err}"))?.into_facts()
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

fn render_agent_config(
    ui: &mut egui::Ui,
    reveal_secrets: &mut bool,
    now_key: i128,
    data: &TribleSet,
    ws: &mut Option<Workspace<Pile>>,
) {
    if data.is_empty() {
        ui.label("No config entries.");
        return;
    }

    // Find the latest config entity.
    let mut latest: Option<(Id, i128)> = None;
    for (config_id, updated_at) in find!(
        (config_id: Id, updated_at: Value<NsTAIInterval>),
        pattern!(data, [{
            ?config_id @
            metadata::tag: playground_config::kind_config,
            metadata::updated_at: ?updated_at,
        }])
    ) {
        let key = interval_key(updated_at);
        if latest.map_or(true, |(_, current)| key > current) {
            latest = Some((config_id, key));
        }
    }

    let Some((config_id, updated_key)) = latest else {
        ui.label("No config entries.");
        return;
    };
    let updated = format_age(now_key, Some(updated_key));
    ui.label(format!(
        "Latest config: {} (updated {updated})",
        id_prefix(config_id)
    ));
    ui.add_space(8.0);

    // Helper closures for inline attribute loading.
    let load_str = |entity_id: Id, attr: Attribute<Handle<Blake3, LongString>>, ws: &mut Option<Workspace<Pile>>| -> Option<String> {
        find!(
            handle: Value<Handle<Blake3, LongString>>,
            pattern!(data, [{ entity_id @ attr: ?handle }])
        )
        .next()
        .and_then(|handle| ws.as_mut().and_then(|w| load_text(w, handle)))
    };
    let load_id = |entity_id: Id, attr: Attribute<GenId>| -> Option<Id> {
        load_optional_id_attr(data, entity_id, attr)
    };
    let load_u64 = |entity_id: Id, attr: Attribute<U256BE>| -> Option<u64> {
        load_optional_u64_attr(data, entity_id, attr)
    };

    // Resolve model profile: if an active profile is set, use the latest profile entry.
    let persona_id = load_id(config_id, playground_config::persona_id);
    let branch = load_str(config_id, playground_config::branch, ws);
    let author = load_str(config_id, playground_config::author, ws);
    let author_role = load_str(config_id, playground_config::author_role, ws);
    let poll_ms = load_u64(config_id, playground_config::poll_ms);
    let model_profile_id = load_id(config_id, playground_config::active_model_profile_id);
    let (model_entity_id, model_profile_name) = if let Some(profile_id) = model_profile_id {
        if let Some(entry_id) = latest_model_profile_entry_id(data, profile_id) {
            let name = load_str(entry_id, metadata::name, ws);
            (entry_id, name)
        } else {
            (config_id, None)
        }
    } else {
        (config_id, None)
    };

    let model_name = load_str(model_entity_id, playground_config::model_name, ws);
    let model_base_url = load_str(model_entity_id, playground_config::model_base_url, ws);
    let model_reasoning_effort = load_str(model_entity_id, playground_config::model_reasoning_effort, ws);
    let model_stream = load_u64(model_entity_id, playground_config::model_stream).map(|v| v != 0);
    let model_context_window_tokens = load_u64(model_entity_id, playground_config::model_context_window_tokens);
    let model_max_output_tokens = load_u64(model_entity_id, playground_config::model_max_output_tokens);
    let model_context_safety_margin_tokens = load_u64(model_entity_id, playground_config::model_context_safety_margin_tokens);
    let model_chars_per_token = load_u64(model_entity_id, playground_config::model_chars_per_token);
    let model_api_key = load_str(model_entity_id, playground_config::model_api_key, ws);
    let tavily_api_key = load_str(config_id, playground_config::tavily_api_key, ws);
    let exa_api_key = load_str(config_id, playground_config::exa_api_key, ws);
    let exec_default_cwd = load_str(config_id, playground_config::exec_default_cwd, ws);
    let exec_sandbox_profile = load_id(config_id, playground_config::exec_sandbox_profile);
    let system_prompt = load_str(config_id, playground_config::system_prompt, ws);

    let config_row = |ui: &mut egui::Ui, label: &str, value: &str| {
        ui.label(egui::RichText::new(label).color(color_muted()));
        ui.label(value);
        ui.end_row();
    };
    let config_row_mono = |ui: &mut egui::Ui, label: &str, value: &str| {
        ui.label(egui::RichText::new(label).color(color_muted()));
        ui.monospace(value);
        ui.end_row();
    };
    let config_header = |ui: &mut egui::Ui, label: &str| {
        let fill = colorhash::ral_categorical(label.as_bytes());
        let text_color = colorhash::text_color_on(fill);
        ui.label(egui::RichText::new(label).strong().color(text_color).background_color(fill));
        ui.label("");
        ui.end_row();
    };

    egui::Grid::new("agent_config_grid")
        .striped(true)
        .spacing(egui::Vec2::new(12.0, 6.0))
        .show(ui, |ui| {
            config_header(ui, "Identity");
            config_row_mono(ui, "config", &id_prefix(config_id));
            config_row_mono(ui, "persona", &persona_id.map(|id| id_prefix(id)).unwrap_or_else(|| "-".to_string()));
            config_row(ui, "branch", branch.as_deref().unwrap_or("-"));
            config_row(ui, "author", author.as_deref().unwrap_or("-"));
            config_row(ui, "role", author_role.as_deref().unwrap_or("-"));
            config_row_mono(ui, "poll ms", &poll_ms.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()));

            config_header(ui, "Model");
            ui.label(egui::RichText::new("profile").color(color_muted()));
            ui.horizontal(|ui| {
                ui.label(model_profile_name.as_deref().unwrap_or("-"));
                if let Some(id) = model_profile_id {
                    ui.monospace(format!("({id:x})"));
                }
            });
            ui.end_row();

            config_row(ui, "model", model_name.as_deref().unwrap_or("-"));
            config_row(ui, "base url", model_base_url.as_deref().unwrap_or("-"));
            config_row(ui, "reasoning", model_reasoning_effort.as_deref().unwrap_or("-"));
            config_row_mono(ui, "stream", &model_stream.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()));
            config_row_mono(ui, "context window", &model_context_window_tokens.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()));
            config_row_mono(ui, "max output", &model_max_output_tokens.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()));
            config_row_mono(ui, "safety margin", &model_context_safety_margin_tokens.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()));
            config_row_mono(ui, "chars/token", &model_chars_per_token.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()));

            config_header(ui, "API Keys");
            ui.label(egui::RichText::new("model key").color(color_muted()));
            ui.horizontal(|ui| {
                let Some(key) = model_api_key.as_deref() else {
                    ui.label("-");
                    return;
                };
                if *reveal_secrets {
                    ui.monospace(key);
                } else {
                    ui.monospace(mask_secret(key));
                }
                let button = if *reveal_secrets {
                    "Hide"
                } else {
                    "Reveal"
                };
                if ui.add(Button::new(button)).clicked() {
                    *reveal_secrets = !*reveal_secrets;
                    ui.ctx().request_repaint();
                }
            });
            ui.end_row();

            ui.label(egui::RichText::new("tavily key").color(color_muted()));
            ui.horizontal(|ui| {
                let Some(key) = tavily_api_key.as_deref() else {
                    ui.label("-");
                    return;
                };
                if *reveal_secrets {
                    ui.monospace(key);
                } else {
                    ui.monospace(mask_secret(key));
                }
                let button = if *reveal_secrets {
                    "Hide"
                } else {
                    "Reveal"
                };
                if ui.add(Button::new(button)).clicked() {
                    *reveal_secrets = !*reveal_secrets;
                    ui.ctx().request_repaint();
                }
            });
            ui.end_row();

            ui.label(egui::RichText::new("exa key").color(color_muted()));
            ui.horizontal(|ui| {
                let Some(key) = exa_api_key.as_deref() else {
                    ui.label("-");
                    return;
                };
                if *reveal_secrets {
                    ui.monospace(key);
                } else {
                    ui.monospace(mask_secret(key));
                }
                let button = if *reveal_secrets {
                    "Hide"
                } else {
                    "Reveal"
                };
                if ui.add(Button::new(button)).clicked() {
                    *reveal_secrets = !*reveal_secrets;
                    ui.ctx().request_repaint();
                }
            });
            ui.end_row();

            config_header(ui, "Execution");
            config_row(ui, "default cwd", exec_default_cwd.as_deref().unwrap_or("-"));
            config_row_mono(ui, "sandbox", &exec_sandbox_profile.map(|id| id_prefix(id)).unwrap_or_else(|| "-".to_string()));
        });

    if let Some(prompt) = system_prompt.as_deref() {
        ui.add_space(8.0);
        ui.label(egui::RichText::new("System prompt").monospace());
        egui::Frame::NONE
            .fill(color_frame())
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

/// Choose a tick interval (in nanoseconds) that gives ~5-10 ticks
/// for the given viewport time span.
const TICK_INTERVALS: &[i128] = {
    const NS: i128 = 1_000_000_000;
    &[
        NS,              // 1 second
        5 * NS,          // 5 seconds
        10 * NS,         // 10 seconds
        30 * NS,         // 30 seconds
        60 * NS,         // 1 minute
        5 * 60 * NS,     // 5 minutes
        10 * 60 * NS,    // 10 minutes
        30 * 60 * NS,    // 30 minutes
        3600 * NS,       // 1 hour
        3 * 3600 * NS,   // 3 hours
        6 * 3600 * NS,   // 6 hours
        12 * 3600 * NS,  // 12 hours
        86400 * NS,      // 1 day
        7 * 86400 * NS,  // 1 week
    ]
};

/// Format a TAI nanosecond key as a human-readable time marker.
fn format_time_marker(key: i128) -> String {
    let ns = hifitime::Duration::from_total_nanoseconds(key);
    let epoch = Epoch::from_tai_duration(ns);
    let (y, m, d, h, min, s, _) = epoch.to_gregorian_utc();
    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{s:02}")
}

/// Default scale: pixels per minute of wall time.
const TIMELINE_DEFAULT_SCALE: f32 = 2.0;

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
        ui.label(egui::RichText::new("Frontier:").color(color_muted()));
        for root in &roots {
            let count = context_leaf_count(root.id, &by_id, &mut leaf_counts);
            let is_selected = state.context_selected_chunk == Some(root.id);
            let fill = if is_selected {
                color_cognition()
            } else {
                color_frame()
            };
            let text_color = colorhash::text_color_on(fill);
            let chip_resp = egui::Frame::NONE
                .fill(fill)
                .corner_radius(egui::CornerRadius::same(5))
                .inner_margin(egui::Margin::symmetric(8, 3))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;
                        ui.label(
                            egui::RichText::new(id_prefix(root.id))
                                .monospace()
                                .small()
                                .color(text_color),
                        );
                        ui.label(
                            egui::RichText::new(format!("{count}"))
                                .small()
                                .color(text_color),
                        );
                    });
                });
            if chip_resp.response.interact(egui::Sense::click()).clicked() {
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

fn context_chunk_label(
    ui: &egui::Ui,
    selected: bool,
    id: Id,
    start: &str,
    end: &str,
    count: usize,
    exec_id: Option<Id>,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();

    let mono = egui::FontId::monospace(11.0);
    let prop = egui::FontId::proportional(12.0);
    let prop_small = egui::FontId::proportional(11.0);
    let bg = ui.visuals().window_fill;

    // Selection dot
    if selected {
        job.append(
            "\u{25CF} ",
            0.0,
            egui::text::TextFormat {
                font_id: prop_small.clone(),
                color: color_cognition(),
                background: bg,
                ..Default::default()
            },
        );
    }

    // ID badge: monospace on dark frame
    let id_fill = color_frame();
    let id_text = colorhash::text_color_on(id_fill);
    job.append(
        &format!(" {} ", id_prefix(id)),
        0.0,
        egui::text::TextFormat {
            font_id: mono.clone(),
            color: id_text,
            background: id_fill,
            ..Default::default()
        },
    );

    // Time range
    job.append(
        &format!("  {start} .. {end}  "),
        0.0,
        egui::text::TextFormat {
            font_id: prop.clone(),
            color: color_muted(),
            background: bg,
            ..Default::default()
        },
    );

    // Leaf count badge
    let leaf_fill = color_frame();
    let leaf_text = colorhash::text_color_on(leaf_fill);
    job.append(
        &format!(" {count} leaves "),
        0.0,
        egui::text::TextFormat {
            font_id: prop_small.clone(),
            color: leaf_text,
            background: leaf_fill,
            ..Default::default()
        },
    );

    // Exec chip (if present)
    if let Some(eid) = exec_id {
        let exec_fill = color_shell();
        let exec_text = colorhash::text_color_on(exec_fill);
        job.append(
            &format!(" exec {} ", id_prefix(eid)),
            4.0,
            egui::text::TextFormat {
                font_id: mono,
                color: exec_text,
                background: exec_fill,
                ..Default::default()
            },
        );
    }

    job
}

fn context_leaf_label(
    ui: &egui::Ui,
    id: Id,
    age: &str,
    exec_id: Option<Id>,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();

    let mono = egui::FontId::monospace(11.0);
    let prop = egui::FontId::proportional(12.0);
    let prop_small = egui::FontId::proportional(11.0);
    let bg = ui.visuals().window_fill;

    // ID badge
    let id_fill = color_frame();
    let id_text = colorhash::text_color_on(id_fill);
    job.append(
        &format!(" {} ", id_prefix(id)),
        0.0,
        egui::text::TextFormat {
            font_id: mono.clone(),
            color: id_text,
            background: id_fill,
            ..Default::default()
        },
    );

    // Age
    job.append(
        &format!("  {age}  "),
        0.0,
        egui::text::TextFormat {
            font_id: prop.clone(),
            color: color_muted(),
            background: bg,
            ..Default::default()
        },
    );

    // Leaf tag
    let leaf_fill = color_frame();
    let leaf_text = colorhash::text_color_on(leaf_fill);
    job.append(
        " leaf ",
        0.0,
        egui::text::TextFormat {
            font_id: prop_small,
            color: leaf_text,
            background: leaf_fill,
            ..Default::default()
        },
    );

    // Exec chip (if present)
    if let Some(eid) = exec_id {
        let exec_fill = color_shell();
        let exec_text = colorhash::text_color_on(exec_fill);
        job.append(
            &format!(" exec {} ", id_prefix(eid)),
            4.0,
            egui::text::TextFormat {
                font_id: mono,
                color: exec_text,
                background: exec_fill,
                ..Default::default()
            },
        );
    }

    job
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

    let label = context_chunk_label(
        ui, selected, node.id, &start, &end, count, node.about_exec_result,
    );

    let response = egui::CollapsingHeader::new(label)
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

    // Structured header with badges instead of monospace dump.
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 4.0;
        ui.label(egui::RichText::new("Selected").color(color_muted()));

        // ID badge
        let id_fill = color_cognition();
        let id_text = colorhash::text_color_on(id_fill);
        egui::Frame::NONE
            .fill(id_fill)
            .corner_radius(egui::CornerRadius::same(3))
            .inner_margin(egui::Margin::symmetric(5, 2))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(id_prefix(node.id))
                        .monospace()
                        .small()
                        .color(id_text),
                );
            });

        // Time range
        ui.label(
            egui::RichText::new(format!("{start} .. {end}"))
                .color(color_muted()),
        );

        // Leaf count badge
        let leaf_fill = color_frame();
        let leaf_text = colorhash::text_color_on(leaf_fill);
        egui::Frame::NONE
            .fill(leaf_fill)
            .corner_radius(egui::CornerRadius::same(3))
            .inner_margin(egui::Margin::symmetric(5, 2))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(format!("{count} leaves"))
                        .small()
                        .color(leaf_text),
                );
            });
    });

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
                .stroke(egui::Stroke::new(1.0, color_muted()))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing.x = 4.0;

                        // Index label
                        ui.label(
                            egui::RichText::new(format!("child[{}]", child.index))
                                .color(color_muted()),
                        );

                        // ID badge
                        let id_fill = color_frame();
                        let id_text = colorhash::text_color_on(id_fill);
                        egui::Frame::NONE
                            .fill(id_fill)
                            .corner_radius(egui::CornerRadius::same(3))
                            .inner_margin(egui::Margin::symmetric(4, 1))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(id_prefix(child.chunk_id))
                                        .monospace()
                                        .small()
                                        .color(id_text),
                                );
                            });

                        // Time range
                        ui.label(
                            egui::RichText::new(format!("{child_start} .. {child_end}"))
                                .color(color_muted()),
                        );

                        // Leaf count badge
                        let leaf_fill = color_frame();
                        let leaf_text = colorhash::text_color_on(leaf_fill);
                        egui::Frame::NONE
                            .fill(leaf_fill)
                            .corner_radius(egui::CornerRadius::same(3))
                            .inner_margin(egui::Margin::symmetric(4, 1))
                            .show(ui, |ui| {
                                ui.label(
                                    egui::RichText::new(format!("{child_count} leaves"))
                                        .small()
                                        .color(leaf_text),
                                );
                            });

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
        let origin_label = context_leaf_label(
            ui,
            origin.chunk_id,
            &age,
            origin.exec_result_id,
        );
        egui::CollapsingHeader::new(origin_label)
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

fn timeline_source_style(source: TimelineSource) -> (&'static str, egui::Color32) {
    match source {
        TimelineSource::Shell => ("shell", color_shell()),
        TimelineSource::Cognition => ("mind", color_cognition()),
        TimelineSource::Teams => ("teams", color_teams()),
        TimelineSource::LocalMessages => ("local", color_local_msg()),
        TimelineSource::Goals => ("goals", color_goals()),
        TimelineSource::Wiki => ("wiki", color_wiki()),
    }
}

/// Queries the compass catalog directly and renders swimlane layout.
fn render_compass_swimlanes_live(
    ui: &mut egui::Ui,
    expanded_goal: &mut Option<Id>,
    data: &TribleSet,
    ws: &mut Option<Workspace<Pile>>,
) {
    // ── Collect goals ──
    let mut tasks: HashMap<Id, CompassTaskRow> = HashMap::new();

    for (task_id, title_handle, created_at) in find!(
        (
            task_id: Id,
            title_handle: Value<Handle<Blake3, LongString>>,
            created_at: Value<NsTAIInterval>
        ),
        pattern!(data, [{
            ?task_id @
            metadata::tag: &COMPASS_KIND_GOAL_ID,
            compass::title: ?title_handle,
            metadata::created_at: ?created_at,
        }])
    ) {
        if tasks.contains_key(&task_id) {
            continue;
        }
        let title = ws
            .as_mut()
            .and_then(|w| load_text(w, title_handle))
            .unwrap_or_else(|| "<missing>".to_string());
        tasks.insert(
            task_id,
            CompassTaskRow {
                id: task_id,
                id_prefix: id_prefix(task_id),
                title,
                tags: Vec::new(),
                created_at: Some(interval_key(created_at)),
                status: "todo".to_string(),
                status_at: None,
                note_count: 0,
                parent: None,
            },
        );
    }

    if tasks.is_empty() {
        ui.label("No goals yet.");
        return;
    }

    // ── Tags ──
    for (task_id, tag) in find!(
        (task_id: Id, tag: String),
        pattern!(data, [{ ?task_id @ metadata::tag: &COMPASS_KIND_GOAL_ID, compass::tag: ?tag }])
    ) {
        if let Some(task) = tasks.get_mut(&task_id) {
            task.tags.push(tag);
        }
    }

    // ── Parents ──
    for (task_id, parent_id) in find!(
        (task_id: Id, parent_id: Id),
        pattern!(data, [{
            ?task_id @
            metadata::tag: &COMPASS_KIND_GOAL_ID,
            compass::parent: ?parent_id,
        }])
    ) {
        if let Some(task) = tasks.get_mut(&task_id) {
            task.parent = Some(parent_id);
        }
    }

    // ── Latest status per goal ──
    let mut status_map: HashMap<Id, (String, i128)> = HashMap::new();
    for (task_id, status, at) in find!(
        (task_id: Id, status: String, at: Value<NsTAIInterval>),
        pattern!(data, [{
            _?event @
            metadata::tag: &COMPASS_KIND_STATUS_ID,
            compass::task: ?task_id,
            compass::status: ?status,
            compass::at: ?at,
        }])
    ) {
        let at_key = interval_key(at);
        status_map
            .entry(task_id)
            .and_modify(|current| {
                if at_key > current.1 {
                    *current = (status.clone(), at_key);
                }
            })
            .or_insert_with(|| (status, at_key));
    }

    // ── Note counts ──
    let mut note_counts: HashMap<Id, usize> = HashMap::new();
    for task_id in find!(
        task_id: Id,
        pattern!(data, [{
            _?event @
            metadata::tag: &COMPASS_KIND_NOTE_ID,
            compass::task: ?task_id,
        }])
    ) {
        *note_counts.entry(task_id).or_insert(0) += 1;
    }

    // ── Apply status & note counts to tasks ──
    for task in tasks.values_mut() {
        if let Some((status, at_key)) = status_map.get(&task.id) {
            task.status = status.clone();
            task.status_at = Some(*at_key);
        }
        if let Some(count) = note_counts.get(&task.id) {
            task.note_count = *count;
        }
        task.tags.sort();
        task.tags.dedup();
    }

    let rows = order_compass_rows(tasks.into_values().collect());

    // ── Query notes on demand (only for expanded goal) ──
    let notes: HashMap<Id, Vec<CompassNoteRow>> = if let Some(goal_id) = *expanded_goal {
        let mut map: HashMap<Id, Vec<CompassNoteRow>> = HashMap::new();
        for (note_handle, at) in find!(
            (note_handle: Value<Handle<Blake3, LongString>>, at: Value<NsTAIInterval>),
            pattern!(data, [{
                _?event @
                metadata::tag: &COMPASS_KIND_NOTE_ID,
                compass::task: &goal_id,
                compass::note: ?note_handle,
                compass::at: ?at,
            }])
        ) {
            let body = ws
                .as_mut()
                .and_then(|w| load_text(w, note_handle))
                .unwrap_or_else(|| "<missing>".to_string());
            map.entry(goal_id).or_default().push(CompassNoteRow { at: Some(interval_key(at)), body });
        }
        for notes in map.values_mut() {
            notes.sort_by(|a, b| b.at.cmp(&a.at));
        }
        map
    } else {
        HashMap::new()
    };

    // ── Render swimlanes ──
    let render_lanes = |ui: &mut egui::Ui| {
        ui.spacing_mut().item_spacing.y = 0.0;

        let mut counts: HashMap<&str, usize> = HashMap::new();
        let mut extra_statuses: HashSet<&str> = HashSet::new();
        for (row, _) in &rows {
            *counts.entry(row.status.as_str()).or_insert(0) += 1;
            if !COMPASS_DEFAULT_STATUSES.contains(&row.status.as_str()) {
                extra_statuses.insert(row.status.as_str());
            }
        }

        let mut statuses: Vec<String> = COMPASS_DEFAULT_STATUSES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let mut extras: Vec<&str> = extra_statuses.into_iter().collect();
        extras.sort();
        statuses.extend(extras.into_iter().map(|s| s.to_string()));

        for status in statuses {
            let count = counts.get(status.as_str()).copied().unwrap_or(0);
            render_compass_swimlane(ui, expanded_goal, &notes, &rows, &status, count);
        }
    };

    if diagnostics_is_headless() {
        egui::ScrollArea::vertical()
            .id_salt("compass_live_headless_scroll")
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
        "todo" => color_todo(),
        "doing" => color_doing(),
        "blocked" => color_blocked(),
        "done" => color_done(),
        _ => color_muted(),
    }
}

fn render_goal_chip(ui: &mut egui::Ui, label: &str, fill: egui::Color32) {
    let text_color = colorhash::text_color_on(fill);
    egui::Frame::NONE
        .fill(fill)
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(6, 1))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(label).small().color(text_color));
        });
}

fn render_goal_card(ui: &mut egui::Ui, row: &CompassTaskRow, dep_indent: f32) -> egui::Response {
    let status_bg = status_color(&row.status);
    let card_bg = color_frame();

    egui::Frame::NONE
        .fill(card_bg)
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(8, 4))
        .outer_margin(egui::Margin { left: dep_indent as i8, right: 0, top: 0, bottom: 0 })
        .show(ui, |ui| {
            // Row 1: status chip · title · id
            ui.horizontal(|ui| {
                render_goal_chip(ui, &row.status, status_bg);
                ui.label(egui::RichText::new(&row.title).monospace());
                let id_text = if let Some(parent) = row.parent {
                    format!("^{} {}", id_prefix(parent), row.id_prefix)
                } else {
                    row.id_prefix.clone()
                };
                ui.label(
                    egui::RichText::new(id_text)
                        .monospace()
                        .small()
                        .color(color_muted()),
                );
            });

            // Row 2: tags + notes (compact, only if present)
            let has_extras = !row.tags.is_empty() || row.note_count > 0;
            if has_extras {
                ui.horizontal_wrapped(|ui| {
                    for tag in &row.tags {
                        let tag_bg = colorhash::ral_categorical(tag.as_bytes());
                        render_goal_chip(ui, &format!("#{tag}"), tag_bg);
                    }
                    if row.note_count > 0 {
                        render_goal_chip(
                            ui,
                            &format!("{}n", row.note_count),
                            color_muted(),
                        );
                    }
                });
            }
        })
        .response
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

    if is_expanded {
        let task_notes = notes.get(&row.id).map(Vec::as_slice).unwrap_or(&[]);
        egui::Frame::NONE
            .stroke(outline)
            .outer_margin(egui::Margin { left: dep_indent as i8, right: 0, top: 0, bottom: 0 })
            .inner_margin(egui::Margin::symmetric(8, 4))
            .show(ui, |ui| {
                if task_notes.is_empty() {
                    ui.small("(no notes)");
                    return;
                }
                let now_key = epoch_key(now_epoch());
                for note in task_notes {
                    ui.label(
                        egui::RichText::new(format_age(now_key, note.at)).small().color(color_muted()),
                    );
                    ui.add(
                        egui::Label::new(egui::RichText::new(&note.body))
                            .wrap_mode(egui::TextWrapMode::Wrap),
                    );
                    ui.add_space(4.0);
                }
            });
        ui.add_space(4.0);
    }

    // Draw a small "dependency gutter" to the left of the goal box.
    let rect = response_rect;
    let painter = ui.painter();
    let stroke = egui::Stroke::new(1.2, color_muted());
    for idx in 0..dep_lines {
        let x = rect.left() - dep_indent + 4.0 + (idx as f32 * DEP_LINE_STEP);
        let y1 = rect.top() + 0.5;
        let y2 = rect.bottom() - 0.5;
        painter.line_segment([egui::pos2(x, y1), egui::pos2(x, y2)], stroke);
    }
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

fn repo_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().map(PathBuf::from).unwrap_or(manifest)
}
