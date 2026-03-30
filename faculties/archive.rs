#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4"
//! rand_core = "0.6.4"
//! rayon = "1.10"
//! scraper = "0.23"
//! serde_json = "1"
//! tracing = "0.1"
//! tracing-subscriber = { version = "0.3", features = ["env-filter"] }
//! triblespace = "0.29"
//! ```

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use hifitime::Epoch;
use tracing::info_span;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::FmtSpan;
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, Handle, NsTAIInterval, U256BE};
use triblespace::prelude::*;

#[path = "../importers/archive_import_chatgpt.rs"]
mod archive_import_chatgpt;
#[path = "../importers/archive_import_codex.rs"]
mod archive_import_codex;
#[path = "../importers/archive_import_copilot.rs"]
mod archive_import_copilot;
#[path = "../importers/archive_import_gemini.rs"]
mod archive_import_gemini;
#[path = "../importers/archive_import_claude_code.rs"]
mod archive_import_claude_code;
mod common {
    #![allow(dead_code)]

    use std::path::{Path, PathBuf};

    use anyhow::{Context, Result, anyhow};
    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use rand_core::OsRng;
    use rayon::ThreadPoolBuilder;
    use rayon::prelude::*;
    use std::fs;
    use tracing::info_span;
    use triblespace::core::id::ExclusiveId;
    pub use triblespace::core::metadata;
    use triblespace::core::repo::pile::Pile;
    use triblespace::core::repo::{Repository, Workspace};
    use triblespace::prelude::blobschemas::{LongString, SimpleArchive};
    use triblespace::prelude::valueschemas::{Blake3, Handle, NsTAIInterval};
    use triblespace::prelude::*;

    pub mod archive_schema {
        use triblespace::core::metadata;
        use triblespace::macros::id_hex;
        pub use triblespace::prelude::blobschemas::FileBytes;
        use triblespace::prelude::blobschemas::LongString;
        use triblespace::prelude::valueschemas::{
            Blake3, GenId, Handle, NsTAIInterval, ShortString, U256BE,
        };
        use triblespace::prelude::*;

        /// A unified archive projection for externally sourced conversations.
        ///
        /// This schema is used by archive importers (ChatGPT, Codex, Copilot, Gemini, ...)
        /// to store a common message/author/attachment graph, while keeping the raw
        /// source artifacts separately (e.g. JSON trees, HTML, etc).
        pub mod archive {
            use super::*;

            attributes! {

                "0D9195A7B1B20DE312A08ECE39168079" as pub reply_to: GenId;
                "838CC157FFDD37C6AC7CC5A472E43ADB" as pub author: GenId;
                "E63EE961ABDB1D1BEC0789FDAFFB9501" as pub author_name: Handle<Blake3, LongString>;
                "2D15150501ACCD9DFD96CB4BF19D1883" as pub author_role: Handle<Blake3, LongString>;
                "4FE6A8A43658BC2F61FEDF5CFB29EEFC" as pub author_model: Handle<Blake3, LongString>;
                "1F127324384335D12ECFE0CB84840925" as pub author_provider: Handle<Blake3, LongString>;
                "ACF09FF3D62B73983A222313FF0C52D2" as pub content: Handle<Blake3, LongString>;
                "59FA7C04A43B96F31414D1B4544FAEC2" as pub created_at: NsTAIInterval;

                "D8A469EAC2518D1A85692E0BEBF20D6C" as pub content_type: ShortString;
                "8334E282F24A4C7779C8899191B29E00" as pub attachment: GenId;

                "C9132D7400892F65B637BCBE92E230FB" as pub attachment_source_id: Handle<Blake3, LongString>;
                "A8F6CF04A9B2391A26F04BC84B77217D" as pub attachment_source_pointer: Handle<Blake3, LongString>;
                "9ADD88D3FFD9E4F91E0DC08126D9180A" as pub attachment_name: Handle<Blake3, LongString>;
                "EEFDB32D37B7B2834D99ACCF159B6507" as pub attachment_mime: ShortString;
                "D233E7BE0E973B09BD51E768E528ACA5" as pub attachment_size_bytes: U256BE;
                "5937E1072AF2F8E493321811B483C57B" as pub attachment_width_px: U256BE;
                "B252F4F77929E54FF8472027B7603EE9" as pub attachment_height_px: U256BE;
                "B0D18159D6035C576AE6B5D871AB4D63" as pub attachment_data: Handle<Blake3, FileBytes>;
            }

            /// Tag for message payloads.
            #[allow(non_upper_case_globals)]
            pub const kind_message: Id = id_hex!("1A0841C92BBDA0A26EA9A8252D6ECD9B");
            /// Tag for author entities.
            #[allow(non_upper_case_globals)]
            pub const kind_author: Id = id_hex!("4E4512EFB0BF0CD42265BD107AE7F082");
            /// Tag for attachment entities.
            #[allow(non_upper_case_globals)]
            pub const kind_attachment: Id = id_hex!("B465C85DD800633F58FE211B920AF2D9");

            #[allow(dead_code)]
            pub fn describe_kinds<B>(blobs: &mut B) -> std::result::Result<TribleSet, B::PutError>
            where
                B: BlobStore<Blake3>,
            {
                let mut tribles = TribleSet::new();
                let kind_message_entity = super::super::aquire_or_force(kind_message);
                let kind_author_entity = super::super::aquire_or_force(kind_author);
                let kind_attachment_entity = super::super::aquire_or_force(kind_attachment);

                tribles += entity! { &kind_message_entity @
                    metadata::name: blobs.put("kind_message".to_string())?,
                    metadata::description: blobs.put("Message payload kind.".to_string())?,
                };

                tribles += entity! { &kind_author_entity @
                    metadata::name: blobs.put("kind_author".to_string())?,
                    metadata::description: blobs.put("Author entity kind.".to_string())?,
                };

                tribles += entity! { &kind_attachment_entity @
                    metadata::name: blobs.put("kind_attachment".to_string())?,
                    metadata::description: blobs.put("Attachment entity kind.".to_string())?,
                };

                Ok(tribles)
            }
        }

        pub fn build_archive_metadata<B>(
            blobs: &mut B,
        ) -> std::result::Result<TribleSet, B::PutError>
        where
            B: BlobStore<Blake3>,
        {
            let mut metadata = archive::describe_kinds(blobs)?;

            metadata += <GenId as metadata::ConstDescribe>::describe(blobs)?;
            metadata += <ShortString as metadata::ConstDescribe>::describe(blobs)?;
            metadata += <U256BE as metadata::ConstDescribe>::describe(blobs)?;
            metadata += <NsTAIInterval as metadata::ConstDescribe>::describe(blobs)?;
            metadata += <Handle<Blake3, LongString> as metadata::ConstDescribe>::describe(blobs)?;
            metadata += <Handle<Blake3, FileBytes> as metadata::ConstDescribe>::describe(blobs)?;
            metadata += <FileBytes as metadata::ConstDescribe>::describe(blobs)?;

            metadata += metadata::Describe::describe(&archive::reply_to, blobs)?;
            metadata += metadata::Describe::describe(&archive::author, blobs)?;
            metadata += metadata::Describe::describe(&archive::author_name, blobs)?;
            metadata += metadata::Describe::describe(&archive::author_role, blobs)?;
            metadata += metadata::Describe::describe(&archive::author_model, blobs)?;
            metadata += metadata::Describe::describe(&archive::author_provider, blobs)?;
            metadata += metadata::Describe::describe(&archive::content, blobs)?;
            metadata += metadata::Describe::describe(&archive::created_at, blobs)?;

            metadata += metadata::Describe::describe(&archive::content_type, blobs)?;
            metadata += metadata::Describe::describe(&archive::attachment, blobs)?;
            metadata += metadata::Describe::describe(&archive::attachment_source_id, blobs)?;
            metadata += metadata::Describe::describe(&archive::attachment_source_pointer, blobs)?;
            metadata += metadata::Describe::describe(&archive::attachment_name, blobs)?;
            metadata += metadata::Describe::describe(&archive::attachment_mime, blobs)?;
            metadata += metadata::Describe::describe(&archive::attachment_size_bytes, blobs)?;
            metadata += metadata::Describe::describe(&archive::attachment_width_px, blobs)?;
            metadata += metadata::Describe::describe(&archive::attachment_height_px, blobs)?;
            metadata += metadata::Describe::describe(&archive::attachment_data, blobs)?;

            Ok(metadata)
        }
    }

    pub mod import_schema {
        use triblespace::core::metadata;
        use triblespace::macros::id_hex;
        use triblespace::prelude::blobschemas::LongString;
        use triblespace::prelude::valueschemas::{
            Blake3, GenId, Handle, NsTAIInterval, ShortString,
        };
        use triblespace::prelude::*;

        attributes! {
            "891508CAD6E1430B221ADA937EFBD982" as pub conversation: GenId;
            "E997DCAAF43BAA04790FCB0FA0FBFE3A" as pub source_format: ShortString;
            "973FB59D3452D3A8276172F8E3272324" as pub source_raw_root: GenId;
            "87B587A3906056038FD767F4225274F9" as pub source_conversation_id: Handle<Blake3, LongString>;
            "1B2A09FF44D2A5736FA320AB255026C1" as pub source_message_id: Handle<Blake3, LongString>;
            "AA3CF220F15CCF724276F1251AFE053B" as pub source_author: Handle<Blake3, LongString>;
            "B4C084B61FB46A932BFCA75B8BC621FA" as pub source_role: Handle<Blake3, LongString>;
            "220DA5084D6261B5420922EADC064A5A" as pub source_parent_id: Handle<Blake3, LongString>;
            "F672605621E56674127FD210CFFDFF2A" as pub source_created_at: NsTAIInterval;
            /// Conversation → message edge (repeated).
            "06DB96427C8EA6FC982D44E018AB0831" as pub message: GenId;
        }

        /// Root id for describing the import metadata protocol.
        #[allow(non_upper_case_globals)]
        #[allow(dead_code)]
        pub const import_metadata: Id = id_hex!("5D57DD8335FECADB173616D780965F0C");

        /// Tag for import conversation entities.
        #[allow(non_upper_case_globals)]
        pub const kind_conversation: Id = id_hex!("573E4291B63CBA1B5AE090B0C25A2D34");

        #[allow(dead_code)]
        pub fn describe_kinds<B>(blobs: &mut B) -> std::result::Result<TribleSet, B::PutError>
        where
            B: BlobStore<Blake3>,
        {
            let mut tribles = TribleSet::new();
            let import_metadata_entity = super::aquire_or_force(import_metadata);
            let kind_conversation_entity = super::aquire_or_force(kind_conversation);

            tribles += entity! { &import_metadata_entity @
                metadata::name: blobs.put("import_metadata")?,
                metadata::description: blobs.put("Root id for describing import metadata.")?,
                metadata::tag: metadata::KIND_PROTOCOL,
            };

            tribles += entity! { &kind_conversation_entity @
                metadata::name: blobs.put("kind_conversation")?,
                metadata::description: blobs.put("Import conversation entity kind.")?,
                metadata::tag: metadata::KIND_TAG,
            };

            Ok(tribles)
        }

        pub fn build_import_metadata<B>(
            blobs: &mut B,
        ) -> std::result::Result<TribleSet, B::PutError>
        where
            B: BlobStore<Blake3>,
        {
            let mut metadata = describe_kinds(blobs)?;

            metadata += <GenId as metadata::ConstDescribe>::describe(blobs)?;
            metadata += <ShortString as metadata::ConstDescribe>::describe(blobs)?;
            metadata += <NsTAIInterval as metadata::ConstDescribe>::describe(blobs)?;
            metadata += <Handle<Blake3, LongString> as metadata::ConstDescribe>::describe(blobs)?;

            metadata += metadata::Describe::describe(&metadata::tag, blobs)?;
            metadata += metadata::Describe::describe(&conversation, blobs)?;
            metadata += metadata::Describe::describe(&source_format, blobs)?;
            metadata += metadata::Describe::describe(&source_raw_root, blobs)?;
            metadata += metadata::Describe::describe(&source_conversation_id, blobs)?;
            metadata += metadata::Describe::describe(&source_message_id, blobs)?;
            metadata += metadata::Describe::describe(&source_author, blobs)?;
            metadata += metadata::Describe::describe(&source_role, blobs)?;
            metadata += metadata::Describe::describe(&source_parent_id, blobs)?;
            metadata += metadata::Describe::describe(&source_created_at, blobs)?;

            Ok(metadata)
        }
    }

    pub use archive_schema::archive;

    pub type Repo = Repository<Pile<Blake3>>;
    pub type Ws = Workspace<Pile<Blake3>>;
    pub type CommitHandle = Value<Handle<Blake3, SimpleArchive>>;

    fn aquire_or_force(id: Id) -> ExclusiveId {
        id.aquire().unwrap_or_else(|| ExclusiveId::force(id))
    }

    pub fn parse_paths_parallel<T, F>(
        label: &str,
        paths: &[PathBuf],
        parse_one: F,
    ) -> Result<Vec<(PathBuf, Result<T>)>>
    where
        T: Send,
        F: Fn(&Path) -> Result<T> + Send + Sync,
    {
        let _span = info_span!("parallel_parse", label = label, files = paths.len()).entered();
        let total_files = paths.len();
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let parser_pool = ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .with_context(|| format!("build {label} parser thread pool"))?;
        let parse_start = std::time::Instant::now();
        println!(
            "{label} phase parse: {} file(s) using {} thread(s)",
            total_files, threads
        );
        let parsed_files = parser_pool.install(|| {
            paths
                .par_iter()
                .map(|path| {
                    let _file_span = info_span!(
                        "parse_file",
                        label = label,
                        path = %path.display()
                    )
                    .entered();
                    (path.to_path_buf(), parse_one(path.as_path()))
                })
                .collect()
        });
        let elapsed = parse_start.elapsed();
        println!("{label} phase parse: done in {:?}", elapsed);
        tracing::info!(
            label = label,
            files = total_files,
            threads = threads,
            elapsed_ms = elapsed.as_millis() as u64,
            "parallel parse complete"
        );
        Ok(parsed_files)
    }

    pub fn open_repo_for_write(
        pile_path: &Path,
        branch_id: Id,
        _branch_name: &str,
    ) -> Result<(Repo, Id)> {
        let mut pile =
            Pile::<Blake3>::open(pile_path).map_err(|e| anyhow!("open pile: {e:?}"))?;
        if let Err(err) = pile.restore() {
            let _ = pile.close();
            return Err(anyhow!("restore pile: {err:?}"));
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        let repo = Repository::new(pile, signing_key, TribleSet::new())
            .map_err(|err| anyhow!("create repository: {err:?}"))?;
        Ok((repo, branch_id))
    }

    pub fn open_repo_for_read(
        pile_path: &Path,
        branch_id: Id,
        branch_name: &str,
    ) -> Result<(Repo, Id)> {
        let mut repo = open_repo(pile_path)?;
        let res = (|| -> Result<(), anyhow::Error> {
            if repo
                .storage_mut()
                .head(branch_id)
                .map_err(|e| anyhow!("branch head {branch_name}: {e:?}"))?
                .is_none()
            {
                return Err(anyhow!("unknown branch {branch_name} ({branch_id:x})"));
            }
            Ok(())
        })();
        if let Err(err) = res {
            let _ = repo.close();
            return Err(err);
        }
        Ok((repo, branch_id))
    }

    fn open_repo(pile_path: &Path) -> Result<Repo> {
        let mut pile = Pile::<Blake3>::open(pile_path).map_err(|e| anyhow!("open pile: {e:?}"))?;
        if let Err(err) = pile.restore() {
            // Avoid Drop warnings on early errors.
            let _ = pile.close();
            return Err(anyhow!("restore pile: {err:?}"));
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        Repository::new(pile, signing_key, TribleSet::new())
            .map_err(|err| anyhow!("create repository: {err:?}"))
    }

    pub fn with_repo<T>(pile: &Path, f: impl FnOnce(&mut Repo) -> Result<T>) -> Result<T> {
        let mut repo = open_repo(pile)?;
        let result = f(&mut repo);
        let close_res = repo.close().map_err(|e| anyhow!("close pile: {e:?}"));
        if let Err(err) = close_res {
            if result.is_ok() {
                return Err(err);
            }
            eprintln!("warning: failed to close pile cleanly: {err:#}");
        }
        result
    }

    pub fn push_workspace(repo: &mut Repo, ws: &mut Ws) -> Result<()> {
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

    pub fn refresh_catalog(
        ws: &mut Ws,
        catalog: &mut TribleSet,
        catalog_head: &mut Option<CommitHandle>,
    ) -> Result<()> {
        let next_head = ws.head();
        if *catalog_head == next_head {
            return Ok(());
        }

        let delta = ws
            .checkout(*catalog_head..next_head)
            .context("checkout workspace delta")?;
        if !delta.is_empty() {
            *catalog += delta;
        }
        *catalog_head = next_head;
        Ok(())
    }

    pub fn commit_delta(
        repo: &mut Repo,
        ws: &mut Ws,
        catalog: &mut TribleSet,
        catalog_head: &mut Option<CommitHandle>,
        change: TribleSet,
        message: &'static str,
    ) -> Result<bool> {
        if change.is_empty() {
            return Ok(false);
        }

        let delta = change.difference(catalog);
        if delta.is_empty() {
            return Ok(false);
        }

        ws.commit(delta, message);
        push_workspace(repo, ws).with_context(|| format!("push {message}"))?;
        refresh_catalog(ws, catalog, catalog_head)
            .with_context(|| format!("refresh catalog after {message}"))?;
        Ok(true)
    }

    pub fn now_epoch() -> Epoch {
        Epoch::now().unwrap_or_else(|_| Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0))
    }

    pub fn unknown_epoch() -> Epoch {
        Epoch::from_gregorian_utc(1970, 1, 1, 0, 0, 0, 0)
    }

    pub fn epoch_from_seconds(value: f64) -> Option<Epoch> {
        if value.is_finite() {
            Some(Epoch::from_unix_seconds(value))
        } else {
            None
        }
    }

    pub fn epoch_interval(epoch: Epoch) -> Value<NsTAIInterval> {
        (epoch, epoch).to_value()
    }

    pub fn ensure_author(
        ws: &mut Ws,
        catalog: &TribleSet,
        name: &str,
        role: &str,
    ) -> Result<(Id, TribleSet)> {
        if let Some(author_id) = find_author_by_name(ws, catalog, name)? {
            let mut change = TribleSet::new();
            if author_role_handle(catalog, author_id).is_none() && !role.is_empty() {
                let handle = ws.put(role.to_owned());
                let author_entity = aquire_or_force(author_id);
                change += entity! { &author_entity @
                    archive::author_role: handle
                };
            }
            return Ok((author_id, change));
        }

        let author_id = ufoid();
        let name_handle = ws.put(name.to_owned());
        let role_handle = (!role.is_empty()).then(|| ws.put(role.to_owned()));
        let mut change = TribleSet::new();
        change += entity! { &author_id @
            metadata::tag: archive::kind_author,
            archive::author_name: name_handle,
            archive::author_role?: role_handle,
        };
        Ok((*author_id, change))
    }

    fn find_author_by_name(
        ws: &mut Ws,
        catalog: &TribleSet,
        target_name: &str,
    ) -> Result<Option<Id>> {
        for (author_id, name_handle) in find!(
            (author: Id, author_name: Value<Handle<Blake3, LongString>>),
            pattern!(catalog, [{
                ?author @
                metadata::tag: archive::kind_author,
                archive::author_name: ?author_name,
            }])
        ) {
            let existing: View<str> = ws.get(name_handle).context("load author name")?;
            if existing.as_ref() == target_name {
                return Ok(Some(author_id));
            }
        }
        Ok(None)
    }

    fn author_role_handle(
        catalog: &TribleSet,
        author_id: Id,
    ) -> Option<Value<Handle<Blake3, LongString>>> {
        for (author, role) in find!(
            (author: Id, role: Value<Handle<Blake3, LongString>>),
            pattern!(catalog, [{ ?author @ archive::author_role: ?role }])
        ) {
            if author == author_id {
                return Some(role);
            }
        }
        None
    }
}

#[derive(Parser)]
#[command(name = "archive", about = "Query imported archives in TribleSpace")]
struct Cli {
    /// Path to the pile file to query.
    #[arg(long)]
    pile: Option<PathBuf>,
    /// Branch name to query.
    #[arg(long, default_value = "archive")]
    branch: String,
    /// Branch id to query (hex). Overrides config/env branch id.
    #[arg(long)]
    branch_id: Option<String>,
    /// Enable tracing spans for importer profiling.
    #[arg(long)]
    trace: bool,
    /// Optional tracing filter (defaults to `info`).
    #[arg(long)]
    trace_filter: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Import external archives into the archive branch.
    Import {
        #[arg(value_enum)]
        source: ImportSource,
        /// Optional path override for this source (or backup root for `all`).
        path: Option<PathBuf>,
    },
    /// List the most recent messages.
    List {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show one message by id prefix.
    Show { id: String },
    /// Show a reply_to chain ending at the given message id prefix.
    Thread {
        id: String,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Search message content (substring match).
    Search {
        #[arg(help = "Substring to search for. Use @path for file input or @- for stdin.")]
        text: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Use case-sensitive matching.
        #[arg(long)]
        case_sensitive: bool,
    },
    /// List imported conversations.
    Imports {
        format: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ImportSource {
    Chatgpt,
    Codex,
    Copilot,
    Gemini,
    ClaudeCode,
    All,
}

impl ImportSource {
    fn label(self) -> &'static str {
        match self {
            ImportSource::Chatgpt => "chatgpt",
            ImportSource::Codex => "codex",
            ImportSource::Copilot => "copilot",
            ImportSource::Gemini => "gemini",
            ImportSource::ClaudeCode => "claude-code",
            ImportSource::All => "all",
        }
    }
}

#[derive(Debug, Clone)]
struct ImportJob {
    source: ImportSource,
    path: PathBuf,
}

fn default_source_path(source: ImportSource, base: &Path) -> PathBuf {
    match source {
        ImportSource::Chatgpt => base.to_path_buf(),
        ImportSource::Codex => base.join("codex"),
        ImportSource::Copilot => base.join("copilot"),
        ImportSource::Gemini => {
            base.join("gemini/Takeout/My Activity/Gemini Apps/My Activity.html")
        }
        ImportSource::ClaudeCode => base.join("claude-code"),
        ImportSource::All => base.to_path_buf(),
    }
}

fn resolve_import_jobs(source: ImportSource, path: Option<&Path>) -> Result<Vec<ImportJob>> {
    match source {
        ImportSource::All => {
            let root = path
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("chatgptbackup"));
            Ok(vec![
                ImportJob {
                    source: ImportSource::Chatgpt,
                    path: default_source_path(ImportSource::Chatgpt, &root),
                },
                ImportJob {
                    source: ImportSource::Codex,
                    path: default_source_path(ImportSource::Codex, &root),
                },
                ImportJob {
                    source: ImportSource::Copilot,
                    path: default_source_path(ImportSource::Copilot, &root),
                },
                ImportJob {
                    source: ImportSource::Gemini,
                    path: default_source_path(ImportSource::Gemini, &root),
                },
                ImportJob {
                    source: ImportSource::ClaudeCode,
                    path: default_source_path(ImportSource::ClaudeCode, &root),
                },
            ])
        }
        one => Ok(vec![ImportJob {
            source: one,
            path: path
                .map(Path::to_path_buf)
                .unwrap_or_else(|| default_source_path(one, Path::new("chatgptbackup"))),
        }]),
    }
}

fn run_import_jobs(
    source: ImportSource,
    path: Option<&Path>,
    pile_path: &Path,
    branch_name: &str,
    branch_id: Id,
) -> Result<()> {
    let all_start = Instant::now();
    let jobs = resolve_import_jobs(source, path)?;
    let _span = info_span!(
        "archive_import",
        source = source.label(),
        jobs = jobs.len(),
        branch = branch_name,
        branch_id = %format!("{branch_id:x}"),
        pile = %pile_path.display()
    )
    .entered();
    println!(
        "archive import: {} job(s) -> {} ({:x}) on pile {}",
        jobs.len(),
        branch_name,
        branch_id,
        pile_path.display()
    );

    let total_jobs = jobs.len();
    for (job_index, job) in jobs.into_iter().enumerate() {
        let _job_span = info_span!(
            "archive_import_job",
            source = job.source.label(),
            job_index = job_index + 1,
            total_jobs = total_jobs,
            path = %job.path.display()
        )
        .entered();
        if source == ImportSource::All && !job.path.exists() {
            eprintln!(
                "skip {} import (path missing): {}",
                job.source.label(),
                job.path.display()
            );
            continue;
        }
        if !job.path.exists() {
            bail!(
                "{} import path not found: {}",
                job.source.label(),
                job.path.display()
            );
        }
        let job_start = Instant::now();
        println!(
            "archive import progress {}/{}: {} from {}",
            job_index + 1,
            total_jobs,
            job.source.label(),
            job.path.display()
        );
        match job.source {
            ImportSource::Chatgpt => archive_import_chatgpt::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::Codex => archive_import_codex::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::Copilot => archive_import_copilot::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::Gemini => archive_import_gemini::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::ClaudeCode => archive_import_claude_code::import_into_archive(
                &job.path,
                pile_path,
                branch_name,
                branch_id,
            ),
            ImportSource::All => Ok(()),
        }
        .with_context(|| {
            format!(
                "run {} importer for {}",
                job.source.label(),
                job.path.display()
            )
        })?;
        println!(
            "archive import done {}/{}: {} in {:?}",
            job_index + 1,
            total_jobs,
            job.source.label(),
            job_start.elapsed()
        );
        tracing::info!(
            source = job.source.label(),
            job_index = job_index + 1,
            total_jobs = total_jobs,
            elapsed_ms = job_start.elapsed().as_millis() as u64,
            "archive import job complete"
        );
    }

    let total_elapsed = all_start.elapsed();
    println!("archive import all jobs done in {:?}", total_elapsed);
    tracing::info!(
        source = source.label(),
        jobs = total_jobs,
        elapsed_ms = total_elapsed.as_millis() as u64,
        "archive import complete"
    );

    Ok(())
}

fn init_tracing(enabled: bool, filter: Option<&str>) {
    static TRACE_INIT: Once = Once::new();
    if !enabled {
        return;
    }

    TRACE_INIT.call_once(|| {
        let env_filter = filter
            .map(EnvFilter::new)
            .or_else(|| {
                std::env::var("PLAYGROUND_ARCHIVE_TRACE_FILTER")
                    .ok()
                    .map(EnvFilter::new)
            })
            .unwrap_or_else(|| EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_target(false)
            .without_time()
            .with_env_filter(env_filter)
            .with_span_events(FmtSpan::CLOSE)
            .try_init();
        tracing::info!("archive tracing enabled");
    });
}

fn interval_key(interval: Value<NsTAIInterval>) -> i128 {
    let (lower, _upper): (Epoch, Epoch) = interval.from_value();
    lower.to_tai_duration().total_nanoseconds()
}

fn load_longstring(
    ws: &mut common::Ws,
    handle: Value<Handle<Blake3, LongString>>,
) -> Result<String> {
    let view: View<str> = ws.get(handle).context("read longstring")?;
    Ok(view.to_string())
}

fn u256be_to_u64(value: Value<U256BE>) -> Option<u64> {
    let raw = value.raw;
    if raw[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    let bytes: [u8; 8] = raw[24..32].try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

fn author_name(ws: &mut common::Ws, catalog: &TribleSet, author_id: Id) -> Result<String> {
    let Some(handle) = find!(
        (handle: Value<Handle<Blake3, LongString>>),
        pattern!(catalog, [{ author_id @ common::archive::author_name: ?handle }])
    )
    .into_iter()
    .next()
    .map(|(h,)| h) else {
        return Ok("<unknown>".to_string());
    };
    load_longstring(ws, handle)
}

fn author_role(ws: &mut common::Ws, catalog: &TribleSet, author_id: Id) -> Result<Option<String>> {
    let Some(handle) = find!(
        (handle: Value<Handle<Blake3, LongString>>),
        pattern!(catalog, [{ author_id @ common::archive::author_role: ?handle }])
    )
    .into_iter()
    .next()
    .map(|(h,)| h) else {
        return Ok(None);
    };
    Ok(Some(load_longstring(ws, handle)?))
}

fn message_content_type(catalog: &TribleSet, message_id: Id) -> Option<String> {
    find!(
        (content_type: String),
        pattern!(catalog, [{ message_id @ common::archive::content_type: ?content_type }])
    )
    .into_iter()
    .next()
    .map(|(ct,)| ct)
}

#[derive(Debug, Clone)]
struct AttachmentRecord {
    id: Id,
    source_id: Option<String>,
    name: Option<String>,
    mime: Option<String>,
    size_bytes: Option<u64>,
    width_px: Option<u64>,
    height_px: Option<u64>,
    has_data: bool,
}

fn message_attachments(
    ws: &mut common::Ws,
    catalog: &TribleSet,
    message_id: Id,
) -> Result<Vec<AttachmentRecord>> {
    let mut attachments: Vec<Id> = find!(
        (attachment: Id),
        pattern!(catalog, [{ message_id @ common::archive::attachment: ?attachment }])
    )
    .into_iter()
    .map(|(a,)| a)
    .collect();
    attachments.sort();
    attachments.dedup();

    let mut out = Vec::new();
    for attachment_id in attachments {
        let source_id = find!(
            (handle: Value<Handle<Blake3, LongString>>),
            pattern!(catalog, [{ attachment_id @ common::archive::attachment_source_id: ?handle }])
        )
        .into_iter()
        .next()
        .map(|(h,)| h);
        let source_id = match source_id {
            Some(h) => Some(load_longstring(ws, h)?),
            None => None,
        };

        let name = find!(
            (handle: Value<Handle<Blake3, LongString>>),
            pattern!(catalog, [{ attachment_id @ common::archive::attachment_name: ?handle }])
        )
        .into_iter()
        .next()
        .map(|(h,)| h);
        let name = match name {
            Some(h) => Some(load_longstring(ws, h)?),
            None => None,
        };

        let mime = find!(
            (mime: String),
            pattern!(catalog, [{ attachment_id @ common::archive::attachment_mime: ?mime }])
        )
        .into_iter()
        .next()
        .map(|(m,)| m);

        let size_bytes = find!(
            (size: Value<U256BE>),
            pattern!(catalog, [{ attachment_id @ common::archive::attachment_size_bytes: ?size }])
        )
        .into_iter()
        .next()
        .and_then(|(s,)| u256be_to_u64(s));

        let width_px = find!(
            (width: Value<U256BE>),
            pattern!(catalog, [{ attachment_id @ common::archive::attachment_width_px: ?width }])
        )
        .into_iter()
        .next()
        .and_then(|(w,)| u256be_to_u64(w));

        let height_px = find!(
            (height: Value<U256BE>),
            pattern!(catalog, [{ attachment_id @ common::archive::attachment_height_px: ?height }])
        )
        .into_iter()
        .next()
        .and_then(|(h,)| u256be_to_u64(h));

        let has_data = find!(
            (handle: Value<_>),
            pattern!(catalog, [{ attachment_id @ common::archive::attachment_data: ?handle }])
        )
        .into_iter()
        .next()
        .is_some();

        out.push(AttachmentRecord {
            id: attachment_id,
            source_id,
            name,
            mime,
            size_bytes,
            width_px,
            height_px,
            has_data,
        });
    }
    Ok(out)
}

fn resolve_message_id(catalog: &TribleSet, prefix: &str) -> Result<Id> {
    let trimmed = prefix.trim();
    if trimmed.len() == 32 {
        if let Some(id) = Id::from_hex(trimmed) {
            return Ok(id);
        }
    }

    let mut matches = Vec::new();
    for (message_id,) in find!(
        (message: Id),
        pattern!(catalog, [{
            ?message @ common::metadata::tag: common::archive::kind_message,
        }])
    ) {
        if format!("{message_id:x}").starts_with(trimmed) {
            matches.push(message_id);
            if matches.len() > 10 {
                break;
            }
        }
    }

    match matches.len() {
        0 => bail!("no message matches id prefix {trimmed}"),
        1 => Ok(matches[0]),
        _ => bail!(
            "id prefix {trimmed} is ambiguous; matches: {}",
            matches
                .into_iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn message_record(
    ws: &mut common::Ws,
    catalog: &TribleSet,
    message_id: Id,
) -> Result<(
    Id,
    String,
    Option<String>,
    Value<NsTAIInterval>,
    Value<Handle<Blake3, LongString>>,
    Option<Id>,
)> {
    let Some((author_id, content_handle, created_at)) = find!(
        (
            author: Id,
            content: Value<Handle<Blake3, LongString>>,
            created_at: Value<NsTAIInterval>
        ),
        pattern!(catalog, [{
            message_id @
                common::archive::author: ?author,
                common::archive::content: ?content,
                common::archive::created_at: ?created_at,
        }])
    )
    .into_iter()
    .next()
    .map(|(a, c, t)| (a, c, t)) else {
        return Err(anyhow!("message {message_id:x} missing required fields"));
    };

    let reply_to = find!(
        (parent: Id),
        pattern!(catalog, [{ message_id @ common::archive::reply_to: ?parent }])
    )
    .into_iter()
    .next()
    .map(|(p,)| p);

    let name = author_name(ws, catalog, author_id)?;
    let role = author_role(ws, catalog, author_id)?;
    Ok((message_id, name, role, created_at, content_handle, reply_to))
}

fn snippet(text: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        if out.chars().count() >= max {
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

fn load_value_or_file(raw: &str, label: &str) -> Result<String> {
    if let Some(path) = raw.strip_prefix('@') {
        if path == "-" {
            let mut value = String::new();
            std::io::stdin()
                .read_to_string(&mut value)
                .with_context(|| format!("read {label} from stdin"))?;
            return Ok(value);
        }
        return std::fs::read_to_string(path).with_context(|| format!("read {label} from {path}"));
    }
    Ok(raw.to_string())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.trace, cli.trace_filter.as_deref());
    let pile_path = cli
        .pile
        .clone()
        .or_else(|| std::env::var("PILE").ok().map(PathBuf::from))
        .expect("--pile argument or PILE env var required");
    let Some(cmd) = cli.command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };

    let branch_id = common::with_repo(&pile_path, |repo| {
        if let Some(hex) = cli.branch_id.as_deref() {
            return Id::from_hex(hex.trim())
                .ok_or_else(|| anyhow!("invalid branch id '{hex}'"));
        }
        repo.ensure_branch(&cli.branch, None)
            .map_err(|e| anyhow!("ensure archive branch: {e:?}"))
    })?;
    if let Command::Import { source, path } = cmd {
        return run_import_jobs(source, path.as_deref(), &pile_path, &cli.branch, branch_id);
    }

    let (mut repo, branch_id) = common::open_repo_for_read(&pile_path, branch_id, &cli.branch)?;

    let res = (|| -> Result<()> {
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
        let catalog = ws.checkout(..).context("checkout workspace")?;

        match cmd {
            Command::Import { .. } => unreachable!("import is handled before opening the branch"),
            Command::List { limit } => {
                let mut records = Vec::new();
                for (message_id, author_id, content_handle, created_at) in find!(
                    (
                        message: Id,
                        author: Id,
                        content: Value<Handle<Blake3, LongString>>,
                        created_at: Value<NsTAIInterval>
                    ),
                    pattern!(&catalog, [{
                        ?message @
                            common::metadata::tag: common::archive::kind_message,
                            common::archive::author: ?author,
                            common::archive::content: ?content,
                            common::archive::created_at: ?created_at,
                    }])
                ) {
                    records.push((
                        interval_key(created_at),
                        message_id,
                        author_id,
                        content_handle,
                        created_at,
                    ));
                }
                records.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                let take = limit.min(records.len());
                for (_key, message_id, author_id, content_handle, created_at) in
                    records.into_iter().rev().take(take)
                {
                    let name = author_name(&mut ws, &catalog, author_id)?;
                    let role = author_role(&mut ws, &catalog, author_id)?;
                    let content = load_longstring(&mut ws, content_handle)?;
                    let (lower, _upper): (Epoch, Epoch) = created_at.from_value();
                    let role = role.as_deref().unwrap_or("");
                    println!(
                        "{} {} {} {}",
                        &format!("{message_id:x}")[..8],
                        lower,
                        if role.is_empty() {
                            name
                        } else {
                            format!("{name} ({role})")
                        },
                        snippet(&content, 120)
                    );
                }
            }
            Command::Show { id } => {
                let message_id = resolve_message_id(&catalog, &id)?;
                let (message_id, name, role, created_at, content_handle, reply_to) =
                    message_record(&mut ws, &catalog, message_id)?;
                let content = load_longstring(&mut ws, content_handle)?;
                let (lower, _upper): (Epoch, Epoch) = created_at.from_value();
                let content_type = message_content_type(&catalog, message_id);
                let attachments = message_attachments(&mut ws, &catalog, message_id)?;

                println!("id: {message_id:x}");
                println!("created_at: {lower}");
                match role {
                    Some(role) => println!("author: {name} ({role})"),
                    None => println!("author: {name}"),
                }
                if let Some(parent) = reply_to {
                    println!("reply_to: {parent:x}");
                }
                if let Some(content_type) = content_type {
                    println!("content_type: {content_type}");
                }
                if !attachments.is_empty() {
                    println!("attachments: {}", attachments.len());
                    for att in attachments {
                        let mut extras = Vec::new();
                        if let Some(mime) = att.mime.as_deref() {
                            extras.push(mime.to_string());
                        }
                        if let Some(size) = att.size_bytes {
                            extras.push(format!("{size}b"));
                        }
                        if let (Some(w), Some(h)) = (att.width_px, att.height_px) {
                            extras.push(format!("{w}x{h}px"));
                        }
                        if att.has_data {
                            extras.push("data".to_string());
                        }
                        let label = att
                            .name
                            .as_deref()
                            .or(att.source_id.as_deref())
                            .unwrap_or("<unknown>");
                        if extras.is_empty() {
                            println!("  - {} {}", &format!("{:x}", att.id)[..8], label);
                        } else {
                            println!(
                                "  - {} {} ({})",
                                &format!("{:x}", att.id)[..8],
                                label,
                                extras.join(", ")
                            );
                        }
                    }
                }
                println!();
                print!("{content}");
                if !content.ends_with('\n') {
                    println!();
                }
            }
            Command::Thread { id, limit } => {
                let leaf = resolve_message_id(&catalog, &id)?;
                let mut chain = Vec::new();
                let mut seen = HashSet::new();
                let mut current = leaf;

                for _ in 0..limit {
                    if !seen.insert(current) {
                        break;
                    }
                    chain.push(current);
                    let parent = find!(
                        (parent: Id),
                        pattern!(&catalog, [{ current @ common::archive::reply_to: ?parent }])
                    )
                    .into_iter()
                    .next()
                    .map(|(p,)| p);
                    let Some(parent) = parent else { break };
                    current = parent;
                }

                chain.reverse();
                for message_id in chain {
                    let (message_id, name, role, created_at, content_handle, _reply_to) =
                        message_record(&mut ws, &catalog, message_id)?;
                    let content = load_longstring(&mut ws, content_handle)?;
                    let (lower, _upper): (Epoch, Epoch) = created_at.from_value();
                    let role = role.as_deref().unwrap_or("");
                    println!(
                        "{} {} {} {}",
                        &format!("{message_id:x}")[..8],
                        lower,
                        if role.is_empty() {
                            name
                        } else {
                            format!("{name} ({role})")
                        },
                        snippet(&content, 120)
                    );
                }
            }
            Command::Search {
                text,
                limit,
                case_sensitive,
            } => {
                let text = load_value_or_file(&text, "search text")?;
                let needle = if case_sensitive {
                    text
                } else {
                    text.to_lowercase()
                };

                let mut matches = Vec::new();
                for (message_id, author_id, content_handle, created_at) in find!(
                    (
                        message: Id,
                        author: Id,
                        content: Value<Handle<Blake3, LongString>>,
                        created_at: Value<NsTAIInterval>
                    ),
                    pattern!(&catalog, [{
                        ?message @
                            common::metadata::tag: common::archive::kind_message,
                            common::archive::author: ?author,
                            common::archive::content: ?content,
                            common::archive::created_at: ?created_at,
                    }])
                ) {
                    let content = load_longstring(&mut ws, content_handle)?;
                    let haystack = if case_sensitive {
                        content.clone()
                    } else {
                        content.to_lowercase()
                    };
                    if haystack.contains(&needle) {
                        matches.push((
                            interval_key(created_at),
                            message_id,
                            author_id,
                            created_at,
                            content,
                        ));
                    }
                }
                matches.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
                for (_key, message_id, author_id, created_at, content) in
                    matches.into_iter().rev().take(limit)
                {
                    let name = author_name(&mut ws, &catalog, author_id)?;
                    let role = author_role(&mut ws, &catalog, author_id)?;
                    let (lower, _upper): (Epoch, Epoch) = created_at.from_value();
                    let role = role.as_deref().unwrap_or("");
                    println!(
                        "{} {} {} {}",
                        &format!("{message_id:x}")[..8],
                        lower,
                        if role.is_empty() {
                            name
                        } else {
                            format!("{name} ({role})")
                        },
                        snippet(&content, 120)
                    );
                }
            }
            Command::Imports { format, limit } => {
                let format_filter = format.map(|s| s.to_lowercase());

                let mut conversations = Vec::new();
                for (conversation_id, source_format, source_conversation_id_handle) in find!(
                    (
                        conversation: Id,
                        format: String,
                        source_conversation_id: Value<Handle<Blake3, LongString>>
                    ),
                    pattern!(&catalog, [{
                        ?conversation @
                            common::metadata::tag: common::import_schema::kind_conversation,
                            common::import_schema::source_format: ?format,
                            common::import_schema::source_conversation_id: ?source_conversation_id,
                    }])
                ) {
                    if let Some(filter) = format_filter.as_deref() {
                        if source_format.to_lowercase() != filter {
                            continue;
                        }
                    }
                    let source_conversation_id =
                        load_longstring(&mut ws, source_conversation_id_handle)?;
                    conversations.push((conversation_id, source_format, source_conversation_id));
                }

                conversations.sort_by(|a, b| a.2.cmp(&b.2).then_with(|| a.0.cmp(&b.0)));
                for (conversation_id, source_format, source_conversation_id) in
                    conversations.into_iter().take(limit)
                {
                    println!(
                        "{} {} convo={}",
                        &format!("{conversation_id:x}")[..8],
                        source_format,
                        source_conversation_id
                    );
                }
            }
        }

        Ok(())
    })();

    let close_result = repo
        .close()
        .map_err(|e| anyhow!("close pile {}: {e:?}", pile_path.display()));

    match (res, close_result) {
        (Err(err), _) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Ok(()), Ok(())) => Ok(()),
    }
}
