#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4.2.3"
//! rand_core = "0.6.4"
//! reqwest = { version = "0.12", default-features = false, features = ["blocking", "rustls-tls"] }
//! anybytes = "0.20"
//! triblespace = "0.22"
//! ```

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use hifitime::efmt::Formatter;
use hifitime::efmt::consts::ISO8601_DATE;
use rand_core::OsRng;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use triblespace::core::metadata;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::macros::id_hex;
use triblespace::prelude::*;

// ── branch name ──────────────────────────────────────────────────────────
const FILES_BRANCH_NAME: &str = "files";

// ── kinds ────────────────────────────────────────────────────────────────
const KIND_FILE: Id = id_hex!("1F9C9DCA69504452F318BA11E81D47D1");
const KIND_DIRECTORY: Id = id_hex!("58CDFCBA4E4B91979766D50FB18777B5");
const KIND_IMPORT: Id = id_hex!("89655D039A90634F09207BFEB5BE65AD");

// ── type aliases ─────────────────────────────────────────────────────────
type FileHandle = Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::FileBytes>>;
type TextHandle = Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>;

// ── attributes ───────────────────────────────────────────────────────────
mod file {
    use super::*;
    attributes! {
        // file leaf: content blob
        "C1E3A12230595280F22ABEB8733D082C" as content: valueschemas::Handle<valueschemas::Blake3, blobschemas::FileBytes>;
        // file/directory: name (filename or dirname)
        "AA6AB6F5E68F3A9D95681251C2B9DAFA" as name: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        // file leaf: MIME type
        "BFE2C88ECD13D56F80967C343FC072EE" as mime: valueschemas::ShortString;
        // import: timestamp
        "EA8B5429A86AF26D2B87F169AFEE3919" as imported_at: valueschemas::NsTAIInterval;
        // any entity: user tag
        "CDA941A27F86A7551779CF9524DE1D0F" as tag: valueschemas::ShortString;
        // directory: children (multi-valued, files or subdirectories)
        "0AC1D962B6E8170FDD73AE3743E16578" as children: valueschemas::GenId;
        // import: root directory or file entity
        "7B36A7A304C26C5504EA54F5723FA135" as root: valueschemas::GenId;
        // import: original filesystem path
        "E4B24BB9F469CEC6FD12926C56514E9F" as source_path: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
    }
}

// ── CLI ──────────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(name = "files", about = "Content-addressed file storage in a TribleSpace pile")]
struct Cli {
    /// Path to the pile file
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch id (hex). Overrides name-based lookup.
    #[arg(long)]
    branch_id: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Import a file or directory into the pile
    Add {
        /// Path to a file or directory
        path: PathBuf,
        /// Override MIME type (single file only)
        #[arg(long)]
        mime: Option<String>,
        /// Add tags to the import (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Preview what would be imported without committing
        #[arg(long)]
        dry_run: bool,
    },
    /// List all imported files
    List {
        /// Filter by tag
        #[arg(long)]
        tag: Vec<String>,
        /// Filter by MIME type prefix (e.g. "application/pdf")
        #[arg(long)]
        mime: Option<String>,
    },
    /// Show metadata for a file, directory, or import
    Show {
        /// Entity id (32 hex chars) or content hash (64 hex chars)
        id: String,
    },
    /// Extract a file, directory, or import to disk
    Get {
        /// Entity id (32 hex chars) or content hash (64 hex chars) (file, directory, or import)
        id: String,
        /// Output path (default: original name in current directory)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
    /// Add a tag to a file
    Tag {
        /// Entity id (32 hex chars) or content hash (64 hex chars)
        id: String,
        /// Tag to add
        name: String,
    },
    /// Fetch a URL and import it as a file
    Fetch {
        /// URL to fetch
        url: String,
        /// Override MIME type
        #[arg(long)]
        mime: Option<String>,
        /// Override filename
        #[arg(long)]
        name: Option<String>,
        /// Add tags to the import (repeatable)
        #[arg(long)]
        tag: Vec<String>,
        /// Maximum response size in bytes (default 8 MiB)
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        max_bytes: usize,
    },
    /// Search files by name or tag
    Search {
        /// Search query (substring, case-insensitive)
        query: String,
    },
    /// List imports (snapshots)
    Imports,
    /// Show the tree structure of an import or directory
    Tree {
        /// Import or directory id prefix
        id: String,
        /// Maximum depth to display (0 = root only, 1 = immediate children, etc.)
        #[arg(long, short)]
        depth: Option<usize>,
    },
    /// Resolve hash/id prefixes. Single prefix or @path/@- for batch (one per line).
    /// Batch mode outputs `old\tnew` mapping; ambiguous prefixes go to stderr.
    Resolve {
        /// Hash prefix, or @path/@- for batch input (one prefix per line)
        input: String,
    },
    /// Compare two imports, directories, or files
    Diff {
        /// Left (older) id prefix
        left: String,
        /// Right (newer) id prefix
        right: String,
    },
}

// ── helpers ──────────────────────────────────────────────────────────────

fn now_tai() -> Value<valueschemas::NsTAIInterval> {
    let now = Epoch::now().unwrap_or(Epoch::from_unix_seconds(0.0));
    (now, now).to_value()
}

fn interval_key(interval: Value<valueschemas::NsTAIInterval>) -> i128 {
    let (lower, _): (Epoch, Epoch) = interval.from_value();
    lower.to_tai_duration().total_nanoseconds()
}

fn format_date(tai_ns: i128) -> String {
    const NANOS_PER_CENTURY: i128 = 3_155_760_000_000_000_000;
    let centuries = (tai_ns / NANOS_PER_CENTURY) as i16;
    let nanos = (tai_ns % NANOS_PER_CENTURY) as u64;
    let dur = hifitime::Duration::from_parts(centuries, nanos);
    let epoch = Epoch::from_tai_duration(dur);
    Formatter::new(epoch, ISO8601_DATE).to_string()
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn handle_hex(h: FileHandle) -> String {
    let hash: Value<valueschemas::Hash<valueschemas::Blake3>> =
        valueschemas::Handle::to_hash(h);
    valueschemas::Hash::<valueschemas::Blake3>::to_hex(&hash)
}

fn infer_mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "pdf" => "application/pdf",
        "json" => "application/json",
        "toml" => "application/toml",
        "yaml" | "yml" => "application/yaml",
        "xml" => "application/xml",
        "csv" => "text/csv",
        "txt" => "text/plain",
        "md" | "markdown" => "text/markdown",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "js" => "application/javascript",
        "ts" => "application/typescript",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "tar" => "application/x-tar",
        "gz" | "gzip" => "application/gzip",
        "zip" => "application/zip",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GiB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MiB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KiB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

// ── query helpers ────────────────────────────────────────────────────────

fn read_name(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    eid: Id,
) -> Option<String> {
    let (h,) = find!(
        (h: TextHandle),
        pattern!(space, [{ eid @ file::name: ?h }])
    )
    .next()?;
    let view: View<str> = ws.get(h).ok()?;
    Some(view.as_ref().to_string())
}

fn read_mime(space: &TribleSet, eid: Id) -> Option<String> {
    find!(
        m: String,
        pattern!(space, [{ eid @ file::mime: ?m }])
    )
    .next()
}

fn content_handle_of(space: &TribleSet, eid: Id) -> Option<FileHandle> {
    find!(
        (h: FileHandle),
        pattern!(space, [{ eid @ file::content: ?h }])
    )
    .next()
    .map(|(h,)| h)
}

fn is_file(space: &TribleSet, id: Id) -> bool {
    exists!(
        (h: FileHandle),
        pattern!(space, [{ id @ metadata::tag: &KIND_FILE, file::content: ?h }])
    )
}

fn is_directory(space: &TribleSet, id: Id) -> bool {
    exists!(
        (c: Id),
        pattern!(space, [{ id @ metadata::tag: &KIND_DIRECTORY, file::children: ?c }])
    )
}

fn is_import(space: &TribleSet, id: Id) -> bool {
    exists!(
        (r: Id),
        pattern!(space, [{ id @ metadata::tag: &KIND_IMPORT, file::root: ?r }])
    )
}

fn children_of(space: &TribleSet, id: Id) -> Vec<Id> {
    find!(
        (c: Id),
        pattern!(space, [{ id @ file::children: ?c }])
    )
    .map(|(c,)| c)
    .collect()
}

fn root_of(space: &TribleSet, id: Id) -> Option<Id> {
    find!(
        (r: Id),
        pattern!(space, [{ id @ file::root: ?r }])
    )
    .next()
    .map(|(r,)| r)
}

fn imported_at_of(space: &TribleSet, eid: Id) -> Option<i128> {
    find!(
        (ts: Value<valueschemas::NsTAIInterval>),
        pattern!(space, [{ eid @ file::imported_at: ?ts }])
    )
    .next()
    .map(|(ts,)| interval_key(ts))
}

fn source_path_of(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    eid: Id,
) -> Option<String> {
    let (h,) = find!(
        (h: TextHandle),
        pattern!(space, [{ eid @ file::source_path: ?h }])
    )
    .next()?;
    let view: View<str> = ws.get(h).ok()?;
    Some(view.as_ref().to_string())
}

fn tags_of(space: &TribleSet, eid: Id) -> Vec<String> {
    find!(
        t: String,
        pattern!(space, [{ eid @ file::tag: ?t }])
    )
    .collect()
}

/// Resolve a hex prefix to any entity (file, directory, or import).
/// For files, also matches the content Blake3 hash.
/// Parse a full entity ID (32 hex chars) or content hash (64 hex chars).
/// - 32 hex chars: treated as an entity ID (direct lookup)
/// - 64 hex chars: treated as a Blake3 content hash (find the file entity with that hash)
fn resolve_entity(space: &TribleSet, input: &str) -> Result<Id> {
    let trimmed = input.trim();
    match trimmed.len() {
        32 => {
            // Entity ID — direct parse
            Id::from_hex(trimmed)
                .ok_or_else(|| anyhow::anyhow!("invalid 32-char hex id '{trimmed}'"))
        }
        64 => {
            // Content hash — find the file entity with this hash
            let hash: Value<valueschemas::Hash<valueschemas::Blake3>> =
                valueschemas::Hash::<valueschemas::Blake3>::from_hex(trimmed)
                    .map_err(|_| anyhow::anyhow!("invalid 64-char hex hash '{trimmed}'"))?;
            let handle: FileHandle = valueschemas::Handle::from_hash(hash);
            find!(
                eid: Id,
                pattern!(space, [{ ?eid @ file::content: &handle }])
            )
            .next()
            .ok_or_else(|| anyhow::anyhow!("no file with content hash '{trimmed}'"))
        }
        n => bail!(
            "expected 32-char hex id or 64-char hex hash, got {n} chars: '{trimmed}'"
        ),
    }
}


// ── repo helpers ─────────────────────────────────────────────────────────

fn open_repo(path: &Path) -> Result<Repository<Pile<valueschemas::Blake3>>> {
    let mut pile = Pile::<valueschemas::Blake3>::open(path)
        .map_err(|e| anyhow::anyhow!("open pile {}: {e:?}", path.display()))?;
    if let Err(err) = pile.restore() {
        let _ = pile.close();
        return Err(anyhow::anyhow!("restore pile {}: {err:?}", path.display()));
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|err| anyhow::anyhow!("create repository: {err:?}"))
}

fn with_files<T>(
    pile: &Path,
    explicit_branch: Option<&str>,
    f: impl FnOnce(
        &mut Repository<Pile<valueschemas::Blake3>>,
        &mut Workspace<Pile<valueschemas::Blake3>>,
    ) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile)?;
    let branch_id = if let Some(hex) = explicit_branch {
        Id::from_hex(hex.trim()).ok_or_else(|| anyhow::anyhow!("invalid branch id '{hex}'"))?
    } else {
        repo.ensure_branch(FILES_BRANCH_NAME, None)
            .map_err(|e| anyhow::anyhow!("ensure files branch: {e:?}"))?
    };
    let mut ws = repo
        .pull(branch_id)
        .map_err(|e| anyhow::anyhow!("pull files workspace: {e:?}"))?;
    let result = f(&mut repo, &mut ws);
    let close_res = repo
        .close()
        .map_err(|e| anyhow::anyhow!("close pile: {e:?}"));
    if let Err(err) = close_res {
        if result.is_ok() {
            return Err(err);
        }
        eprintln!("warning: failed to close pile cleanly: {err:#}");
    }
    result
}

// ── tree builder ─────────────────────────────────────────────────────────

struct TreeStats {
    files: usize,
    dirs: usize,
    bytes: u64,
}

/// Build a Merkle tree from a filesystem path, bottom-up.
/// Returns a Fragment whose root is the top-level entity and whose
/// facts contain the entire tree.
fn print_fs_tree(
    path: &Path,
    prefix: &str,
    child_prefix: &str,
    stats: &mut TreeStats,
) -> Result<()> {
    let meta = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or(".");

    if meta.is_file() {
        let size = meta.len();
        stats.bytes += size;
        stats.files += 1;
        let mime = infer_mime(path);
        println!("{prefix}{name}  ({mime}, {})", human_size(size));
    } else if meta.is_dir() {
        stats.dirs += 1;
        let mut dirs: Vec<(String, PathBuf)> = Vec::new();
        let mut files: Vec<(String, PathBuf)> = Vec::new();
        for entry in fs::read_dir(path)
            .with_context(|| format!("read dir {}", path.display()))?
        {
            let entry = entry?;
            let ename = entry.file_name().to_string_lossy().to_string();
            if ename.starts_with('.') {
                continue;
            }
            if entry.file_type()?.is_dir() {
                dirs.push((ename, entry.path()));
            } else {
                files.push((ename, entry.path()));
            }
        }
        dirs.sort_by(|a, b| a.0.cmp(&b.0));
        files.sort_by(|a, b| a.0.cmp(&b.0));

        println!("{prefix}{name}/");
        let all: Vec<_> = dirs.into_iter().chain(files).collect();
        for (i, (_, child_path)) in all.iter().enumerate() {
            let last = i == all.len() - 1;
            let connector = if last { "└── " } else { "├── " };
            let continuation = if last { "    " } else { "│   " };
            print_fs_tree(
                child_path,
                &format!("{child_prefix}{connector}"),
                &format!("{child_prefix}{continuation}"),
                stats,
            )?;
        }
    }
    Ok(())
}

fn build_tree(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    path: &Path,
    mime_override: Option<&str>,
    stats: &mut TreeStats,
) -> Result<Fragment> {
    let meta = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?;

    if meta.is_file() {
        let bytes = fs::read(path)
            .with_context(|| format!("read {}", path.display()))?;
        stats.bytes += bytes.len() as u64;
        let content_h: FileHandle = ws.put::<blobschemas::FileBytes, _>(bytes);
        let name_str = path.file_name().and_then(|n| n.to_str()).unwrap_or("unnamed");
        let name_h: TextHandle = ws.put(name_str.to_string());
        let mime = mime_override.unwrap_or_else(|| infer_mime(path));

        stats.files += 1;
        Ok(entity! {
            metadata::tag: &KIND_FILE,
            file::content: content_h,
            file::name: name_h,
            file::mime: mime
        })
    } else if meta.is_dir() {
        // Collect children sorted by name for deterministic ordering.
        let mut entries: BTreeMap<String, PathBuf> = BTreeMap::new();
        for entry in fs::read_dir(path)
            .with_context(|| format!("read dir {}", path.display()))?
        {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip hidden files and common noise.
            if name.starts_with('.') {
                continue;
            }
            entries.insert(name, entry.path());
        }

        let mut children = Fragment::default();

        for (_name, child_path) in &entries {
            let child_frag = build_tree(ws, child_path, None, stats)?;
            children += child_frag;
        }

        let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or(".");
        let name_h: TextHandle = ws.put(dir_name.to_string());
        stats.dirs += 1;
        Ok(entity! {
            metadata::tag: &KIND_DIRECTORY,
            file::name: name_h,
            file::children*: children
        })
    } else {
        bail!("unsupported file type: {}", path.display());
    }
}

// ── commands ─────────────────────────────────────────────────────────────

fn cmd_add(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    path: &Path,
    mime_override: Option<&str>,
    tags: &[String],
    dry_run: bool,
) -> Result<()> {
    let abs_path = fs::canonicalize(path)
        .with_context(|| format!("canonicalize {}", path.display()))?;

    if dry_run {
        let mut stats = TreeStats { files: 0, dirs: 0, bytes: 0 };
        print_fs_tree(&abs_path, "", "", &mut stats)?;
        println!();
        println!(
            "Would import: {} files, {} dirs, {}",
            stats.files, stats.dirs, human_size(stats.bytes),
        );
        if !tags.is_empty() {
            println!("Tags: {}", tags.join(", "));
        }
        return Ok(());
    }

    let source = abs_path.to_string_lossy().to_string();

    let mut stats = TreeStats { files: 0, dirs: 0, bytes: 0 };
    let tree = build_tree(ws, &abs_path, mime_override, &mut stats)?;
    let root_id = tree.root().expect("tree has a root");

    // Create import entity, spreading the tree into it.
    let ts = now_tai();
    let source_h: TextHandle = ws.put(source.clone());

    let import_frag = entity! {
        metadata::tag: &KIND_IMPORT,
        file::root: &root_id,
        file::imported_at: ts,
        file::source_path: source_h
    };
    let import_id = import_frag.root().expect("import has an id");
    let mut change: TribleSet = tree.into();
    change += import_frag;

    // Tags go on the import entity.
    for t in tags {
        change += entity! { ExclusiveId::force_ref(&import_id) @ file::tag: t.as_str() };
    }

    ws.commit(change, "files add");
    repo.push(ws)
        .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;

    if stats.dirs > 0 {
        println!(
            "Imported {} ({} files, {} dirs, {})",
            abs_path.display(),
            stats.files,
            stats.dirs,
            human_size(stats.bytes),
        );
    } else {
        // Single file — show the content hash.
        let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
        let h = content_handle_of(&space, root_id)
            .ok_or_else(|| anyhow::anyhow!("missing content handle"))?;
        let hash = handle_hex(h);
        let name = abs_path.file_name().and_then(|n| n.to_str()).unwrap_or("?");
        let mime = read_mime(&space, root_id).unwrap_or_default();
        println!("{}  {}  ({})", hash, name, human_size(stats.bytes));
        if mime.starts_with("image/") {
            println!("![{name}](files:{hash})");
        }
    }
    println!("Import: {}", fmt_id(import_id));
    Ok(())
}

fn cmd_fetch(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    url: &str,
    mime_override: Option<&str>,
    name_override: Option<&str>,
    tags: &[String],
    max_bytes: usize,
) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("playground-files-faculty/0")
        .build()
        .context("build http client")?;
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("fetch {url}"))?
        .error_for_status()
        .with_context(|| format!("fetch {url}"))?;

    let header_mime = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    let bytes = response.bytes().context("read response body")?;
    if bytes.len() > max_bytes {
        bail!(
            "response too large: {} bytes (limit {})",
            bytes.len(),
            max_bytes
        );
    }

    let guessed_name = name_override
        .map(str::to_owned)
        .or_else(|| {
            let before_query = url.split('?').next().unwrap_or(url);
            let last = before_query.rsplit('/').next()?.trim();
            if last.is_empty() { None } else { Some(last.to_owned()) }
        });
    let mime = mime_override
        .map(str::to_owned)
        .or(header_mime)
        .unwrap_or_else(|| {
            guessed_name
                .as_deref()
                .map(|n| infer_mime(Path::new(n)))
                .unwrap_or("application/octet-stream")
                .to_string()
        });
    let fname = guessed_name.unwrap_or_else(|| "fetched".to_string());

    // Write to a temp file so we can reuse build_tree / cmd_add flow.
    let tmp_dir = std::env::temp_dir().join("files-fetch");
    fs::create_dir_all(&tmp_dir).context("create temp dir")?;
    let tmp_path = tmp_dir.join(&fname);
    fs::write(&tmp_path, bytes.as_ref())
        .with_context(|| format!("write temp file {}", tmp_path.display()))?;

    let result = cmd_add(repo, ws, &tmp_path, Some(mime.as_str()), tags, false);
    let _ = fs::remove_file(&tmp_path);
    let _ = fs::remove_dir(&tmp_dir);
    result
}

fn cmd_list(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    filter_tags: &[String],
    filter_mime: Option<&str>,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

    let mut entries: Vec<(String, String, String, Vec<String>)> = Vec::new();

    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(&space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        let fname = read_name(&space, ws, eid).unwrap_or_else(|| "?".into());
        let mime = read_mime(&space, eid).unwrap_or_else(|| "?".into());
        let tags = tags_of(&space, eid);

        if let Some(mp) = filter_mime {
            if !mime.starts_with(mp) {
                continue;
            }
        }
        if !filter_tags.is_empty() && !filter_tags.iter().all(|ft| tags.iter().any(|t| t == ft)) {
            continue;
        }

        let hash = handle_hex(h);
        entries.push((hash, fname, mime, tags));
    }

    entries.sort_by(|a, b| a.1.cmp(&b.1));

    if entries.is_empty() {
        println!("(no files)");
        return Ok(());
    }

    for (hash, fname, mime, tags) in &entries {
        let tag_str = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        println!("{}  {}  {}{}", &hash[..12], fname, mime, tag_str);
    }

    Ok(())
}

fn resolve_one_prefix(space: &TribleSet, needle: &str) -> Result<String, String> {
    let mut matches = Vec::new();
    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        let hash_hex = handle_hex(h).to_lowercase();
        if hash_hex.starts_with(needle) {
            matches.push(hash_hex);
        }
        let eid_hex = format!("{eid:x}");
        if eid_hex.starts_with(needle) && !matches.iter().any(|m| m == &eid_hex) {
            matches.push(eid_hex);
        }
    }
    for eid in find!(
        eid: Id,
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_DIRECTORY }])
    ) {
        let hex = format!("{eid:x}");
        if hex.starts_with(needle) && !matches.contains(&hex) {
            matches.push(hex);
        }
    }
    for eid in find!(
        eid: Id,
        pattern!(space, [{ ?eid @ metadata::tag: &KIND_IMPORT }])
    ) {
        let hex = format!("{eid:x}");
        if hex.starts_with(needle) && !matches.contains(&hex) {
            matches.push(hex);
        }
    }
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => Err(format!("no match")),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => Err(format!("ambiguous ({n} matches)")),
    }
}

fn cmd_resolve(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    input: &str,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

    // Batch mode: @path or @-
    if let Some(path) = input.strip_prefix('@') {
        let content = if path == "-" {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                .context("read stdin")?;
            buf
        } else {
            fs::read_to_string(path)
                .with_context(|| format!("read {path}"))?
        };
        let mut resolved = 0u32;
        let mut ambiguous = 0u32;
        let mut already_full = 0u32;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() { continue; }
            let prefix = line.strip_prefix("files:").unwrap_or(line);
            if prefix.len() >= 64 {
                already_full += 1;
                continue;
            }
            let needle = prefix.to_lowercase();
            if needle.len() < 4 { continue; }
            match resolve_one_prefix(&space, &needle) {
                Ok(full) => {
                    println!("{}\tfiles:{}", line, full);
                    resolved += 1;
                }
                Err(e) => {
                    eprintln!("AMBIGUOUS: {} — {}", line, e);
                    ambiguous += 1;
                }
            }
        }
        eprintln!("{} resolved, {} ambiguous, {} already full", resolved, ambiguous, already_full);
        return Ok(());
    }

    // Single prefix mode
    let needle = input.trim().to_lowercase();
    if needle.len() < 4 {
        bail!("prefix too short (need at least 4 hex chars)");
    }
    match resolve_one_prefix(&space, &needle) {
        Ok(full) => {
            println!("{}", full);
            Ok(())
        }
        Err(e) => bail!("files resolve '{}': {}", input.trim(), e),
    }
}

fn cmd_show(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: &str,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let eid = resolve_entity(&space, id)?;

    if is_file(&space, eid) {
        let h = content_handle_of(&space, eid).unwrap();
        let size = ws.get::<anybytes::Bytes, _>(h)
            .map(|b| b.len() as u64)
            .unwrap_or(0);
        println!("Type:     file");
        println!("Hash:     {}", handle_hex(h));
        println!("Entity:   {}", fmt_id(eid));
        println!("Name:     {}", read_name(&space, ws, eid).unwrap_or("?".into()));
        println!("MIME:     {}", read_mime(&space, eid).unwrap_or("?".into()));
        println!("Size:     {}", human_size(size));
    } else if is_directory(&space, eid) {
        let children = children_of(&space, eid);
        println!("Type:     directory");
        println!("Entity:   {}", fmt_id(eid));
        println!("Name:     {}", read_name(&space, ws, eid).unwrap_or("?".into()));
        println!("Children: {}", children.len());
    } else if is_import(&space, eid) {
        let root = root_of(&space, eid);
        let ts = imported_at_of(&space, eid);
        let src = source_path_of(&space, ws, eid);
        println!("Type:     import");
        println!("Entity:   {}", fmt_id(eid));
        if let Some(r) = root {
            println!("Root:     {}", fmt_id(r));
        }
        if let Some(t) = ts {
            println!("Imported: {}", format_date(t));
        }
        if let Some(s) = src {
            println!("Source:   {s}");
        }
    } else {
        bail!("unknown entity kind for '{id}'");
    }

    let tags = tags_of(&space, eid);
    if !tags.is_empty() {
        println!("Tags:     {}", tags.join(", "));
    }

    Ok(())
}

fn cmd_get(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: &str,
    output: Option<&Path>,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let eid = resolve_entity(&space, id)?;

    // For imports, follow to root.
    let target = if is_import(&space, eid) {
        root_of(&space, eid).ok_or_else(|| anyhow::anyhow!("import has no root"))?
    } else {
        eid
    };

    if is_file(&space, target) {
        let h = content_handle_of(&space, target)
            .ok_or_else(|| anyhow::anyhow!("no content for file"))?;
        let bytes: anybytes::Bytes = ws.get::<anybytes::Bytes, _>(h)
            .map_err(|e| anyhow::anyhow!("get blob: {e:?}"))?;

        let out_path = if let Some(p) = output {
            p.to_path_buf()
        } else {
            let fname = read_name(&space, ws, target).unwrap_or_else(|| "file.bin".into());
            PathBuf::from(fname)
        };

        fs::write(&out_path, bytes.as_ref())
            .with_context(|| format!("write {}", out_path.display()))?;
        println!("Wrote {} ({})", out_path.display(), human_size(bytes.len() as u64));
    } else if is_directory(&space, target) {
        let dir_name = read_name(&space, ws, target).unwrap_or_else(|| "extracted".into());
        let out_dir = output.map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from(&dir_name));
        let mut stats = TreeStats { files: 0, dirs: 0, bytes: 0 };
        extract_tree(&space, ws, target, &out_dir, &mut stats)?;
        println!(
            "Extracted to {} ({} files, {} dirs, {})",
            out_dir.display(), stats.files, stats.dirs, human_size(stats.bytes),
        );
    } else {
        bail!("entity is not a file, directory, or import");
    }

    Ok(())
}

fn extract_tree(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: Id,
    dest: &Path,
    stats: &mut TreeStats,
) -> Result<()> {
    if is_file(space, id) {
        let h = content_handle_of(space, id)
            .ok_or_else(|| anyhow::anyhow!("no content for file"))?;
        let bytes: anybytes::Bytes = ws.get::<anybytes::Bytes, _>(h)
            .map_err(|e| anyhow::anyhow!("get blob: {e:?}"))?;
        fs::write(dest, bytes.as_ref())
            .with_context(|| format!("write {}", dest.display()))?;
        stats.files += 1;
        stats.bytes += bytes.len() as u64;
    } else if is_directory(space, id) {
        fs::create_dir_all(dest)
            .with_context(|| format!("mkdir {}", dest.display()))?;
        stats.dirs += 1;
        for cid in children_of(space, id) {
            let cname = read_name(space, ws, cid).unwrap_or_else(|| fmt_id(cid));
            extract_tree(space, ws, cid, &dest.join(&cname), stats)?;
        }
    } else {
        bail!("unknown entity kind during extraction");
    }
    Ok(())
}

fn cmd_tag(
    repo: &mut Repository<Pile<valueschemas::Blake3>>,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: &str,
    tag_name: &str,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let eid = resolve_entity(&space, id)?;

    let existing = tags_of(&space, eid);
    if existing.iter().any(|t| t == tag_name) {
        println!("Tag '{tag_name}' already present.");
        return Ok(());
    }

    let change = entity! { ExclusiveId::force_ref(&eid) @ file::tag: tag_name };
    ws.commit(change, "files tag");
    repo.push(ws)
        .map_err(|e| anyhow::anyhow!("push: {e:?}"))?;

    let name = read_name(&space, ws, eid).unwrap_or_else(|| fmt_id(eid));
    println!("Tagged {name} with '{tag_name}'");
    Ok(())
}

fn cmd_search(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    query: &str,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

    let needle = query.to_lowercase();
    let mut hits: Vec<(String, String, String, Vec<String>)> = Vec::new();

    for (eid, h) in find!(
        (eid: Id, h: FileHandle),
        pattern!(&space, [{ ?eid @ metadata::tag: &KIND_FILE, file::content: ?h }])
    ) {
        let fname = read_name(&space, ws, eid).unwrap_or_else(|| "?".into());
        let mime = read_mime(&space, eid).unwrap_or_else(|| "?".into());
        let tags = tags_of(&space, eid);

        let fname_match = fname.to_lowercase().contains(&needle);
        let tag_match = tags.iter().any(|t| t.to_lowercase().contains(&needle));
        let mime_match = mime.to_lowercase().contains(&needle);

        if fname_match || tag_match || mime_match {
            hits.push((handle_hex(h), fname, mime, tags));
        }
    }

    hits.sort_by(|a, b| a.1.cmp(&b.1));

    if hits.is_empty() {
        println!("No files matching '{query}'");
        return Ok(());
    }

    for (hash, fname, mime, tags) in &hits {
        let tag_str = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        println!("{}  {}  {}{}", &hash[..12], fname, mime, tag_str);
    }

    Ok(())
}

fn cmd_imports(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

    let mut imports: Vec<(i128, Id, Option<String>, Vec<String>)> = Vec::new();

    for (eid,) in find!(
        (eid: Id),
        pattern!(&space, [{ ?eid @ metadata::tag: &KIND_IMPORT }])
    ) {
        let ts = imported_at_of(&space, eid).unwrap_or(0);
        let src = source_path_of(&space, ws, eid);
        let tags = tags_of(&space, eid);
        imports.push((ts, eid, src, tags));
    }

    imports.sort_by(|a, b| b.0.cmp(&a.0));

    if imports.is_empty() {
        println!("(no imports)");
        return Ok(());
    }

    for (ts, eid, src, tags) in &imports {
        let date = if *ts > 0 { format_date(*ts) } else { "?".into() };
        let src_str = src.as_deref().unwrap_or("?");
        let tag_str = if tags.is_empty() {
            String::new()
        } else {
            format!("  [{}]", tags.join(", "))
        };
        println!("{}  {}  {}{}", &fmt_id(*eid)[..12], date, src_str, tag_str);
    }

    Ok(())
}

fn cmd_tree(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: &str,
    max_depth: Option<usize>,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;
    let eid = resolve_entity(&space, id)?;

    // If it's an import, follow to root.
    let root = if is_import(&space, eid) {
        root_of(&space, eid).ok_or_else(|| anyhow::anyhow!("import has no root"))?
    } else {
        eid
    };

    print_tree(&space, ws, root, "", "", max_depth, 0);
    Ok(())
}

fn print_tree(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: Id,
    prefix: &str,
    child_prefix: &str,
    max_depth: Option<usize>,
    depth: usize,
) {
    let name = read_name(space, ws, id).unwrap_or_else(|| fmt_id(id));

    if is_file(space, id) {
        let mime = read_mime(space, id).unwrap_or_else(|| "?".into());
        let size_str = content_handle_of(space, id)
            .and_then(|h| ws.get::<anybytes::Bytes, _>(h).ok())
            .map(|b| human_size(b.len() as u64))
            .unwrap_or_else(|| "?".into());
        println!("{prefix}{name}  ({mime}, {size_str})");
    } else if is_directory(space, id) {
        let children = children_of(space, id);
        if max_depth.is_some_and(|d| depth >= d) {
            println!("{prefix}{name}/  ({} children)", children.len());
            return;
        }
        println!("{prefix}{name}/");
        let mut dirs: Vec<(String, Id)> = Vec::new();
        let mut files: Vec<(String, Id)> = Vec::new();
        for &cid in &children {
            let cname = read_name(space, ws, cid).unwrap_or_else(|| fmt_id(cid));
            if is_directory(space, cid) {
                dirs.push((cname, cid));
            } else {
                files.push((cname, cid));
            }
        }
        dirs.sort_by(|a, b| a.0.cmp(&b.0));
        files.sort_by(|a, b| a.0.cmp(&b.0));

        let all: Vec<Id> = dirs.iter().chain(files.iter()).map(|(_, id)| *id).collect();
        for (i, &cid) in all.iter().enumerate() {
            let last = i == all.len() - 1;
            let connector = if last { "└── " } else { "├── " };
            let continuation = if last { "    " } else { "│   " };
            print_tree(
                space, ws, cid,
                &format!("{child_prefix}{connector}"),
                &format!("{child_prefix}{continuation}"),
                max_depth, depth + 1,
            );
        }
    } else {
        println!("{prefix}{name}  (unknown)");
    }
}

fn cmd_diff(
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    left_id: &str,
    right_id: &str,
) -> Result<()> {
    let space = ws
        .checkout(..)
        .map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

    let resolve_root = |raw: &str| -> Result<Id> {
        let eid = resolve_entity(&space, raw)?;
        if is_import(&space, eid) {
            root_of(&space, eid).ok_or_else(|| anyhow::anyhow!("import has no root"))
        } else {
            Ok(eid)
        }
    };

    let left = resolve_root(left_id)?;
    let right = resolve_root(right_id)?;

    if left == right {
        println!("Identical (same entity).");
        return Ok(());
    }

    let mut stats = DiffStats::default();
    diff_tree(&space, ws, left, right, "", &mut stats);

    if stats.is_empty() {
        println!("No differences.");
    } else {
        println!(
            "\n{} added, {} removed, {} modified",
            stats.added, stats.removed, stats.modified,
        );
    }
    Ok(())
}

#[derive(Default)]
struct DiffStats {
    added: usize,
    removed: usize,
    modified: usize,
}

impl DiffStats {
    fn is_empty(&self) -> bool {
        self.added == 0 && self.removed == 0 && self.modified == 0
    }
}

fn diff_tree(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    left: Id,
    right: Id,
    path: &str,
    stats: &mut DiffStats,
) {
    // Merkle shortcut: same id means identical subtree.
    if left == right {
        return;
    }

    let left_is_dir = is_directory(space, left);
    let right_is_dir = is_directory(space, right);

    // Both files — content changed.
    if !left_is_dir && !right_is_dir {
        let lname = read_name(space, ws, left).unwrap_or_else(|| "?".into());
        let lsize = file_size(space, ws, left);
        let rsize = file_size(space, ws, right);
        println!("  ~ {path}{lname}  ({} → {})", human_size(lsize), human_size(rsize));
        stats.modified += 1;
        return;
    }

    // Type mismatch: show as remove + add.
    if left_is_dir != right_is_dir {
        print_diff_removed(space, ws, left, path, stats);
        print_diff_added(space, ws, right, path, stats);
        return;
    }

    // Both directories — diff children by name.
    let left_children = named_children(space, ws, left);
    let right_children = named_children(space, ws, right);

    let left_name = read_name(space, ws, left).unwrap_or_else(|| "?".into());
    let sub = if path.is_empty() {
        format!("{left_name}/")
    } else {
        format!("{path}{left_name}/")
    };

    let mut li = left_children.iter().peekable();
    let mut ri = right_children.iter().peekable();

    // Merge-join on name (BTreeMap is sorted).
    loop {
        match (li.peek(), ri.peek()) {
            (None, None) => break,
            (Some(_), None) => {
                let (_lname, lid) = li.next().unwrap();
                print_diff_removed(space, ws, *lid, &sub, stats);
            }
            (None, Some(_)) => {
                let (_rname, rid) = ri.next().unwrap();
                print_diff_added(space, ws, *rid, &sub, stats);
            }
            (Some((lname, _)), Some((rname, _))) => {
                match lname.cmp(rname) {
                    std::cmp::Ordering::Less => {
                        let (lname, lid) = li.next().unwrap();
                        print_diff_removed(space, ws, *lid, &sub, stats);
                        let _ = lname;
                    }
                    std::cmp::Ordering::Greater => {
                        let (rname, rid) = ri.next().unwrap();
                        print_diff_added(space, ws, *rid, &sub, stats);
                        let _ = rname;
                    }
                    std::cmp::Ordering::Equal => {
                        let (_lname, lid) = li.next().unwrap();
                        let (_rname, rid) = ri.next().unwrap();
                        diff_tree(space, ws, *lid, *rid, &sub, stats);
                    }
                }
            }
        }
    }
}

fn named_children(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: Id,
) -> BTreeMap<String, Id> {
    let mut map = BTreeMap::new();
    for cid in children_of(space, id) {
        let name = read_name(space, ws, cid).unwrap_or_else(|| fmt_id(cid));
        map.insert(name, cid);
    }
    map
}

fn file_size(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: Id,
) -> u64 {
    content_handle_of(space, id)
        .and_then(|h| ws.get::<anybytes::Bytes, _>(h).ok())
        .map(|b| b.len() as u64)
        .unwrap_or(0)
}

fn print_diff_added(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: Id,
    path: &str,
    stats: &mut DiffStats,
) {
    let name = read_name(space, ws, id).unwrap_or_else(|| "?".into());
    if is_directory(space, id) {
        println!("  + {path}{name}/");
        stats.added += 1;
        let sub = format!("{path}{name}/");
        for cid in children_of(space, id) {
            print_diff_added(space, ws, cid, &sub, stats);
        }
    } else {
        let size = file_size(space, ws, id);
        println!("  + {path}{name}  ({})", human_size(size));
        stats.added += 1;
    }
}

fn print_diff_removed(
    space: &TribleSet,
    ws: &mut Workspace<Pile<valueschemas::Blake3>>,
    id: Id,
    path: &str,
    stats: &mut DiffStats,
) {
    let name = read_name(space, ws, id).unwrap_or_else(|| "?".into());
    if is_directory(space, id) {
        println!("  - {path}{name}/");
        stats.removed += 1;
        let sub = format!("{path}{name}/");
        for cid in children_of(space, id) {
            print_diff_removed(space, ws, cid, &sub, stats);
        }
    } else {
        let size = file_size(space, ws, id);
        println!("  - {path}{name}  ({})", human_size(size));
        stats.removed += 1;
    }
}

// ── main ─────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        return Ok(());
    };

    let pile = &cli.pile;
    let branch = cli.branch_id.as_deref();

    match command {
        Command::Add { path, mime, tag, dry_run } => {
            with_files(pile, branch, |repo, ws| {
                cmd_add(repo, ws, &path, mime.as_deref(), &tag, dry_run)
            })
        }
        Command::List { tag, mime } => {
            with_files(pile, branch, |_repo, ws| {
                cmd_list(ws, &tag, mime.as_deref())
            })
        }
        Command::Show { id } => {
            with_files(pile, branch, |_repo, ws| cmd_show(ws, &id))
        }
        Command::Get { id, output } => {
            with_files(pile, branch, |_repo, ws| {
                cmd_get(ws, &id, output.as_deref())
            })
        }
        Command::Tag { id, name } => {
            with_files(pile, branch, |repo, ws| cmd_tag(repo, ws, &id, &name))
        }
        Command::Fetch { url, mime, name, tag, max_bytes } => {
            with_files(pile, branch, |repo, ws| {
                cmd_fetch(repo, ws, &url, mime.as_deref(), name.as_deref(), &tag, max_bytes)
            })
        }
        Command::Search { query } => {
            with_files(pile, branch, |_repo, ws| cmd_search(ws, &query))
        }
        Command::Imports => {
            with_files(pile, branch, |_repo, ws| cmd_imports(ws))
        }
        Command::Tree { id, depth } => {
            with_files(pile, branch, |_repo, ws| cmd_tree(ws, &id, depth))
        }
        Command::Resolve { input } => {
            with_files(pile, branch, |_repo, ws| cmd_resolve(ws, &input))
        }
        Command::Diff { left, right } => {
            with_files(pile, branch, |_repo, ws| cmd_diff(ws, &left, &right))
        }
    }
}
