#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! rand_core = "0.6.4"
//! triblespace = "0.34.1"
//! ```

use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::{Repository, Workspace};
use triblespace::prelude::blobschemas::LongString;
use triblespace::prelude::valueschemas::{Blake3, Handle};
use triblespace::prelude::*;

const DEFAULT_BRANCH: &str = "atlas";

#[derive(Parser)]
#[command(name = "atlas", about = "Schema metadata inspection faculty")]
struct Cli {
    /// Path to the pile file to use.
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Branch name for schema metadata.
    #[arg(long, default_value = DEFAULT_BRANCH)]
    branch: String,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// List entities that have metadata::name entries.
    List,
    /// Show metadata for a single id prefix.
    Show { id: String },
}

#[derive(Clone)]
struct MetaRow {
    id: Id,
    name: String,
    description: Option<String>,
    source_module: Option<String>,
    tags: Vec<Id>,
    grouped_by: Vec<Id>,
}

fn main() -> Result<()> {
    let Cli {
        pile,
        branch,
        command,
    } = Cli::parse();
    let Some(cmd) = command else {
        let mut command = Cli::command();
        command.print_help()?;
        println!();
        return Ok(());
    };

    match cmd {
        Command::List => cmd_list(&pile, &branch),
        Command::Show { id } => cmd_show(&pile, &branch, &id),
    }
}

fn cmd_list(pile: &Path, branch: &str) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo.ensure_branch(branch, None)
            .map_err(|e| anyhow!("ensure atlas branch: {e:?}"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
        let space = ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout atlas: {e:?}"))?;

        let mut rows = collect_rows(&mut ws, &space)?;
        rows.sort_by(|a, b| match a.name.cmp(&b.name) {
            Ordering::Equal => format!("{:x}", a.id).cmp(&format!("{:x}", b.id)),
            other => other,
        });

        for row in rows {
            let short_id = fmt_id(row.id);
            let tags = if row.tags.is_empty() {
                String::new()
            } else {
                format!(
                    " [tags: {}]",
                    row.tags
                        .iter()
                        .map(|id| fmt_id(*id))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let grouped_by = if row.grouped_by.is_empty() {
                String::new()
            } else {
                format!(
                    " [groups: {}]",
                    row.grouped_by
                        .iter()
                        .map(|id| fmt_id(*id))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let description = row
                .description
                .map(|d| format!(" - {d}"))
                .unwrap_or_default();
            let source_module = row
                .source_module
                .map(|m| format!(" @{m}"))
                .unwrap_or_default();
            println!(
                "{short_id} {name}{source_module}{tags}{grouped_by}{description}",
                name = row.name
            );
        }
        Ok(())
    })
}

fn cmd_show(pile: &Path, branch: &str, prefix: &str) -> Result<()> {
    with_repo(pile, |repo| {
        let branch_id = repo.ensure_branch(branch, None)
            .map_err(|e| anyhow!("ensure atlas branch: {e:?}"))?;
        let mut ws = repo
            .pull(branch_id)
            .map_err(|e| anyhow!("pull workspace: {e:?}"))?;
        let space = ws
            .checkout(..)
            .map_err(|e| anyhow!("checkout atlas: {e:?}"))?;
        let rows = collect_rows(&mut ws, &space)?;
        let row = resolve_prefix(rows, prefix)?;

        println!("id: {:x}", row.id);
        println!("name: {}", row.name);
        if let Some(description) = row.description {
            println!("description: {description}");
        }
        if let Some(source_module) = row.source_module {
            println!("source_module: {source_module}");
        }
        if !row.tags.is_empty() {
            let tags = row
                .tags
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ");
            println!("tags: {tags}");
        }
        if !row.grouped_by.is_empty() {
            let groups = row
                .grouped_by
                .iter()
                .map(|id| format!("{id:x}"))
                .collect::<Vec<_>>()
                .join(", ");
            println!("grouped_by: {groups}");
        }
        Ok(())
    })
}

fn collect_rows(ws: &mut Workspace<Pile<Blake3>>, space: &TribleSet) -> Result<Vec<MetaRow>> {
    let mut rows = Vec::new();
    for (id, handle) in find!(
        (id: Id, handle: Value<Handle<Blake3, LongString>>),
        pattern!(space, [{ ?id @ metadata::name: ?handle }])
    ) {
        let name: View<str> = ws.get(handle).context("read name")?;
        let description = match find!(
            (handle: Value<Handle<Blake3, LongString>>),
            pattern!(space, [{ id @ metadata::description: ?handle }])
        )
        .into_iter()
        .next()
        {
            Some((handle,)) => {
                let view: View<str> = ws.get(handle).context("read description")?;
                Some(view.to_string())
            }
            None => None,
        };
        let source_module_value = match find!(
            (handle: Value<Handle<Blake3, LongString>>),
            pattern!(space, [{ id @ metadata::source_module: ?handle }])
        )
        .into_iter()
        .next()
        {
            Some((handle,)) => {
                let view: View<str> = ws.get(handle).context("read source module")?;
                Some(view.to_string())
            }
            None => None,
        };

        let mut tags = find!(
            (tag: Id),
            pattern!(space, [{ id @ metadata::tag: ?tag }])
        )
        .into_iter()
        .map(|(tag,)| tag)
        .collect::<Vec<_>>();
        tags.sort();
        tags.dedup();

        let mut grouped_by = find!(
            (group: Id),
            pattern!(space, [{ ?group @ metadata::tag: id }])
        )
        .into_iter()
        .map(|(group,)| group)
        .collect::<Vec<_>>();
        grouped_by.sort();
        grouped_by.dedup();

        rows.push(MetaRow {
            id,
            name: name.to_string(),
            description,
            source_module: source_module_value,
            tags,
            grouped_by,
        });
    }
    Ok(rows)
}

fn resolve_prefix(rows: Vec<MetaRow>, prefix: &str) -> Result<MetaRow> {
    let prefix = prefix.trim().to_lowercase();
    if prefix.is_empty() {
        bail!("id prefix is empty");
    }
    let mut matches = Vec::new();
    for row in rows {
        let hex = format!("{:x}", row.id);
        if hex.starts_with(&prefix) {
            matches.push(row);
        }
    }
    match matches.len() {
        0 => bail!("no id matches prefix '{prefix}'"),
        1 => Ok(matches.remove(0)),
        _ => bail!("multiple ids match prefix '{prefix}'"),
    }
}

fn fmt_id(id: Id) -> String {
    format!("{id:x}")
}

fn open_repo(pile_path: &Path) -> Result<Repository<Pile<Blake3>>> {
    let mut pile =
        Pile::<Blake3>::open(pile_path).map_err(|e| anyhow!("open pile: {e:?}"))?;
    if let Err(err) = pile.restore() {
        let _ = pile.close();
        return Err(anyhow!("restore pile: {err:?}"));
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|e| anyhow!("create repository: {e:?}"))
}

fn with_repo<T>(
    pile_path: &Path,
    f: impl FnOnce(&mut Repository<Pile<Blake3>>) -> Result<T>,
) -> Result<T> {
    let mut repo = open_repo(pile_path)?;
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
