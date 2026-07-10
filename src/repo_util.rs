use std::fs;

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::id::ExclusiveId;
use triblespace::core::metadata;
use triblespace::core::repo::pile::{Pile, ReadError};
use triblespace::core::repo::{PullError, Repository, Workspace};
use triblespace::prelude::blobencodings::LongString;
use triblespace::prelude::inlineencodings::{Handle};
use triblespace::prelude::*;

use crate::config::Config;
pub(crate) use crate::repo_ops::push_workspace;
use crate::schema::build_playground_metadata;

/// Load the pile, failing loud on corruption instead of auto-truncating.
///
/// `Pile::amputate()` silently truncates the file to the last valid record —
/// under version skew (a stale binary reading a newer-format record) that is
/// a silent data-loss hazard. Repair is explicit and destructive: `trible pile amputate <path>`.
pub(crate) fn refresh_pile(pile: &mut Pile, path: &std::path::Path) -> Result<()> {
    if let Err(err) = pile.refresh() {
        return Err(match err {
            ReadError::CorruptPile { valid_length } => anyhow!(
                "pile {} corrupt at byte {valid_length}: refusing to auto-repair (a stale \
                 binary could truncate newer data). Repair the torn tail explicitly with: \
                 trible pile amputate {}",
                path.display(),
                path.display()
            ),
            other => anyhow!("refresh pile {}: {other:?}", path.display()),
        });
    }
    Ok(())
}

/// Open a pile that is expected to already contain data, refusing an empty
/// (0-byte) file. `Pile::open` treats a zero-length file as a valid *fresh*
/// pile (`Bytes::empty`), which is how a truncated personal pile silently got
/// re-seeded on 2026-07-10 (a stray `File::create` truncated it, then this
/// runtime opened the empty file and wrote fresh branches). Faculties fail on
/// a MISSING pile; this makes the playground runtime fail on an EMPTY one too.
/// A deliberate new pile is bootstrapped explicitly, never opened at runtime.
pub(crate) fn open_existing_pile(path: &std::path::Path) -> Result<Pile> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() == 0 {
            return Err(anyhow!(
                "pile at {} is empty (0 bytes) — refusing to open a truncated or \
                 uninitialized pile; restore it from backup or bootstrap explicitly",
                path.display()
            ));
        }
    }
    Pile::open(path).context("open pile")
}

pub(crate) fn init_repo(config: &Config) -> Result<(Repository<Pile>, Id)> {
    if let Some(parent) = config.pile_path.parent() {
        fs::create_dir_all(parent).context("create pile directory")?;
    }
    let mut pile = open_existing_pile(&config.pile_path)?;
    if let Err(err) = refresh_pile(&mut pile, &config.pile_path) {
        let close_res = pile.close().context("close pile after refresh failure");
        if let Err(close_err) = close_res {
            eprintln!("warning: failed to close pile cleanly: {close_err:#}");
        }
        return Err(err);
    }

    let metadata = build_playground_metadata();
    let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), metadata)
        .map_err(|err| anyhow!("create repository: {err:?}"))?;
    let branch_id = repo
        .ensure_branch(&config.branch, None)
        .map_err(|e| anyhow!("ensure branch '{}': {e:?}", config.branch))?;
    let result = (|| -> Result<()> {
        pull_workspace(&mut repo, branch_id, &format!("pull branch {branch_id:x}"))?;
        Ok(())
    })();

    if let Err(err) = result {
        let close_res = close_repo(repo).context("close pile after init failure");
        if let Err(close_err) = close_res {
            eprintln!("warning: failed to close pile cleanly: {close_err:#}");
        }
        return Err(err);
    }

    Ok((repo, branch_id))
}

pub(crate) fn close_repo(repo: Repository<Pile>) -> Result<()> {
    repo.into_storage().close().context("close pile")
}

pub(crate) type CommitHandle = Inline<Handle<SimpleArchive>>;

pub(crate) fn current_branch_head(
    repo: &mut Repository<Pile>,
    branch_id: Id,
) -> Result<Option<CommitHandle>> {
    match repo.storage_mut().head(branch_id) {
        Ok(head) => Ok(head),
        Err(ReadError::CorruptPile { valid_length }) => Err(anyhow!(
            "read branch head {branch_id:x}: pile corrupt at byte {valid_length}: refusing to \
             auto-repair (a stale binary could truncate newer data). Repair the torn tail \
             explicitly with: trible pile amputate <pile>"
        )),
        Err(err) => Err(anyhow!("read branch head {branch_id:x}: {err:?}")),
    }
}

pub(crate) fn refresh_cached_checkout(
    ws: &mut Workspace<Pile>,
    cached_head: &mut Option<CommitHandle>,
    cached_catalog: &mut TribleSet,
) -> Result<TribleSet> {
    let head = ws.head();
    if *cached_head == head {
        return Ok(TribleSet::new());
    }

    let checkout = ws
        .checkout(*cached_head..head)
        .context("checkout from cached head to current head")?;
    let delta = checkout.into_facts();
    let mut data = cached_catalog.clone();
    data += delta.clone();

    *cached_catalog = data;
    *cached_head = head;
    Ok(delta)
}

pub(crate) fn load_text(
    ws: &mut Workspace<Pile>,
    handle: Inline<Handle<LongString>>,
) -> Result<String> {
    let view: View<str> = ws.get(handle).context("read text blob")?;
    Ok(view.as_ref().to_string())
}

pub(crate) fn ensure_worker_name(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    worker_id: Id,
    label: &str,
) -> Result<()> {
    let mut ws = pull_workspace(repo, branch_id, "pull workspace for worker name")?;
    let catalog = ws.checkout(..).context("checkout workspace")?;

    let exists = find!(
        (name_handle: Inline<Handle<LongString>>),
        pattern!(&catalog, [{ worker_id @ metadata::name: ?name_handle }])
    )
    .into_iter()
    .next()
    .is_some();
    if exists {
        return Ok(());
    }

    let name_blob = label.to_owned().to_blob();
    let name_handle = name_blob.get_handle();
    repo.storage_mut()
        .put::<LongString, _>(name_blob)
        .map_err(|err| anyhow!("store worker name blob: {err:?}"))?;

    let mut change = TribleSet::new();
    change += entity! { ExclusiveId::force_ref(&worker_id) @
        metadata::name: name_handle
    };
    ws.commit(change, "worker name");
    push_workspace(repo, &mut ws).context("push worker name")?;
    Ok(())
}

pub(crate) fn pull_workspace(
    repo: &mut Repository<Pile>,
    branch_id: Id,
    context: &str,
) -> Result<Workspace<Pile>> {
    match repo.pull(branch_id) {
        Ok(ws) => Ok(ws),
        Err(err) => {
            let Some(valid_length) = pull_corrupt_valid_length(&err) else {
                return Err(anyhow!("{context}: {err:?}"));
            };
            Err(anyhow!(
                "{context}: pile corrupt at byte {valid_length}: refusing to auto-repair (a \
                 stale binary could truncate newer data). Repair the torn tail explicitly \
                 with: trible pile amputate <pile>"
            ))
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
