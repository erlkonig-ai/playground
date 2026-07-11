//! Provisioning of the faculty CLI bundle for sandbox sessions.
//!
//! A sandbox session should be able to run `compass list`, `wiki search X`,
//! `orient show`, etc. against its mounted pile. Those are the faculty binaries
//! from the sibling `faculties` crate — real Rust CLIs, not scripts. This module
//! produces a directory of **Linux-aarch64** faculty binaries that the Lima
//! backend mounts read-only into each guest and puts on PATH.
//!
//! ## Why build in a guest VM, not cross-compile on the host
//!
//! The host is macOS-aarch64. Cross-compiling the faculties for
//! `aarch64-unknown-linux-musl` from macOS needs the Rust musl target plus a
//! cross linker (and the faculties dependency tree occasionally pulls C shims).
//! That is a heavy, fragile host-side toolchain. The Lima guest is *native*
//! aarch64 Linux, so it compiles the faculties with a stock rustup and no cross
//! machinery. We therefore build **inside a throwaway Lima builder VM** and copy
//! the resulting `target/release` binaries out to a host cache directory.
//!
//! The builder mounts the *workspace root* (parent of the faculties crate)
//! read-only, because the faculties crate has `../sibling` path deps
//! (`triblespace-rs`, `mary`, `cubecl-fork`). That mount incidentally exposes a
//! `self.pile` in the workspace to the builder VM — but read-only, and the
//! builder only ever runs `cargo build` (never a faculty, never a pile touch),
//! so the append-only pile invariant is not at risk on this path.
//!
//! ## Why a host cache (build once, mount many)
//!
//! Compiling the faculties is slow (minutes). Doing it per session would make
//! every `open_session` glacial. Instead the build is cached on the host, keyed
//! by a hash of the faculty sources; a session just mounts the cached directory.
//! The bundle is rebuilt only when the sources change. This keeps the append-only
//! pile-mount property untouched — the bundle is a *separate*, read-only mount.
//!
//! ## Lean build (`--no-default-features`)
//!
//! The faculties' default feature `local-embed` pulls in `mary` (Burn/Metal ML,
//! GPU embedders) — irrelevant to a text CLI in a headless Linux guest and huge
//! to compile. We build with `--no-default-features`, which drops `mary` and
//! yields the lean CLI faculties (`wiki`/`compass`/`orient`/`message`/`files`/
//! `teams`/`memory`/…). The semantic-recall subcommands (`wiki similar`,
//! `memory similar`, `files` image search) are compiled out; the core CLI — the
//! part a session needs — is fully present.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use super::proc::drive_child;

/// The non-widget, non-`mary` faculty binaries we stage into a session. These
/// are exactly the CLI verbs a session invokes against its pile. Kept explicit
/// (rather than "everything cargo builds") so the bundle is small and the build
/// command is a clear allow-list.
pub const SESSION_FACULTIES: &[&str] = &[
    "wiki", "compass", "orient", "message", "files", "teams", "memory",
    "relations", "status", "decide", "gauge", "patience", "reason", "web",
];

/// Timeout for the (slow) in-guest cargo build.
const BUILD_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Where prebuilt Linux-aarch64 faculty bundles are cached on the host.
///
/// `~/.cache/playground/faculties-linux-aarch64/<source-hash>/` holds one
/// immutable bundle per faculty-source revision (a `.complete` stamp marks a
/// finished build). Stale revisions are left in place — cheap, and a build that
/// changed nothing reuses its bundle by fingerprint.
fn cache_root() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .ok_or_else(|| anyhow!("no HOME / XDG_CACHE_HOME to place the faculties cache"))?;
    Ok(base.join("playground").join("faculties-linux-aarch64"))
}

/// A cheap, order-independent content hash of the faculty sources, so the cache
/// key changes exactly when a rebuild is warranted (a `.rs` bin, the lib, or a
/// manifest changed). We hash file paths + sizes + mtimes rather than full
/// contents: fast, and mtime bumps on every real edit.
fn source_fingerprint(faculties_src: &Path) -> Result<String> {
    use std::collections::BTreeMap;
    let mut entries: BTreeMap<String, (u64, i64)> = BTreeMap::new();

    fn visit(
        dir: &Path,
        root: &Path,
        out: &mut BTreeMap<String, (u64, i64)>,
    ) -> Result<()> {
        for entry in std::fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Skip build artifacts and VCS noise — they don't affect the output.
            if name == "target" || name == ".git" {
                continue;
            }
            let meta = entry.metadata()?;
            if meta.is_dir() {
                visit(&path, root, out)?;
            } else if meta.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                out.insert(rel, (meta.len(), mtime));
            }
        }
        Ok(())
    }

    // Cargo.toml, Cargo.lock, src/ are what determine the build.
    for sub in ["Cargo.toml", "Cargo.lock", "src"] {
        let p = faculties_src.join(sub);
        if p.is_dir() {
            visit(&p, faculties_src, &mut entries)?;
        } else if p.is_file() {
            let meta = std::fs::metadata(&p)?;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            entries.insert(sub.to_string(), (meta.len(), mtime));
        }
    }

    // FNV-1a over the sorted (path,size,mtime) triples.
    let mut hash: u64 = 0xcbf29ce484222325;
    for (path, (size, mtime)) in &entries {
        for byte in path
            .as_bytes()
            .iter()
            .copied()
            .chain(size.to_le_bytes())
            .chain((*mtime as u64).to_le_bytes())
        {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    Ok(format!("{hash:016x}"))
}

/// Ensure a Linux-aarch64 faculty bundle exists on the host and return its path.
///
/// Fast path: if a cached bundle for the current source fingerprint already
/// exists (and looks populated), return it without touching Lima. Otherwise
/// build it inside a throwaway Lima builder VM and populate the cache.
///
/// `faculties_src` is the host path to the `faculties` crate (the directory with
/// `Cargo.toml` + `src/bin/`). `builder_instance` is the Lima instance name used
/// for the one-off build VM.
pub fn ensure_faculties_bundle(faculties_src: &Path, builder_instance: &str) -> Result<PathBuf> {
    if !faculties_src.join("Cargo.toml").is_file() {
        bail!(
            "faculties source '{}' has no Cargo.toml (expected the faculties crate root)",
            faculties_src.display()
        );
    }
    let fingerprint = source_fingerprint(faculties_src)?;
    let bundle = cache_root()?.join(&fingerprint);
    let stamp = bundle.join(".complete");

    if stamp.is_file() {
        eprintln!(
            "[faculties] using cached bundle {} ({} binaries)",
            bundle.display(),
            SESSION_FACULTIES.len()
        );
        return Ok(bundle);
    }

    eprintln!(
        "[faculties] no cached bundle for fingerprint {fingerprint}; building in Lima VM '{builder_instance}' (this is slow, first time only)"
    );
    build_bundle_in_lima(faculties_src, &bundle, builder_instance)
        .with_context(|| format!("build faculties bundle into {}", bundle.display()))?;
    std::fs::write(&stamp, fingerprint.as_bytes()).context("write bundle completion stamp")?;
    Ok(bundle)
}

/// Build the faculty bundle inside a throwaway Lima builder VM, then copy the
/// binaries to `bundle_out` on the host.
///
/// The faculties crate has sibling **path dependencies** (`../triblespace-rs`,
/// `../mary`, `../cubecl-fork`, …), so the *parent* workspace directory is
/// mounted read-only — not the crate alone — or cargo cannot resolve the
/// dependency graph. A scratch build dir is mounted writable (guest `target/`
/// never lands back in the read-only source tree). We install rustup in-guest,
/// `cargo build --release --no-default-features` the allow-listed bins (which
/// drops `mary`/`cubecl` — the optional GPU deps — so those mounts are only
/// needed for manifest resolution, not compilation), then copy each binary out.
fn build_bundle_in_lima(
    faculties_src: &Path,
    bundle_out: &Path,
    builder_instance: &str,
) -> Result<()> {
    // Mount the workspace root (parent of the faculties crate) so the crate's
    // `../sibling` path deps resolve; build the faculties subdir within it.
    let workspace_root = faculties_src
        .parent()
        .ok_or_else(|| anyhow!("faculties source '{}' has no parent", faculties_src.display()))?;
    let facdir = faculties_src
        .file_name()
        .ok_or_else(|| anyhow!("faculties source '{}' has no dir name", faculties_src.display()))?
        .to_string_lossy()
        .into_owned();

    let scratch = std::env::temp_dir()
        .join("playground-faculties-build")
        .join(builder_instance);
    let build_dir = scratch.join("target");
    std::fs::create_dir_all(&build_dir).context("create builder scratch/target dir")?;

    let config = scratch.join("lima.yaml");
    std::fs::write(&config, builder_config(workspace_root, &build_dir))
        .context("write builder Lima config")?;

    // Best-effort clean of a stale builder instance.
    let _ = Command::new("limactl")
        .args(["delete", "--force", builder_instance])
        .status();

    let bins = SESSION_FACULTIES.join(" ");
    // One build command: install rustup if needed, then build the allow-listed
    // bins with the lean feature set. CARGO_TARGET_DIR points at the writable
    // scratch mount so the read-only source tree is never written to.
    // DEBIAN_FRONTEND=noninteractive silences the debconf/dialog warning; a
    // stray Cargo.lock write attempt against the read-only source is avoided by
    // building with the committed lock (`--locked`).
    let build_script = format!(
        r#"set -eu
export CARGO_TARGET_DIR=/build
export DEBIAN_FRONTEND=noninteractive
if [ ! -x "$HOME/.cargo/bin/cargo" ]; then
  echo "[faculties-build] installing rustup"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
. "$HOME/.cargo/env"
# triblespace-core's build script compiles a wasm formatter, so the wasm
# target must be present (same requirement as the `playground run` template).
rustup target add wasm32-unknown-unknown
sudo apt-get update
# build-essential + pkg-config for C shims; libasound2-dev because `rodio`
# (a non-optional faculties dep, used for audio device enumeration) links
# alsa-sys, which needs the ALSA headers to build on Linux.
sudo apt-get install -y --no-install-recommends build-essential pkg-config libasound2-dev
cd /src/{facdir}
BINARGS=""
for b in {bins}; do BINARGS="$BINARGS --bin $b"; done
echo "[faculties-build] cargo build --release --locked --no-default-features $BINARGS"
cargo build --release --locked --no-default-features $BINARGS
echo "[faculties-build] done"
ls -la /build/release | head -40
"#
    );

    let start = Command::new("limactl")
        .args([
            "start",
            "--tty=false",
            "--name",
            builder_instance,
            &config.to_string_lossy(),
        ])
        .status()
        .context("limactl start builder VM")?;
    if !start.success() {
        bail!("limactl start failed for builder instance '{builder_instance}'");
    }

    // Run the build; drive_child so a multi-megabyte build log can't deadlock.
    let build_result = (|| -> Result<()> {
        let mut cmd = Command::new("limactl");
        cmd.arg("shell")
            // Without an explicit workdir, `limactl shell` tries to cd into the
            // host cwd mirrored in the guest; the builder VM does not mount that
            // path, so the login shell aborts before our script runs. Anchor at
            // a directory we know exists (the read-only workspace mount).
            .arg("--workdir")
            .arg("/src")
            .arg(builder_instance)
            .arg("--")
            .arg("sh")
            .arg("-lc")
            .arg(&build_script);
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        let child = cmd.spawn().context("spawn builder cargo build")?;
        let out = drive_child(child, None, BUILD_TIMEOUT)?;
        if out.timed_out {
            bail!("faculties build timed out after {BUILD_TIMEOUT:?}");
        }
        if out.exit_code != Some(0) {
            bail!(
                "faculties build failed (exit {:?}):\n{}",
                out.exit_code,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(())
    })();

    // Copy the built binaries out of the writable scratch/target mount, which is
    // a real host directory (`build_dir`) — no `limactl copy` needed.
    let copy_result = build_result.and_then(|()| {
        let release = build_dir.join("release");
        std::fs::create_dir_all(bundle_out).context("create bundle output dir")?;
        let mut copied = 0usize;
        for name in SESSION_FACULTIES {
            let src = release.join(name);
            if !src.is_file() {
                bail!(
                    "expected built binary {} missing from {}",
                    name,
                    release.display()
                );
            }
            let dst = bundle_out.join(name);
            std::fs::copy(&src, &dst)
                .with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
            // Ensure executable bit.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&dst)?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&dst, perms)?;
            }
            copied += 1;
        }
        eprintln!("[faculties] staged {copied} binaries into {}", bundle_out.display());
        Ok(())
    });

    // Always tear the builder VM down, then surface any build/copy error.
    let _ = Command::new("limactl")
        .args(["stop", builder_instance])
        .status();
    let _ = Command::new("limactl")
        .args(["delete", "--force", builder_instance])
        .status();
    let _ = std::fs::remove_dir_all(&scratch);

    copy_result
}

/// Lima config for the one-off faculties builder VM. Mounts the workspace root
/// (which holds the faculties crate *and* its `../sibling` path deps) read-only
/// at `/src`, and a scratch target dir writable at `/build`; no pile involved.
fn builder_config(workspace_root: &Path, build_dir: &Path) -> String {
    format!(
        r#"# Throwaway Lima VM that builds the Linux-aarch64 faculty bundle.
# Written by src/sandbox/faculties.rs; safe to delete.
images:
  - location: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img"
    arch: "aarch64"
  - location: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
    arch: "x86_64"

vmType: "vz"
mountType: "virtiofs"

cpus: 4
memory: "8GiB"
disk: "30GiB"

mounts:
  - location: "{src}"
    mountPoint: "/src"
    writable: false
  - location: "{build}"
    mountPoint: "/build"
    writable: true
"#,
        src = workspace_root.display(),
        build = build_dir.display(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_sensitive() {
        let dir = std::env::temp_dir().join(format!("fac-fp-{}", std::process::id()));
        let src = dir.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(dir.join("Cargo.toml"), b"[package]\nname='x'\n").unwrap();
        std::fs::write(src.join("lib.rs"), b"// a\n").unwrap();

        let a = source_fingerprint(&dir).unwrap();
        let b = source_fingerprint(&dir).unwrap();
        assert_eq!(a, b, "fingerprint must be stable for unchanged sources");

        // A content change (size bump) must change the fingerprint.
        std::fs::write(src.join("lib.rs"), b"// a much longer line than before\n").unwrap();
        let c = source_fingerprint(&dir).unwrap();
        assert_ne!(a, c, "fingerprint must change when a source file changes");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_faculties_are_unique_and_nonempty() {
        assert!(!SESSION_FACULTIES.is_empty());
        let mut seen = std::collections::HashSet::new();
        for f in SESSION_FACULTIES {
            assert!(seen.insert(*f), "duplicate faculty in SESSION_FACULTIES: {f}");
        }
    }
}
