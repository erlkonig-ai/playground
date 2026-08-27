//! Backend-agnostic sandbox policy.
//!
//! Three of the hardest-won invariants in this crate were, by accident,
//! written down only inside `jail.rs`:
//!
//!   - the **tenant assistant identity** every sandbox exports as `PERSONA` and
//!     registers in the shared pile;
//!   - the **tri-state, error-preserving probe** that keeps "it is not there"
//!     apart from "I could not tell", so no lifecycle path ever runs a
//!     destructive cleanup on a transient failure (the 2026-07-24 blocker-#3
//!     data-loss class); and
//!   - **exact-mount verification**: a pile mount is trusted only when the whole
//!     `(source, target, fstype)` tuple matches and the target has exactly one
//!     occupant, so a redirected or shadowed mountpoint fails closed instead of
//!     silently becoming the tenant's `PILE`.
//!
//! None of that is FreeBSD. It is what a sandbox provider must do regardless of
//! which kernel isolates the sandbox, and a second backend that re-derived it
//! would re-derive the holes the repairs closed. So it lives here, once, and
//! each backend supplies only the OS-specific *spelling* — the ZFS not-found
//! phrase, the `mount(8)` line format, the `/proc/self/mountinfo` field order.
//!
//! What deliberately does NOT live here: anything whose *shape* differs per
//! backend. This module holds pure functions and small data; it drives no
//! commands and knows about no runner.

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

use super::runner::HostOutput;

// ---------------------------------------------------------------------------
// Tenant assistant identity
// ---------------------------------------------------------------------------

/// Domain separator for the deterministic tenant-assistant identity. The
/// lower 128 bits of SHA-256 become an opaque, deterministic GenId. This is
/// deliberately not called an intrinsic entity id: intrinsic identity hashes
/// canonical facts with Blake3, while this operational identity hashes one
/// agreed namespace + tenant key and reuses the provider's existing SHA-256
/// dependency.
const TENANT_ASSISTANT_ID_DOMAIN: &[u8] = b"playground/tenant-assistant/v1\0";

/// `relations::label_norm` is a ShortString, so the human-facing persona label
/// supplied to `relations add` must fit its 32-byte inline representation.
const RELATIONS_LABEL_MAX_BYTES: usize = 32;

/// The single source of truth for a tenant's assistant identity.
///
/// Both the `PERSONA` profile export and the person inserted into the shared
/// pile are rendered from this one value. Identity is scoped by the original
/// (unsanitised) tenant label, so labels that happen to map to similar sandbox
/// names cannot share an assistant.
///
/// The domain separator is part of the identity, so this must stay one
/// implementation across backends: a Linux sandbox and a FreeBSD jail
/// provisioned for the same tenant label are the same assistant, and moving a
/// tenant between backends must not mint a second person in the shared pile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantAssistantPersona {
    pub id_hex: String,
    pub label: String,
}

impl TenantAssistantPersona {
    pub fn for_tenant(tenant: &str) -> Result<Self> {
        if tenant.trim() != tenant {
            bail!(
                "invalid tenant label: leading/trailing whitespace would make its assistant \
                 persona resolve differently in the relations faculty"
            );
        }

        let label = format!("{tenant} assistant");
        if label.len() > RELATIONS_LABEL_MAX_BYTES {
            bail!(
                "tenant assistant label '{label}' is {} bytes but relations labels hold at most \
                 {RELATIONS_LABEL_MAX_BYTES}; shorten the tenant label",
                label.len()
            );
        }

        let mut hasher = Sha256::new();
        hasher.update(TENANT_ASSISTANT_ID_DOMAIN);
        hasher.update(tenant.as_bytes());
        let digest_hex = format!("{:x}", hasher.finalize());
        let id_hex = digest_hex[digest_hex.len() - 32..].to_string();

        Ok(Self { id_hex, label })
    }
}

// ---------------------------------------------------------------------------
// Tri-state existence probe
// ---------------------------------------------------------------------------

/// Tri-state, ERROR-PRESERVING result of a "does this backend resource exist?"
/// probe (a ZFS dataset, a podman container, a storage volume).
///
/// A plain `bool` collapses transport failure, permission failure, timeout, and
/// true absence all into "no", and a lifecycle op that then runs destructive
/// cleanup on a merely-transient probe failure can DESTROY a valid persistent
/// workspace (the 2026-07-24 blocker-#3 data-loss class). This enum keeps the
/// three cases apart so a caller can fail CLOSED on doubt:
///
///   - [`ResourceState::Exists`] — the probe returned success. Definitely present.
///   - [`ResourceState::Absent`] — the probe failed with the CANONICAL absence
///     signal for that tool. Only in this state is it safe to treat a tenant as
///     un-provisioned / free to create into.
///   - [`ResourceState::Unknown`] — anything else: a transport error (ssh 255),
///     a local timeout, a permission failure, a faulted pool, or any other
///     failure whose signal is NOT the canonical absence. The probe simply does
///     not know, so NO destructive action may run on this state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceState {
    Exists,
    Absent,
    Unknown,
}

/// Classify one existence probe into a [`ResourceState`], fail-closed.
///
/// `probe` is the runner's own result, so a spawn/pipe failure (the runner's
/// `Err`) is Unknown rather than being mistaken for a command that ran and said
/// no. `transport_error_exit` is the runner's reserved transport code (ssh's
/// 255); when the observed exit equals it, the probe never reached the tool and
/// the answer is Unknown regardless of what its stderr says. `absent_stderr` is
/// the ONE canonical phrase that tool emits for a genuinely missing name (ZFS:
/// "does not exist") — every other failure is Unknown by construction.
///
/// Order matters and is the fail-closed part: success first, then the two ways
/// of never having gotten a real answer (timeout, transport), and only then the
/// canonical absence. Everything that falls through is Unknown.
pub fn classify_probe(
    probe: &Result<HostOutput>,
    transport_error_exit: Option<i32>,
    absent_stderr: &str,
) -> ResourceState {
    let out = match probe {
        Ok(out) => out,
        // The command never produced a trustworthy status (spawn failed, pipe
        // error, ...). We do not know — fail closed.
        Err(_) => return ResourceState::Unknown,
    };
    if out.success() {
        return ResourceState::Exists;
    }
    // A local wall-clock kill or the transport's own error exit (ssh 255) means
    // we never got the tool's real answer — Unknown, not Absent.
    if out.timed_out || (out.exit_code.is_some() && out.exit_code == transport_error_exit) {
        return ResourceState::Unknown;
    }
    if String::from_utf8_lossy(&out.stderr).contains(absent_stderr) {
        ResourceState::Absent
    } else {
        ResourceState::Unknown
    }
}

// ---------------------------------------------------------------------------
// Exact-mount verification
// ---------------------------------------------------------------------------

/// One row of a host mount table, normalised across the formats the backends
/// read (`mount(8)` on FreeBSD, `/proc/self/mountinfo` on Linux).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountRow {
    pub source: String,
    pub target: String,
    pub fstype: String,
}

/// Every row whose TARGET is exactly `target` (whole-token, so `/pile` never
/// matches `/pile/self.pile`). More than one is ambiguous authority.
pub fn occupants<'a>(rows: &'a [MountRow], target: &str) -> Vec<&'a MountRow> {
    rows.iter().filter(|row| row.target == target).collect()
}

/// True iff the table shows the exact intended `(source, target, fstype)`.
/// All three must match: a DIFFERENT source at `target` is a redirection and a
/// different fstype is a shadowing, and neither may be accepted as our mount.
pub fn has_exact(rows: &[MountRow], source: &str, target: &str, fstype: &str) -> bool {
    rows.iter()
        .any(|row| row.source == source && row.target == target && row.fstype == fstype)
}

/// Return whether `target` carries exactly the intended mount (`true`), or is
/// unmounted (`false`). Any wrong or duplicate occupant is ambiguous authority
/// and fails closed with an error rather than a boolean.
pub fn exact_or_absent(
    rows: &[MountRow],
    source: &str,
    target: &str,
    fstype: &str,
) -> Result<bool> {
    let occupants = occupants(rows, target);
    match occupants.as_slice() {
        [] => Ok(false),
        [_] if has_exact(rows, source, target, fstype) => Ok(true),
        _ => bail!(
            "mount target {target} has {} occupant(s), not exactly one ({source}, {target}, {fstype})",
            occupants.len()
        ),
    }
}

/// Parse FreeBSD `mount(8)` output: `<source> on <target> (<fstype>, <opts>)`.
///
/// All paths this provider creates are whitespace-safe, so the literal
/// delimiters mount(8) emits are unambiguous here. Unparseable lines are
/// dropped, which is safe because every consumer asks "is my exact tuple
/// present" — a dropped line can only make a check stricter, never laxer.
pub fn parse_bsd_mount(listing: &str) -> Vec<MountRow> {
    listing
        .lines()
        .filter_map(|line| {
            let (source, rest) = line.split_once(" on ")?;
            let (target, tail) = rest.split_once(" (")?;
            let fstype = tail.split([',', ')']).next()?.trim();
            Some(MountRow {
                source: source.trim().to_string(),
                target: target.trim().to_string(),
                fstype: fstype.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_assistant_identity_is_stable_and_tenant_scoped() {
        let alice = TenantAssistantPersona::for_tenant("alice").expect("alice persona");
        let alice_again = TenantAssistantPersona::for_tenant("alice").expect("same alice persona");
        let bob = TenantAssistantPersona::for_tenant("bob").expect("bob persona");

        assert_eq!(alice, alice_again);
        assert_eq!(alice.label, "alice assistant");
        assert_eq!(alice.id_hex, "25c147ed19fde75186fef26c7217f5db");
        assert_ne!(alice.id_hex, bob.id_hex);
        assert!(TenantAssistantPersona::for_tenant(" alice").is_err());
        assert!(TenantAssistantPersona::for_tenant("abcdefghijklmnopqrstuvw").is_err());
    }

    fn out(exit: Option<i32>, stderr: &str, timed_out: bool) -> Result<HostOutput> {
        Ok(HostOutput {
            exit_code: exit,
            stderr: stderr.as_bytes().to_vec(),
            timed_out,
            ..Default::default()
        })
    }

    /// Exit 0 is Exists, the canonical phrase is Absent, and EVERYTHING else — a
    /// bare non-zero, a permission error, the transport's own 255, a local
    /// timeout, a runner `Err` — is Unknown. This ordering is the whole
    /// blocker-#3 repair; a caller may destroy only on `Absent`.
    #[test]
    fn probe_classification_keeps_absence_apart_from_failure() {
        let absent = "does not exist";
        assert_eq!(
            classify_probe(&out(Some(0), "", false), Some(255), absent),
            ResourceState::Exists
        );
        assert_eq!(
            classify_probe(
                &out(Some(1), "cannot open 'p/x': dataset does not exist", false),
                Some(255),
                absent
            ),
            ResourceState::Absent
        );
        assert_eq!(
            classify_probe(&out(Some(1), "permission denied", false), Some(255), absent),
            ResourceState::Unknown
        );
        assert_eq!(
            classify_probe(&out(Some(1), "", false), Some(255), absent),
            ResourceState::Unknown
        );
        // The transport never reached the tool: 255 is Unknown even though the
        // stderr would otherwise have read as a clean absence.
        assert_eq!(
            classify_probe(
                &out(Some(255), "ssh: dataset does not exist", false),
                Some(255),
                absent
            ),
            ResourceState::Unknown
        );
        assert_eq!(
            classify_probe(&out(None, "dataset does not exist", true), Some(255), absent),
            ResourceState::Unknown
        );
        assert_eq!(
            classify_probe(&Err(anyhow::anyhow!("spawn failed")), Some(255), absent),
            ResourceState::Unknown
        );
    }

    #[test]
    fn bsd_mount_lines_parse_to_exact_tuples() {
        let rows = parse_bsd_mount(
            "aitemp/playground/box on /jails/box (zfs, local, nfsv4acls)\n\
             devfs on /jails/box/dev (devfs)\n\
             /piles/box/self.pile on /jails/box/pile/self.pile (nullfs, local)\n",
        );
        assert!(has_exact(
            &rows,
            "/piles/box/self.pile",
            "/jails/box/pile/self.pile",
            "nullfs"
        ));
        // Same target, different source: a redirection, not our mount.
        assert!(!has_exact(
            &rows,
            "/piles/evil/self.pile",
            "/jails/box/pile/self.pile",
            "nullfs"
        ));
        // Whole-token targets: the parent dir is not the file.
        assert!(occupants(&rows, "/jails/box/pile").is_empty());
    }

    /// A target with two occupants is ambiguous authority: it must error, not
    /// return a boolean that some caller reads as "fine, it is mounted".
    #[test]
    fn duplicate_occupants_fail_closed() {
        let rows = parse_bsd_mount(
            "/srv/a on /pile/self.pile (nullfs)\n/srv/b on /pile/self.pile (nullfs)\n",
        );
        assert!(exact_or_absent(&rows, "/srv/a", "/pile/self.pile", "nullfs").is_err());

        let single = parse_bsd_mount("/srv/a on /pile/self.pile (nullfs)\n");
        assert!(exact_or_absent(&single, "/srv/a", "/pile/self.pile", "nullfs").unwrap());
        assert!(!exact_or_absent(&single, "/srv/a", "/pile/other.pile", "nullfs").unwrap());
        // Occupied by a different source: an error, never a silent `true`.
        assert!(exact_or_absent(&single, "/srv/b", "/pile/self.pile", "nullfs").is_err());
    }
}
