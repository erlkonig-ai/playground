//! OAuth 2.1 authorization for the Streamable-HTTP MCP transport.
//!
//! Browser-based MCP connectors (claude.ai, ChatGPT web) cannot be handed a
//! static bearer token out of band — they discover authorization dynamically.
//! The dance, per the MCP authorization spec:
//!
//! 1. the connector hits `/mcp` without a token, gets a `401` whose
//!    `WWW-Authenticate: Bearer resource_metadata="..."` points at
//! 2. `/.well-known/oauth-protected-resource` (RFC 9728), which names this
//!    same server as the authorization server, described by
//! 3. `/.well-known/oauth-authorization-server` (RFC 8414); the connector then
//! 4. registers itself as a public client (`POST /oauth/register`, RFC 7591),
//! 5. sends the user's browser through `GET/POST /oauth/authorize` (an invite
//!    -code form — see below), receiving an authorization code, and
//! 6. exchanges the code at `POST /oauth/token` with PKCE (RFC 7636, S256
//!    only) for an access token + rotating refresh token.
//!
//! The human gate is an **invite code**, minted with `playground token invite
//! --tenant <label>`: client registration is deliberately open (any connector
//! may register), but the authorize form demands an invite, and the invite
//! carries the tenant the resulting tokens act as. Downstream, an
//! OAuth-derived access token resolves to the very same
//! [`TokenEntry`]`{tenant, backend}` a static token does, so session scoping
//! and tenant enforcement in `mcp_http` see no difference.
//!
//! ## State
//!
//! Clients, invite codes, access tokens and refresh-token families persist in
//! one JSON file (`--oauth-state`, mode 0600, same load/save shape as the
//! token store), saved after every mutation. Authorization codes are
//! 10-minute single-use and live in memory only — a restart mid-handshake
//! just means the connector retries the flow.
//!
//! Refresh tokens rotate on every use: redeeming one marks it spent and
//! issues a successor in the same *family*. Presenting a spent token is
//! treated as theft evidence and revokes the whole family (all refresh
//! tokens and access tokens descended from the original authorization).
//!
//! Everything here is mounted by `mcp_http::router` only when `--public-url`
//! *and* `--oauth-state` are given; without them the server behaves exactly
//! as before. TLS stays out of scope (reverse-proxy assumption), which is
//! also why `--public-url` is explicit config rather than sniffed from Host
//! headers.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::mcp_http::{HttpState, TokenEntry, http_error, random_urlsafe};

/// Authorization codes expire this long after issuance (RFC 6749 recommends
/// at most 10 minutes).
const AUTH_CODE_TTL: Duration = Duration::from_secs(600);

/// Hard cap on stored client records. `POST /oauth/register` is unauthenticated
/// (a `client_id` grants nothing without an invite), so the only harm it can do
/// is fill the state file; this bounds it. Overflow answers 503 until GC or the
/// operator frees room. A few thousand distinct connectors is already generous.
const MAX_CLIENTS: usize = 5_000;

/// A registered client that never completed an authorization (never had a code
/// issued to it) is garbage after this long — abandoned/abusive registrations
/// self-drain instead of accreting. Clients that *have* authorized are kept.
const CLIENT_GC_TTL: Duration = Duration::from_secs(24 * 3600);

/// Registration token bucket: at most this many registrations may burst from
/// one source before the steady refill rate throttles it.
const REGISTER_BUCKET_CAPACITY: f64 = 20.0;
/// Steady-state registration allowance, tokens per second (≈1 every 6 s).
const REGISTER_REFILL_PER_SEC: f64 = 1.0 / 6.0;

/// Upper bound on `--oauth-access-ttl-secs`: a misconfiguration must not be able
/// to mint near-immortal access tokens (refresh rotation is the long-lived
/// path, gated by theft-detection; access tokens are the bearer credential and
/// stay short). 24h is the ceiling.
pub const MAX_ACCESS_TTL: Duration = Duration::from_secs(24 * 3600);

// ---------------------------------------------------------------------------
// Persistent store (clients, invites, tokens)
// ---------------------------------------------------------------------------

/// A dynamically registered OAuth client (RFC 7591). Public client, no
/// secret: possession of a `client_id` grants nothing by itself — the
/// authorize form's invite code is the real gate, and PKCE binds each code to
/// the browser session that started the flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEntry {
    /// Exact-match allowlist for `redirect_uri` (no wildcard, no prefix).
    pub redirect_uris: Vec<String>,
    /// Human-readable name from registration, for operator inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Unix seconds at registration.
    pub created_at: u64,
    /// Unix seconds of the most recent completed authorization (a code issued
    /// to this client). `None` = registered but never used; such clients are
    /// GC'd once older than [`CLIENT_GC_TTL`] so the store self-drains.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_at: Option<u64>,
}

/// An invite code: the operator-minted, human-carried credential that maps a
/// browser-based login onto a tenant. Single-use by default; a used
/// single-use invite is deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteEntry {
    /// Tenant the resulting tokens act as.
    pub tenant: String,
    /// `true` keeps the invite valid after use (e.g. a team invite).
    #[serde(default)]
    pub reusable: bool,
    /// Unix seconds at mint.
    pub created_at: u64,
}

/// One live OAuth access token. Resolves to the same shape as a static
/// [`TokenEntry`] plus expiry and lineage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenEntry {
    pub tenant: String,
    /// Backend this server ran when the token was minted (checked like a
    /// static token's backend on every request).
    pub backend: String,
    /// Client the token was issued to.
    pub client_id: String,
    /// Unix seconds after which the token is dead (removed lazily on use).
    pub expires_at: u64,
    /// Refresh-token family this access token descends from; family
    /// revocation removes it.
    pub family_id: String,
}

/// One refresh token, spent or current. Spent tokens are *kept* (with
/// `current: false`) precisely so their reuse can be detected and punished
/// with family revocation; family revocation deletes the whole lineage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenEntry {
    pub tenant: String,
    pub backend: String,
    pub client_id: String,
    /// All rotations of one authorization share this id.
    pub family_id: String,
    /// `true` for the newest rotation only; presenting a `false` one revokes
    /// the family.
    pub current: bool,
}

/// On-disk OAuth state: one JSON file, mode 0600, saved after every mutation.
/// Same load/save conventions as [`crate::mcp_http::TokenStore`].
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct OauthStore {
    #[serde(default)]
    pub clients: HashMap<String, ClientEntry>,
    #[serde(default)]
    pub invites: HashMap<String, InviteEntry>,
    #[serde(default)]
    pub access_tokens: HashMap<String, AccessTokenEntry>,
    #[serde(default)]
    pub refresh_tokens: HashMap<String, RefreshTokenEntry>,
}

/// Outcome of presenting a refresh token (see [`OauthStore::rotate_refresh`]).
#[derive(Debug, PartialEq, Eq)]
pub enum RotateError {
    /// Token was never issued (or its family was already revoked).
    Unknown,
    /// Token exists but was issued to a different client.
    ClientMismatch,
    /// Token was already rotated out — theft evidence; the family has now
    /// been revoked.
    ReuseRevoked,
}

impl OauthStore {
    /// Load the store from `path`. A missing file is an empty store, so
    /// `token invite` works on a fresh path without a separate init step.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parse oauth state {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(OauthStore::default()),
            Err(e) => Err(e).with_context(|| format!("read oauth state {}", path.display())),
        }
    }

    /// Persist the store to `path` (pretty JSON, mode 0600).
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
            .with_context(|| format!("write oauth state {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 600 oauth state {}", path.display()))?;
        }
        Ok(())
    }

    /// Register a public client; returns the minted `client_id`.
    pub fn register_client(
        &mut self,
        redirect_uris: Vec<String>,
        client_name: Option<String>,
        now: u64,
    ) -> String {
        let client_id = random_urlsafe(32);
        self.clients.insert(
            client_id.clone(),
            ClientEntry {
                redirect_uris,
                client_name,
                created_at: now,
                authorized_at: None,
            },
        );
        client_id
    }

    /// Drop clients that registered but never completed an authorization and
    /// are now older than [`CLIENT_GC_TTL`] — the store's self-drain, run on
    /// the registration write path so an abandoned/abusive burst evaporates
    /// on its own. Clients that have authorized (`authorized_at.is_some()`)
    /// are always kept. Returns the number removed.
    pub fn gc_stale_clients(&mut self, now: u64) -> usize {
        let cutoff = now.saturating_sub(CLIENT_GC_TTL.as_secs());
        let before = self.clients.len();
        self.clients
            .retain(|_, c| c.authorized_at.is_some() || c.created_at > cutoff);
        before - self.clients.len()
    }

    /// Mint an invite code bound to `tenant`. Single-use unless `reusable`.
    pub fn mint_invite(&mut self, tenant: &str, reusable: bool, now: u64) -> String {
        let code = random_urlsafe(32);
        self.invites.insert(
            code.clone(),
            InviteEntry {
                tenant: tenant.to_string(),
                reusable,
                created_at: now,
            },
        );
        code
    }

    /// Redeem an invite code, returning its tenant. Single-use invites are
    /// consumed (deleted); reusable ones stay.
    pub fn consume_invite(&mut self, code: &str) -> Option<String> {
        let entry = self.invites.get(code)?.clone();
        if !entry.reusable {
            self.invites.remove(code);
        }
        Some(entry.tenant)
    }

    /// Mint a fresh access + refresh token pair in a brand-new family
    /// (authorization-code redemption). Returns `(access, refresh)`.
    pub fn mint_token_pair(
        &mut self,
        tenant: &str,
        backend: &str,
        client_id: &str,
        access_ttl: Duration,
        now: u64,
    ) -> (String, String) {
        let family_id = random_urlsafe(16);
        self.mint_pair_in_family(tenant, backend, client_id, &family_id, access_ttl, now)
    }

    /// Mint an access + refresh pair inside an existing family (rotation).
    fn mint_pair_in_family(
        &mut self,
        tenant: &str,
        backend: &str,
        client_id: &str,
        family_id: &str,
        access_ttl: Duration,
        now: u64,
    ) -> (String, String) {
        let access = random_urlsafe(32);
        self.access_tokens.insert(
            access.clone(),
            AccessTokenEntry {
                tenant: tenant.to_string(),
                backend: backend.to_string(),
                client_id: client_id.to_string(),
                expires_at: now + access_ttl.as_secs(),
                family_id: family_id.to_string(),
            },
        );
        let refresh = random_urlsafe(32);
        self.refresh_tokens.insert(
            refresh.clone(),
            RefreshTokenEntry {
                tenant: tenant.to_string(),
                backend: backend.to_string(),
                client_id: client_id.to_string(),
                family_id: family_id.to_string(),
                current: true,
            },
        );
        (access, refresh)
    }

    /// Rotate a refresh token: spend it, mint a successor pair in the same
    /// family. Reuse of an already-spent token revokes the whole family
    /// before returning [`RotateError::ReuseRevoked`].
    pub fn rotate_refresh(
        &mut self,
        token: &str,
        client_id: Option<&str>,
        access_ttl: Duration,
        now: u64,
    ) -> std::result::Result<(String, String, RefreshTokenEntry), RotateError> {
        let entry = self
            .refresh_tokens
            .get(token)
            .cloned()
            .ok_or(RotateError::Unknown)?;
        // Public clients send their client_id with the grant; if they do, it
        // must be the client the token was issued to.
        if let Some(client_id) = client_id {
            if client_id != entry.client_id {
                return Err(RotateError::ClientMismatch);
            }
        }
        if !entry.current {
            // Rotated-out token presented again: someone replayed it. Burn
            // the family — attacker and victim both lose, victim re-auths.
            self.revoke_family(&entry.family_id);
            return Err(RotateError::ReuseRevoked);
        }
        self.refresh_tokens
            .get_mut(token)
            .expect("entry just read")
            .current = false;
        let (access, refresh) = self.mint_pair_in_family(
            &entry.tenant,
            &entry.backend,
            &entry.client_id,
            &entry.family_id,
            access_ttl,
            now,
        );
        Ok((access, refresh, entry))
    }

    /// Delete every access and refresh token descending from `family_id`.
    pub fn revoke_family(&mut self, family_id: &str) {
        self.access_tokens.retain(|_, e| e.family_id != family_id);
        self.refresh_tokens.retain(|_, e| e.family_id != family_id);
    }

    /// Resolve an access token to a [`TokenEntry`], enforcing expiry (expired
    /// tokens are removed — lazy reaping, no timer thread). `Err` carries the
    /// 401 message and whether the store was mutated (needs saving).
    pub fn lookup_access(
        &mut self,
        token: &str,
        now: u64,
    ) -> std::result::Result<TokenEntry, (&'static str, bool)> {
        let Some(entry) = self.access_tokens.get(token) else {
            return Err(("unknown token", false));
        };
        if entry.expires_at <= now {
            self.access_tokens.remove(token);
            return Err(("access token expired", true));
        }
        let entry = entry.clone();
        Ok(TokenEntry {
            tenant: entry.tenant,
            backend: entry.backend,
        })
    }
}

// ---------------------------------------------------------------------------
// Runtime (config + store + in-memory auth codes)
// ---------------------------------------------------------------------------

/// OAuth settings, all three required together (`--public-url`,
/// `--oauth-state`, `--oauth-access-ttl-secs`).
#[derive(Debug, Clone)]
pub struct OauthConfig {
    /// Public base URL of this server as clients reach it (scheme + host
    /// [+ port], e.g. `https://mcp.example.org`) — the RFC 8414 issuer and
    /// the base every discovery/endpoint URL is derived from.
    pub public_url: String,
    /// Path of the persistent JSON state file.
    pub state_path: PathBuf,
    /// Access-token lifetime.
    pub access_ttl: Duration,
}

/// A pending authorization code: single-use, 10-minute, bound to the client,
/// redirect URI and PKCE challenge of the authorize request plus the tenant
/// the invite granted. In-memory only (see module docs).
#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub tenant: String,
    pub scope: String,
    pub expires_at: u64,
}

/// Outcome of redeeming an authorization code.
pub enum CodeTake {
    Ok(AuthCode),
    Expired,
    Unknown,
}

/// A per-source token bucket (registration rate-limiter). `tokens` refills at
/// [`REGISTER_REFILL_PER_SEC`] up to [`REGISTER_BUCKET_CAPACITY`]; each attempt
/// costs one token. Purely in-memory (rate-limiting is best-effort throttling,
/// not a security boundary — the invite gate is the boundary).
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: u64,
}

impl TokenBucket {
    fn new(now: u64) -> Self {
        TokenBucket {
            tokens: REGISTER_BUCKET_CAPACITY,
            last_refill: now,
        }
    }

    /// Refill for elapsed time, then try to spend one token. `true` = allowed.
    fn try_take(&mut self, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.last_refill) as f64;
        self.tokens = (self.tokens + elapsed * REGISTER_REFILL_PER_SEC)
            .min(REGISTER_BUCKET_CAPACITY);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Live OAuth state hung off `HttpState` when the feature is configured.
pub struct OauthRuntime {
    /// `OauthConfig::public_url`, normalized (no trailing slash).
    pub public_url: String,
    state_path: PathBuf,
    pub access_ttl: Duration,
    pub store: Mutex<OauthStore>,
    codes: Mutex<HashMap<String, AuthCode>>,
    /// Registration rate-limiter, keyed by remote IP (or a single shared bucket
    /// under the unspecified `0.0.0.0` key when `ConnectInfo` is unavailable).
    register_buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
}

impl OauthRuntime {
    /// Load the persistent store and build the runtime. Rejects a malformed
    /// `--public-url` up front — it is interpolated into `WWW-Authenticate`
    /// header values, so it must be an absolute, header-safe URL.
    pub fn new(config: OauthConfig) -> Result<Self> {
        let parsed: Uri = config
            .public_url
            .parse()
            .with_context(|| format!("--public-url '{}' is not a valid URL", config.public_url))?;
        if parsed.scheme().is_none() || parsed.authority().is_none() {
            anyhow::bail!(
                "--public-url '{}' must be absolute (scheme + host)",
                config.public_url
            );
        }
        let store = OauthStore::load(&config.state_path)?;
        Ok(OauthRuntime {
            public_url: config.public_url.trim_end_matches('/').to_string(),
            state_path: config.state_path,
            access_ttl: config.access_ttl,
            store: Mutex::new(store),
            codes: Mutex::new(HashMap::new()),
            register_buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Consult the registration rate-limiter for `source`. `true` = allowed.
    /// A stale-bucket sweep keeps the map bounded (a bucket at full capacity
    /// has no memory worth keeping).
    fn register_allowed(&self, source: IpAddr, now: u64) -> bool {
        let mut buckets = self.register_buckets.lock().expect("buckets poisoned");
        let allowed = buckets
            .entry(source)
            .or_insert_with(|| TokenBucket::new(now))
            .try_take(now);
        buckets.retain(|_, b| {
            let elapsed = now.saturating_sub(b.last_refill) as f64;
            (b.tokens + elapsed * REGISTER_REFILL_PER_SEC) < REGISTER_BUCKET_CAPACITY
        });
        allowed
    }

    /// Apply a mutation to the persistent store under the cross-process file
    /// lock, re-reading the latest on-disk state first so a concurrent
    /// `token invite` write is never clobbered (and, symmetrically, the CLI
    /// re-reads our revocations before it writes). The in-memory `store` mirror
    /// is refreshed with the freshly-written state so the hot-path access-token
    /// lookups stay consistent. Holds the in-memory `store` mutex for the whole
    /// critical section, so server-internal callers also serialise.
    fn with_locked_store<R>(
        &self,
        mutate: impl FnOnce(&mut OauthStore) -> R,
    ) -> Result<R> {
        let mut mirror = self.store.lock().expect("oauth store poisoned");
        let (fresh, result) = mutate_state_locked(&self.state_path, mutate)?;
        *mirror = fresh;
        Ok(result)
    }

    /// Mint and remember an authorization code. Expired leftovers are purged
    /// opportunistically so the map stays bounded without a reaper.
    pub fn issue_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        tenant: &str,
        scope: &str,
        now: u64,
    ) -> String {
        let code = random_urlsafe(32);
        let mut codes = self.codes.lock().expect("codes poisoned");
        codes.retain(|_, c| c.expires_at > now);
        codes.insert(
            code.clone(),
            AuthCode {
                client_id: client_id.to_string(),
                redirect_uri: redirect_uri.to_string(),
                code_challenge: code_challenge.to_string(),
                tenant: tenant.to_string(),
                scope: scope.to_string(),
                expires_at: now + AUTH_CODE_TTL.as_secs(),
            },
        );
        code
    }

    /// Redeem an authorization code. Single-use: the code is removed on
    /// *any* redemption attempt — even one that subsequently fails PKCE —
    /// per RFC 6749 §4.1.2's replay guidance.
    pub fn take_code(&self, code: &str, now: u64) -> CodeTake {
        let mut codes = self.codes.lock().expect("codes poisoned");
        match codes.remove(code) {
            None => CodeTake::Unknown,
            Some(entry) if entry.expires_at <= now => CodeTake::Expired,
            Some(entry) => CodeTake::Ok(entry),
        }
    }

    /// Resolve a bearer access token (the `authenticate` hook). The common
    /// case is a pure read against the in-memory mirror. Reaping an expired
    /// token is a store mutation, so it goes through the cross-process file lock
    /// (re-read → reap → write) — removing a dead token can never resurrect a
    /// family, but funnelling every write through one primitive keeps the race
    /// impossible by construction rather than by case analysis.
    pub fn lookup_access(&self, token: &str) -> std::result::Result<TokenEntry, &'static str> {
        let now = unix_now();
        {
            let store = self.store.lock().expect("oauth store poisoned");
            if let Some(entry) = store.access_tokens.get(token) {
                if entry.expires_at > now {
                    let entry = entry.clone();
                    return Ok(TokenEntry {
                        tenant: entry.tenant,
                        backend: entry.backend,
                    });
                }
            } else {
                return Err("unknown token");
            }
        }
        // Fell through: the token is present but expired. Reap it under the lock.
        let outcome = self.with_locked_store(|store| store.lookup_access(token, now));
        match outcome {
            Ok(Ok(entry)) => Ok(entry), // Refreshed on another writer; still valid.
            Ok(Err((message, _))) => Err(message),
            Err(e) => {
                eprintln!("warning: failed to reap expired oauth token: {e:#}");
                Err("access token expired")
            }
        }
    }
}

/// Seconds since the Unix epoch — the store's clock (persists across
/// restarts, unlike `Instant`).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_secs()
}

// ---------------------------------------------------------------------------
// Cross-process state serialisation (advisory file lock)
// ---------------------------------------------------------------------------
//
// The server and the `token invite` CLI both read-modify-write the same state
// file. Without coordination the loser of a race writes a stale snapshot back,
// worst case *resurrecting* a token family the server just revoked on
// refresh-theft. An exclusive advisory lock (`flock`) on a sibling `.lock` file
// serialises every writer; each holds the lock across the whole re-read →
// mutate → write, so the on-disk state a writer overwrites is always the one it
// just read — never a stale copy.

/// RAII `flock(LOCK_EX)` on a lock file; released (`LOCK_UN` + close) on drop.
/// Unix-only, which is the deployment target (the state file is mode 0600 via
/// the same `#[cfg(unix)]` path). The lock file lives beside the state file and
/// is never truncated, so holding it never touches the state itself.
struct FileLock {
    file: std::fs::File,
}

impl FileLock {
    /// Acquire the exclusive lock, blocking until no other writer holds it.
    fn acquire(state_path: &Path) -> Result<Self> {
        let lock_path = lock_path_for(state_path);
        let file = std::fs::OpenOptions::new()
            .create(true)
            // Never truncate: the lock file's *existence* is the lock target;
            // its contents are irrelevant and holding it must not touch them.
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("open oauth lock file {}", lock_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // flock is advisory but honoured by every writer here; blocks until
            // the current holder drops it. EINTR is the only expected transient.
            loop {
                let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
                if rc == 0 {
                    break;
                }
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err).with_context(|| {
                    format!("flock oauth lock file {}", lock_path.display())
                });
            }
        }
        Ok(FileLock { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // Best-effort unlock; closing the fd (on drop of `file`) releases it
            // regardless, so an error here is not actionable.
            unsafe {
                let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// The sibling lock file for a state path (`<state>.lock`).
fn lock_path_for(state_path: &Path) -> PathBuf {
    let mut name = state_path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    state_path.with_file_name(name)
}

/// Run `mutate` against the *current on-disk* store under the exclusive file
/// lock, then persist the result: lock → re-read disk → mutate → write →
/// unlock. This is the one safe read-modify-write primitive; the server and the
/// CLI both funnel through it so a stale snapshot can never clobber a newer one.
/// Returns the mutated store (so callers can refresh their in-memory cache) and
/// the closure's own return value.
fn mutate_state_locked<R>(
    state_path: &Path,
    mutate: impl FnOnce(&mut OauthStore) -> R,
) -> Result<(OauthStore, R)> {
    let _lock = FileLock::acquire(state_path)?;
    let mut store = OauthStore::load(state_path)?;
    let result = mutate(&mut store);
    store.save(state_path)?;
    Ok((store, result))
}

/// Mint an invite from the `token invite` CLI under the same file lock the
/// server uses (M2): lock → re-read the server's latest state → mint → write →
/// unlock. Re-reading under the lock is what stops a stale CLI snapshot from
/// clobbering (worst case *resurrecting* a revoked family) a mutation the
/// server made between the CLI's load and write.
pub fn mint_invite_locked(
    state_path: &Path,
    tenant: &str,
    reusable: bool,
    now: u64,
) -> Result<String> {
    let (_store, code) =
        mutate_state_locked(state_path, |store| store.mint_invite(tenant, reusable, now))?;
    Ok(code)
}

/// PKCE S256 (RFC 7636): `BASE64URL(SHA256(ascii(verifier))) == challenge`.
/// The only supported method — `plain` defeats the point.
pub fn verify_pkce_s256(verifier: &str, challenge: &str) -> bool {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest) == challenge
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// The OAuth route table, merged into the main router only when OAuth is
/// configured. Handlers may therefore assume `state.oauth` is `Some`.
pub fn routes() -> Router<Arc<HttpState>> {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(authorization_server_metadata),
        )
        .route("/oauth/register", axum::routing::post(register))
        .route(
            "/oauth/authorize",
            axum::routing::get(authorize_form).post(authorize_submit),
        )
        .route("/oauth/token", axum::routing::post(token))
}

/// Shorthand: the runtime, which route mounting guarantees present.
fn oauth(state: &HttpState) -> &OauthRuntime {
    state
        .oauth
        .as_ref()
        .expect("oauth routes are mounted only when oauth is configured")
}

/// `GET /.well-known/oauth-protected-resource` (RFC 9728): tells a connector
/// that got a 401 *who* can authorize it — this same server.
async fn protected_resource_metadata(State(state): State<Arc<HttpState>>) -> Response {
    let base = &oauth(&state).public_url;
    json_ok(json!({
        "resource": base,
        "authorization_servers": [base],
    }))
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414): the
/// authorization server's capability card. `token_endpoint_auth_methods
/// _supported: ["none"]` says clients are public (no secret); S256 is the
/// only PKCE method.
async fn authorization_server_metadata(State(state): State<Arc<HttpState>>) -> Response {
    let base = &oauth(&state).public_url;
    json_ok(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }))
}

/// `POST /oauth/register` (RFC 7591): open dynamic registration of public
/// clients. Open is safe here because a `client_id` grants nothing — the
/// authorize form's invite code is the actual gate. Registration is the
/// moment redirect URIs get pinned; everything later exact-matches them.
async fn register(
    State(state): State<Arc<HttpState>>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    body: Bytes,
) -> Response {
    let oauth = oauth(&state);
    let now = unix_now();

    // Resource-bounding (registration is unauthenticated by design — a
    // client_id grants nothing without an invite — so guard the store, not the
    // access). Rate-limit per remote IP; behind a reverse proxy the peer is the
    // proxy, so the bucket is shared — still a bound, just coarser.
    if !oauth.register_allowed(peer.ip(), now) {
        return registration_rate_limited();
    }

    let request: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(e) => return registration_error(&format!("invalid JSON body: {e}")),
    };

    let Some(uris) = request.get("redirect_uris").and_then(Value::as_array) else {
        return registration_error("redirect_uris (non-empty array) is required");
    };
    let mut redirect_uris = Vec::with_capacity(uris.len());
    for uri in uris {
        let Some(uri) = uri.as_str() else {
            return registration_error("redirect_uris entries must be strings");
        };
        // Must parse as an absolute URI (scheme + host) and carry no
        // fragment — RFC 6749 §3.1.2. Codes travel in the query component.
        match uri.parse::<Uri>() {
            Ok(parsed) if parsed.scheme().is_some() && !uri.contains('#') => {
                // L4: only https (redirect carries the auth code, so it must be
                // confidential in transit), plus http loopback for local dev.
                if !redirect_scheme_allowed(&parsed) {
                    return registration_error(&format!(
                        "redirect_uri '{uri}' must use https:// (or http://127.0.0.1 / http://localhost for local dev)"
                    ));
                }
                redirect_uris.push(uri.to_string());
            }
            _ => {
                return registration_error(&format!(
                    "redirect_uri '{uri}' is not an absolute, fragment-free URI"
                ));
            }
        }
    }
    if redirect_uris.is_empty() {
        return registration_error("redirect_uris must not be empty");
    }

    // Public clients only: "none" (or unspecified) is the sole supported
    // token-endpoint auth method — there are no client secrets to check.
    if let Some(method) = request
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
    {
        if method != "none" {
            return registration_error(&format!(
                "token_endpoint_auth_method '{method}' unsupported; only 'none' (public client)"
            ));
        }
    }

    let client_name = request
        .get("client_name")
        .and_then(Value::as_str)
        .map(str::to_string);

    // GC self-drains abandoned registrations, then the hard cap bounds N (which
    // also bounds the O(N) full-file rewrite this save does). Both run inside
    // the file lock so the count we check is the count we write.
    let outcome = oauth.with_locked_store(|store| {
        store.gc_stale_clients(now);
        if store.clients.len() >= MAX_CLIENTS {
            return Err(());
        }
        Ok(store.register_client(redirect_uris.clone(), client_name.clone(), now))
    });
    let client_id = match outcome {
        Ok(Ok(client_id)) => client_id,
        Ok(Err(())) => return registration_store_full(),
        Err(e) => {
            return http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to persist client registration: {e:#}"),
            );
        }
    };

    let mut body = json!({
        "client_id": client_id,
        "client_id_issued_at": now,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    });
    if let Some(name) = client_name {
        body["client_name"] = json!(name);
    }
    (
        StatusCode::CREATED,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// L4: a redirect URI's scheme must be `https`, or `http` bound to a loopback
/// host (`127.0.0.1` / `localhost`) for local development. Everything else —
/// plain-`http` public hosts, custom app schemes — is refused: the redirect
/// carries the authorization code and must not leak it in cleartext.
fn redirect_scheme_allowed(uri: &Uri) -> bool {
    match uri.scheme_str() {
        Some("https") => true,
        Some("http") => matches!(uri.host(), Some("127.0.0.1") | Some("localhost")),
        _ => false,
    }
}

/// 429 when a source exceeds the registration rate limit (RFC 6749 §5.2 uses
/// `slow_down`/`temporarily_unavailable`; we borrow the latter's spirit).
fn registration_rate_limited() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::CONTENT_TYPE, "application/json")],
        json!({
            "error": "temporarily_unavailable",
            "error_description": "registration rate limit exceeded; retry later",
        })
        .to_string(),
    )
        .into_response()
}

/// 503 when the client store is at capacity ([`MAX_CLIENTS`]). GC drains
/// abandoned registrations over time, so this is transient, not a hard wall.
fn registration_store_full() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CONTENT_TYPE, "application/json")],
        json!({
            "error": "temporarily_unavailable",
            "error_description": "client registration store is full; retry later",
        })
        .to_string(),
    )
        .into_response()
}

/// RFC 7591 §3.2.2 error shape (400 + `invalid_client_metadata`).
fn registration_error(description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "application/json")],
        json!({
            "error": "invalid_client_metadata",
            "error_description": description,
        })
        .to_string(),
    )
        .into_response()
}

/// The parameters an authorize request must carry, shared by GET (render the
/// form) and POST (redeem it — the hidden fields round-trip them).
struct AuthorizeParams {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    state: String,
    scope: String,
}

impl AuthorizeParams {
    fn from_map(params: &HashMap<String, String>) -> Self {
        let get = |key: &str| params.get(key).cloned().unwrap_or_default();
        AuthorizeParams {
            response_type: get("response_type"),
            client_id: get("client_id"),
            redirect_uri: get("redirect_uri"),
            code_challenge: get("code_challenge"),
            code_challenge_method: get("code_challenge_method"),
            state: get("state"),
            scope: get("scope"),
        }
    }
}

/// Validate the identity half of an authorize request: known client, exactly
/// registered redirect URI. Failures here get a 400 page, never a redirect —
/// redirecting to an unvalidated URI is an open redirect (RFC 6749 §4.1.2.1).
fn validate_client_and_redirect(
    state: &HttpState,
    params: &AuthorizeParams,
) -> std::result::Result<(), Response> {
    let store = oauth(state).store.lock().expect("oauth store poisoned");
    let Some(client) = store.clients.get(&params.client_id) else {
        return Err(authorize_error_page("unknown client_id"));
    };
    if !client.redirect_uris.iter().any(|u| u == &params.redirect_uri) {
        return Err(authorize_error_page(
            "redirect_uri is not registered for this client",
        ));
    }
    Ok(())
}

/// Validate the protocol half: `response_type=code`, PKCE challenge present,
/// method S256. Failures render a 400 error PAGE, never a redirect: this runs
/// *before* an invite is consumed, and redirecting to a client-supplied URI at
/// that point is the open-redirect hole (an attacker registers evil.com, then
/// hands a victim an authorize URL with a bad grant param to bounce them off
/// this trusted origin). Only a request that has cleared the invite gate has
/// earned a redirect — and by then the only remaining outcome is success.
fn validate_grant_shape(params: &AuthorizeParams) -> std::result::Result<(), Response> {
    if params.response_type != "code" {
        return Err(authorize_error_page("only response_type=code is supported"));
    }
    if params.code_challenge.is_empty() {
        return Err(authorize_error_page("PKCE code_challenge is required"));
    }
    if params.code_challenge_method != "S256" {
        return Err(authorize_error_page(
            "only code_challenge_method=S256 is supported",
        ));
    }
    Ok(())
}

/// `GET /oauth/authorize`: serve the invite-code form. The request is
/// validated up front (same checks as the POST) so a user never types an
/// invite into a doomed form; the POST re-validates from scratch anyway
/// because hidden form fields are attacker-editable.
async fn authorize_form(State(state): State<Arc<HttpState>>, uri: Uri) -> Response {
    let params = AuthorizeParams::from_map(&parse_form(uri.query().unwrap_or("")));
    if let Err(response) = validate_client_and_redirect(&state, &params) {
        return response;
    }
    if let Err(response) = validate_grant_shape(&params) {
        return response;
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        authorize_page(&params),
    )
        .into_response()
}

/// `POST /oauth/authorize`: redeem the invite code, mint an authorization
/// code bound to {client, redirect URI, PKCE challenge, tenant}, and bounce
/// the browser back to the client with `code` (+ `state` passthrough).
async fn authorize_submit(State(state): State<Arc<HttpState>>, body: Bytes) -> Response {
    let oauth = oauth(&state);
    let Ok(body) = std::str::from_utf8(&body) else {
        return authorize_error_page("form body is not UTF-8");
    };
    let form = parse_form(body);
    let params = AuthorizeParams::from_map(&form);

    if let Err(response) = validate_client_and_redirect(&state, &params) {
        return response;
    }
    if let Err(response) = validate_grant_shape(&params) {
        return response;
    }

    // The human gate: a valid invite code names the tenant. Consumption, the
    // client's `authorized_at` stamp (so GC keeps it — it has now completed an
    // authorization) and the write all happen atomically under the file lock.
    // An invalid invite is a *pre-redirect* failure → 400 page, never a bounce
    // off this origin (the open-redirect defence: the redirect_uri is only
    // trusted as a redirect target once a real invite has been presented).
    let invite_code = form.get("invite_code").map(String::as_str).unwrap_or("");
    let now = unix_now();
    let consumed = oauth.with_locked_store(|store| {
        let tenant = store.consume_invite(invite_code)?;
        if let Some(client) = store.clients.get_mut(&params.client_id) {
            client.authorized_at = Some(now);
        }
        Some(tenant)
    });
    let tenant = match consumed {
        Ok(Some(tenant)) => tenant,
        Ok(None) => return authorize_error_page("invalid invite code"),
        Err(e) => {
            return http_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to persist invite consumption: {e:#}"),
            );
        }
    };

    let code = oauth.issue_code(
        &params.client_id,
        &params.redirect_uri,
        &params.code_challenge,
        &tenant,
        &params.scope,
        now,
    );
    let mut query = vec![("code", code.as_str())];
    if !params.state.is_empty() {
        query.push(("state", params.state.as_str()));
    }
    redirect(&append_query(&params.redirect_uri, &query))
}

/// `POST /oauth/token`: the code-for-tokens (and refresh-rotation) exchange.
/// Form-encoded per RFC 6749; errors use the §5.2 JSON shape. Every response
/// carries `Cache-Control: no-store` (§5.1).
async fn token(State(state): State<Arc<HttpState>>, body: Bytes) -> Response {
    let oauth = oauth(&state);
    let Ok(body) = std::str::from_utf8(&body) else {
        return token_error("invalid_request", "form body is not UTF-8");
    };
    let form = parse_form(body);
    let get = |key: &str| form.get(key).map(String::as_str).unwrap_or("");
    let now = unix_now();

    let (access, refresh, scope) = match get("grant_type") {
        // --- authorization_code + PKCE --------------------------------
        "authorization_code" => {
            // Single-use: the code is consumed by this lookup no matter how
            // the rest of the checks go.
            let code = match oauth.take_code(get("code"), now) {
                CodeTake::Ok(code) => code,
                CodeTake::Expired => {
                    return token_error("invalid_grant", "authorization code expired");
                }
                CodeTake::Unknown => {
                    return token_error("invalid_grant", "unknown or already-used code");
                }
            };
            // The code is bound to the client and redirect URI it was minted
            // for (RFC 6749 §4.1.3)...
            if get("client_id") != code.client_id {
                return token_error("invalid_grant", "client_id does not match code");
            }
            if get("redirect_uri") != code.redirect_uri {
                return token_error("invalid_grant", "redirect_uri does not match code");
            }
            // ...and to the browser session that started the flow, via PKCE.
            let verifier = get("code_verifier");
            if !(43..=128).contains(&verifier.len()) {
                return token_error("invalid_grant", "code_verifier must be 43-128 chars");
            }
            if !verify_pkce_s256(verifier, &code.code_challenge) {
                return token_error("invalid_grant", "PKCE verification failed");
            }

            // Mint under the file lock (re-read → mint → write) so a concurrent
            // `token invite` write can't roll this token pair back.
            let minted = oauth.with_locked_store(|store| {
                store.mint_token_pair(
                    &code.tenant,
                    &state.config.backend_name,
                    &code.client_id,
                    oauth.access_ttl,
                    now,
                )
            });
            let (access, refresh) = match minted {
                Ok(pair) => pair,
                Err(e) => {
                    return http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("failed to persist tokens: {e:#}"),
                    );
                }
            };
            (access, refresh, code.scope)
        }
        // --- refresh_token rotation -----------------------------------
        "refresh_token" => {
            let client_id = form.get("client_id").map(String::as_str);
            // The rotation itself (including the family-revoke on reuse) is a
            // store mutation, so it runs inside the file lock: re-read the
            // latest on-disk state, rotate, write. This is exactly the path M2
            // guards — a stale CLI write must never resurrect a family revoked
            // here.
            let rotated = oauth.with_locked_store(|store| {
                store.rotate_refresh(get("refresh_token"), client_id, oauth.access_ttl, now)
            });
            let rotation = match rotated {
                Ok(rotation) => rotation,
                Err(e) => {
                    return http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("failed to persist tokens: {e:#}"),
                    );
                }
            };
            match rotation {
                // The rotated grant keeps its tenant/backend (copied from the
                // spent entry into the minted ones); scope was recorded at
                // authorize time and is not re-negotiated on refresh.
                Ok((access, refresh, _spent)) => (access, refresh, String::new()),
                Err(RotateError::ReuseRevoked) => {
                    // The family-revoke was already persisted inside the lock.
                    return token_error(
                        "invalid_grant",
                        "refresh token reuse detected; token family revoked",
                    );
                }
                Err(RotateError::ClientMismatch) => {
                    return token_error("invalid_grant", "refresh token belongs to another client");
                }
                Err(RotateError::Unknown) => {
                    return token_error("invalid_grant", "unknown refresh token");
                }
            }
        }
        other => {
            return token_error(
                "unsupported_grant_type",
                &format!("grant_type '{other}' unsupported (authorization_code, refresh_token)"),
            );
        }
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": oauth.access_ttl.as_secs(),
            "refresh_token": refresh,
            "scope": scope,
        })
        .to_string(),
    )
        .into_response()
}

/// RFC 6749 §5.2 token-endpoint error: 400 + JSON error object, no-store.
fn token_error(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        json!({ "error": error, "error_description": description }).to_string(),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// HTML + redirect helpers
// ---------------------------------------------------------------------------

/// The invite-code form: fully self-contained (inline CSS, no external
/// assets), request parameters round-tripped as hidden fields. Everything
/// interpolated is HTML-escaped — `state` in particular is attacker-chosen.
fn authorize_page(params: &AuthorizeParams) -> String {
    let hidden = [
        ("response_type", &params.response_type),
        ("client_id", &params.client_id),
        ("redirect_uri", &params.redirect_uri),
        ("code_challenge", &params.code_challenge),
        ("code_challenge_method", &params.code_challenge_method),
        ("state", &params.state),
        ("scope", &params.scope),
    ]
    .iter()
    .map(|(name, value)| {
        format!(
            "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
            html_escape(value)
        )
    })
    .collect::<String>();
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>playground &mdash; authorize</title>\n\
         <style>\n\
         body {{ font: 16px/1.5 system-ui, sans-serif; max-width: 26rem; margin: 4rem auto; padding: 0 1rem; }}\n\
         label {{ display: block; margin-bottom: .5rem; }}\n\
         input[type=text] {{ width: 100%; padding: .5rem; font: inherit; box-sizing: border-box; }}\n\
         button {{ margin-top: 1rem; padding: .5rem 1.5rem; font: inherit; }}\n\
         p.hint {{ color: #555; font-size: .875rem; }}\n\
         </style>\n</head>\n<body>\n\
         <h1>Authorize access</h1>\n\
         <p>A client wants to connect to this playground server.</p>\n\
         <form method=\"post\" action=\"/oauth/authorize\">\n{hidden}\n\
         <label for=\"invite_code\">Invite code</label>\n\
         <input type=\"text\" id=\"invite_code\" name=\"invite_code\" autofocus \
         autocomplete=\"off\" spellcheck=\"false\">\n\
         <p class=\"hint\">Ask the operator for an invite code (<code>playground token invite</code>).</p>\n\
         <button type=\"submit\">Authorize</button>\n\
         </form>\n</body>\n</html>\n",
    )
}

/// 400 error page for failures where redirecting would be unsafe (unknown
/// client, unregistered redirect URI, malformed body).
fn authorize_error_page(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>playground &mdash; error</title></head>\n\
             <body style=\"font: 16px/1.5 system-ui, sans-serif; max-width: 26rem; margin: 4rem auto;\">\n\
             <h1>Authorization error</h1>\n<p>{}</p>\n</body></html>\n",
            html_escape(message)
        ),
    )
        .into_response()
}

/// 302 Found to `location`.
fn redirect(location: &str) -> Response {
    match location.parse::<header::HeaderValue>() {
        Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
        // Registered URIs are parse-checked, so this is unreachable in
        // practice; fail closed rather than panic.
        Err(_) => authorize_error_page("redirect target is not a valid header value"),
    }
}

/// Append URL-encoded query parameters to a URI that may already carry a
/// query component.
fn append_query(uri: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::from(uri);
    let mut sep = if uri.contains('?') { '&' } else { '?' };
    for (key, value) in params {
        out.push(sep);
        out.push_str(&url_encode(key));
        out.push('=');
        out.push_str(&url_encode(value));
        sep = '&';
    }
    out
}

// ---------------------------------------------------------------------------
// Tiny codecs (kept dependency-free: sha2 is this module's only new crate)
// ---------------------------------------------------------------------------

/// Parse an `application/x-www-form-urlencoded` body or query string.
/// Undecodable pairs are dropped rather than failing the whole request.
fn parse_form(body: &str) -> HashMap<String, String> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Some((form_decode(key)?, form_decode(value)?))
        })
        .collect()
}

/// Decode one form-encoded token (`+` → space, `%XX` → byte).
fn form_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hi = (*bytes.get(i + 1)? as char).to_digit(16)?;
                let lo = (*bytes.get(i + 2)? as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Percent-encode a query-component value (RFC 3986 unreserved set kept).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Escape a string for HTML text/attribute interpolation.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// 200 + JSON body.
fn json_ok(body: Value) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_http::tests::{post, rpc, spawn_server, test_state_with_oauth};

    /// Fresh scratch dir for a test's state file.
    fn scratch_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "playground_oauth_{label}_{}_{:x}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // -- PKCE ---------------------------------------------------------------

    /// RFC 7636 appendix B's official verifier/challenge pair, plus rejection
    /// of a wrong verifier and of `plain`-style (identity) matching.
    #[test]
    fn pkce_s256_rfc7636_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce_s256(verifier, challenge));
        assert!(!verify_pkce_s256("wrong-verifier-wrong-verifier-wrong-verifi", challenge));
        // A `plain` client sending challenge == verifier must not pass S256.
        assert!(!verify_pkce_s256(verifier, verifier));
    }

    // -- Authorization codes ------------------------------------------------

    /// Codes redeem exactly once (even the failed take consumes) and expire.
    #[test]
    fn auth_codes_are_single_use_and_expire() {
        let dir = scratch_dir("codes");
        let runtime = OauthRuntime::new(OauthConfig {
            public_url: "https://mcp.example.test".to_string(),
            state_path: dir.join("oauth.json"),
            access_ttl: Duration::from_secs(3600),
        })
        .unwrap();

        // Single-use: first take wins, second take finds nothing.
        let code = runtime.issue_code("client-1", "https://a/cb", "chal", "alice", "", 1_000);
        assert!(matches!(runtime.take_code(&code, 1_001), CodeTake::Ok(c) if c.tenant == "alice"));
        assert!(matches!(runtime.take_code(&code, 1_001), CodeTake::Unknown));

        // Expiry: a code is dead AUTH_CODE_TTL after issuance...
        let code = runtime.issue_code("client-1", "https://a/cb", "chal", "alice", "", 1_000);
        let expired_at = 1_000 + AUTH_CODE_TTL.as_secs();
        assert!(matches!(runtime.take_code(&code, expired_at), CodeTake::Expired));
        // ...and the expired take also consumed it.
        assert!(matches!(runtime.take_code(&code, 1_001), CodeTake::Unknown));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Refresh rotation ---------------------------------------------------

    /// Rotation spends the old token; replaying a spent token revokes every
    /// access + refresh token in the family.
    #[test]
    fn refresh_rotation_and_reuse_revokes_family() {
        let ttl = Duration::from_secs(3600);
        let mut store = OauthStore::default();
        let (access1, refresh1) = store.mint_token_pair("alice", "mock", "client-1", ttl, 1_000);

        // Normal rotation: new pair in the same family, old refresh spent.
        let (access2, refresh2, spent) = store
            .rotate_refresh(&refresh1, Some("client-1"), ttl, 2_000)
            .expect("first rotation");
        assert_eq!(spent.tenant, "alice");
        assert!(!store.refresh_tokens[&refresh1].current);
        assert!(store.refresh_tokens[&refresh2].current);
        assert_eq!(
            store.access_tokens[&access1].family_id,
            store.access_tokens[&access2].family_id
        );

        // Wrong client on a valid token: rejected without side effects.
        assert_eq!(
            store.rotate_refresh(&refresh2, Some("client-2"), ttl, 2_500).err(),
            Some(RotateError::ClientMismatch)
        );

        // Replay of the spent refresh1: the whole family burns.
        assert_eq!(
            store.rotate_refresh(&refresh1, Some("client-1"), ttl, 3_000).err(),
            Some(RotateError::ReuseRevoked)
        );
        assert!(store.access_tokens.is_empty(), "family access tokens revoked");
        assert!(store.refresh_tokens.is_empty(), "family refresh tokens revoked");

        // The current-at-revocation refresh2 is now unknown.
        assert_eq!(
            store.rotate_refresh(&refresh2, Some("client-1"), ttl, 3_100).err(),
            Some(RotateError::Unknown)
        );
    }

    // -- Access-token lookup ------------------------------------------------

    /// Expired access tokens 401 and are reaped by the lookup itself.
    #[test]
    fn access_token_lookup_enforces_expiry() {
        let ttl = Duration::from_secs(100);
        let mut store = OauthStore::default();
        let (access, _refresh) = store.mint_token_pair("alice", "mock", "client-1", ttl, 1_000);

        let entry = store.lookup_access(&access, 1_050).expect("still valid");
        assert_eq!((entry.tenant.as_str(), entry.backend.as_str()), ("alice", "mock"));

        assert_eq!(
            store.lookup_access(&access, 1_100).err(),
            Some(("access token expired", true))
        );
        // The expired token was removed: a retry is now just unknown.
        assert_eq!(store.lookup_access(&access, 1_100).err(), Some(("unknown token", false)));
        assert_eq!(store.lookup_access("never-issued", 0).err(), Some(("unknown token", false)));
    }

    // -- Invites ------------------------------------------------------------

    /// Single-use invites vanish on redemption; reusable ones persist.
    #[test]
    fn invite_consumption_semantics() {
        let mut store = OauthStore::default();
        let single = store.mint_invite("alice", false, 1_000);
        let multi = store.mint_invite("team", true, 1_000);

        assert_eq!(store.consume_invite(&single).as_deref(), Some("alice"));
        assert_eq!(store.consume_invite(&single), None, "single-use is gone");

        assert_eq!(store.consume_invite(&multi).as_deref(), Some("team"));
        assert_eq!(store.consume_invite(&multi).as_deref(), Some("team"));

        assert_eq!(store.consume_invite("never-minted"), None);
    }

    // -- Persistence --------------------------------------------------------

    /// The whole store (clients, invites, tokens, families) round-trips
    /// through its JSON file, which is written mode 0600.
    #[test]
    fn state_file_round_trip() {
        let dir = scratch_dir("roundtrip");
        let path = dir.join("oauth.json");

        // A fresh path loads as an empty store.
        let mut store = OauthStore::load(&path).expect("load fresh");
        assert!(store.clients.is_empty());

        let client_id = store.register_client(
            vec!["https://claude.ai/api/mcp/auth_callback".to_string()],
            Some("Claude".to_string()),
            1_000,
        );
        let invite = store.mint_invite("alice", false, 1_001);
        let (access, refresh) =
            store.mint_token_pair("alice", "mock", &client_id, Duration::from_secs(60), 1_002);
        store.save(&path).expect("save");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "state file must be 0600");
        }

        let reloaded = OauthStore::load(&path).expect("reload");
        let client = reloaded.clients.get(&client_id).expect("client persisted");
        assert_eq!(client.redirect_uris, ["https://claude.ai/api/mcp/auth_callback"]);
        assert_eq!(client.client_name.as_deref(), Some("Claude"));
        assert_eq!(reloaded.invites.get(&invite).map(|i| i.tenant.as_str()), Some("alice"));
        let access_entry = reloaded.access_tokens.get(&access).expect("access persisted");
        assert_eq!(access_entry.expires_at, 1_062);
        let refresh_entry = reloaded.refresh_tokens.get(&refresh).expect("refresh persisted");
        assert!(refresh_entry.current);
        assert_eq!(refresh_entry.family_id, access_entry.family_id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Codecs -------------------------------------------------------------

    #[test]
    fn form_codec_round_trip() {
        assert_eq!(form_decode("a+b%2Bc%3D%26"), Some("a b+c=&".to_string()));
        assert_eq!(form_decode("%zz"), None, "bad hex rejected");
        assert_eq!(url_encode("a b+c=&/?"), "a%20b%2Bc%3D%26%2F%3F");

        let form = parse_form("grant_type=authorization_code&code=abc%2F1&empty=&flag");
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "abc/1");
        assert_eq!(form["empty"], "");
        assert_eq!(form["flag"], "");

        assert_eq!(
            append_query("https://a/cb?x=1", &[("code", "c d"), ("state", "s&s")]),
            "https://a/cb?x=1&code=c%20d&state=s%26s"
        );
    }

    // -- Integration: the whole browser-connector flow ----------------------

    /// ureq agent that does NOT follow redirects (we assert on Location).
    fn no_redirect_agent() -> ureq::Agent {
        ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .build(),
        )
    }

    /// Read a redirect's Location and parse its query into a map.
    fn location_query(response: &ureq::http::Response<ureq::Body>) -> (String, HashMap<String, String>) {
        let location = response
            .headers()
            .get("location")
            .expect("Location header")
            .to_str()
            .unwrap()
            .to_string();
        let (base, query) = location.split_once('?').expect("query in redirect");
        (base.to_string(), parse_form(query))
    }

    fn read_json(response: &mut ureq::http::Response<ureq::Body>) -> Value {
        let text = response.body_mut().read_to_string().expect("read body");
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    }

    /// Discovery → register → authorize (form + invite) → PKCE token exchange
    /// → authenticated MCP handshake, plus the negative space: code reuse,
    /// wrong verifier, invite reuse, expired token, refresh-replay revocation,
    /// and static tokens running untouched next to it all.
    #[test]
    fn oauth_full_flow_end_to_end() {
        let dir = scratch_dir("flow");
        let state_path = dir.join("oauth.json");
        let issuer = "https://mcp.example.test";
        let state = test_state_with_oauth(issuer, &state_path, Duration::from_secs(3600));
        let addr = spawn_server(state.clone());
        let agent = no_redirect_agent();
        let redirect_uri = "https://client.example.test/callback";

        // --- 401 challenge advertises the discovery document.
        let bare = post(&agent, addr, None, None, None, &rpc(1, "initialize", json!({})));
        assert_eq!(bare.status, 401);
        let mut challenge = agent
            .post(format!("http://{addr}/mcp"))
            .send_json(&rpc(1, "initialize", json!({})))
            .expect("bare request");
        let www = challenge
            .headers()
            .get("www-authenticate")
            .expect("WWW-Authenticate on 401")
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(
            www,
            format!("Bearer resource_metadata=\"{issuer}/.well-known/oauth-protected-resource\"")
        );
        let _ = challenge.body_mut().read_to_string();

        // --- Discovery documents.
        let mut resource = agent
            .get(format!("http://{addr}/.well-known/oauth-protected-resource"))
            .call()
            .expect("resource metadata");
        let resource = read_json(&mut resource);
        assert_eq!(resource["resource"], issuer);
        assert_eq!(resource["authorization_servers"], json!([issuer]));

        let mut auth_server = agent
            .get(format!("http://{addr}/.well-known/oauth-authorization-server"))
            .call()
            .expect("authorization-server metadata");
        let auth_server = read_json(&mut auth_server);
        assert_eq!(auth_server["issuer"], issuer);
        assert_eq!(auth_server["authorization_endpoint"], format!("{issuer}/oauth/authorize"));
        assert_eq!(auth_server["token_endpoint"], format!("{issuer}/oauth/token"));
        assert_eq!(auth_server["registration_endpoint"], format!("{issuer}/oauth/register"));
        assert_eq!(auth_server["code_challenge_methods_supported"], json!(["S256"]));
        assert_eq!(auth_server["token_endpoint_auth_methods_supported"], json!(["none"]));

        // --- Dynamic client registration.
        let mut registered = agent
            .post(format!("http://{addr}/oauth/register"))
            .send_json(json!({
                "redirect_uris": [redirect_uri],
                "client_name": "Test Connector",
                "token_endpoint_auth_method": "none",
            }))
            .expect("register");
        assert_eq!(registered.status().as_u16(), 201);
        let registered = read_json(&mut registered);
        let client_id = registered["client_id"].as_str().expect("client_id").to_string();
        assert_eq!(registered["redirect_uris"], json!([redirect_uri]));
        // Registration persisted to the state file on disk.
        assert!(
            OauthStore::load(&state_path).unwrap().clients.contains_key(&client_id),
            "client persisted"
        );

        // --- PKCE pair for the flow.
        let verifier = random_urlsafe(32); // 43 chars, valid verifier charset
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let authorize_query = |challenge: &str| {
            format!(
                "response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=xyz-123&scope=mcp",
                url_encode(&client_id),
                url_encode(redirect_uri),
                url_encode(challenge),
            )
        };

        // --- GET authorize: the invite form, self-contained HTML.
        let mut form_page = agent
            .get(format!("http://{addr}/oauth/authorize?{}", authorize_query(&challenge)))
            .call()
            .expect("authorize form");
        assert_eq!(form_page.status().as_u16(), 200);
        let html = form_page.body_mut().read_to_string().unwrap();
        assert!(html.contains("name=\"invite_code\""), "invite field present");
        assert!(html.contains(&format!("value=\"{challenge}\"")), "challenge round-trips");
        assert!(!html.contains("http-equiv"), "no external/refresh tricks");

        // Unknown client_id gets a 400 page, not a redirect (open-redirect defence).
        let mut bad_client = agent
            .get(format!(
                "http://{addr}/oauth/authorize?response_type=code&client_id=nope&redirect_uri={}&code_challenge=x&code_challenge_method=S256",
                url_encode(redirect_uri)
            ))
            .call()
            .expect("bad client");
        assert_eq!(bad_client.status().as_u16(), 400);
        let _ = bad_client.body_mut().read_to_string();

        // A plain (non-S256) challenge method is a pre-invite failure: a 400
        // PAGE, never a redirect (open-redirect defence — nothing bounces off
        // this origin before an invite is presented).
        let mut plain = agent
            .post(format!("http://{addr}/oauth/authorize"))
            .send_form([
                ("response_type", "code"),
                ("client_id", client_id.as_str()),
                ("redirect_uri", redirect_uri),
                ("code_challenge", verifier.as_str()),
                ("code_challenge_method", "plain"),
                ("state", "xyz-123"),
                ("invite_code", "irrelevant"),
            ])
            .expect("plain pkce");
        assert_eq!(plain.status().as_u16(), 400, "pre-invite failure is a page, not a redirect");
        assert!(plain.headers().get("location").is_none(), "no Location off-origin");
        let _ = plain.body_mut().read_to_string();

        // --- POST authorize with a minted invite → code redirect.
        // Invites are minted through the persistent (file-locked) path, the way
        // the CLI does — the server reads the on-disk store when consuming.
        let oauth = state.oauth.as_ref().expect("oauth configured");
        let invite = oauth
            .with_locked_store(|store| store.mint_invite("alice", false, unix_now()))
            .expect("mint invite");
        let submit = |invite: &str, challenge: &str| {
            agent
                .post(format!("http://{addr}/oauth/authorize"))
                .send_form([
                    ("response_type", "code"),
                    ("client_id", client_id.as_str()),
                    ("redirect_uri", redirect_uri),
                    ("code_challenge", challenge),
                    ("code_challenge_method", "S256"),
                    ("state", "xyz-123"),
                    ("scope", "mcp"),
                    ("invite_code", invite),
                ])
                .expect("authorize submit")
        };
        let mut granted = submit(&invite, &challenge);
        assert_eq!(granted.status().as_u16(), 302);
        let (base, query) = location_query(&granted);
        assert_eq!(base, redirect_uri);
        assert_eq!(query["state"], "xyz-123", "state passes through");
        let code = query["code"].clone();
        let _ = granted.body_mut().read_to_string();

        // A wrong invite is a pre-redirect failure → 400 page, not a bounce
        // off this origin (the invite gate is what earns a redirect).
        let mut denied = submit("not-an-invite", &challenge);
        assert_eq!(denied.status().as_u16(), 400);
        assert!(denied.headers().get("location").is_none(), "bad invite doesn't redirect");
        let _ = denied.body_mut().read_to_string();

        // The single-use invite is spent: replaying it is a 400 page too.
        let mut reused_invite = submit(&invite, &challenge);
        assert_eq!(reused_invite.status().as_u16(), 400, "invite is single-use");
        let _ = reused_invite.body_mut().read_to_string();

        // --- Token exchange with PKCE.
        let exchange = |code: &str, verifier: &str| {
            agent
                .post(format!("http://{addr}/oauth/token"))
                .send_form([
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", client_id.as_str()),
                    ("redirect_uri", redirect_uri),
                    ("code_verifier", verifier),
                ])
                .expect("token exchange")
        };
        let mut tokens = exchange(&code, &verifier);
        assert_eq!(tokens.status().as_u16(), 200);
        let tokens = read_json(&mut tokens);
        assert_eq!(tokens["token_type"], "Bearer");
        assert_eq!(tokens["expires_in"], 3600);
        assert_eq!(tokens["scope"], "mcp");
        let access = tokens["access_token"].as_str().unwrap().to_string();
        let refresh = tokens["refresh_token"].as_str().unwrap().to_string();

        // Codes are single-use: replaying the exchange fails.
        let mut replayed = exchange(&code, &verifier);
        assert_eq!(replayed.status().as_u16(), 400);
        assert_eq!(read_json(&mut replayed)["error"], "invalid_grant");

        // --- The access token drives a real MCP handshake, tenant-scoped.
        let init = post(&agent, addr, Some(&access), None, None, &rpc(1, "initialize", json!({ "protocolVersion": "2025-06-18" })));
        assert_eq!(init.status, 200, "init body: {}", init.body);
        let session = init.session.expect("session issued");
        let opened = post(
            &agent,
            addr,
            Some(&access),
            Some(&session),
            None,
            &rpc(2, "tools/call", json!({ "name": "open_session", "arguments": { "pile_host_path": "/tmp/alice/self.pile" } })),
        );
        assert_eq!(opened.status, 200);
        // The invite's tenant flowed through: the sandbox session is alice's.
        assert_eq!(opened.body["result"]["content"][0]["text"], "mock-alice");

        // Static tokens keep working, byte-for-byte, next to OAuth.
        let static_init = post(&agent, addr, Some("tok-alice"), None, None, &rpc(3, "initialize", json!({})));
        assert_eq!(static_init.status, 200);

        // --- Wrong verifier burns its (fresh) code and yields invalid_grant.
        let invite2 = oauth
            .with_locked_store(|store| store.mint_invite("bob", false, unix_now()))
            .expect("mint invite2");
        let mut granted2 = submit(&invite2, &challenge);
        let (_, query) = location_query(&granted2);
        let code2 = query["code"].clone();
        let _ = granted2.body_mut().read_to_string();
        let wrong_verifier = random_urlsafe(32);
        let mut failed = exchange(&code2, &wrong_verifier);
        assert_eq!(failed.status().as_u16(), 400);
        assert_eq!(read_json(&mut failed)["error"], "invalid_grant");
        // Even the correct verifier can't resurrect the consumed code.
        let mut burned = exchange(&code2, &verifier);
        assert_eq!(burned.status().as_u16(), 400);
        assert_eq!(read_json(&mut burned)["error"], "invalid_grant");

        // --- Expired access tokens 401 with the discovery challenge.
        // Minted at now=0 (expired an hour past the epoch), through the locked
        // path so it survives the mirror-refresh that every server write does.
        let stale = oauth
            .with_locked_store(|store| {
                store
                    .mint_token_pair("alice", "mock", &client_id, Duration::from_secs(3600), 0)
                    .0
            })
            .expect("mint stale token");
        let expired = post(&agent, addr, Some(&stale), None, None, &rpc(4, "initialize", json!({})));
        assert_eq!(expired.status, 401);
        let mut expired_raw = agent
            .post(format!("http://{addr}/mcp"))
            .header("Authorization", format!("Bearer {stale}"))
            .send_json(&rpc(4, "initialize", json!({})))
            .expect("expired request");
        assert!(
            expired_raw
                .headers()
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("resource_metadata"),
            "expired 401 still advertises discovery"
        );
        let _ = expired_raw.body_mut().read_to_string();

        // --- Refresh rotation, then replay → family revocation.
        let rotate = |refresh: &str| {
            agent
                .post(format!("http://{addr}/oauth/token"))
                .send_form([
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh),
                    ("client_id", client_id.as_str()),
                ])
                .expect("refresh")
        };
        let mut rotated = rotate(&refresh);
        assert_eq!(rotated.status().as_u16(), 200);
        let rotated = read_json(&mut rotated);
        let access2 = rotated["access_token"].as_str().unwrap().to_string();
        let refresh2 = rotated["refresh_token"].as_str().unwrap().to_string();
        assert_ne!(refresh2, refresh, "refresh token rotates");

        // The rotated-in access token works...
        let init2 = post(&agent, addr, Some(&access2), None, None, &rpc(5, "initialize", json!({})));
        assert_eq!(init2.status, 200);

        // ...until the spent refresh token is replayed: family revoked.
        let mut replay = rotate(&refresh);
        assert_eq!(replay.status().as_u16(), 400);
        assert_eq!(read_json(&mut replay)["error"], "invalid_grant");
        let revoked_new = post(&agent, addr, Some(&access2), None, None, &rpc(6, "initialize", json!({})));
        assert_eq!(revoked_new.status, 401, "family revocation kills the newest access token");
        let revoked_old = post(&agent, addr, Some(&access), None, None, &rpc(7, "initialize", json!({})));
        assert_eq!(revoked_old.status, 401, "and the original one");
        let mut dead_refresh = rotate(&refresh2);
        assert_eq!(dead_refresh.status().as_u16(), 400, "successor refresh died with the family");
        let _ = dead_refresh.body_mut().read_to_string();

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unsupported grant types and malformed exchanges are 400s in the RFC
    /// 6749 §5.2 shape (spawned server, no prior flow needed).
    #[test]
    fn token_endpoint_rejects_unsupported_grants() {
        let dir = scratch_dir("grants");
        let state = test_state_with_oauth(
            "https://mcp.example.test",
            &dir.join("oauth.json"),
            Duration::from_secs(3600),
        );
        let addr = spawn_server(state);
        let agent = no_redirect_agent();

        let mut bad_grant = agent
            .post(format!("http://{addr}/oauth/token"))
            .send_form([("grant_type", "client_credentials")])
            .expect("bad grant");
        assert_eq!(bad_grant.status().as_u16(), 400);
        assert_eq!(read_json(&mut bad_grant)["error"], "unsupported_grant_type");

        let mut bogus_code = agent
            .post(format!("http://{addr}/oauth/token"))
            .send_form([
                ("grant_type", "authorization_code"),
                ("code", "never-issued"),
                ("client_id", "whoever"),
                ("redirect_uri", "https://a/cb"),
                ("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            ])
            .expect("bogus code");
        assert_eq!(bogus_code.status().as_u16(), 400);
        assert_eq!(read_json(&mut bogus_code)["error"], "invalid_grant");

        let mut bogus_refresh = agent
            .post(format!("http://{addr}/oauth/token"))
            .send_form([("grant_type", "refresh_token"), ("refresh_token", "never-issued")])
            .expect("bogus refresh");
        assert_eq!(bogus_refresh.status().as_u16(), 400);
        assert_eq!(read_json(&mut bogus_refresh)["error"], "invalid_grant");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Registration rejects fragment/relative redirect URIs and confidential
    /// clients; a well-formed registration answers 201.
    #[test]
    fn registration_validates_metadata() {
        let dir = scratch_dir("register");
        let state = test_state_with_oauth(
            "https://mcp.example.test",
            &dir.join("oauth.json"),
            Duration::from_secs(3600),
        );
        let addr = spawn_server(state);
        let agent = no_redirect_agent();
        let register = |body: Value| {
            let mut response = agent
                .post(format!("http://{addr}/oauth/register"))
                .send_json(body)
                .expect("register");
            (response.status().as_u16(), read_json(&mut response))
        };

        let (status, body) = register(json!({ "redirect_uris": [] }));
        assert_eq!((status, body["error"].as_str()), (400, Some("invalid_client_metadata")));

        let (status, _) = register(json!({ "redirect_uris": ["/relative/path"] }));
        assert_eq!(status, 400, "relative redirect URI rejected");

        let (status, _) = register(json!({ "redirect_uris": ["https://a/cb#frag"] }));
        assert_eq!(status, 400, "fragment redirect URI rejected");

        let (status, _) = register(json!({
            "redirect_uris": ["https://a/cb"],
            "token_endpoint_auth_method": "client_secret_basic",
        }));
        assert_eq!(status, 400, "confidential clients unsupported");

        let (status, body) = register(json!({ "redirect_uris": ["https://a/cb"] }));
        assert_eq!(status, 201);
        assert!(body["client_id"].as_str().is_some());
        assert!(body.get("client_secret").is_none(), "public client has no secret");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- L4: redirect-URI scheme allowlist ----------------------------------

    /// Registration accepts https and http-loopback redirect URIs and rejects
    /// plain-http public hosts and custom schemes (the redirect carries the
    /// authorization code, so it must be confidential in transit).
    #[test]
    fn registration_restricts_redirect_scheme() {
        let dir = scratch_dir("scheme");
        let state = test_state_with_oauth(
            "https://mcp.example.test",
            &dir.join("oauth.json"),
            Duration::from_secs(3600),
        );
        let addr = spawn_server(state);
        let agent = no_redirect_agent();
        let register = |uri: &str| {
            agent
                .post(format!("http://{addr}/oauth/register"))
                .send_json(json!({ "redirect_uris": [uri] }))
                .expect("register")
                .status()
                .as_u16()
        };

        // Allowed: https anywhere, http only on loopback (local dev).
        assert_eq!(register("https://claude.ai/api/mcp/auth_callback"), 201);
        assert_eq!(register("http://127.0.0.1:8080/cb"), 201, "loopback dev ok");
        assert_eq!(register("http://localhost/cb"), 201, "localhost dev ok");

        // Rejected: plain-http public host, and non-http(s) custom schemes.
        assert_eq!(register("http://evil.example.com/cb"), 400, "plain http public rejected");
        assert_eq!(register("ftp://a/cb"), 400, "non-http scheme rejected");
        assert_eq!(register("com.example.app://cb"), 400, "custom app scheme rejected");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- M1: registration resource-bounding ---------------------------------

    /// The client store is capped ([`MAX_CLIENTS`]) — registration answers 503
    /// at the cap — and GC drains clients that registered but never authorized.
    #[test]
    fn registration_cap_and_gc_bound_the_store() {
        let dir = scratch_dir("cap");
        let path = dir.join("oauth.json");
        let runtime = OauthRuntime::new(OauthConfig {
            public_url: "https://mcp.example.test".to_string(),
            state_path: path.clone(),
            access_ttl: Duration::from_secs(3600),
        })
        .unwrap();

        // Fill to the cap directly in the store (fast; the HTTP path is
        // exercised by registration_rate_limits_registration below).
        runtime
            .with_locked_store(|store| {
                for _ in 0..MAX_CLIENTS {
                    store.register_client(vec!["https://a/cb".to_string()], None, 1_000);
                }
            })
            .unwrap();
        // At capacity, another registration is refused (the handler checks
        // `len() >= MAX_CLIENTS`).
        let refused = runtime.with_locked_store(|store| {
            store.gc_stale_clients(1_000);
            store.clients.len() >= MAX_CLIENTS
        });
        assert!(refused.unwrap(), "store is at the cap");

        // GC: a never-authorized client older than the TTL is dropped; one that
        // authorized (or is fresh) is kept.
        let removed = runtime
            .with_locked_store(|store| {
                store.clients.clear();
                store.register_client(vec!["https://a/cb".to_string()], None, 0); // stale, unused
                let kept = store.register_client(vec!["https://b/cb".to_string()], None, 0);
                store.clients.get_mut(&kept).unwrap().authorized_at = Some(1);
                store.register_client(vec!["https://c/cb".to_string()], None, 1_000_000); // fresh
                // GC at a time well past CLIENT_GC_TTL from t=0.
                store.gc_stale_clients(CLIENT_GC_TTL.as_secs() + 10)
            })
            .unwrap();
        assert_eq!(removed, 1, "only the stale, never-authorized client is GC'd");
        let survivors = runtime.store.lock().unwrap().clients.len();
        assert_eq!(survivors, 2, "authorized and fresh clients survive GC");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Registration is rate-limited per source: a burst past the bucket
    /// capacity gets 429s (the store-bounding half is covered above).
    #[test]
    fn registration_rate_limits_registration() {
        let dir = scratch_dir("ratelimit");
        let state = test_state_with_oauth(
            "https://mcp.example.test",
            &dir.join("oauth.json"),
            Duration::from_secs(3600),
        );
        let addr = spawn_server(state);
        let agent = no_redirect_agent();
        let register = || {
            agent
                .post(format!("http://{addr}/oauth/register"))
                .send_json(json!({ "redirect_uris": ["https://a/cb"] }))
                .expect("register")
                .status()
                .as_u16()
        };

        // The bucket starts full (REGISTER_BUCKET_CAPACITY tokens). Draining it
        // plus one more forces a 429 within the same wall-clock second (refill
        // is ~1 token / 6 s, far slower than this loop).
        let mut saw_429 = false;
        for _ in 0..(REGISTER_BUCKET_CAPACITY as usize + 5) {
            if register() == 429 {
                saw_429 = true;
                break;
            }
        }
        assert!(saw_429, "a burst past the bucket capacity is rate-limited");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- M2: state-file race (the dangerous one) ----------------------------

    /// Interleaved writers serialise through the advisory file lock, and a
    /// stale snapshot can never resurrect a revoked family. Simulates the exact
    /// incident: the server revokes a family (refresh-reuse), while a `token
    /// invite`-style CLI writer holds an *older* in-memory snapshot and writes
    /// it back — the file-locked re-read means its write starts from the
    /// server's revoked state, so the family stays dead.
    #[test]
    fn state_file_lock_prevents_family_resurrection() {
        let dir = scratch_dir("race");
        let path = dir.join("oauth.json");

        // Seed a family (access + refresh) on disk.
        let (access, refresh, family_id) = {
            let mut store = OauthStore::default();
            let (a, r) = store.mint_token_pair("alice", "mock", "client-1", Duration::from_secs(3600), 1_000);
            let fam = store.refresh_tokens[&r].family_id.clone();
            store.save(&path).unwrap();
            (a, r, fam)
        };

        // The CLI reads an OLD snapshot (family still present) — this is the
        // stale copy that, written back naively, would resurrect the family.
        let stale_snapshot = OauthStore::load(&path).unwrap();
        assert!(stale_snapshot.access_tokens.contains_key(&access));

        // The server revokes the family on refresh-reuse, through the lock.
        mutate_state_locked(&path, |store| {
            // Spend then replay: replay revokes the whole family.
            let _ = store.rotate_refresh(&refresh, Some("client-1"), Duration::from_secs(3600), 2_000);
            let err = store
                .rotate_refresh(&refresh, Some("client-1"), Duration::from_secs(3600), 2_100)
                .err();
            assert_eq!(err, Some(RotateError::ReuseRevoked));
        })
        .unwrap();

        // On-disk, the family is gone.
        let after_revoke = OauthStore::load(&path).unwrap();
        assert!(!after_revoke.access_tokens.values().any(|e| e.family_id == family_id));

        // Now the CLI writer commits *its* mutation. Because it goes through the
        // SAME locked re-read primitive (not a blind write of `stale_snapshot`),
        // it starts from the server's revoked state and only ADDS an invite —
        // the revoked family is NOT resurrected.
        let _invite = mint_invite_locked(&path, "bob", false, 3_000).unwrap();

        let final_state = OauthStore::load(&path).unwrap();
        assert!(
            !final_state.access_tokens.values().any(|e| e.family_id == family_id),
            "revoked family stays dead after a concurrent invite write"
        );
        assert!(
            !final_state.refresh_tokens.values().any(|e| e.family_id == family_id),
            "revoked refresh family stays dead too"
        );
        assert_eq!(final_state.invites.len(), 1, "the invite write did land");
        // Demonstrate the counterfactual: a BLIND write of the stale snapshot
        // *would* have resurrected the family — proving the lock is load-bearing.
        stale_snapshot.save(&path).unwrap();
        assert!(
            OauthStore::load(&path).unwrap().access_tokens.contains_key(&access),
            "control: a naive stale write resurrects — which the locked path prevents"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- M3: open-redirect via the authorize error path ---------------------

    /// A pre-invite bad-parameter authorize request against a client whose
    /// redirect_uri is attacker-controlled gets a 400 PAGE, never a 302 to that
    /// URI — the open-redirect the error-redirect path used to allow.
    #[test]
    fn authorize_bad_param_is_page_not_open_redirect() {
        let dir = scratch_dir("openredirect");
        let state_path = dir.join("oauth.json");
        let state = test_state_with_oauth("https://mcp.example.test", &state_path, Duration::from_secs(3600));
        let addr = spawn_server(state.clone());
        let agent = no_redirect_agent();

        // Attacker registers a client pointing at attacker-controlled evil.com.
        let mut registered = agent
            .post(format!("http://{addr}/oauth/register"))
            .send_json(json!({ "redirect_uris": ["https://evil.example.com/steal"] }))
            .expect("register");
        let client_id = read_json(&mut registered)["client_id"].as_str().unwrap().to_string();

        // Victim is handed an authorize URL with a bad grant param (plain PKCE),
        // BEFORE presenting any invite. It must NOT 302 to evil.com.
        let bad_param = |query: String| {
            agent
                .get(format!("http://{addr}/oauth/authorize?{query}"))
                .call()
                .expect("authorize")
        };

        // Unsupported response_type.
        let mut r1 = bad_param(format!(
            "response_type=token&client_id={}&redirect_uri={}&code_challenge=x&code_challenge_method=S256",
            url_encode(&client_id),
            url_encode("https://evil.example.com/steal"),
        ));
        assert_eq!(r1.status().as_u16(), 400, "bad response_type is a 400 page");
        assert!(r1.headers().get("location").is_none(), "no Location to evil.com");
        let _ = r1.body_mut().read_to_string();

        // Non-S256 PKCE method.
        let mut r2 = bad_param(format!(
            "response_type=code&client_id={}&redirect_uri={}&code_challenge=x&code_challenge_method=plain",
            url_encode(&client_id),
            url_encode("https://evil.example.com/steal"),
        ));
        assert_eq!(r2.status().as_u16(), 400, "plain PKCE is a 400 page");
        assert!(r2.headers().get("location").is_none(), "no Location to evil.com");
        let _ = r2.body_mut().read_to_string();

        // Also via POST (hidden fields are attacker-editable) with a bad invite:
        // still a 400 page, no redirect.
        let mut r3 = agent
            .post(format!("http://{addr}/oauth/authorize"))
            .send_form([
                ("response_type", "code"),
                ("client_id", client_id.as_str()),
                ("redirect_uri", "https://evil.example.com/steal"),
                ("code_challenge", "x"),
                ("code_challenge_method", "S256"),
                ("invite_code", "wrong"),
            ])
            .expect("post authorize");
        assert_eq!(r3.status().as_u16(), 400, "bad invite is a 400 page");
        assert!(r3.headers().get("location").is_none(), "bad invite doesn't redirect off-origin");
        let _ = r3.body_mut().read_to_string();

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Access-TTL cap -----------------------------------------------------

    /// The access-TTL ceiling is 24h — the boundary the CLI enforces so a
    /// misconfiguration can't mint near-immortal tokens.
    #[test]
    fn access_ttl_cap_is_24h() {
        assert_eq!(MAX_ACCESS_TTL, Duration::from_secs(24 * 3600));
        // A day is allowed; a day-and-a-second is over the ceiling.
        assert!(Duration::from_secs(24 * 3600) <= MAX_ACCESS_TTL);
        assert!(Duration::from_secs(24 * 3600 + 1) > MAX_ACCESS_TTL);
    }
}
