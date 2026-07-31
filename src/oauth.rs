//! OAuth 2.1 authorization for the Streamable-HTTP MCP transport.
//!
//! Browser-based MCP connectors (claude.ai, ChatGPT web) cannot be handed a
//! static bearer token out of band — they discover authorization dynamically.
//! The dance, per the MCP authorization spec:
//!
//! 1. the connector hits the origin root without a token, gets a `401` whose
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
//! The human gate is an **invite code**, minted with `playground invite
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
///
/// An invite may optionally be **bound** to an expected `client_id` and/or
/// `redirect_uri` (repair #5 HIGH: an open-registration attacker must not be
/// able to have a victim's invite authorize a client the attacker controls). A
/// bound invite is only redeemable by an authorize request whose client/redirect
/// exact-match the binding; an unbound invite keeps the prior behaviour (any
/// registered client). The operator mints a bound invite when they already know
/// which connector the human will use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteEntry {
    /// Tenant the resulting tokens act as.
    pub tenant: String,
    /// `true` keeps the invite valid after use (e.g. a team invite).
    #[serde(default)]
    pub reusable: bool,
    /// Unix seconds at mint.
    pub created_at: u64,
    /// If set, the invite is only redeemable by this exact `client_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// If set, the invite is only redeemable with this exact `redirect_uri`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
}

/// Why an invite redemption was refused at the authorize step — each a
/// no-write, pre-redirect failure (repair #5 HIGH).
enum InviteRejection {
    /// No such invite (or already spent).
    Unknown,
    /// Invite is bound to a different `client_id`.
    ClientMismatch,
    /// Invite is bound to a different `redirect_uri`.
    RedirectMismatch,
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
    /// RFC 8707 audience. Empty only for legacy on-disk entries, which are
    /// deliberately rejected rather than accepted as audience-free tokens.
    #[serde(default)]
    pub resource: String,
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
    /// RFC 8707 audience. Empty legacy entries remain readable but cannot be
    /// rotated into an audience-bound family without a fresh authorization.
    #[serde(default)]
    pub resource: String,
    /// Scope granted by the authorization that created this family. Older
    /// on-disk entries predate scope persistence; rotating one keeps working
    /// but omits `scope` from the token response rather than claiming an
    /// incorrect empty scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
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
    /// Monotonic tenant generation captured by pending authorization codes.
    /// Advancing it invalidates codes already issued for that tenant without
    /// having to persist the short-lived codes themselves.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tenant_generations: HashMap<String, u64>,
}

/// Tenant-scoped OAuth credentials removed by [`OauthStore::revoke_tenant`].
///
/// Dynamic client registrations are deliberately absent: a client is not
/// tenant-owned and may have authorized more than one tenant. Invites, access
/// tokens, and refresh tokens are tenant-bound and are all credentials capable
/// of reaching that tenant, so revocation removes all three kinds.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TenantRevocation {
    pub invites: usize,
    pub access_tokens: usize,
    pub refresh_tokens: usize,
    /// The new generation; authorization codes carrying an older value can no
    /// longer be exchanged for tokens.
    pub authorization_generation: u64,
}

/// Outcome of presenting a refresh token (see [`OauthStore::rotate_refresh`]).
#[derive(Debug, PartialEq, Eq)]
pub enum RotateError {
    /// Token was never issued (or its family was already revoked).
    Unknown,
    /// Token exists but was issued to a different client.
    ClientMismatch,
    /// The request named a different protected resource than this family.
    InvalidTarget,
    /// A refresh request tried to alter the authorization's scope set.
    InvalidScope,
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

    /// Persist the store to `path` (pretty JSON, mode 0600) crash-atomically —
    /// a `0600` temp sibling written + fsync'd, then `rename`d into place, so a
    /// crash never leaves the auth state torn or briefly world-readable. Shares
    /// [`crate::mcp_http::atomic_write_0600`] with the static token store.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        crate::mcp_http::atomic_write_0600(path, json.as_bytes())
            .with_context(|| format!("write oauth state {}", path.display()))
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
    /// Optionally bound to an expected `client_id` / `redirect_uri` (repair #5
    /// HIGH: invite→attacker-client), which the authorize step exact-matches.
    pub fn mint_invite(
        &mut self,
        tenant: &str,
        reusable: bool,
        client_id: Option<String>,
        redirect_uri: Option<String>,
        now: u64,
    ) -> String {
        let code = random_urlsafe(32);
        self.invites.insert(
            code.clone(),
            InviteEntry {
                tenant: tenant.to_string(),
                reusable,
                created_at: now,
                client_id,
                redirect_uri,
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
        resource: &str,
        scope: Option<&str>,
        access_ttl: Duration,
        now: u64,
    ) -> (String, String) {
        let family_id = random_urlsafe(16);
        self.mint_pair_in_family(
            tenant, backend, client_id, resource, scope, &family_id, access_ttl, now,
        )
    }

    /// Mint an access + refresh pair inside an existing family (rotation).
    fn mint_pair_in_family(
        &mut self,
        tenant: &str,
        backend: &str,
        client_id: &str,
        resource: &str,
        scope: Option<&str>,
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
                resource: resource.to_string(),
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
                resource: resource.to_string(),
                scope: scope.filter(|scope| !scope.is_empty()).map(str::to_owned),
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
        resource: &str,
        requested_scope: Option<&str>,
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
        if resource != entry.resource {
            return Err(RotateError::InvalidTarget);
        }
        if requested_scope.is_some_and(|scope| entry.scope.as_deref() != Some(scope)) {
            return Err(RotateError::InvalidScope);
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
            &entry.resource,
            entry.scope.as_deref(),
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

    /// Revoke every persisted OAuth credential bound to `tenant`.
    ///
    /// This includes unredeemed invites: retaining one would let its bearer
    /// mint a new token family immediately after an operator reset/destroy.
    /// Client registrations remain because they carry no tenant identity.
    pub fn revoke_tenant(&mut self, tenant: &str) -> TenantRevocation {
        let invites_before = self.invites.len();
        self.invites.retain(|_, entry| entry.tenant != tenant);

        let access_before = self.access_tokens.len();
        self.access_tokens.retain(|_, entry| entry.tenant != tenant);

        let refresh_before = self.refresh_tokens.len();
        self.refresh_tokens
            .retain(|_, entry| entry.tenant != tenant);

        // This deliberately advances even if the persisted credential counts
        // are zero: a single-use invite may already have become an in-memory
        // authorization code in the running daemon. The generation is the
        // durable revocation signal for that otherwise invisible credential.
        let generation = self
            .tenant_generations
            .entry(tenant.to_string())
            .or_default();
        *generation = generation
            .checked_add(1)
            .expect("tenant OAuth revocation generation exhausted");

        TenantRevocation {
            invites: invites_before - self.invites.len(),
            access_tokens: access_before - self.access_tokens.len(),
            refresh_tokens: refresh_before - self.refresh_tokens.len(),
            authorization_generation: *generation,
        }
    }

    /// Current generation captured by a newly-issued authorization code.
    pub fn tenant_generation(&self, tenant: &str) -> u64 {
        self.tenant_generations.get(tenant).copied().unwrap_or(0)
    }

    /// Resolve an access token to a [`TokenEntry`], enforcing expiry (expired
    /// tokens are removed — lazy reaping, no timer thread). `Err` carries the
    /// 401 message and whether the store was mutated (needs saving).
    pub fn lookup_access(
        &mut self,
        token: &str,
        resource: &str,
        now: u64,
    ) -> std::result::Result<TokenEntry, (&'static str, bool)> {
        let Some(entry) = self.access_tokens.get(token) else {
            return Err(("unknown token", false));
        };
        if entry.expires_at <= now {
            self.access_tokens.remove(token);
            return Err(("access token expired", true));
        }
        if entry.resource != resource {
            return Err(("access token is for a different resource", false));
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

/// Tenant identity and durable revocation generation captured atomically when
/// an invite is consumed.
#[derive(Debug, Clone)]
struct TenantGrant {
    label: String,
    generation: u64,
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
    /// Must still equal the tenant's persistent generation when exchanged.
    pub tenant_generation: u64,
    /// Exact RFC 8707 protected-resource identifier this grant targets.
    pub resource: String,
    pub scope: String,
    pub expires_at: u64,
}

/// Outcome of redeeming an authorization code.
pub enum CodeTake {
    Ok(AuthCode),
    Expired,
    Unknown,
    StoreUnavailable,
}

/// Live OAuth state hung off `HttpState` when the feature is configured.
pub struct OauthRuntime {
    /// `OauthConfig::public_url`, normalized (no trailing slash).
    pub public_url: String,
    /// Canonical protected resource served by this process. MCP lives at
    /// `public_url` itself.
    pub resource: String,
    state_path: PathBuf,
    pub access_ttl: Duration,
    pub store: Mutex<OauthStore>,
    /// Fingerprint of the state file mirrored by `store`. The atomic writer
    /// replaces the inode, so the fingerprint detects CLI revocations even on
    /// filesystems whose mtime resolution is coarse.
    disk_fingerprint: Mutex<Option<FileFingerprint>>,
    codes: Mutex<HashMap<String, AuthCode>>,
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
        // Pair the initial snapshot with its fingerprint under the same lock
        // every cooperating writer uses; otherwise a CLI rename between load
        // and stat could make an old snapshot look current forever.
        let (store, disk_fingerprint) = {
            let _lock = FileLock::acquire(&config.state_path)?;
            (
                OauthStore::load(&config.state_path)?,
                file_fingerprint(&config.state_path),
            )
        };
        let public_url = config.public_url.trim_end_matches('/').to_string();
        let resource = public_url.clone();
        Ok(OauthRuntime {
            public_url,
            resource,
            state_path: config.state_path,
            access_ttl: config.access_ttl,
            store: Mutex::new(store),
            disk_fingerprint: Mutex::new(disk_fingerprint),
            codes: Mutex::new(HashMap::new()),
        })
    }

    /// Apply a mutation to the persistent store under the cross-process file
    /// lock, re-reading the latest on-disk state first so a concurrent
    /// `token invite` write is never clobbered (and, symmetrically, the CLI
    /// re-reads our revocations before it writes). The in-memory `store` mirror
    /// is refreshed with the freshly-written state so the hot-path access-token
    /// lookups stay consistent. Holds the in-memory `store` mutex for the whole
    /// critical section, so server-internal callers also serialise.
    #[cfg(test)]
    fn with_locked_store<R>(&self, mutate: impl FnOnce(&mut OauthStore) -> R) -> Result<R> {
        // Callers of this method always mutate (mint/rotate-success), so the
        // write is unconditional here. No-op/error paths use
        // [`with_locked_store_if`] instead so they never write.
        self.with_locked_store_if(|store| (true, mutate(store)))
    }

    /// Like [`with_locked_store`], but the closure returns `(dirty, R)`: the
    /// store is `save()`d only when `dirty` is true. This is the write-avoidance
    /// primitive for no-op/error paths (repair #5 HIGH: unauthenticated OAuth
    /// write amplification) — an invalid unauthenticated request that reaches
    /// the lock still re-reads the latest disk state (so a real concurrent write
    /// is never lost), but performs no write of its own, so it cannot be used to
    /// force an unbounded stream of full-file rewrites.
    fn with_locked_store_if<R>(
        &self,
        mutate: impl FnOnce(&mut OauthStore) -> (bool, R),
    ) -> Result<R> {
        // Lock order throughout this type is fingerprint → store → codes.
        // Keeping the fingerprint guard through the disk transaction prevents
        // a concurrent request from tagging a stale mirror as current.
        let mut fingerprint = self
            .disk_fingerprint
            .lock()
            .expect("oauth disk fingerprint poisoned");
        let mut mirror = self.store.lock().expect("oauth store poisoned");
        let (fresh, fresh_fingerprint, result) = mutate_state_locked(&self.state_path, mutate)?;
        *mirror = fresh;
        let mut codes = self.codes.lock().expect("codes poisoned");
        codes.retain(|_, code| mirror.tenant_generation(&code.tenant) == code.tenant_generation);
        // This fingerprint was sampled while the same file lock still guarded
        // `fresh`. If an external CLI writer commits immediately afterward,
        // its new inode differs and the next lookup reloads it; an older mirror
        // can never be tagged with a newer writer's fingerprint.
        *fingerprint = fresh_fingerprint;
        Ok(result)
    }

    /// Mint and remember an authorization code. Expired leftovers are purged
    /// opportunistically so the map stays bounded without a reaper.
    fn issue_code(
        &self,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        tenant: &TenantGrant,
        resource: &str,
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
                tenant: tenant.label.clone(),
                tenant_generation: tenant.generation,
                resource: resource.to_string(),
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
        // A CLI reset/destroy is out-of-process. Refreshing first both updates
        // the access-token mirror and drops codes invalidated by its tenant
        // generation before one can reach the exchange path.
        if let Err(e) = self.refresh_if_changed() {
            eprintln!("warning: failed to refresh oauth state before code exchange: {e:#}");
            return CodeTake::StoreUnavailable;
        }
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
        if let Err(e) = self.refresh_if_changed() {
            eprintln!("warning: failed to refresh oauth state before access lookup: {e:#}");
            return Err("oauth state unavailable");
        }
        {
            let store = self.store.lock().expect("oauth store poisoned");
            if let Some(entry) = store.access_tokens.get(token) {
                if entry.expires_at > now {
                    let entry = entry.clone();
                    if entry.resource != self.resource {
                        return Err("access token is for a different resource");
                    }
                    return Ok(TokenEntry {
                        tenant: entry.tenant,
                        backend: entry.backend,
                    });
                }
            } else {
                return Err("unknown token");
            }
        }
        // Fell through: the token is present but expired. Reap it under the
        // lock — but only *write* when the reap actually removed something
        // (`OauthStore::lookup_access` reports that via the `mutated` bool), so
        // a token another writer already cleaned up doesn't trigger a redundant
        // full-file rewrite.
        let resource = self.resource.clone();
        let outcome =
            self.with_locked_store_if(|store| match store.lookup_access(token, &resource, now) {
                Ok(entry) => (false, Ok(entry)),
                Err((message, mutated)) => (mutated, Err(message)),
            });
        match outcome {
            Ok(Ok(entry)) => Ok(entry), // Refreshed on another writer; still valid.
            Ok(Err(message)) => Err(message),
            Err(e) => {
                eprintln!("warning: failed to reap expired oauth token: {e:#}");
                Err("access token expired")
            }
        }
    }

    /// Reload an OAuth state file changed by an out-of-process CLI operation.
    /// The steady state is one `stat`; a changed atomic-write inode triggers a
    /// locked load and mirror swap. Pending codes whose tenant generation moved
    /// are dropped in the same refresh.
    fn refresh_if_changed(&self) -> Result<()> {
        let mut loaded = self
            .disk_fingerprint
            .lock()
            .expect("oauth disk fingerprint poisoned");
        if file_fingerprint(&self.state_path) == *loaded {
            return Ok(());
        }

        let _lock = FileLock::acquire(&self.state_path)?;
        let fresh = OauthStore::load(&self.state_path)?;
        let current = file_fingerprint(&self.state_path);

        let mut mirror = self.store.lock().expect("oauth store poisoned");
        *mirror = fresh;
        let mut codes = self.codes.lock().expect("codes poisoned");
        codes.retain(|_, code| mirror.tenant_generation(&code.tenant) == code.tenant_generation);
        *loaded = current;
        Ok(())
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

/// Identity of the atomically-written OAuth state file mirrored in memory.
/// `atomic_write_0600` renames a newly-created sibling over the live path, so
/// `(device, inode)` is the strongest Unix signal; length + mtime retain useful
/// behaviour on other targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

fn file_fingerprint(path: &Path) -> Option<FileFingerprint> {
    let metadata = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt as _;
    Some(FileFingerprint {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    })
}

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
                return Err(err)
                    .with_context(|| format!("flock oauth lock file {}", lock_path.display()));
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
/// lock, then persist the result iff the closure reports a change: lock →
/// re-read disk → mutate → (write only if dirty) → unlock. This is the one safe
/// read-modify-write primitive; the server and the CLI both funnel through it so
/// a stale snapshot can never clobber a newer one. The `dirty` half of the
/// closure's return lets no-op/error paths skip the (O(N), fsyncing) write
/// entirely so they cannot be turned into a write-amplification lever. Returns
/// the freshly-read store, its fingerprint sampled under the same lock, and
/// the closure's own return value.
fn mutate_state_locked<R>(
    state_path: &Path,
    mutate: impl FnOnce(&mut OauthStore) -> (bool, R),
) -> Result<(OauthStore, Option<FileFingerprint>, R)> {
    let _lock = FileLock::acquire(state_path)?;
    let mut store = OauthStore::load(state_path)?;
    let (dirty, result) = mutate(&mut store);
    if dirty {
        store.save(state_path)?;
    }
    let fingerprint = file_fingerprint(state_path);
    Ok((store, fingerprint, result))
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
    client_id: Option<String>,
    redirect_uri: Option<String>,
    now: u64,
) -> Result<String> {
    let (_store, _fingerprint, code) = mutate_state_locked(state_path, |store| {
        (
            true,
            store.mint_invite(
                tenant,
                reusable,
                client_id.clone(),
                redirect_uri.clone(),
                now,
            ),
        )
    })?;
    Ok(code)
}

/// Revoke all persisted OAuth credentials for `tenant` under the same
/// cross-process lock used by the server and invite CLI.
///
/// The store is re-read after locking, so this cannot overwrite a concurrent
/// refresh rotation or invite mint with a stale snapshot. The generation is
/// always advanced—even when no persisted entry remains—because an invite may
/// already have become a pending in-memory authorization code in the daemon.
pub fn revoke_tenant_locked(state_path: &Path, tenant: &str) -> Result<TenantRevocation> {
    let (_store, _fingerprint, revoked) = mutate_state_locked(state_path, |store| {
        let revoked = store.revoke_tenant(tenant);
        (true, revoked)
    })?;
    Ok(revoked)
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

/// Run a store-mutating closure on the blocking pool (repair #5 HIGH: move
/// blocking persistence off the async runtime workers). The OAuth store writes
/// take a cross-process `flock`, re-read the file, and `fsync` — all blocking
/// syscalls that must not sit on a tokio worker. `write` gets `&OauthRuntime`
/// (via the moved `Arc<HttpState>`) and returns the same `Result<R>` the
/// `with_locked_store*` methods do; a `spawn_blocking` join failure is folded
/// into that `Result` so callers see one error channel.
async fn run_store_write<R>(
    state: &Arc<HttpState>,
    write: impl FnOnce(&OauthRuntime) -> Result<R> + Send + 'static,
) -> Result<R>
where
    R: Send + 'static,
{
    let state = state.clone();
    match tokio::task::spawn_blocking(move || write(oauth(&state))).await {
        Ok(result) => result,
        Err(join) => Err(anyhow::anyhow!("oauth store write task panicked: {join}")),
    }
}

/// `GET /.well-known/oauth-protected-resource` (RFC 9728): tells a connector
/// that got a 401 *who* can authorize it — this same server.
async fn protected_resource_metadata(State(state): State<Arc<HttpState>>) -> Response {
    let oauth = oauth(&state);
    let base = &oauth.public_url;
    json_ok(json!({
        "resource": oauth.resource,
        "authorization_servers": [base],
        "scopes_supported": ["mcp", "offline_access"],
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
        "scopes_supported": ["mcp", "offline_access"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }))
}

/// `POST /oauth/register` (RFC 7591): open dynamic registration of public
/// clients. Open is safe here because a `client_id` grants nothing — the
/// authorize form's invite code is the actual gate. Registration is the
/// moment redirect URIs get pinned; everything later exact-matches them.
async fn register(State(state): State<Arc<HttpState>>, body: Bytes) -> Response {
    let now = unix_now();

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
    // the file lock so the count we check is the count we write. The store is
    // written only when something actually changed — a rejected (store-full)
    // registration that also GC'd nothing performs no write, so a burst of
    // registrations against a full store cannot amplify into a write storm.
    //
    // The whole flock + re-read + fsync critical section is blocking IO, so it
    // runs on the blocking pool (repair #5 HIGH: move blocking persistence off
    // the async runtime workers) rather than stalling a tokio worker.
    // Clone what the blocking closure consumes; `redirect_uris`/`client_name`
    // are reused in the success response body below, so they must not be moved
    // into the closure.
    let uris_for_store = redirect_uris.clone();
    let name_for_store = client_name.clone();
    let outcome = run_store_write(&state, move |oauth| {
        oauth.with_locked_store_if(|store| {
            let reclaimed = store.gc_stale_clients(now);
            if store.clients.len() >= MAX_CLIENTS {
                // Persist only if GC actually freed clients; otherwise no-op.
                return (reclaimed > 0, Err(()));
            }
            let client_id =
                store.register_client(uris_for_store.clone(), name_for_store.clone(), now);
            (true, Ok(client_id))
        })
    })
    .await;
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
    resource: String,
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
            resource: get("resource"),
            scope: get("scope"),
        }
    }
}

/// Validate the identity half of an authorize request: known client, exactly
/// registered redirect URI. Failures here get a 400 page, never a redirect —
/// redirecting to an unvalidated URI is an open redirect (RFC 6749 §4.1.2.1).
/// Returns the client's registered display name (if any) so the consent page
/// can show *who* is asking (repair #5 HIGH: the consent page must show the
/// client identity + redirect host).
fn validate_client_and_redirect(
    state: &HttpState,
    params: &AuthorizeParams,
) -> std::result::Result<Option<String>, Response> {
    let store = oauth(state).store.lock().expect("oauth store poisoned");
    let Some(client) = store.clients.get(&params.client_id) else {
        return Err(authorize_error_page("unknown client_id"));
    };
    if !client
        .redirect_uris
        .iter()
        .any(|u| u == &params.redirect_uri)
    {
        return Err(authorize_error_page(
            "redirect_uri is not registered for this client",
        ));
    }
    Ok(client.client_name.clone())
}

/// Validate the protocol half: `response_type=code`, PKCE challenge present,
/// method S256. Failures render a 400 error PAGE, never a redirect: this runs
/// *before* an invite is consumed, and redirecting to a client-supplied URI at
/// that point is the open-redirect hole (an attacker registers evil.com, then
/// hands a victim an authorize URL with a bad grant param to bounce them off
/// this trusted origin). Only a request that has cleared the invite gate has
/// earned a redirect — and by then the only remaining outcome is success.
fn validate_grant_shape(
    params: &AuthorizeParams,
    expected_resource: &str,
) -> std::result::Result<String, Response> {
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
    if !resource_matches(&params.resource, expected_resource) {
        return Err(authorize_error_page(
            "resource must match this MCP protected resource",
        ));
    }
    canonicalize_scope(&params.scope).map_err(authorize_error_page)
}

/// Compare an RFC 8707 resource indicator with this server's canonical
/// resource identity. The only non-byte-exact spelling admitted is the URI
/// equivalence between a bare origin and that origin's root path (`https://h`
/// versus `https://h/`). Codex serializes a root Streamable-HTTP endpoint with
/// the slash during token exchange even when discovery advertised the bare
/// origin. Non-root paths, queries, authorities, ports, and schemes remain
/// byte-exact so this cannot widen a grant to another protected resource.
fn resource_matches(requested: &str, canonical: &str) -> bool {
    if requested == canonical {
        return true;
    }
    let Ok(canonical_uri) = canonical.parse::<Uri>() else {
        return false;
    };
    let (Some(scheme), Some(authority)) = (canonical_uri.scheme_str(), canonical_uri.authority())
    else {
        return false;
    };
    canonical == format!("{scheme}://{authority}") && requested == format!("{canonical}/")
}

/// Parse the OAuth space-delimited scope set and return the one canonical
/// spelling persisted in grants. The MCP capability is the default and is
/// always required; `offline_access` is the only optional extension.
fn canonicalize_scope(scope: &str) -> std::result::Result<String, &'static str> {
    if scope.trim().is_empty() {
        return Ok("mcp".to_string());
    }
    let mut mcp = false;
    let mut offline = false;
    for item in scope.split_whitespace() {
        match item {
            "mcp" => mcp = true,
            "offline_access" => offline = true,
            _ => return Err("scope contains an unsupported value"),
        }
    }
    if !mcp {
        return Err("scope must include mcp");
    }
    Ok(if offline {
        "mcp offline_access".to_string()
    } else {
        "mcp".to_string()
    })
}

/// `GET /oauth/authorize`: serve the invite-code form. The request is
/// validated up front (same checks as the POST) so a user never types an
/// invite into a doomed form; the POST re-validates from scratch anyway
/// because hidden form fields are attacker-editable.
async fn authorize_form(State(state): State<Arc<HttpState>>, uri: Uri) -> Response {
    let mut params = AuthorizeParams::from_map(&parse_form(uri.query().unwrap_or("")));
    let client_name = match validate_client_and_redirect(&state, &params) {
        Ok(name) => name,
        Err(response) => return response,
    };
    let oauth = oauth(&state);
    params.scope = match validate_grant_shape(&params, &oauth.resource) {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    // Grants and hidden form fields always carry our one canonical spelling,
    // irrespective of which equivalent root spelling the client requested.
    params.resource.clone_from(&oauth.resource);
    // Anti-framing (repair #5 HIGH): the consent page must not be embeddable, so
    // a clickjacking overlay can't trick the human into submitting the invite.
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"),
        ],
        authorize_page(&params, client_name.as_deref()),
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
    let mut params = AuthorizeParams::from_map(&form);

    if let Err(response) = validate_client_and_redirect(&state, &params) {
        return response;
    }
    params.scope = match validate_grant_shape(&params, &oauth.resource) {
        Ok(scope) => scope,
        Err(response) => return response,
    };
    params.resource.clone_from(&oauth.resource);

    // The human gate: a valid invite code names the tenant. Consumption, the
    // client's `authorized_at` stamp (so GC keeps it — it has now completed an
    // authorization) and the write all happen atomically under the file lock.
    // An invalid invite is a *pre-redirect* failure → 400 page, never a bounce
    // off this origin (the open-redirect defence: the redirect_uri is only
    // trusted as a redirect target once a real invite has been presented).
    let invite_code = form.get("invite_code").cloned().unwrap_or_default();
    let now = unix_now();
    let expected_client = params.client_id.clone();
    let expected_redirect = params.redirect_uri.clone();
    // The flock + fsync runs on the blocking pool (repair #5 HIGH: off the
    // runtime workers), and only writes when the invite is actually consumed
    // (repair #5 HIGH: no write on a rejected binding / invalid invite).
    let consumed = run_store_write(&state, move |oauth| {
        oauth.with_locked_store_if(|store| {
            // Peek the invite WITHOUT consuming, so we can enforce the client /
            // redirect binding (repair #5 HIGH: invite→attacker-client) and
            // reject a mismatch with NO write (repair #5 HIGH: write
            // amplification). The invite is only spent once it passes the binding.
            let Some(invite) = store.invites.get(&invite_code).cloned() else {
                return (false, Err(InviteRejection::Unknown));
            };
            if invite
                .client_id
                .as_deref()
                .is_some_and(|want| want != expected_client)
            {
                return (false, Err(InviteRejection::ClientMismatch));
            }
            if invite
                .redirect_uri
                .as_deref()
                .is_some_and(|want| want != expected_redirect)
            {
                return (false, Err(InviteRejection::RedirectMismatch));
            }
            // Binding cleared: now actually consume (mutation) + stamp the client.
            let tenant = store
                .consume_invite(&invite_code)
                .expect("invite present, just peeked");
            let grant = TenantGrant {
                generation: store.tenant_generation(&tenant),
                label: tenant,
            };
            if let Some(client) = store.clients.get_mut(&expected_client) {
                client.authorized_at = Some(now);
            }
            (true, Ok(grant))
        })
    })
    .await;
    let tenant = match consumed {
        Ok(Ok(consumed)) => consumed,
        Ok(Err(InviteRejection::Unknown)) => return authorize_error_page("invalid invite code"),
        Ok(Err(InviteRejection::ClientMismatch)) => {
            return authorize_error_page("this invite is bound to a different client_id");
        }
        Ok(Err(InviteRejection::RedirectMismatch)) => {
            return authorize_error_page("this invite is bound to a different redirect_uri");
        }
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
        &params.resource,
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
    let now = unix_now();
    let Ok(body) = std::str::from_utf8(&body) else {
        return token_error("invalid_request", "form body is not UTF-8");
    };
    let form = parse_form(body);
    let get = |key: &str| form.get(key).map(String::as_str).unwrap_or("");

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
                CodeTake::StoreUnavailable => {
                    return http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "OAuth state is temporarily unavailable",
                    );
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
            if !resource_matches(get("resource"), &code.resource) || code.resource != oauth.resource
            {
                return token_error(
                    "invalid_target",
                    "resource does not match the authorization grant",
                );
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
            // `token invite` write can't roll this token pair back — on the
            // blocking pool (repair #5 HIGH: off the runtime workers).
            let backend_name = state.config.backend_name.clone();
            let code_tenant = code.tenant.clone();
            let code_client = code.client_id.clone();
            let code_resource = code.resource.clone();
            let code_scope = code.scope.clone();
            let code_generation = code.tenant_generation;
            let minted = run_store_write(&state, move |oauth| {
                oauth.with_locked_store_if(|store| {
                    if store.tenant_generation(&code_tenant) != code_generation {
                        return (false, None);
                    }
                    (
                        true,
                        Some(store.mint_token_pair(
                            &code_tenant,
                            &backend_name,
                            &code_client,
                            &code_resource,
                            Some(&code_scope),
                            oauth.access_ttl,
                            now,
                        )),
                    )
                })
            })
            .await;
            let (access, refresh) = match minted {
                Ok(Some(pair)) => pair,
                Ok(None) => {
                    return token_error(
                        "invalid_grant",
                        "authorization code was revoked by a tenant reset",
                    );
                }
                Err(e) => {
                    return http_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("failed to persist tokens: {e:#}"),
                    );
                }
            };
            (access, refresh, Some(code.scope))
        }
        // --- refresh_token rotation -----------------------------------
        "refresh_token" => {
            let client_id = form.get("client_id").cloned();
            let refresh_token = get("refresh_token").to_string();
            if !resource_matches(get("resource"), &oauth.resource) {
                return token_error(
                    "invalid_target",
                    "resource must match this MCP protected resource",
                );
            }
            // Persist and compare only the server's canonical spelling.
            let resource = oauth.resource.clone();
            let requested_scope = match form.get("scope") {
                Some(scope) => match canonicalize_scope(scope) {
                    Ok(scope) => Some(scope),
                    Err(message) => return token_error("invalid_scope", message),
                },
                None => None,
            };
            // The rotation itself (including the family-revoke on reuse) is a
            // store mutation, so it runs inside the file lock: re-read the
            // latest on-disk state, rotate, write. This is exactly the path M2
            // guards — a stale CLI write must never resurrect a family revoked
            // here. It runs on the blocking pool (repair #5 HIGH: off the
            // runtime workers). The write is CONDITIONAL on an actual mutation
            // (repair #5 HIGH: OAuth write amplification): an unknown refresh
            // token or a client mismatch changes nothing, so it performs no
            // write — an unauthenticated caller replaying garbage refresh tokens
            // can no longer force a full-file rewrite per request. A successful
            // rotation and a reuse-triggered family-revoke both DO write.
            let rotated = run_store_write(&state, move |oauth| {
                oauth.with_locked_store_if(|store| {
                    match store.rotate_refresh(
                        &refresh_token,
                        client_id.as_deref(),
                        &resource,
                        requested_scope.as_deref(),
                        oauth.access_ttl,
                        now,
                    ) {
                        Ok(rotation) => (true, Ok(rotation)),
                        // ReuseRevoked mutated (burned the family); Unknown /
                        // ClientMismatch did not.
                        Err(RotateError::ReuseRevoked) => (true, Err(RotateError::ReuseRevoked)),
                        Err(
                            other @ (RotateError::Unknown
                            | RotateError::ClientMismatch
                            | RotateError::InvalidTarget
                            | RotateError::InvalidScope),
                        ) => (false, Err(other)),
                    }
                })
            })
            .await;
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
                Ok((access, refresh, spent)) => (access, refresh, spent.scope),
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
                Err(RotateError::InvalidTarget) => {
                    return token_error(
                        "invalid_target",
                        "refresh token belongs to another resource",
                    );
                }
                Err(RotateError::InvalidScope) => {
                    return token_error(
                        "invalid_scope",
                        "refresh scope differs from the original grant",
                    );
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

    let mut body = json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": oauth.access_ttl.as_secs(),
        "refresh_token": refresh,
    });
    if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
        body["scope"] = json!(scope);
    }

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
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
///
/// The consent copy names the requesting **client** (registered `client_name`
/// if any, else its `client_id`) and the **redirect host** (repair #5 HIGH: the
/// human must be able to see *who* is asking and *where* the code will be sent —
/// this is what lets them refuse an attacker-chosen client/callback before
/// pasting a valid invite). The redirect host is derived independently from the
/// registered `redirect_uri`, not from anything the client can restyle.
fn authorize_page(params: &AuthorizeParams, client_name: Option<&str>) -> String {
    let hidden = [
        ("response_type", &params.response_type),
        ("client_id", &params.client_id),
        ("redirect_uri", &params.redirect_uri),
        ("code_challenge", &params.code_challenge),
        ("code_challenge_method", &params.code_challenge_method),
        ("state", &params.state),
        ("resource", &params.resource),
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

    // The client label the human sees: the registered name if present, else the
    // raw client_id (always shown so a nameless client isn't invisible).
    let client_label = match client_name {
        Some(name) if !name.is_empty() => {
            format!(
                "{} (<code>{}</code>)",
                html_escape(name),
                html_escape(&params.client_id)
            )
        }
        _ => format!("<code>{}</code>", html_escape(&params.client_id)),
    };
    let redirect_host = redirect_host(&params.redirect_uri);

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
         dl.details {{ background: #f4f4f4; padding: .75rem 1rem; border-radius: .375rem; }}\n\
         dl.details dt {{ font-weight: 600; }}\n\
         dl.details dd {{ margin: 0 0 .5rem; word-break: break-all; }}\n\
         dl.details dd:last-child {{ margin-bottom: 0; }}\n\
         </style>\n</head>\n<body>\n\
         <h1>Authorize access</h1>\n\
         <p>A client is asking to connect to this playground server. Check who it \
         is and where it will send your authorization before continuing.</p>\n\
         <dl class=\"details\">\n\
         <dt>Client</dt><dd>{client_label}</dd>\n\
         <dt>Will send the code to</dt><dd><code>{redirect_host}</code></dd>\n\
         </dl>\n\
         <form method=\"post\" action=\"/oauth/authorize\">\n{hidden}\n\
         <label for=\"invite_code\">Invite code</label>\n\
         <input type=\"text\" id=\"invite_code\" name=\"invite_code\" autofocus \
         autocomplete=\"off\" spellcheck=\"false\">\n\
         <p class=\"hint\">Ask the operator for an invite code (<code>playground invite</code>). \
         Only paste it if the client and destination above are the ones you expect.</p>\n\
         <button type=\"submit\">Authorize</button>\n\
         </form>\n</body>\n</html>\n",
    )
}

/// The host (`scheme://host[:port]`) of a redirect URI, for the consent page —
/// derived from the registered URI independently of anything else the client
/// controls. Falls back to the (escaped) whole URI if it won't parse as one
/// with an authority (registration already rejects those, so this is just
/// defensive).
fn redirect_host(redirect_uri: &str) -> String {
    match redirect_uri.parse::<Uri>() {
        Ok(uri) => match (uri.scheme_str(), uri.authority()) {
            (Some(scheme), Some(authority)) => html_escape(&format!("{scheme}://{authority}")),
            _ => html_escape(redirect_uri),
        },
        Err(_) => html_escape(redirect_uri),
    }
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

    const TEST_RESOURCE: &str = "https://mcp.example.test";

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
        assert!(!verify_pkce_s256(
            "wrong-verifier-wrong-verifier-wrong-verifi",
            challenge
        ));
        // A `plain` client sending challenge == verifier must not pass S256.
        assert!(!verify_pkce_s256(verifier, verifier));
    }

    #[test]
    fn scopes_are_validated_and_canonicalized() {
        assert_eq!(canonicalize_scope("").unwrap(), "mcp");
        assert_eq!(canonicalize_scope("mcp").unwrap(), "mcp");
        assert_eq!(
            canonicalize_scope("offline_access  mcp mcp").unwrap(),
            "mcp offline_access"
        );
        assert_eq!(
            canonicalize_scope("offline_access").unwrap_err(),
            "scope must include mcp"
        );
        assert_eq!(
            canonicalize_scope("mcp admin").unwrap_err(),
            "scope contains an unsupported value"
        );
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
        let alice = TenantGrant {
            label: "alice".to_string(),
            generation: 0,
        };

        // Single-use: first take wins, second take finds nothing.
        let code = runtime.issue_code(
            "client-1",
            "https://a/cb",
            "chal",
            &alice,
            TEST_RESOURCE,
            "",
            1_000,
        );
        assert!(matches!(runtime.take_code(&code, 1_001), CodeTake::Ok(c) if c.tenant == "alice"));
        assert!(matches!(runtime.take_code(&code, 1_001), CodeTake::Unknown));

        // Expiry: a code is dead AUTH_CODE_TTL after issuance...
        let code = runtime.issue_code(
            "client-1",
            "https://a/cb",
            "chal",
            &alice,
            TEST_RESOURCE,
            "",
            1_000,
        );
        let expired_at = 1_000 + AUTH_CODE_TTL.as_secs();
        assert!(matches!(
            runtime.take_code(&code, expired_at),
            CodeTake::Expired
        ));
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
        let (access1, refresh1) = store.mint_token_pair(
            "alice",
            "mock",
            "client-1",
            TEST_RESOURCE,
            Some("mcp offline_access"),
            ttl,
            1_000,
        );

        // Normal rotation: new pair in the same family, old refresh spent.
        let (access2, refresh2, spent) = store
            .rotate_refresh(&refresh1, Some("client-1"), TEST_RESOURCE, None, ttl, 2_000)
            .expect("first rotation");
        assert_eq!(spent.tenant, "alice");
        assert_eq!(spent.resource, TEST_RESOURCE);
        assert_eq!(spent.scope.as_deref(), Some("mcp offline_access"));
        assert_eq!(
            store.refresh_tokens[&refresh2].scope.as_deref(),
            Some("mcp offline_access"),
            "rotation preserves the originally granted scope"
        );
        assert!(!store.refresh_tokens[&refresh1].current);
        assert!(store.refresh_tokens[&refresh2].current);
        assert_eq!(
            store.access_tokens[&access1].family_id,
            store.access_tokens[&access2].family_id
        );

        // Wrong client on a valid token: rejected without side effects.
        assert_eq!(
            store
                .rotate_refresh(&refresh2, Some("client-2"), TEST_RESOURCE, None, ttl, 2_500,)
                .err(),
            Some(RotateError::ClientMismatch)
        );
        assert_eq!(
            store
                .rotate_refresh(
                    &refresh2,
                    Some("client-1"),
                    "https://other.example.test",
                    None,
                    ttl,
                    2_500,
                )
                .err(),
            Some(RotateError::InvalidTarget)
        );
        assert!(
            store.refresh_tokens[&refresh2].current,
            "wrong audience must not spend the refresh token"
        );
        assert_eq!(
            store
                .rotate_refresh(
                    &refresh2,
                    Some("client-1"),
                    TEST_RESOURCE,
                    Some("mcp"),
                    ttl,
                    2_500,
                )
                .err(),
            Some(RotateError::InvalidScope)
        );
        assert!(
            store.refresh_tokens[&refresh2].current,
            "scope substitution must not spend the refresh token"
        );

        // Replay of the spent refresh1: the whole family burns.
        assert_eq!(
            store
                .rotate_refresh(&refresh1, Some("client-1"), TEST_RESOURCE, None, ttl, 3_000,)
                .err(),
            Some(RotateError::ReuseRevoked)
        );
        assert!(
            store.access_tokens.is_empty(),
            "family access tokens revoked"
        );
        assert!(
            store.refresh_tokens.is_empty(),
            "family refresh tokens revoked"
        );

        // The current-at-revocation refresh2 is now unknown.
        assert_eq!(
            store
                .rotate_refresh(&refresh2, Some("client-1"), TEST_RESOURCE, None, ttl, 3_100,)
                .err(),
            Some(RotateError::Unknown)
        );
    }

    // -- Access-token lookup ------------------------------------------------

    /// Expired access tokens 401 and are reaped by the lookup itself.
    #[test]
    fn access_token_lookup_enforces_expiry() {
        let ttl = Duration::from_secs(100);
        let mut store = OauthStore::default();
        let (access, _refresh) =
            store.mint_token_pair("alice", "mock", "client-1", TEST_RESOURCE, None, ttl, 1_000);

        let entry = store
            .lookup_access(&access, TEST_RESOURCE, 1_050)
            .expect("still valid");
        assert_eq!(
            (entry.tenant.as_str(), entry.backend.as_str()),
            ("alice", "mock")
        );
        assert_eq!(
            store
                .lookup_access(&access, "https://other.example.test", 1_050)
                .err(),
            Some(("access token is for a different resource", false))
        );

        assert_eq!(
            store.lookup_access(&access, TEST_RESOURCE, 1_100).err(),
            Some(("access token expired", true))
        );
        // The expired token was removed: a retry is now just unknown.
        assert_eq!(
            store.lookup_access(&access, TEST_RESOURCE, 1_100).err(),
            Some(("unknown token", false))
        );
        assert_eq!(
            store.lookup_access("never-issued", TEST_RESOURCE, 0).err(),
            Some(("unknown token", false))
        );
    }

    /// Tenant revocation removes every tenant-bound credential (including
    /// invites) while preserving unrelated tenants and shared client records.
    #[test]
    fn tenant_revocation_is_complete_and_scoped() {
        let ttl = Duration::from_secs(3600);
        let mut store = OauthStore::default();
        let client = store.register_client(vec!["https://a/cb".to_string()], None, 1_000);
        store.mint_invite("alice", false, None, None, 1_000);
        store.mint_invite("alice", true, None, None, 1_000);
        let bob_invite = store.mint_invite("bob", false, None, None, 1_000);
        let (alice_access, alice_refresh) =
            store.mint_token_pair("alice", "mock", &client, TEST_RESOURCE, None, ttl, 1_000);
        let (bob_access, bob_refresh) =
            store.mint_token_pair("bob", "mock", &client, TEST_RESOURCE, None, ttl, 1_000);

        let revoked = store.revoke_tenant("alice");
        assert_eq!(revoked.invites, 2);
        assert_eq!(revoked.access_tokens, 1);
        assert_eq!(revoked.refresh_tokens, 1);
        assert_eq!(revoked.authorization_generation, 1);
        assert!(!store.access_tokens.contains_key(&alice_access));
        assert!(!store.refresh_tokens.contains_key(&alice_refresh));
        assert!(store.invites.contains_key(&bob_invite));
        assert!(store.access_tokens.contains_key(&bob_access));
        assert!(store.refresh_tokens.contains_key(&bob_refresh));
        assert!(
            store.clients.contains_key(&client),
            "clients are not tenant-owned"
        );

        // Even with no persisted Alice credential left, another revoke moves
        // the generation so any still-pending authorization code stays dead.
        let again = store.revoke_tenant("alice");
        assert_eq!(
            again.invites + again.access_tokens + again.refresh_tokens,
            0
        );
        assert_eq!(again.authorization_generation, 2);
    }

    /// A separate CLI process can rewrite the OAuth file and the already-live
    /// runtime rejects the old access token and pending code on its next use,
    /// without a daemon restart. The refreshed mirror drops refresh tokens too.
    #[test]
    fn locked_tenant_revocation_is_live_in_running_runtime() {
        let dir = scratch_dir("tenant_revoke_live");
        let path = dir.join("oauth.json");
        let (access, refresh) = {
            let mut store = OauthStore::default();
            let pair = store.mint_token_pair(
                "alice",
                "mock",
                "client-1",
                TEST_RESOURCE,
                None,
                Duration::from_secs(3600),
                unix_now(),
            );
            store.save(&path).unwrap();
            pair
        };
        let runtime = OauthRuntime::new(OauthConfig {
            public_url: "https://mcp.example.test".to_string(),
            state_path: path.clone(),
            access_ttl: Duration::from_secs(3600),
        })
        .unwrap();
        let access_runtime = OauthRuntime::new(OauthConfig {
            public_url: "https://mcp.example.test".to_string(),
            state_path: path.clone(),
            access_ttl: Duration::from_secs(3600),
        })
        .unwrap();
        assert!(access_runtime.lookup_access(&access).is_ok());
        let stale_alice = TenantGrant {
            label: "alice".to_string(),
            generation: 0,
        };
        let code_before = runtime.issue_code(
            "client-1",
            "https://a/cb",
            "chal",
            &stale_alice,
            TEST_RESOURCE,
            "",
            unix_now(),
        );

        let revoked = revoke_tenant_locked(&path, "alice").unwrap();
        assert_eq!((revoked.access_tokens, revoked.refresh_tokens), (1, 1));
        // Models the tight race where authorize consumed the invite before the
        // CLI revoke, but only inserts its in-memory code afterward: the code
        // still carries the old generation and must be just as dead.
        let code_after = runtime.issue_code(
            "client-1",
            "https://a/cb",
            "chal",
            &stale_alice,
            TEST_RESOURCE,
            "",
            unix_now(),
        );

        assert!(matches!(
            runtime.take_code(&code_before, unix_now()),
            CodeTake::Unknown
        ));
        assert!(matches!(
            runtime.take_code(&code_after, unix_now()),
            CodeTake::Unknown
        ));
        assert!(matches!(
            access_runtime.lookup_access(&access),
            Err("unknown token")
        ));
        let mirror = access_runtime.store.lock().unwrap();
        assert!(!mirror.refresh_tokens.contains_key(&refresh));
        assert_eq!(mirror.tenant_generation("alice"), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- Invites ------------------------------------------------------------

    /// Single-use invites vanish on redemption; reusable ones persist.
    #[test]
    fn invite_consumption_semantics() {
        let mut store = OauthStore::default();
        let single = store.mint_invite("alice", false, None, None, 1_000);
        let multi = store.mint_invite("team", true, None, None, 1_000);

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
        let invite = store.mint_invite("alice", false, None, None, 1_001);
        let (access, refresh) = store.mint_token_pair(
            "alice",
            "mock",
            &client_id,
            TEST_RESOURCE,
            Some("mcp offline_access"),
            Duration::from_secs(60),
            1_002,
        );
        store.save(&path).expect("save");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "state file must be 0600");
        }

        let reloaded = OauthStore::load(&path).expect("reload");
        let client = reloaded.clients.get(&client_id).expect("client persisted");
        assert_eq!(
            client.redirect_uris,
            ["https://claude.ai/api/mcp/auth_callback"]
        );
        assert_eq!(client.client_name.as_deref(), Some("Claude"));
        assert_eq!(
            reloaded.invites.get(&invite).map(|i| i.tenant.as_str()),
            Some("alice")
        );
        let access_entry = reloaded
            .access_tokens
            .get(&access)
            .expect("access persisted");
        assert_eq!(access_entry.expires_at, 1_062);
        assert_eq!(access_entry.resource, TEST_RESOURCE);
        let refresh_entry = reloaded
            .refresh_tokens
            .get(&refresh)
            .expect("refresh persisted");
        assert!(refresh_entry.current);
        assert_eq!(refresh_entry.resource, TEST_RESOURCE);
        assert_eq!(refresh_entry.scope.as_deref(), Some("mcp offline_access"));
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

    #[test]
    fn resource_match_only_normalizes_an_origin_root_slash() {
        let root = "https://mcp.example.test";
        assert!(resource_matches(root, root));
        assert!(resource_matches("https://mcp.example.test/", root));

        for different in [
            "https://mcp.example.test//",
            "https://mcp.example.test/mcp",
            "https://mcp.example.test?resource=other",
            "http://mcp.example.test/",
            "https://mcp.example.test:444/",
            "https://other.example.test/",
        ] {
            assert!(
                !resource_matches(different, root),
                "must not widen the resource to {different}"
            );
        }

        let non_root = "https://mcp.example.test/mcp";
        assert!(resource_matches(non_root, non_root));
        assert!(!resource_matches("https://mcp.example.test/mcp/", non_root));
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
    fn location_query(
        response: &ureq::http::Response<ureq::Body>,
    ) -> (String, HashMap<String, String>) {
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

    /// Refresh tokens minted before scope persistence remain rotatable, but
    /// their response omits `scope`: absence truthfully means the server did
    /// not restate the grant, while an empty string would incorrectly claim an
    /// empty grant.
    #[test]
    fn legacy_refresh_without_scope_omits_scope_from_response() {
        let dir = scratch_dir("legacy_refresh_scope");
        let state_path = dir.join("oauth.json");
        let legacy: RefreshTokenEntry = serde_json::from_value(json!({
            "tenant": "alice",
            "backend": "mock",
            "client_id": "client-1",
            "resource": TEST_RESOURCE,
            "family_id": "family-1",
            "current": true,
        }))
        .expect("legacy refresh entry deserializes");
        assert_eq!(legacy.scope, None);

        let mut store = OauthStore::default();
        store
            .refresh_tokens
            .insert("legacy-refresh".to_string(), legacy);
        store.save(&state_path).expect("seed legacy OAuth state");

        let state = test_state_with_oauth(
            "https://mcp.example.test",
            &state_path,
            Duration::from_secs(3600),
        );
        let addr = spawn_server(state);
        let agent = no_redirect_agent();
        let mut response = agent
            .post(format!("http://{addr}/oauth/token"))
            .send_form([
                ("grant_type", "refresh_token"),
                ("refresh_token", "legacy-refresh"),
                ("client_id", "client-1"),
                ("resource", TEST_RESOURCE),
            ])
            .expect("rotate legacy refresh token");
        assert_eq!(response.status().as_u16(), 200);
        let body = read_json(&mut response);
        assert!(
            body.get("scope").is_none(),
            "unknown legacy scope is omitted rather than emitted as empty"
        );
        let successor = body["refresh_token"].as_str().expect("successor refresh");
        assert_eq!(
            OauthStore::load(&state_path).unwrap().refresh_tokens[successor].scope,
            None,
            "an unknown scope remains unknown across rotation"
        );

        let _ = std::fs::remove_dir_all(&dir);
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
        let protected_resource = issuer.to_string();
        let root_slash_resource = format!("{protected_resource}/");
        let state = test_state_with_oauth(issuer, &state_path, Duration::from_secs(3600));
        let addr = spawn_server(state.clone());
        let agent = no_redirect_agent();
        let redirect_uri = "https://client.example.test/callback";

        // --- 401 challenge advertises the discovery document.
        let bare = post(
            &agent,
            addr,
            None,
            None,
            None,
            &rpc(1, "initialize", json!({})),
        );
        assert_eq!(bare.status, 401);
        let mut challenge = agent
            .post(format!("http://{addr}"))
            .send_json(rpc(1, "initialize", json!({})))
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
            .get(format!(
                "http://{addr}/.well-known/oauth-protected-resource"
            ))
            .call()
            .expect("resource metadata");
        let resource = read_json(&mut resource);
        assert_eq!(resource["resource"], protected_resource);
        assert_eq!(resource["authorization_servers"], json!([issuer]));
        assert_eq!(
            resource["scopes_supported"],
            json!(["mcp", "offline_access"])
        );

        let mut auth_server = agent
            .get(format!(
                "http://{addr}/.well-known/oauth-authorization-server"
            ))
            .call()
            .expect("authorization-server metadata");
        let auth_server = read_json(&mut auth_server);
        assert_eq!(auth_server["issuer"], issuer);
        assert_eq!(
            auth_server["authorization_endpoint"],
            format!("{issuer}/oauth/authorize")
        );
        assert_eq!(
            auth_server["token_endpoint"],
            format!("{issuer}/oauth/token")
        );
        assert_eq!(
            auth_server["registration_endpoint"],
            format!("{issuer}/oauth/register")
        );
        assert_eq!(
            auth_server["code_challenge_methods_supported"],
            json!(["S256"])
        );
        assert_eq!(
            auth_server["token_endpoint_auth_methods_supported"],
            json!(["none"])
        );
        assert_eq!(
            auth_server["scopes_supported"],
            json!(["mcp", "offline_access"])
        );

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
        let client_id = registered["client_id"]
            .as_str()
            .expect("client_id")
            .to_string();
        assert_eq!(registered["redirect_uris"], json!([redirect_uri]));
        // Registration persisted to the state file on disk.
        assert!(
            OauthStore::load(&state_path)
                .unwrap()
                .clients
                .contains_key(&client_id),
            "client persisted"
        );

        // --- PKCE pair for the flow.
        let verifier = random_urlsafe(32); // 43 chars, valid verifier charset
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let requested_scope = "mcp offline_access";
        let authorize_query = |challenge: &str| {
            format!(
                "response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=xyz-123&resource={}&scope={}",
                url_encode(&client_id),
                url_encode(redirect_uri),
                url_encode(challenge),
                url_encode(&root_slash_resource),
                url_encode(requested_scope),
            )
        };

        // --- GET authorize: the invite form, self-contained HTML.
        let mut form_page = agent
            .get(format!(
                "http://{addr}/oauth/authorize?{}",
                authorize_query(&challenge)
            ))
            .call()
            .expect("authorize form");
        assert_eq!(form_page.status().as_u16(), 200);
        let html = form_page.body_mut().read_to_string().unwrap();
        assert!(
            html.contains("name=\"invite_code\""),
            "invite field present"
        );
        assert!(
            html.contains(&format!("value=\"{challenge}\"")),
            "challenge round-trips"
        );
        assert!(
            html.contains(&format!("value=\"{protected_resource}\"")),
            "resource round-trips through the consent form"
        );
        assert!(!html.contains("http-equiv"), "no external/refresh tricks");

        for resource_query in [
            String::new(),
            "&resource=https%3A%2F%2Fother.example".into(),
        ] {
            let mut wrong_resource = agent
                .get(format!(
                    "http://{addr}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256{}",
                    url_encode(&client_id),
                    url_encode(redirect_uri),
                    url_encode(&challenge),
                    resource_query,
                ))
                .call()
                .expect("invalid resource authorize response");
            assert_eq!(wrong_resource.status().as_u16(), 400);
            assert!(wrong_resource.headers().get("location").is_none());
            let _ = wrong_resource.body_mut().read_to_string();
        }

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
        assert_eq!(
            plain.status().as_u16(),
            400,
            "pre-invite failure is a page, not a redirect"
        );
        assert!(
            plain.headers().get("location").is_none(),
            "no Location off-origin"
        );
        let _ = plain.body_mut().read_to_string();

        // --- POST authorize with a minted invite → code redirect.
        // Invites are minted through the persistent (file-locked) path, the way
        // the CLI does — the server reads the on-disk store when consuming.
        let oauth = state.oauth.as_ref().expect("oauth configured");
        let invite = oauth
            .with_locked_store(|store| store.mint_invite("alice", false, None, None, unix_now()))
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
                    ("resource", root_slash_resource.as_str()),
                    ("scope", requested_scope),
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
        assert_eq!(
            oauth.codes.lock().unwrap()[&code].resource,
            protected_resource,
            "authorization code is audience-bound"
        );
        let _ = granted.body_mut().read_to_string();

        // A wrong invite is a pre-redirect failure → 400 page, not a bounce
        // off this origin (the invite gate is what earns a redirect).
        let mut denied = submit("not-an-invite", &challenge);
        assert_eq!(denied.status().as_u16(), 400);
        assert!(
            denied.headers().get("location").is_none(),
            "bad invite doesn't redirect"
        );
        let _ = denied.body_mut().read_to_string();

        // The single-use invite is spent: replaying it is a 400 page too.
        let mut reused_invite = submit(&invite, &challenge);
        assert_eq!(reused_invite.status().as_u16(), 400, "invite is single-use");
        let _ = reused_invite.body_mut().read_to_string();

        // --- Token exchange with PKCE.
        let exchange_for = |code: &str, verifier: &str, resource: &str| {
            agent
                .post(format!("http://{addr}/oauth/token"))
                .send_form([
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", client_id.as_str()),
                    ("redirect_uri", redirect_uri),
                    ("code_verifier", verifier),
                    ("resource", resource),
                ])
                .expect("token exchange")
        };
        // Codex serializes a root endpoint with `/` at token exchange. The
        // authorization code remains audience-bound to the discovery
        // document's canonical bare origin while this equivalent spelling
        // succeeds.
        let exchange =
            |code: &str, verifier: &str| exchange_for(code, verifier, root_slash_resource.as_str());
        let mut tokens = exchange(&code, &verifier);
        assert_eq!(tokens.status().as_u16(), 200);
        let tokens = read_json(&mut tokens);
        assert_eq!(tokens["token_type"], "Bearer");
        assert_eq!(tokens["expires_in"], 3600);
        assert_eq!(tokens["scope"], requested_scope);
        let access = tokens["access_token"].as_str().unwrap().to_string();
        let refresh = tokens["refresh_token"].as_str().unwrap().to_string();

        // Codes are single-use: replaying the exchange fails.
        let mut replayed = exchange(&code, &verifier);
        assert_eq!(replayed.status().as_u16(), 400);
        assert_eq!(read_json(&mut replayed)["error"], "invalid_grant");

        // --- The access token drives a real MCP handshake, tenant-scoped.
        let init = post(
            &agent,
            addr,
            Some(&access),
            None,
            None,
            &rpc(1, "initialize", json!({ "protocolVersion": "2025-06-18" })),
        );
        assert_eq!(init.status, 200, "init body: {}", init.body);
        let session = init.session.expect("session issued");
        let opened = post(
            &agent,
            addr,
            Some(&access),
            Some(&session),
            None,
            &rpc(
                2,
                "tools/call",
                json!({ "name": "open_session", "arguments": { "pile_host_path": "/tmp/alice/self.pile" } }),
            ),
        );
        assert_eq!(opened.status, 200);
        // The invite's tenant flowed through: the sandbox session is alice's.
        assert_eq!(opened.body["result"]["content"][0]["text"], "mock-alice");

        // Static tokens keep working, byte-for-byte, next to OAuth.
        let static_init = post(
            &agent,
            addr,
            Some("tok-alice"),
            None,
            None,
            &rpc(3, "initialize", json!({})),
        );
        assert_eq!(static_init.status, 200);

        // --- Wrong verifier burns its (fresh) code and yields invalid_grant.
        let invite2 = oauth
            .with_locked_store(|store| store.mint_invite("bob", false, None, None, unix_now()))
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

        // The token request must repeat the exact RFC 8707 audience captured
        // by authorize. A substituted audience fails and consumes the code.
        let invite3 = oauth
            .with_locked_store(|store| store.mint_invite("carol", false, None, None, unix_now()))
            .expect("mint invite3");
        let mut granted3 = submit(&invite3, &challenge);
        let (_, query) = location_query(&granted3);
        let code3 = query["code"].clone();
        let _ = granted3.body_mut().read_to_string();
        let mut wrong_target = exchange_for(&code3, &verifier, "https://other.example.test");
        assert_eq!(wrong_target.status().as_u16(), 400);
        assert_eq!(read_json(&mut wrong_target)["error"], "invalid_target");
        let mut burned = exchange(&code3, &verifier);
        assert_eq!(read_json(&mut burned)["error"], "invalid_grant");

        // --- Expired access tokens 401 with the discovery challenge.
        // Minted at now=0 (expired an hour past the epoch), through the locked
        // path so it survives the mirror-refresh that every server write does.
        let stale = oauth
            .with_locked_store(|store| {
                store
                    .mint_token_pair(
                        "alice",
                        "mock",
                        &client_id,
                        TEST_RESOURCE,
                        None,
                        Duration::from_secs(3600),
                        0,
                    )
                    .0
            })
            .expect("mint stale token");
        let expired = post(
            &agent,
            addr,
            Some(&stale),
            None,
            None,
            &rpc(4, "initialize", json!({})),
        );
        assert_eq!(expired.status, 401);
        let mut expired_raw = agent
            .post(format!("http://{addr}"))
            .header("Authorization", format!("Bearer {stale}"))
            .send_json(rpc(4, "initialize", json!({})))
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
        let rotate_for = |refresh: &str, resource: &str| {
            agent
                .post(format!("http://{addr}/oauth/token"))
                .send_form([
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh),
                    ("client_id", client_id.as_str()),
                    ("resource", resource),
                ])
                .expect("refresh")
        };
        let rotate = |refresh: &str| rotate_for(refresh, root_slash_resource.as_str());
        let mut wrong_target = rotate_for(&refresh, "https://other.example.test");
        assert_eq!(wrong_target.status().as_u16(), 400);
        assert_eq!(read_json(&mut wrong_target)["error"], "invalid_target");
        let mut rotated = rotate(&refresh);
        assert_eq!(rotated.status().as_u16(), 200);
        let rotated = read_json(&mut rotated);
        assert_eq!(
            rotated["scope"], requested_scope,
            "refresh rotation preserves the authorization's offline_access scope"
        );
        let access2 = rotated["access_token"].as_str().unwrap().to_string();
        let refresh2 = rotated["refresh_token"].as_str().unwrap().to_string();
        assert_ne!(refresh2, refresh, "refresh token rotates");

        // The rotated-in access token works...
        let init2 = post(
            &agent,
            addr,
            Some(&access2),
            None,
            None,
            &rpc(5, "initialize", json!({})),
        );
        assert_eq!(init2.status, 200);

        // ...until the spent refresh token is replayed: family revoked.
        let mut replay = rotate(&refresh);
        assert_eq!(replay.status().as_u16(), 400);
        assert_eq!(read_json(&mut replay)["error"], "invalid_grant");
        let revoked_new = post(
            &agent,
            addr,
            Some(&access2),
            None,
            None,
            &rpc(6, "initialize", json!({})),
        );
        assert_eq!(
            revoked_new.status, 401,
            "family revocation kills the newest access token"
        );
        let revoked_old = post(
            &agent,
            addr,
            Some(&access),
            None,
            None,
            &rpc(7, "initialize", json!({})),
        );
        assert_eq!(revoked_old.status, 401, "and the original one");
        let mut dead_refresh = rotate(&refresh2);
        assert_eq!(
            dead_refresh.status().as_u16(),
            400,
            "successor refresh died with the family"
        );
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
                (
                    "code_verifier",
                    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                ),
            ])
            .expect("bogus code");
        assert_eq!(bogus_code.status().as_u16(), 400);
        assert_eq!(read_json(&mut bogus_code)["error"], "invalid_grant");

        let mut bogus_refresh = agent
            .post(format!("http://{addr}/oauth/token"))
            .send_form([
                ("grant_type", "refresh_token"),
                ("refresh_token", "never-issued"),
                ("resource", TEST_RESOURCE),
            ])
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
        assert_eq!(
            (status, body["error"].as_str()),
            (400, Some("invalid_client_metadata"))
        );

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
        assert!(
            body.get("client_secret").is_none(),
            "public client has no secret"
        );

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
        assert_eq!(
            register("http://evil.example.com/cb"),
            400,
            "plain http public rejected"
        );
        assert_eq!(register("ftp://a/cb"), 400, "non-http scheme rejected");
        assert_eq!(
            register("com.example.app://cb"),
            400,
            "custom app scheme rejected"
        );

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

        // Fill to the cap directly in the store (fast).
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
        assert_eq!(
            removed, 1,
            "only the stale, never-authorized client is GC'd"
        );
        let survivors = runtime.store.lock().unwrap().clients.len();
        assert_eq!(survivors, 2, "authorized and fresh clients survive GC");

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
            let (a, r) = store.mint_token_pair(
                "alice",
                "mock",
                "client-1",
                TEST_RESOURCE,
                None,
                Duration::from_secs(3600),
                1_000,
            );
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
            let _ = store.rotate_refresh(
                &refresh,
                Some("client-1"),
                TEST_RESOURCE,
                None,
                Duration::from_secs(3600),
                2_000,
            );
            let err = store
                .rotate_refresh(
                    &refresh,
                    Some("client-1"),
                    TEST_RESOURCE,
                    None,
                    Duration::from_secs(3600),
                    2_100,
                )
                .err();
            assert_eq!(err, Some(RotateError::ReuseRevoked));
            (true, ())
        })
        .unwrap();

        // On-disk, the family is gone.
        let after_revoke = OauthStore::load(&path).unwrap();
        assert!(
            !after_revoke
                .access_tokens
                .values()
                .any(|e| e.family_id == family_id)
        );

        // Now the CLI writer commits *its* mutation. Because it goes through the
        // SAME locked re-read primitive (not a blind write of `stale_snapshot`),
        // it starts from the server's revoked state and only ADDS an invite —
        // the revoked family is NOT resurrected.
        let _invite = mint_invite_locked(&path, "bob", false, None, None, 3_000).unwrap();

        let final_state = OauthStore::load(&path).unwrap();
        assert!(
            !final_state
                .access_tokens
                .values()
                .any(|e| e.family_id == family_id),
            "revoked family stays dead after a concurrent invite write"
        );
        assert!(
            !final_state
                .refresh_tokens
                .values()
                .any(|e| e.family_id == family_id),
            "revoked refresh family stays dead too"
        );
        assert_eq!(final_state.invites.len(), 1, "the invite write did land");
        // Demonstrate the counterfactual: a BLIND write of the stale snapshot
        // *would* have resurrected the family — proving the lock is load-bearing.
        stale_snapshot.save(&path).unwrap();
        assert!(
            OauthStore::load(&path)
                .unwrap()
                .access_tokens
                .contains_key(&access),
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
        let state = test_state_with_oauth(
            "https://mcp.example.test",
            &state_path,
            Duration::from_secs(3600),
        );
        let addr = spawn_server(state.clone());
        let agent = no_redirect_agent();

        // Attacker registers a client pointing at attacker-controlled evil.com.
        let mut registered = agent
            .post(format!("http://{addr}/oauth/register"))
            .send_json(json!({ "redirect_uris": ["https://evil.example.com/steal"] }))
            .expect("register");
        let client_id = read_json(&mut registered)["client_id"]
            .as_str()
            .unwrap()
            .to_string();

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
        assert!(
            r1.headers().get("location").is_none(),
            "no Location to evil.com"
        );
        let _ = r1.body_mut().read_to_string();

        // Non-S256 PKCE method.
        let mut r2 = bad_param(format!(
            "response_type=code&client_id={}&redirect_uri={}&code_challenge=x&code_challenge_method=plain",
            url_encode(&client_id),
            url_encode("https://evil.example.com/steal"),
        ));
        assert_eq!(r2.status().as_u16(), 400, "plain PKCE is a 400 page");
        assert!(
            r2.headers().get("location").is_none(),
            "no Location to evil.com"
        );
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
        assert!(
            r3.headers().get("location").is_none(),
            "bad invite doesn't redirect off-origin"
        );
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

    // -- repair #5 HIGH: no write on no-op/error OAuth paths -----------------

    /// An unauthenticated garbage `refresh_token` and an invalid `invite_code`
    /// perform NO write to the state file — the byte content and mtime are
    /// unchanged — so an attacker cannot use them to force full-file rewrites
    /// (write amplification). A genuine mutation still writes (control).
    #[test]
    fn no_op_oauth_paths_perform_no_write() {
        let dir = scratch_dir("nowrite");
        let path = dir.join("oauth.json");

        // Seed a real family so the file exists with content.
        {
            let mut store = OauthStore::default();
            store.mint_token_pair(
                "alice",
                "mock",
                "client-1",
                TEST_RESOURCE,
                None,
                Duration::from_secs(3600),
                1_000,
            );
            store.save(&path).unwrap();
        }
        let read_all = || std::fs::read(&path).unwrap();
        let mtime = || std::fs::metadata(&path).unwrap().modified().unwrap();

        let before_bytes = read_all();
        let before_mtime = mtime();
        // Sleep so a real write would move the (coarse-resolution) mtime.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Unknown refresh token: rotate_refresh returns Unknown, no mutation.
        {
            let (_store, _fingerprint, result) = mutate_state_locked(&path, |store| {
                match store.rotate_refresh(
                    "never-issued",
                    None,
                    TEST_RESOURCE,
                    None,
                    Duration::from_secs(3600),
                    2_000,
                ) {
                    Ok(r) => (true, Ok(r)),
                    Err(RotateError::ReuseRevoked) => (true, Err(RotateError::ReuseRevoked)),
                    Err(other) => (false, Err(other)),
                }
            })
            .unwrap();
            assert_eq!(result.err(), Some(RotateError::Unknown));
        }
        assert_eq!(read_all(), before_bytes, "unknown refresh wrote nothing");
        assert_eq!(
            mtime(),
            before_mtime,
            "unknown refresh left mtime untouched"
        );

        // Invalid invite consume: consume_invite returns None, no mutation.
        {
            let (_store, _fingerprint, wrote) = mutate_state_locked(&path, |store| {
                let consumed = store.consume_invite("never-minted");
                (consumed.is_some(), consumed)
            })
            .unwrap();
            assert!(wrote.is_none(), "invalid invite consumed nothing");
        }
        assert_eq!(read_all(), before_bytes, "invalid invite wrote nothing");
        assert_eq!(mtime(), before_mtime, "invalid invite left mtime untouched");

        // Control: a real invite mint DOES write (mtime advances, bytes change).
        mint_invite_locked(&path, "bob", false, None, None, 3_000).unwrap();
        assert_ne!(read_all(), before_bytes, "a real mint does write");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- repair #5 HIGH: invite bound to expected client / redirect ----------

    /// A client/redirect-bound invite is only redeemable by the matching
    /// authorize request: a mismatched redirect (or client) is refused with a
    /// 400 page and the invite is NOT consumed; the matching request redeems it.
    #[test]
    fn invite_binding_enforced_and_no_consume_on_mismatch() {
        let dir = scratch_dir("invitebind");
        let state_path = dir.join("oauth.json");
        let issuer = "https://mcp.example.test";
        let state = test_state_with_oauth(issuer, &state_path, Duration::from_secs(3600));
        let addr = spawn_server(state.clone());
        let agent = no_redirect_agent();
        let good_redirect = "https://client.example.test/callback";

        // Register a client with TWO registered redirect URIs — both pass the
        // client-redirect check, so the invite BINDING is what distinguishes them.
        let other_redirect = "https://client.example.test/other";
        let mut registered = agent
            .post(format!("http://{addr}/oauth/register"))
            .send_json(json!({ "redirect_uris": [good_redirect, other_redirect] }))
            .expect("register");
        let client_id = read_json(&mut registered)["client_id"]
            .as_str()
            .unwrap()
            .to_string();

        // Mint an invite BOUND to this client + the good redirect.
        let oauth = state.oauth.as_ref().unwrap();
        let invite = oauth
            .with_locked_store(|store| {
                store.mint_invite(
                    "alice",
                    false,
                    Some(client_id.clone()),
                    Some(good_redirect.to_string()),
                    unix_now(),
                )
            })
            .expect("mint bound invite");

        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; // valid S256 shape
        let submit = |redirect: &str| {
            agent
                .post(format!("http://{addr}/oauth/authorize"))
                .send_form([
                    ("response_type", "code"),
                    ("client_id", client_id.as_str()),
                    ("redirect_uri", redirect),
                    ("code_challenge", challenge),
                    ("code_challenge_method", "S256"),
                    ("state", "s"),
                    ("resource", TEST_RESOURCE),
                    ("scope", "mcp"),
                    ("invite_code", invite.as_str()),
                ])
                .expect("authorize submit")
        };

        // Mismatched (but registered) redirect: refused with a 400 page, no
        // redirect off-origin, and the invite is NOT consumed.
        let mut wrong = submit(other_redirect);
        assert_eq!(
            wrong.status().as_u16(),
            400,
            "invite bound to a different redirect is refused"
        );
        assert!(
            wrong.headers().get("location").is_none(),
            "no redirect on a binding mismatch"
        );
        let _ = wrong.body_mut().read_to_string();
        assert!(
            OauthStore::load(&state_path)
                .unwrap()
                .invites
                .values()
                .any(|i| i.tenant == "alice"),
            "the invite survives a mismatched attempt (not consumed)"
        );

        // Matching redirect: redeems, 302 with a code, and the invite is spent.
        let mut ok = submit(good_redirect);
        assert_eq!(
            ok.status().as_u16(),
            302,
            "matching client+redirect redeems the bound invite"
        );
        let (base, query) = location_query(&ok);
        assert_eq!(base, good_redirect);
        assert!(query.contains_key("code"), "an auth code was issued");
        let _ = ok.body_mut().read_to_string();
        assert!(
            OauthStore::load(&state_path).unwrap().invites.is_empty(),
            "the single-use bound invite is consumed on success"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- repair #5 HIGH: consent page shows client + redirect + anti-framing --

    /// The consent page names the requesting client (registered name) and the
    /// redirect host, and carries anti-framing headers so it cannot be
    /// clickjacked.
    #[test]
    fn consent_page_shows_client_and_redirect_and_anti_framing() {
        let dir = scratch_dir("consent");
        let issuer = "https://mcp.example.test";
        let state =
            test_state_with_oauth(issuer, &dir.join("oauth.json"), Duration::from_secs(3600));
        let addr = spawn_server(state);
        let agent = no_redirect_agent();
        let redirect_uri = "https://connector.example.org/mcp/callback";

        let mut registered = agent
            .post(format!("http://{addr}/oauth/register"))
            .send_json(json!({
                "redirect_uris": [redirect_uri],
                "client_name": "Acme Connector",
            }))
            .expect("register");
        let client_id = read_json(&mut registered)["client_id"]
            .as_str()
            .unwrap()
            .to_string();

        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let mut form_page = agent
            .get(format!(
                "http://{addr}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&resource={}",
                url_encode(&client_id),
                url_encode(redirect_uri),
                url_encode(challenge),
                url_encode(TEST_RESOURCE),
            ))
            .call()
            .expect("authorize form");
        assert_eq!(form_page.status().as_u16(), 200);

        // Anti-framing headers present.
        assert_eq!(
            form_page
                .headers()
                .get("x-frame-options")
                .unwrap()
                .to_str()
                .unwrap(),
            "DENY"
        );
        assert!(
            form_page
                .headers()
                .get("content-security-policy")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'"),
            "CSP forbids framing"
        );

        let html = form_page.body_mut().read_to_string().unwrap();
        assert!(
            html.contains("Acme Connector"),
            "consent page names the client"
        );
        assert!(
            html.contains(&client_id),
            "consent page shows the client_id"
        );
        assert!(
            html.contains("https://connector.example.org"),
            "consent page shows the redirect host"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
