#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! triblespace = "0.33"
//! ed25519-dalek = { version = "2.1.0", features = ["rand_core"] }
//! rand = "0.8"
//! anyhow = "1"
//! clap = { version = "4", features = ["derive", "env"] }
//! hex = "0.4"
//! ```

use anyhow::{anyhow, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use triblespace::prelude::*;
use triblespace::core::repo::Workspace;

fn hex_to_raw(hex_str: &str) -> [u8; 16] {
    let mut id = [0u8; 16];
    hex::decode_to_slice(hex_str, &mut id).expect("valid hex");
    id
}

/// Build the full migration map: old attr ID → canonical attr ID.
/// Returns (full_map, missed_set) where missed_set contains attrs that
/// have mixed LE/OBE data and need commit-era-based classification.
fn build_maps() -> (HashMap<[u8; 16], [u8; 16]>, HashSet<[u8; 16]>) {
    let mut map = HashMap::new();
    let mut missed = HashSet::new();

    // ── Canonical metadata targets ──
    let created_at = hex_to_raw("9B1E79DFD065F643954141593CD8B9E0");
    let updated_at = hex_to_raw("93B7372E3443063392CD801B03A8D390");
    let started_at = hex_to_raw("06973030ACA83A7B2B4FC8BEBB31F77A");
    let finished_at = hex_to_raw("9B06AA4060EF9928A923FC7E6A6B6438");
    let expires_at = hex_to_raw("89FEC3B560336BA88B10759DECD3155F");

    // ── Domain-specific targets (newly minted) ──
    let source_created_at = hex_to_raw("D59247F3AADD3DE8E23B01E8B7406020");
    let imported_at = hex_to_raw("3765160CC1A96BE38302B344718E4C49");
    let orient_at = hex_to_raw("EB687567424358B8780A561EA900513C");

    // ── ORDERED per-faculty attrs → canonical metadata ──
    // Values are always OBE (created by first migration). Just remap attr ID.

    for old in [
        "59FA7C04A43B96F31414D1B4544FAEC2", // memory/archive created_at
        "E915C4D678D0F484B89B4E85E55DB442", // compass created_at
        "5FA453867880877B613B7632A233419B", // local_messages/triage created_at
        "79C9CB4C48864D28B215D4264E1037BF", // reason created_at
        "4036F38AB05D26764A1E5E456337F399", // memory/triage context created_at
        "1AE17985F2AE74631CE16FD84DC97FB4", // triage cog created_at
    ] {
        map.insert(hex_to_raw(old), created_at);
    }

    for old in ["5E32E36AD28B0B1E035D2DFCC20A3DC5"] {
        map.insert(hex_to_raw(old), updated_at);
    }

    for old in [
        "CCFAE38E0C70AFBBF7223D2DA28A93C7",
        "D1384E835F1C325249A603D93CA2701D",
    ] {
        map.insert(hex_to_raw(old), started_at);
    }

    for old in [
        "3BB7917C5E41E494FECE36FFE79FEF23",
        "2A98AB108752C0C0C6355B84871932DA",
    ] {
        map.insert(hex_to_raw(old), finished_at);
    }

    // ── MISSED / ERA-DEPENDENT attrs ──
    // Values have mixed LE/OBE — need commit-era classification.
    // Includes 3 per-faculty attrs that were NOT first-migration targets
    // (wiki, web, teams) plus 3 domain-specific attrs.

    let missed_entries = [
        // Per-faculty attrs NOT in first migration (era-dependent, map to metadata)
        ("476F6E26FCA65A0B49E38CC44CF31467", created_at),     // wiki created_at
        ("283A66F0FCF94EBCB04DEBF323D2B30D", created_at),     // web created_at
        ("706CC590BF4684CA8FA00E4123C43124", expires_at),      // teams expires_at
        // Domain-specific attrs (newly minted targets)
        ("F672605621E56674127FD210CFFDFF2A", source_created_at),
        ("EA8B5429A86AF26D2B87F169AFEE3919", imported_at),
        ("077630536F9D01DBE64320D7044D55A5", orient_at),
    ];

    for (old_hex, target) in missed_entries {
        let old = hex_to_raw(old_hex);
        map.insert(old, target);
        missed.insert(old);
    }

    (map, missed)
}

const SIGN_BIT: u128 = 1u128 << 127;

fn i128_to_ordered_be(v: i128) -> [u8; 16] {
    ((v as u128) ^ SIGN_BIT).to_be_bytes()
}

fn i128_from_ordered_be(bytes: [u8; 16]) -> i128 {
    (u128::from_be_bytes(bytes) ^ SIGN_BIT) as i128
}

/// Reasonable TAI nanosecond range: 1900–2100.
/// LE/OBE misinterpretation gives values ~±1e20, so any positive
/// value below 6.4e18 is unambiguously a valid timestamp.
fn is_reasonable_tai_ns(v: i128) -> bool {
    v > 0 && v < 6_400_000_000_000_000_000
}

/// Check if an NsTAIInterval value is clearly LE, clearly OBE, or ambiguous.
fn classify_value(value: &[u8; 32]) -> Option<bool> {
    let lower_le = i128::from_le_bytes(value[0..16].try_into().unwrap());
    let lower_obe = i128_from_ordered_be(value[0..16].try_into().unwrap());
    match (is_reasonable_tai_ns(lower_le), is_reasonable_tai_ns(lower_obe)) {
        (true, false) => Some(true),   // clearly LE
        (false, true) => Some(false),  // clearly OBE
        _ => None,                     // ambiguous
    }
}

fn le_to_obe(value: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let lower = i128::from_le_bytes(value[0..16].try_into().unwrap());
    let upper = i128::from_le_bytes(value[16..32].try_into().unwrap());
    result[0..16].copy_from_slice(&i128_to_ordered_be(lower));
    result[16..32].copy_from_slice(&i128_to_ordered_be(upper));
    result
}

/// Classify a commit as LE-era or OBE-era by checking its content for
/// MISSED attr values. Returns Some(true) for LE, Some(false) for OBE,
/// None if no MISSED attrs found or all values are ambiguous.
fn classify_commit_by_content(
    content: &TribleSet,
    missed_attrs: &HashSet<[u8; 16]>,
) -> Option<bool> {
    for trible in content.iter() {
        let attr: [u8; 16] = trible.data[16..32].try_into().unwrap();
        if missed_attrs.contains(&attr) {
            let value: [u8; 32] = trible.data[32..64].try_into().unwrap();
            if let Some(is_le) = classify_value(&value) {
                return Some(is_le);
            }
        }
    }
    None
}

/// Walk the commit DAG in reverse (head → roots), classify each commit
/// as LE-era (true) or OBE-era (false) by content inspection + chain
/// propagation. Returns two sets of commit handles.
fn classify_commits<B: BlobStore<valueschemas::Blake3>>(
    ws: &mut Workspace<B>,
    all_commits: &[[u8; 32]],
    missed_attrs: &HashSet<[u8; 16]>,
) -> Result<(Vec<CommitHandle>, Vec<CommitHandle>)> {
    // Build parent mapping and per-commit content classification.
    let mut children: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    let mut parents_of: HashMap<[u8; 32], Vec<[u8; 32]>> = HashMap::new();
    let mut classification: HashMap<[u8; 32], bool> = HashMap::new();

    for raw in all_commits {
        let handle = CommitHandle::new(*raw);
        let meta: TribleSet = ws.get(handle)
            .map_err(|e| anyhow!("get commit meta: {e:?}"))?;

        // Extract parent handles.
        let mut commit_parents = Vec::new();
        for trible in meta.iter() {
            let attr: [u8; 16] = trible.data[16..32].try_into().unwrap();
            // parent attr: 317044B612C690000D798CA660ECFD2A
            if attr == [0x31, 0x70, 0x44, 0xB6, 0x12, 0xC6, 0x90, 0x00,
                        0x0D, 0x79, 0x8C, 0xA6, 0x60, 0xEC, 0xFD, 0x2A] {
                let parent_raw: [u8; 32] = trible.data[32..64].try_into().unwrap();
                commit_parents.push(parent_raw);
                children.entry(parent_raw).or_default().push(*raw);
            }
        }
        parents_of.insert(*raw, commit_parents);

        // Try to classify by content.
        let content_checkout = ws.checkout(handle)
            .map_err(|e| anyhow!("checkout commit: {e:?}"))?;
        // Get just this commit's contribution by checking for MISSED attrs.
        if let Some(is_le) = classify_commit_by_content(&content_checkout, missed_attrs) {
            classification.insert(*raw, is_le);
        }
    }

    // Propagate: walk from roots (commits with no parents in our set).
    // A commit inherits LE from its parent unless it or a descendant is
    // classified as OBE. The encoding change is monotonic: once OBE, stays OBE.
    let commit_set: HashSet<[u8; 32]> = all_commits.iter().copied().collect();
    let roots: Vec<[u8; 32]> = all_commits.iter()
        .filter(|c| parents_of.get(*c).map_or(true, |ps| ps.iter().all(|p| !commit_set.contains(p))))
        .copied()
        .collect();

    let mut era: HashMap<[u8; 32], bool> = HashMap::new();
    let mut queue = std::collections::VecDeque::new();
    for root in &roots {
        // Roots default to LE unless classified otherwise.
        let is_le = classification.get(root).copied().unwrap_or(true);
        era.insert(*root, is_le);
        queue.push_back(*root);
    }

    while let Some(commit) = queue.pop_front() {
        let parent_era = era[&commit];
        if let Some(kids) = children.get(&commit) {
            for kid in kids {
                if let Some(existing) = era.get(kid) {
                    // Already visited — but if this parent is OBE, flip child
                    // to OBE too (monotonic: once OBE, stays OBE).
                    if !parent_era && *existing {
                        era.insert(*kid, false);
                        queue.push_back(*kid); // re-propagate
                    }
                    continue;
                }
                // Child inherits parent era, unless it's classified differently.
                let kid_era = if let Some(&classified) = classification.get(kid) {
                    // If parent is OBE, child must be OBE (monotonic).
                    if !parent_era { false } else { classified }
                } else {
                    parent_era
                };
                era.insert(*kid, kid_era);
                queue.push_back(*kid);
            }
        }
    }

    // Handle any unreachable commits (shouldn't happen, but be safe).
    for raw in all_commits {
        era.entry(*raw).or_insert(true); // default LE
    }

    let mut le_handles = Vec::new();
    let mut obe_handles = Vec::new();
    for raw in all_commits {
        let handle = CommitHandle::new(*raw);
        if era[raw] {
            le_handles.push(handle);
        } else {
            obe_handles.push(handle);
        }
    }

    Ok((le_handles, obe_handles))
}

#[derive(Parser)]
#[command(about = "Migrate timestamps to canonical attributes via new branches")]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Report what would change without writing.
    #[arg(long)]
    dry_run: bool,
    /// Suffix for new branch names (default: "-v2").
    #[arg(long, default_value = "-v2")]
    suffix: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (migration_map, missed_attrs) = build_maps();

    let mut pile: Pile<valueschemas::Blake3> = Pile::open(&cli.pile)
        .map_err(|e| anyhow!("open pile: {e:?}"))?;
    pile.restore().map_err(|e| anyhow!("restore: {e:?}"))?;

    let branch_ids: Vec<Id> = pile.branches()
        .map_err(|e| anyhow!("branches: {e:?}"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("branch iter: {e:?}"))?;

    // Resolve branch names before wrapping in Repository.
    let mut branch_names: HashMap<Id, String> = HashMap::new();
    for &id in &branch_ids {
        if let Ok(Some(meta_handle)) = pile.head(id) {
            let reader = pile.reader().map_err(|e| anyhow!("reader: {e:?}"))?;
            let meta: TribleSet = reader.get(meta_handle)
                .map_err(|e| anyhow!("get branch meta: {e:?}"))?;
            for trible in meta.iter() {
                let attr: [u8; 16] = trible.data[16..32].try_into().unwrap();
                // metadata::name attr: 7FB28C0B48E1924687857310EE230414
                if attr == [0x7F, 0xB2, 0x8C, 0x0B, 0x48, 0xE1, 0x92, 0x46,
                            0x87, 0x85, 0x73, 0x10, 0xEE, 0x23, 0x04, 0x14] {
                    let raw: [u8; 32] = trible.data[32..64].try_into().unwrap();
                    let name_handle = Value::<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>::new(raw);
                    if let Ok(name_view) = reader.get::<View<str>, _>(name_handle) {
                        branch_names.insert(id, name_view.to_string());
                    }
                    break;
                }
            }
        }
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let mut repo = Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|e| anyhow!("repo: {e:?}"))?;

    let mut total_le = 0usize;
    let mut total_obe = 0usize;

    for branch_id in &branch_ids {
        let mut ws = match repo.pull(*branch_id) {
            Ok(ws) => ws,
            Err(e) => { eprintln!("skip {branch_id:X}: {e:?}"); continue; }
        };

        // 1. Collect all commit handles.
        let all_checkout = match ws.checkout(..) {
            Ok(c) => c,
            Err(e) => { eprintln!("skip {branch_id:X}: {e:?}"); continue; }
        };
        let all_raws: Vec<[u8; 32]> = all_checkout.commits().iter().copied().collect();
        drop(all_checkout);

        if all_raws.is_empty() { continue; }

        // 2. Classify commits by chain structure.
        let (le_handles, obe_handles) = match classify_commits(&mut ws, &all_raws, &missed_attrs) {
            Ok(r) => r,
            Err(e) => { eprintln!("skip {branch_id:X}: classify: {e}"); continue; }
        };

        let name = branch_names.get(branch_id).map(|s| s.as_str()).unwrap_or("?");
        println!("branch {branch_id:X} ({name}): {} commits ({} LE-era, {} OBE-era)",
            all_raws.len(), le_handles.len(), obe_handles.len());

        // 3. Sanity check: verify the boundary is clean for MISSED attrs.
        if !le_handles.is_empty() || !obe_handles.is_empty() {
            let mut le_clear_le = 0usize;
            let mut le_clear_obe = 0usize;
            let mut le_ambiguous = 0usize;
            let mut obe_clear_le = 0usize;
            let mut obe_clear_obe = 0usize;
            let mut obe_ambiguous = 0usize;

            if !le_handles.is_empty() {
                let le_c = ws.checkout(le_handles.clone())
                    .map_err(|e| anyhow!("sanity LE {branch_id:X}: {e:?}"))?;
                for trible in le_c.iter() {
                    let attr: [u8; 16] = trible.data[16..32].try_into().unwrap();
                    if missed_attrs.contains(&attr) {
                        let value: [u8; 32] = trible.data[32..64].try_into().unwrap();
                        match classify_value(&value) {
                            Some(true) => le_clear_le += 1,
                            Some(false) => le_clear_obe += 1,
                            None => le_ambiguous += 1,
                        }
                    }
                }
            }

            if !obe_handles.is_empty() {
                let obe_c = ws.checkout(obe_handles.clone())
                    .map_err(|e| anyhow!("sanity OBE {branch_id:X}: {e:?}"))?;
                for trible in obe_c.iter() {
                    let attr: [u8; 16] = trible.data[16..32].try_into().unwrap();
                    if missed_attrs.contains(&attr) {
                        let value: [u8; 32] = trible.data[32..64].try_into().unwrap();
                        match classify_value(&value) {
                            Some(true) => obe_clear_le += 1,
                            Some(false) => obe_clear_obe += 1,
                            None => obe_ambiguous += 1,
                        }
                    }
                }
            }

            let le_total = le_clear_le + le_clear_obe + le_ambiguous;
            let obe_total = obe_clear_le + obe_clear_obe + obe_ambiguous;
            if le_total + obe_total > 0 {
                println!("  sanity: LE-era MISSED: {le_clear_le} LE, {le_clear_obe} OBE(!), {le_ambiguous} ambiguous");
                println!("  sanity: OBE-era MISSED: {obe_clear_le} LE(!), {obe_clear_obe} OBE, {obe_ambiguous} ambiguous");
                if le_clear_obe > 0 {
                    eprintln!("  WARNING: {le_clear_obe} clearly-OBE values in LE-era commits!");
                }
                if obe_clear_le > 0 {
                    eprintln!("  WARNING: {obe_clear_le} clearly-LE values in OBE-era commits!");
                }
            }
        }

        // 4. Process LE-era commits.
        let mut migrated = TribleSet::new();
        let mut le_count = 0usize;
        let mut obe_count = 0usize;
        let mut min_ts: i128 = i128::MAX;
        let mut max_ts: i128 = i128::MIN;

        if !le_handles.is_empty() {
            let le_checkout = ws.checkout(le_handles)
                .map_err(|e| anyhow!("checkout LE {branch_id:X}: {e:?}"))?;
            for trible in le_checkout.iter() {
                let attr: [u8; 16] = trible.data[16..32].try_into().unwrap();
                if let Some(new_attr) = migration_map.get(&attr) {
                    let value: [u8; 32] = trible.data[32..64].try_into().unwrap();
                    let entity = Id::new(trible.data[0..16].try_into().unwrap()).unwrap();
                    let new_attr_id = Id::new(*new_attr).unwrap();
                    // ORDERED attrs are already OBE (from first migration);
                    // MISSED attrs in LE-era commits are LE → convert.
                    let new_value = if missed_attrs.contains(&attr) {
                        le_to_obe(&value)
                    } else {
                        // ORDERED: already OBE — validate (wide range: 1900–2100)
                        let decoded = i128_from_ordered_be(value[0..16].try_into().unwrap());
                        if decoded < 0 || decoded > 6_400_000_000_000_000_000 {
                            eprintln!("  WARNING: ORDERED value decodes to out-of-range timestamp: {decoded}");
                        }
                        value
                    };
                    let ts = i128_from_ordered_be(new_value[0..16].try_into().unwrap());
                    min_ts = min_ts.min(ts);
                    max_ts = max_ts.max(ts);
                    le_count += 1;
                    let val = Value::<valueschemas::NsTAIInterval>::new(new_value);
                    migrated.insert(&Trible::force(&entity, &new_attr_id, &val));
                }
            }
        }

        // 5. Process OBE-era commits — all values are OBE, just remap.
        if !obe_handles.is_empty() {
            let obe_checkout = ws.checkout(obe_handles)
                .map_err(|e| anyhow!("checkout OBE {branch_id:X}: {e:?}"))?;
            for trible in obe_checkout.iter() {
                let attr: [u8; 16] = trible.data[16..32].try_into().unwrap();
                if let Some(new_attr) = migration_map.get(&attr) {
                    let value: [u8; 32] = trible.data[32..64].try_into().unwrap();
                    let entity = Id::new(trible.data[0..16].try_into().unwrap()).unwrap();
                    let new_attr_id = Id::new(*new_attr).unwrap();
                    let ts = i128_from_ordered_be(value[0..16].try_into().unwrap());
                    min_ts = min_ts.min(ts);
                    max_ts = max_ts.max(ts);
                    obe_count += 1;
                    let val = Value::<valueschemas::NsTAIInterval>::new(value);
                    migrated.insert(&Trible::force(&entity, &new_attr_id, &val));
                }
            }
        }

        let total = le_count + obe_count;
        if total == 0 { continue; }

        // Convert TAI ns to approximate year for display.
        let tai_to_year = |ns: i128| -> f64 { 1900.0 + (ns as f64) / 365.25 / 86400.0 / 1e9 };
        println!("  → {total} timestamps ({le_count} from LE-era, {obe_count} from OBE-era)");
        println!("  → range: {:.1}–{:.1}", tai_to_year(min_ts), tai_to_year(max_ts));

        if !cli.dry_run {
            // 5. Create new branch and commit.
            let old_name = branch_names.get(branch_id)
                .map(|s| s.as_str())
                .unwrap_or("unknown");
            let new_name = format!("{old_name}{}", cli.suffix);

            // Idempotency: skip if branch already exists.
            match repo.lookup_branch(&new_name) {
                Ok(Some(_)) => {
                    println!("  → branch {new_name} already exists, skipping");
                    total_le += le_count;
                    total_obe += obe_count;
                    continue;
                }
                Ok(None) => {} // good, doesn't exist
                Err(e) => { eprintln!("  lookup {new_name}: {e:?}"); }
            }

            let new_branch_id = repo.create_branch(&new_name, None)
                .map_err(|e| anyhow!("create branch: {e:?}"))?;
            let mut new_ws = repo.pull(*new_branch_id)
                .map_err(|e| anyhow!("pull new branch: {e:?}"))?;
            new_ws.commit(migrated, "migrate timestamps to canonical attrs");
            repo.push(&mut new_ws).map_err(|e| anyhow!("push: {e:?}"))?;
            println!("  → committed to branch {new_name}");
        }

        total_le += le_count;
        total_obe += obe_count;
    }

    println!("\nTotal: {} timestamps ({total_le} from LE-era, {total_obe} from OBE-era)",
        total_le + total_obe);

    if cli.dry_run && (total_le + total_obe) > 0 {
        println!("(dry run — rerun without --dry-run to apply)");
    }

    repo.close().map_err(|e| anyhow!("close: {e:?}"))?;
    Ok(())
}
