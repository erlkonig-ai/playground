#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! triblespace = "0.33"
//! ed25519-dalek = { version = "2.1.0", features = ["rand_core"] }
//! rand = "0.8"
//! hex = "0.4"
//! anyhow = "1"
//! clap = { version = "4", features = ["derive", "env"] }
//! ```
//!
//! Repair 24 wiki version entities that have bogus `metadata::created_at`
//! timestamps (0xFF sentinels and encoding artifacts from a historical bug).
//!
//! For each bogus entity, the corrected timestamp is the MINIMUM good
//! timestamp among sibling versions of the same fragment. This places the
//! bogus versions at the beginning of the version history rather than
//! outranking the real latest version.
//!
//! The output is a new branch ("wiki-repaired" by default) containing
//! the full wiki content with the 24 values corrected. Use
//! `trible pile branch rename` to swap it into place.

use anyhow::{anyhow, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::path::PathBuf;
use triblespace::prelude::*;

const SIGN_BIT: u128 = 1u128 << 127;
const MAX_REASONABLE: i128 = 6_400_000_000_000_000_000;

fn i128_from_obe(bytes: [u8; 16]) -> i128 {
    (u128::from_be_bytes(bytes) ^ SIGN_BIT) as i128
}

fn i128_to_obe(v: i128) -> [u8; 16] {
    ((v as u128) ^ SIGN_BIT).to_be_bytes()
}

fn is_bogus(lower: i128) -> bool {
    lower > MAX_REASONABLE || lower <= 0
}

#[derive(Parser)]
#[command(about = "Repair bogus wiki timestamps")]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Name for the repaired branch.
    #[arg(long, default_value = "wiki-repaired")]
    out_branch: String,
    /// Source wiki branch name.
    #[arg(long, default_value = "wiki")]
    source_branch: String,
    /// Only report, don't write.
    #[arg(long)]
    dry_run: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut pile: Pile<valueschemas::Blake3> = Pile::open(&cli.pile)
        .map_err(|e| anyhow!("open: {e:?}"))?;
    pile.restore().map_err(|e| anyhow!("restore: {e:?}"))?;
    let sk = SigningKey::generate(&mut OsRng);
    let mut repo = Repository::new(pile, sk, TribleSet::new())
        .map_err(|e| anyhow!("repo: {e:?}"))?;

    // Find source branch.
    let source_id = repo.lookup_branch(&cli.source_branch)
        .map_err(|e| anyhow!("lookup: {e:?}"))?
        .ok_or_else(|| anyhow!("branch '{}' not found", cli.source_branch))?;

    let mut ws = repo.pull(source_id).map_err(|e| anyhow!("pull: {e:?}"))?;

    // Checkout data + metadata.
    let (data, metadata) = ws.checkout_with_metadata(..)
        .map_err(|e| anyhow!("checkout: {e:?}"))?;

    println!("Data: {} tribles", data.len());
    println!("Metadata: {} tribles", metadata.len());

    let created_at_attr: [u8; 16] = [0x9B, 0x1E, 0x79, 0xDF, 0xD0, 0x65, 0xF6, 0x43,
                                      0x95, 0x41, 0x41, 0x59, 0x3C, 0xD8, 0xB9, 0xE0];
    let fragment_attr: [u8; 16] = [0x78, 0xBA, 0xBE, 0xF1, 0x79, 0x25, 0x31, 0xA2,
                                    0xE5, 0x1A, 0x37, 0x2D, 0x96, 0xFE, 0x5F, 0x3E];

    // 1. Find bogus tribles and entity→fragment mapping.
    let mut bogus: HashMap<Id, [u8; 32]> = HashMap::new();
    let mut entity_frag: HashMap<Id, Id> = HashMap::new();

    for trible in data.iter() {
        let eid = Id::new(trible.data[0..16].try_into().unwrap()).unwrap();
        let attr: [u8; 16] = trible.data[16..32].try_into().unwrap();
        if attr == created_at_attr {
            let value: [u8; 32] = trible.data[32..64].try_into().unwrap();
            let lower = i128_from_obe(value[0..16].try_into().unwrap());
            if is_bogus(lower) {
                bogus.insert(eid, value);
            }
        }
        if attr == fragment_attr {
            let frag = Id::new(trible.data[32..48].try_into().unwrap()).unwrap();
            entity_frag.insert(eid, frag);
        }
    }

    println!("Bogus timestamps: {}", bogus.len());

    if bogus.is_empty() {
        println!("Nothing to repair.");
        repo.close().map_err(|e| anyhow!("close: {e:?}"))?;
        return Ok(());
    }

    // 2. For each bogus entity, find the MINIMUM good timestamp from sibling versions.
    //    This places repaired versions at the start of the history.
    let mut corrections: HashMap<Id, i128> = HashMap::new();
    for (eid, _) in &bogus {
        let Some(frag) = entity_frag.get(eid) else { continue };

        // Find all versions of this fragment.
        let mut good_timestamps: Vec<i128> = Vec::new();
        for trible in data.iter() {
            let a: [u8; 16] = trible.data[16..32].try_into().unwrap();
            if a == fragment_attr {
                let v: [u8; 16] = trible.data[32..48].try_into().unwrap();
                if v == frag.raw() {
                    let vid = Id::new(trible.data[0..16].try_into().unwrap()).unwrap();
                    // Find this version's timestamp.
                    for t2 in data.iter() {
                        if t2.data[0..16] == vid.raw() && t2.data[16..32] == created_at_attr {
                            let val: [u8; 32] = t2.data[32..64].try_into().unwrap();
                            let ts = i128_from_obe(val[0..16].try_into().unwrap());
                            if !is_bogus(ts) {
                                good_timestamps.push(ts);
                            }
                        }
                    }
                }
            }
        }

        let corrected = good_timestamps.iter().min().copied().unwrap_or(0);
        if corrected > 0 {
            corrections.insert(*eid, corrected);
            let bogus_lower = i128_from_obe(bogus[eid][0..16].try_into().unwrap());
            println!("  {eid:x}  frag={:x}  bogus={bogus_lower}  corrected={corrected}  siblings={}",
                frag, good_timestamps.len());
        } else {
            eprintln!("  {eid:x}  frag={:x}  NO good siblings!", frag);
        }
    }

    println!("Corrections: {}", corrections.len());

    if cli.dry_run {
        println!("(dry run — no changes written)");
        repo.close().map_err(|e| anyhow!("close: {e:?}"))?;
        return Ok(());
    }

    // 3. Build corrected content: all tribles minus bogus, plus corrections.
    let mut fixed = TribleSet::new();
    let mut removed = 0;
    for trible in data.iter() {
        let eid = Id::new(trible.data[0..16].try_into().unwrap()).unwrap();
        let attr: [u8; 16] = trible.data[16..32].try_into().unwrap();
        if attr == created_at_attr && bogus.contains_key(&eid) {
            let value: [u8; 32] = trible.data[32..64].try_into().unwrap();
            let lower = i128_from_obe(value[0..16].try_into().unwrap());
            if is_bogus(lower) {
                removed += 1;
                continue;
            }
        }
        fixed.insert(trible);
    }

    for (eid, ts) in &corrections {
        let mut value = [0u8; 32];
        value[0..16].copy_from_slice(&i128_to_obe(*ts));
        value[16..32].copy_from_slice(&i128_to_obe(*ts));
        let val = Value::<valueschemas::NsTAIInterval>::new(value);
        let attr_id = Id::new(created_at_attr).unwrap();
        fixed.insert(&Trible::force(eid, &attr_id, &val));
    }

    println!("Removed {removed} bogus, added {} corrections", corrections.len());
    println!("Content: {} → {} tribles", data.len(), fixed.len());

    // 4. Check for existing output branch.
    if let Ok(Some(_)) = repo.lookup_branch(&cli.out_branch) {
        return Err(anyhow!("branch '{}' already exists — delete it first or use a different --out-branch", cli.out_branch));
    }

    // 5. Create output branch with metadata.
    let new_branch_id = repo.create_branch(&cli.out_branch, None)
        .map_err(|e| anyhow!("create branch: {e:?}"))?;
    let mut new_ws = repo.pull(*new_branch_id)
        .map_err(|e| anyhow!("pull new: {e:?}"))?;

    if metadata.is_empty() {
        new_ws.commit(fixed, "repair bogus wiki timestamps (min sibling)");
    } else {
        let metadata_handle = new_ws.put(metadata.to_blob());
        new_ws.commit_with_metadata(fixed, metadata_handle, "repair bogus wiki timestamps (min sibling)");
    }
    repo.push(&mut new_ws).map_err(|e| anyhow!("push: {e:?}"))?;
    println!("Created branch '{}'", cli.out_branch);

    repo.close().map_err(|e| anyhow!("close: {e:?}"))?;
    Ok(())
}
