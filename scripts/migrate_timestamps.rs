#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1"
//! clap = { version = "4", features = ["derive", "env"] }
//! ed25519-dalek = "2"
//! rand_core = "0.6"
//! triblespace = { version = "0.28", default-features = false }
//! hifitime = "4.2"
//! ```

//! Migrate LE timestamps (NsTAIInterval) to OBE (OrderedNsTAIInterval).
//!
//! For each branch, reads all tribles with old LE timestamp attributes,
//! re-encodes the values as order-preserving big-endian, and writes them
//! with new attribute IDs in a single commit.

use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use std::path::PathBuf;
use triblespace::core::id::Id;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Repository;
use triblespace::core::trible::{Trible, TribleSet};
use triblespace::macros::id_hex;
use triblespace::prelude::*;

#[derive(Parser)]
#[command(about = "Migrate NsTAIInterval (LE) → OrderedNsTAIInterval (OBE)")]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    /// Dry run: show what would be migrated without writing.
    #[arg(long)]
    dry_run: bool,
}

/// Old LE attribute ID → New OBE attribute ID.
const MIGRATIONS: &[(Id, Id)] = &[
    // exec
    (id_hex!("AAD2627FB70DC16F6ADF8869AE1B203F"), id_hex!("D8910A14B31096DF94DE9E807B87645F")), // requested_at
    (id_hex!("B878792F16C0C27C776992FA053A2218"), id_hex!("CCFAE38E0C70AFBBF7223D2DA28A93C7")), // started_at
    (id_hex!("B4B81B90EFB4D1F5EE62DDE9CB48025D"), id_hex!("3BB7917C5E41E494FECE36FFE79FEF23")), // finished_at
    // config
    (id_hex!("DDF83FEC915816ACAE7F3FEBB57E5137"), id_hex!("5E32E36AD28B0B1E035D2DFCC20A3DC5")), // updated_at
    // cog
    (id_hex!("99F834C6A6A050DECBE42D639288B559"), id_hex!("1AE17985F2AE74631CE16FD84DC97FB4")), // created_at
    // context
    (id_hex!("3D5865566AF5118471DA1FF7F87CB791"), id_hex!("4036F38AB05D26764A1E5E456337F399")), // created_at
    (id_hex!("4EAF7FE3122A0AE2D8309B79DCCB8D75"), id_hex!("502F7D33822A90366F0F0ADA0556177F")), // start_at
    (id_hex!("95D629052C40FA09B378DDC507BEA0D3"), id_hex!("DF84E872EB68FBFCA63D760F27FD8A6F")), // end_at
    // model_chat / archive (shared ID)
    (id_hex!("0DA5DD275AA34F86B0297CC35F1B7395"), id_hex!("59FA7C04A43B96F31414D1B4544FAEC2")), // requested_at / created_at
    // model_chat
    (id_hex!("1DE7C6BCE0223199368070A82EA23A7E"), id_hex!("D1384E835F1C325249A603D93CA2701D")), // started_at
    (id_hex!("238CF718317A94DB46B8D75E7CB6D609"), id_hex!("2A98AB108752C0C0C6355B84871932DA")), // finished_at
    // local_messages
    (id_hex!("53ECCC7489AF8D30EF385ED12073F4A3"), id_hex!("5FA453867880877B613B7632A233419B")), // created_at
    (id_hex!("934C5AD3DA8F7A2EB467460E50D17A4F"), id_hex!("CFEF2E96BC66FF3BE0A39C34E70A5032")), // read_at
    // reason_events
    (id_hex!("FBA9BC32A457C7BFFDB7E0181D3E82A4"), id_hex!("79C9CB4C48864D28B215D4264E1037BF")), // created_at
];

/// Compass attributes: ShortString ISO timestamps → OrderedNsTAIInterval.
const COMPASS_MIGRATIONS: &[(Id, Id)] = &[
    (id_hex!("F9B56611861316B31A6C510B081C30B3"), id_hex!("E915C4D678D0F484B89B4E85E55DB442")), // created_at
    (id_hex!("8200ADEDC8D4D3D6D01CDC7396DF9AEC"), id_hex!("4FB34DB057497FB845B3816521A9A05E")), // at
];

const SIGN_BIT: u128 = 1u128 << 127;

/// Convert LE NsTAIInterval value bytes to OBE OrderedNsTAIInterval bytes.
fn le_to_obe(le_value: &[u8; 32]) -> [u8; 32] {
    let lower = i128::from_le_bytes(le_value[0..16].try_into().unwrap());
    let upper = i128::from_le_bytes(le_value[16..32].try_into().unwrap());
    let mut obe = [0u8; 32];
    obe[0..16].copy_from_slice(&((lower as u128) ^ SIGN_BIT).to_be_bytes());
    obe[16..32].copy_from_slice(&((upper as u128) ^ SIGN_BIT).to_be_bytes());
    obe
}

/// Convert ISO timestamp string to OrderedNsTAIInterval value bytes.
fn iso_to_obe(iso: &str) -> Option<[u8; 32]> {
    let epoch = hifitime::Epoch::from_gregorian_str(iso).ok()?;
    let ns = epoch.to_tai_duration().total_nanoseconds();
    let encoded = ((ns as u128) ^ SIGN_BIT).to_be_bytes();
    let mut obe = [0u8; 32];
    obe[0..16].copy_from_slice(&encoded);
    obe[16..32].copy_from_slice(&encoded); // point timestamp: lower == upper
    Some(obe)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let mut pile = Pile::open(&cli.pile).context("open pile")?;
    pile.restore().context("restore pile")?;
    let signing_key = SigningKey::generate(&mut OsRng);
    let mut repo = Repository::new(pile, signing_key, TribleSet::new())
        .map_err(|e| anyhow::anyhow!("create repo: {e:?}"))?;

    // Collect branch IDs.
    let branch_ids: Vec<Id> = repo
        .storage_mut()
        .branches()
        .map_err(|e| anyhow::anyhow!("list branches: {e:?}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("iter branches: {e:?}"))?;

    println!("Found {} branches", branch_ids.len());

    // Build lookup: old attribute ID → new attribute ID (as raw bytes).
    let migration_map: std::collections::HashMap<[u8; 16], [u8; 16]> = MIGRATIONS
        .iter()
        .map(|(old, new)| (old.raw(), new.raw()))
        .collect();
    let compass_map: std::collections::HashMap<[u8; 16], [u8; 16]> = COMPASS_MIGRATIONS
        .iter()
        .map(|(old, new)| (old.raw(), new.raw()))
        .collect();

    for branch_id in &branch_ids {
        let mut ws = repo
            .pull(*branch_id)
            .map_err(|e| anyhow::anyhow!("pull branch {branch_id:x}: {e:?}"))?;

        if ws.head().is_none() {
            continue;
        }

        let checkout = ws
            .checkout(..)
            .map_err(|e| anyhow::anyhow!("checkout branch {branch_id:x}: {e:?}"))?;
        let data = checkout.facts();

        let branch_name = format!("{branch_id:x}");

        let mut change = TribleSet::new();
        let mut migrated_le = 0usize;
        let mut migrated_compass = 0usize;
        let mut already_present = 0usize;

        // Migrate NsTAIInterval (LE) → OrderedNsTAIInterval (OBE).
        for trible in data.iter() {
            let e = &trible.data[0..16];
            let a = &trible.data[16..32];
            let v = &trible.data[32..64];

            let a_raw: [u8; 16] = a.try_into().unwrap();

            if let Some(new_a) = migration_map.get(&a_raw) {
                let obe_v = le_to_obe(v.try_into().unwrap());
                let mut new_trible_data = [0u8; 64];
                new_trible_data[0..16].copy_from_slice(e);
                new_trible_data[16..32].copy_from_slice(new_a);
                new_trible_data[32..64].copy_from_slice(&obe_v);

                // Check if already migrated (idempotent).
                let new_trible = Trible::as_transmute_raw_unchecked(&new_trible_data);
                if data.contains(new_trible) {
                    already_present += 1;
                } else {
                    change.insert(new_trible);
                    migrated_le += 1;
                }
            }

            // Compass: ShortString → OrderedNsTAIInterval.
            if let Some(new_a) = compass_map.get(&a_raw) {
                // Extract ShortString value: it's a fixed 32-byte field, read as UTF-8.
                let s = std::str::from_utf8(v).unwrap_or("").trim_end_matches('\0');
                if s.is_empty() {
                    continue;
                }
                match iso_to_obe(s) {
                    Some(obe_v) => {
                        let mut new_trible_data = [0u8; 64];
                        new_trible_data[0..16].copy_from_slice(e);
                        new_trible_data[16..32].copy_from_slice(new_a);
                        new_trible_data[32..64].copy_from_slice(&obe_v);

                        let new_trible = Trible::as_transmute_raw_unchecked(&new_trible_data);
                        if data.contains(new_trible) {
                            already_present += 1;
                        } else {
                            change.insert(new_trible);
                            migrated_compass += 1;
                        }
                    }
                    None => {
                        eprintln!("    warning: failed to parse compass timestamp: {s:?}");
                    }
                }
            }
        }

        let total = migrated_le + migrated_compass;
        println!(
            "  {branch_name}: {total} to migrate ({migrated_le} LE→OBE, {migrated_compass} compass→OBE, {already_present} already done)"
        );

        if total > 0 && !cli.dry_run {
            ws.commit(change, "migrate timestamps to OrderedNsTAIInterval");
            repo.push(&mut ws)
                .map_err(|e| anyhow::anyhow!("push branch {branch_name}: {e:?}"))?;
            println!("    committed.");
        }
    }

    if cli.dry_run {
        println!("\nDry run — no changes written.");
    } else {
        println!("\nMigration complete.");
    }

    let _ = repo.into_storage().close();
    Ok(())
}
