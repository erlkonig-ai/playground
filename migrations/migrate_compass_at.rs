#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! triblespace = "0.33"
//! ed25519-dalek = { version = "2.1.0", features = ["rand_core"] }
//! rand = "0.8"
//! anyhow = "1"
//! hex = "0.4"
//! ```
use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::Path;
use triblespace::prelude::*;

fn migrate_pile(path: &Path) -> Result<()> {
    let mut pile: Pile<valueschemas::Blake3> = Pile::open(path)
        .map_err(|e| anyhow!("open: {e:?}"))?;
    pile.restore().map_err(|e| anyhow!("restore: {e:?}"))?;
    let sk = SigningKey::generate(&mut OsRng);
    let mut repo = Repository::new(pile, sk, TribleSet::new())
        .map_err(|e| anyhow!("repo: {e:?}"))?;

    // Old compass `at` → canonical `metadata::created_at`
    let old_attr: [u8; 16] = [0x4F,0xB3,0x4D,0xB0,0x57,0x49,0x7F,0xB8,
                               0x45,0xB3,0x81,0x65,0x21,0xA9,0xA0,0x5E];
    let new_attr: [u8; 16] = [0x9B,0x1E,0x79,0xDF,0xD0,0x65,0xF6,0x43,
                               0x95,0x41,0x41,0x59,0x3C,0xD8,0xB9,0xE0];

    // Find all branches that have this attr
    let branch_ids: Vec<Id> = repo.storage_mut().branches()
        .map_err(|e| anyhow!("branches: {e:?}"))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("iter: {e:?}"))?;

    let new_attr_id = Id::new(new_attr).unwrap();
    let mut total = 0usize;

    for bid in &branch_ids {
        let mut ws = match repo.pull(*bid) {
            Ok(ws) => ws,
            Err(_) => continue,
        };
        let checkout = match ws.checkout(..) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mut migrated = TribleSet::new();
        let mut count = 0;
        for trible in checkout.iter() {
            let attr: [u8; 16] = trible.data[16..32].try_into().unwrap();
            if attr == old_attr {
                let entity = Id::new(trible.data[0..16].try_into().unwrap()).unwrap();
                let value: [u8; 32] = trible.data[32..64].try_into().unwrap();
                let val = Value::<valueschemas::NsTAIInterval>::new(value);
                migrated.insert(&Trible::force(&entity, &new_attr_id, &val));
                count += 1;
            }
        }

        if count > 0 {
            let name = repo.lookup_branch("?").ok().flatten()
                .map(|_| "?".to_string())
                .unwrap_or_else(|| format!("{bid:x}"));
            ws.commit(migrated, "migrate compass at → metadata::created_at");
            repo.push(&mut ws).map_err(|e| anyhow!("push: {e:?}"))?;
            println!("  {bid:X}: {count} tribles migrated");
            total += count;
        }
    }

    println!("  total: {total} tribles");
    repo.close().map_err(|e| anyhow!("close: {e:?}"))?;
    Ok(())
}

fn main() -> Result<()> {
    println!("=== Operator ===");
    migrate_pile(Path::new("./personas/operator/pile/self.pile"))?;
    println!("=== Bulti ===");
    migrate_pile(Path::new("./personas/bulti/pile/self.pile"))?;
    Ok(())
}
