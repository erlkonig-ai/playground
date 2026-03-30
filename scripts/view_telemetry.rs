#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! triblespace = { version = "0.29", features = ["telemetry"] }
//! hifitime = "4.2"
//! ed25519-dalek = "2"
//! rand_core = "0.6"
//! ```

use triblespace::prelude::*;
use triblespace::core::repo::pile::Pile;
use triblespace::core::repo::Repository;
use triblespace::core::value::schemas::hash::Blake3;
use triblespace::telemetry::schema;
use triblespace::macros::id_hex;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

fn main() {
    let mut pile = Pile::<Blake3>::open("./telemetry.pile").unwrap();
    pile.restore().unwrap();
    let key = SigningKey::generate(&mut OsRng);
    let mut repo = Repository::new(pile, key, TribleSet::new()).unwrap();

    let branch_id = id_hex!("5D1559A07E060D82615C532539FC8B56");
    let mut ws = repo.pull(branch_id).unwrap();
    let co = ws.checkout(..).unwrap();
    let data = co.facts();

    println!("Total tribles: {}", data.len());

    // Count and list spans with duration
    let mut spans: Vec<(String, u128)> = find!(
        (id: Id, dur_val: Value<valueschemas::U256BE>),
        pattern!(data, [{
            ?id @
            metadata::tag: schema::kind_span,
            schema::duration_ns: ?dur_val,
        }])
    ).filter_map(|(id, dur_val)| {
        let dur: u128 = dur_val.try_from_value().ok()?;
        let name: Option<String> = find!(
            h: Value<Handle<Blake3, blobschemas::LongString>>,
            pattern!(data, [{ &id @ schema::name: ?h }])
        ).next().and_then(|h| ws.get(h).ok()).map(|v: View<str>| v.as_ref().to_string());
        Some((name.unwrap_or_else(|| format!("{id:x}")), dur))
    }).collect();

    spans.sort_by(|a, b| b.1.cmp(&a.1)); // sort by duration descending

    println!("\nTop spans by duration:");
    println!("{:<50} {:>10}", "Name", "Duration");
    println!("{:-<62}", "");
    for (name, dur_ns) in spans.iter().take(30) {
        let dur_ms = *dur_ns as f64 / 1_000_000.0;
        println!("{:<50} {:>8.1}ms", name, dur_ms);
    }

    println!("\nTotal spans: {}", spans.len());

    // Aggregate by name
    let mut by_name: std::collections::HashMap<String, (u128, usize)> = std::collections::HashMap::new();
    for (name, dur) in &spans {
        let entry = by_name.entry(name.clone()).or_insert((0, 0));
        entry.0 += dur;
        entry.1 += 1;
    }
    let mut aggregated: Vec<(String, u128, usize)> = by_name.into_iter().map(|(n, (d, c))| (n, d, c)).collect();
    aggregated.sort_by(|a, b| b.1.cmp(&a.1));

    println!("\nAggregated by name (total time):");
    println!("{:<50} {:>10} {:>6}", "Name", "Total", "Count");
    println!("{:-<68}", "");
    for (name, total_ns, count) in aggregated.iter().take(20) {
        let total_ms = *total_ns as f64 / 1_000_000.0;
        println!("{:<50} {:>8.1}ms {:>6}", name, total_ms, count);
    }

    let _ = repo.into_storage().close();
}
