#!/usr/bin/env -S rust-script
//! ```cargo
//! [dependencies]
//! anyhow = "1.0"
//! clap = { version = "4.5.4", features = ["derive", "env"] }
//! ed25519-dalek = "2.1.1"
//! hifitime = "4.2.3"
//! rand_core = "0.6.4"
//! hex = "0.4"
//! triblespace = "0.34.1"
//! ```
//!
//! Research quality gauge: reads wiki tag metadata to measure research health.
//! Pure read-only lens on existing data — no writes, no new schemas.

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use hifitime::Epoch;
use rand_core::OsRng;
use std::collections::HashMap;
use std::path::PathBuf;
use triblespace::core::metadata;
use triblespace::core::repo::Workspace;
use triblespace::prelude::*;

// ── reuse wiki schemas ──────────────────────────────────────────────────
mod wiki {
    use triblespace::prelude::*;
    attributes! {
        "EBFC56D50B748E38A14F5FC768F1B9C1" as fragment: valueschemas::GenId;
        "78BABEF1792531A2E51A372D96FE5F3E" as title: valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>;
        "DEAFB7E307DF72389AD95A850F24BAA5" as links_to: valueschemas::GenId;
    }
}

const WIKI_BRANCH_NAME: &str = "wiki";

type Repo = Repository<Pile<valueschemas::Blake3>>;
type Lower = i128;

// ── CLI ─────────────────────────────────────────────────────────────────
#[derive(Parser)]
#[command(name = "gauge", about = "Research quality gauge — reads wiki tag metadata")]
struct Cli {
    #[arg(long, env = "PILE")]
    pile: PathBuf,
    #[arg(long)]
    branch_id: Option<String>,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Show research health metrics
    Health,
    /// Count fragments by tag
    Tags,
    /// Show the published/refuted ratio over time
    Quality,
    /// Show most-linked fragments (knowledge hubs)
    Hubs {
        /// Number of top hubs to show
        #[arg(short, long, default_value = "15")]
        top: usize,
    },
    /// Find fragments citing audit-warned or refuted hubs (contamination scan)
    Risk,
    /// Show how metrics change over time (buckets by creation date)
    Drift,
    /// List orphan fragments (no outgoing links)
    Orphans {
        /// Number to show
        #[arg(short, long, default_value = "20")]
        top: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.command.is_none() {
        Cli::command().print_help()?;
        return Ok(());
    }

    let mut pile = Pile::open(&cli.pile)?;
    pile.restore()?;
    let mut repo = Repository::new(pile, SigningKey::generate(&mut OsRng), TribleSet::new())?;

    let bid = if let Some(hex_str) = &cli.branch_id {
        let raw = hex::decode(hex_str)?;
        Id::new(raw.try_into().map_err(|_| anyhow::anyhow!("bad branch id"))?)
            .ok_or_else(|| anyhow::anyhow!("nil branch id"))?
    } else {
        repo.ensure_branch(WIKI_BRANCH_NAME, None)
            .map_err(|e| anyhow::anyhow!("ensure wiki branch: {e:?}"))?
    };

    let mut ws = repo.pull(bid).map_err(|e| anyhow::anyhow!("pull: {e:?}"))?;
    let space = ws.checkout(..).map_err(|e| anyhow::anyhow!("checkout: {e:?}"))?;

    match cli.command.unwrap() {
        Commands::Health => cmd_health(&space, &mut ws),
        Commands::Tags => cmd_tags(&space, &mut ws),
        Commands::Quality => cmd_quality(&space, &mut ws),
        Commands::Hubs { top } => cmd_hubs(&space, &mut ws, top),
        Commands::Risk => cmd_risk(&space, &mut ws),
        Commands::Drift => cmd_drift(&space, &mut ws),
        Commands::Orphans { top } => cmd_orphans(&space, &mut ws, top),
    }
}

// ── helpers (borrowed from wiki.rs pattern) ─────────────────────────────

fn latest_versions(space: &TribleSet) -> HashMap<Id, (Id, Lower)> {
    let mut best: HashMap<Id, (Id, Lower)> = HashMap::new();
    for (vid, frag, (lower, _upper)) in find!(
        (vid: Id, frag: Id, ts: (Epoch, Epoch)),
        pattern!(space, [{
            ?vid @
            wiki::fragment: ?frag,
            metadata::created_at: ?ts,
        }])
    ) {
        let ts = lower.to_tai_duration().total_nanoseconds();
        best.entry(frag)
            .and_modify(|(old_vid, old_ts)| {
                if ts > *old_ts { *old_vid = vid; *old_ts = ts; }
            })
            .or_insert((vid, ts));
    }
    best
}

fn tags_of(space: &TribleSet, vid: Id) -> Vec<Id> {
    find!(
        tag: Id,
        pattern!(space, [{ &vid @ metadata::tag: ?tag }])
    ).collect()
}

fn tag_name(space: &TribleSet, ws: &mut Workspace<Pile<valueschemas::Blake3>>, tag_id: Id) -> String {
    let results: Vec<_> = find!(
        h: Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>,
        pattern!(space, [{ &tag_id @ metadata::name: ?h }])
    ).collect();
    if let Some(handle) = results.into_iter().next() {
        if let Ok(view) = ws.get::<View<str>, _>(handle) {
            let s: &str = view.as_ref();
            return s.to_string();
        }
    }
    format!("{:?}", tag_id)
}

// ── commands ────────────────────────────────────────────────────────────

fn cmd_health(space: &TribleSet, ws: &mut Workspace<Pile<valueschemas::Blake3>>) -> Result<()> {
    let latest = latest_versions(space);
    let total = latest.len();

    let mut tag_counts: HashMap<String, usize> = HashMap::new();
    let mut orphan_count = 0usize;
    let mut link_count = 0usize;

    for (_frag, (vid, _ts)) in &latest {
        let tags = tags_of(space, *vid);
        for tag_id in &tags {
            let name = tag_name(space, ws, *tag_id);
            *tag_counts.entry(name).or_insert(0) += 1;
        }

        // Count outgoing links
        let links: Vec<Id> = find!(
            target: Id,
            pattern!(space, [{ vid @ wiki::links_to: ?target }])
        ).collect();
        if links.is_empty() {
            orphan_count += 1;
        }
        link_count += links.len();
    }

    let published = tag_counts.get("published").copied().unwrap_or(0);
    let refuted = tag_counts.get("refuted").copied().unwrap_or(0);
    let preprint = tag_counts.get("preprint").copied().unwrap_or(0);
    let hypothesis = tag_counts.get("hypothesis").copied().unwrap_or(0);
    let evidence = tag_counts.get("evidence").copied().unwrap_or(0);
    let review = tag_counts.get("review").copied().unwrap_or(0);
    let synthesis = tag_counts.get("synthesis").copied().unwrap_or(0);
    let prediction = tag_counts.get("prediction").copied().unwrap_or(0);
    let finding = tag_counts.get("finding").copied().unwrap_or(0);
    let audit_warning = tag_counts.get("audit-warning").copied().unwrap_or(0);

    println!("=== GAUGE: Research Health ===");
    println!();
    println!("Versions: {total}");
    println!("Links: {link_count} ({:.1} per version)", link_count as f64 / total as f64);
    println!("Orphans: {orphan_count} ({:.0}%)", 100.0 * orphan_count as f64 / total as f64);
    println!();
    println!("--- Epistemic Status ---");
    println!("  Published:      {published:>4}");
    println!("  Refuted:        {refuted:>4}");
    println!("  Preprint:       {preprint:>4}");
    println!("  Audit-warning:  {audit_warning:>4}");
    println!();
    println!("--- Content Type ---");
    println!("  Synthesis:      {synthesis:>4}");
    println!("  Hypothesis:     {hypothesis:>4}");
    println!("  Evidence:        {evidence:>4}");
    println!("  Finding:         {finding:>4}");
    println!("  Review:          {review:>4}");
    println!("  Prediction:      {prediction:>4}");
    println!();
    println!("--- Ratios ---");
    if published + refuted > 0 {
        println!("  Survival rate:  {:.0}% ({published} published / {} tested)",
            100.0 * published as f64 / (published + refuted) as f64,
            published + refuted);
    }
    if synthesis > 0 {
        println!("  Theory grounding: {:.1}% ({published} published / {synthesis} synthesis)",
            100.0 * published as f64 / synthesis as f64);
    }
    if hypothesis > 0 {
        let tested = evidence + finding;
        println!("  Hypothesis coverage: {tested} evidence+findings / {hypothesis} hypotheses ({:.0}%)",
            100.0 * tested as f64 / hypothesis as f64);
    }
    if prediction > 0 {
        println!("  Predictions: {prediction} made ({refuted} refuted, track outcomes!)");
    }
    if review > 0 {
        println!("  Review density: {:.1} reviews per published finding",
            review as f64 / published.max(1) as f64);
    }
    println!();
    Ok(())
}

fn cmd_tags(space: &TribleSet, ws: &mut Workspace<Pile<valueschemas::Blake3>>) -> Result<()> {
    let latest = latest_versions(space);
    let mut tag_counts: HashMap<String, usize> = HashMap::new();

    for (_frag, (vid, _ts)) in &latest {
        let tags = tags_of(space, *vid);
        for tag_id in &tags {
            let name = tag_name(space, ws, *tag_id);
            *tag_counts.entry(name).or_insert(0) += 1;
        }
    }

    let mut sorted: Vec<_> = tag_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    println!("=== GAUGE: Tag Counts ===");
    println!();
    for (name, count) in sorted {
        println!("  {name:<25} {count:>4}");
    }
    println!();
    Ok(())
}

fn cmd_quality(space: &TribleSet, ws: &mut Workspace<Pile<valueschemas::Blake3>>) -> Result<()> {
    let latest = latest_versions(space);
    let mut published_frags = Vec::new();
    let mut refuted_frags = Vec::new();

    for (_frag, (vid, _ts)) in &latest {
        let tags = tags_of(space, *vid);
        let tag_names: Vec<String> = tags.iter()
            .map(|t| tag_name(space, ws, *t))
            .collect();

        // Get title
        let title: String = find!(
            h: Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>,
            pattern!(space, [{ vid @ wiki::title: ?h }])
        ).next()
            .and_then(|h| ws.get::<View<str>, _>(h).ok())
            .map(|v| { let s: &str = v.as_ref(); s.to_string() })
            .unwrap_or_else(|| "untitled".to_string());

        let short_title: String = title.chars().take(60).collect();

        if tag_names.iter().any(|t| t == "published") {
            published_frags.push(short_title.clone());
        }
        if tag_names.iter().any(|t| t == "refuted") {
            refuted_frags.push(short_title);
        }
    }

    println!("=== GAUGE: Quality Assessment ===");
    println!();
    println!("PUBLISHED ({}):", published_frags.len());
    for t in &published_frags {
        println!("  + {t}");
    }
    println!();
    println!("REFUTED ({}):", refuted_frags.len());
    for t in &refuted_frags {
        println!("  - {t}");
    }
    println!();
    if !published_frags.is_empty() || !refuted_frags.is_empty() {
        let total = published_frags.len() + refuted_frags.len();
        println!("Survival: {}/{} ({:.0}%)",
            published_frags.len(), total,
            100.0 * published_frags.len() as f64 / total as f64);
    }
    println!();
    Ok(())
}

fn cmd_hubs(space: &TribleSet, ws: &mut Workspace<Pile<valueschemas::Blake3>>, top: usize) -> Result<()> {
    let latest = latest_versions(space);

    // Build version->fragment and fragment->title maps
    let vid_to_frag: HashMap<Id, Id> = latest.iter()
        .map(|(frag, (vid, _))| (*vid, *frag))
        .collect();
    let frag_to_vid: HashMap<Id, Id> = latest.iter()
        .map(|(frag, (vid, _))| (*frag, *vid))
        .collect();

    // Count incoming links per target (could be version or fragment ID)
    let mut incoming: HashMap<Id, usize> = HashMap::new();
    for (_frag, (vid, _ts)) in &latest {
        let targets: Vec<Id> = find!(
            target: Id,
            pattern!(space, [{ vid @ wiki::links_to: ?target }])
        ).collect();
        for target in targets {
            // Normalize: if target is a version, map to its fragment
            let canonical = vid_to_frag.get(&target).copied().unwrap_or(target);
            *incoming.entry(canonical).or_insert(0) += 1;
        }
    }

    // Sort by incoming count
    let mut sorted: Vec<_> = incoming.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    println!("=== GAUGE: Knowledge Hubs (most-linked fragments) ===");
    println!();
    for (id, count) in sorted.into_iter().take(top) {
        // Try title from the fragment's latest version, or from the ID directly
        let lookup_vid = frag_to_vid.get(&id).copied().unwrap_or(id);
        let title: String = find!(
            h: Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>,
            pattern!(space, [{ &lookup_vid @ wiki::title: ?h }])
        ).next()
            .and_then(|h| ws.get::<View<str>, _>(h).ok())
            .map(|v| { let s: &str = v.as_ref(); s.to_string() })
            .unwrap_or_else(|| format!("(unknown {:X?})", &id[..4]));

        let short: String = title.chars().take(65).collect();
        println!("  {count:>3} links <- {short}");
    }
    println!();
    Ok(())
}

fn cmd_risk(space: &TribleSet, ws: &mut Workspace<Pile<valueschemas::Blake3>>) -> Result<()> {
    let latest = latest_versions(space);

    // Find all audit-warned and refuted fragment IDs
    let mut flagged: HashMap<Id, (String, Vec<String>)> = HashMap::new(); // frag -> (title, [tags])
    for (frag, (vid, _ts)) in &latest {
        let tags = tags_of(space, *vid);
        let tag_names: Vec<String> = tags.iter()
            .map(|t| tag_name(space, ws, *t))
            .collect();
        if tag_names.iter().any(|t| t == "refuted" || t == "audit-warning") {
            let title: String = find!(
                h: Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>,
                pattern!(space, [{ vid @ wiki::title: ?h }])
            ).next()
                .and_then(|h| ws.get::<View<str>, _>(h).ok())
                .map(|v| { let s: &str = v.as_ref(); s.to_string() })
                .unwrap_or_else(|| "untitled".to_string());
            let risk_tags: Vec<String> = tag_names.into_iter()
                .filter(|t| t == "refuted" || t == "audit-warning")
                .collect();
            flagged.insert(*frag, (title, risk_tags));
        }
    }

    if flagged.is_empty() {
        println!("No audit-warned or refuted fragments found.");
        return Ok(());
    }

    // Build version->fragment map
    let vid_to_frag: HashMap<Id, Id> = latest.iter()
        .map(|(frag, (vid, _))| (*vid, *frag))
        .collect();

    // For each non-flagged fragment, check if it links to any flagged fragment
    println!("=== GAUGE: Risk Scan — Fragments Citing Flagged Sources ===");
    println!();

    println!("Flagged sources ({}):", flagged.len());
    for (frag, (title, tags)) in &flagged {
        let short: String = title.chars().take(55).collect();
        println!("  [{tags}] {short}", tags = tags.join(", "));
    }
    println!();

    let mut contaminated: Vec<(String, Vec<String>)> = Vec::new(); // (title, [flagged sources cited])
    for (frag, (vid, _ts)) in &latest {
        if flagged.contains_key(frag) { continue; } // skip the flagged ones themselves

        let targets: Vec<Id> = find!(
            target: Id,
            pattern!(space, [{ vid @ wiki::links_to: ?target }])
        ).collect();

        let mut cited_flagged: Vec<String> = Vec::new();
        for target in &targets {
            // Normalize to fragment ID
            let canonical = vid_to_frag.get(target).copied().unwrap_or(*target);
            if let Some((flagged_title, _)) = flagged.get(&canonical) {
                let short: String = flagged_title.chars().take(30).collect();
                cited_flagged.push(short);
            }
        }

        if !cited_flagged.is_empty() {
            let title: String = find!(
                h: Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>,
                pattern!(space, [{ vid @ wiki::title: ?h }])
            ).next()
                .and_then(|h| ws.get::<View<str>, _>(h).ok())
                .map(|v| { let s: &str = v.as_ref(); s.to_string() })
                .unwrap_or_else(|| "untitled".to_string());
            contaminated.push((title, cited_flagged));
        }
    }

    contaminated.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    println!("Potentially contaminated fragments ({}):", contaminated.len());
    for (title, sources) in &contaminated {
        let short: String = title.chars().take(55).collect();
        println!("  {short}");
        for src in sources {
            println!("    cites -> {src}");
        }
    }
    println!();

    Ok(())
}

fn cmd_orphans(space: &TribleSet, ws: &mut Workspace<Pile<valueschemas::Blake3>>, top: usize) -> Result<()> {
    let latest = latest_versions(space);
    let mut orphans: Vec<(String, Vec<String>)> = Vec::new();

    for (_frag, (vid, _ts)) in &latest {
        let links: Vec<Id> = find!(
            target: Id,
            pattern!(space, [{ vid @ wiki::links_to: ?target }])
        ).collect();

        if links.is_empty() {
            let title: String = find!(
                h: Value<valueschemas::Handle<valueschemas::Blake3, blobschemas::LongString>>,
                pattern!(space, [{ vid @ wiki::title: ?h }])
            ).next()
                .and_then(|h| ws.get::<View<str>, _>(h).ok())
                .map(|v| { let s: &str = v.as_ref(); s.to_string() })
                .unwrap_or_else(|| "untitled".to_string());

            let tags = tags_of(space, *vid);
            let tag_names: Vec<String> = tags.iter()
                .map(|t| tag_name(space, ws, *t))
                .collect();

            orphans.push((title, tag_names));
        }
    }

    // Sort alphabetically for browsability
    orphans.sort_by(|a, b| a.0.cmp(&b.0));

    println!("=== GAUGE: Orphan Fragments (no outgoing links) ===");
    println!();
    println!("Total orphans: {} / {} ({:.0}%)", orphans.len(), latest.len(),
        100.0 * orphans.len() as f64 / latest.len() as f64);
    println!();
    for (title, tags) in orphans.iter().take(top) {
        let short: String = title.chars().take(60).collect();
        let tag_str: String = tags.iter()
            .filter(|t| *t != "version" && *t != "typst" && *t != "markdown")
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        println!("  {short}");
        if !tag_str.is_empty() {
            println!("    [{tag_str}]");
        }
    }
    if orphans.len() > top {
        println!("  ... and {} more", orphans.len() - top);
    }
    println!();
    Ok(())
}

fn cmd_drift(space: &TribleSet, ws: &mut Workspace<Pile<valueschemas::Blake3>>) -> Result<()> {
    let latest = latest_versions(space);

    // Bucket fragments by date (YYYY-MM)
    let mut buckets: std::collections::BTreeMap<String, HashMap<String, usize>> = std::collections::BTreeMap::new();

    for (_frag, (vid, ts_ns)) in &latest {
        // Convert TAI nanoseconds to approximate date
        let epoch = Epoch::from_tai_duration(hifitime::Duration::from_parts(0, (*ts_ns).max(0) as u64));
        let (year, month, _, _, _, _, _) = epoch.to_gregorian_utc();

        // Skip obviously broken dates (far future)
        if year > 2030 || year < 2020 { continue; }

        let bucket = format!("{year:04}-{month:02}");

        let tags = tags_of(space, *vid);
        let tag_names: Vec<String> = tags.iter()
            .map(|t| tag_name(space, ws, *t))
            .collect();

        let entry = buckets.entry(bucket).or_insert_with(HashMap::new);
        *entry.entry("total".to_string()).or_insert(0) += 1;

        for name in &tag_names {
            match name.as_str() {
                "published" | "refuted" | "preprint" | "hypothesis" |
                "evidence" | "review" | "synthesis" | "finding" |
                "prediction" | "audit-warning" | "experiment" => {
                    *entry.entry(name.clone()).or_insert(0) += 1;
                }
                _ => {}
            }
        }
    }

    println!("=== GAUGE: Research Drift Over Time ===");
    println!();
    println!("{:<10} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5}",
        "Month", "Total", "Synth", "Evid", "Hypo", "Rev", "Pub", "Ref", "Pred");
    println!("{}", "-".repeat(75));

    for (month, counts) in &buckets {
        let total = counts.get("total").copied().unwrap_or(0);
        let synth = counts.get("synthesis").copied().unwrap_or(0);
        let evid = counts.get("evidence").copied().unwrap_or(0);
        let hypo = counts.get("hypothesis").copied().unwrap_or(0);
        let rev = counts.get("review").copied().unwrap_or(0);
        let publ = counts.get("published").copied().unwrap_or(0);
        let refut = counts.get("refuted").copied().unwrap_or(0);
        let pred = counts.get("prediction").copied().unwrap_or(0);

        println!("{month:<10} {total:>5} {synth:>5} {evid:>5} {hypo:>5} {rev:>5} {publ:>5} {refut:>5} {pred:>5}");
    }
    println!();

    Ok(())
}

// Note: future additions planned:
// - `gauge orphans` — list fragments with zero incoming/outgoing links
// - `gauge hubs` — list most-linked fragments (foundational knowledge)
// - `gauge trend` — compare metrics across time windows
// - `gauge provenance` — once wiki::source_turn is added, trace quality back to model invocations
