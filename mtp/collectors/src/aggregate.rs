//! Aggregation (ADR-0027 §5, §4): fold the raw [`FactStore`] into the
//! deterministic core's [`EpochInput`], applying the §5 Sybil-resistance rules —
//! the per-ID node decrement `d_n` and the /24-or-ASN co-location cap — along the
//! way. Everything here is a pure, order-independent function of the store, so
//! two operators with the same facts build byte-identical input.

use crate::collect::EpochWindow;
use crate::store::{ChainFixedKind, FactStore, NodeRecord};
use misaka_mtp::{Contribution, ContributionEntry, EpochInput};
use std::collections::BTreeMap;

/// §5 co-location cap: at most this many *counted* nodes may share a /24 prefix
/// or an ASN. Extra nodes in the same bucket are dropped before ranking.
pub const COLOCATION_CAP: usize = 2;

/// A node that survived the §5 co-location cap, with its per-owner rank assigned.
struct RankedNode<'a> {
    node: &'a NodeRecord,
    node_rank: usize,
}

/// Deterministic node order: earliest-seen first, `node_key` as the tie-break.
fn node_order(a: &NodeRecord, b: &NodeRecord) -> std::cmp::Ordering {
    a.first_seen_ms.cmp(&b.first_seen_ms).then_with(|| a.node_key.cmp(&b.node_key))
}

/// Apply the §5 /24-or-ASN cap, then assign the per-owner `d_n` rank. Nodes are
/// considered in deterministic [`node_order`]; a node is kept only if **every**
/// co-location key it exposes (/24 and/or ASN) is still under [`COLOCATION_CAP`].
/// Kept nodes are then ranked 0,1,2,… within each owner id (rank ≥ 4 scores 0 by
/// the core's `d_n` table, but we still emit it so the evidence is recorded).
///
/// Fail-closed on missing attribution (adversarial-review hardening): a node with
/// NEITHER a /24 nor an ASN exposes no co-location key, so it would otherwise
/// escape the cap entirely — "unknown location" must not read as "known-isolated"
/// in a Sybil control. All key-less nodes are bucketed together under one sentinel
/// and share the same [`COLOCATION_CAP`], so an operator can't farm unlimited
/// unattributed nodes. (In practice the /24 is crawler-observed from the TCP source
/// IP, so key-less nodes are rare, but the control fails safe regardless.)
fn rank_nodes(store: &FactStore) -> Vec<RankedNode<'_>> {
    let mut ordered: Vec<&NodeRecord> = store.nodes.iter().collect();
    ordered.sort_by(|a, b| node_order(a, b));

    // Co-location cap pass.
    let mut per_24: BTreeMap<[u8; 3], usize> = BTreeMap::new();
    let mut per_asn: BTreeMap<u32, usize> = BTreeMap::new();
    let mut keyless: usize = 0; // nodes exposing neither /24 nor ASN, capped together
    let mut kept: Vec<&NodeRecord> = Vec::new();
    for node in ordered {
        if node.ip_v4_24.is_none() && node.asn.is_none() {
            if keyless >= COLOCATION_CAP {
                continue; // fail-closed: unattributed nodes share one capped bucket
            }
            keyless += 1;
            kept.push(node);
            continue;
        }
        let over_24 = node.ip_v4_24.map(|k| *per_24.get(&k).unwrap_or(&0) >= COLOCATION_CAP).unwrap_or(false);
        let over_asn = node.asn.map(|k| *per_asn.get(&k).unwrap_or(&0) >= COLOCATION_CAP).unwrap_or(false);
        if over_24 || over_asn {
            continue; // this /24 or ASN already has COLOCATION_CAP counted nodes
        }
        if let Some(k) = node.ip_v4_24 {
            *per_24.entry(k).or_insert(0) += 1;
        }
        if let Some(k) = node.asn {
            *per_asn.entry(k).or_insert(0) += 1;
        }
        kept.push(node);
    }

    // Per-owner rank pass (kept is already in node_order, so ranks are stable).
    let mut per_owner: BTreeMap<&str, usize> = BTreeMap::new();
    kept.into_iter()
        .map(|node| {
            let rank = per_owner.entry(node.owner_id.as_str()).or_insert(0);
            let node_rank = *rank;
            *rank += 1;
            RankedNode { node, node_rank }
        })
        .collect()
}

/// C1 node contributions from uptime samples + the §5 rank (one entry per kept
/// node, attributed to its owner). `uptime_ok/total` is the at-sync-required
/// success rate (`in_sync` samples over all samples for the node).
fn node_contributions(store: &FactStore) -> Vec<ContributionEntry> {
    rank_nodes(store)
        .into_iter()
        .map(|rn| {
            let total = store.samples_for(&rn.node.node_key).count() as u64;
            let ok = store.samples_for(&rn.node.node_key).filter(|s| s.in_sync).count() as u64;
            let mut evidence: Vec<String> = store.samples_for(&rn.node.node_key).map(|s| s.evidence.clone()).collect();
            evidence.sort();
            ContributionEntry {
                id: rn.node.owner_id.clone(),
                contribution: Contribution::Node {
                    uptime_ok: ok,
                    uptime_total: total,
                    geo_diverse: rn.node.geo_diverse,
                    fast_follow: rn.node.fast_follow,
                    node_rank: rn.node_rank,
                },
                evidence,
            }
        })
        .collect()
}

/// C1 validator contributions: aggregate each validator's attestation rows into
/// `attested/total` epoch participation; any slash in the window forfeits it.
fn validator_contributions(store: &FactStore) -> Vec<ContributionEntry> {
    // (attested, total, slashed, evidence) per validator, in a BTreeMap for order.
    let mut agg: BTreeMap<&str, (u64, u64, bool, Vec<String>)> = BTreeMap::new();
    for a in &store.attestations {
        let e = agg.entry(a.validator_id.as_str()).or_insert((0, 0, false, Vec::new()));
        e.1 += 1;
        if a.attested {
            e.0 += 1;
        }
        e.2 |= a.slashed;
        e.3.push(a.evidence.clone());
    }
    agg.into_iter()
        .map(|(id, (attested, total, slashed, mut evidence))| {
            evidence.sort();
            ContributionEntry {
                id: id.to_string(),
                contribution: Contribution::Validator { attested_epochs: attested, total_epochs: total, slashed },
                evidence,
            }
        })
        .collect()
}

/// C1 fixed chain activities (IBD bench / drill), one entry per row.
fn chain_fixed_contributions(store: &FactStore) -> Vec<ContributionEntry> {
    store
        .chain_fixed
        .iter()
        .map(|c| ContributionEntry {
            id: c.author_id.clone(),
            contribution: match c.kind {
                ChainFixedKind::IbdBench => Contribution::IbdBench,
                ChainFixedKind::Drill => Contribution::Drill,
            },
            evidence: vec![c.evidence.clone()],
        })
        .collect()
}

/// C2 bug contributions, one entry per triaged gh event.
fn bug_contributions(store: &FactStore) -> Vec<ContributionEntry> {
    store
        .gh_events
        .iter()
        .map(|e| ContributionEntry {
            id: e.reporter_id.clone(),
            contribution: Contribution::Bug { severity: e.severity, first_report: e.first_report, fix_pr_accepted: e.fix_pr_accepted },
            evidence: vec![e.evidence.clone()],
        })
        .collect()
}

/// C3/C4 fixed submissions, one entry per row (base points already tier-resolved).
fn submission_contributions(store: &FactStore) -> Vec<ContributionEntry> {
    store
        .submissions
        .iter()
        .map(|s| ContributionEntry {
            id: s.author_id.clone(),
            contribution: Contribution::Fixed { category: s.category, base_points: s.base_points },
            evidence: vec![s.evidence.clone()],
        })
        .collect()
}

/// Fold the whole store into the deterministic core's [`EpochInput`] for
/// `window`. The result is fed straight into [`misaka_mtp::score_epoch`]; its
/// `inputs_hash` is order-independent, so the entry order here is not consensus-
/// critical, but it is stable (node → validator → chain-fixed → bug → submission).
///
/// **Contract: the `store` must hold facts for exactly `window` and no other
/// epoch.** This function counts every fact in the store (it does not itself
/// filter by `window.range`), so the per-epoch cron MUST collect into a *fresh*
/// [`FactStore`] each run (see [`crate::collect::run_all`], which appends into a
/// caller-owned store). Reusing an accumulating store across epochs would
/// double-count prior epochs' facts — the caller owns this scoping.
pub fn build_epoch_input(window: &EpochWindow, store: &FactStore) -> EpochInput {
    let mut contributions = Vec::new();
    contributions.extend(node_contributions(store));
    contributions.extend(validator_contributions(store));
    contributions.extend(chain_fixed_contributions(store));
    contributions.extend(bug_contributions(store));
    contributions.extend(submission_contributions(store));

    EpochInput {
        epoch: window.epoch,
        range: window.range.clone(),
        network: window.network.clone(),
        stage: window.stage,
        contributions,
    }
}
