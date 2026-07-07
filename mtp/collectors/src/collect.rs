//! Collectors (ADR-0027 §4.1, D8): the I/O layer that fills the [`FactStore`].
//!
//! Each of the four production collectors — **p2p-crawler** (×2 vantage),
//! **chain-indexer**, **github-sync**, **campaign-forms** — implements the
//! [`Collector`] seam. In a deployment the concrete collector performs the
//! network/DB/GitHub fetch on its cron tick; the part that lives here and is
//! deterministically testable is the **normalization**: taking already-fetched
//! raw rows and writing typed §4.2 facts into the store. A [`MockCollector`]
//! feeds a fixed fact set so the whole pipeline is exercised offline — the same
//! trait-seam-plus-mock shape as `misaka-mil-provider`'s `InferenceBackend`
//! /`MockBackend`.
//!
//! The network fetch itself (dialing peers, reading the chain, calling the
//! GitHub API) is explicitly out of scope — the ADR specifies a single Rust
//! service + cron around this crate.

use crate::store::{AttestationRow, ChainFixed, FactStore, GhEvent, Identity, IdentityKind, NodeRecord, Submission, UptimeSample};
use misaka_mtp::Stage;

/// The epoch window a collection run targets (mirrors [`misaka_mtp::EpochInput`]'s
/// header). Passed to every collector so time-scoped sources agree on the range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochWindow {
    pub epoch: u64,
    /// `[start, end)` RFC-3339 UTC bounds of the weekly epoch.
    pub range: [String; 2],
    pub network: String,
    pub stage: Stage,
}

/// A collection failure (a source was unreachable / returned malformed rows).
#[derive(Debug, thiserror::Error)]
pub enum CollectError {
    #[error("collector {collector} source error: {reason}")]
    Source { collector: String, reason: String },
}

/// A source of raw contribution facts for one epoch window (§4.1). Real adapters
/// fetch then normalize; the [`MockCollector`] just replays a fixed fact set.
pub trait Collector {
    /// Stable collector name (for logs / the run report).
    fn name(&self) -> &str;

    /// Normalize this source's rows into `store` for `window`. Returns the number
    /// of fact rows written (across all tables it touches).
    fn collect(&self, window: &EpochWindow, store: &mut FactStore) -> Result<usize, CollectError>;
}

/// Run every collector in order into a shared store, returning `(name, rows)` per
/// collector. Ordering does not affect the final ledger — the aggregator and the
/// core's `inputs_hash` are order-independent — but a stable order keeps the run
/// report reproducible.
pub fn run_all(
    collectors: &[Box<dyn Collector>],
    window: &EpochWindow,
    store: &mut FactStore,
) -> Result<Vec<(String, usize)>, CollectError> {
    let mut report = Vec::with_capacity(collectors.len());
    for c in collectors {
        let n = c.collect(window, store)?;
        report.push((c.name().to_string(), n));
    }
    Ok(report)
}

// --- p2p-crawler (×2 vantage): uptime samples + node records -----------------------------

/// The p2p-crawler collector (§4.1, §5). A crawl vantage produces per-node
/// probes; this normalizes them into `nodes` + `uptime_samples`. Two instances
/// (DE / JP) run and both write into the same store — cross-vantage agreement is
/// what earns the `m_geo` bonus at aggregation time.
pub struct P2pCrawlerCollector {
    pub vantage: String,
    /// Nodes this vantage knows about (already fetched).
    pub nodes: Vec<NodeRecord>,
    /// Probes taken this window (already fetched).
    pub samples: Vec<UptimeSample>,
}

impl Collector for P2pCrawlerCollector {
    fn name(&self) -> &str {
        "p2p-crawler"
    }

    fn collect(&self, _window: &EpochWindow, store: &mut FactStore) -> Result<usize, CollectError> {
        let mut n = 0;
        for node in &self.nodes {
            store.upsert_identity(Identity { id: node.owner_id.clone(), kind: IdentityKind::Node });
            store.upsert_node(node.clone());
            n += 1;
        }
        for s in &self.samples {
            store.uptime_samples.push(s.clone());
            n += 1;
        }
        Ok(n)
    }
}

// --- chain-indexer: validator attestations + C1 fixed chain activities -------------------

/// The chain-indexer collector (§4.1). Reads the chain for validator attestations
/// (and slash events) plus IBD-benchmark / drill participation.
pub struct ChainIndexerCollector {
    pub attestations: Vec<AttestationRow>,
    pub chain_fixed: Vec<ChainFixed>,
}

impl Collector for ChainIndexerCollector {
    fn name(&self) -> &str {
        "chain-indexer"
    }

    fn collect(&self, _window: &EpochWindow, store: &mut FactStore) -> Result<usize, CollectError> {
        let mut n = 0;
        for a in &self.attestations {
            store.upsert_identity(Identity { id: a.validator_id.clone(), kind: IdentityKind::Address });
            store.attestations.push(a.clone());
            n += 1;
        }
        for c in &self.chain_fixed {
            store.upsert_identity(Identity { id: c.author_id.clone(), kind: IdentityKind::Address });
            store.chain_fixed.push(c.clone());
            n += 1;
        }
        Ok(n)
    }
}

// --- github-sync: bug reports ------------------------------------------------------------

/// The github-sync collector (§4.1, §3.2). Mirrors triaged issues/PRs into
/// `gh_events` (the severity/first/fix curation is done by the triage step it
/// wraps, per D2's mandatory-private-disclosure rule).
pub struct GithubSyncCollector {
    pub events: Vec<GhEvent>,
}

impl Collector for GithubSyncCollector {
    fn name(&self) -> &str {
        "github-sync"
    }

    fn collect(&self, _window: &EpochWindow, store: &mut FactStore) -> Result<usize, CollectError> {
        let mut n = 0;
        for e in &self.events {
            store.upsert_identity(Identity { id: e.reporter_id.clone(), kind: IdentityKind::Github });
            store.gh_events.push(e.clone());
            n += 1;
        }
        Ok(n)
    }
}

// --- campaign-forms: C3 verification + C4 infra submissions ------------------------------

/// The campaign-forms collector (§4.1, §3.3/§3.4). Ingests form submissions whose
/// per-event cap / tier is already resolved into `base_points`.
pub struct CampaignFormsCollector {
    pub submissions: Vec<Submission>,
}

impl Collector for CampaignFormsCollector {
    fn name(&self) -> &str {
        "campaign-forms"
    }

    fn collect(&self, _window: &EpochWindow, store: &mut FactStore) -> Result<usize, CollectError> {
        let mut n = 0;
        for s in &self.submissions {
            store.upsert_identity(Identity { id: s.author_id.clone(), kind: IdentityKind::Address });
            store.submissions.push(s.clone());
            n += 1;
        }
        Ok(n)
    }
}

// --- mock: a fixed store for offline pipeline tests --------------------------------------

/// A collector that writes a caller-supplied store snapshot verbatim — the
/// offline stand-in that lets the aggregation pipeline be tested without any
/// live source (mirrors `MockBackend`).
pub struct MockCollector {
    pub facts: FactStore,
}

impl Collector for MockCollector {
    fn name(&self) -> &str {
        "mock"
    }

    fn collect(&self, _window: &EpochWindow, store: &mut FactStore) -> Result<usize, CollectError> {
        let f = &self.facts;
        store.identities.extend(f.identities.iter().cloned());
        store.nodes.extend(f.nodes.iter().cloned());
        store.uptime_samples.extend(f.uptime_samples.iter().cloned());
        store.attestations.extend(f.attestations.iter().cloned());
        store.gh_events.extend(f.gh_events.iter().cloned());
        store.submissions.extend(f.submissions.iter().cloned());
        store.chain_fixed.extend(f.chain_fixed.iter().cloned());
        Ok(f.len())
    }
}
