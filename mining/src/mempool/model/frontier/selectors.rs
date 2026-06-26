use crate::Policy;
use kaspa_consensus_core::{
    block::TemplateTransactionSelector,
    subnets::SUBNETWORK_ID_STAKE_ATTESTATION_SHARD,
    tx::{Transaction, TransactionId},
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

/// kaspa-pq audit v24 (H-3/M-4): a shared per-block `StakeAttestationShard` budget
/// (tx count + mass) that EVERY selector path funnels through, so the cap holds
/// uniformly whether the frontier produced a [`TakeAllSelector`], a
/// [`SequenceSelector`], or a [`RebalancingWeightedTransactionSelector`]. Before
/// this, only the rebalancing selector enforced the tx-count cap and NO selector
/// enforced the mass cap, so a small/medium frontier (TakeAll/Sequence path) could
/// emit an unbounded number of shard txs and unbounded shard mass into a template.
///
/// `0` for a limit means "unlimited" (overlay off / unconfigured), which makes the
/// whole filter a no-op — non-overlay nets are byte-identical.
#[derive(Clone, Copy, Default)]
pub(crate) struct ShardCap {
    /// Max shard txs (`0` = unlimited).
    max_txs: u64,
    /// Max cumulative shard mass (`0` = unlimited).
    max_mass: u64,
    /// Shard txs already admitted across `admit` calls within one selection round.
    used_txs: u64,
    /// Shard mass already admitted across `admit` calls within one selection round.
    used_mass: u64,
}

impl ShardCap {
    pub fn from_policy(policy: &Policy) -> Self {
        Self { max_txs: policy.max_attestation_shard_txs, max_mass: policy.max_attestation_shard_mass, used_txs: 0, used_mass: 0 }
    }

    /// `true` when no caps are configured — callers can skip the per-tx accounting
    /// entirely (the common, non-overlay case).
    #[inline]
    pub fn is_unlimited(&self) -> bool {
        self.max_txs == 0 && self.max_mass == 0
    }

    /// Reset the running usage for a fresh selection round.
    #[inline]
    pub fn reset(&mut self) {
        self.used_txs = 0;
        self.used_mass = 0;
    }

    /// Decide whether a tx may be admitted given the running shard usage. Non-shard
    /// txs are always admitted and never charged. A shard tx is admitted iff it
    /// would not exceed either configured cap; on admission its mass/count are
    /// charged. Returns `true` to keep, `false` to skip.
    #[inline]
    pub fn admit(&mut self, tx: &Transaction, mass: u64) -> bool {
        if tx.subnetwork_id != SUBNETWORK_ID_STAKE_ATTESTATION_SHARD {
            return true;
        }
        if self.max_txs != 0 && self.used_txs >= self.max_txs {
            return false;
        }
        let next_mass = self.used_mass.saturating_add(mass);
        if self.max_mass != 0 && next_mass > self.max_mass {
            return false;
        }
        self.used_txs += 1;
        self.used_mass = next_mass;
        true
    }
}

pub struct SequenceSelectorTransaction {
    pub tx: Arc<Transaction>,
    pub mass: u64,
}

impl SequenceSelectorTransaction {
    pub fn new(tx: Arc<Transaction>, mass: u64) -> Self {
        Self { tx, mass }
    }
}

type SequencePriorityIndex = u32;

/// The input sequence for the [`SequenceSelector`] transaction selector
#[derive(Default)]
pub struct SequenceSelectorInput {
    /// We use the btree map ordered by insertion order in order to follow
    /// the initial sequence order while allowing for efficient removal of previous selections
    inner: BTreeMap<SequencePriorityIndex, SequenceSelectorTransaction>,
}

impl FromIterator<SequenceSelectorTransaction> for SequenceSelectorInput {
    fn from_iter<T: IntoIterator<Item = SequenceSelectorTransaction>>(iter: T) -> Self {
        Self { inner: BTreeMap::from_iter(iter.into_iter().enumerate().map(|(i, v)| (i as SequencePriorityIndex, v))) }
    }
}

impl SequenceSelectorInput {
    pub fn push(&mut self, tx: Arc<Transaction>, mass: u64) {
        let idx = self.inner.len() as SequencePriorityIndex;
        self.inner.insert(idx, SequenceSelectorTransaction::new(tx, mass));
    }

    pub fn iter(&self) -> impl Iterator<Item = &SequenceSelectorTransaction> {
        self.inner.values()
    }
}

/// Helper struct for storing data related to previous selections
struct SequenceSelectorSelection {
    tx_id: TransactionId,
    mass: u64,
    priority_index: SequencePriorityIndex,
}

/// A selector which selects transactions in the order they are provided. The selector assumes
/// that the transactions were already selected via weighted sampling and simply tries them one
/// after the other until the block mass limit is reached.  
pub struct SequenceSelector {
    input_sequence: SequenceSelectorInput,
    selected_vec: Vec<SequenceSelectorSelection>,
    /// Maps from selected tx ids to tx mass so that the total used mass can be subtracted on tx reject
    selected_map: Option<HashMap<TransactionId, u64>>,
    total_selected_mass: u64,
    overall_candidates: usize,
    overall_rejections: usize,
    /// kaspa-pq audit v24 (H-3/M-4): per-block `StakeAttestationShard` budget,
    /// enforced in lockstep with the block-mass cap. A no-op (`is_unlimited`) when
    /// the overlay is off, keeping non-overlay nets byte-identical.
    shard_cap: ShardCap,
    policy: Policy,
}

impl SequenceSelector {
    pub fn new(input_sequence: SequenceSelectorInput, policy: Policy) -> Self {
        Self {
            overall_candidates: input_sequence.inner.len(),
            selected_vec: Vec::with_capacity(input_sequence.inner.len()),
            input_sequence,
            selected_map: Default::default(),
            total_selected_mass: Default::default(),
            overall_rejections: Default::default(),
            shard_cap: ShardCap::from_policy(&policy),
            policy,
        }
    }

    #[inline]
    fn reset_selection(&mut self) {
        self.selected_vec.clear();
        self.selected_map = None;
        self.shard_cap.reset();
    }
}

impl TemplateTransactionSelector for SequenceSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        // Remove selections from the previous round if any
        for selection in self.selected_vec.drain(..) {
            self.input_sequence.inner.remove(&selection.priority_index);
        }
        // Reset selection data structures
        self.reset_selection();
        let mut transactions = Vec::with_capacity(self.input_sequence.inner.len());

        // Iterate the input sequence in order
        for (&priority_index, tx) in self.input_sequence.inner.iter() {
            if self.total_selected_mass.saturating_add(tx.mass) > self.policy.max_block_mass {
                // We assume the sequence is relatively small, hence we keep on searching
                // for transactions with lower mass which might fit into the remaining gap
                continue;
            }
            // kaspa-pq audit v24 (H-3/M-4): enforce the per-block shard tx/mass budget
            // here too (not only in the rebalancing selector). A no-op when the overlay
            // is off. Skip a shard tx over budget but keep searching for fitting txs.
            if !self.shard_cap.admit(&tx.tx, tx.mass) {
                continue;
            }
            self.total_selected_mass += tx.mass;
            self.selected_vec.push(SequenceSelectorSelection { tx_id: tx.tx.id(), mass: tx.mass, priority_index });
            transactions.push(tx.tx.as_ref().clone())
        }
        transactions
    }

    fn reject_selection(&mut self, tx_id: TransactionId) {
        // Lazy-create the map only when there are actual rejections
        let selected_map = self.selected_map.get_or_insert_with(|| self.selected_vec.iter().map(|tx| (tx.tx_id, tx.mass)).collect());
        let mass = selected_map.remove(&tx_id).expect("only previously selected txs can be rejected (and only once)");
        // Selections must be counted in total selected mass, so this subtraction cannot underflow
        self.total_selected_mass -= mass;
        self.overall_rejections += 1;
    }

    fn is_successful(&self) -> bool {
        const SUFFICIENT_MASS_THRESHOLD: f64 = 0.8;
        const LOW_REJECTION_FRACTION: f64 = 0.2;

        // We consider the operation successful if either mass occupation is above 80% or rejection rate is below 20%
        self.overall_rejections == 0
            || (self.total_selected_mass as f64) > self.policy.max_block_mass as f64 * SUFFICIENT_MASS_THRESHOLD
            || (self.overall_rejections as f64) < self.overall_candidates as f64 * LOW_REJECTION_FRACTION
    }
}

/// kaspa-pq DNS-finality block-template composition (P1).
///
/// Yields a fixed, pre-chosen set of "priority" attestation-shard transactions FIRST (deterministic
/// order, bounded by the per-block shard tx/mass budget), then delegates to an inner selector built
/// over the remaining (non-priority) candidates with the remaining block mass.
///
/// This makes current/recent-epoch (and reward-fresh) attestation shards win over stale ones in the
/// template even when the stale ones have accumulated, which was the root cause of the live-testnet
/// DNS-finality stall. Correct-over-clever: the priority set is selected once up front; rejects of
/// priority txs are tracked so the inner selector's mass accounting is never double-counted, and the
/// total selected mass never exceeds the block limit.
pub struct AttestationPrioritySelector {
    /// The pre-chosen priority attestation txs (with mass), yielded on the first call.
    priority: Vec<SequenceSelectorTransaction>,
    /// Inner selector for the remaining (non-priority) candidates.
    inner: Box<dyn TemplateTransactionSelector>,
    /// Whether the priority batch has already been emitted (it is emitted exactly once).
    priority_emitted: bool,
    /// Mass of the priority txs that survived (were not rejected), for the success heuristic.
    selected_priority_mass: u64,
    /// Map of currently-selected priority tx ids -> mass (for reject bookkeeping). Built lazily.
    priority_selected_map: Option<HashMap<TransactionId, u64>>,
    /// Number of priority rejections (counts toward the success heuristic).
    priority_rejections: usize,
    policy: Policy,
}

impl AttestationPrioritySelector {
    pub fn new(priority: Vec<SequenceSelectorTransaction>, inner: Box<dyn TemplateTransactionSelector>, policy: Policy) -> Self {
        Self {
            priority,
            inner,
            priority_emitted: false,
            selected_priority_mass: 0,
            priority_selected_map: None,
            priority_rejections: 0,
            policy,
        }
    }
}

impl TemplateTransactionSelector for AttestationPrioritySelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        if !self.priority_emitted {
            self.priority_emitted = true;
            // Emit all priority txs first (their cumulative mass was already bounded at construction
            // time against the per-block shard mass budget and the block mass). Then top up from the
            // inner selector with whatever block mass remains.
            self.selected_priority_mass = self.priority.iter().map(|t| t.mass).sum();
            self.priority_selected_map = None;
            let mut txs: Vec<Transaction> = self.priority.iter().map(|t| t.tx.as_ref().clone()).collect();
            txs.extend(self.inner.select_transactions());
            txs
        } else {
            // Subsequent calls only refill from the inner selector (priority txs are emitted once).
            self.inner.select_transactions()
        }
    }

    fn reject_selection(&mut self, tx_id: TransactionId) {
        // A rejection may target either a priority tx or an inner tx. Resolve against the priority
        // set first (lazily built map), else delegate to the inner selector.
        let map = self
            .priority_selected_map
            .get_or_insert_with(|| self.priority.iter().map(|t| (t.tx.id(), t.mass)).collect());
        if let Some(mass) = map.remove(&tx_id) {
            self.selected_priority_mass = self.selected_priority_mass.saturating_sub(mass);
            self.priority_rejections += 1;
        } else {
            self.inner.reject_selection(tx_id);
        }
    }

    fn is_successful(&self) -> bool {
        const SUFFICIENT_MASS_THRESHOLD: f64 = 0.8;

        // Successful if the inner selection is successful, or if the priority txs alone already fill
        // most of the block, or if priority had no rejections and the inner selector is satisfied.
        self.inner.is_successful()
            && (self.priority_rejections == 0
                || (self.selected_priority_mass as f64) > self.policy.max_block_mass as f64 * SUFFICIENT_MASS_THRESHOLD)
    }
}

/// A selector that selects all the transactions it holds and is always considered successful.
/// If all mempool transactions have combined mass which is <= block mass limit, this selector
/// should be called and provided with all the transactions.
pub struct TakeAllSelector {
    txs: Vec<Arc<Transaction>>,
    /// kaspa-pq audit v24 (H-3/M-4): per-tx masses, parallel to `txs`, present only
    /// when a `StakeAttestationShard` cap is configured (otherwise empty — the
    /// non-overlay path stays allocation-free). Used to enforce the shard mass cap.
    masses: Vec<u64>,
    /// kaspa-pq audit v24 (H-3/M-4): the per-block shard budget. A no-op
    /// (`is_unlimited`) when the overlay is off, keeping non-overlay nets identical.
    cap: ShardCap,
}

impl TakeAllSelector {
    pub fn new(txs: Vec<Arc<Transaction>>) -> Self {
        Self { txs, masses: Vec::new(), cap: ShardCap::default() }
    }

    /// kaspa-pq audit v24 (H-3/M-4): construct with a per-block shard cap. `masses`
    /// must be 1:1 with `txs`. Shard txs beyond the cap (count or mass) are skipped;
    /// non-shard txs are always taken. When the cap is unlimited this behaves exactly
    /// like [`TakeAllSelector::new`].
    pub(crate) fn with_cap(txs: Vec<Arc<Transaction>>, masses: Vec<u64>, cap: ShardCap) -> Self {
        debug_assert!(cap.is_unlimited() || masses.len() == txs.len(), "masses must be 1:1 with txs when a shard cap applies");
        Self { txs, masses, cap }
    }
}

impl TemplateTransactionSelector for TakeAllSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        // Fast path: no shard cap → drain everything (byte-identical to upstream).
        if self.cap.is_unlimited() {
            return self.txs.drain(..).map(|tx| tx.as_ref().clone()).collect();
        }
        // Cap path: take all non-shard txs and shard txs within the per-block budget.
        self.cap.reset();
        let mut out = Vec::with_capacity(self.txs.len());
        for (tx, &mass) in self.txs.drain(..).zip(self.masses.iter()) {
            if self.cap.admit(&tx, mass) {
                out.push(tx.as_ref().clone());
            }
        }
        out
    }

    fn reject_selection(&mut self, _tx_id: TransactionId) {
        // No need to track rejections (for reduced mass), since there's nothing else to select
    }

    fn is_successful(&self) -> bool {
        // Considered successful because we provided all mempool transactions to this
        // selector, so there's no point in retries
        true
    }
}
