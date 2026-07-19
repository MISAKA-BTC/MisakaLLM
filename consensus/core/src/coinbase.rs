use crate::tx::{ScriptPublicKey, Transaction};
use kaspa_hashes::Hash64;
use serde::{Deserialize, Serialize};

/// ADR-0039 §17.2: which work lane produced a mergeset source block, and — for the PALW compute lane —
/// the provider-pair reward scripts and leaf reference. Derived **identically** in coinbase
/// construction and validation from the source `Header` + PALW leaf state (both go through the single
/// [`BlockRewardData`] built in `calculate_utxo_state`), so construction == validation cannot drift.
/// `HashMiner` is the only variant while the PALW lane is inert — no algo-4 header is minted, so every
/// source block is on the algo-3 hash floor.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum WorkRewardClass {
    /// algo-3 hash-floor source — the worker base is paid to the single source miner (`BlockRewardData::
    /// script_public_key`), i.e. the current, pre-PALW behavior.
    HashMiner,
    /// algo-4 PALW replica source — on a **unique blue** credit the worker base (77 %, ADR-0039 §17.1)
    /// splits between the two providers' one-time reward scripts (A 38.5 % / B 38.5 %) and the validator
    /// share is the PALW-lane 15 %. Red/duplicate PALW sources pay the pair nothing (§17.4).
    ReplicaPalw { batch_id: Hash64, leaf_index: u32, provider_a_script: ScriptPublicKey, provider_b_script: ScriptPublicKey },
    /// algo-4 PALW replica source whose MINTING epoch reconstructs as `Halted` from the merging block's
    /// derived beacon state (ADR-0039 §11.3 / K5): compute minted under an untrusted (halted) beacon is
    /// paid NOTHING anywhere — no provider outputs, no fee-worker output, no inclusion-pool add, zero
    /// validator pool — the §17.4 red/duplicate burn-by-don't-mint treatment. Carries only the leaf
    /// reference (no scripts: nothing is paid). NEVER a silent `HashMiner` downgrade, which would
    /// reroute the 77 % worker base to the miner script.
    ///
    /// Bincode caveat (same as `BlockRewardData::finality_fees`): `BlockRewardData` rides the persisted
    /// `VirtualState`, so ONLY a TRAILING variant append is decode-safe for pre-existing rows; this
    /// variant is additionally never constructed while PALW is inert (`u64::MAX` on every shipped
    /// preset), so live stores never contain it.
    ReplicaPalwHalted { batch_id: Hash64, leaf_index: u32 },
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct MinerData<T: AsRef<[u8]> = Vec<u8>> {
    pub script_public_key: ScriptPublicKey,
    pub extra_data: T,
}

impl<T: AsRef<[u8]>> MinerData<T> {
    pub fn new(script_public_key: ScriptPublicKey, extra_data: T) -> Self {
        Self { script_public_key, extra_data }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct CoinbaseData<T: AsRef<[u8]> = Vec<u8>> {
    pub blue_score: u64,
    pub subsidy: u64,
    pub miner_data: MinerData<T>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlockRewardData {
    pub subsidy: u64,
    pub total_fees: u64,
    /// kaspa-pq ADR-0018 §F bridge wiring: the subset of `total_fees` paid by **finality-class**
    /// txs — accepted txs creating ≥1 `EVM_DEPOSIT_LOCK` output (ADR-0020 §9.2), classified at fee
    /// accumulation in `calculate_utxo_state` (shared by coinbase construction AND validation, so
    /// c==v holds) and gated on `DnsParams::finality_fee_activation_daa_score`. Split at the
    /// validator-primary `split_finality_fees` ratios; the normal-class part is `total_fees −
    /// finality_fees`. `0` below the fence ⇒ all splits byte-identical to the pre-wiring math.
    /// Invariant: `finality_fees ≤ total_fees`. NOTE: `BlockRewardData` is persisted inside
    /// `VirtualState` (serde/bincode, not self-describing) — adding this field is a store-format
    /// change riding the ADR-0007 Phase-3 re-genesis. On mainnet/testnet an un-wiped data dir is
    /// caught by the startup genesis-mismatch guard (their genesis hash changed in Phase 3); on
    /// devnet/simnet (genesis unchanged) the old `VirtualState` fails to DECODE instead — surfaced
    /// as the actionable "store format changed — wipe the data directory" error in
    /// `DbVirtualStateStore::new`. Either way no old data dir can be silently resumed.
    pub finality_fees: u64,
    pub script_public_key: ScriptPublicKey,
    /// ADR-0039 §17.2: the source block's work lane + (for PALW) provider-pair reward scripts. Always
    /// [`WorkRewardClass::HashMiner`] while the PALW lane is inert. Same `VirtualState` bincode
    /// store-format caveat as `finality_fees` above — this field rides the same re-genesis; an
    /// un-wiped data dir fails the genesis guard or the `VirtualState` decode, never a silent resume.
    pub work_reward_class: WorkRewardClass,
}

impl BlockRewardData {
    pub fn new(
        subsidy: u64,
        total_fees: u64,
        finality_fees: u64,
        script_public_key: ScriptPublicKey,
        work_reward_class: WorkRewardClass,
    ) -> Self {
        Self { subsidy, total_fees, finality_fees, script_public_key, work_reward_class }
    }
}

/// Holds a coinbase transaction along with meta-data obtained during creation
pub struct CoinbaseTransactionTemplate {
    pub tx: Transaction,
    pub has_red_reward: bool,
    /// Coinbase output indices whose script belongs to the current block miner
    /// and must be rewritten when `MinerData::script_public_key` changes.
    /// Currently this includes the aggregate red reward and the worker-inclusion
    /// bounty; validator/reserve outputs can be interleaved between them.
    pub miner_script_output_indices: Vec<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::ScriptVec;

    fn spk(byte: u8) -> ScriptPublicKey {
        ScriptPublicKey::new(0, ScriptVec::from_slice(&[byte, byte]))
    }

    /// ADR-0039 §17.2: `BlockRewardData` (with the new `work_reward_class`) is persisted in
    /// `VirtualState` via bincode. Both `WorkRewardClass` variants must round-trip so a re-genesis
    /// store faithfully carries a source block's lane + provider scripts.
    #[test]
    fn block_reward_data_work_reward_class_bincode_roundtrip() {
        // Inert / hash-floor default.
        let hash = BlockRewardData::new(500, 12, 3, spk(0xaa), WorkRewardClass::HashMiner);
        assert_eq!(hash.work_reward_class, WorkRewardClass::HashMiner);
        let bytes = bincode::serialize(&hash).unwrap();
        let back: BlockRewardData = bincode::deserialize(&bytes).unwrap();
        assert_eq!(back.subsidy, 500);
        assert_eq!(back.finality_fees, 3);
        assert_eq!(back.work_reward_class, WorkRewardClass::HashMiner);

        // PALW replica variant carries the leaf ref + both provider scripts.
        let palw = BlockRewardData::new(
            600,
            0,
            0,
            spk(0x01),
            WorkRewardClass::ReplicaPalw {
                batch_id: Hash64::from_bytes([7u8; 64]),
                leaf_index: 42,
                provider_a_script: spk(0xa0),
                provider_b_script: spk(0xb0),
            },
        );
        let back: BlockRewardData = bincode::deserialize(&bincode::serialize(&palw).unwrap()).unwrap();
        match back.work_reward_class {
            WorkRewardClass::ReplicaPalw { batch_id, leaf_index, provider_a_script, provider_b_script } => {
                assert_eq!(batch_id, Hash64::from_bytes([7u8; 64]));
                assert_eq!(leaf_index, 42);
                assert_eq!(provider_a_script, spk(0xa0));
                assert_eq!(provider_b_script, spk(0xb0));
            }
            _ => panic!("expected ReplicaPalw"),
        }

        // K5 (§11.3): the trailing ReplicaPalwHalted zero-pay variant round-trips (carries only the leaf
        // ref — no scripts, since nothing is paid).
        let halted = BlockRewardData::new(
            600,
            0,
            0,
            spk(0x01),
            WorkRewardClass::ReplicaPalwHalted { batch_id: Hash64::from_bytes([9u8; 64]), leaf_index: 7 },
        );
        let back: BlockRewardData = bincode::deserialize(&bincode::serialize(&halted).unwrap()).unwrap();
        match back.work_reward_class {
            WorkRewardClass::ReplicaPalwHalted { batch_id, leaf_index } => {
                assert_eq!(batch_id, Hash64::from_bytes([9u8; 64]));
                assert_eq!(leaf_index, 7);
            }
            _ => panic!("expected ReplicaPalwHalted"),
        }
    }
}
