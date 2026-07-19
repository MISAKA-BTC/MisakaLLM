//! PALW beacon producer (ADR-0039 §11.2) — the commit/reveal half of the epoch randomness
//! beacon `R_E` a bonded node runs so the algo-4 eligibility draw has fresh, unbiased entropy.
//!
//! Each epoch a participant:
//!   1. **commits** (carried in epoch `E-2`, targeting `E`): pick a 64-byte secret, publish
//!      `commitment = Hash64_k(beacon-commit, E ‖ secret ‖ bond)` in a signed
//!      [`PalwBeaconCommitV1`], and KEEP the secret ([`BeaconSecret`]);
//!   2. **reveals** (carried in epoch `E-1`): open the secret in a signed [`PalwBeaconRevealV1`].
//!
//! The consensus aggregates the valid reveals (a commitment with a matching opened secret and a
//! valid ML-DSA-87 signature from the bond's validator key) into `R_E`. This module produces the
//! two signed payloads byte-for-byte the way the virtual processor verifies them
//! (`signing_hash` under [`PALW_BEACON_MLDSA87_CONTEXT`], commitment via `beacon_commitment`);
//! carrying them into an actual TX + submitting is the node's job (later phase). Pure + no
//! wall-clock apart from the caller-supplied `current_epoch`.

use kaspa_consensus_core::palw::{
    PALW_BEACON_MLDSA87_CONTEXT, PalwBeaconCommitV1, PalwBeaconRevealV1, beacon_commit_target_epoch, beacon_commitment,
    beacon_reveal_target_epoch,
};
use kaspa_consensus_core::tx::TransactionOutpoint;
use kaspa_pq_validator_core::ValidatorKey;

/// The secret an operator keeps between its commit (epoch `E-2`) and its reveal (epoch `E-1`).
/// Opaque randomness; disclosed only in the reveal.
#[derive(Clone)]
pub struct BeaconSecret {
    /// The epoch this secret's beacon targets (`E`).
    pub target_epoch: u64,
    /// The 64-byte opened-at-reveal secret.
    pub random_64: [u8; 64],
    /// The bond outpoint this beacon is attributed to.
    pub bond: TransactionOutpoint,
}

/// A signed beacon commit + its borsh payload + the secret to keep for the reveal.
pub struct SignedBeaconCommit {
    pub commit: PalwBeaconCommitV1,
    /// `borsh(commit)` — the bytes a beacon-commit PALW TX output carries.
    pub payload: Vec<u8>,
    pub secret: BeaconSecret,
}

/// A signed beacon reveal + its borsh payload.
pub struct SignedBeaconReveal {
    pub reveal: PalwBeaconRevealV1,
    /// `borsh(reveal)` — the bytes a beacon-reveal PALW TX output carries.
    pub payload: Vec<u8>,
}

/// Produces this node's signed beacon commit/reveal payloads for its bond.
pub struct BeaconProducer {
    key: ValidatorKey,
    bond: TransactionOutpoint,
    network_id: u32,
}

impl BeaconProducer {
    /// `key` is the bond's ML-DSA-87 validator key; `bond` the beacon-attributed bond outpoint;
    /// `network_id` the consensus PALW network number (bound into every beacon signing hash).
    pub fn new(key: ValidatorKey, bond: TransactionOutpoint, network_id: u32) -> Self {
        Self { key, bond, network_id }
    }

    pub fn bond(&self) -> &TransactionOutpoint {
        &self.bond
    }

    /// Build a signed beacon COMMIT for the epoch a commit carried in `current_epoch` targets
    /// (`E = current_epoch + 2`). `random_64` is the freshly-drawn secret to commit to. `None`
    /// only if the target epoch would overflow. Keep the returned [`BeaconSecret`] for the reveal.
    pub fn build_commit(&self, current_epoch: u64, random_64: [u8; 64]) -> Option<SignedBeaconCommit> {
        let target = beacon_commit_target_epoch(current_epoch)?;
        let commitment = beacon_commitment(target, &random_64, &self.bond);
        let mut commit = PalwBeaconCommitV1 { version: 1, epoch: target, bond_outpoint: self.bond, commitment, signature: Vec::new() };
        let digest = commit.signing_hash(self.network_id);
        commit.signature = self.key.sign_with_context(&digest.as_bytes(), PALW_BEACON_MLDSA87_CONTEXT).to_vec();
        let payload = borsh::to_vec(&commit).ok()?;
        Some(SignedBeaconCommit { commit, payload, secret: BeaconSecret { target_epoch: target, random_64, bond: self.bond } })
    }

    /// Build a signed beacon REVEAL for the epoch a reveal carried in `current_epoch` targets
    /// (`E = current_epoch + 1`), opening `secret`. `None` if the target epoch does not match the
    /// secret's `target_epoch` (only the secret committed for THIS epoch may be revealed now).
    pub fn build_reveal(&self, current_epoch: u64, secret: &BeaconSecret) -> Option<SignedBeaconReveal> {
        let target = beacon_reveal_target_epoch(current_epoch)?;
        if target != secret.target_epoch {
            return None;
        }
        let mut reveal = PalwBeaconRevealV1 {
            version: 1,
            epoch: target,
            bond_outpoint: self.bond,
            random_64: secret.random_64,
            signature: Vec::new(),
        };
        let digest = reveal.signing_hash(self.network_id);
        reveal.signature = self.key.sign_with_context(&digest.as_bytes(), PALW_BEACON_MLDSA87_CONTEXT).to_vec();
        let payload = borsh::to_vec(&reveal).ok()?;
        Some(SignedBeaconReveal { reveal, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::palw::{PalwBeaconCommitV1, PalwBeaconRevealV1};
    use kaspa_hashes::Hash64;
    use kaspa_txscript::verify_mldsa87_with_context;

    const NET: u32 = 0x9107;

    fn producer() -> (BeaconProducer, ValidatorKey) {
        let key = ValidatorKey::from_seed([0xB7; 32]);
        let bond = TransactionOutpoint::new(Hash64::from_bytes([6; 64]), 0);
        (BeaconProducer::new(ValidatorKey::from_seed([0xB7; 32]), bond, NET), key)
    }

    #[test]
    fn commit_then_reveal_verify_and_open_the_secret() {
        let (p, key) = producer();
        let pubkey = key.public_key();
        let random = [0x5A; 64];

        // Commit carried in epoch 10 targets epoch 12 (lead 2).
        let sc = p.build_commit(10, random).expect("commit builds");
        assert_eq!(sc.commit.epoch, 12);
        assert_eq!(sc.secret.target_epoch, 12);
        // The signature verifies under the bond's pubkey + the beacon context (the exact call the
        // virtual processor makes).
        let cdigest = sc.commit.signing_hash(NET);
        assert_eq!(
            verify_mldsa87_with_context(pubkey, &cdigest.as_bytes(), &sc.commit.signature, PALW_BEACON_MLDSA87_CONTEXT),
            Ok(true)
        );
        // The payload round-trips to the same commit.
        let decoded: PalwBeaconCommitV1 = borsh::from_slice(&sc.payload).unwrap();
        assert_eq!(decoded, sc.commit);

        // Reveal carried in epoch 11 targets epoch 12 (lead 1) and must open the committed secret.
        let sr = p.build_reveal(11, &sc.secret).expect("reveal builds for the matching target");
        assert_eq!(sr.reveal.epoch, 12);
        assert!(sr.reveal.matches_commit(&sc.commit.commitment), "the reveal opens the committed secret");
        let rdigest = sr.reveal.signing_hash(NET);
        assert_eq!(
            verify_mldsa87_with_context(pubkey, &rdigest.as_bytes(), &sr.reveal.signature, PALW_BEACON_MLDSA87_CONTEXT),
            Ok(true)
        );
        let decoded_r: PalwBeaconRevealV1 = borsh::from_slice(&sr.payload).unwrap();
        assert_eq!(decoded_r, sr.reveal);
    }

    #[test]
    fn reveal_only_the_secret_for_this_epoch() {
        let (p, _key) = producer();
        // A secret committed for epoch 12 cannot be revealed in epoch 12 (that targets epoch 13).
        let sc = p.build_commit(10, [0x11; 64]).unwrap();
        assert!(p.build_reveal(12, &sc.secret).is_none(), "epoch-12 reveal targets 13, not the epoch-12 secret");
        // The correct reveal epoch (11 → target 12) works.
        assert!(p.build_reveal(11, &sc.secret).is_some());
    }
}
