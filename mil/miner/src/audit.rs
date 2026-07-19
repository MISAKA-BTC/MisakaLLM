//! PALW auditor role (ADR-0039 §10) — the batch **certificate** a single node cannot self-produce.
//!
//! A leaf chunk puts a provider's minted leaves on-chain, but a batch only becomes block-referenceable
//! after an AUDITOR QUORUM certifies it: the beacon deterministically selects a slate of bonded
//! auditors ([`sample_auditors_by_score`]), each independently samples the batch's receipts, votes
//! pass/reject, and ML-DSA-87-signs its verdict; consensus caches the batch's certificate once the
//! stake-weighted PASS tally reaches quorum ([`PalwBatchCertificateV1::quorum_reached`]). This module
//! is the auditor SIDE of that role — one [`Auditor`] per independent key — plus the quorum assembly a
//! certificate submitter runs. It is NOT a single-operator shortcut: every vote is a real, separately
//! keyed ML-DSA-87 signature over the design-§10.1 binding, so a certificate produced here is
//! indistinguishable from one produced by N physically distinct auditors.
//!
//! **What consensus enforces, and why this module must match it exactly.** The stateless
//! `validate_certificate` (transaction isolation) only length-checks each vote signature and requires
//! the canonical `bond_outpoint`-ascending vote order + a sane epoch range. Since ADR-0040 P1-3
//! (CERT-01) the cryptographic half is no longer hypothetical: `verify_certificate_attestation`
//! ML-DSA-87-verifies **every** vote under the bond's registered `validator_pubkey`, requires each
//! voting bond to be ACTIVE at the certifying block's DAA score, binds the declared `approving_stake`
//! to the recomputed PASS tally, and applies the stake-weighted quorum. So this producer is not
//! rehearsing a future check — it is feeding a live one, and construction == validation is a hard
//! requirement: each vote is signed under [`PALW_AUDITOR_MLDSA87_CONTEXT`] (the same `ctx` the verifier
//! passes; FIPS-204 binds `ctx` into the signature, so a mismatch here makes every certificate this
//! module emits unverifiable), and `approving_stake` is declared as exactly the tally the verifier will
//! re-derive. The tests prove both via `verify_mldsa87_with_context`.

use std::collections::HashMap;

use kaspa_consensus_core::palw::{
    PALW_AUDITOR_MLDSA87_CONTEXT, PALW_MAX_AUDITOR_VOTES_V1, PalwAuditorVoteV1, PalwBatchCertificateV1, auditor_set_commitment,
    sample_auditors_by_score,
};
use kaspa_consensus_core::tx::TransactionOutpoint;
use kaspa_hashes::Hash64;
use kaspa_pq_validator_core::ValidatorKey;

/// The `0x33` subnetwork byte a batch-certificate PALW TX output carries (mirrors
/// `PalwTxKind::from_subnetwork_byte(0x33) == BatchCertificate`).
pub const BATCH_CERTIFICATE_SUBNETWORK_BYTE: u8 = 0x33;

/// Why a certificate could not be assembled.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    #[error("a certificate needs 1..={max} votes, got {got}")]
    VoteCount { got: usize, max: usize },
    #[error("two votes share a bond outpoint (votes must be over distinct auditors)")]
    DuplicateAuditor,
    #[error("degenerate certificate epochs: need audit_beacon_epoch <= certificate_epoch < activation_epoch < expiry_epoch")]
    EpochRange,
    #[error("passed_leaf_count must be > 0")]
    NoPassedLeaves,
    #[error("the PASS tally did not reach the {num}/{den} stake quorum")]
    QuorumNotReached { num: u16, den: u16 },
    #[error("borsh encoding failed")]
    Encode,
}

/// One auditor's identity + verdict on a batch. `key` is the auditor's ML-DSA-87 validator key (its
/// bond's key); `bond` the DNS bond outpoint whose stake weights the vote; `pass` the sampled verdict;
/// `checked_leaf_bitmap_root` the commitment to WHICH leaves this auditor sampled (design §10.1).
pub struct Auditor {
    pub key: ValidatorKey,
    pub bond: TransactionOutpoint,
    pub pass: bool,
    pub checked_leaf_bitmap_root: Hash64,
}

/// The shared audit-round facts every vote in a certificate binds to (design §10.1) and the
/// certificate's own window/commitment fields. `audit_sample_root` is the beacon-selected receipt-DA
/// sample commitment (off-protocol input the auditors agree on); `leaf_root` / `manifest_hash` are
/// copied from the batch's manifest; `auditor_set_commitment` is the commitment over the selected
/// slate (see [`select_audit_slate`]).
#[derive(Clone, Debug)]
pub struct AuditRound {
    pub network_id: u32,
    pub batch_id: Hash64,
    pub manifest_hash: Hash64,
    pub leaf_root: Hash64,
    pub audit_beacon_epoch: u64,
    pub audit_sample_root: Hash64,
    pub passed_leaf_count: u32,
    pub rejected_leaf_bitmap_root: Hash64,
    pub certificate_epoch: u64,
    pub activation_epoch: u64,
    pub expiry_epoch: u64,
    pub auditor_set_commitment: Hash64,
}

/// The stake-quorum fraction a certificate must reach (testnet 2/3). `pass_stake · den >= total · num`.
#[derive(Clone, Copy, Debug)]
pub struct QuorumPolicy {
    pub num: u16,
    pub den: u16,
}

/// An assembled quorum certificate ready to become a PALW TX output tagged
/// [`BATCH_CERTIFICATE_SUBNETWORK_BYTE`].
#[derive(Clone, Debug)]
pub struct AuditCertificate {
    /// [`BATCH_CERTIFICATE_SUBNETWORK_BYTE`].
    pub subnetwork_byte: u8,
    /// `borsh(cert)` — the bytes the certificate PALW TX output carries.
    pub payload: Vec<u8>,
    pub cert: PalwBatchCertificateV1,
}

/// The beacon-determined auditor slate for `batch_id` under the prior-epoch beacon seed, plus the
/// canonical commitment over it. Thin composition of [`sample_auditors_by_score`] +
/// [`auditor_set_commitment`], so the producer and the future verifier agree on both the slate and the
/// value the certificate's `auditor_set_commitment` field carries. `candidates` must already exclude
/// the registering provider and its related bonds (design §10.2 — the caller filters first).
pub fn select_audit_slate(
    prev_seed: &Hash64,
    batch_id: &Hash64,
    candidates: &[TransactionOutpoint],
    count: usize,
) -> (Vec<TransactionOutpoint>, Hash64) {
    let slate = sample_auditors_by_score(prev_seed, batch_id, candidates, count);
    let commitment = auditor_set_commitment(&slate);
    (slate, commitment)
}

/// Produce one auditor's signed vote for `round`. The signature is a real ML-DSA-87 signature over
/// [`PalwAuditorVoteV1::signing_hash`] under [`PALW_AUDITOR_MLDSA87_CONTEXT`] — the exact digest +
/// context the audit-slice verifier checks. Binds the vote to the batch, the audit-beacon epoch, the
/// beacon-selected `audit_sample_root`, the auditor's bond, and which leaves it checked (I-14).
pub fn sign_vote(round: &AuditRound, auditor: &Auditor) -> PalwAuditorVoteV1 {
    let mut vote = PalwAuditorVoteV1 {
        bond_outpoint: auditor.bond,
        vote: u8::from(auditor.pass),
        checked_leaf_bitmap_root: auditor.checked_leaf_bitmap_root,
        signature: Vec::new(),
    };
    let digest = vote.signing_hash(round.network_id, &round.batch_id, round.audit_beacon_epoch, &round.audit_sample_root);
    vote.signature = auditor.key.sign_with_context(&digest.as_bytes(), PALW_AUDITOR_MLDSA87_CONTEXT).to_vec();
    vote
}

/// Canonical `bond_outpoint` order — the strict ascending order the stateless `validate_certificate`
/// requires (`transaction_id` bytes, then `index`; mirrors the consensus `cmp_outpoint`).
fn cmp_bond(a: &TransactionOutpoint, b: &TransactionOutpoint) -> std::cmp::Ordering {
    a.transaction_id.as_byte_slice().cmp(b.transaction_id.as_byte_slice()).then(a.index.cmp(&b.index))
}

/// Assemble a quorum certificate from already-signed `votes`. Sorts the votes into the canonical
/// `bond_outpoint`-ascending order, rejects duplicate auditors, checks the certificate epoch range and
/// `passed_leaf_count`, and verifies the stake-weighted PASS tally reaches `quorum` against
/// `total_auditor_stake` (the sum of the eligible slate's stake) via `stake_of`. Returns the
/// borsh-encoded certificate ready to submit.
///
/// The result passes the stateless `validate_certificate` (1..=64 canonically-ordered votes, valid
/// signature lengths, sane epochs) AND [`PalwBatchCertificateV1::quorum_reached`] — the two gates a
/// real certificate must clear.
pub fn assemble_certificate(
    round: &AuditRound,
    mut votes: Vec<PalwAuditorVoteV1>,
    total_auditor_stake: u128,
    quorum: QuorumPolicy,
    stake_of: impl Fn(&TransactionOutpoint) -> u128,
) -> Result<AuditCertificate, AuditError> {
    if votes.is_empty() || votes.len() > PALW_MAX_AUDITOR_VOTES_V1 {
        return Err(AuditError::VoteCount { got: votes.len(), max: PALW_MAX_AUDITOR_VOTES_V1 });
    }
    if round.passed_leaf_count == 0 {
        return Err(AuditError::NoPassedLeaves);
    }
    // The exact epoch chain the stateless validator requires.
    if !(round.audit_beacon_epoch <= round.certificate_epoch
        && round.certificate_epoch < round.activation_epoch
        && round.activation_epoch < round.expiry_epoch)
    {
        return Err(AuditError::EpochRange);
    }
    votes.sort_by(|x, y| cmp_bond(&x.bond_outpoint, &y.bond_outpoint));
    if votes.windows(2).any(|w| w[0].bond_outpoint == w[1].bond_outpoint) {
        return Err(AuditError::DuplicateAuditor);
    }
    // ADR-0040 §12′ — `approving_stake` is a COMMITMENT, not a free input: consensus
    // (`verify_certificate_attestation` step 4) recomputes the PASS tally from the active bond view and
    // rejects any certificate whose declared value disagrees. So the producer must declare exactly the
    // tally the verifier will derive — construction == validation. Computed here over the already
    // sorted/deduplicated votes, which is the same multiset the verifier walks.
    let approving_stake: u128 = votes.iter().filter(|v| v.vote == 1).map(|v| stake_of(&v.bond_outpoint)).sum();
    let cert = PalwBatchCertificateV1 {
        version: 1,
        batch_id: round.batch_id,
        manifest_hash: round.manifest_hash,
        leaf_root: round.leaf_root,
        audit_beacon_epoch: round.audit_beacon_epoch,
        audit_sample_root: round.audit_sample_root,
        passed_leaf_count: round.passed_leaf_count,
        rejected_leaf_bitmap_root: round.rejected_leaf_bitmap_root,
        certificate_epoch: round.certificate_epoch,
        activation_epoch: round.activation_epoch,
        expiry_epoch: round.expiry_epoch,
        auditor_set_commitment: round.auditor_set_commitment,
        approving_stake,
        votes,
    };
    if !cert.quorum_reached(total_auditor_stake, quorum.num, quorum.den, &stake_of) {
        return Err(AuditError::QuorumNotReached { num: quorum.num, den: quorum.den });
    }
    let payload = borsh::to_vec(&cert).map_err(|_| AuditError::Encode)?;
    Ok(AuditCertificate { subnetwork_byte: BATCH_CERTIFICATE_SUBNETWORK_BYTE, payload, cert })
}

/// Run a full audit round over an independent set of `auditors`: each signs its vote for `round`, the
/// votes are assembled into a quorum certificate, and the stake-weighted PASS tally is checked against
/// the total stake of the eligible slate. `stakes` maps each auditor bond → its DNS-bond stake (the
/// quorum weight); the total is summed over `auditors`. This is the certificate-submitter's driver;
/// the per-auditor [`sign_vote`] runs on each auditor's own machine in the network.
pub fn run_audit_round(
    round: &AuditRound,
    auditors: &[Auditor],
    stakes: &HashMap<TransactionOutpoint, u128>,
    quorum: QuorumPolicy,
) -> Result<AuditCertificate, AuditError> {
    let votes: Vec<PalwAuditorVoteV1> = auditors.iter().map(|a| sign_vote(round, a)).collect();
    let total_auditor_stake: u128 = auditors.iter().map(|a| stakes.get(&a.bond).copied().unwrap_or(0)).sum();
    assemble_certificate(round, votes, total_auditor_stake, quorum, |bond| stakes.get(bond).copied().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::palw::validate_palw_overlay_payload;
    use kaspa_txscript::verify_mldsa87_with_context;

    const NET: u32 = 0x9107;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    fn op(n: u8) -> TransactionOutpoint {
        TransactionOutpoint::new(h(n), n as u32)
    }

    /// A distinctly-seeded auditor keyed by its seed byte, bonded at `op(seed)`, voting `pass`.
    fn auditor(seed: u8, pass: bool) -> Auditor {
        Auditor { key: ValidatorKey::from_seed([seed; 32]), bond: op(seed), pass, checked_leaf_bitmap_root: h(seed ^ 0x5A) }
    }

    fn round(auditor_set_commitment: Hash64) -> AuditRound {
        AuditRound {
            network_id: NET,
            batch_id: h(0x42),
            manifest_hash: h(0x11),
            leaf_root: h(0x22),
            audit_beacon_epoch: 5,
            audit_sample_root: h(0x33),
            passed_leaf_count: 2,
            rejected_leaf_bitmap_root: h(0x44),
            certificate_epoch: 6,
            activation_epoch: 7,
            expiry_epoch: 13,
            auditor_set_commitment,
        }
    }

    /// The centerpiece: three independently-keyed auditors sign real ML-DSA-87 votes; the assembled
    /// certificate passes the exact stateless validator the mempool/body runs, EACH vote verifies under
    /// the auditor's own pubkey + the audit-vote context (the audit-slice check), and the stake-weighted
    /// quorum is reached.
    #[test]
    fn independent_auditors_form_a_certificate_that_validates_verifies_and_reaches_quorum() {
        let auditors = [auditor(0x11, true), auditor(0x22, true), auditor(0x33, true)];
        let stakes: HashMap<_, _> = auditors.iter().map(|a| (a.bond, 100u128)).collect();
        // Bind the certificate to this exact slate.
        let (_slate, set_commit) = select_audit_slate(&h(0x99), &h(0x42), &[op(0x11), op(0x22), op(0x33)], 3);
        let r = AuditRound { auditor_set_commitment: set_commit, ..round(set_commit) };

        let ac = run_audit_round(&r, &auditors, &stakes, QuorumPolicy { num: 2, den: 3 }).expect("quorum certificate");
        assert_eq!(ac.subnetwork_byte, BATCH_CERTIFICATE_SUBNETWORK_BYTE);

        // (1) The stateless certificate validator the mempool/body runs accepts it.
        assert_eq!(validate_palw_overlay_payload(ac.subnetwork_byte, &ac.payload), Ok(()));

        // (2) Every vote is a genuine ML-DSA-87 signature over the §10.1 binding, verifiable under the
        //     auditor's own pubkey + the audit-vote context — the exact call the audit slice makes.
        assert_eq!(ac.cert.votes.len(), 3);
        for vote in &ac.cert.votes {
            // votes are re-sorted in the cert; match each back to its auditor by bond.
            let signer = auditors.iter().find(|x| x.bond == vote.bond_outpoint).expect("vote maps to an auditor");
            let digest = vote.signing_hash(NET, &r.batch_id, r.audit_beacon_epoch, &r.audit_sample_root);
            assert_eq!(
                verify_mldsa87_with_context(
                    signer.key.public_key(),
                    &digest.as_bytes(),
                    &vote.signature,
                    PALW_AUDITOR_MLDSA87_CONTEXT
                ),
                Ok(true),
                "vote from {:?} must verify",
                vote.bond_outpoint
            );
        }

        // (3) The certificate independently reaches the 2/3 stake quorum.
        assert!(ac.cert.quorum_reached(300, 2, 3, |b| stakes.get(b).copied().unwrap_or(0)));
        // The borsh payload round-trips to the same certificate.
        let decoded: PalwBatchCertificateV1 = borsh::from_slice(&ac.payload).unwrap();
        assert_eq!(decoded, ac.cert);
    }

    /// Votes fed in any order are assembled into the strict `bond_outpoint`-ascending order the
    /// stateless validator requires.
    #[test]
    fn votes_are_canonically_ordered_regardless_of_input() {
        let auditors = [auditor(0x33, true), auditor(0x11, true), auditor(0x22, true)];
        let stakes: HashMap<_, _> = auditors.iter().map(|a| (a.bond, 100u128)).collect();
        let set_commit = auditor_set_commitment(&auditors.iter().map(|a| a.bond).collect::<Vec<_>>());
        let ac = run_audit_round(&round(set_commit), &auditors, &stakes, QuorumPolicy { num: 2, den: 3 }).unwrap();
        // Strictly ascending by (transaction_id bytes, index).
        assert!(ac.cert.votes.windows(2).all(|w| cmp_bond(&w[0].bond_outpoint, &w[1].bond_outpoint) == std::cmp::Ordering::Less));
        assert_eq!(validate_palw_overlay_payload(ac.subnetwork_byte, &ac.payload), Ok(()));
    }

    /// Below quorum: a lone PASS vote among a three-auditor slate (only 100 of 300 stake) fails the
    /// 2/3 quorum — the certificate is not assembled.
    #[test]
    fn below_quorum_pass_tally_is_rejected() {
        // One passing auditor, but the eligible slate's total stake is 300 (two others abstain/reject).
        let passing = auditor(0x11, true);
        let stakes: HashMap<_, _> = [(op(0x11), 100u128), (op(0x22), 100), (op(0x33), 100)].into_iter().collect();
        let r = round(auditor_set_commitment(&[op(0x11), op(0x22), op(0x33)]));
        // total_auditor_stake = 300 (whole slate), but only 100 voted pass ⇒ 100·3 < 300·2.
        let err = assemble_certificate(&r, vec![sign_vote(&r, &passing)], 300, QuorumPolicy { num: 2, den: 3 }, |b| {
            stakes.get(b).copied().unwrap_or(0)
        })
        .unwrap_err();
        assert_eq!(err, AuditError::QuorumNotReached { num: 2, den: 3 });
    }

    /// A reject vote (`vote = 0`) contributes no PASS stake; a slate that only rejects cannot certify.
    #[test]
    fn reject_votes_do_not_count_toward_quorum() {
        let rejecting = [auditor(0x11, false), auditor(0x22, false)];
        let stakes: HashMap<_, _> = rejecting.iter().map(|a| (a.bond, 100u128)).collect();
        let r = round(auditor_set_commitment(&rejecting.iter().map(|a| a.bond).collect::<Vec<_>>()));
        let err = run_audit_round(&r, &rejecting, &stakes, QuorumPolicy { num: 2, den: 3 }).unwrap_err();
        assert_eq!(err, AuditError::QuorumNotReached { num: 2, den: 3 });
    }

    /// A degenerate epoch chain is rejected before any certificate is emitted.
    #[test]
    fn degenerate_epoch_range_is_rejected() {
        let a = auditor(0x11, true);
        let stakes: HashMap<_, _> = [(a.bond, 100u128)].into_iter().collect();
        let bad = AuditRound { activation_epoch: 6, certificate_epoch: 6, ..round(h(0)) }; // certificate_epoch !< activation_epoch
        let err = run_audit_round(&bad, std::slice::from_ref(&a), &stakes, QuorumPolicy { num: 1, den: 1 }).unwrap_err();
        assert_eq!(err, AuditError::EpochRange);
    }

    /// Auditor selection is deterministic and its commitment is exactly `auditor_set_commitment` over
    /// the selected slate.
    #[test]
    fn slate_selection_is_deterministic_and_commits_to_the_selected_set() {
        let candidates = [op(1), op(2), op(3), op(4), op(5)];
        let (slate_a, commit_a) = select_audit_slate(&h(0x77), &h(0x42), &candidates, 3);
        let (slate_b, commit_b) = select_audit_slate(&h(0x77), &h(0x42), &candidates, 3);
        assert_eq!(slate_a, slate_b, "deterministic");
        assert_eq!(commit_a, commit_b);
        assert_eq!(slate_a.len(), 3);
        assert_eq!(commit_a, auditor_set_commitment(&slate_a), "the commitment is over exactly the selected slate");
        // A different beacon seed yields a different slate/commitment.
        let (_slate_c, commit_c) = select_audit_slate(&h(0x88), &h(0x42), &candidates, 3);
        assert_ne!(commit_a, commit_c);
    }
}
