//! Proof-of-Inference receipts (design §4.1).
//!
//! The enclave signs a **cumulative** receipt every
//! [`crate::params::RECEIPT_INTERVAL_OUTPUT_TOKENS`] output tokens (and once
//! more at stream end, `is_final`). Because counters are cumulative, a claim
//! only ever needs the single latest receipt — the ML-DSA-87 mass cost
//! (2592-byte pk + 4627-byte sig) is paid once per claim, not per interval.
//!
//! Signing uses the dedicated [`MIL_RECEIPT_MLDSA87_CONTEXT`] ML-DSA context,
//! so a receipt signature can never double as a tx-input / DNS-attestation /
//! unbond signature. Verification always goes through the **portable** libcrux
//! backend, mirroring the consensus rule in `kaspa_txscript` (audit H-2: the
//! runtime-multiplexed backend is never used to accept/reject signatures).

use crate::domains::{MIL_PROTOCOL_VERSION, MIL_RECEIPT_HASH_DOMAIN, MIL_RECEIPT_MLDSA87_CONTEXT, MIL_SESSION_RK_SEED_DOMAIN};
use borsh::{BorshDeserialize, BorshSerialize};
use kaspa_hashes::{HASH64_SIZE, Hash64, blake2b_256_keyed, blake2b_512_keyed};
use libcrux_ml_dsa::ml_dsa_87;
use rand::RngCore;
use zeroize::Zeroize;

/// ML-DSA-87 verification-key length — must equal `kaspa_txscript::MLDSA87_PK_LEN`
/// (kept local so this crate stays consensus-independent; pinned by test).
pub const MIL_MLDSA87_PK_LEN: usize = 2592;
/// ML-DSA-87 signature length — must equal `kaspa_txscript::MLDSA87_SIG_LEN`.
pub const MIL_MLDSA87_SIG_LEN: usize = 4627;
/// Seed length for deterministic ML-DSA-87 keygen (matches the wallet/validator).
pub const RECEIPT_KEY_SEED_LEN: usize = 32;

/// The signed fields of a cumulative receipt `R_k` (§4.1).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReceiptBody {
    /// [`MIL_PROTOCOL_VERSION`].
    pub version: u16,
    /// Session this receipt settles (from [`crate::ident::session_id`]).
    pub session_id: Hash64,
    /// Receipt counter `k`, strictly increasing from 1 within a session.
    pub counter: u64,
    /// Cumulative prompt tokens consumed so far.
    pub cum_tokens_in: u64,
    /// Cumulative output tokens produced so far.
    pub cum_tokens_out: u64,
    /// Enclave wall-clock, unix milliseconds (informational; monotonicity is
    /// enforced per session).
    pub timestamp_ms: u64,
    /// Transcript commitment `cm_resp_k` at this receipt boundary (§3.3).
    pub cm_resp: Hash64,
    /// Set on the last receipt of the stream; billing settles on the exact
    /// final cumulative counts (§14.4), and no further receipts are accepted.
    pub is_final: bool,
}

impl ReceiptBody {
    /// Canonical fixed-width signing transcript. The design message is
    /// `session_id ‖ k ‖ cum_in ‖ cum_out ‖ ts ‖ cm_resp` (§4.1); v1 prepends
    /// the protocol version and appends the `is_final` flag so a final receipt
    /// can never be replayed as a non-final one. Domain separation itself
    /// rides in the ML-DSA `ctx` parameter, following repo convention.
    pub fn signing_message(&self) -> [u8; 2 + HASH64_SIZE + 8 * 4 + HASH64_SIZE + 1] {
        let mut msg = [0u8; 2 + HASH64_SIZE + 8 * 4 + HASH64_SIZE + 1];
        let mut off = 0;
        msg[off..off + 2].copy_from_slice(&self.version.to_le_bytes());
        off += 2;
        msg[off..off + HASH64_SIZE].copy_from_slice(self.session_id.as_byte_slice());
        off += HASH64_SIZE;
        for v in [self.counter, self.cum_tokens_in, self.cum_tokens_out, self.timestamp_ms] {
            msg[off..off + 8].copy_from_slice(&v.to_le_bytes());
            off += 8;
        }
        msg[off..off + HASH64_SIZE].copy_from_slice(self.cm_resp.as_byte_slice());
        off += HASH64_SIZE;
        msg[off] = self.is_final as u8;
        msg
    }
}

/// A receipt plus its ML-DSA-87 signature and the signer's verification key —
/// self-contained: anyone can verify against the registered `pk_receipt`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SignedReceipt {
    pub body: ReceiptBody,
    /// ML-DSA-87 signature ([`MIL_MLDSA87_SIG_LEN`] bytes).
    pub signature: Vec<u8>,
    /// ML-DSA-87 verification key ([`MIL_MLDSA87_PK_LEN`] bytes).
    pub provider_pk: Vec<u8>,
}

impl SignedReceipt {
    /// Verify the signature (portable backend, receipt context). Structural
    /// and cryptographic checks only — chain monotonicity is
    /// [`ReceiptChainVerifier`]'s job.
    pub fn verify(&self) -> Result<(), ReceiptError> {
        if self.body.version != MIL_PROTOCOL_VERSION {
            return Err(ReceiptError::UnsupportedVersion(self.body.version));
        }
        let pk: [u8; MIL_MLDSA87_PK_LEN] =
            self.provider_pk.as_slice().try_into().map_err(|_| ReceiptError::BadPublicKeyLength(self.provider_pk.len()))?;
        let sig: [u8; MIL_MLDSA87_SIG_LEN] =
            self.signature.as_slice().try_into().map_err(|_| ReceiptError::BadSignatureLength(self.signature.len()))?;
        let vk = ml_dsa_87::MLDSA87VerificationKey::new(pk);
        let sig = ml_dsa_87::MLDSA87Signature::new(sig);
        ml_dsa_87::portable::verify(&vk, &self.body.signing_message(), MIL_RECEIPT_MLDSA87_CONTEXT, &sig)
            .map_err(|_| ReceiptError::BadSignature)
    }

    /// `Hash64_k("misaka-mil-v1/receipt-hash" ‖ borsh(self))` — the compact
    /// on-chain anchor of this receipt (v0 anchors the hash, not the 7 KiB
    /// signature blob; the full receipt travels off-chain, §8.1).
    pub fn receipt_hash(&self) -> Hash64 {
        let bytes = borsh::to_vec(self).expect("borsh serialization of an in-memory receipt is infallible");
        blake2b_512_keyed(MIL_RECEIPT_HASH_DOMAIN, &bytes)
    }
}

/// A receipt on the **anonymous** reward path (ADR-0037 §3 #3 — "receipt without
/// provider naming"): the [`ReceiptBody`] plus its ML-DSA-87 signature, WITHOUT
/// the signer's verification key. The v1 [`SignedReceipt`] carries `provider_pk`
/// (the long-term registration key) in the clear, so every receipt links to the
/// provider's registration (audit H-04). The anonymous receipt names only a
/// SESSION: it is signed under a per-session key ([`ReceiptSigner::from_session_key`])
/// and the verification key is supplied OUT-OF-BAND (fresh per session, unlinkable
/// across sessions; in the handshake it rides as the per-session `session_pk`, and
/// C-P6/B1 later binds it in-circuit to the provider's registry leaf — never the
/// long-term key). INERT: no live path emits this; the v0 named lane keeps
/// [`SignedReceipt`] unchanged.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AnonSignedReceipt {
    pub body: ReceiptBody,
    /// ML-DSA-87 signature ([`MIL_MLDSA87_SIG_LEN`] bytes).
    pub signature: Vec<u8>,
}

impl AnonSignedReceipt {
    /// Verify the signature against a per-session verification key supplied
    /// **out-of-band** — `ReceiptSigner::from_session_key(session_rk).public_key()`,
    /// which the honest requester receives as the handshake `session_pk`. Structural
    /// and cryptographic checks only; chain monotonicity is
    /// [`AnonReceiptChainVerifier`]'s job.
    pub fn verify_with_key(&self, session_pk: &[u8]) -> Result<(), ReceiptError> {
        if self.body.version != MIL_PROTOCOL_VERSION {
            return Err(ReceiptError::UnsupportedVersion(self.body.version));
        }
        let pk: [u8; MIL_MLDSA87_PK_LEN] =
            session_pk.try_into().map_err(|_| ReceiptError::BadPublicKeyLength(session_pk.len()))?;
        let sig: [u8; MIL_MLDSA87_SIG_LEN] =
            self.signature.as_slice().try_into().map_err(|_| ReceiptError::BadSignatureLength(self.signature.len()))?;
        let vk = ml_dsa_87::MLDSA87VerificationKey::new(pk);
        let sig = ml_dsa_87::MLDSA87Signature::new(sig);
        ml_dsa_87::portable::verify(&vk, &self.body.signing_message(), MIL_RECEIPT_MLDSA87_CONTEXT, &sig)
            .map_err(|_| ReceiptError::BadSignature)
    }
}

/// The enclave-held receipt signing key. In Tier 1 this is generated *inside*
/// the TEE and never leaves it; the v0 sidecar derives it from a 0600 seed
/// file (same operational shape as the DNS validator key).
pub struct ReceiptSigner {
    keypair: ml_dsa_87::MLDSA87KeyPair,
}

impl ReceiptSigner {
    /// Deterministic keygen from a 32-byte seed (scrubbed after use).
    pub fn from_seed(mut seed: [u8; RECEIPT_KEY_SEED_LEN]) -> Self {
        let keypair = ml_dsa_87::generate_key_pair(seed);
        seed.zeroize();
        Self { keypair }
    }

    /// Deterministic keygen from a **per-session receipt key** (ADR-0037 §3 #3,
    /// the off-circuit half — "receipt without provider naming"). The 64-byte
    /// `session_rk` — `misaka_mil_shield::provider::session_receipt_key(claim_secret,
    /// session_cm)`, keyed in the provider's anonymous `claim_secret` and the
    /// session — is compressed to the 32-byte ML-DSA-87 seed via
    /// [`MIL_SESSION_RK_SEED_DOMAIN`], so **every session is signed under a fresh
    /// key that names a session, not a provider**. This is what CONNECTS the
    /// (formerly dangling) `session_receipt_key` derivation to real ML-DSA-87
    /// keygen — a requester/relay/receipt-log can no longer link two sessions to
    /// one provider by a long-term key.
    ///
    /// Enforced NOW: distinct `session_rk` ⇒ distinct signing key (genuinely
    /// session-keyed). Pending the in-circuit build (C-P6 / B1): a ZK proof that
    /// this per-session key was derived from the `claim_secret` behind the
    /// provider's registered leaf, so the receipt binds to the anonymity set
    /// without naming the provider. `session_rk` reaching a live serving context
    /// (it is keyed in `claim_secret`, not yet wired into the provider config) is
    /// the remaining plumbing dependency; this API takes it as an argument.
    pub fn from_session_key(session_rk: Hash64) -> Self {
        let mut seed: [u8; RECEIPT_KEY_SEED_LEN] = blake2b_256_keyed(MIL_SESSION_RK_SEED_DOMAIN, session_rk.as_byte_slice());
        let signer = Self::from_seed(seed);
        seed.zeroize();
        signer
    }

    /// The raw [`MIL_MLDSA87_PK_LEN`]-byte verification key (`pk_receipt`).
    pub fn public_key(&self) -> &[u8; MIL_MLDSA87_PK_LEN] {
        self.keypair.verification_key.as_ref()
    }

    /// Sign a receipt body with explicit signing randomness (hedged ML-DSA;
    /// determinism is not required and fresh randomness is the FIPS-204
    /// default posture).
    pub fn sign_with_randomness(&self, body: ReceiptBody, randomness: [u8; 32]) -> SignedReceipt {
        let sig = ml_dsa_87::sign(&self.keypair.signing_key, &body.signing_message(), MIL_RECEIPT_MLDSA87_CONTEXT, randomness)
            .expect("ML-DSA-87 sign is infallible for a <= 255-byte context");
        SignedReceipt { body, signature: sig.as_slice().to_vec(), provider_pk: self.public_key().to_vec() }
    }

    /// Sign with fresh OS randomness.
    pub fn sign(&self, body: ReceiptBody) -> SignedReceipt {
        let mut randomness = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut randomness);
        self.sign_with_randomness(body, randomness)
    }

    /// Sign a receipt body into a provider-NON-naming [`AnonSignedReceipt`] (no
    /// `provider_pk`), with explicit signing randomness. Same ML-DSA-87 context as
    /// [`Self::sign`]; intended for a signer built via [`Self::from_session_key`].
    pub fn sign_anon_with_randomness(&self, body: ReceiptBody, randomness: [u8; 32]) -> AnonSignedReceipt {
        let sig = ml_dsa_87::sign(&self.keypair.signing_key, &body.signing_message(), MIL_RECEIPT_MLDSA87_CONTEXT, randomness)
            .expect("ML-DSA-87 sign is infallible for a <= 255-byte context");
        AnonSignedReceipt { body, signature: sig.as_slice().to_vec() }
    }

    /// Sign an [`AnonSignedReceipt`] with fresh OS randomness.
    pub fn sign_anon(&self, body: ReceiptBody) -> AnonSignedReceipt {
        let mut randomness = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut randomness);
        self.sign_anon_with_randomness(body, randomness)
    }
}

/// Shared per-session monotonicity check for both receipt-chain verifiers: the
/// receipt is for this session, its counter starts at 1 and strictly increases,
/// cumulative counters never shrink, timestamps never go backwards, and nothing
/// follows a `is_final` receipt. Signature/key verification is the caller's
/// job (it differs between the named and anonymous paths); this is the pure
/// progression rule (§4.1/§5.6).
fn check_receipt_progression(session_id: &Hash64, latest: &Option<ReceiptBody>, body: &ReceiptBody) -> Result<(), ReceiptError> {
    if body.session_id != *session_id {
        return Err(ReceiptError::SessionMismatch { expected: *session_id, got: body.session_id });
    }
    if body.counter == 0 {
        return Err(ReceiptError::ZeroCounter);
    }
    if let Some(prev) = latest {
        if prev.is_final {
            return Err(ReceiptError::AfterFinal);
        }
        if body.counter <= prev.counter {
            return Err(ReceiptError::NonMonotonicCounter { prev: prev.counter, got: body.counter });
        }
        if body.cum_tokens_in < prev.cum_tokens_in || body.cum_tokens_out < prev.cum_tokens_out {
            return Err(ReceiptError::ShrinkingCumulativeTokens);
        }
        if body.timestamp_ms < prev.timestamp_ms {
            return Err(ReceiptError::NonMonotonicTimestamp);
        }
    }
    Ok(())
}

/// Requester/settlement-side receipt-chain validator: enforces per-session
/// monotonicity so the latest accepted receipt is always the settlement
/// dominance point (§4.1/§5.6).
pub struct ReceiptChainVerifier {
    session_id: Hash64,
    expected_pk: Vec<u8>,
    latest: Option<ReceiptBody>,
}

impl ReceiptChainVerifier {
    pub fn new(session_id: Hash64, expected_pk: Vec<u8>) -> Self {
        Self { session_id, expected_pk, latest: None }
    }

    /// Verify and ingest the next receipt. On success the receipt becomes the
    /// new settlement head.
    pub fn ingest(&mut self, receipt: &SignedReceipt) -> Result<(), ReceiptError> {
        if receipt.provider_pk != self.expected_pk {
            return Err(ReceiptError::ProviderKeyMismatch);
        }
        receipt.verify()?;
        check_receipt_progression(&self.session_id, &self.latest, &receipt.body)?;
        self.latest = Some(receipt.body.clone());
        Ok(())
    }

    /// The current settlement head (latest valid receipt), if any.
    pub fn latest(&self) -> Option<&ReceiptBody> {
        self.latest.as_ref()
    }

    /// Whether the stream is closed by a final receipt.
    pub fn is_finalized(&self) -> bool {
        self.latest.as_ref().is_some_and(|r| r.is_final)
    }
}

/// ANONYMOUS-path receipt-chain validator (ADR-0037 §3 #3). Identical
/// per-session monotonicity to [`ReceiptChainVerifier`], but the verification
/// key is the **per-session** key supplied out-of-band (the receipt does not
/// carry it) — the honest requester takes it from the handshake `session_pk`.
/// Because that key is fresh per session, ingesting a chain reveals nothing that
/// links the session to a named provider.
pub struct AnonReceiptChainVerifier {
    session_id: Hash64,
    session_pk: Vec<u8>,
    latest: Option<ReceiptBody>,
}

impl AnonReceiptChainVerifier {
    pub fn new(session_id: Hash64, session_pk: Vec<u8>) -> Self {
        Self { session_id, session_pk, latest: None }
    }

    /// Verify (against the out-of-band per-session key) and ingest the next
    /// anonymous receipt. On success it becomes the new settlement head.
    pub fn ingest(&mut self, receipt: &AnonSignedReceipt) -> Result<(), ReceiptError> {
        receipt.verify_with_key(&self.session_pk)?;
        check_receipt_progression(&self.session_id, &self.latest, &receipt.body)?;
        self.latest = Some(receipt.body.clone());
        Ok(())
    }

    /// The current settlement head (latest valid receipt), if any.
    pub fn latest(&self) -> Option<&ReceiptBody> {
        self.latest.as_ref()
    }

    /// Whether the stream is closed by a final receipt.
    pub fn is_finalized(&self) -> bool {
        self.latest.as_ref().is_some_and(|r| r.is_final)
    }
}

/// Receipt validation failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("unsupported receipt version {0}")]
    UnsupportedVersion(u16),
    #[error("receipt public key must be {MIL_MLDSA87_PK_LEN} bytes, got {0}")]
    BadPublicKeyLength(usize),
    #[error("receipt signature must be {MIL_MLDSA87_SIG_LEN} bytes, got {0}")]
    BadSignatureLength(usize),
    #[error("ML-DSA-87 receipt signature verification failed")]
    BadSignature,
    #[error("receipt signed by a different provider key than registered")]
    ProviderKeyMismatch,
    #[error("receipt session mismatch: expected {expected}, got {got}")]
    SessionMismatch { expected: Hash64, got: Hash64 },
    #[error("receipt counter must start at 1")]
    ZeroCounter,
    #[error("receipt counter not strictly increasing: prev {prev}, got {got}")]
    NonMonotonicCounter { prev: u64, got: u64 },
    #[error("cumulative token counters decreased")]
    ShrinkingCumulativeTokens,
    #[error("receipt timestamp decreased")]
    NonMonotonicTimestamp,
    #[error("receipt received after the final receipt of the session")]
    AfterFinal,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> ReceiptSigner {
        ReceiptSigner::from_seed([0x51u8; RECEIPT_KEY_SEED_LEN])
    }

    fn body(k: u64, out: u64, is_final: bool) -> ReceiptBody {
        ReceiptBody {
            version: MIL_PROTOCOL_VERSION,
            session_id: Hash64::from_bytes([3u8; 64]),
            counter: k,
            cum_tokens_in: 100,
            cum_tokens_out: out,
            timestamp_ms: 1_000 + k,
            cm_resp: Hash64::from_bytes([4u8; 64]),
            is_final,
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let s = signer();
        let r = s.sign_with_randomness(body(1, 512, false), [7u8; 32]);
        assert_eq!(r.provider_pk.len(), MIL_MLDSA87_PK_LEN);
        assert_eq!(r.signature.len(), MIL_MLDSA87_SIG_LEN);
        r.verify().expect("valid receipt must verify");
        // any field tamper breaks the signature
        let mut t = r.clone();
        t.body.cum_tokens_out += 1;
        assert_eq!(t.verify(), Err(ReceiptError::BadSignature));
        let mut t = r.clone();
        t.body.is_final = true;
        assert_eq!(t.verify(), Err(ReceiptError::BadSignature));
        // a signature from another key fails
        let other = ReceiptSigner::from_seed([9u8; 32]);
        let mut t = r.clone();
        t.provider_pk = other.public_key().to_vec();
        assert_eq!(t.verify(), Err(ReceiptError::BadSignature));
    }

    #[test]
    fn receipt_hash_is_stable_and_tamper_evident() {
        let s = signer();
        let r = s.sign_with_randomness(body(1, 512, false), [7u8; 32]);
        assert_eq!(r.receipt_hash(), r.receipt_hash());
        let r2 = s.sign_with_randomness(body(2, 1024, false), [7u8; 32]);
        assert_ne!(r.receipt_hash(), r2.receipt_hash());
    }

    #[test]
    fn chain_enforces_monotonicity() {
        let s = signer();
        let mut chain = ReceiptChainVerifier::new(body(1, 0, false).session_id, s.public_key().to_vec());

        chain.ingest(&s.sign(body(1, 512, false))).unwrap();
        chain.ingest(&s.sign(body(2, 1024, false))).unwrap();

        // counter must strictly increase
        assert!(matches!(chain.ingest(&s.sign(body(2, 1500, false))), Err(ReceiptError::NonMonotonicCounter { .. })));
        // cumulative counters must not shrink
        assert_eq!(chain.ingest(&s.sign(body(3, 1000, false))), Err(ReceiptError::ShrinkingCumulativeTokens));
        // counter 0 is invalid even as the first receipt
        let mut fresh = ReceiptChainVerifier::new(body(1, 0, false).session_id, s.public_key().to_vec());
        assert_eq!(fresh.ingest(&s.sign(body(0, 1, false))), Err(ReceiptError::ZeroCounter));

        // finalization closes the chain
        chain.ingest(&s.sign(body(3, 1400, true))).unwrap();
        assert!(chain.is_finalized());
        assert_eq!(chain.ingest(&s.sign(body(4, 1500, false))), Err(ReceiptError::AfterFinal));
        assert_eq!(chain.latest().unwrap().cum_tokens_out, 1400);

        // wrong session id is rejected
        let mut other = ReceiptChainVerifier::new(Hash64::from_bytes([8u8; 64]), s.public_key().to_vec());
        assert!(matches!(other.ingest(&s.sign(body(1, 10, false))), Err(ReceiptError::SessionMismatch { .. })));

        // wrong provider key is rejected before signature checking
        let stranger = ReceiptSigner::from_seed([0xAAu8; 32]);
        let mut chain2 = ReceiptChainVerifier::new(body(1, 0, false).session_id, s.public_key().to_vec());
        assert_eq!(chain2.ingest(&stranger.sign(body(1, 10, false))), Err(ReceiptError::ProviderKeyMismatch));
    }

    // ---- H-04: anonymous per-session receipt path (ADR-0037 §3 #3) ----

    #[test]
    fn session_keyed_signer_is_deterministic_unlinkable_and_provider_non_naming() {
        let rk1 = Hash64::from_bytes([0x5Au8; 64]);
        let rk2 = Hash64::from_bytes([0x5Bu8; 64]);
        // deterministic in session_rk
        let a = ReceiptSigner::from_session_key(rk1);
        let b = ReceiptSigner::from_session_key(rk1);
        assert_eq!(a.public_key(), b.public_key(), "same session_rk ⇒ same per-session key");
        // distinct sessions ⇒ distinct keys — a requester/relay cannot link them
        let c = ReceiptSigner::from_session_key(rk2);
        assert_ne!(a.public_key(), c.public_key(), "distinct session_rk ⇒ distinct key (unlinkable)");
        // domain-separated from feeding the raw 32-byte prefix straight into from_seed,
        // so the per-session key is not derivable from the session_rk by any other route.
        let raw_prefix: [u8; RECEIPT_KEY_SEED_LEN] = rk1.as_byte_slice()[..RECEIPT_KEY_SEED_LEN].try_into().unwrap();
        assert_ne!(a.public_key(), ReceiptSigner::from_seed(raw_prefix).public_key());
    }

    #[test]
    fn anon_receipt_omits_provider_pk_and_verifies_under_session_key() {
        let rk = Hash64::from_bytes([0x77u8; 64]);
        let signer = ReceiptSigner::from_session_key(rk);
        let session_pk = signer.public_key().to_vec();
        let r = signer.sign_anon_with_randomness(body(1, 512, true), [7u8; 32]);
        assert_eq!(r.signature.len(), MIL_MLDSA87_SIG_LEN);
        // structurally there is no long-term key on the wire: AnonSignedReceipt has
        // only { body, signature }. It verifies against the OUT-OF-BAND session key.
        r.verify_with_key(&session_pk).expect("anon receipt must verify under its session key");
        // a different session's key does not verify it (no long-term linkage)
        let other = ReceiptSigner::from_session_key(Hash64::from_bytes([0x78u8; 64]));
        assert_eq!(r.verify_with_key(other.public_key()), Err(ReceiptError::BadSignature));
        // any body tamper breaks the signature
        let mut t = r.clone();
        t.body.cum_tokens_out += 1;
        assert_eq!(t.verify_with_key(&session_pk), Err(ReceiptError::BadSignature));
        // wrong-length key is rejected structurally
        assert_eq!(r.verify_with_key(&[0u8; 10]), Err(ReceiptError::BadPublicKeyLength(10)));
    }

    #[test]
    fn anon_chain_enforces_monotonicity_under_session_key() {
        let signer = ReceiptSigner::from_session_key(Hash64::from_bytes([0x33u8; 64]));
        let session_pk = signer.public_key().to_vec();
        let sid = body(1, 0, false).session_id;
        let mut chain = AnonReceiptChainVerifier::new(sid, session_pk.clone());
        chain.ingest(&signer.sign_anon(body(1, 512, false))).unwrap();
        chain.ingest(&signer.sign_anon(body(2, 1024, false))).unwrap();
        // strict counter increase
        assert!(matches!(chain.ingest(&signer.sign_anon(body(2, 1500, false))), Err(ReceiptError::NonMonotonicCounter { .. })));
        // finalization closes the chain
        chain.ingest(&signer.sign_anon(body(3, 1400, true))).unwrap();
        assert!(chain.is_finalized());
        assert_eq!(chain.ingest(&signer.sign_anon(body(4, 1500, false))), Err(ReceiptError::AfterFinal));
        // a receipt signed under a DIFFERENT session key fails verification (no cross-session mixing)
        let stranger = ReceiptSigner::from_session_key(Hash64::from_bytes([0x99u8; 64]));
        let mut fresh = AnonReceiptChainVerifier::new(sid, session_pk);
        assert_eq!(fresh.ingest(&stranger.sign_anon(body(1, 10, false))), Err(ReceiptError::BadSignature));
    }
}
