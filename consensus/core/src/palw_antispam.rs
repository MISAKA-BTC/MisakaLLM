//! PALW Header-v4 objective anti-spam stamp and rolling-lane admission arithmetic.
//!
//! This module deliberately contains only pure, bounded consensus functions. The fork-local
//! accumulator which supplies [`PalwSpamWindowCounts`] lives in the consensus engine store; both the
//! header validator and algo-4 template builder call the functions here, so target derivation cannot
//! drift between construction and validation.

use crate::{BlockHash, Hash64, hashing::header::palw_spam_hash, header::Header};
use kaspa_hashes::PalwSpamAccumulatorHash64;

/// Maximum useful stamp difficulty for the 512-bit PALW stamp digest.
pub const PALW_SPAM_HASH_BITS: u16 = 512;
/// Largest exact DAA horizon accepted by the re-genesis-only Header-v4 accumulator. The rolling
/// checkpoint span is the next power of two at or above `window_daa`, so this ceiling also bounds a
/// complete pruning boundary to at most 65,536 fixed-size history rows.
pub const PALW_SPAM_MAX_WINDOW_DAA: u64 = 1 << 16;

/// Power-of-two selected-height checkpoint span used by the bounded skip rule. Active parameters are
/// structurally restricted so this is always in `1..=PALW_SPAM_MAX_WINDOW_DAA`.
pub const fn palw_spam_checkpoint_span(window_daa: u64) -> u64 {
    if window_daa == 0 || window_daa > PALW_SPAM_MAX_WINDOW_DAA {
        return 0;
    }
    let mut span = 1u64;
    while span < window_daa {
        span <<= 1;
    }
    span
}

/// Consensus parameters for the Header-v4 PALW anti-spam rule.
///
/// `INERT` is carried by every existing preset. A public/value network must use a new genesis and
/// explicitly configure a non-zero floor before activating Header v4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PalwSpamParams {
    /// Exact, unsampled DAA horizon used by the fork-local accumulator.
    pub window_daa: u64,
    /// Maximum replica-blue allowance minted by each hash-blue in the horizon.
    pub replicas_per_hash: u64,
    /// Bootstrap/concurrency allowance when the horizon contains few hash blocks.
    pub burst: u64,
    /// Objective stamp floor. Must be non-zero on an active v4 network.
    pub base_stamp_bits: u16,
    /// Explicit consensus upper bound for the dynamic target.
    pub max_stamp_bits: u16,
}

impl PalwSpamParams {
    pub const INERT: Self = Self { window_daa: 0, replicas_per_hash: 0, burst: 0, base_stamp_bits: 0, max_stamp_bits: 0 };

    /// Concrete starting point for a future public/value re-genesis. The magnitude is intentionally
    /// still a Measurement gate: operators must calibrate the 12..19 bit floor/ramp under the G6
    /// header-flood benchmark before activating it in a preset.
    pub const PUBLIC_REGENESIS_CANDIDATE: Self =
        Self { window_daa: 26_440, replicas_per_hash: 4, burst: 8, base_stamp_bits: 12, max_stamp_bits: 19 };

    pub const fn is_inert(self) -> bool {
        self.window_daa == 0 && self.base_stamp_bits == 0 && self.max_stamp_bits == 0
    }

    pub const fn is_structurally_valid(self) -> bool {
        self.window_daa > 0
            && self.window_daa <= PALW_SPAM_MAX_WINDOW_DAA
            && self.replicas_per_hash > 0
            && self.base_stamp_bits > 0
            && self.base_stamp_bits <= self.max_stamp_bits
            && self.max_stamp_bits <= PALW_SPAM_HASH_BITS
    }
}

/// Exact blue-lane counts in the configured full horizon.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PalwSpamWindowCounts {
    pub hash_blues: u64,
    pub replica_blues: u64,
}

/// A fully derived admission target for one algo-4 candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PalwSpamTarget {
    pub required_stamp_bits: u16,
    pub replica_capacity: u64,
    pub prospective_replicas: u64,
}

/// Commit the complete fork-local accumulator row carried by a Header-v4 block.
///
/// Pointer presence and ordering are explicit so malformed or substituted skip links cannot share a commitment.
/// The version tag freezes this v1 row encoding independently from the containing Header-v4 layout.
pub fn palw_spam_accumulator_commitment(
    daa_score: u64,
    selected_height: u64,
    total_hash_blues: u64,
    total_replica_blues: u64,
    selected_parent: Option<BlockHash>,
    skip: Option<BlockHash>,
) -> Hash64 {
    let mut hasher = PalwSpamAccumulatorHash64::new();
    hasher.write(1u16.to_le_bytes());
    hasher.write(daa_score.to_le_bytes());
    hasher.write(selected_height.to_le_bytes());
    hasher.write(total_hash_blues.to_le_bytes());
    hasher.write(total_replica_blues.to_le_bytes());
    for pointer in [selected_parent, skip] {
        match pointer {
            Some(hash) => {
                hasher.write([1]);
                hasher.write(hash.as_bytes());
            }
            None => hasher.write([0]),
        };
    }
    hasher.finalize()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PalwSpamError {
    #[error("PALW Header-v4 anti-spam parameters are inert or structurally invalid")]
    InvalidParams,
    #[error("PALW rolling anti-spam counter overflow")]
    CounterOverflow,
    #[error("PALW replica window is full: prospective replicas {prospective} exceeds capacity {capacity}")]
    RateExceeded { prospective: u64, capacity: u64 },
    #[error("PALW objective stamp has {actual_bits} leading zero bits but {required_bits} are required")]
    StampTooWeak { required_bits: u16, actual_bits: u16 },
    #[error("PALW objective stamp nonce range exhausted at {max_nonce}")]
    NonceExhausted { max_nonce: u64 },
}

/// Derive the exact candidate target with overflow-safe arithmetic.
///
/// The hard rate bound is `replicas <= replicas_per_hash * hash_blues + burst`. Within that capacity,
/// stamp work ramps through at most seven congestion steps. The explicit `max_stamp_bits` clamps the
/// result; the non-zero `base_stamp_bits` is always paid, including by arbitrarily many siblings that
/// share an identical selected past.
pub fn palw_spam_target(
    params: PalwSpamParams,
    counts_before_candidate: PalwSpamWindowCounts,
) -> Result<PalwSpamTarget, PalwSpamError> {
    if !params.is_structurally_valid() {
        return Err(PalwSpamError::InvalidParams);
    }

    let capacity_u128 = (counts_before_candidate.hash_blues as u128)
        .checked_mul(params.replicas_per_hash as u128)
        .and_then(|v| v.checked_add(params.burst as u128))
        .ok_or(PalwSpamError::CounterOverflow)?;
    let capacity = u64::try_from(capacity_u128).map_err(|_| PalwSpamError::CounterOverflow)?;
    let prospective = counts_before_candidate.replica_blues.checked_add(1).ok_or(PalwSpamError::CounterOverflow)?;
    if prospective > capacity {
        return Err(PalwSpamError::RateExceeded { prospective, capacity });
    }

    // Eight deterministic load bands, 0..=7. `capacity + 1` is evaluated in u128 so a u64-max
    // capacity remains defined; conversion happens only after the result is bounded by seven.
    let congestion = (((prospective as u128) * 8) / (capacity_u128 + 1)).min(7) as u16;
    let required_stamp_bits = params.base_stamp_bits.saturating_add(congestion).min(params.max_stamp_bits);
    Ok(PalwSpamTarget { required_stamp_bits, replica_capacity: capacity, prospective_replicas: prospective })
}

/// Number of zero bits at the beginning of the independent 512-bit stamp digest.
pub fn palw_spam_leading_zero_bits(header: &Header) -> u16 {
    let digest = palw_spam_hash(header);
    let mut bits = 0u16;
    for byte in digest.as_bytes() {
        if byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros() as u16;
            break;
        }
    }
    bits
}

pub fn validate_palw_spam_stamp(header: &Header, required_bits: u16) -> Result<(), PalwSpamError> {
    if header.version < crate::constants::PALW_ANTISPAM_HEADER_VERSION || required_bits == 0 || required_bits > PALW_SPAM_HASH_BITS {
        return Err(PalwSpamError::InvalidParams);
    }
    let actual_bits = palw_spam_leading_zero_bits(header);
    if actual_bits < required_bits {
        return Err(PalwSpamError::StampTooWeak { required_bits, actual_bits });
    }
    Ok(())
}

/// Grind only the Header-v4 spam nonce, inclusively over `[start_nonce, max_nonce]`.
///
/// The ticket authorization intentionally excludes this one field. Consequently the caller signs and
/// finalizes the authorization transaction first, then calls this helper over a header whose every
/// other field (including the final merkle root and authorization hash) is frozen. Exhaustion is an
/// error, never a partially stamped template.
pub fn mine_palw_spam_stamp(header: &mut Header, required_bits: u16, start_nonce: u64, max_nonce: u64) -> Result<u64, PalwSpamError> {
    if header.version < crate::constants::PALW_ANTISPAM_HEADER_VERSION
        || required_bits == 0
        || required_bits > PALW_SPAM_HASH_BITS
        || start_nonce > max_nonce
    {
        return Err(PalwSpamError::InvalidParams);
    }
    let mut nonce = start_nonce;
    loop {
        header.palw_spam_nonce = nonce;
        header.finalize();
        if validate_palw_spam_stamp(header, required_bits).is_ok() {
            return Ok(nonce);
        }
        if nonce == max_nonce {
            return Err(PalwSpamError::NonceExhausted { max_nonce });
        }
        nonce = nonce.checked_add(1).ok_or(PalwSpamError::NonceExhausted { max_nonce })?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlueWorkType, header::PalwHeaderFields, pow_layer0::POW_ALGO_ID_PALW_REPLICA};
    use kaspa_hashes::Hash64;

    fn header() -> Header {
        Header::new_finalized(
            crate::constants::PALW_ANTISPAM_HEADER_VERSION,
            vec![vec![Hash64::from_bytes([1; 64])]].try_into().unwrap(),
            Hash64::from_bytes([2; 64]),
            Hash64::from_bytes([3; 64]),
            Hash64::from_bytes([4; 64]),
            5,
            0x1f00ffff,
            7,
            POW_ALGO_ID_PALW_REPLICA,
            8,
            BlueWorkType::from(9u64),
            10,
            Hash64::from_bytes([11; 64]),
        )
        .with_palw_fields(PalwHeaderFields { palw_authorization_hash: Hash64::from_bytes([12; 64]), ..Default::default() })
    }

    #[test]
    fn target_is_overflow_safe_rate_bounded_and_explicitly_capped() {
        let p = PalwSpamParams { window_daa: 100, replicas_per_hash: 4, burst: 2, base_stamp_bits: 3, max_stamp_bits: 7 };
        let t = palw_spam_target(p, PalwSpamWindowCounts { hash_blues: 1, replica_blues: 4 }).unwrap();
        assert_eq!(t.replica_capacity, 6);
        assert_eq!(t.prospective_replicas, 5);
        assert!((p.base_stamp_bits..=p.max_stamp_bits).contains(&t.required_stamp_bits));
        assert!(matches!(
            palw_spam_target(p, PalwSpamWindowCounts { hash_blues: 1, replica_blues: 6 }),
            Err(PalwSpamError::RateExceeded { prospective: 7, capacity: 6 })
        ));
        assert!(matches!(
            palw_spam_target(p, PalwSpamWindowCounts { hash_blues: u64::MAX, replica_blues: 0 }),
            Err(PalwSpamError::CounterOverflow)
        ));
    }

    #[test]
    fn checkpoint_span_and_parameter_ceiling_are_consensus_bounded() {
        assert_eq!(palw_spam_checkpoint_span(0), 0);
        assert_eq!(palw_spam_checkpoint_span(1), 1);
        assert_eq!(palw_spam_checkpoint_span(2), 2);
        assert_eq!(palw_spam_checkpoint_span(3), 4);
        assert_eq!(palw_spam_checkpoint_span(26_440), 32_768);
        assert_eq!(palw_spam_checkpoint_span(PALW_SPAM_MAX_WINDOW_DAA), PALW_SPAM_MAX_WINDOW_DAA);
        assert_eq!(palw_spam_checkpoint_span(PALW_SPAM_MAX_WINDOW_DAA + 1), 0);
        assert!(PalwSpamParams::PUBLIC_REGENESIS_CANDIDATE.is_structurally_valid());

        let oversized = PalwSpamParams { window_daa: PALW_SPAM_MAX_WINDOW_DAA + 1, ..PalwSpamParams::PUBLIC_REGENESIS_CANDIDATE };
        assert!(!oversized.is_structurally_valid());
        assert_eq!(palw_spam_target(oversized, PalwSpamWindowCounts::default()), Err(PalwSpamError::InvalidParams));
    }

    #[test]
    fn accumulator_commitment_binds_counters_height_and_pointer_roles() {
        let a = Hash64::from_bytes([0xa1; 64]);
        let b = Hash64::from_bytes([0xb2; 64]);
        let base = palw_spam_accumulator_commitment(7, 9, 11, 13, Some(a), Some(b));
        assert_ne!(base, palw_spam_accumulator_commitment(8, 9, 11, 13, Some(a), Some(b)));
        assert_ne!(base, palw_spam_accumulator_commitment(7, 10, 11, 13, Some(a), Some(b)));
        assert_ne!(base, palw_spam_accumulator_commitment(7, 9, 12, 13, Some(a), Some(b)));
        assert_ne!(base, palw_spam_accumulator_commitment(7, 9, 11, 14, Some(a), Some(b)));
        assert_ne!(base, palw_spam_accumulator_commitment(7, 9, 11, 13, Some(b), Some(a)));
        assert_ne!(base, palw_spam_accumulator_commitment(7, 9, 11, 13, Some(a), None));
    }

    #[test]
    fn stamp_grinds_only_spam_nonce_and_binds_every_other_final_header_field() {
        let mut h = header();
        let original_ticket_nonce = h.nonce;
        let original_auth = h.palw_authorization_hash;
        let mined = mine_palw_spam_stamp(&mut h, 5, 0, 10_000).unwrap();
        assert_eq!(h.palw_spam_nonce, mined);
        assert_eq!(h.nonce, original_ticket_nonce, "the eligibility nonce stays pinned to the ticket");
        assert_eq!(h.palw_authorization_hash, original_auth, "the completed signature hash is frozen before grinding");
        validate_palw_spam_stamp(&h, 5).unwrap();

        let mut changed = h.clone();
        changed.palw_authorization_hash = Hash64::from_bytes([0xee; 64]);
        changed.finalize();
        assert_ne!(palw_spam_hash(&changed), palw_spam_hash(&h), "the final authorization/signature hash is stamp-bound");
    }

    #[test]
    fn stamp_nonce_exhaustion_fails_closed() {
        let mut h = header();
        let only = 17;
        h.palw_spam_nonce = only;
        h.finalize();
        let actual = palw_spam_leading_zero_bits(&h);
        let impossible_for_this_nonce = actual + 1;
        assert_eq!(
            mine_palw_spam_stamp(&mut h, impossible_for_this_nonce, only, only),
            Err(PalwSpamError::NonceExhausted { max_nonce: only })
        );

        let mut v3 = header();
        v3.version = crate::constants::PALW_HEADER_VERSION;
        v3.finalize();
        assert_eq!(mine_palw_spam_stamp(&mut v3, 1, 0, 1), Err(PalwSpamError::InvalidParams));
        assert_eq!(validate_palw_spam_stamp(&v3, 1), Err(PalwSpamError::InvalidParams));
    }
}
