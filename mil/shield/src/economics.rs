//! The claim-v2 ECONOMIC SPLIT — the single Rust specification of
//! `MilShieldedEscrow.claimAnonV2`'s gross → 88 % / 5 % / 7 % → whole-sompi
//! `providerShareSompi` integer arithmetic (audit 2026-07-11 **C-02**).
//!
//! # Normative rounding semantics (frozen; ADR-0037 §2.3.1 amendment)
//!
//! Mirrored **operation for operation** from the Solidity source (uint256
//! intermediates, floor divisions, checked arithmetic):
//!
//! ```text
//! grossSompi  = (price · (tokIn + tokOut)) / 1000          // uint256 floor
//! grossWei    = grossSompi · NATIVE_SCALE                  // exact (10^10)
//! providerWei = (grossWei · 88) / 100                      // exact: = 88·grossSompi·10^8
//! REVERT SplitMismatch unless providerWei % NATIVE_SCALE == 0
//! providerShareSompi = uint64(providerWei / NATIVE_SCALE)  // TRUNCATING cast
//! burnWei     = (grossWei · 5) / 100                       // exact: = 5·grossSompi·10^8
//! poolWei     = grossWei − providerWei − burnWei           // exact 7 % (lossless leg)
//! ```
//!
//! Consequences (all pinned by the shared differential vectors
//! `contracts/mil/test/vectors/claim_v2_split_vectors.json`, consumed by both this
//! module's tests and `contracts/mil/test/MilClaimV2Split.t.sol`):
//!
//! - **Whole-sompi gate ⇔ `grossSompi ≡ 0 (mod 25)`.** `providerWei % 10^10 =
//!   (88·grossSompi mod 100)·10^8`, and `88g ≡ 0 (mod 100) ⇔ g ≡ 0 (mod 25)`.
//!   Any `(price, tokIn+tokOut)` whose gross is NOT a multiple of 25 sompi makes
//!   `claimAnonV2` revert `SplitMismatch` **permanently** — the escrow can then only
//!   be refunded after `refundAfter`. The pricing layer (gateway / provider SDK)
//!   MUST therefore quantize token totals so `grossSompi ≡ 0 (mod 25)` (with the
//!   ADR-0037 §3 denomination ladder this holds for every ladder rung × price that
//!   is a multiple of 25; e.g. keep `price·denom/1000` a multiple of 25). The on-chain
//!   `MilShieldedEscrow.setClaimPolicy` now enforces this at the SOURCE by requiring the
//!   uniform price to be a multiple of [`WHOLE_SOMPI_PRICE_STEP`] (25_000) — see
//!   [`price_yields_whole_sompi`] — so no escrow it admits can ever hit the trap. This
//!   revert-not-floor choice is deliberate: flooring would silently strand dust and
//!   change the money path; the gate keeps the 88/5/7 split EXACT whenever a claim
//!   settles.
//! - **Once the gate passes, the split is exact**: `providerWei = 88·g·10^8`,
//!   `burnWei = 5·g·10^8`, `poolWei = 7·g·10^8` — no rounding loss anywhere; the
//!   only lossy operations in the whole pipeline are the `/1000` gross floor and
//!   (theoretical) `uint64` cast below.
//! - **The `uint64` cast never truncates within supply**: `providerWei ≤ grossWei ≤
//!   escrow.locked ≤ total supply < 2^64 sompi · NATIVE_SCALE`, so
//!   `providerWei / NATIVE_SCALE < 2^64` on-chain. The cast CAN truncate for
//!   super-supply inputs (u64-max price × u64-max tokens); this spec reproduces the
//!   truncation exactly so the differential pins it (vector
//!   `share_uint64_cast_truncation`).
//!
//! `Overdraw` (`grossWei > escrow.locked`) is contract-state-dependent and outside
//! this pure function.

/// MUST equal `MilShieldedEscrow.NATIVE_SCALE` (wei per sompi).
pub const NATIVE_SCALE: u64 = 10_000_000_000;
/// MUST equal `MilConstants.FEE_PROVIDER_PCT`.
pub const FEE_PROVIDER_PCT: u64 = 88;
/// MUST equal `MilConstants.FEE_BURN_PCT`.
pub const FEE_BURN_PCT: u64 = 5;

/// A minimal unsigned 256-bit integer (little-endian u64 limbs) — just enough to
/// reproduce Solidity's `uint256` semantics deterministically, with no external
/// dependency. All operations are fixed-width and panic-free for the input domain
/// of [`claim_v2_split`] (every intermediate is < 2^170; see the bound proofs at
/// the call sites).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);

    pub fn from_u128(x: u128) -> Self {
        U256([x as u64, (x >> 64) as u64, 0, 0])
    }

    /// Full 128×128→256 multiply (schoolbook on 64-bit limbs; cannot overflow).
    pub fn mul_u128(a: u128, b: u128) -> Self {
        let (a0, a1) = (a as u64 as u128, (a >> 64) as u64 as u128);
        let (b0, b1) = (b as u64 as u128, (b >> 64) as u64 as u128);
        let mut limbs = [0u64; 4];
        // limb 0
        let p00 = a0 * b0;
        limbs[0] = p00 as u64;
        let mut carry: u128 = p00 >> 64;
        // limb 1: a0b1 + a1b0 + carry (accumulate in u128 pieces to avoid overflow)
        let p01 = a0 * b1;
        let p10 = a1 * b0;
        let s = (p01 as u64 as u128) + (p10 as u64 as u128) + carry;
        limbs[1] = s as u64;
        carry = (s >> 64) + (p01 >> 64) + (p10 >> 64);
        // limb 2: a1b1 + carry
        let p11 = a1 * b1;
        let s = (p11 as u64 as u128) + carry;
        limbs[2] = s as u64;
        carry = (s >> 64) + (p11 >> 64);
        // limb 3
        limbs[3] = carry as u64;
        debug_assert_eq!(carry >> 64, 0);
        U256(limbs)
    }

    /// `self * m`, panicking on 256-bit overflow (Solidity 0.8 would revert; the
    /// input domain of `claim_v2_split` provably never reaches it).
    #[allow(clippy::needless_range_loop)] // limb index i reads self.0[i] AND writes limbs[i]
    pub fn mul_u64(self, m: u64) -> Self {
        let mut limbs = [0u64; 4];
        let mut carry: u128 = 0;
        for i in 0..4 {
            let p = (self.0[i] as u128) * (m as u128) + carry;
            limbs[i] = p as u64;
            carry = p >> 64;
        }
        assert_eq!(carry, 0, "U256 multiplication overflow (outside the claim_v2_split domain)");
        U256(limbs)
    }

    /// `(self / d, self % d)` for a small (u64) divisor — Solidity's floor division.
    pub fn divmod_u64(self, d: u64) -> (Self, u64) {
        assert_ne!(d, 0);
        let mut q = [0u64; 4];
        let mut rem: u128 = 0;
        for i in (0..4).rev() {
            let cur = (rem << 64) | (self.0[i] as u128);
            q[i] = (cur / d as u128) as u64;
            rem = cur % d as u128;
        }
        (U256(q), rem as u64)
    }

    /// `self - b`, panicking on underflow (never reached: `poolWei = grossWei −
    /// providerWei − burnWei ≥ 0` since 88 + 5 ≤ 100).
    #[allow(clippy::should_implement_trait)] // deliberately NOT std::ops::Sub: this sub asserts no-underflow (Solidity 0.8 revert semantics)
    #[allow(clippy::needless_range_loop)]
    pub fn sub(self, b: Self) -> Self {
        let mut limbs = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (x, b1) = self.0[i].overflowing_sub(b.0[i]);
            let (x, b2) = x.overflowing_sub(borrow);
            limbs[i] = x;
            borrow = (b1 as u64) + (b2 as u64);
        }
        assert_eq!(borrow, 0, "U256 subtraction underflow (outside the claim_v2_split domain)");
        U256(limbs)
    }

    /// Solidity's `uint64(x)` — the truncating cast (low 64 bits).
    pub fn low_u64(self) -> u64 {
        self.0[0]
    }

    /// The value as u128, panicking if it does not fit (call sites carry bound proofs).
    pub fn to_u128(self) -> u128 {
        assert_eq!(self.0[2] | self.0[3], 0, "U256 does not fit u128");
        (self.0[1] as u128) << 64 | self.0[0] as u128
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 4]
    }

    /// Decimal string (for the shared differential vectors).
    pub fn to_decimal(self) -> String {
        if self.is_zero() {
            return "0".into();
        }
        let mut digits = Vec::new();
        let mut cur = self;
        while !cur.is_zero() {
            let (q, r) = cur.divmod_u64(10);
            digits.push(b'0' + r as u8);
            cur = q;
        }
        digits.reverse();
        String::from_utf8(digits).unwrap()
    }

    /// Parse a decimal string (test/vector helper). `None` on a non-digit or overflow.
    pub fn from_decimal(s: &str) -> Option<Self> {
        if s.is_empty() {
            return None;
        }
        let mut acc = U256::ZERO;
        for c in s.bytes() {
            if !c.is_ascii_digit() {
                return None;
            }
            acc = acc.mul_u64(10);
            // add the digit (with carry)
            let mut carry = (c - b'0') as u128;
            for limb in acc.0.iter_mut() {
                if carry == 0 {
                    break;
                }
                let s = *limb as u128 + carry;
                *limb = s as u64;
                carry = s >> 64;
            }
            if carry != 0 {
                return None;
            }
        }
        Some(acc)
    }
}

/// The exact split `claimAnonV2` performs (all legs, wei-exact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimV2Split {
    /// `(price · (tokIn + tokOut)) / 1000` — floor. Fits u128 (≤ 2^129/1000 < 2^120).
    pub gross_sompi: u128,
    /// `gross_sompi · NATIVE_SCALE` (what the escrow debits from `locked`).
    pub gross_wei: U256,
    /// The 88 % leg paid into the shielded pool (`depositNote{value: providerWei}`).
    pub provider_wei: U256,
    /// `providerWei / NATIVE_SCALE` BEFORE the uint64 cast (fits u128).
    pub provider_share_sompi_full: u128,
    /// **The statement's public input** — `uint64(providerWei / NATIVE_SCALE)`,
    /// Solidity's TRUNCATING cast (equal to `provider_share_sompi_full` whenever
    /// gross ≤ supply; see the module docs).
    pub provider_share_sompi: u64,
    /// True iff the uint64 cast truncated (impossible within supply — diagnostic).
    pub share_truncated: bool,
    /// The 5 % burn leg.
    pub burn_wei: U256,
    /// The 7 % validator+treasury leg (lossless remainder).
    pub pool_wei: U256,
}

/// Why the split cannot settle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimV2SplitError {
    /// `providerWei % NATIVE_SCALE != 0` ⇔ `grossSompi % 25 != 0` — the contract
    /// reverts `SplitMismatch`; the claim can never settle at these inputs.
    #[error("provider share is not a whole sompi (grossSompi % 25 != 0) — claimAnonV2 reverts SplitMismatch")]
    SplitMismatch,
}

/// THE specification of `MilShieldedEscrow.claimAnonV2`'s split arithmetic —
/// operation-for-operation identical to the Solidity (see the module docs for the
/// frozen semantics and the shared cross-language vectors). Pure and total over all
/// `u64` inputs; `Err(SplitMismatch)` exactly when the contract reverts.
pub fn claim_v2_split(snapshot_price: u64, tok_in: u64, tok_out: u64) -> Result<ClaimV2Split, ClaimV2SplitError> {
    // uint256 grossSompi = (uint256(price) * (uint256(tokIn) + uint256(tokOut))) / 1000;
    // sum ≤ 2^65 − 2 (fits u128); price·sum < 2^129 (fits U256 trivially).
    let sum = tok_in as u128 + tok_out as u128;
    let prod = U256::mul_u128(snapshot_price as u128, sum);
    let (gross_sompi_u256, _) = prod.divmod_u64(1000);
    // gross ≤ 2^129/1000 < 2^120 → u128.
    let gross_sompi = gross_sompi_u256.to_u128();
    // uint256 grossWei = grossSompi * NATIVE_SCALE;  (< 2^120 · 2^34 = 2^154)
    let gross_wei = gross_sompi_u256.mul_u64(NATIVE_SCALE);
    // uint256 providerWei = (grossWei * 88) / 100;   (< 2^154 · 2^7 = 2^161)
    let (provider_wei, _) = gross_wei.mul_u64(FEE_PROVIDER_PCT).divmod_u64(100);
    // if (providerWei % NATIVE_SCALE != 0) revert SplitMismatch();
    let (share_full_u256, share_rem) = provider_wei.divmod_u64(NATIVE_SCALE);
    if share_rem != 0 {
        return Err(ClaimV2SplitError::SplitMismatch);
    }
    // uint64 providerShareSompi = uint64(providerWei / NATIVE_SCALE);  — truncating.
    let provider_share_sompi_full = share_full_u256.to_u128(); // ≤ 0.88·gross < 2^120
    let provider_share_sompi = share_full_u256.low_u64();
    let share_truncated = provider_share_sompi_full > u64::MAX as u128;
    // uint256 burnWei = (grossWei * 5) / 100;
    let (burn_wei, _) = gross_wei.mul_u64(FEE_BURN_PCT).divmod_u64(100);
    // uint256 poolWei = grossWei - providerWei - burnWei;
    let pool_wei = gross_wei.sub(provider_wei).sub(burn_wei);
    Ok(ClaimV2Split {
        gross_sompi,
        gross_wei,
        provider_wei,
        provider_share_sompi_full,
        provider_share_sompi,
        share_truncated,
        burn_wei,
        pool_wei,
    })
}

/// The FUNDING-TIME whole-sompi price step (audit M-07): the `/1000` token divisor × the 25-sompi
/// gross granularity. MUST equal `MilShieldedEscrow.WHOLE_SOMPI_PRICE_STEP` and the provider SDK's
/// `WHOLE_SOMPI_GROSS_STEP · 1000`.
pub const WHOLE_SOMPI_PRICE_STEP: u64 = 25_000;

/// Whether a uniform price is whole-sompi–denominated (audit M-07): `price % 25_000 == 0`.
///
/// When true, `gross = (price/1000)·tokens = 25·(price/25_000)·tokens` is an EXACT multiple of 25
/// for EVERY `(tok_in, tok_out)` (no `/1000` floor remainder), so [`claim_v2_split`] can never
/// return [`ClaimV2SplitError::SplitMismatch`] for that price. This is exactly the denomination
/// `MilShieldedEscrow.setClaimPolicy` enforces at the SOURCE, converting the former permanent
/// claim-time `SplitMismatch` trap into a governance-time rejection; the per-claim gate remains as
/// belt-and-suspenders. Off-chain pricing (gateway / provider SDK) should publish only
/// whole-sompi–denominated uniform prices for the shielded escrow.
pub fn price_yields_whole_sompi(uniform_price_per_1k: u64) -> bool {
    uniform_price_per_1k.is_multiple_of(WHOLE_SOMPI_PRICE_STEP)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The SHARED cross-language vector file (single source; also consumed by
    /// `contracts/mil/test/MilClaimV2Split.t.sol`).
    const VECTORS: &str = include_str!("../../../contracts/mil/test/vectors/claim_v2_split_vectors.json");

    fn u128s(v: &serde_json::Value, k: &str) -> u128 {
        v[k].as_str().unwrap().parse::<u128>().unwrap()
    }
    fn u64s(v: &serde_json::Value, k: &str) -> u64 {
        v[k].as_str().unwrap().parse::<u64>().unwrap()
    }
    fn u256s(v: &serde_json::Value, k: &str) -> U256 {
        U256::from_decimal(v[k].as_str().unwrap()).unwrap()
    }

    /// (audit C-02 acceptance) The Rust spec reproduces every shared vector —
    /// boundaries (0, floors, mod-25 residues 1/2/24, u64-max-adjacent, the
    /// uint64-cast truncation, abs-max inputs) byte-for-byte with the values the
    /// forge test asserts against the LIVE contract.
    #[test]
    fn shared_vectors_differential() {
        let root: serde_json::Value = serde_json::from_str(VECTORS).expect("vector file parses");
        let vectors = root["vectors"].as_array().unwrap();
        assert_eq!(vectors.len() as u64, root["count"].as_u64().unwrap(), "count field in sync");
        assert!(vectors.len() >= 12, "boundary corpus present");
        let mut ok_count = 0;
        let mut revert_count = 0;
        for v in vectors {
            let name = v["name"].as_str().unwrap();
            let r = claim_v2_split(u64s(v, "price"), u64s(v, "tokIn"), u64s(v, "tokOut"));
            if v["ok"].as_bool().unwrap() {
                let s = r.unwrap_or_else(|e| panic!("vector {name} must split: {e}"));
                assert_eq!(s.gross_sompi, u128s(v, "grossSompi"), "{name}: grossSompi");
                assert_eq!(s.gross_wei, u256s(v, "grossWei"), "{name}: grossWei");
                assert_eq!(s.provider_share_sompi, u64s(v, "shareSompi"), "{name}: shareSompi (post-uint64-cast)");
                assert_eq!(s.provider_wei, u256s(v, "providerWei"), "{name}: providerWei");
                assert_eq!(s.burn_wei, u256s(v, "burnWei"), "{name}: burnWei");
                assert_eq!(s.pool_wei, u256s(v, "poolWei"), "{name}: poolWei");
                // conservation: the three legs recompose the gross exactly.
                let recomposed = {
                    // provider + burn + pool == gross
                    let mut limbs = [0u64; 4];
                    let mut carry: u128 = 0;
                    #[allow(clippy::needless_range_loop)]
                    for i in 0..4 {
                        let t = s.provider_wei.0[i] as u128 + s.burn_wei.0[i] as u128 + s.pool_wei.0[i] as u128 + carry;
                        limbs[i] = t as u64;
                        carry = t >> 64;
                    }
                    assert_eq!(carry, 0);
                    U256(limbs)
                };
                assert_eq!(recomposed, s.gross_wei, "{name}: 88+5+7 legs must recompose the gross exactly");
                ok_count += 1;
            } else {
                assert_eq!(r, Err(ClaimV2SplitError::SplitMismatch), "vector {name} must revert SplitMismatch");
                // and the revert condition is exactly gross % 25 != 0.
                assert_ne!(u128s(v, "grossSompi") % 25, 0, "{name}: revert vectors have gross % 25 != 0");
                revert_count += 1;
            }
        }
        assert!(ok_count >= 6 && revert_count >= 4, "corpus covers both outcomes (ok={ok_count}, revert={revert_count})");
        println!("C-02 differential: {ok_count} settle vectors + {revert_count} SplitMismatch vectors match the Solidity semantics");
    }

    /// The whole-sompi gate is EXACTLY `gross % 25 == 0` — property-checked across a
    /// contiguous gross range (every residue class) plus supply-scale grosses.
    #[test]
    fn whole_sompi_gate_iff_gross_mod_25() {
        for gross in 0u64..=1000 {
            // price = 1000·gross / (tokIn=1000) reproduces an exact gross of `gross`.
            let r = claim_v2_split(gross, 1000, 0);
            assert_eq!(r.is_ok(), gross % 25 == 0, "gross {gross}");
            if let Ok(s) = r {
                assert_eq!(s.gross_sompi, gross as u128);
                assert_eq!(s.provider_share_sompi as u128, (gross as u128) * 88 / 100);
                assert!(!s.share_truncated);
            }
        }
    }

    /// (audit M-07) The funding-time price gate is SOUND and TIGHT. SOUND: any whole-sompi–
    /// denominated uniform price (`price % 25_000 == 0`) makes `claim_v2_split` settle for EVERY
    /// token count — never `SplitMismatch` — so the on-chain `setClaimPolicy` gate provably admits
    /// only permanently-settleable escrows. TIGHT: a price one whole-sompi step off has a token
    /// count that traps, which is exactly why the gate cannot be relaxed below a 25_000 multiple.
    #[test]
    fn whole_sompi_price_gate_admits_only_settleable_escrows() {
        // SOUND: every multiple of 25_000 settles across a broad token grid, gross always ≡ 0 mod 25.
        for k in 0u64..=8 {
            let price = k * WHOLE_SOMPI_PRICE_STEP;
            assert!(price_yields_whole_sompi(price), "price {price} is whole-sompi denominated");
            for tin in [0u64, 1, 7, 999, 1000, 1001, 24_000, 25_999, 50_000, 1_000_003] {
                for tout in [0u64, 1, 500, 51_000] {
                    let r = claim_v2_split(price, tin, tout);
                    let s = r.unwrap_or_else(|e| panic!("whole-sompi price {price} must settle for ({tin},{tout}): {e}"));
                    assert_eq!(s.gross_sompi % 25, 0, "gross must be ≡ 0 (mod 25) for price {price}, ({tin},{tout})");
                }
            }
        }
        // TIGHT: a non-gated price near the step (26_000) is rejected by the gate AND has a token
        // count whose gross (26_000·1/1000 = 26, 26 % 25 = 1) traps claim_v2_split at SplitMismatch.
        assert!(!price_yields_whole_sompi(26_000));
        assert_eq!(claim_v2_split(26_000, 1, 0), Err(ClaimV2SplitError::SplitMismatch));
    }

    /// net ±1 mutation (audit C-02 acceptance): a share off by one in EITHER direction
    /// can never satisfy the exact-split identity `share · 25 == 22 · gross`.
    #[test]
    fn share_plus_minus_one_breaks_the_split_identity() {
        for gross in (25u64..=10_000).step_by(25) {
            let s = claim_v2_split(gross, 1000, 0).unwrap();
            let share = s.provider_share_sompi;
            assert_eq!(share as u128 * 25, gross as u128 * 22, "the exact 88% identity");
            for mutated in [share.wrapping_add(1), share.wrapping_sub(1)] {
                assert_ne!(mutated as u128 * 25, gross as u128 * 22, "share ±1 must not satisfy the identity (gross {gross})");
            }
        }
    }

    /// Total over ALL u64 inputs — no panic anywhere near the overflow edges
    /// (Solidity could not overflow either: max intermediate < 2^170 < 2^256).
    #[test]
    fn no_panic_on_extreme_inputs() {
        for (p, i, o) in [
            (u64::MAX, u64::MAX, u64::MAX),
            (u64::MAX, u64::MAX, 0),
            (u64::MAX, 0, 0),
            (0, u64::MAX, u64::MAX),
            (1, u64::MAX, u64::MAX),
            (u64::MAX, 1, 1),
        ] {
            let _ = claim_v2_split(p, i, o); // Ok or Err, never a panic
        }
    }

    #[test]
    fn u256_decimal_roundtrip_and_arithmetic() {
        for s in [
            "0",
            "1",
            "25",
            "18446744073709551615",
            "18446744073709551616",
            "680564733841876926852962238568698216",
            "6805647338418769268529622385686982160000000000",
        ] {
            let v = U256::from_decimal(s).unwrap();
            assert_eq!(v.to_decimal(), s, "roundtrip {s}");
        }
        // 128×128 multiply spot check vs u128 (within range) and beyond.
        let a = U256::mul_u128(u64::MAX as u128, u64::MAX as u128);
        assert_eq!(a.to_u128(), (u64::MAX as u128) * (u64::MAX as u128));
        let b = U256::mul_u128(u128::MAX, 2);
        assert_eq!(b.to_decimal(), "680564733841876926926749214863536422910"); // (2^128−1)·2
        // divmod
        let (q, r) = b.divmod_u64(1000);
        assert_eq!(q.mul_u64(1000).0, b.sub(U256::from_u128(r as u128)).0);
        assert!(U256::from_decimal("").is_none());
        assert!(U256::from_decimal("12a").is_none());
    }
}
