//! Response-length side-channel padding (design §15.3).
//!
//! The AEAD ciphertext length leaks the plaintext length, so an observer can
//! infer response size (and, across turns, content structure). Two defenses,
//! both applied to the *plaintext* before it is sealed:
//!
//! - **Cell padding** ([`PaddingPolicy::Cell`]): every frame's plaintext is
//!   padded to a fixed cell multiple, so all records on the wire are
//!   size-quantized. (The v2 2-hop relay uses a fixed 4 KiB cell, §15.3c; this
//!   is the same codec at any cell size.)
//! - **Bucket rounding** ([`bucket_round`]): the number of emitted response
//!   chunks/tokens is rounded up to a coarse bucket, so the total length
//!   reveals only the bucket, not the exact count.
//!
//! Wire format of a padded frame: `real_len (u32 LE) ‖ payload ‖ zero-fill`,
//! total length a multiple of the cell. The receiver reads `real_len` and
//! returns exactly that many payload bytes; the zero-fill authenticates as part
//! of the AEAD record but carries no information.

/// How a stream pads its frames (§15.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingPolicy {
    /// No padding — the wire length equals the plaintext length.
    None,
    /// Pad each frame's plaintext up to a multiple of `cell` bytes (cell ≥ 1).
    Cell(usize),
}

impl PaddingPolicy {
    /// Whether this policy frames (and thus must be [`Self::unpad`]'d on receipt).
    /// [`Self::None`] is zero-overhead identity so it stays byte-compatible.
    pub fn is_framed(&self) -> bool {
        matches!(self, PaddingPolicy::Cell(_))
    }

    /// Encode `payload` under this policy. [`Self::None`] returns it unchanged
    /// (no framing, no overhead). [`Self::Cell`] prepends a u32 real-length and
    /// zero-fills to the next cell multiple.
    pub fn pad(&self, payload: &[u8]) -> Vec<u8> {
        let PaddingPolicy::Cell(cell) = self else {
            return payload.to_vec();
        };
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        framed.extend_from_slice(payload);
        let cell = (*cell).max(1);
        let rem = framed.len() % cell;
        if rem != 0 {
            framed.resize(framed.len() + (cell - rem), 0);
        }
        framed
    }

    /// Decode a [`Self::Cell`]-padded frame back to the original payload. Rejects
    /// a frame whose declared real-length exceeds the available bytes (tamper /
    /// truncation). Only call this when the sender used a framed policy.
    pub fn unpad(framed: &[u8]) -> Result<Vec<u8>, PaddingError> {
        if framed.len() < 4 {
            return Err(PaddingError::TooShort);
        }
        let real_len = u32::from_le_bytes(framed[0..4].try_into().unwrap()) as usize;
        if real_len > framed.len() - 4 {
            return Err(PaddingError::BadLength { declared: real_len, available: framed.len() - 4 });
        }
        Ok(framed[4..4 + real_len].to_vec())
    }
}

/// Padding decode failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PaddingError {
    #[error("padded frame is shorter than the 4-byte length prefix")]
    TooShort,
    #[error("padded frame declares {declared} payload bytes but only {available} are present")]
    BadLength { declared: usize, available: usize },
}

/// Round `n` up to the next multiple of `bucket` (bucket ≥ 1) — length
/// quantization for the total response (§15.3a). The extra units are emitted as
/// padding tokens so the on-wire response length reveals only the bucket.
pub fn bucket_round(n: u64, bucket: u64) -> u64 {
    let bucket = bucket.max(1);
    n.div_ceil(bucket) * bucket
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_padding_quantizes_and_round_trips() {
        let policy = PaddingPolicy::Cell(64);
        for len in [0usize, 1, 59, 60, 61, 128, 200] {
            let payload = vec![0xABu8; len];
            let framed = policy.pad(&payload);
            assert_eq!(framed.len() % 64, 0, "framed length must be a cell multiple for len={len}");
            assert_eq!(PaddingPolicy::unpad(&framed).unwrap(), payload);
        }
        // different payload lengths within the same cell produce equal wire lengths
        assert_eq!(policy.pad(&[0u8; 10]).len(), policy.pad(&[0u8; 20]).len());
    }

    #[test]
    fn none_policy_is_zero_overhead_identity() {
        assert!(!PaddingPolicy::None.is_framed());
        assert_eq!(PaddingPolicy::None.pad(b"hello"), b"hello", "None adds no framing (byte-identical)");
        assert!(PaddingPolicy::Cell(64).is_framed());
    }

    #[test]
    fn unpad_rejects_malformed() {
        assert_eq!(PaddingPolicy::unpad(&[0u8; 2]), Err(PaddingError::TooShort));
        let mut framed = PaddingPolicy::Cell(64).pad(b"hi");
        framed[0] = 0xff; // declare 255 bytes
        assert!(matches!(PaddingPolicy::unpad(&framed), Err(PaddingError::BadLength { .. })));
    }

    #[test]
    fn bucket_rounding() {
        assert_eq!(bucket_round(0, 32), 0);
        assert_eq!(bucket_round(1, 32), 32);
        assert_eq!(bucket_round(32, 32), 32);
        assert_eq!(bucket_round(33, 32), 64);
        assert_eq!(bucket_round(100, 1), 100);
    }
}
