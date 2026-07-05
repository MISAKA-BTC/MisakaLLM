//! ML-KEM-1024 (FIPS 203) wrappers over the RustCrypto `ml-kem` crate.
//!
//! The provider (enclave) holds the decapsulation key; the requester
//! encapsulates against the registered/attested `pk_kem`. Byte-level key and
//! ciphertext encodings are the FIPS 203 canonical ones.

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024};
use rand::SeedableRng;
use rand::rngs::OsRng;
use zeroize::Zeroize;

type DecapsKey = <MlKem1024 as KemCore>::DecapsulationKey;
type EncapsKey = <MlKem1024 as KemCore>::EncapsulationKey;

/// ML-KEM-1024 encapsulation-key length (FIPS 203).
pub const KEM_EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext length (FIPS 203).
pub const KEM_CT_LEN: usize = 1568;
/// Shared-secret length.
pub const KEM_SS_LEN: usize = 32;
/// Seed length for deterministic provider keygen.
pub const KEM_SEED_LEN: usize = 32;

/// KEM-level failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KemError {
    #[error("ML-KEM-1024 encapsulation key must be {KEM_EK_LEN} bytes, got {0}")]
    BadEncapsKeyLength(usize),
    #[error("ML-KEM-1024 ciphertext must be {KEM_CT_LEN} bytes, got {0}")]
    BadCiphertextLength(usize),
    #[error("malformed ML-KEM-1024 encapsulation key")]
    MalformedEncapsKey,
}

/// The provider-side ML-KEM-1024 keypair. In Tier 1 this is generated inside
/// the enclave; the v0 sidecar derives it deterministically from its seed
/// file so the registered `pk_kem` survives restarts.
pub struct ProviderKemKeys {
    dk: DecapsKey,
    ek_bytes: [u8; KEM_EK_LEN],
}

impl ProviderKemKeys {
    /// Fresh random keypair (enclave path).
    pub fn generate() -> Self {
        let (dk, ek) = MlKem1024::generate(&mut OsRng);
        Self { ek_bytes: ek.as_bytes().into(), dk }
    }

    /// Deterministic keypair from a 32-byte seed (v0 sidecar path). The seed
    /// drives a ChaCha20 DRBG so we do not depend on the `ml-kem`
    /// `deterministic` test feature; the seed is scrubbed after use.
    pub fn from_seed(mut seed: [u8; KEM_SEED_LEN]) -> Self {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        seed.zeroize();
        let (dk, ek) = MlKem1024::generate(&mut rng);
        Self { ek_bytes: ek.as_bytes().into(), dk }
    }

    /// The public encapsulation key (`pk_kem`), FIPS 203 encoding.
    pub fn public_key(&self) -> &[u8; KEM_EK_LEN] {
        &self.ek_bytes
    }

    /// Recover the session shared secret from the requester's ciphertext.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<[u8; KEM_SS_LEN], KemError> {
        decapsulate(&self.dk, ct)
    }
}

/// Requester side: encapsulate to a provider's registered `pk_kem`.
/// Returns `(ciphertext, shared_secret)`.
pub fn encapsulate(pk_kem: &[u8]) -> Result<([u8; KEM_CT_LEN], [u8; KEM_SS_LEN]), KemError> {
    let encoded: [u8; KEM_EK_LEN] = pk_kem.try_into().map_err(|_| KemError::BadEncapsKeyLength(pk_kem.len()))?;
    let ek = EncapsKey::from_bytes(&Encoded::<EncapsKey>::from(encoded));
    let (ct, ss) = ek.encapsulate(&mut OsRng).map_err(|_| KemError::MalformedEncapsKey)?;
    Ok((ct.into(), ss.into()))
}

/// Provider side: decapsulate with an explicit decapsulation key.
pub fn decapsulate(dk: &DecapsKey, ct: &[u8]) -> Result<[u8; KEM_SS_LEN], KemError> {
    let ct_arr: [u8; KEM_CT_LEN] = ct.try_into().map_err(|_| KemError::BadCiphertextLength(ct.len()))?;
    let ct = ml_kem::Ciphertext::<MlKem1024>::from(ct_arr);
    // ML-KEM decapsulation is implicit-rejection: it cannot fail, it returns
    // a pseudorandom secret for a bad ciphertext (the AEAD then fails).
    let ss = dk.decapsulate(&ct).expect("ML-KEM decapsulation is infallible (implicit rejection)");
    Ok(ss.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encaps_decaps_agree() {
        let keys = ProviderKemKeys::generate();
        let (ct, ss_req) = encapsulate(keys.public_key()).unwrap();
        let ss_prov = keys.decapsulate(&ct).unwrap();
        assert_eq!(ss_req, ss_prov);
        assert_ne!(ss_req, [0u8; KEM_SS_LEN]);
    }

    #[test]
    fn seeded_keygen_is_deterministic() {
        let a = ProviderKemKeys::from_seed([7u8; KEM_SEED_LEN]);
        let b = ProviderKemKeys::from_seed([7u8; KEM_SEED_LEN]);
        let c = ProviderKemKeys::from_seed([8u8; KEM_SEED_LEN]);
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a.public_key(), c.public_key());
        // and the deterministic key actually decapsulates
        let (ct, ss) = encapsulate(a.public_key()).unwrap();
        assert_eq!(b.decapsulate(&ct).unwrap(), ss);
    }

    #[test]
    fn tampered_ciphertext_yields_different_secret_not_error() {
        let keys = ProviderKemKeys::generate();
        let (mut ct, ss) = encapsulate(keys.public_key()).unwrap();
        ct[10] ^= 0x55;
        let ss2 = keys.decapsulate(&ct).unwrap();
        assert_ne!(ss, ss2, "implicit rejection must divert to a pseudorandom secret");
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        assert_eq!(encapsulate(&[0u8; 10]).unwrap_err(), KemError::BadEncapsKeyLength(10));
        let keys = ProviderKemKeys::generate();
        assert_eq!(keys.decapsulate(&[0u8; 5]).unwrap_err(), KemError::BadCiphertextLength(5));
    }
}
