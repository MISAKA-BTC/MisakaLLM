//! kaspa-pq **ADR-0040 §D — the signature domain table**.
//!
//! # Why a table rather than per-pair fixes
//!
//! Cross-protocol signature replay is a *class* of defect, not a sequence of incidents. It was closed
//! once for the PALW auditor vote (a beacon-commit signature must not be replayable as an audit vote),
//! but closing it pairwise means the next signing object re-opens it, and the review that would have
//! caught it has nothing to check against.
//!
//! This table is the enforcement point for the rule "**every ML-DSA-87 signing object declares a
//! distinct libcrux `ctx`**". A new signed object is added here or the table test fails — the same
//! shape as ADR-0040's other rule/enforcement pairings (§2.6): a rule that lives only in prose is a
//! rule that will be violated by a type.
//!
//! # What belongs here
//!
//! Only **signature** contexts — the `ctx` argument to `verify_mldsa87_with_context` / `sign`. Keyed
//! *hash* domains (`blake2b_512_keyed` keys such as `OverlayCommit64` or `EvmPayload64`) are a separate
//! namespace: they domain-separate digests, not signatures, and a collision between the two namespaces
//! is harmless because neither is ever fed to the other's primitive. Mixing them into one table would
//! make the distinctness assertion say less than it appears to.
//!
//! # Known naming inconsistency (deliberately surfaced, not silently normalised)
//!
//! Most contexts follow `"<project>-v1/<purpose>/mldsa87"`. The two PALW entries do not
//! (`"PALWBeaconV1"`, `"PALWAuditorVoteV1"`). Renaming them would change every signature they cover, so
//! it is a re-genesis-only change — recorded here so the divergence is a known debt rather than a
//! surprise, and so a new PALW object copies the surrounding convention consciously.

/// One row of the signature domain table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureDomain {
    /// The object whose signature this context covers.
    pub object: &'static str,
    /// The libcrux `ctx` bytes.
    pub context: &'static [u8],
    /// Where the signing preimage is defined.
    pub defined_in: &'static str,
}

/// **Every ML-DSA-87 signature context in consensus.** Adding a signed object without adding a row
/// here is caught by [`tests::every_signature_domain_is_distinct`] only if the row is added — so the
/// discipline is: *new signing object ⇒ new row, in the same commit.*
pub const SIGNATURE_DOMAINS: &[SignatureDomain] = &[
    SignatureDomain {
        object: "DNS validator attestation",
        context: crate::dns_finality::ATTESTATION_MLDSA87_CONTEXT,
        defined_in: "dns_finality::StakeAttestationPayload",
    },
    SignatureDomain {
        object: "DNS unbond request",
        context: crate::dns_finality::UNBOND_REQUEST_CONTEXT,
        defined_in: "dns_finality::UnbondRequestPayload",
    },
    SignatureDomain {
        object: "DNS validator takeover token",
        context: crate::dns_finality::TAKEOVER_TOKEN_CONTEXT,
        defined_in: "dns_finality::TakeoverToken",
    },
    SignatureDomain {
        object: "DNS audit checkpoint",
        context: crate::dns_finality::AUDIT_CHECKPOINT_MLDSA87_CONTEXT,
        defined_in: "dns_finality::AuditCheckpoint",
    },
    SignatureDomain {
        object: "PALW beacon commit/reveal",
        context: crate::palw::PALW_BEACON_MLDSA87_CONTEXT,
        defined_in: "palw::PalwBeaconCommitV1::signing_hash",
    },
    SignatureDomain {
        object: "PALW batch-certificate auditor vote",
        context: crate::palw::PALW_AUDITOR_MLDSA87_CONTEXT,
        defined_in: "palw::PalwAuditorVoteV1::signing_hash",
    },
    SignatureDomain {
        object: "PALW per-block ticket authorization",
        context: crate::palw::PALW_AUTHORIZATION_MLDSA87_CONTEXT,
        defined_in: "palw::PalwBlockAuthorizationV1::signing_hash",
    },
    SignatureDomain {
        object: "F003 PREA account root key",
        context: crate::evm::F003_PREA_ROOT_MLDSA87_CONTEXT,
        defined_in: "evm::F003 PREA",
    },
    SignatureDomain {
        object: "F003 PREA per-operation key",
        context: crate::evm::F003_PREA_OP_MLDSA87_CONTEXT,
        defined_in: "evm::F003 PREA",
    },
    SignatureDomain {
        object: "F003 FSL verify",
        context: crate::evm::F003_FSL_VERIFY_MLDSA87_CONTEXT,
        defined_in: "evm::F003 FSL",
    },
];

/// Objects that ADR-0040 expects to sign something but which have **no context yet**, because the
/// object itself is unimplemented. Listed so the gap is visible in the same place as the table rather
/// than being discovered when someone implements one and reaches for an existing constant.
pub const PENDING_SIGNATURE_DOMAINS: &[&str] = &[
    // ADR-0040 §16′: the per-job completion tip is a fee-era lever, not yet specified.
    "PALW job completion tip (§16′ fee lane)",
    // ADR-0040 P2-1: provider/credential registration in the single bonded registry.
    "PALW provider credential registration (P2-1)",
    // The MIL inference lane (F003 MIL-receipt precompile) is not part of this build: this tree carries
    // PALW only. Its receipt context is therefore absent rather than pending-by-design — listed here so
    // that porting the lane in adds a row to SIGNATURE_DOMAINS instead of reusing an F003 PREA/FSL ctx.
    "MIL provider receipt (F003 MIL receipt — lane not built here)",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The enforcement point for "cross-protocol replay is closed as a class".
    ///
    /// Distinctness is the whole property: two objects sharing a `ctx` means a signature over one can be
    /// presented as a signature over the other whenever their preimages can be made to coincide — and
    /// preimage coincidence is exactly the kind of thing a later refactor introduces by accident.
    #[test]
    fn every_signature_domain_is_distinct() {
        let mut seen: HashSet<&[u8]> = HashSet::new();
        for d in SIGNATURE_DOMAINS {
            assert!(!d.context.is_empty(), "{}: an empty context provides no separation at all", d.object);
            assert!(seen.insert(d.context), "duplicate signature context {:?} — {} collides with an earlier row", d.context, d.object);
        }
        assert_eq!(seen.len(), SIGNATURE_DOMAINS.len());
    }

    /// No context may be a prefix of another. Distinctness alone is not sufficient for every encoding:
    /// if `ctx` were ever concatenated with a variable-length field rather than passed as its own
    /// argument, `"A"` and `"AB"` would become confusable. Enforcing prefix-freedom costs nothing now
    /// and removes that whole failure mode from the design's future.
    #[test]
    fn signature_domains_are_prefix_free() {
        for a in SIGNATURE_DOMAINS {
            for b in SIGNATURE_DOMAINS {
                if a.context == b.context {
                    continue;
                }
                assert!(
                    !a.context.starts_with(b.context),
                    "{:?} ({}) is a prefix of {:?} ({})",
                    b.context,
                    b.object,
                    a.context,
                    a.object
                );
            }
        }
    }

    /// The PALW rows deliberately diverge from the `"<project>-v1/<purpose>/mldsa87"` convention. This
    /// test PINS that divergence rather than hiding it: renaming them changes every signature they
    /// cover, so it is a re-genesis-only change. If a future PALW object copies the wrong convention,
    /// this is where the decision surfaces.
    #[test]
    fn palw_naming_divergence_is_pinned_not_forgotten() {
        let palw: Vec<_> = SIGNATURE_DOMAINS.iter().filter(|d| d.object.starts_with("PALW")).collect();
        assert_eq!(palw.len(), 3, "if a PALW signing object was added, decide its naming convention explicitly");
        for d in &palw {
            assert!(
                !d.context.starts_with(b"kaspa-pq-v1/"),
                "{} now follows the slash convention — update this test and the module note",
                d.object
            );
        }
    }

    /// A row must not silently lose its context (e.g. a constant refactored to `b""`).
    #[test]
    fn pending_domains_are_named_not_empty() {
        for p in PENDING_SIGNATURE_DOMAINS {
            assert!(!p.is_empty());
        }
    }
}
