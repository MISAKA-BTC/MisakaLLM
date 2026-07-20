//! Cross-crate pin for the duplicated Receipt v3 signature context.
//!
//! `kaspa-consensus-core` owns the signature-domain registry and must remain independent of the
//! provider-side `misaka-palw` crate. This integration-test crate already depends on both and is the
//! acyclic place to prove that the registry row and wire verifier use exactly the same FIPS-204 ctx.

#[test]
fn receipt_v3_signature_context_matches_consensus_registry() {
    assert_eq!(kaspa_consensus_core::palw::PALW_RECEIPT_V3_MLDSA87_CONTEXT, misaka_palw::receipt_v3::PALW_RECEIPT_V3_MLDSA87_CONTEXT,);
}
