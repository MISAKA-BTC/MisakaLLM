//! THE versioned statement-schema MANIFEST (audit 2026-07-11 C-01 remediation).
//!
//! This module is the **single source of truth** for the field NAME / ORDER /
//! WIDTH / total size of every frozen shield statement, keyed by
//! `circuit_version`. Every layer that encodes, decodes, or surfaces a
//! statement MUST agree with this manifest, and each is pinned to it by a test:
//!
//! - **Rust encoders/decoders** — the borsh `#[derive]` on
//!   [`crate::spend::SpendStatement`], [`crate::provider::ProviderClaimStatement`]
//!   and [`crate::provider::ProviderClaimStatementV2`] serializes fields in
//!   declaration order; the tests below assert byte-for-byte that the borsh
//!   output equals the schema-driven assembly (order, offsets, widths, total).
//! - **Solidity builders** — `MilShieldedEscrow._borshClaimStatement{,V2}`
//!   assemble the same bytes with `abi.encodePacked`; the tests below
//!   independently reconstruct that exact packed layout (the established
//!   `evm_ctx.rs` cross-language differential pattern) and assert equality
//!   with the Rust encoding. `contracts/mil/test/MilClaimV2Split.t.sol`
//!   mirrors the layout pin on the contract side.
//! - **Node verifier** — `mil/shield-stark-verify`'s `statement_to_pvs` is
//!   one byte = one BabyBear element over exactly these bytes; its tests
//!   cross-assert the sizes against this manifest.
//! - **AIR public inputs** — the claim-v2 AIR
//!   (`docs/bench/plonky3-shield-air/claim_v2.rs`) surfaces its public values
//!   in this exact field order (bit-decomposed), including the
//!   `provider_share_sompi` word between `cm_payout` and `ctx`.
//!
//! Changing any statement layout REQUIRES a new `circuit_version` + a new
//! schema constant here — never an in-place edit (the vk-pinning ceremony and
//! the on-chain builders both freeze the old bytes).

/// Field primitive kind — determines the byte encoding inside the statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// 64-byte keyed-BLAKE2b digest (`Hash64`), raw bytes.
    Hash64,
    /// Little-endian `u64` (8 bytes) — borsh and Solidity `_le64` agree.
    U64Le,
    /// Little-endian `u32` (4 bytes).
    U32Le,
}

impl FieldKind {
    pub const fn width(self) -> usize {
        match self {
            FieldKind::Hash64 => 64,
            FieldKind::U64Le => 8,
            FieldKind::U32Le => 4,
        }
    }
}

/// One statement field: canonical name, kind (⇒ width), and byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    pub name: &'static str,
    pub kind: FieldKind,
    pub offset: usize,
}

impl FieldSpec {
    pub const fn width(&self) -> usize {
        self.kind.width()
    }
    /// The byte range of this field inside the encoded statement.
    pub fn range(&self) -> core::ops::Range<usize> {
        self.offset..self.offset + self.width()
    }
}

/// The frozen encoding of one statement version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatementSchema {
    /// The `circuit_version` this schema belongs to (`ShieldProof.circuit_version`).
    pub circuit_version: u16,
    pub name: &'static str,
    /// Total encoded size in bytes (fixed — no variable-width field is allowed
    /// in a statement; a valid encoding has EXACTLY this length).
    pub size: usize,
    pub fields: &'static [FieldSpec],
}

impl StatementSchema {
    /// Look a field up by name.
    pub fn field(&self, name: &str) -> Option<&'static FieldSpec> {
        self.fields.iter().find(|f| f.name == name)
    }
}

/// `SpendStatement` (circuit_version = 1): 404 bytes.
pub const SPEND_STATEMENT_SCHEMA: StatementSchema = StatementSchema {
    circuit_version: crate::proof::CIRCUIT_SPEND,
    name: "SpendStatement",
    size: 404,
    fields: &[
        FieldSpec { name: "anchor", kind: FieldKind::Hash64, offset: 0 },
        FieldSpec { name: "nf_old[0]", kind: FieldKind::Hash64, offset: 64 },
        FieldSpec { name: "nf_old[1]", kind: FieldKind::Hash64, offset: 128 },
        FieldSpec { name: "cm_new[0]", kind: FieldKind::Hash64, offset: 192 },
        FieldSpec { name: "cm_new[1]", kind: FieldKind::Hash64, offset: 256 },
        FieldSpec { name: "v_pub_in", kind: FieldKind::U64Le, offset: 320 },
        FieldSpec { name: "v_pub_out", kind: FieldKind::U64Le, offset: 328 },
        FieldSpec { name: "token_id", kind: FieldKind::U32Le, offset: 336 },
        FieldSpec { name: "ctx", kind: FieldKind::Hash64, offset: 340 },
    ],
};

/// `ProviderClaimStatement` (circuit_version = 2): 328 bytes.
/// Solidity builder: `MilShieldedEscrow._borshClaimStatement`.
pub const PROVIDER_CLAIM_STATEMENT_SCHEMA: StatementSchema = StatementSchema {
    circuit_version: crate::proof::CIRCUIT_PROVIDER_CLAIM,
    name: "ProviderClaimStatement",
    size: 328,
    fields: &[
        FieldSpec { name: "provider_set_root", kind: FieldKind::Hash64, offset: 0 },
        FieldSpec { name: "session_cm", kind: FieldKind::Hash64, offset: 64 },
        FieldSpec { name: "amount", kind: FieldKind::U64Le, offset: 128 },
        FieldSpec { name: "provider_nf", kind: FieldKind::Hash64, offset: 136 },
        FieldSpec { name: "cm_payout", kind: FieldKind::Hash64, offset: 200 },
        FieldSpec { name: "ctx", kind: FieldKind::Hash64, offset: 264 },
    ],
};

/// `ProviderClaimStatementV2` (circuit_version = 4, hidden-amount claim): 392 bytes.
/// Solidity builder: `MilShieldedEscrow._borshClaimStatementV2`. The
/// `provider_share_sompi` field is the CONTRACT-COMPUTED 88%-of-gross whole-sompi
/// share (audit C-06.2 / C-01): the claim circuit binds its private payout amount
/// to exactly this public value, so a proof can neither fund a larger note than
/// the contract pays in nor a smaller one than the provider is owed.
pub const PROVIDER_CLAIM_V2_STATEMENT_SCHEMA: StatementSchema = StatementSchema {
    circuit_version: crate::proof::CIRCUIT_PROVIDER_CLAIM_V2,
    name: "ProviderClaimStatementV2",
    size: 392,
    fields: &[
        FieldSpec { name: "provider_set_root", kind: FieldKind::Hash64, offset: 0 },
        FieldSpec { name: "session_cm", kind: FieldKind::Hash64, offset: 64 },
        FieldSpec { name: "v_claim_cm", kind: FieldKind::Hash64, offset: 128 },
        FieldSpec { name: "provider_nf", kind: FieldKind::Hash64, offset: 192 },
        FieldSpec { name: "cm_payout", kind: FieldKind::Hash64, offset: 256 },
        FieldSpec { name: "provider_share_sompi", kind: FieldKind::U64Le, offset: 320 },
        FieldSpec { name: "ctx", kind: FieldKind::Hash64, offset: 328 },
    ],
};

/// `ProviderClaimStatementV3` (circuit_version = 3, receipt-authorized claim / C-P6): 456 bytes.
/// Solidity builder: `MilShieldedEscrow._borshClaimStatementV3`. It is the 392-byte claim-v2
/// layout with one 64-byte field inserted — `receipt_cm`, the [`crate::provider::receipt_verify_commitment`]
/// binding a VALID in-circuit ML-DSA-87 service receipt (ADR-0037 §2.4). `receipt_cm` sits between
/// `cm_payout` and `provider_share_sompi`, so the v2 fields keep their names/kinds and only the
/// offsets of `provider_share_sompi` (320→384) and `ctx` (328→392) shift by 64. INERT — the
/// circuit-3 vk is unfrozen and the F006 fence is `u64::MAX`; the layout is frozen HERE so the
/// on-chain builder and the node decoder cannot drift once C-P6 activates.
pub const PROVIDER_CLAIM_V3_STATEMENT_SCHEMA: StatementSchema = StatementSchema {
    circuit_version: crate::proof::CIRCUIT_PROVIDER_CLAIM_V3,
    name: "ProviderClaimStatementV3",
    size: 456,
    fields: &[
        FieldSpec { name: "provider_set_root", kind: FieldKind::Hash64, offset: 0 },
        FieldSpec { name: "session_cm", kind: FieldKind::Hash64, offset: 64 },
        FieldSpec { name: "v_claim_cm", kind: FieldKind::Hash64, offset: 128 },
        FieldSpec { name: "provider_nf", kind: FieldKind::Hash64, offset: 192 },
        FieldSpec { name: "cm_payout", kind: FieldKind::Hash64, offset: 256 },
        FieldSpec { name: "receipt_cm", kind: FieldKind::Hash64, offset: 320 },
        FieldSpec { name: "provider_share_sompi", kind: FieldKind::U64Le, offset: 384 },
        FieldSpec { name: "ctx", kind: FieldKind::Hash64, offset: 392 },
    ],
};

/// Every frozen statement schema, in `circuit_version` order.
pub const ALL_STATEMENT_SCHEMAS: &[&StatementSchema] = &[
    &SPEND_STATEMENT_SCHEMA,
    &PROVIDER_CLAIM_STATEMENT_SCHEMA,
    &PROVIDER_CLAIM_V3_STATEMENT_SCHEMA,
    &PROVIDER_CLAIM_V2_STATEMENT_SCHEMA,
];

/// The schema for a `circuit_version`, or `None` if that circuit has no frozen
/// statement (fail-closed — the verifier rejects unknown circuits anyway).
pub fn schema_for_circuit(circuit_version: u16) -> Option<&'static StatementSchema> {
    ALL_STATEMENT_SCHEMAS.iter().copied().find(|s| s.circuit_version == circuit_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::{Commitment, Nullifier};
    use crate::proof::{CIRCUIT_PROVIDER_CLAIM, CIRCUIT_PROVIDER_CLAIM_V2, CIRCUIT_PROVIDER_CLAIM_V3, CIRCUIT_SPEND};
    use crate::provider::{ProviderClaimStatement, ProviderClaimStatementV2, ProviderClaimStatementV3};
    use crate::spend::SpendStatement;
    use kaspa_hashes::Hash64;

    fn h(b: u8) -> Hash64 {
        Hash64::from_bytes([b; 64])
    }

    /// Every schema must be internally consistent: fields contiguous from 0,
    /// widths from the kind, total == size, unique names.
    #[test]
    fn schemas_are_contiguous_and_sized() {
        for s in ALL_STATEMENT_SCHEMAS {
            let mut off = 0usize;
            for f in s.fields {
                assert_eq!(f.offset, off, "{}: field {} offset", s.name, f.name);
                off += f.width();
            }
            assert_eq!(off, s.size, "{}: total size", s.name);
            let names: std::collections::BTreeSet<_> = s.fields.iter().map(|f| f.name).collect();
            assert_eq!(names.len(), s.fields.len(), "{}: duplicate field name", s.name);
        }
        // registry lookups agree
        assert_eq!(schema_for_circuit(CIRCUIT_SPEND).unwrap().size, 404);
        assert_eq!(schema_for_circuit(CIRCUIT_PROVIDER_CLAIM).unwrap().size, 328);
        assert_eq!(schema_for_circuit(CIRCUIT_PROVIDER_CLAIM_V2).unwrap().size, 392);
        // circuit 3 (C-P6 receipt-authorized claim) now has a FROZEN statement layout (456 B) —
        // the inert production surface. The circuit itself stays fail-closed (vk unfrozen).
        assert_eq!(schema_for_circuit(CIRCUIT_PROVIDER_CLAIM_V3).unwrap().size, 456);
        assert_eq!(schema_for_circuit(CIRCUIT_PROVIDER_CLAIM_V3).unwrap().name, "ProviderClaimStatementV3");
        assert_eq!(schema_for_circuit(999), None);
    }

    fn spend_stmt() -> SpendStatement {
        SpendStatement {
            anchor: h(0xA0),
            nf_old: [Nullifier(h(0xA1)), Nullifier(h(0xA2))],
            cm_new: [Commitment(h(0xA3)), Commitment(h(0xA4))],
            v_pub_in: 0x0102_0304_0506_0708,
            v_pub_out: 0x1112_1314_1516_1718,
            token_id: 0x2122_2324,
            ctx: h(0xA5),
        }
    }

    fn claim_v1_stmt() -> ProviderClaimStatement {
        ProviderClaimStatement {
            provider_set_root: h(0xB0),
            session_cm: h(0xB1),
            amount: 0x0102_0304_0506_0708,
            provider_nf: Nullifier(h(0xB2)),
            cm_payout: Commitment(h(0xB3)),
            ctx: h(0xB4),
        }
    }

    fn claim_v2_stmt() -> ProviderClaimStatementV2 {
        ProviderClaimStatementV2 {
            provider_set_root: h(0xC0),
            session_cm: h(0xC1),
            v_claim_cm: h(0xC2),
            provider_nf: Nullifier(h(0xC3)),
            cm_payout: Commitment(h(0xC4)),
            provider_share_sompi: 0x0102_0304_0506_0708,
            ctx: h(0xC5),
        }
    }

    fn claim_v3_stmt() -> ProviderClaimStatementV3 {
        ProviderClaimStatementV3 {
            provider_set_root: h(0xD0),
            session_cm: h(0xD1),
            v_claim_cm: h(0xD2),
            provider_nf: Nullifier(h(0xD3)),
            cm_payout: Commitment(h(0xD4)),
            receipt_cm: h(0xD5),
            provider_share_sompi: 0x0102_0304_0506_0708,
            ctx: h(0xD6),
        }
    }

    /// (audit C-01, the `evm_ctx.rs` differential pattern applied to the STATEMENT)
    /// Independently reconstruct the exact packed bytes the Solidity builder
    /// `_borshClaimStatementV2` produces —
    /// `abi.encodePacked(setRoot, sessionCm, vClaimCm, providerNf, cmPayout) ‖
    ///  _le64(providerShareSompi) ‖ ctx` — and assert the Rust borsh encoding is
    /// byte-identical, field by field, at the schema offsets.
    #[test]
    fn claim_v2_borsh_matches_solidity_packed_layout() {
        let s = claim_v2_stmt();
        let enc = borsh::to_vec(&s).unwrap();
        let schema = &PROVIDER_CLAIM_V2_STATEMENT_SCHEMA;
        assert_eq!(enc.len(), schema.size, "borsh(ProviderClaimStatementV2) must be exactly {} bytes", schema.size);

        // the Solidity abi.encodePacked assembly, rebuilt independently
        let mut golden = Vec::with_capacity(schema.size);
        golden.extend_from_slice(s.provider_set_root.as_byte_slice()); // setRoot (64)
        golden.extend_from_slice(s.session_cm.as_byte_slice()); // sessionCm (64)
        golden.extend_from_slice(s.v_claim_cm.as_byte_slice()); // vClaimCm (64)
        golden.extend_from_slice(s.provider_nf.0.as_byte_slice()); // providerNf (64)
        golden.extend_from_slice(s.cm_payout.0.as_byte_slice()); // cmPayout (64)
        golden.extend_from_slice(&s.provider_share_sompi.to_le_bytes()); // _le64(share)
        golden.extend_from_slice(s.ctx.as_byte_slice()); // ctx (64)
        assert_eq!(enc, golden, "borsh(v2 statement) must equal the Solidity _borshClaimStatementV2 packed bytes");

        // field-by-field: each schema range slices out exactly that field's bytes
        let f = |name: &str| schema.field(name).unwrap().range();
        assert_eq!(&enc[f("provider_set_root")], s.provider_set_root.as_byte_slice());
        assert_eq!(&enc[f("session_cm")], s.session_cm.as_byte_slice());
        assert_eq!(&enc[f("v_claim_cm")], s.v_claim_cm.as_byte_slice());
        assert_eq!(&enc[f("provider_nf")], s.provider_nf.0.as_byte_slice());
        assert_eq!(&enc[f("cm_payout")], s.cm_payout.0.as_byte_slice());
        assert_eq!(&enc[f("provider_share_sompi")], &s.provider_share_sompi.to_le_bytes());
        assert_eq!(&enc[f("ctx")], s.ctx.as_byte_slice());
    }

    /// (C-P6 / ADR-0037 §2.4) The frozen circuit-3 statement layout: independently reconstruct
    /// the exact packed bytes the Solidity builder `_borshClaimStatementV3` produces —
    /// `abi.encodePacked(setRoot, sessionCm, vClaimCm, providerNf, cmPayout, receiptCm) ‖
    ///  _le64(providerShareSompi) ‖ ctx` — and assert the Rust borsh encoding is byte-identical,
    /// field by field, at the schema offsets. The `receipt_cm` insertion shifts `provider_share_sompi`
    /// to [384,392) and `ctx` to [392,456); everything else keeps its v2 range. INERT surface — the
    /// pin exists so the on-chain builder and node decoder cannot drift before C-P6 activates.
    #[test]
    fn claim_v3_borsh_matches_solidity_packed_layout() {
        let s = claim_v3_stmt();
        let enc = borsh::to_vec(&s).unwrap();
        let schema = &PROVIDER_CLAIM_V3_STATEMENT_SCHEMA;
        assert_eq!(enc.len(), schema.size, "borsh(ProviderClaimStatementV3) must be exactly {} bytes", schema.size);

        let mut golden = Vec::with_capacity(schema.size);
        golden.extend_from_slice(s.provider_set_root.as_byte_slice()); // setRoot (64)
        golden.extend_from_slice(s.session_cm.as_byte_slice()); // sessionCm (64)
        golden.extend_from_slice(s.v_claim_cm.as_byte_slice()); // vClaimCm (64)
        golden.extend_from_slice(s.provider_nf.0.as_byte_slice()); // providerNf (64)
        golden.extend_from_slice(s.cm_payout.0.as_byte_slice()); // cmPayout (64)
        golden.extend_from_slice(s.receipt_cm.as_byte_slice()); // receiptCm (64) — the C-P6 addition
        golden.extend_from_slice(&s.provider_share_sompi.to_le_bytes()); // _le64(share)
        golden.extend_from_slice(s.ctx.as_byte_slice()); // ctx (64)
        assert_eq!(enc, golden, "borsh(v3 statement) must equal the Solidity _borshClaimStatementV3 packed bytes");

        // field-by-field: each schema range slices out exactly that field's bytes.
        let f = |name: &str| schema.field(name).unwrap().range();
        assert_eq!(&enc[f("provider_set_root")], s.provider_set_root.as_byte_slice());
        assert_eq!(&enc[f("session_cm")], s.session_cm.as_byte_slice());
        assert_eq!(&enc[f("v_claim_cm")], s.v_claim_cm.as_byte_slice());
        assert_eq!(&enc[f("provider_nf")], s.provider_nf.0.as_byte_slice());
        assert_eq!(&enc[f("cm_payout")], s.cm_payout.0.as_byte_slice());
        assert_eq!(&enc[f("receipt_cm")], s.receipt_cm.as_byte_slice());
        assert_eq!(&enc[f("provider_share_sompi")], &s.provider_share_sompi.to_le_bytes());
        assert_eq!(&enc[f("ctx")], s.ctx.as_byte_slice());
        // the receipt_cm insertion pushed share + ctx by exactly 64 bytes vs v2 (392 → 456 total).
        assert_eq!(schema.field("provider_share_sompi").unwrap().offset, 384);
        assert_eq!(schema.field("ctx").unwrap().offset, 392);
        assert_eq!(schema.field("receipt_cm").unwrap().offset, 256 + 64);

        // strict borsh: truncation and trailing append are rejected.
        use borsh::BorshDeserialize;
        assert!(ProviderClaimStatementV3::try_from_slice(&enc[..enc.len() - 1]).is_err(), "truncated statement must not decode");
        let mut appended = enc.clone();
        appended.push(0x00);
        assert!(ProviderClaimStatementV3::try_from_slice(&appended).is_err(), "trailing bytes must not decode");
        // and it round-trips.
        assert_eq!(ProviderClaimStatementV3::try_from_slice(&enc).unwrap(), s);
    }

    /// Same pin for the v1 claim statement (`_borshClaimStatement`).
    #[test]
    fn claim_v1_borsh_matches_solidity_packed_layout() {
        let s = claim_v1_stmt();
        let enc = borsh::to_vec(&s).unwrap();
        let schema = &PROVIDER_CLAIM_STATEMENT_SCHEMA;
        assert_eq!(enc.len(), schema.size);
        let mut golden = Vec::with_capacity(schema.size);
        golden.extend_from_slice(s.provider_set_root.as_byte_slice());
        golden.extend_from_slice(s.session_cm.as_byte_slice());
        golden.extend_from_slice(&s.amount.to_le_bytes());
        golden.extend_from_slice(s.provider_nf.0.as_byte_slice());
        golden.extend_from_slice(s.cm_payout.0.as_byte_slice());
        golden.extend_from_slice(s.ctx.as_byte_slice());
        assert_eq!(enc, golden, "borsh(v1 statement) must equal the Solidity _borshClaimStatement packed bytes");
    }

    /// And the spend statement (`ShieldedPool._borshStatement` layout).
    #[test]
    fn spend_borsh_matches_schema_layout() {
        let s = spend_stmt();
        let enc = borsh::to_vec(&s).unwrap();
        let schema = &SPEND_STATEMENT_SCHEMA;
        assert_eq!(enc.len(), schema.size);
        let mut golden = Vec::with_capacity(schema.size);
        golden.extend_from_slice(s.anchor.as_byte_slice());
        golden.extend_from_slice(s.nf_old[0].0.as_byte_slice());
        golden.extend_from_slice(s.nf_old[1].0.as_byte_slice());
        golden.extend_from_slice(s.cm_new[0].0.as_byte_slice());
        golden.extend_from_slice(s.cm_new[1].0.as_byte_slice());
        golden.extend_from_slice(&s.v_pub_in.to_le_bytes());
        golden.extend_from_slice(&s.v_pub_out.to_le_bytes());
        golden.extend_from_slice(&s.token_id.to_le_bytes());
        golden.extend_from_slice(s.ctx.as_byte_slice());
        assert_eq!(enc, golden);
    }

    /// MUTATION acceptance (audit C-01): payout ±1 must move EXACTLY the schema's
    /// `provider_share_sompi` bytes; truncation/append must fail borsh decode;
    /// zero / max / flipped share values all round-trip to DIFFERENT statements
    /// (so the relation / node binding rejects them — asserted in their layers).
    #[test]
    fn claim_v2_share_mutations_are_localized_and_decode_strict() {
        use borsh::BorshDeserialize;
        let base = claim_v2_stmt();
        let enc = borsh::to_vec(&base).unwrap();
        let range = PROVIDER_CLAIM_V2_STATEMENT_SCHEMA.field("provider_share_sompi").unwrap().range();

        for mutated_share in
            [base.provider_share_sompi + 1, base.provider_share_sompi - 1, 0u64, u64::MAX, base.provider_share_sompi ^ (1 << 63)]
        {
            let m = ProviderClaimStatementV2 { provider_share_sompi: mutated_share, ..base.clone() };
            let menc = borsh::to_vec(&m).unwrap();
            assert_eq!(menc.len(), enc.len());
            // every differing byte lies inside the share field's schema range
            let diff: Vec<usize> = (0..enc.len()).filter(|&i| enc[i] != menc[i]).collect();
            assert!(!diff.is_empty(), "share mutation must change the encoding");
            assert!(diff.iter().all(|i| range.contains(i)), "share mutation must be localized to {range:?}, got {diff:?}");
            // and the mutated bytes decode back to the mutated share (no aliasing)
            let dec = ProviderClaimStatementV2::try_from_slice(&menc).unwrap();
            assert_eq!(dec.provider_share_sompi, mutated_share);
            assert_ne!(dec, base);
        }

        // truncation and trailing append are rejected by strict borsh decode
        assert!(ProviderClaimStatementV2::try_from_slice(&enc[..enc.len() - 1]).is_err(), "truncated statement must not decode");
        let mut appended = enc.clone();
        appended.push(0x00);
        assert!(ProviderClaimStatementV2::try_from_slice(&appended).is_err(), "trailing bytes must not decode");
        assert!(ProviderClaimStatementV2::try_from_slice(&[]).is_err());

        // FIELD-ORDER SWAP: exchanging two same-width fields (session_cm ↔ v_claim_cm)
        // produces a DIFFERENT statement (decode succeeds — same widths — but no field
        // aliases another; the relation/AIR then rejects it because the nullifier,
        // value-commitment and ctx constraints are all field-position-specific).
        let swapped = ProviderClaimStatementV2 { session_cm: base.v_claim_cm, v_claim_cm: base.session_cm, ..base.clone() };
        let senc = borsh::to_vec(&swapped).unwrap();
        assert_ne!(senc, enc, "field-order swap must change the bytes");
        let sdec = ProviderClaimStatementV2::try_from_slice(&senc).unwrap();
        assert_ne!(sdec, base);
    }
}
