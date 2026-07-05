//! Intel TDX quote v4 structural parser.
//!
//! Layout (Intel "TDX DCAP Quoting Library API" rev 0.9, quote format v4):
//!
//! ```text
//! offset  size  field
//! 0       48    quote header { version u16, att_key_type u16, tee_type u32,
//!                              reserved u32, qe_svn u16 ‖ pce_svn u16 packed
//!                              per spec, qe_vendor_id [16], user_data [20] }
//! 48      584   TD report body (TDREPORT_INFO):
//!   +0    16    tee_tcb_svn
//!   +16   48    mr_seam
//!   +64   48    mr_signer_seam
//!   +112  8     seam_attributes
//!   +120  8     td_attributes
//!   +128  8     xfam
//!   +136  48    mr_td
//!   +184  48    mr_config_id
//!   +232  48    mr_owner
//!   +280  48    mr_owner_config
//!   +328  192   rt_mr0..rt_mr3 (4 × 48)
//!   +520  64    report_data
//! 632     4     signature_data_len (u32 LE)
//! 636     var   signature data (ECDSA-P256 chain — NOT validated in v0, §3.6)
//! ```
//!
//! v0 validates structure and extracts measurement fields; the classical
//! signature section is length-checked only (see the crate-level scope note).

pub const TDX_QUOTE_VERSION: u16 = 4;
/// TEE type tag for TDX quotes (SGX is 0x00000000).
pub const TDX_TEE_TYPE: u32 = 0x0000_0081;
pub const TDX_HEADER_LEN: usize = 48;
pub const TDX_REPORT_LEN: usize = 584;
pub const TDX_MIN_QUOTE_LEN: usize = TDX_HEADER_LEN + TDX_REPORT_LEN + 4;

/// Parsed measurement view of a TDX v4 quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxQuote {
    pub version: u16,
    pub att_key_type: u16,
    pub tee_type: u32,
    pub tee_tcb_svn: [u8; 16],
    pub mr_seam: [u8; 48],
    pub mr_td: [u8; 48],
    pub rt_mr: [[u8; 48]; 4],
    pub report_data: [u8; 64],
    /// Declared length of the (unvalidated) signature section.
    pub signature_len: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TdxParseError {
    #[error("TDX quote is {0} bytes; a v4 quote needs at least {TDX_MIN_QUOTE_LEN}")]
    TooShort(usize),
    #[error("unsupported TDX quote version {0} (expected {TDX_QUOTE_VERSION})")]
    BadVersion(u16),
    #[error("quote tee_type {0:#010x} is not TDX ({TDX_TEE_TYPE:#010x})")]
    NotTdx(u32),
    #[error("signature section declares {declared} bytes but only {available} follow")]
    SignatureLengthMismatch { declared: u32, available: usize },
}

/// Parse and structurally validate a TDX v4 quote.
pub fn parse_tdx_quote(bytes: &[u8]) -> Result<TdxQuote, TdxParseError> {
    if bytes.len() < TDX_MIN_QUOTE_LEN {
        return Err(TdxParseError::TooShort(bytes.len()));
    }
    let version = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
    if version != TDX_QUOTE_VERSION {
        return Err(TdxParseError::BadVersion(version));
    }
    let att_key_type = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
    let tee_type = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if tee_type != TDX_TEE_TYPE {
        return Err(TdxParseError::NotTdx(tee_type));
    }

    let body = &bytes[TDX_HEADER_LEN..TDX_HEADER_LEN + TDX_REPORT_LEN];
    let field48 = |off: usize| -> [u8; 48] { body[off..off + 48].try_into().unwrap() };

    let sig_off = TDX_HEADER_LEN + TDX_REPORT_LEN;
    let signature_len = u32::from_le_bytes(bytes[sig_off..sig_off + 4].try_into().unwrap());
    let available = bytes.len() - sig_off - 4;
    if signature_len as usize > available {
        return Err(TdxParseError::SignatureLengthMismatch { declared: signature_len, available });
    }

    Ok(TdxQuote {
        version,
        att_key_type,
        tee_type,
        tee_tcb_svn: body[0..16].try_into().unwrap(),
        mr_seam: field48(16),
        mr_td: field48(136),
        rt_mr: [field48(328), field48(376), field48(424), field48(472)],
        report_data: body[520..584].try_into().unwrap(),
        signature_len,
    })
}

/// Build a synthetic, structurally valid TDX v4 quote — test/dev fixture
/// generator (also used by provider `--tee dev-tdx` smoke mode).
pub fn synth_tdx_quote(mr_td: [u8; 48], rt_mr0: [u8; 48], report_data: [u8; 64]) -> Vec<u8> {
    let mut q = vec![0u8; TDX_MIN_QUOTE_LEN];
    q[0..2].copy_from_slice(&TDX_QUOTE_VERSION.to_le_bytes());
    q[2..4].copy_from_slice(&2u16.to_le_bytes()); // ECDSA-P256 attestation key type
    q[4..8].copy_from_slice(&TDX_TEE_TYPE.to_le_bytes());
    let body = &mut q[TDX_HEADER_LEN..TDX_HEADER_LEN + TDX_REPORT_LEN];
    body[136..184].copy_from_slice(&mr_td);
    body[328..376].copy_from_slice(&rt_mr0);
    body[520..584].copy_from_slice(&report_data);
    // signature_data_len stays 0 (no signature section in the fixture)
    q
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_synthetic_quote() {
        let mr_td = [0xAAu8; 48];
        let rt0 = [0xBBu8; 48];
        let rd = [0xCCu8; 64];
        let quote = synth_tdx_quote(mr_td, rt0, rd);
        let parsed = parse_tdx_quote(&quote).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.tee_type, TDX_TEE_TYPE);
        assert_eq!(parsed.mr_td, mr_td);
        assert_eq!(parsed.rt_mr[0], rt0);
        assert_eq!(parsed.rt_mr[1], [0u8; 48]);
        assert_eq!(parsed.report_data, rd);
        assert_eq!(parsed.signature_len, 0);
    }

    #[test]
    fn rejects_malformed_quotes() {
        assert_eq!(parse_tdx_quote(&[0u8; 10]).unwrap_err(), TdxParseError::TooShort(10));

        let mut q = synth_tdx_quote([0u8; 48], [0u8; 48], [0u8; 64]);
        q[0] = 3; // version 3
        assert_eq!(parse_tdx_quote(&q).unwrap_err(), TdxParseError::BadVersion(3));

        let mut q = synth_tdx_quote([0u8; 48], [0u8; 48], [0u8; 64]);
        q[4] = 0; // SGX tee_type
        q[5] = 0;
        q[6] = 0;
        q[7] = 0;
        assert_eq!(parse_tdx_quote(&q).unwrap_err(), TdxParseError::NotTdx(0));

        let mut q = synth_tdx_quote([0u8; 48], [0u8; 48], [0u8; 64]);
        let off = TDX_HEADER_LEN + TDX_REPORT_LEN;
        q[off..off + 4].copy_from_slice(&100u32.to_le_bytes()); // declares 100 sig bytes, none follow
        assert!(matches!(parse_tdx_quote(&q).unwrap_err(), TdxParseError::SignatureLengthMismatch { declared: 100, .. }));
    }
}
