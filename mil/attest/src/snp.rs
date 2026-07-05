//! AMD SEV-SNP attestation-report structural parser.
//!
//! Layout (AMD SEV-SNP ABI spec, `ATTESTATION_REPORT`, 1184 bytes):
//!
//! ```text
//! offset  size  field
//! 0x000   4     version (2 or 3)
//! 0x004   4     guest_svn
//! 0x008   8     policy
//! 0x010   16    family_id
//! 0x020   16    image_id
//! 0x030   4     vmpl
//! 0x034   4     signature_algo
//! 0x038   8     current_tcb
//! 0x040   8     platform_info
//! 0x048   4     flags
//! 0x050   64    report_data          (guest-supplied — the MIL key binding)
//! 0x090   48    measurement          (launch measurement)
//! 0x0C0   32    host_data
//! 0x1A0   64    chip_id              (device identity — Sybil resistance §4.4)
//! 0x2A0   512   signature            (ECDSA P-384 — NOT validated in v0, §3.6)
//! total 0x4A0 = 1184
//! ```

pub const SNP_REPORT_LEN: usize = 1184;
pub const SNP_SUPPORTED_VERSIONS: [u32; 2] = [2, 3];

/// Parsed measurement view of an SNP attestation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub vmpl: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    /// Per-device chip id — the Tier-1 "1 physical GPU host = 1 count"
    /// anchor (§4.4).
    pub chip_id: [u8; 64],
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SnpParseError {
    #[error("SNP attestation report is {0} bytes; expected exactly {SNP_REPORT_LEN}")]
    BadLength(usize),
    #[error("unsupported SNP report version {0} (supported: 2, 3)")]
    BadVersion(u32),
}

/// Parse and structurally validate an SNP attestation report.
pub fn parse_snp_report(bytes: &[u8]) -> Result<SnpReport, SnpParseError> {
    if bytes.len() != SNP_REPORT_LEN {
        return Err(SnpParseError::BadLength(bytes.len()));
    }
    let version = u32::from_le_bytes(bytes[0x000..0x004].try_into().unwrap());
    if !SNP_SUPPORTED_VERSIONS.contains(&version) {
        return Err(SnpParseError::BadVersion(version));
    }
    Ok(SnpReport {
        version,
        guest_svn: u32::from_le_bytes(bytes[0x004..0x008].try_into().unwrap()),
        policy: u64::from_le_bytes(bytes[0x008..0x010].try_into().unwrap()),
        vmpl: u32::from_le_bytes(bytes[0x030..0x034].try_into().unwrap()),
        report_data: bytes[0x050..0x090].try_into().unwrap(),
        measurement: bytes[0x090..0x0C0].try_into().unwrap(),
        chip_id: bytes[0x1A0..0x1E0].try_into().unwrap(),
    })
}

/// Synthetic, structurally valid SNP report — test/dev fixture generator.
pub fn synth_snp_report(measurement: [u8; 48], report_data: [u8; 64], chip_id: [u8; 64]) -> Vec<u8> {
    let mut r = vec![0u8; SNP_REPORT_LEN];
    r[0x000..0x004].copy_from_slice(&2u32.to_le_bytes());
    r[0x050..0x090].copy_from_slice(&report_data);
    r[0x090..0x0C0].copy_from_slice(&measurement);
    r[0x1A0..0x1E0].copy_from_slice(&chip_id);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_synthetic_report() {
        let m = [0x11u8; 48];
        let rd = [0x22u8; 64];
        let chip = [0x33u8; 64];
        let report = synth_snp_report(m, rd, chip);
        let parsed = parse_snp_report(&report).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.measurement, m);
        assert_eq!(parsed.report_data, rd);
        assert_eq!(parsed.chip_id, chip);
    }

    #[test]
    fn rejects_malformed_reports() {
        assert_eq!(parse_snp_report(&[0u8; 100]).unwrap_err(), SnpParseError::BadLength(100));
        let mut r = synth_snp_report([0u8; 48], [0u8; 64], [0u8; 64]);
        r[0] = 9;
        assert_eq!(parse_snp_report(&r).unwrap_err(), SnpParseError::BadVersion(9));
    }
}
