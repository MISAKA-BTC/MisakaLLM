//! Provider observability: a durable receipt store + stats + CSV export
//! (design §16.5).
//!
//! Each served session appends one compact [`SessionRecord`] (billing fields +
//! the receipt hash) to an append-only JSONL file. The `stats` and
//! `export-receipts` CLI commands read it back for the operator dashboard and
//! accounting export — no dependency on the on-chain anchor. The full 7 KiB
//! receipt is not persisted here (it travels on-chain / off-chain); the record
//! keeps the settlement summary an operator needs.

use crate::service::SessionOutcome;
use misaka_mil_core::params::job_cost_sompi;
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// One settled session, as persisted (JSON-per-line).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    /// 128-char hex session id.
    pub session_id: String,
    /// Cumulative input tokens.
    pub tokens_in: u64,
    /// Cumulative output tokens.
    pub tokens_out: u64,
    /// Number of prompt turns.
    pub turns: u32,
    /// Whether the session ended on a cancel.
    pub cancelled: bool,
    /// Gross fee for the session at the provider's ask, sompi (pre-split).
    pub gross_sompi: u64,
    /// 128-char hex of the final receipt hash (settlement evidence).
    pub receipt_hash: String,
    /// Settlement wall-clock, unix milliseconds.
    pub timestamp_ms: u64,
}

impl SessionRecord {
    /// Build a record from a served-session outcome + the provider's ask.
    pub fn from_outcome(outcome: &SessionOutcome, ask_in_per_1k: u64, ask_out_per_1k: u64, timestamp_ms: u64) -> Self {
        Self {
            session_id: outcome.session_id.to_string(),
            tokens_in: outcome.tokens_in,
            tokens_out: outcome.tokens_out,
            turns: outcome.turns,
            cancelled: outcome.cancelled,
            gross_sompi: job_cost_sompi(ask_in_per_1k, ask_out_per_1k, outcome.tokens_in, outcome.tokens_out),
            receipt_hash: outcome.final_receipt.receipt_hash().to_string(),
            timestamp_ms,
        }
    }
}

/// Append a record to the JSONL store (created if absent).
pub fn append_record(path: &Path, record: &SessionRecord) -> std::io::Result<()> {
    let line = serde_json::to_string(record).expect("record serializes");
    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(f, "{line}")
}

/// Read every record from the store (skips malformed lines).
pub fn read_records(path: &Path) -> std::io::Result<Vec<SessionRecord>> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(r) = serde_json::from_str::<SessionRecord>(&line) {
            out.push(r);
        }
    }
    Ok(out)
}

/// Aggregate operator stats over a set of records (§16.5 dashboard input).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProviderStats {
    pub sessions: u64,
    pub turns: u64,
    pub cancelled: u64,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub gross_sompi: u64,
    /// Provider's 88% share of gross (§5.3), sompi.
    pub provider_sompi: u64,
}

/// Compute aggregate stats.
pub fn aggregate(records: &[SessionRecord]) -> ProviderStats {
    let mut s = ProviderStats::default();
    for r in records {
        s.sessions += 1;
        s.turns += r.turns as u64;
        s.cancelled += r.cancelled as u64;
        s.tokens_in += r.tokens_in;
        s.tokens_out += r.tokens_out;
        s.gross_sompi = s.gross_sompi.saturating_add(r.gross_sompi);
    }
    s.provider_sompi = misaka_mil_core::params::split_fee(s.gross_sompi).provider;
    s
}

/// Render records as CSV (accounting export, §16.5).
pub fn to_csv(records: &[SessionRecord]) -> String {
    let mut out = String::from("session_id,timestamp_ms,turns,cancelled,tokens_in,tokens_out,gross_sompi,receipt_hash\n");
    for r in records {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            r.session_id, r.timestamp_ms, r.turns, r.cancelled, r.tokens_in, r.tokens_out, r.gross_sompi, r.receipt_hash
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: u8, tin: u64, tout: u64, cancelled: bool) -> SessionRecord {
        SessionRecord {
            session_id: kaspa_hashes::Hash64::from_bytes([id; 64]).to_string(),
            tokens_in: tin,
            tokens_out: tout,
            turns: 1,
            cancelled,
            gross_sompi: job_cost_sompi(1_000_000, 1_000_000, tin, tout),
            receipt_hash: kaspa_hashes::Hash64::from_bytes([id ^ 0xFF; 64]).to_string(),
            timestamp_ms: 1_000 + id as u64,
        }
    }

    #[test]
    fn append_read_roundtrip_and_aggregate() {
        let dir = std::env::temp_dir().join(format!("mil-store-{}", std::process::id()));
        let path = dir.join("receipts.jsonl");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(&path);

        append_record(&path, &rec(1, 100, 1000, false)).unwrap();
        append_record(&path, &rec(2, 50, 500, true)).unwrap();
        let records = read_records(&path).unwrap();
        assert_eq!(records.len(), 2);

        let stats = aggregate(&records);
        assert_eq!(stats.sessions, 2);
        assert_eq!(stats.cancelled, 1);
        assert_eq!(stats.tokens_in, 150);
        assert_eq!(stats.tokens_out, 1500);
        assert_eq!(stats.provider_sompi, misaka_mil_core::params::split_fee(stats.gross_sompi).provider);

        let csv = to_csv(&records);
        assert!(csv.starts_with("session_id,timestamp_ms,"));
        assert_eq!(csv.lines().count(), 3); // header + 2 rows

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_store_reads_empty() {
        let path = std::env::temp_dir().join("mil-nonexistent-store.jsonl");
        let _ = std::fs::remove_file(&path);
        assert!(read_records(&path).unwrap().is_empty());
        assert_eq!(aggregate(&[]), ProviderStats::default());
    }
}
