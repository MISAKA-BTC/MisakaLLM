//! Service configuration (ADR-0038 D1, D2). The single knob that must never be
//! misconfigurable is the network family: the binary can only construct the
//! **testnet** address prefix, so there is no mainnet registration mode to fall
//! into. Everything else (role, paths, listen address) is ordinary deployment
//! config.

use kaspa_addresses::Prefix;
use misaka_mtp::Stage;
use std::path::PathBuf;

/// The role a service instance plays (ADR-0038 D2). A deployment runs one `Full`
/// node (cron + query-http + chain/github/forms collectors) and two `Vantage`
/// crawlers (DE, JP) that only feed uptime/node facts back to the full node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Cron + query-http + chain-indexer + github-sync + campaign-forms (the `.119` node).
    Full,
    /// A p2p-crawler vantage only (the DE / JP seeder hosts).
    Vantage,
}

/// The testnet networks in ADR-0027 D1 scope, each with its ADR-0026 BPS stage
/// coefficient. testnet-10 (live today) and testnet-25 both score at the Stage-A
/// floor (×1.0); the coefficient only lifts as BPS stress rises at 40/50.
pub const NETWORKS: &[(&str, Stage)] =
    &[("testnet-10", Stage::A), ("testnet-25", Stage::A), ("testnet-40", Stage::B), ("testnet-50", Stage::C)];

/// The BPS stage for a scoped testnet network name, or `None` if out of scope
/// (e.g. a mainnet name — which by D1 can never reach the scorer anyway).
pub fn stage_for(network: &str) -> Option<Stage> {
    NETWORKS.iter().find(|(n, _)| *n == network).map(|(_, s)| *s)
}

/// Whole-service configuration. Constructed from CLI/env at [`crate::main`];
/// [`Self::prefix`] is hard-wired to testnet (D1).
#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub role: Role,
    /// Network name this instance scores for (must be in [`NETWORKS`]).
    pub network: String,
    /// Root data directory: SQLite-equivalent fact store + published ledger archive.
    pub data_dir: PathBuf,
    /// Path to the dedicated MTP operator seed (D7); `Full` role only.
    pub operator_key_path: Option<String>,
    /// `query-http` listen address; `Full` role only.
    pub http_listen: Option<String>,
    /// In-repo maintainer allowlist for the label-actor gate (I-MTP-5).
    pub maintainer_allowlist: Vec<String>,
}

impl ServiceConfig {
    /// The one and only address prefix this service accepts — testnet, always.
    /// Not derived from `self`; a compile-time constant so no config path can
    /// turn on a mainnet registration mode (D1).
    pub const fn prefix(&self) -> Prefix {
        Prefix::Testnet
    }

    /// The BPS stage coefficient for [`Self::network`].
    pub fn stage(&self) -> Option<Stage> {
        stage_for(&self.network)
    }

    /// Directory holding the published, signed epoch ledger JSONL files + index.
    pub fn ledger_dir(&self) -> PathBuf {
        self.data_dir.join("points")
    }

    /// Directory holding the persistent (timed) fact store.
    pub fn store_dir(&self) -> PathBuf {
        self.data_dir.join("facts")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_always_testnet() {
        let cfg = ServiceConfig {
            role: Role::Full,
            network: "testnet-10".into(),
            data_dir: "/tmp/mtp".into(),
            operator_key_path: None,
            http_listen: None,
            maintainer_allowlist: vec![],
        };
        assert_eq!(cfg.prefix(), Prefix::Testnet, "D1: no mainnet mode exists");
    }

    #[test]
    fn stage_mapping_matches_adr_0026() {
        assert_eq!(stage_for("testnet-10"), Some(Stage::A));
        assert_eq!(stage_for("testnet-25"), Some(Stage::A));
        assert_eq!(stage_for("testnet-40"), Some(Stage::B));
        assert_eq!(stage_for("testnet-50"), Some(Stage::C));
        assert_eq!(stage_for("mainnet"), None, "out-of-scope names never score");
    }
}
