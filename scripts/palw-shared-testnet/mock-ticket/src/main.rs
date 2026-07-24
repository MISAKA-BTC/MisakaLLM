//! mock-ticket — WIRING-ONLY (non-inference) ticket helper for the Phase-0 closed
//! two-node PALW testnet harness (`scripts/palw-shared-testnet/`).
//!
//! It produces the ticket cryptography that a real provider inference tool would emit
//! for a leaf, so a MOCK leaf can be minted end-to-end on a no-GPU box. It delegates
//! ENTIRELY to the real consensus/validator functions, so its output is byte-identical
//! to what consensus verifies and the miner loads:
//!   * `ticket_nullifier_commitment` — the exact
//!     `kaspa_consensus_core::palw::ticket_nullifier_commitment` (keyed BLAKE2b-512 over
//!     the raw nullifier under domain "misaka-palw-ticket-nf-commit-v1").
//!   * `ticket_authority_pk_hash` — `blake2b_512_keyed(PALW_AUTHORIZATION_DOMAIN, vk)`,
//!     which is the exact consensus clause-7 check (consensus/core/src/palw.rs) and the
//!     miner's `TicketAuthority::pk_hash` (kaspad/src/palw_mine_service.rs).
//!   * the raw nullifier is recorded into the miner's authority-bound `TicketSecretStore`
//!     via its own `record_and_flush`, so the on-disk key layout matches what the miner
//!     reads with `secret_for(batch_id, leaf_index)`.
//!
//! HONESTY: this NEVER runs real inference, NEVER fabricates a leaf beyond its ticket
//! fields, and NEVER touches the seeded test-only `palw_demo` path. The raw nullifier
//! is a SECRET: it is read from a file and written only into the 0600 store — never logged.
//!
//! Subcommands (the contract `create-lifecycle.sh` drives):
//!   mock-ticket commit    --authority-key <seed> --nullifier-file <128hex> [--network <net>]
//!       -> stdout: `ticket_nullifier_commitment: <128hex>`
//!                  `ticket_authority_pk_hash:    <128hex>`
//!   mock-ticket store-add --authority-key <seed> --secret-file <store.json>
//!                         --batch-id <128hex> --leaf-index <u32> --nullifier-file <128hex>
//!                         [--network <net>]
//!       -> upserts (batch_id, leaf_index) -> nullifier into the authority-bound store.
//!
//! `--network` is accepted for CLI symmetry but does not affect any output: the ticket
//! domains are network-independent constants.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;

use kaspa_consensus_core::palw::{PALW_AUTHORIZATION_DOMAIN, ticket_nullifier_commitment};
use kaspa_hashes::{Hash64, blake2b_512_keyed};
use kaspa_pq_validator_core::{TicketSecretStore, ValidatorKey, load_validator_seed};

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("mock-ticket: error: {}", msg.as_ref());
    exit(1);
}

/// Parse `--flag value` pairs (after the subcommand). Fail-closed on anything else.
fn parse_flags(args: &[String]) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.strip_prefix("--") {
            Some(name) => {
                let val = args.get(i + 1).cloned().unwrap_or_else(|| die(format!("flag --{name} needs a value")));
                m.insert(name.to_string(), val);
                i += 2;
            }
            None => die(format!("unexpected argument '{a}' (flags must look like --name value)")),
        }
    }
    m
}

fn require<'a>(m: &'a HashMap<String, String>, k: &str) -> &'a str {
    m.get(k).map(String::as_str).unwrap_or_else(|| die(format!("missing required --{k}")))
}

/// Load the ticket authority the SAME way the miner does
/// (kaspad/src/palw_mine_service.rs::load_ticket_authority): `load_validator_seed` ->
/// `ValidatorKey::from_seed`, then keyed-BLAKE2b over the ML-DSA-87 verification key
/// under `PALW_AUTHORIZATION_DOMAIN` — the exact value the leaf's
/// `ticket_authority_pk_hash` must carry for clause 7 to accept the minted block.
fn authority_pk_hash(seed_path: &str) -> Hash64 {
    let seed = load_validator_seed(seed_path).unwrap_or_else(|e| die(format!("cannot load authority seed '{seed_path}': {e}")));
    let key = ValidatorKey::from_seed(seed);
    blake2b_512_keyed(PALW_AUTHORIZATION_DOMAIN, key.public_key())
}

/// Read a trimmed 128-hex nullifier (64 bytes) from a file into a `Hash64`.
fn read_nullifier(path: &str) -> Hash64 {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| die(format!("cannot read --nullifier-file '{path}': {e}")));
    Hash64::from_str(raw.trim()).unwrap_or_else(|e| die(format!("--nullifier-file '{path}' is not a 128-hex Hash64: {e:?}")))
}

fn cmd_commit(args: &[String]) {
    let f = parse_flags(args);
    let pk_hash = authority_pk_hash(require(&f, "authority-key"));
    let nullifier = read_nullifier(require(&f, "nullifier-file"));
    let commitment = ticket_nullifier_commitment(&nullifier);
    // Exactly the two labels create-lifecycle.sh's _kv parser expects. The raw
    // nullifier itself is never printed.
    println!("ticket_nullifier_commitment: {commitment}");
    println!("ticket_authority_pk_hash:    {pk_hash}");
}

fn cmd_store_add(args: &[String]) {
    let f = parse_flags(args);
    let pk_hash = authority_pk_hash(require(&f, "authority-key"));
    let secret_file = PathBuf::from(require(&f, "secret-file"));
    let batch_id =
        Hash64::from_str(require(&f, "batch-id")).unwrap_or_else(|e| die(format!("--batch-id is not a 128-hex Hash64: {e:?}")));
    let leaf_index: u32 = require(&f, "leaf-index").parse().unwrap_or_else(|e| die(format!("--leaf-index is not a u32: {e}")));
    let nullifier = read_nullifier(require(&f, "nullifier-file"));
    // load_or_empty refuses a store belonging to a DIFFERENT authority; record_and_flush
    // refuses to overwrite an existing entry with a different value (a registered leaf's
    // nullifier is immutable). Both are consensus-safety properties we deliberately keep.
    let mut store = TicketSecretStore::load_or_empty(secret_file, pk_hash).unwrap_or_else(|e| die(e));
    store.record_and_flush(batch_id, leaf_index, nullifier).unwrap_or_else(|e| die(e));
    // Public identifiers only; never the nullifier value.
    eprintln!("mock-ticket: recorded (batch_id, leaf_index={leaf_index}) into the authority-bound ticket-secret store.");
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let sub = argv.get(1).map(String::as_str).unwrap_or("");
    let rest: &[String] = if argv.len() > 2 { &argv[2..] } else { &[] };
    match sub {
        "commit" => cmd_commit(rest),
        "store-add" => cmd_store_add(rest),
        _ => {
            eprintln!(
                "mock-ticket (WIRING-ONLY, non-inference) — Phase-0 PALW harness helper\n\
                 usage:\n  \
                 mock-ticket commit    --authority-key <seed> --nullifier-file <128hex> [--network <net>]\n  \
                 mock-ticket store-add --authority-key <seed> --secret-file <store.json> \
                 --batch-id <128hex> --leaf-index <u32> --nullifier-file <128hex> [--network <net>]"
            );
            exit(2);
        }
    }
}
