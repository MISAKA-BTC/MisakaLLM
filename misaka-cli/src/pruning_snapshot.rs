//! Offline, read-only PALW pruning snapshot verification for operator handoff/recovery drills.

use std::{fs, str::FromStr};

use kaspa_consensus_core::{Hash64, palw_pruned_frontier::PalwPruningPointSnapshotV1};

use crate::{CliError, CliResult, OutputFormat, exit, node::Ctx};

const MAX_PALW_PRUNING_SNAPSHOT_BYTES: usize = 128 << 20;

fn parse_hash(label: &str, value: &str) -> Result<Hash64, CliError> {
    Hash64::from_str(value).map_err(|_| CliError::new(exit::GENERIC, format!("{label} is not a canonical 64-byte hash: {value}")))
}

pub fn verify(ctx: &Ctx, file: &str, expected_pruning_point: Option<&str>, expected_digest: Option<&str>) -> CliResult {
    let metadata = fs::metadata(file).map_err(|err| CliError::generic(format!("cannot stat snapshot '{file}': {err}")))?;
    let encoded_len = usize::try_from(metadata.len())
        .map_err(|_| CliError::generic(format!("snapshot '{file}' length does not fit this platform")))?;
    if encoded_len > MAX_PALW_PRUNING_SNAPSHOT_BYTES {
        return Err(CliError::new(
            exit::UNSAFE_REFUSED,
            format!("snapshot is {encoded_len} bytes; accepted PALW transport cap is {MAX_PALW_PRUNING_SNAPSHOT_BYTES} bytes"),
        ));
    }
    let bytes = fs::read(file).map_err(|err| CliError::generic(format!("cannot read snapshot '{file}': {err}")))?;
    let snapshot: PalwPruningPointSnapshotV1 = borsh::from_slice(&bytes)
        .map_err(|err| CliError::generic(format!("snapshot is not canonical PalwPruningPointSnapshotV1 Borsh: {err}")))?;
    snapshot.validate_canonical().map_err(|err| CliError::new(exit::UNSAFE_REFUSED, format!("snapshot validation failed: {err}")))?;

    if let Some(expected) = expected_pruning_point {
        let expected = parse_hash("--expect-pruning-point", expected)?;
        if snapshot.payload.pruning_point != expected {
            return Err(CliError::new(
                exit::UNSAFE_REFUSED,
                format!("snapshot pruning point {} differs from expected {expected}", snapshot.payload.pruning_point),
            ));
        }
    }
    if let Some(expected) = expected_digest {
        let expected = parse_hash("--expect-digest", expected)?;
        if snapshot.payload_digest != expected {
            return Err(CliError::new(
                exit::UNSAFE_REFUSED,
                format!("snapshot digest {} differs from expected {expected}", snapshot.payload_digest),
            ));
        }
    }

    let payload = &snapshot.payload;
    let paid_nullifiers: usize = payload.paid_work.iter().map(|row| row.job_nullifiers.len()).sum();
    let spam_support_rows = payload.spam_accumulator.as_ref().map_or(0, |spam| spam.support_rows.len());
    let (da_obligations, da_challenges, da_timeout_evidence) = payload
        .da_snapshot
        .as_ref()
        .map_or((0, 0, 0), |da| (da.state.obligations.len(), da.state.challenges.len(), da.state.timeout_evidence.len()));

    match ctx.output {
        OutputFormat::Json => println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "file": file,
                "encodedBytes": encoded_len,
                "version": payload.version,
                "pruningPoint": payload.pruning_point.to_string(),
                "pruningPointDaaScore": payload.pruning_point_daa_score,
                "payloadDigest": snapshot.payload_digest.to_string(),
                "providerBonds": payload.provider_bonds.len(),
                "paidWorkBlocks": payload.paid_work.len(),
                "paidWorkNullifiers": paid_nullifiers,
                "activeNullifiers": payload.frontier.active_nullifiers.len(),
                "spamSupportRows": spam_support_rows,
                "daObligations": da_obligations,
                "daChallenges": da_challenges,
                "daTimeoutEvidence": da_timeout_evidence,
            })
        ),
        OutputFormat::Human => {
            println!("PALW pruning snapshot: VALID");
            println!("file                 {file}");
            println!("encoded bytes        {encoded_len}");
            println!("pruning point        {}", payload.pruning_point);
            println!("pruning point DAA    {}", payload.pruning_point_daa_score);
            println!("payload digest       {}", snapshot.payload_digest);
            println!("provider bonds       {}", payload.provider_bonds.len());
            println!("paid rows/nullifiers {}/{}", payload.paid_work.len(), paid_nullifiers);
            println!("active nullifiers    {}", payload.frontier.active_nullifiers.len());
            println!("spam support rows    {spam_support_rows}");
            println!("DA obligations       {da_obligations}");
            println!("DA challenges        {da_challenges}");
            println!("DA timeout evidence  {da_timeout_evidence}");
        }
    }
    Ok(())
}
