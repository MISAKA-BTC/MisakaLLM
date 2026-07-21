//! Opt-in PALW Object-v2 restart rehydration and peer recovery.
//!
//! This service is started only when the independent algo-4 acceptance lever is enabled. It never
//! invents roots or trusts transport metadata: every root/coordinate comes from one selected-parent
//! consensus snapshot, every chunk proof is verified, and a reconstructed object still passes the
//! complete selected-chain admission verifier before durable storage or serving.

use crate::{
    flow_context::{FlowContext, PROTOCOL_VERSION_PALW_DA},
    v8::palw_da::PalwDaChunkRequester,
};
use async_trait::async_trait;
use kaspa_consensus_core::palw::da::{
    PALW_DA_CHUNK_BYTES, PALW_RECEIPT_DA_OBJECT_VERSION_V2, PalwDaFetchTargetV1, PalwReceiptDaChunkProofV1,
    palw_receipt_da_commitment, verify_palw_receipt_da_chunk,
};
use kaspa_core::{debug, info, task::tick::TickReason, warn};
use kaspa_hashes::Hash64;
use kaspa_p2p_lib::{PeerKey, Router, common::ProtocolError};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::time::Instant;

const PALW_DA_SERVICE_INTERVAL: Duration = Duration::from_secs(15);
const PALW_DA_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const PALW_DA_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const PALW_DA_MAX_BACKOFF: Duration = Duration::from_secs(1);
const PALW_DA_MAX_FETCH_WINDOW: Duration = Duration::from_secs(10);
const PALW_DA_MAX_PEERS: usize = 8;
const PALW_DA_MAX_OBJECTS_PER_CYCLE: usize = 4;
const PALW_DA_GC_EVERY_CYCLES: u64 = 240; // one hour at the 15-second service cadence

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PalwDaServiceTelemetrySnapshot {
    pub rehydrate_successes: u64,
    pub rehydrate_failures: u64,
    pub fetch_successes: u64,
    pub fetch_timeouts: u64,
    pub invalid_responses: u64,
    pub peer_failovers: u64,
    pub gc_successes: u64,
    pub gc_failures: u64,
    pub gc_deleted_objects: u64,
}

#[derive(Debug, Default)]
pub(crate) struct PalwDaServiceTelemetry {
    rehydrate_successes: AtomicU64,
    rehydrate_failures: AtomicU64,
    fetch_successes: AtomicU64,
    fetch_timeouts: AtomicU64,
    invalid_responses: AtomicU64,
    peer_failovers: AtomicU64,
    gc_successes: AtomicU64,
    gc_failures: AtomicU64,
    gc_deleted_objects: AtomicU64,
}

impl PalwDaServiceTelemetry {
    pub(crate) fn snapshot(&self) -> PalwDaServiceTelemetrySnapshot {
        PalwDaServiceTelemetrySnapshot {
            rehydrate_successes: self.rehydrate_successes.load(Ordering::Relaxed),
            rehydrate_failures: self.rehydrate_failures.load(Ordering::Relaxed),
            fetch_successes: self.fetch_successes.load(Ordering::Relaxed),
            fetch_timeouts: self.fetch_timeouts.load(Ordering::Relaxed),
            invalid_responses: self.invalid_responses.load(Ordering::Relaxed),
            peer_failovers: self.peer_failovers.load(Ordering::Relaxed),
            gc_successes: self.gc_successes.load(Ordering::Relaxed),
            gc_failures: self.gc_failures.load(Ordering::Relaxed),
            gc_deleted_objects: self.gc_deleted_objects.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkSourceError {
    Timeout,
    Invalid,
    Unavailable,
}

#[async_trait]
trait PalwDaChunkSource {
    fn peer_count(&self) -> usize;

    async fn request(
        &mut self,
        peer_index: usize,
        object_root: Hash64,
        chunk_index: u16,
        timeout: Duration,
    ) -> Result<PalwReceiptDaChunkProofV1, ChunkSourceError>;
}

struct NetworkRequester {
    router: Arc<Router>,
    requester: PalwDaChunkRequester,
}

#[derive(Default)]
struct NetworkChunkSource {
    peers: Vec<PeerKey>,
    requesters: HashMap<PeerKey, NetworkRequester>,
}

impl NetworkChunkSource {
    fn update(&mut self, routers: Vec<Arc<Router>>) {
        self.peers.clear();
        for router in routers {
            let key = router.key();
            let replace = self.requesters.get(&key).is_none_or(|entry| !Arc::ptr_eq(&entry.router, &router));
            if replace {
                self.requesters.insert(key, NetworkRequester { requester: PalwDaChunkRequester::new(router.clone()), router });
            }
            self.peers.push(key);
        }
        self.requesters.retain(|key, _| self.peers.contains(key));
    }
}

#[async_trait]
impl PalwDaChunkSource for NetworkChunkSource {
    fn peer_count(&self) -> usize {
        self.peers.len()
    }

    async fn request(
        &mut self,
        peer_index: usize,
        object_root: Hash64,
        chunk_index: u16,
        timeout: Duration,
    ) -> Result<PalwReceiptDaChunkProofV1, ChunkSourceError> {
        let key = *self.peers.get(peer_index).ok_or(ChunkSourceError::Unavailable)?;
        let requester = &mut self.requesters.get_mut(&key).ok_or(ChunkSourceError::Unavailable)?.requester;
        let pending = requester.enqueue(object_root, chunk_index).await.map_err(classify_protocol_error)?;
        match requester.receive(timeout).await {
            Ok(proof) => Ok(proof),
            Err(error) => {
                requester.cancel(pending);
                Err(classify_protocol_error(error))
            }
        }
    }
}

fn classify_protocol_error(error: ProtocolError) -> ChunkSourceError {
    match error {
        ProtocolError::Timeout(_) => ChunkSourceError::Timeout,
        ProtocolError::MisbehavingPeer(_) | ProtocolError::UnexpectedMessage(_, _) => ChunkSourceError::Invalid,
        _ => ChunkSourceError::Unavailable,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
enum FetchError {
    #[error("PALW DA fetch deadline expired")]
    Timeout,
    #[error("PALW DA peer returned invalid Object-v2 chunk metadata or proof")]
    InvalidResponse,
    #[error("PALW DA reconstructed bytes do not match the selected-chain commitment")]
    CommitmentMismatch,
}

async fn fetch_chunk<S: PalwDaChunkSource + Send>(
    source: &mut S,
    target: &PalwDaFetchTargetV1,
    chunk_index: u16,
    deadline: Instant,
    telemetry: &PalwDaServiceTelemetry,
) -> Result<PalwReceiptDaChunkProofV1, FetchError> {
    let mut backoff = PALW_DA_INITIAL_BACKOFF;
    let mut first_peer = chunk_index as usize;
    let mut saw_invalid = false;
    loop {
        let peer_count = source.peer_count();
        if peer_count > 0 {
            for offset in 0..peer_count {
                let now = Instant::now();
                if now >= deadline {
                    return Err(if saw_invalid { FetchError::InvalidResponse } else { FetchError::Timeout });
                }
                let peer_index = (first_peer + offset) % peer_count;
                let timeout = PALW_DA_REQUEST_TIMEOUT.min(deadline.saturating_duration_since(now));
                match source.request(peer_index, target.object_root, chunk_index, timeout).await {
                    Ok(proof)
                        if proof.object_version == PALW_RECEIPT_DA_OBJECT_VERSION_V2
                            && proof.object_len == target.object_len
                            && proof.chunk_count == target.chunk_count
                            && proof.chunk_index == chunk_index
                            && verify_palw_receipt_da_chunk(&target.object_root, &proof).is_ok() =>
                    {
                        return Ok(proof);
                    }
                    Ok(_) | Err(ChunkSourceError::Invalid) => {
                        saw_invalid = true;
                        telemetry.invalid_responses.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(ChunkSourceError::Timeout | ChunkSourceError::Unavailable) => {}
                }
                if offset + 1 < peer_count {
                    telemetry.peer_failovers.fetch_add(1, Ordering::Relaxed);
                }
            }
            first_peer = first_peer.wrapping_add(1);
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(if saw_invalid { FetchError::InvalidResponse } else { FetchError::Timeout });
        }
        tokio::time::sleep(backoff.min(deadline.saturating_duration_since(now))).await;
        backoff = (backoff * 2).min(PALW_DA_MAX_BACKOFF);
    }
}

async fn fetch_object<S: PalwDaChunkSource + Send>(
    source: &mut S,
    target: &PalwDaFetchTargetV1,
    deadline: Instant,
    telemetry: &PalwDaServiceTelemetry,
) -> Result<Arc<Vec<u8>>, FetchError> {
    let mut chunks = vec![None; target.chunk_count as usize];
    // An open challenge's sampled chunk is requested first. The full object is still required before
    // local admission/publication, so a valid sample alone never reaches durable storage.
    let order = std::iter::once(target.required_chunk_index)
        .chain((0..target.chunk_count).filter(|index| *index != target.required_chunk_index));
    for chunk_index in order {
        let proof = fetch_chunk(source, target, chunk_index, deadline, telemetry).await?;
        chunks[chunk_index as usize] = Some(proof.chunk);
    }

    let mut bytes = Vec::with_capacity(target.object_len as usize);
    for chunk in chunks {
        bytes.extend_from_slice(chunk.as_deref().ok_or(FetchError::CommitmentMismatch)?);
    }
    if bytes.len() != target.object_len as usize || bytes.chunks(PALW_DA_CHUNK_BYTES).count() != target.chunk_count as usize {
        return Err(FetchError::CommitmentMismatch);
    }
    let commitment =
        palw_receipt_da_commitment(PALW_RECEIPT_DA_OBJECT_VERSION_V2, &bytes).map_err(|_| FetchError::CommitmentMismatch)?;
    if commitment.root != target.object_root
        || commitment.object_len != target.object_len
        || commitment.chunk_count != target.chunk_count
    {
        return Err(FetchError::CommitmentMismatch);
    }
    Ok(Arc::new(bytes))
}

fn fetch_window(current_daa_score: u64, deadline_daa_score: u64, bps: usize) -> Duration {
    if deadline_daa_score <= current_daa_score {
        return Duration::ZERO;
    }
    let remaining_daa = deadline_daa_score - current_daa_score;
    Duration::from_millis(remaining_daa.saturating_mul(1_000).div_ceil(bps.max(1) as u64)).min(PALW_DA_MAX_FETCH_WINDOW)
}

impl FlowContext {
    pub(crate) async fn run_palw_da_service(self) {
        let mut network = NetworkChunkSource::default();
        let mut cycle = 0u64;
        loop {
            self.palw_da_service_cycle(&mut network).await;
            if cycle.is_multiple_of(PALW_DA_GC_EVERY_CYCLES) {
                let consensus = self.consensus().unguarded_session();
                match consensus.async_palw_da_gc_objects().await {
                    Ok(stats) => {
                        self.palw_da_service_telemetry.gc_successes.fetch_add(1, Ordering::Relaxed);
                        self.palw_da_service_telemetry.gc_deleted_objects.fetch_add(stats.deleted_objects as u64, Ordering::Relaxed);
                        if stats.deleted_objects > 0 {
                            info!(
                                "PALW DA object GC deleted {} stale object(s), retained {} root(s)",
                                stats.deleted_objects, stats.retained_roots
                            );
                        }
                    }
                    Err(error) => {
                        self.palw_da_service_telemetry.gc_failures.fetch_add(1, Ordering::Relaxed);
                        warn!("PALW DA object GC deleted zero objects: {error}");
                    }
                }
            }
            cycle = cycle.wrapping_add(1);
            if let TickReason::Shutdown = self.tick_service.tick(PALW_DA_SERVICE_INTERVAL).await {
                debug!("PALW DA service stopped");
                return;
            }
        }
    }

    async fn palw_da_service_cycle(&self, network: &mut NetworkChunkSource) {
        let consensus = self.consensus().unguarded_session();
        let snapshot = match consensus.async_palw_da_service_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                // Fail closed on snapshot/corruption errors: retaining a prior side-fork root would
                // make restart/reorg refresh look successful while serving the wrong availability set.
                self.clear_palw_da_serving_objects().await;
                self.palw_da_service_telemetry.rehydrate_failures.fetch_add(1, Ordering::Relaxed);
                warn!("PALW DA selected-chain rehydration failed; serving cache cleared: {error}");
                return;
            }
        };

        let serving = snapshot.serving_objects.into_iter().map(|object| (object.object_root, object.bytes)).collect();
        let replace_result = self.replace_palw_da_serving_objects(serving).await;
        if let Err(error) = replace_result {
            self.clear_palw_da_serving_objects().await;
            self.palw_da_service_telemetry.rehydrate_failures.fetch_add(1, Ordering::Relaxed);
            warn!("PALW DA durable rehydration produced invalid bytes; serving cache cleared: {error}");
            return;
        }
        self.palw_da_service_telemetry.rehydrate_successes.fetch_add(1, Ordering::Relaxed);

        network.update(self.hub().sample_routers_with_min_version(PROTOCOL_VERSION_PALW_DA, PALW_DA_MAX_PEERS));
        for target in snapshot.fetch_targets.into_iter().take(PALW_DA_MAX_OBJECTS_PER_CYCLE) {
            let window = fetch_window(snapshot.current_daa_score, target.deadline_daa_score, self.config.bps() as usize);
            if window.is_zero() {
                self.palw_da_service_telemetry.fetch_timeouts.fetch_add(1, Ordering::Relaxed);
                warn!("PALW DA obligation {} expired before recovery", target.obligation_id);
                continue;
            }
            let deadline = Instant::now() + window;
            match fetch_object(network, &target, deadline, &self.palw_da_service_telemetry).await {
                Ok(bytes) => match self.cache_palw_da_object(&consensus, target.batch_id, target.leaf_index, bytes).await {
                    Ok(root) => {
                        self.palw_da_service_telemetry.fetch_successes.fetch_add(1, Ordering::Relaxed);
                        info!("PALW DA recovered, admitted, and published Object-v2 {root}");
                    }
                    Err(error) => {
                        // A reorg during download is expected to land here: admission re-resolves the
                        // coordinate at the new sink and stale bytes never persist or become served.
                        warn!("PALW DA recovered bytes rejected by selected-chain admission: {error}");
                    }
                },
                Err(error) => {
                    self.palw_da_service_telemetry.fetch_timeouts.fetch_add(1, Ordering::Relaxed);
                    warn!("PALW DA recovery timed out for obligation {}: {error}", target.obligation_id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::palw::da::{palw_receipt_da_chunk_proof, palw_receipt_da_commitment};
    use std::collections::BTreeMap;

    struct FakeSource {
        peers: usize,
        proofs: BTreeMap<u16, PalwReceiptDaChunkProofV1>,
        withhold_peer: usize,
        requests: Vec<(usize, u16)>,
        corrupt: bool,
    }

    #[async_trait]
    impl PalwDaChunkSource for FakeSource {
        fn peer_count(&self) -> usize {
            self.peers
        }

        async fn request(
            &mut self,
            peer_index: usize,
            _object_root: Hash64,
            chunk_index: u16,
            _timeout: Duration,
        ) -> Result<PalwReceiptDaChunkProofV1, ChunkSourceError> {
            self.requests.push((peer_index, chunk_index));
            if peer_index == self.withhold_peer {
                return Err(ChunkSourceError::Timeout);
            }
            let mut proof = self.proofs[&chunk_index].clone();
            if self.corrupt {
                proof.chunk[0] ^= 1;
            }
            Ok(proof)
        }
    }

    fn target(bytes: &[u8], required_chunk_index: u16) -> (PalwDaFetchTargetV1, BTreeMap<u16, PalwReceiptDaChunkProofV1>) {
        let commitment = palw_receipt_da_commitment(PALW_RECEIPT_DA_OBJECT_VERSION_V2, bytes).unwrap();
        let target = PalwDaFetchTargetV1 {
            obligation_id: Hash64::from_bytes([1; 64]),
            batch_id: Hash64::from_bytes([2; 64]),
            leaf_index: 3,
            object_root: commitment.root,
            object_len: commitment.object_len,
            chunk_count: commitment.chunk_count,
            required_chunk_index,
            deadline_daa_score: 100,
            challenged: true,
        };
        let proofs = (0..commitment.chunk_count)
            .map(|index| (index, palw_receipt_da_chunk_proof(PALW_RECEIPT_DA_OBJECT_VERSION_V2, bytes, index).unwrap()))
            .collect();
        (target, proofs)
    }

    #[tokio::test]
    async fn withholding_peer_fails_over_and_reconstructs_only_verified_v2() {
        let mut bytes = (0..40_000).map(|index| (index % 251) as u8).collect::<Vec<_>>();
        bytes[..2].copy_from_slice(&PALW_RECEIPT_DA_OBJECT_VERSION_V2.to_le_bytes());
        let (target, proofs) = target(&bytes, 1);
        let mut source = FakeSource { peers: 2, proofs, withhold_peer: 1, requests: vec![], corrupt: false };
        let telemetry = PalwDaServiceTelemetry::default();

        let fetched = fetch_object(&mut source, &target, Instant::now() + Duration::from_secs(1), &telemetry).await.unwrap();
        assert_eq!(*fetched, bytes);
        assert_eq!(source.requests[0], (1, 1), "challenged sample is fetched first");
        assert!(source.requests.contains(&(0, 1)), "second peer supplied the withheld sample");
        assert!(telemetry.snapshot().peer_failovers > 0);
    }

    #[tokio::test]
    async fn malformed_peer_bytes_never_form_an_admissible_object() {
        let mut bytes = vec![0x42; 20_000];
        bytes[..2].copy_from_slice(&PALW_RECEIPT_DA_OBJECT_VERSION_V2.to_le_bytes());
        let (target, proofs) = target(&bytes, 0);
        let mut source = FakeSource { peers: 1, proofs, withhold_peer: usize::MAX, requests: vec![], corrupt: true };
        let telemetry = PalwDaServiceTelemetry::default();
        let result = fetch_object(&mut source, &target, Instant::now() + Duration::from_millis(20), &telemetry).await;
        assert!(matches!(result, Err(FetchError::InvalidResponse)));
        assert!(telemetry.snapshot().invalid_responses > 0);
    }

    #[test]
    fn daa_deadline_window_is_bounded_and_expired_is_zero() {
        assert_eq!(fetch_window(100, 100, 10), Duration::ZERO);
        assert_eq!(fetch_window(100, 101, 10), Duration::from_millis(100));
        assert_eq!(fetch_window(0, u64::MAX, 1), PALW_DA_MAX_FETCH_WINDOW);
    }
}
