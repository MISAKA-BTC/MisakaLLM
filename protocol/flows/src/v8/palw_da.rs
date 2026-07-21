//! DA-01 receipt-object chunk serving flow.
//!
//! A peer asks for exactly one `(root, index)` and receives at most one fixed-chunk Merkle proof.
//! Unknown roots intentionally produce no response; the requesting side owns its bounded timeout
//! and may sample another provider. Malformed or out-of-range requests disconnect the peer.

use crate::{flow_context::FlowContext, flow_trait::Flow};
use kaspa_consensus_core::palw::da::PalwReceiptDaChunkProofV1;
use kaspa_hashes::Hash64;
use kaspa_p2p_lib::{
    IncomingRoute, Router,
    common::ProtocolError,
    dequeue_with_request_id, dequeue_with_timeout, make_request, make_response,
    palw_da::{
        PALW_DA_P2P_MAX_IN_FLIGHT, PalwDaPendingChunk, PalwDaRequestTracker, palw_da_get_chunk_message, validate_get_palw_da_chunk,
    },
    pb::kaspad_message::Payload,
};
use std::{sync::Arc, time::Duration};

pub struct RequestedPalwDaChunksFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

impl RequestedPalwDaChunksFlow {
    pub const fn channel_size() -> usize {
        PALW_DA_P2P_MAX_IN_FLIGHT
    }

    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        loop {
            let (message, request_id) = dequeue_with_request_id!(self.incoming_route, Payload::GetPalwDaChunk)?;
            let request = validate_get_palw_da_chunk(&message)
                .map_err(|error| ProtocolError::MisbehavingPeer(format!("invalid PALW DA chunk request: {error}")))?;
            let response = self
                .ctx
                .palw_da_chunk(&request.object_root, request.chunk_index)
                .await
                .map_err(|error| ProtocolError::MisbehavingPeer(format!("invalid PALW DA chunk request: {error}")))?;
            if let Some(response) = response {
                self.router.enqueue(make_response!(Payload::PalwDaChunk, response, request_id)).await?;
            }
        }
    }
}

/// Per-peer requester used by sampling/challenge callers. Responses are routed by the request ID of
/// a private route, so no global `PalwDaChunk` route is registered and unsolicited chunks still
/// disconnect at the router boundary. Callers may enqueue up to 16 samples before draining them.
pub struct PalwDaChunkRequester {
    router: Arc<Router>,
    incoming_route: IncomingRoute,
    tracker: PalwDaRequestTracker,
}

impl PalwDaChunkRequester {
    pub fn new(router: Arc<Router>) -> Self {
        let incoming_route = router.subscribe_with_capacity(vec![], PALW_DA_P2P_MAX_IN_FLIGHT);
        Self { router, incoming_route, tracker: PalwDaRequestTracker::default() }
    }

    pub fn pending(&self) -> usize {
        self.tracker.len()
    }

    pub async fn enqueue(&mut self, object_root: Hash64, chunk_index: u16) -> Result<PalwDaPendingChunk, ProtocolError> {
        let message = palw_da_get_chunk_message(object_root, chunk_index);
        let pending = self
            .tracker
            .register(&message)
            .map_err(|error| ProtocolError::OtherOwned(format!("cannot enqueue PALW DA chunk request: {error}")))?;
        if let Err(error) = self.router.enqueue(make_request!(Payload::GetPalwDaChunk, message, self.incoming_route.id())).await {
            self.tracker.cancel(pending);
            return Err(error);
        }
        Ok(pending)
    }

    pub async fn receive(&mut self, timeout: Duration) -> Result<PalwReceiptDaChunkProofV1, ProtocolError> {
        let response = dequeue_with_timeout!(self.incoming_route, Payload::PalwDaChunk, timeout)?;
        self.tracker
            .validate_response(&response)
            .map_err(|error| ProtocolError::MisbehavingPeer(format!("invalid PALW DA chunk response: {error}")))
    }

    pub fn cancel(&mut self, request: PalwDaPendingChunk) -> bool {
        self.tracker.cancel(request)
    }
}

#[async_trait::async_trait]
impl Flow for RequestedPalwDaChunksFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incoming_queue_matches_per_peer_in_flight_cap() {
        assert_eq!(RequestedPalwDaChunksFlow::channel_size(), PALW_DA_P2P_MAX_IN_FLIGHT);
    }
}
