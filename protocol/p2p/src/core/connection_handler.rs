use crate::common::ProtocolError;
use crate::core::hub::HubEvent;
use crate::pb::{
    KaspadMessage, p2p_client::P2pClient as ProtoP2pClient, p2p_server::P2p as ProtoP2p, p2p_server::P2pServer as ProtoP2pServer,
};
use crate::{ConnectionInitializer, Router};
use futures::FutureExt;
use kaspa_core::{debug, info};
use kaspa_utils::networking::NetAddress;
use kaspa_utils_tower::{
    counters::TowerConnectionCounters,
    middleware::{CountBytesBody, MapRequestBodyLayer, MapResponseBodyLayer, ServiceBuilder},
};
use std::collections::HashSet;
use std::net::{IpAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc::{Sender as MpscSender, channel as mpsc_channel};
use tokio::sync::oneshot::{Sender as OneshotSender, channel as oneshot_channel};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Error as TonicError, Server as TonicServer};
use tonic::{Request, Response, Status as TonicStatus, Streaming};

#[derive(Error, Debug)]
pub enum ConnectionError {
    #[error("missing socket address")]
    NoAddress,

    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    TonicError(#[from] TonicError),

    #[error("{0}")]
    TonicStatus(#[from] TonicStatus),

    #[error("{0}")]
    ProtocolError(#[from] ProtocolError),
}

/// Maximum P2P decoded gRPC message size to send and receive
const P2P_MAX_MESSAGE_SIZE: usize = 1024 * 1024 * 1024; // 1GB

/// Handles Router creation for both server and client-side new connections
#[derive(Clone)]
pub struct ConnectionHandler {
    /// Cloned on each new connection so that routers can communicate with a central hub
    hub_sender: MpscSender<HubEvent>,
    initializer: Arc<dyn ConnectionInitializer>,
    counters: Arc<TowerConnectionCounters>,
    /// Optional fail-closed IP allowlist for server-side P2P connections. Outbound connections are
    /// unaffected. PALW closed testnets use this to remain reachable by their explicitly configured
    /// peers without opening the listener to third parties.
    inbound_ip_allowlist: Option<Arc<HashSet<IpAddr>>>,
}

impl ConnectionHandler {
    pub(crate) fn new(
        hub_sender: MpscSender<HubEvent>,
        initializer: Arc<dyn ConnectionInitializer>,
        counters: Arc<TowerConnectionCounters>,
        inbound_ip_allowlist: Option<Arc<HashSet<IpAddr>>>,
    ) -> Self {
        Self { hub_sender, initializer, counters, inbound_ip_allowlist }
    }

    /// Launches a P2P server listener loop
    pub(crate) fn serve(&self, serve_address: NetAddress) -> Result<OneshotSender<()>, ConnectionError> {
        let (termination_sender, termination_receiver) = oneshot_channel::<()>();
        let connection_handler = self.clone();
        info!("P2P Server starting on: {}", serve_address);

        let bytes_tx = self.counters.bytes_tx.clone();
        let bytes_rx = self.counters.bytes_rx.clone();

        tokio::spawn(async move {
            let proto_server = ProtoP2pServer::new(connection_handler)
                .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
                .send_compressed(tonic::codec::CompressionEncoding::Gzip)
                .max_decoding_message_size(P2P_MAX_MESSAGE_SIZE);

            // TODO: check whether we should set tcp_keepalive
            let serve_result = TonicServer::builder()
                .layer(MapRequestBodyLayer::new(move |body| tonic::body::Body::new(CountBytesBody::new(body, bytes_rx.clone()))))
                .layer(MapResponseBodyLayer::new(move |body| tonic::body::Body::new(CountBytesBody::new(body, bytes_tx.clone()))))
                .add_service(proto_server)
                .serve_with_shutdown(serve_address.into(), termination_receiver.map(drop))
                .await;

            match serve_result {
                Ok(_) => info!("P2P Server stopped: {}", serve_address),
                Err(err) => panic!("P2P, Server {serve_address} stopped with error: {err:?}"),
            }
        });
        Ok(termination_sender)
    }

    /// Connect to a new peer
    pub(crate) async fn connect(&self, peer_address: String) -> Result<Arc<Router>, ConnectionError> {
        let Some(socket_address) = peer_address.to_socket_addrs()?.next() else {
            return Err(ConnectionError::NoAddress);
        };
        let peer_address = format!("http://{}", peer_address); // Add scheme prefix as required by Tonic

        let channel = tonic::transport::Endpoint::new(peer_address)?
            .timeout(Duration::from_millis(Self::communication_timeout()))
            .connect_timeout(Duration::from_millis(Self::connect_timeout()))
            .tcp_keepalive(Some(Duration::from_millis(Self::keep_alive())))
            .connect()
            .await?;

        let channel = ServiceBuilder::new()
            .layer(MapResponseBodyLayer::new(move |body| {
                tonic::body::Body::new(CountBytesBody::new(body, self.counters.bytes_rx.clone()))
            }))
            .layer(MapRequestBodyLayer::new(move |body| {
                tonic::body::Body::new(CountBytesBody::new(body, self.counters.bytes_tx.clone()))
            }))
            .service(channel);

        let mut client = ProtoP2pClient::new(channel)
            .send_compressed(tonic::codec::CompressionEncoding::Gzip)
            .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
            .max_decoding_message_size(P2P_MAX_MESSAGE_SIZE);

        let (outgoing_route, outgoing_receiver) = mpsc_channel(Self::outgoing_network_channel_size());
        let incoming_stream = client.message_stream(ReceiverStream::new(outgoing_receiver)).await?.into_inner();

        let router = Router::new(socket_address, true, self.hub_sender.clone(), incoming_stream, outgoing_route).await;

        // For outbound peers, we perform the initialization as part of the connect logic
        match self.initializer.initialize_connection(router.clone()).await {
            Ok(()) => {
                // Notify the central Hub about the new peer
                self.hub_sender.send(HubEvent::NewPeer(router.clone())).await.expect("hub receiver should never drop before senders");
            }

            Err(err) => {
                router.try_sending_reject_message(&err).await;
                // Ignoring the new router
                router.close().await;
                debug!("P2P, handshake failed for outbound peer {}: {}", router, err);
                return Err(ConnectionError::ProtocolError(err));
            }
        }

        Ok(router)
    }

    /// Connect to a new peer with `retry_attempts` retries and `retry_interval` duration between each attempt
    pub(crate) async fn connect_with_retry(
        &self,
        address: String,
        retry_attempts: u8,
        retry_interval: Duration,
    ) -> Result<Arc<Router>, ConnectionError> {
        let mut counter = 0;
        loop {
            counter += 1;
            match self.connect(address.clone()).await {
                Ok(router) => {
                    debug!("P2P, Client connected, peer: {:?}", address);
                    return Ok(router);
                }
                Err(ConnectionError::ProtocolError(err)) => {
                    // On protocol errors we avoid retrying
                    debug!("P2P, connect retry #{} failed with error {:?}, peer: {:?}, aborting retries", counter, err, address);
                    return Err(ConnectionError::ProtocolError(err));
                }
                Err(err) => {
                    debug!("P2P, connect retry #{} failed with error {:?}, peer: {:?}", counter, err, address);
                    if counter < retry_attempts {
                        // Await `retry_interval` time before retrying
                        tokio::time::sleep(retry_interval).await;
                    } else {
                        debug!("P2P, Client connection retry #{} - all failed", retry_attempts);
                        return Err(err);
                    }
                }
            }
        }
    }

    // TODO: revisit the below constants
    fn outgoing_network_channel_size() -> usize {
        // TODO: this number is taken from go-kaspad and should be re-evaluated
        (1 << 17) + 256
    }

    fn communication_timeout() -> u64 {
        10_000
    }

    fn keep_alive() -> u64 {
        10_000
    }

    fn connect_timeout() -> u64 {
        1_000
    }
}

#[tonic::async_trait]
impl ProtoP2p for ConnectionHandler {
    type MessageStreamStream = Pin<Box<dyn futures::Stream<Item = Result<KaspadMessage, TonicStatus>> + Send + 'static>>;

    /// Handle the new arriving **server** connections
    async fn message_stream(
        &self,
        request: Request<Streaming<KaspadMessage>>,
    ) -> Result<Response<Self::MessageStreamStream>, TonicStatus> {
        let Some(remote_address) = request.remote_addr() else {
            return Err(TonicStatus::new(tonic::Code::InvalidArgument, "Incoming connection opening request has no remote address"));
        };
        if !inbound_ip_allowed(self.inbound_ip_allowlist.as_deref(), remote_address.ip()) {
            // Reject before constructing a Router or running the protocol handshake. Disconnecting in
            // the connection manager after initialization would leave an unauthorized peer a window in
            // which it could exchange consensus messages, defeating the closed-testnet fence.
            debug!("P2P rejected inbound connection from non-allowlisted address {remote_address}");
            return Err(TonicStatus::new(tonic::Code::PermissionDenied, "P2P peer is not in the inbound allowlist"));
        }

        // Build the in/out pipes
        let (outgoing_route, outgoing_receiver) = mpsc_channel(Self::outgoing_network_channel_size());
        let incoming_stream = request.into_inner();

        // Build the router object
        let router = Router::new(remote_address, false, self.hub_sender.clone(), incoming_stream, outgoing_route).await;

        // Notify the central Hub about the new peer
        self.hub_sender.send(HubEvent::NewPeer(router)).await.expect("hub receiver should never drop before senders");

        // Give tonic a receiver stream (messages sent to it will be forwarded to the network peer)
        Ok(Response::new(Box::pin(ReceiverStream::new(outgoing_receiver).map(Ok)) as Self::MessageStreamStream))
    }
}

/// Treat an IPv4-mapped IPv6 remote as the equivalent IPv4 address. Depending on the listener/socket
/// stack, an allowlisted `127.0.0.1` or public IPv4 peer can arrive as `::ffff:a.b.c.d`; comparing the
/// raw enum variants would reject the intended peer and recreate the two-node deadlock on dual-stack
/// hosts.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        IpAddr::V4(_) => ip,
    }
}

fn inbound_ip_allowed(allowlist: Option<&HashSet<IpAddr>>, remote: IpAddr) -> bool {
    let remote = canonical_ip(remote);
    allowlist.map(|allowed| allowed.iter().copied().map(canonical_ip).any(|candidate| candidate == remote)).unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn inbound_allowlist_is_fail_closed_and_accepts_ipv4_mapped_peers() {
        let allowed_v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let allowed = HashSet::from([allowed_v4]);
        assert!(inbound_ip_allowed(None, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))));
        assert!(inbound_ip_allowed(Some(&allowed), allowed_v4));
        assert!(inbound_ip_allowed(Some(&allowed), IpAddr::V6(allowed_v4.to_string().parse::<Ipv4Addr>().unwrap().to_ipv6_mapped())));
        let allowed_mapped = HashSet::from([IpAddr::V6(Ipv4Addr::new(203, 0, 113, 7).to_ipv6_mapped())]);
        assert!(inbound_ip_allowed(Some(&allowed_mapped), allowed_v4));
        assert!(!inbound_ip_allowed(Some(&allowed), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8))));
        assert!(!inbound_ip_allowed(Some(&HashSet::new()), IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }
}
