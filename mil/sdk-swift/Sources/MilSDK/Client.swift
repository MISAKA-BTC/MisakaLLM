import Foundation

/// MIL requester client outline (design §2.3, §14.2). Transport-agnostic: it
/// drives the handshake + prompt/job/response state machine over any framed
/// byte channel, delegating PQ + AEAD to a `MilCryptoProvider`. A platform
/// integration supplies the Network.framework / URLSession transport and the
/// concrete crypto provider.
///
/// This is intentionally transport-free so the protocol logic is unit-testable;
/// wiring `send`/`recvFrame` to a live socket is the platform step.
public final class MilSession {
    private let crypto: MilCryptoProvider
    public let sessionId: [UInt8]
    public let peerPkReceipt: [UInt8]
    private var send: SendCipher
    private var recv: RecvCipher

    /// The attestation verifier returns the canonical quote hash or throws.
    public typealias AttestationVerifier = (ServerHello) throws -> [UInt8]

    /// Complete the client handshake given the two handshake frames already
    /// exchanged out-of-band by the transport (ServerHello bytes in; the caller
    /// has sent ClientHello and will send the returned ClientKem frame).
    public static func establish(
        crypto: MilCryptoProvider,
        nonceReq: [UInt8],
        serverHelloBytes: [UInt8],
        verify: AttestationVerifier
    ) throws -> (session: MilSession, clientKemFrame: [UInt8]) {
        let hello = ServerHello.decode(serverHelloBytes)
        guard hello.version == MilProtocol.version else { throw MilError.versionMismatch(hello.version) }
        let quoteHash = try verify(hello)
        let (ct, ss) = try crypto.encapsulate(pkKem: hello.pkKem)
        let sid = MilHash.sessionId(quoteHash: quoteHash, kemCt: ct, nonceReq: nonceReq)
        let keys = deriveSessionKeys(crypto, sharedSecret: ss, sessionId: sid)
        let session = MilSession(
            crypto: crypto, sessionId: sid, peerPkReceipt: hello.pkReceipt,
            send: SendCipher(crypto: crypto, key: keys.kC2P, sessionId: sid, direction: .clientToProvider),
            recv: RecvCipher(crypto: crypto, key: keys.kP2C, sessionId: sid, direction: .providerToClient))
        return (session, encodeClientKem(kemCt: ct))
    }

    private init(crypto: MilCryptoProvider, sessionId: [UInt8], peerPkReceipt: [UInt8], send: SendCipher, recv: RecvCipher) {
        self.crypto = crypto; self.sessionId = sessionId; self.peerPkReceipt = peerPkReceipt
        self.send = send; self.recv = recv
    }

    /// Seal a client application message into a length-agnostic frame (the
    /// transport length-prefixes it). Returns (frameBytes, recordCiphertext);
    /// the prompt's record ciphertext feeds cm_req.
    public func sealClient(_ plaintext: [UInt8]) -> (frame: [UInt8], recordCiphertext: [UInt8]) {
        let (seq, ct) = send.seal(frameType: MilProtocol.ftClient, plaintext: plaintext)
        return (encodeFrame(frameType: MilProtocol.ftClient, seq: seq, ciphertext: ct), ct)
    }

    /// Open a provider frame into a decoded `ServerMsg`.
    public func openServer(frameBytes: [UInt8]) throws -> ServerMsg {
        let (ft, seq, ct) = decodeFrame(frameBytes)
        let plaintext = try recv.open(frameType: ft, seq: seq, ciphertext: ct)
        return ServerMsg.decode(plaintext)
    }

    /// Verify a receipt against the running transcript + this session's key.
    public func check(receipt: SignedReceipt, transcriptCommitment: [UInt8]) throws {
        guard receipt.body.cmResp == transcriptCommitment else { throw MilError.transcriptMismatch }
        guard receipt.providerPk == peerPkReceipt else { throw MilError.receiptInvalid("provider key mismatch") }
        guard verifyReceipt(crypto, receipt) else { throw MilError.receiptInvalid("bad signature") }
    }
}
