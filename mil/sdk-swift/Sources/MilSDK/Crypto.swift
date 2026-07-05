import Foundation

/// The PQ + AEAD primitives the MIL data plane needs (design §3.2). These are
/// abstracted so the pure-Swift parts (Borsh, Hash64, receipt layout) build and
/// test with no external crypto dependency; a platform integration binds this
/// protocol to CryptoKit (macOS 15+ / iOS 18+ ship `MLKEM1024` and `MLDSA`) or
/// swift-crypto.
///
/// Byte contracts (all must match `misaka_mil_channel`):
/// - `encapsulate`: ML-KEM-1024, returns (ciphertext[1568], sharedSecret[32]).
/// - `hkdfSha3_512`: HKDF with SHA3-512, salt = nil (RFC5869 → HashLen zeros).
/// - `aesGcmSeal`/`aesGcmOpen`: AES-256-GCM, 12-byte nonce, ciphertext‖tag(16).
/// - `mldsa87Verify`: ML-DSA-87 verify with a context string (FIPS 204).
public protocol MilCryptoProvider {
    func encapsulate(pkKem: [UInt8]) throws -> (ciphertext: [UInt8], sharedSecret: [UInt8])
    func hkdfSha3_512(ikm: [UInt8], info: [UInt8], length: Int) -> [UInt8]
    func aesGcmSeal(key: [UInt8], nonce: [UInt8], aad: [UInt8], plaintext: [UInt8]) -> [UInt8]
    func aesGcmOpen(key: [UInt8], nonce: [UInt8], aad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8]
    func mldsa87Verify(publicKey: [UInt8], message: [UInt8], signature: [UInt8], context: [UInt8]) -> Bool
}

public enum Direction: UInt8 { case clientToProvider = 0x01, providerToClient = 0x02 }

/// Derive the two direction keys: `info = "misaka-mil-v1/kdf" ‖ session_id`,
/// first 32 bytes = client→provider, last 32 = provider→client.
public func deriveSessionKeys(_ crypto: MilCryptoProvider, sharedSecret: [UInt8], sessionId: [UInt8])
    -> (kC2P: [UInt8], kP2C: [UInt8])
{
    let okm = crypto.hkdfSha3_512(ikm: sharedSecret, info: MilHash.Domain.kdf + sessionId, length: 64)
    return (Array(okm[0..<32]), Array(okm[32..<64]))
}

public func aeadNonce(direction: Direction, seq: UInt64) -> [UInt8] {
    var n = [UInt8](repeating: 0, count: 12)
    n[0] = direction.rawValue
    for i in 0..<8 { n[4 + i] = UInt8((seq >> (8 * UInt64(i))) & 0xff) }
    return n
}

public func aeadAad(sessionId: [UInt8], direction: Direction, frameType: UInt8, seq: UInt64) -> [UInt8] {
    var aad = [UInt8](repeating: 0, count: 74)
    for i in 0..<64 { aad[i] = sessionId[i] }
    aad[64] = direction.rawValue
    aad[65] = frameType
    for i in 0..<8 { aad[66 + i] = UInt8((seq >> (8 * UInt64(i))) & 0xff) }
    return aad
}

/// Sealing half with a monotonic send counter.
public struct SendCipher {
    private let crypto: MilCryptoProvider
    private let key: [UInt8]
    private let sessionId: [UInt8]
    private let direction: Direction
    private var nextSeq: UInt64 = 0

    public init(crypto: MilCryptoProvider, key: [UInt8], sessionId: [UInt8], direction: Direction) {
        self.crypto = crypto; self.key = key; self.sessionId = sessionId; self.direction = direction
    }

    public mutating func seal(frameType: UInt8, plaintext: [UInt8]) -> (seq: UInt64, ciphertext: [UInt8]) {
        let seq = nextSeq
        nextSeq += 1
        let ct = crypto.aesGcmSeal(
            key: key, nonce: aeadNonce(direction: direction, seq: seq),
            aad: aeadAad(sessionId: sessionId, direction: direction, frameType: frameType, seq: seq),
            plaintext: plaintext)
        return (seq, ct)
    }
}

/// Opening half enforcing strict in-order sequence numbers.
public struct RecvCipher {
    private let crypto: MilCryptoProvider
    private let key: [UInt8]
    private let sessionId: [UInt8]
    private let direction: Direction
    private var expectedSeq: UInt64 = 0

    public init(crypto: MilCryptoProvider, key: [UInt8], sessionId: [UInt8], direction: Direction) {
        self.crypto = crypto; self.key = key; self.sessionId = sessionId; self.direction = direction
    }

    public mutating func open(frameType: UInt8, seq: UInt64, ciphertext: [UInt8]) throws -> [UInt8] {
        guard seq == expectedSeq else {
            throw MilError.recordOutOfOrder(expected: expectedSeq, got: seq)
        }
        let pt = try crypto.aesGcmOpen(
            key: key, nonce: aeadNonce(direction: direction, seq: seq),
            aad: aeadAad(sessionId: sessionId, direction: direction, frameType: frameType, seq: seq),
            ciphertext: ciphertext)
        expectedSeq += 1
        return pt
    }
}

public enum MilError: Error {
    case recordOutOfOrder(expected: UInt64, got: UInt64)
    case versionMismatch(UInt16)
    case attestationRejected(String)
    case receiptInvalid(String)
    case transcriptMismatch
}

/// Verify a receipt's ML-DSA-87 signature under the MIL receipt context.
public func verifyReceipt(_ crypto: MilCryptoProvider, _ r: SignedReceipt) -> Bool {
    guard r.body.version == MilProtocol.version,
          r.providerPk.count == 2592, r.signature.count == 4627 else { return false }
    return crypto.mldsa87Verify(
        publicKey: r.providerPk, message: r.body.signingMessage(),
        signature: r.signature, context: MilHash.Domain.receiptCtx)
}
