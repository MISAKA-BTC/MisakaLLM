import Foundation

/// MIL Hash64 identity derivations (design §3.2/§3.3), keyed BLAKE2b-512.
/// Matches `misaka_mil_core::{ident, commit}` (cross-checked against Rust
/// vectors in the tests).
public enum MilHash {
    public enum Domain {
        public static let bind = Array("misaka-mil-v1/bind".utf8)
        public static let session = Array("misaka-mil-v1/session".utf8)
        public static let commit = Array("misaka-mil-v1/commit".utf8)
        public static let promptCt = Array("misaka-mil-v1/commit/prompt-ct".utf8)
        public static let transcript = Array("misaka-mil-v1/transcript".utf8)
        public static let providerId = Array("misaka-mil-v1/provider-id".utf8)
        public static let quote = Array("misaka-mil-v1/quote".utf8)
        public static let kdf = Array("misaka-mil-v1/kdf".utf8)
        public static let receiptCtx = Array("misaka-mil-v1/receipt/mldsa87".utf8)
    }

    public static func hash64Keyed(_ domain: [UInt8], _ data: [UInt8]) -> [UInt8] {
        Blake2b.keyed512(key: domain, data: data)
    }

    public static func keyBinding(pkKem: [UInt8], pkReceipt: [UInt8]) -> [UInt8] {
        hash64Keyed(Domain.bind, pkKem + pkReceipt)
    }

    public static func providerId(pkReceipt: [UInt8]) -> [UInt8] {
        hash64Keyed(Domain.providerId, pkReceipt)
    }

    public static func sessionId(quoteHash: [UInt8], kemCt: [UInt8], nonceReq: [UInt8]) -> [UInt8] {
        hash64Keyed(Domain.session, quoteHash + kemCt + nonceReq)
    }

    public static func promptCtHash(_ promptCt: [UInt8]) -> [UInt8] {
        hash64Keyed(Domain.promptCt, promptCt)
    }

    public static func requestCommitment(salt: [UInt8], promptCtHashV: [UInt8]) -> [UInt8] {
        hash64Keyed(Domain.commit, salt + promptCtHashV)
    }

    public static func requestCommitmentForCt(salt: [UInt8], promptCt: [UInt8]) -> [UInt8] {
        requestCommitment(salt: salt, promptCtHashV: promptCtHash(promptCt))
    }
}

/// Incremental response-transcript hasher producing cm_resp (design §3.3/§4.1):
/// seeded with the session id, absorbs each response chunk.
public struct TranscriptHasher {
    private var absorbed: [UInt8]
    public init(sessionId: [UInt8]) { absorbed = sessionId }
    public mutating func absorb(_ chunk: [UInt8]) { absorbed.append(contentsOf: chunk) }
    public func commitment() -> [UInt8] { MilHash.hash64Keyed(MilHash.Domain.transcript, absorbed) }
}

public enum Hex {
    public static func encode(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
    public static func decode(_ s: String) -> [UInt8] {
        let clean = s.hasPrefix("0x") ? String(s.dropFirst(2)) : s
        var out = [UInt8]()
        var i = clean.startIndex
        while i < clean.endIndex {
            let j = clean.index(i, offsetBy: 2)
            out.append(UInt8(clean[i..<j], radix: 16)!)
            i = j
        }
        return out
    }
}
