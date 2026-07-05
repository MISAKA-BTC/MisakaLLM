import Foundation

/// MIL protocol types + wire codecs (design §2.3/§7.4), Borsh-compatible with
/// the Rust `misaka_mil_channel::wire` + `misaka_mil_core::{job, receipt}`.
public enum MilProtocol {
    public static let version: UInt16 = 1
    public static let ftClient: UInt8 = 0x01
    public static let ftServer: UInt8 = 0x02
}

public enum Tier: UInt8 { case tee = 0, open = 1 }

public struct SamplingParams {
    public var temperatureMilli: UInt16
    public var topPMilli: UInt16
    public var seed: UInt64?
    public init(temperatureMilli: UInt16 = 0, topPMilli: UInt16 = 1000, seed: UInt64? = nil) {
        self.temperatureMilli = temperatureMilli
        self.topPMilli = topPMilli
        self.seed = seed
    }
    public static let greedy = SamplingParams()
}

public struct SlaParams {
    public var ttfbMs: UInt32
    public var minTps: UInt32
    public init(ttfbMs: UInt32, minTps: UInt32) { self.ttfbMs = ttfbMs; self.minTps = minTps }
}

public struct JobSpec {
    public var version: UInt16 = MilProtocol.version
    public var modelId: [UInt8]      // 64
    public var profileId: [UInt8]?   // 64
    public var tier: Tier
    public var maxTokens: UInt32
    public var sampling: SamplingParams
    public var sla: SlaParams
    public var priceCapSompi: UInt64
    public var cmReq: [UInt8]        // 64

    public func encodeAsClientMsg() -> [UInt8] {
        var w = BorshWriter()
        w.u8(1)  // ClientMsg::Job
        w.u16(version); w.fixed(modelId)
        w.option(profileId != nil) { $0.fixed(profileId!) }
        w.u8(tier.rawValue)
        w.u32(maxTokens)
        w.u16(sampling.temperatureMilli); w.u16(sampling.topPMilli)
        w.option(sampling.seed != nil) { $0.u64(sampling.seed!) }
        w.u32(sla.ttfbMs); w.u32(sla.minTps)
        w.u64(priceCapSompi)
        w.fixed(cmReq)
        return w.bytes
    }
}

public struct ReceiptBody {
    public var version: UInt16
    public var sessionId: [UInt8]  // 64
    public var counter: UInt64
    public var cumTokensIn: UInt64
    public var cumTokensOut: UInt64
    public var timestampMs: UInt64
    public var cmResp: [UInt8]     // 64
    public var isFinal: Bool

    /// The canonical 163-byte receipt signing transcript (LE ints).
    public func signingMessage() -> [UInt8] {
        var w = BorshWriter()
        w.u16(version); w.fixed(sessionId)
        w.u64(counter); w.u64(cumTokensIn); w.u64(cumTokensOut); w.u64(timestampMs)
        w.fixed(cmResp); w.u8(isFinal ? 1 : 0)
        return w.bytes
    }
}

public struct SignedReceipt {
    public var body: ReceiptBody
    public var signature: [UInt8]  // 4627
    public var providerPk: [UInt8] // 2592
}

// Wire messages.

public struct ServerHello {
    public var version: UInt16
    public var attestation: [UInt8]
    public var pkKem: [UInt8]
    public var pkReceipt: [UInt8]

    public static func decode(_ buf: [UInt8]) -> ServerHello {
        var r = BorshReader(buf)
        return ServerHello(version: r.u16(), attestation: r.vecU8(), pkKem: r.vecU8(), pkReceipt: r.vecU8())
    }
}

public enum ClientMsg {
    public static func prompt(_ p: [UInt8]) -> [UInt8] {
        var w = BorshWriter(); w.u8(0); w.vecU8(p); return w.bytes
    }
    public static let cancel: [UInt8] = { var w = BorshWriter(); w.u8(2); return w.bytes }()
}

public enum ServerMsg {
    case chunk(text: [UInt8], tokenCount: UInt32)
    case receipt(SignedReceipt)
    case done(totalTokensOut: UInt64)
    case error(String)

    public static func decode(_ buf: [UInt8]) -> ServerMsg {
        var r = BorshReader(buf)
        switch r.u8() {
        case 0: return .chunk(text: r.vecU8(), tokenCount: r.u32())
        case 1:
            let body = ReceiptBody(
                version: r.u16(), sessionId: r.fixed(64), counter: r.u64(),
                cumTokensIn: r.u64(), cumTokensOut: r.u64(), timestampMs: r.u64(),
                cmResp: r.fixed(64), isFinal: r.bool())
            return .receipt(SignedReceipt(body: body, signature: r.vecU8(), providerPk: r.vecU8()))
        case 2: return .done(totalTokensOut: r.u64())
        case 3: return .error(r.string())
        default: return .error("unknown ServerMsg tag")
        }
    }
}

public func encodeClientHello(nonceReq: [UInt8]) -> [UInt8] {
    var w = BorshWriter(); w.u16(MilProtocol.version); w.fixed(nonceReq); return w.bytes
}
public func encodeClientKem(kemCt: [UInt8]) -> [UInt8] {
    var w = BorshWriter(); w.vecU8(kemCt); return w.bytes
}
public func encodeFrame(frameType: UInt8, seq: UInt64, ciphertext: [UInt8]) -> [UInt8] {
    var w = BorshWriter(); w.u8(frameType); w.u64(seq); w.vecU8(ciphertext); return w.bytes
}
public func decodeFrame(_ buf: [UInt8]) -> (frameType: UInt8, seq: UInt64, ciphertext: [UInt8]) {
    var r = BorshReader(buf); return (r.u8(), r.u64(), r.vecU8())
}
