import XCTest
@testable import MilSDK

/// Cross-language conformance: the pure-Swift Hash64 derivations, Borsh codec,
/// and receipt signing-message layout must match the Rust implementation's byte
/// vectors (emitted by misaka-mil-core / misaka-mil-channel test probes). The PQ
/// + AEAD primitives are behind `MilCryptoProvider` (platform integration), so
/// they are not exercised here — the crypto-independent core is.
final class VectorsTests: XCTestCase {
    func repeated(_ b: UInt8, _ n: Int) -> [UInt8] { [UInt8](repeating: b, count: n) }

    func testKeyBindingMatchesRust() {
        let got = MilHash.keyBinding(pkKem: repeated(0x11, 1568), pkReceipt: repeated(0x22, 2592))
        XCTAssertEqual(
            Hex.encode(got),
            "7448dd2bf5ebc5333616fc39d50b0ba5e69948ee39709112fe409c5a5b319f245b24f75561b2465e7b30141725276ba5d640a4998913a1a8abe7e6a857132454")
    }

    func testProviderIdMatchesRust() {
        XCTAssertEqual(
            Hex.encode(MilHash.providerId(pkReceipt: repeated(0x22, 2592))),
            "ddfc70261dbe03e8cb68aaef61babbb3f425e9b66eda79f88dec61dc923c610b9272b449d0c34fd23b56b981c83d7418a5d97fcae548206321999542b32a4851")
    }

    func testSessionIdMatchesRust() {
        let got = MilHash.sessionId(quoteHash: repeated(0x07, 64), kemCt: repeated(0x33, 1568), nonceReq: repeated(0x44, 32))
        XCTAssertEqual(
            Hex.encode(got),
            "f48b2e29ae5a85fae462c1fa5b46d92e52ced5d0c1c0889041c9ebd99cd21eec469fac66d90cdd6d51f0e863671e52f465904309ce1343324c7d91df29043762")
    }

    func testCommitmentsMatchRust() {
        let pch = MilHash.promptCtHash(Array("hello ct".utf8))
        XCTAssertEqual(
            Hex.encode(pch),
            "07faca56bfbd517c2e84258da70b3f12e914b33f091492f87b2c59d6afdadacb453e19e13790bb23c1f49e7f4383eb8df521626b3154843eab69883ac6dda061")
        let cm = MilHash.requestCommitment(salt: repeated(0x07, 32), promptCtHashV: pch)
        XCTAssertEqual(
            Hex.encode(cm),
            "45ec52be0fc71d36a35a5ed288fabb6803e4114f4ce5f898d556be916b28f0c003f02419ba217278dba0ee2a69bb96684ee58a22824bb06a8e93e7df2ac99ed6")
    }

    func testReceiptSigningMessageMatchesRust() {
        let body = ReceiptBody(
            version: 1, sessionId: repeated(0x05, 64), counter: 2, cumTokensIn: 10,
            cumTokensOut: 1024, timestampMs: 1234, cmResp: repeated(0x04, 64), isFinal: false)
        // Layout: version(2) ‖ sessionId(64) ‖ counter(8) ‖ cum_in(8) ‖
        // cum_out(8) ‖ ts(8) ‖ cm_resp(64) ‖ is_final(1) = 163, LE ints.
        let msg = body.signingMessage()
        XCTAssertEqual(msg.count, 163)
        XCTAssertEqual(Hex.encode(Array(msg[0..<2])), "0100")                // version=1 u16 LE
        XCTAssertEqual(Hex.encode(Array(msg[66..<74])), "0200000000000000")  // counter=2 u64 LE
        XCTAssertEqual(Hex.encode(Array(msg[82..<90])), "0004000000000000")  // cum_out=1024 u64 LE
        XCTAssertEqual(msg[162], 0)                                          // is_final=false
    }

    func testBorshRoundTripJobSpec() {
        let job = JobSpec(
            modelId: repeated(0x01, 64), profileId: nil, tier: .open, maxTokens: 256,
            sampling: .greedy, sla: SlaParams(ttfbMs: 1500, minTps: 1),
            priceCapSompi: 123456, cmReq: repeated(0x02, 64))
        let enc = job.encodeAsClientMsg()
        // ClientMsg::Job tag(1) ‖ version u16 LE(01 00) ‖ modelId(64) ‖ ...
        XCTAssertEqual(enc[0], 1)   // ClientMsg::Job variant tag
        XCTAssertEqual(enc[1], 1)   // version u16 LE low byte
        XCTAssertEqual(enc[2], 0)   // version u16 LE high byte
        // after tag(1)+version(2)+modelId(64) comes the profileId Option = None(0)
        XCTAssertEqual(enc[1 + 2 + 64], 0)
    }

    func testBlake2bUnkeyedKnownAnswer() {
        // RFC 7693 BLAKE2b-512("abc")
        var s = Blake2b(outLen: 64)
        s.update(Array("abc".utf8))
        XCTAssertEqual(
            Hex.encode(s.finalize()),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
    }
}
