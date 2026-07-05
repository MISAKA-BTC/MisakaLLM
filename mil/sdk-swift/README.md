# MilSDK — MISAKA Inference Lane Swift SDK

A Swift client for the MISAKA Inference Lane (design §14.2), mirroring the
protocol of the Rust reference and the TypeScript SDK.

## What builds and is tested here

Pure-Swift, dependency-free, cross-checked against the Rust implementation's
byte vectors (`swift test`, 7 tests):

- **Borsh** codec (`Borsh.swift`)
- **BLAKE2b-512** (`Blake2b.swift`, RFC 7693 — validated against the `"abc"`
  known answer)
- **Hash64 derivations** (`Hash.swift`: `keyBinding`, `providerId`, `sessionId`,
  `promptCtHash`, `requestCommitment`) — byte-identical to Rust
- **Protocol types + receipt signing-message layout** (`Protocol.swift`)
- The **channel state machine** (`Client.swift`) and AEAD framing helpers
  (`Crypto.swift`)

## Platform integration point

The PQ + AEAD primitives are abstracted behind `MilCryptoProvider`
(`Crypto.swift`): ML-KEM-1024 encapsulation, HKDF-SHA3-512, AES-256-GCM, and
ML-DSA-87 verification with a context string. A platform build binds these to
CryptoKit (macOS 15+ / iOS 18+ ship `MLKEM1024` and `MLDSA`) or swift-crypto,
and supplies a Network.framework transport to `MilSession`. The byte contracts
are documented on the protocol and validated by the shared cross-language
vectors, so an implementation that satisfies them is wire-compatible with the
Rust provider and the TS SDK.

```
swift build
swift test
```
