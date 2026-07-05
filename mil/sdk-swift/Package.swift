// swift-tools-version:5.9
import PackageDescription

// MISAKA Inference Lane (MIL) Swift SDK (design §14.2).
//
// The Borsh codec, keyed BLAKE2b-512 Hash64 derivations, and receipt
// signing-message layout are pure Swift and cross-checked against the Rust
// implementation's byte vectors (see Tests). The PQ + AEAD primitives
// (ML-KEM-1024 encapsulation, ML-DSA-87 verify, HKDF-SHA3-512, AES-256-GCM) are
// abstracted behind `MilCryptoProvider`; a platform integration binds them to
// CryptoKit (macOS 15+ ships MLKEM1024 / MLDSA) or swift-crypto.
let package = Package(
    name: "MilSDK",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "MilSDK", targets: ["MilSDK"])
    ],
    targets: [
        .target(name: "MilSDK"),
        .testTarget(name: "MilSDKTests", dependencies: ["MilSDK"])
    ]
)
