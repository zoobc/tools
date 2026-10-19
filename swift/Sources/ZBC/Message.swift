// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Foundation

/// Message signing (spec/signing.md sections 5 and 5a).
///
/// ZBC-MSG-v2 binds the signature to one chain, the way transactions do since signing v2:
/// digest = SHA3-256("ZBC-MSG-v2" || genesis_hash (32) || message). New signatures are always v2.
/// ZBC-MSG-v1 (SHA3-256("ZBC-MSG" || message), no chain) is still accepted by `verify` until
/// `v1Sunset` (2026-12-01T00:00:00Z) and refused after.
public enum Message {
    public static let scheme = "ZBC-MSG-v2"
    public static let schemeV1 = "ZBC-MSG-v1"
    /// What `check` reports for a v1 signature that still verifies.
    public static let schemeV1Accepted = "ZBC-MSG-v1 (accepted until 2026-12-01)"
    /// Unix seconds of 2026-12-01T00:00:00Z: v1 signatures are refused from here on.
    public static let v1Sunset: Int64 = 1796083200

    /// SHA3-256("ZBC-MSG-v2" || genesisHash || message); `genesisHash` is the chain's 32-byte genesis block hash.
    public static func digest(_ message: [UInt8], genesisHash: [UInt8]) -> [UInt8] {
        precondition(genesisHash.count == 32, "ZBC-MSG-v2 needs the chain's 32-byte genesis hash")
        return SHA3.hash256(Array("ZBC-MSG-v2".utf8), genesisHash, message)
    }

    /// SHA3-256("ZBC-MSG" || message): the legacy, chain-independent digest.
    public static func digestV1(_ message: [UInt8]) -> [UInt8] { SHA3.hash256(Array("ZBC-MSG".utf8), message) }

    public struct Signed {
        public let scheme: String, genesisHash: String, address: String, publicKey: String, messageHex: String, digest: String, signature: String
    }

    /// Sign `message` for the chain whose genesis block hash is `genesisHash` (ZBC-MSG-v2).
    public static func sign(_ kp: KeyPair, _ message: [UInt8], genesisHash: [UInt8]) -> Signed {
        let d = digest(message, genesisHash: genesisHash)
        return Signed(scheme: scheme, genesisHash: Enc.hex(genesisHash), address: kp.address, publicKey: Enc.hex(kp.publicKey), messageHex: Enc.hex(message), digest: Enc.hex(d), signature: Enc.hex(kp.sign(d)))
    }

    /// The public key behind a ZBC_ address or 64 hex, or nil.
    public static func publicKey(of address: String) -> [UInt8]? {
        if Enc.isHex(address, 64) { return Enc.unhex(address) }
        guard let d = Address.decode(address), d.0 == "ZBC" else { return nil }
        return d.1
    }

    /// The outcome of `check`: `scheme` names what verified (v2, or v1 while accepted); `digest` is the one checked last.
    public struct Verified { public let valid: Bool, scheme: String, digest: [UInt8] }

    /// v2 first (when `genesisHash` is the chain's 32 bytes; nil = chain unknown, v2 is skipped), then v1 while
    /// `now` (unix seconds) is before `v1Sunset`. Never throws.
    public static func check(_ address: String, _ message: [UInt8], _ signature: [UInt8], genesisHash: [UInt8]?, now: Int64 = Int64(Date().timeIntervalSince1970)) -> Verified {
        let pub = publicKey(of: address)
        let ok = pub != nil && signature.count == 64
        var digest: [UInt8] = []
        if let g = genesisHash, g.count == 32 {
            digest = Self.digest(message, genesisHash: g)
            if ok, Ed25519.verify(digest, signature, pub!) { return Verified(valid: true, scheme: scheme, digest: digest) }
        }
        if now < v1Sunset {
            let d1 = digestV1(message)
            if ok, Ed25519.verify(d1, signature, pub!) { return Verified(valid: true, scheme: schemeV1Accepted, digest: d1) }
        }
        return Verified(valid: false, scheme: scheme, digest: digest.isEmpty ? digestV1(message) : digest)
    }

    /// False for anything that does not verify (v2 for `genesisHash`, or v1 until the sunset); never throws.
    public static func verify(_ address: String, _ message: [UInt8], _ signature: [UInt8], genesisHash: [UInt8]?, now: Int64 = Int64(Date().timeIntervalSince1970)) -> Bool {
        check(address, message, signature, genesisHash: genesisHash, now: now).valid
    }
}
