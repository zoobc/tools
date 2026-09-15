// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

/// ZBC-MSG-v1 message signing (spec/signing.md section 5).
public enum Message {
    public static let scheme = "ZBC-MSG-v1"

    /// SHA3-256("ZBC-MSG" || message).
    public static func digest(_ message: [UInt8]) -> [UInt8] { SHA3.hash256(Array("ZBC-MSG".utf8), message) }

    public struct Signed {
        public let scheme: String, address: String, publicKey: String, messageHex: String, digest: String, signature: String
    }

    public static func sign(_ kp: KeyPair, _ message: [UInt8]) -> Signed {
        let d = digest(message)
        return Signed(scheme: scheme, address: kp.address, publicKey: Enc.hex(kp.publicKey), messageHex: Enc.hex(message), digest: Enc.hex(d), signature: Enc.hex(kp.sign(d)))
    }

    /// The public key behind a ZBC_ address or 64 hex, or nil.
    public static func publicKey(of address: String) -> [UInt8]? {
        if Enc.isHex(address, 64) { return Enc.unhex(address) }
        guard let (prefix, payload) = Address.decode(address), prefix == "ZBC" else { return nil }
        return payload
    }

    /// False for anything that does not verify; never throws.
    public static func verify(_ address: String, _ message: [UInt8], _ signature: [UInt8]) -> Bool {
        guard let pub = publicKey(of: address) else { return false }
        return Ed25519.verify(digest(message), signature, pub)
    }
}
