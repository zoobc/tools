// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Crypto
import Foundation

/// Sealed transaction messages (spec/signing.md section 8): "ZBE1" || libsodium sealed box to the recipient's
/// Ed25519 key converted to X25519. X25519 and SHA-512 come from CryptoKit / swift-crypto; the key conversion
/// uses the package's own field arithmetic; HSalsa20, XSalsa20 and Poly1305 are written here (CryptoKit has none).
public enum Encryption {
    /// The 4-byte marker in front of a sealed message field.
    public static let sealedMagic: [UInt8] = Array("ZBE1".utf8)
    /// How much longer a sealed field is than its plaintext: marker 4 + ephemeral key 32 + tag 16.
    public static let sealedOverhead = 52

    /// Ed25519 public key -> X25519 public key of the same point: u = (1 + y) / (1 - y) mod p.
    public static func ed25519PublicKeyToX25519(_ pk: [UInt8]) -> [UInt8]? {
        guard pk.count == 32 else { return nil }
        var yb = pk
        yb[31] &= 0x7f
        let y = Ed25519.reduceP(Ed25519.Big(le: yb))
        let one = Ed25519.Big(1)
        let den = Ed25519.fsub(one, y)
        if den.isZero { return nil }
        let u = Ed25519.fmul(Ed25519.fadd(one, y), Ed25519.finv(den))
        return u.leBytes(32)
    }

    /// Ed25519 seed -> X25519 secret key: the clamped first half of SHA-512(seed).
    public static func ed25519SeedToX25519(_ seed: [UInt8]) -> [UInt8] {
        var sk = Array(Array(SHA512.hash(data: seed)).prefix(32))
        sk[0] &= 248
        sk[31] &= 127
        sk[31] |= 64
        return sk
    }

    /// The X25519 public key of a scalar: X25519(scalar, 9).
    public static func x25519Base(_ scalar: [UInt8]) -> [UInt8]? {
        guard let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar) else { return nil }
        return Array(k.publicKey.rawRepresentation)
    }

    static func x25519(_ scalar: [UInt8], _ u: [UInt8]) -> [UInt8]? {
        guard let k = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar),
              let p = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: u),
              let shared = try? k.sharedSecretFromKeyAgreement(with: p) else { return nil }
        return shared.withUnsafeBytes { Array($0) }
    }

    private static let sigma: [UInt32] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]   // "expand 32-byte k"
    private static let quarters: [[Int]] = [[0, 4, 8, 12], [5, 9, 13, 1], [10, 14, 2, 6], [15, 3, 7, 11], [0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14]]

    private static func le32(_ b: [UInt8], _ off: Int) -> UInt32 {
        return UInt32(b[off]) | (UInt32(b[off + 1]) << 8) | (UInt32(b[off + 2]) << 16) | (UInt32(b[off + 3]) << 24)
    }
    private static func put32(_ out: inout [UInt8], _ off: Int, _ v: UInt32) {
        out[off] = UInt8(v & 0xff); out[off + 1] = UInt8((v >> 8) & 0xff); out[off + 2] = UInt8((v >> 16) & 0xff); out[off + 3] = UInt8((v >> 24) & 0xff)
    }
    @inline(__always) private static func rotl(_ v: UInt32, _ c: UInt32) -> UInt32 { (v << c) | (v >> (32 - c)) }
    private static func salsaRounds(_ x: inout [UInt32]) {
        for _ in 0..<10 {
            for q in quarters {
                let a = q[0], b = q[1], c = q[2], d = q[3]
                x[b] ^= rotl(x[a] &+ x[d], 7)
                x[c] ^= rotl(x[b] &+ x[a], 9)
                x[d] ^= rotl(x[c] &+ x[b], 13)
                x[a] ^= rotl(x[d] &+ x[c], 18)
            }
        }
    }
    private static func salsaState(_ key: [UInt8]) -> [UInt32] {
        var x = [UInt32](repeating: 0, count: 16)
        x[0] = sigma[0]; x[5] = sigma[1]; x[10] = sigma[2]; x[15] = sigma[3]
        for i in 0..<4 { x[1 + i] = le32(key, 4 * i); x[11 + i] = le32(key, 16 + 4 * i) }
        return x
    }

    /// HSalsa20(key 32, input 16) -> 32 bytes.
    public static func hsalsa20(_ key: [UInt8], _ input: [UInt8]) -> [UInt8] {
        var x = salsaState(key)
        for i in 0..<4 { x[6 + i] = le32(input, 4 * i) }
        salsaRounds(&x)
        var out = [UInt8](repeating: 0, count: 32)
        let words = [0, 5, 10, 15, 6, 7, 8, 9]
        for i in 0..<8 { put32(&out, 4 * i, x[words[i]]) }
        return out
    }

    private static func salsa20Block(_ key: [UInt8], _ nonce8: [UInt8], _ counter: UInt64) -> [UInt8] {
        var x0 = salsaState(key)
        x0[6] = le32(nonce8, 0); x0[7] = le32(nonce8, 4)
        x0[8] = UInt32(truncatingIfNeeded: counter); x0[9] = UInt32(truncatingIfNeeded: counter >> 32)
        var x = x0
        salsaRounds(&x)
        var out = [UInt8](repeating: 0, count: 64)
        for i in 0..<16 { put32(&out, 4 * i, x[i] &+ x0[i]) }
        return out
    }

    /// The XSalsa20 keystream of a 32-byte key and a 24-byte nonce.
    public static func xsalsa20Stream(_ key: [UInt8], _ nonce24: [UInt8], _ length: Int) -> [UInt8] {
        let sub = hsalsa20(key, Array(nonce24[0..<16]))
        let nonce8 = Array(nonce24[16..<24])
        var out: [UInt8] = []
        out.reserveCapacity(length + 64)
        var c: UInt64 = 0
        while out.count < length {
            out.append(contentsOf: salsa20Block(sub, nonce8, c))
            c += 1
        }
        return Array(out.prefix(length))
    }

    /// Poly1305 one-time authenticator (RFC 8439 section 2.5).
    public static func poly1305(_ key32: [UInt8], _ msg: [UInt8]) -> [UInt8] {
        var rb = Array(key32[0..<16])
        rb[3] &= 15; rb[7] &= 15; rb[11] &= 15; rb[15] &= 15; rb[4] &= 252; rb[8] &= 252; rb[12] &= 252
        let r = Ed25519.Big(le: rb)
        let s = Ed25519.Big(le: Array(key32[16..<32]))
        let p = Ed25519.Big(1).shiftedLeft(130) - Ed25519.Big(5)
        var acc = Ed25519.Big([])
        var i = 0
        while i < msg.count {
            let n = min(16, msg.count - i)
            var block = Array(msg[i..<(i + n)])
            block.append(1)
            acc = ((acc + Ed25519.Big(le: block)) * r).mod(p)
            i += n
        }
        return (acc + s).leBytes(16)
    }

    /// crypto_secretbox_easy: tag (16) || ciphertext.
    public static func secretbox(_ key: [UInt8], _ nonce: [UInt8], _ plaintext: [UInt8]) -> [UInt8] {
        let stream = xsalsa20Stream(key, nonce, 32 + plaintext.count)
        var c = [UInt8](repeating: 0, count: plaintext.count)
        for i in 0..<plaintext.count { c[i] = plaintext[i] ^ stream[32 + i] }
        return poly1305(Array(stream[0..<32]), c) + c
    }

    /// crypto_secretbox_open_easy: the plaintext, or nil when the tag does not verify.
    public static func secretboxOpen(_ key: [UInt8], _ nonce: [UInt8], _ boxed: [UInt8]) -> [UInt8]? {
        guard boxed.count >= 16 else { return nil }
        let c = Array(boxed[16...])
        let stream = xsalsa20Stream(key, nonce, 32 + c.count)
        let tag = poly1305(Array(stream[0..<32]), c)
        var diff: UInt8 = 0
        for i in 0..<16 { diff |= tag[i] ^ boxed[i] }
        if diff != 0 { return nil }
        var out = [UInt8](repeating: 0, count: c.count)
        for i in 0..<c.count { out[i] = c[i] ^ stream[32 + i] }
        return out
    }

    private static func boxKey(_ sk: [UInt8], _ pk: [UInt8]) -> [UInt8]? {
        guard let shared = x25519(sk, pk) else { return nil }
        return hsalsa20(shared, [UInt8](repeating: 0, count: 16))
    }
    private static func sealedNonce(_ ephemeralPk: [UInt8], _ recipientPkX: [UInt8]) -> [UInt8] {
        return Blake2b.hash(ephemeralPk + recipientPkX, outLen: 24)
    }

    /// True when the field starts with the marker (it may still fail to open).
    public static func isSealed(_ field: [UInt8]) -> Bool { field.count >= 4 && Array(field[0..<4]) == sealedMagic }

    /// Seal `plaintext` to the recipient's 32-byte Ed25519 public key. The ephemeral secret key is random unless given (tests).
    public static func seal(_ plaintext: [UInt8], recipientPublicKey: [UInt8], ephemeralSecretKey: [UInt8]? = nil) -> [UInt8]? {
        guard let rpk = ed25519PublicKeyToX25519(recipientPublicKey) else { return nil }
        let esk = ephemeralSecretKey ?? (0..<32).map { _ in UInt8.random(in: 0...255) }
        guard esk.count == 32, let epk = x25519Base(esk), let key = boxKey(esk, rpk) else { return nil }
        let boxed = secretbox(key, sealedNonce(epk, rpk), plaintext)
        return sealedMagic + epk + boxed
    }

    /// Open a sealed field with the recipient's 32-byte Ed25519 seed: the plaintext, or nil when it is not a sealed message or the key does not open it.
    public static func openSealed(_ field: [UInt8], recipientSeed: [UInt8]) -> [UInt8]? {
        guard isSealed(field), field.count >= sealedOverhead, recipientSeed.count == 32 else { return nil }
        let sk = ed25519SeedToX25519(recipientSeed)
        guard let pk = x25519Base(sk) else { return nil }
        let epk = Array(field[4..<36])
        guard let key = boxKey(sk, epk) else { return nil }
        return secretboxOpen(key, sealedNonce(epk, pk), Array(field[36...]))
    }
}
