// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Crypto
import Foundation

/// A 32-byte seed with its public key (spec/signing.md section 1).
public struct KeyPair {
    public let seed: [UInt8]
    public let publicKey: [UInt8]
    private let signing: Curve25519.Signing.PrivateKey

    public init(seed: [UInt8]) throws {
        guard seed.count == 32, let k = try? Curve25519.Signing.PrivateKey(rawRepresentation: seed) else { throw Address.Invalid(message: "Private key must be 64 hex characters (32 bytes)") }
        self.seed = seed; signing = k; publicKey = Array(k.publicKey.rawRepresentation)
    }
    public init(hex: String) throws {
        guard Enc.isHex(hex, 64), let s = Enc.unhex(hex) else { throw Address.Invalid(message: "Private key must be 64 hex characters (32 bytes)") }
        try self.init(seed: s)
    }
    public static func random() -> KeyPair { try! KeyPair(seed: Array(Curve25519.Signing.PrivateKey().rawRepresentation)) }

    /// The ZBC_ form of the public key.
    public var address: String { Address.encode(publicKey, prefix: "ZBC")! }
    /// The ZNK_ form of the same key.
    public var nodeAddress: String { Address.encode(publicKey, prefix: "ZNK")! }
    /// 36-byte typed account address: 00000000 || public key.
    public var accountBytes: [UInt8] { Address.typed(AccountType.zoobc, publicKey) }
    /// Detached Ed25519 signature (64 bytes).
    public func sign(_ message: [UInt8]) -> [UInt8] { Array(try! signing.signature(for: message)) }
}

/// Ed25519 verification that never throws.
public enum Ed25519 {
    public static func verify(_ message: [UInt8], _ signature: [UInt8], _ publicKey: [UInt8]) -> Bool {
        guard signature.count == 64, let pk = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKey) else { return false }
        return pk.isValidSignature(signature, for: message)
    }
}

/// BIP-39 mnemonics and SLIP-10 derivation along m/44'/883'/index'.
public enum Wallet {
    public static let zoobcCoinType = 883

    /// True for 12, 15, 18, 21 or 24 English words with a valid checksum.
    public static func validateMnemonic(_ mnemonic: String) -> Bool {
        let words = mnemonic.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" }).map(String.init)
        guard [12, 15, 18, 21, 24].contains(words.count) else { return false }
        var bits = ""
        for w in words { guard let i = bip39Words.firstIndex(of: w) else { return false }; bits += binary(i, 11) }
        let cs = words.count / 3
        let entropyBits = bits.dropLast(cs)
        var entropy: [UInt8] = []
        var idx = entropyBits.startIndex
        while idx < entropyBits.endIndex { let e = entropyBits.index(idx, offsetBy: 8); entropy.append(UInt8(entropyBits[idx..<e], radix: 2)!); idx = e }
        let sum = Enc.sha256(entropy)
        return String(bits.suffix(cs)) == String(binary(Int(sum[0]), 8).prefix(cs))
    }
    private static func binary(_ v: Int, _ width: Int) -> String { let s = String(v, radix: 2); return String(repeating: "0", count: max(0, width - s.count)) + s }

    public static func mnemonicFromEntropy(_ entropy: [UInt8]) throws -> String {
        guard entropy.count >= 16, entropy.count <= 32, entropy.count % 4 == 0 else { throw Address.Invalid(message: "entropy must be 16-32 bytes, a multiple of 4") }
        var bits = entropy.map { binary(Int($0), 8) }.joined()
        bits += String(binary(Int(Enc.sha256(entropy)[0]), 8).prefix(entropy.count / 4))
        var words: [String] = []
        var idx = bits.startIndex
        while idx < bits.endIndex { let e = bits.index(idx, offsetBy: 11); words.append(bip39Words[Int(bits[idx..<e], radix: 2)!]); idx = e }
        return words.joined(separator: " ")
    }
    public static func generateMnemonic(words: Int = 24) throws -> String {
        var entropy = [UInt8](repeating: 0, count: (words * 11 - words / 3) / 8)
        for i in entropy.indices { entropy[i] = UInt8.random(in: 0...255, using: &SystemRandomNumberGenerator.shared) }
        return try mnemonicFromEntropy(entropy)
    }

    /// PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048, 64).
    public static func mnemonicToSeed(_ mnemonic: String, passphrase: String = "") -> [UInt8] {
        let password = SymmetricKey(data: Array(mnemonic.split(separator: " ").joined(separator: " ").utf8))
        var u = Array(HMAC<SHA512>.authenticationCode(for: Array(("mnemonic" + passphrase).utf8) + [0, 0, 0, 1], using: password))
        var t = u
        for _ in 1..<2048 {
            u = Array(HMAC<SHA512>.authenticationCode(for: u, using: password))
            for j in 0..<64 { t[j] ^= u[j] }
        }
        return t
    }

    /// SLIP-10 for Ed25519 along a hardened-only path such as m/44'/883'/0'; the 32-byte key.
    public static func slip10Derive(_ path: String, seed: [UInt8]) throws -> [UInt8] {
        let segs = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard segs.first == "m", segs.count >= 2, segs.dropFirst().allSatisfy({ $0.hasSuffix("'") && $0.count >= 2 && $0.dropLast().allSatisfy { $0.isNumber } }) else {
            throw Address.Invalid(message: "invalid derivation path: \(path)")
        }
        var digest = Array(HMAC<SHA512>.authenticationCode(for: seed, using: SymmetricKey(data: Array("ed25519 seed".utf8))))
        var key = Array(digest[0..<32]), chain = Array(digest[32..<64])
        for seg in segs.dropFirst() {
            guard let index = UInt64(seg.dropLast()), index < 0x8000_0000 else { throw Address.Invalid(message: "path index too large") }
            let i = UInt32(index) + 0x8000_0000
            let data: [UInt8] = [0] + key + [UInt8(i >> 24), UInt8((i >> 16) & 0xff), UInt8((i >> 8) & 0xff), UInt8(i & 0xff)]
            digest = Array(HMAC<SHA512>.authenticationCode(for: data, using: SymmetricKey(data: chain)))
            key = Array(digest[0..<32]); chain = Array(digest[32..<64])
        }
        return key
    }

    /// Account `index` of a mnemonic wallet: m/44'/883'/index'. Returns the key pair and its path.
    public static func account(_ mnemonic: String, index: Int, passphrase: String = "") throws -> (KeyPair, String) {
        let path = "m/44'/\(zoobcCoinType)'/\(index)'"
        return (try KeyPair(seed: try slip10Derive(path, seed: mnemonicToSeed(mnemonic, passphrase: passphrase))), path)
    }
}

extension SystemRandomNumberGenerator { static var shared = SystemRandomNumberGenerator() }
