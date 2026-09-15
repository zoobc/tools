// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Crypto
import Foundation

/// Hex, base32 (no padding), base58/base58check (Bitcoin and Ripple alphabets), bech32/bech32m, SS58.
public enum Enc {
    public static let bitcoinAlphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".utf8)
    public static let rippleAlphabet = Array("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz".utf8)
    private static let b32 = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
    private static let charset = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l".utf8)
    private static let gen: [UInt32] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]

    public static func isHex(_ s: String, _ n: Int = 0) -> Bool {
        s.utf8.count % 2 == 0 && (n <= 0 || s.utf8.count == n) && s.utf8.allSatisfy { ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 70) || ($0 >= 97 && $0 <= 102) }
    }
    public static func hex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
    public static func unhex(_ s: String) -> [UInt8]? {
        guard isHex(s) else { return nil }
        let u = Array(s.utf8)
        func v(_ c: UInt8) -> UInt8 { c <= 57 ? c - 48 : (c <= 70 ? c - 55 : c - 87) }
        return stride(from: 0, to: u.count, by: 2).map { v(u[$0]) << 4 | v(u[$0 + 1]) }
    }
    public static func sha256(_ b: [UInt8]) -> [UInt8] { Array(Crypto.SHA256.hash(data: b)) }

    public static func base32Encode(_ data: [UInt8]) -> String {
        var out: [UInt8] = []; var buf: UInt32 = 0; var bits = 0
        for b in data {
            buf = ((buf << 8) | UInt32(b)) & 0x1fff; bits += 8
            while bits >= 5 { bits -= 5; out.append(b32[Int((buf >> UInt32(bits)) & 31)]) }
        }
        if bits > 0 { out.append(b32[Int((buf << UInt32(5 - bits)) & 31)]) }
        return String(decoding: out, as: UTF8.self)
    }
    public static func base32Decode(_ s: String) -> [UInt8]? {
        var out: [UInt8] = []; var buf: UInt32 = 0; var bits = 0
        for c in s.utf8 {
            guard let v = b32.firstIndex(of: c) else { return nil }
            buf = ((buf << 5) | UInt32(v)) & 0x1fff; bits += 5
            if bits >= 8 { bits -= 8; out.append(UInt8((buf >> UInt32(bits)) & 0xff)) }
        }
        return out
    }

    public static func base58Decode(_ s: String, _ alphabet: [UInt8] = bitcoinAlphabet) -> [UInt8]? {
        var big: [UInt32] = []   // little-endian base-256 digits
        for c in s.utf8 {
            guard let idx = alphabet.firstIndex(of: c) else { return nil }
            var carry = UInt32(idx)
            for i in 0..<big.count { let v = big[i] * 58 + carry; big[i] = v & 0xff; carry = v >> 8 }
            while carry > 0 { big.append(carry & 0xff); carry >>= 8 }
        }
        let zeros = s.utf8.prefix { $0 == alphabet[0] }.count
        return [UInt8](repeating: 0, count: zeros) + big.reversed().map { UInt8($0) }
    }
    public static func base58Encode(_ data: [UInt8], _ alphabet: [UInt8] = bitcoinAlphabet) -> String {
        var digits: [UInt32] = []
        for b in data {
            var carry = UInt32(b)
            for i in 0..<digits.count { let v = (digits[i] << 8) + carry; digits[i] = v % 58; carry = v / 58 }
            while carry > 0 { digits.append(carry % 58); carry /= 58 }
        }
        let zeros = data.prefix { $0 == 0 }.count
        let out = [UInt8](repeating: alphabet[0], count: zeros) + digits.reversed().map { alphabet[Int($0)] }
        return String(decoding: out, as: UTF8.self)
    }
    public static func base58CheckDecode(_ s: String, _ alphabet: [UInt8] = bitcoinAlphabet) -> [UInt8]? {
        guard let raw = base58Decode(s, alphabet), raw.count >= 5 else { return nil }
        let body = Array(raw[0..<(raw.count - 4)])
        let sum = sha256(sha256(body))
        return Array(sum[0..<4]) == Array(raw[(raw.count - 4)...]) ? body : nil
    }

    private static func polymod(_ values: [UInt32]) -> UInt32 {
        var chk: UInt32 = 1
        for v in values {
            let b = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in 0..<5 where (b >> UInt32(i)) & 1 == 1 { chk ^= gen[i] }
        }
        return chk
    }
    private static func hrpExpand(_ hrp: String) -> [UInt32] { hrp.utf8.map { UInt32($0 >> 5) } + [0] + hrp.utf8.map { UInt32($0 & 31) } }

    /// (hrp, 5-bit data without checksum, "bech32" | "bech32m").
    public static func bech32DecodeRaw(_ s: String) -> (String, [UInt8], String)? {
        if s.utf8.count > 1023 || (s.lowercased() != s && s.uppercased() != s) { return nil }
        let low = Array(s.lowercased().utf8)
        guard let pos = low.lastIndex(of: UInt8(ascii: "1")), pos >= 1, pos + 7 <= low.count else { return nil }
        let hrp = String(decoding: low[0..<pos], as: UTF8.self)
        var data: [UInt8] = []
        for c in low[(pos + 1)...] { guard let v = charset.firstIndex(of: c) else { return nil }; data.append(UInt8(v)) }
        let pm = polymod(hrpExpand(hrp) + data.map { UInt32($0) })
        let enc: String
        switch pm { case 1: enc = "bech32"; case 0x2bc830a3: enc = "bech32m"; default: return nil }
        return (hrp, Array(data[0..<(data.count - 6)]), enc)
    }
    public static func convertBits(_ data: [UInt8], _ from: Int, _ to: Int, _ pad: Bool) -> [UInt8]? {
        var acc = 0, bits = 0; var out: [UInt8] = []; let maxv = (1 << to) - 1
        for v in data {
            if Int(v) >> from != 0 { return nil }
            acc = (acc << from) | Int(v); bits += from
            while bits >= to { bits -= to; out.append(UInt8((acc >> bits) & maxv)) }
        }
        if pad { if bits > 0 { out.append(UInt8((acc << (to - bits)) & maxv)) } }
        else if bits >= from || ((acc << (to - bits)) & maxv) != 0 { return nil }
        return out
    }
    /// (hrp, witness version, program) of a segwit address.
    public static func segwitDecode(_ s: String) -> (String, Int, [UInt8])? {
        guard let raw = bech32DecodeRaw(s), let first = raw.1.first else { return nil }
        let (hrp, data, enc) = raw
        let version = Int(first)
        guard let prog = convertBits(Array(data.dropFirst()), 5, 8, false), prog.count >= 2, prog.count <= 40, version <= 16 else { return nil }
        if version == 0 && prog.count != 20 && prog.count != 32 { return nil }
        if (version == 0) != (enc == "bech32") { return nil }
        return (hrp, version, prog)
    }
    /// Plain bech32 with an 8-bit payload (Cardano addresses).
    public static func bech32DecodePlain(_ s: String) -> (String, [UInt8])? {
        guard let raw = bech32DecodeRaw(s), raw.2 == "bech32", let b = convertBits(raw.1, 5, 8, false) else { return nil }
        return (raw.0, b)
    }
    /// (prefix, 32-byte account id) of an SS58 address; checksum = BLAKE2b-512("SS58PRE" || body)[0..1].
    public static func ss58Decode(_ s: String) -> (Int, [UInt8])? {
        guard let raw = base58Decode(s), let r0 = raw.first else { return nil }
        let plen: Int, prefix: Int
        if raw.count >= 35 && r0 < 64 { plen = 1; prefix = Int(r0) }
        else if raw.count >= 36 && r0 >= 64 && r0 < 128 { plen = 2; prefix = ((Int(r0) & 0x3f) << 2) | (Int(raw[1]) >> 6) | ((Int(raw[1]) & 0x3f) << 8) }
        else { return nil }
        let body = Array(raw[0..<(raw.count - 2)])
        if body.count - plen != 32 { return nil }
        let sum = Blake2b.hash512(Array("SS58PRE".utf8) + body)
        if sum[0] != raw[raw.count - 2] || sum[1] != raw[raw.count - 1] { return nil }
        return (prefix, Array(body[plen...]))
    }
}

/// Little-endian byte helpers.
public enum LE {
    public static func u16(_ v: Int) -> [UInt8] { [UInt8(v & 0xff), UInt8((v >> 8) & 0xff)] }
    public static func u32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8((v >> UInt32(8 * $0)) & 0xff) } }
    public static func i32(_ v: Int32) -> [UInt8] { u32(UInt32(bitPattern: v)) }
    public static func i64(_ v: Int64) -> [UInt8] { let u = UInt64(bitPattern: v); return (0..<8).map { UInt8((u >> UInt64(8 * $0)) & 0xff) } }
    public static func readI64(_ b: [UInt8], _ off: Int) -> Int64 { var u: UInt64 = 0; for i in (0..<8).reversed() { u = (u << 8) | UInt64(b[off + i]) }; return Int64(bitPattern: u) }
}
