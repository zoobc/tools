// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

/// SHA3-256 (FIPS 202): Keccak-f[1600], rate 136, domain byte 0x06. Neither CryptoKit nor
/// swift-crypto offers SHA-3, so it lives here.
public enum SHA3 {
    private static let rc: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    private static let rot: [Int] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]

    @inline(__always) private static func rotl(_ x: UInt64, _ n: Int) -> UInt64 { n == 0 ? x : (x << UInt64(n)) | (x >> UInt64(64 - n)) }

    private static func keccakF(_ s: inout [UInt64]) {
        var b = [UInt64](repeating: 0, count: 25)
        var c = [UInt64](repeating: 0, count: 5)
        for round in 0..<24 {
            for x in 0..<5 { c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20] }
            for x in 0..<5 {
                let d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1)
                for y in stride(from: 0, to: 25, by: 5) { s[x + y] ^= d }
            }
            for x in 0..<5 { for y in 0..<5 { b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], rot[x + 5 * y]) } }
            for y in stride(from: 0, to: 25, by: 5) { for x in 0..<5 { s[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]) } }
            s[0] ^= rc[round]
        }
    }

    /// SHA3-256 of the concatenation of the parts.
    public static func hash256(_ parts: [UInt8]...) -> [UInt8] {
        var msg: [UInt8] = []
        for p in parts { msg.append(contentsOf: p) }
        let rate = 136
        var padded = msg
        padded.append(0x06)
        while padded.count % rate != 0 { padded.append(0) }
        padded[padded.count - 1] |= 0x80
        var s = [UInt64](repeating: 0, count: 25)
        var off = 0
        while off < padded.count {
            for i in 0..<(rate / 8) {
                var lane: UInt64 = 0
                for j in (0..<8).reversed() { lane = (lane << 8) | UInt64(padded[off + 8 * i + j]) }
                s[i] ^= lane
            }
            keccakF(&s)
            off += rate
        }
        var out = [UInt8](repeating: 0, count: 32)
        for i in 0..<4 { var lane = s[i]; for j in 0..<8 { out[8 * i + j] = UInt8(lane & 0xff); lane >>= 8 } }
        return out
    }
}
