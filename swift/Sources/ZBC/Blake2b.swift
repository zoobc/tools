// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

/// BLAKE2b (RFC 7693), unkeyed, with a chosen output length: 64 for the SS58 checksum, 24 for the nonce of a sealed message.
public enum Blake2b {
    private static let iv: [UInt64] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
                                       0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ]
    @inline(__always) private static func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 { (x >> n) | (x << (64 - n)) }

    public static func hash512(_ msg: [UInt8]) -> [UInt8] { hash(msg, outLen: 64) }

    /// BLAKE2b with an output of `outLen` bytes (1...64).
    public static func hash(_ msg: [UInt8], outLen: Int) -> [UInt8] {
        var h = iv
        h[0] ^= 0x01010000 ^ UInt64(outLen)
        var padded = msg
        let padLen = max(128, (msg.count + 127) / 128 * 128)
        padded.append(contentsOf: [UInt8](repeating: 0, count: padLen - msg.count))
        var off = 0
        while off < padded.count {
            let last = off + 128 >= padded.count
            let t = UInt64(last ? msg.count : off + 128)
            var m = [UInt64](repeating: 0, count: 16)
            for i in 0..<16 { var v: UInt64 = 0; for j in (0..<8).reversed() { v = (v << 8) | UInt64(padded[off + 8 * i + j]) }; m[i] = v }
            var v = h + iv
            v[12] ^= t
            if last { v[14] = ~v[14] }
            func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
                v[a] = v[a] &+ v[b] &+ x; v[d] = rotr(v[d] ^ v[a], 32)
                v[c] = v[c] &+ v[d]; v[b] = rotr(v[b] ^ v[c], 24)
                v[a] = v[a] &+ v[b] &+ y; v[d] = rotr(v[d] ^ v[a], 16)
                v[c] = v[c] &+ v[d]; v[b] = rotr(v[b] ^ v[c], 63)
            }
            for r in 0..<12 {
                let s = sigma[r]
                g(0, 4, 8, 12, m[s[0]], m[s[1]]); g(1, 5, 9, 13, m[s[2]], m[s[3]]); g(2, 6, 10, 14, m[s[4]], m[s[5]]); g(3, 7, 11, 15, m[s[6]], m[s[7]])
                g(0, 5, 10, 15, m[s[8]], m[s[9]]); g(1, 6, 11, 12, m[s[10]], m[s[11]]); g(2, 7, 8, 13, m[s[12]], m[s[13]]); g(3, 4, 9, 14, m[s[14]], m[s[15]])
            }
            for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
            off += 128
        }
        var out: [UInt8] = []
        for i in 0..<8 { var x = h[i]; for _ in 0..<8 { out.append(UInt8(x & 0xff)); x >>= 8 } }
        return Array(out.prefix(outLen))
    }
}
