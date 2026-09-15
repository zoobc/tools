// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

/** BLAKE2b-512 (RFC 7693), unkeyed; used for the SS58 checksum only, so the library has no crypto dependency. */
object Blake2b {
    private val IV = longArrayOf(
        0x6a09e667f3bcc908L, -0x4498517a7b3558c5L, 0x3c6ef372fe94f82bL, -0x5ab00ac5a0e2c90fL,
        0x510e527fade682d1L, -0x64fa9773d4c193e1L, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
    )
    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15), intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4), intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13), intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11), intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5), intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15), intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
    )

    fun digest(msg: ByteArray, outLen: Int = 64): ByteArray {
        val h = IV.copyOf()
        h[0] = h[0] xor (0x01010000L xor outLen.toLong())
        val padded = ByteArray(maxOf(128, (msg.size + 127) / 128 * 128))
        msg.copyInto(padded)
        var off = 0
        while (off < padded.size) {
            val last = off + 128 >= padded.size
            val t = if (last) msg.size.toLong() else (off + 128).toLong()
            val m = LongArray(16) { i -> readLe(padded, off + 8 * i) }
            val v = LongArray(16)
            h.copyInto(v, 0); IV.copyInto(v, 8)
            v[12] = v[12] xor t
            if (last) v[14] = v[14].inv()
            fun g(a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
                v[a] = v[a] + v[b] + x; v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 32)
                v[c] = v[c] + v[d]; v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 24)
                v[a] = v[a] + v[b] + y; v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 16)
                v[c] = v[c] + v[d]; v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 63)
            }
            for (r in 0 until 12) {
                val s = SIGMA[r]
                g(0, 4, 8, 12, m[s[0]], m[s[1]]); g(1, 5, 9, 13, m[s[2]], m[s[3]]); g(2, 6, 10, 14, m[s[4]], m[s[5]]); g(3, 7, 11, 15, m[s[6]], m[s[7]])
                g(0, 5, 10, 15, m[s[8]], m[s[9]]); g(1, 6, 11, 12, m[s[10]], m[s[11]]); g(2, 7, 8, 13, m[s[12]], m[s[13]]); g(3, 4, 9, 14, m[s[14]], m[s[15]])
            }
            for (i in 0 until 8) h[i] = h[i] xor v[i] xor v[i + 8]
            off += 128
        }
        val out = ByteArray(outLen)
        for (i in 0 until outLen) out[i] = (h[i shr 3] ushr (8 * (i and 7))).toByte()
        return out
    }

    private fun readLe(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }
}
