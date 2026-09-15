// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import java.math.BigInteger
import java.security.MessageDigest

/**
 * Ed25519 (RFC 8032) on BigInteger: public key from a 32-byte seed, detached signatures,
 * verification. The scalar multiplication takes the same path for every scalar at the Kotlin
 * level; BigInteger is not constant time, so keep seeds on machines you trust.
 */
object Ed25519 {
    private val P = BigInteger.TWO.pow(255) - BigInteger.valueOf(19)
    private val L = BigInteger.TWO.pow(252) + BigInteger("27742317777372353535851937790883648493")
    private val D = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P)
    private val I = BigInteger.TWO.modPow((P - BigInteger.ONE).divide(BigInteger.valueOf(4)), P)

    private class Pt(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger)

    private fun recoverX(y: BigInteger, sign: Int): BigInteger {
        val y2 = y.multiply(y).mod(P)
        val u = (y2 - BigInteger.ONE).mod(P)
        val v = (D.multiply(y2) + BigInteger.ONE).mod(P)
        var x = u.multiply(v.modInverse(P)).modPow((P + BigInteger.valueOf(3)).divide(BigInteger.valueOf(8)), P)
        if (v.multiply(x).multiply(x).subtract(u).mod(P) != BigInteger.ZERO) x = x.multiply(I).mod(P)
        if (v.multiply(x).multiply(x).subtract(u).mod(P) != BigInteger.ZERO) throw IllegalArgumentException("not a point on the curve")
        if (x.testBit(0) != (sign == 1)) x = P - x
        return x
    }

    private val GY = BigInteger.valueOf(4).multiply(BigInteger.valueOf(5).modInverse(P)).mod(P)
    private val GX = recoverX(GY, 0)
    private val G = Pt(GX, GY, BigInteger.ONE, GX.multiply(GY).mod(P))
    private val ZERO = Pt(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)

    private fun add(p: Pt, q: Pt): Pt {
        val a = (p.y - p.x).multiply(q.y - q.x).mod(P)
        val b = (p.y + p.x).multiply(q.y + q.x).mod(P)
        val c = BigInteger.TWO.multiply(p.t).multiply(q.t).multiply(D).mod(P)
        val d = BigInteger.TWO.multiply(p.z).multiply(q.z).mod(P)
        val e = b - a; val f = d - c; val g = d + c; val h = b + a
        return Pt(e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P))
    }

    private fun mul(p: Pt, s: BigInteger): Pt {
        var r = ZERO; var q = p
        for (i in 0 until 256) {
            val sum = add(r, q)
            r = if (s.testBit(i)) sum else r
            q = add(q, q)
        }
        return r
    }

    private fun encode(p: Pt): ByteArray {
        val zi = p.z.modInverse(P)
        val x = p.x.multiply(zi).mod(P); val y = p.y.multiply(zi).mod(P)
        val v = if (x.testBit(0)) y.setBit(255) else y
        return toLe(v, 32)
    }

    private fun decode(b: ByteArray): Pt {
        require(b.size == 32) { "point must be 32 bytes" }
        val raw = fromLe(b)
        val sign = if (raw.testBit(255)) 1 else 0
        val y = raw.clearBit(255)
        if (y >= P) throw IllegalArgumentException("non-canonical point")
        val x = recoverX(y, sign)
        if (x == BigInteger.ZERO && sign == 1) throw IllegalArgumentException("non-canonical point")
        return Pt(x, y, BigInteger.ONE, x.multiply(y).mod(P))
    }

    private fun fromLe(b: ByteArray): BigInteger = BigInteger(1, b.reversedArray())
    private fun toLe(v: BigInteger, n: Int): ByteArray {
        val be = v.toByteArray()
        val out = ByteArray(n)
        var j = 0
        for (i in be.indices.reversed()) { if (j < n) out[j++] = be[i] }
        return out
    }
    private fun sha512(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").also { md -> parts.forEach { md.update(it) } }.digest()
    private fun clamp(h: ByteArray): BigInteger {
        val k = h.copyOf(32)
        k[0] = (k[0].toInt() and 248).toByte(); k[31] = (k[31].toInt() and 127).toByte(); k[31] = (k[31].toInt() or 64).toByte()
        return fromLe(k)
    }

    /** The 32-byte public key of a 32-byte seed. */
    fun publicKey(seed: ByteArray): ByteArray {
        require(seed.size == 32) { "seed must be 32 bytes" }
        return encode(mul(G, clamp(sha512(seed))))
    }

    /** Detached 64-byte signature of [message] with the 32-byte seed. */
    fun sign(message: ByteArray, seed: ByteArray): ByteArray {
        require(seed.size == 32) { "seed must be 32 bytes" }
        val h = sha512(seed)
        val a = clamp(h)
        val prefix = h.copyOfRange(32, 64)
        val pub = encode(mul(G, a))
        val r = fromLe(sha512(prefix, message)).mod(L)
        val bigR = encode(mul(G, r))
        val k = fromLe(sha512(bigR, pub, message)).mod(L)
        return bigR + toLe((r + k.multiply(a)).mod(L), 32)
    }

    /** True when [signature] is a valid signature of [message] by [pub]. Never throws. */
    fun verify(message: ByteArray, signature: ByteArray, pub: ByteArray): Boolean = try {
        if (signature.size != 64 || pub.size != 32) false else {
            val a = decode(pub)
            val bigR = decode(signature.copyOf(32))
            val s = fromLe(signature.copyOfRange(32, 64))
            if (s >= L) false else {
                val k = fromLe(sha512(signature.copyOf(32), pub, message)).mod(L)
                encode(mul(G, s)).contentEquals(encode(add(bigR, mul(a, k))))
            }
        }
    } catch (e: Exception) { false }
}
