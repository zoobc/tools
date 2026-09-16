// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Sealed transaction messages (spec/signing.md section 8): "ZBE1" || libsodium sealed box to the recipient's
 * Ed25519 key converted to X25519. X25519 (RFC 7748) on BigInteger, HSalsa20, XSalsa20 and Poly1305 written
 * here: the JDK has X25519 but neither Salsa20 nor Poly1305, and one self-contained rendering of the spec is
 * easier to check than a mix.
 */
object Encryption {
    /** The 4-byte marker in front of a sealed message field. */
    @JvmField val SEALED_MAGIC: ByteArray = "ZBE1".toByteArray()
    /** How much longer a sealed field is than its plaintext: marker 4 + ephemeral key 32 + tag 16. */
    const val SEALED_OVERHEAD = 52

    private val P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19))
    private val A24 = BigInteger.valueOf(121665)
    private val MASK255 = BigInteger.TWO.pow(255).subtract(BigInteger.ONE)

    private fun fromLe(b: ByteArray): BigInteger = BigInteger(1, b.reversedArray())
    private fun toLe(v: BigInteger, n: Int): ByteArray {
        val be = v.toByteArray(); val out = ByteArray(n)
        var i = 0; var j = be.size - 1
        while (i < n && j >= 0) { out[i++] = be[j--] }
        return out
    }
    private fun clamp(k: ByteArray): ByteArray = k.copyOf().also { it[0] = (it[0].toInt() and 248).toByte(); it[31] = ((it[31].toInt() and 127) or 64).toByte() }

    /** X25519(scalar, u): 32 bytes. The scalar is clamped as the RFC prescribes. */
    @JvmStatic
    fun x25519(scalar: ByteArray, u: ByteArray): ByteArray {
        require(scalar.size == 32 && u.size == 32) { "X25519 takes 32-byte inputs" }
        val s = fromLe(clamp(scalar)); val x1 = fromLe(u).and(MASK255)
        var x2 = BigInteger.ONE; var z2 = BigInteger.ZERO; var x3 = x1; var z3 = BigInteger.ONE; var swap = 0
        for (t in 254 downTo 0) {
            val kt = if (s.testBit(t)) 1 else 0
            swap = swap xor kt
            if (swap == 1) { val tx = x2; x2 = x3; x3 = tx; val tz = z2; z2 = z3; z3 = tz }
            swap = kt
            val a = x2.add(z2).mod(P); val aa = a.multiply(a).mod(P); val b = x2.subtract(z2).mod(P); val bb = b.multiply(b).mod(P); val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P); val d = x3.subtract(z3).mod(P); val da = d.multiply(a).mod(P); val cb = c.multiply(b).mod(P)
            x3 = da.add(cb).mod(P).let { it.multiply(it) }.mod(P); z3 = x1.multiply(da.subtract(cb).mod(P).let { it.multiply(it) }).mod(P)
            x2 = aa.multiply(bb).mod(P); z2 = e.multiply(aa.add(A24.multiply(e)).mod(P)).mod(P)
        }
        if (swap == 1) { val tx = x2; x2 = x3; x3 = tx; val tz = z2; z2 = z3; z3 = tz }
        return toLe(x2.multiply(z2.modInverse(P)).mod(P), 32)
    }

    /** The X25519 public key of a scalar: X25519(scalar, 9). */
    @JvmStatic fun x25519Base(scalar: ByteArray): ByteArray = x25519(scalar, ByteArray(32).also { it[0] = 9 })

    /** Ed25519 public key -> X25519 public key: u = (1 + y) / (1 - y) mod p. */
    @JvmStatic
    fun ed25519PublicKeyToX25519(pk: ByteArray): ByteArray {
        require(pk.size == 32) { "public key must be 32 bytes" }
        val y = fromLe(pk).and(MASK255)
        val den = BigInteger.ONE.subtract(y).mod(P)
        require(den.signum() != 0) { "public key has no X25519 form" }
        return toLe(BigInteger.ONE.add(y).multiply(den.modInverse(P)).mod(P), 32)
    }

    /** Ed25519 seed -> X25519 secret key: the clamped first half of SHA-512(seed). */
    @JvmStatic fun ed25519SeedToX25519(seed: ByteArray): ByteArray = clamp(MessageDigest.getInstance("SHA-512").digest(seed).copyOf(32))

    private val SIGMA = intArrayOf(0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)   // "expand 32-byte k"
    private val QUARTERS = arrayOf(intArrayOf(0, 4, 8, 12), intArrayOf(5, 9, 13, 1), intArrayOf(10, 14, 2, 6), intArrayOf(15, 3, 7, 11),
        intArrayOf(0, 1, 2, 3), intArrayOf(5, 6, 7, 4), intArrayOf(10, 11, 8, 9), intArrayOf(15, 12, 13, 14))

    private fun le32(b: ByteArray, off: Int): Int = (b[off].toInt() and 0xff) or ((b[off + 1].toInt() and 0xff) shl 8) or ((b[off + 2].toInt() and 0xff) shl 16) or ((b[off + 3].toInt() and 0xff) shl 24)
    private fun put32(out: ByteArray, off: Int, v: Int) { out[off] = v.toByte(); out[off + 1] = (v ushr 8).toByte(); out[off + 2] = (v ushr 16).toByte(); out[off + 3] = (v ushr 24).toByte() }
    private fun salsaRounds(x: IntArray) {
        repeat(10) {
            for (q in QUARTERS) {
                val (a, b, c, d) = q
                x[b] = x[b] xor Integer.rotateLeft(x[a] + x[d], 7); x[c] = x[c] xor Integer.rotateLeft(x[b] + x[a], 9)
                x[d] = x[d] xor Integer.rotateLeft(x[c] + x[b], 13); x[a] = x[a] xor Integer.rotateLeft(x[d] + x[c], 18)
            }
        }
    }
    private fun salsaState(key: ByteArray): IntArray {
        val x = IntArray(16)
        x[0] = SIGMA[0]; x[5] = SIGMA[1]; x[10] = SIGMA[2]; x[15] = SIGMA[3]
        for (i in 0 until 4) { x[1 + i] = le32(key, 4 * i); x[11 + i] = le32(key, 16 + 4 * i) }
        return x
    }

    /** HSalsa20(key 32, input 16) -> 32 bytes. */
    @JvmStatic
    fun hsalsa20(key: ByteArray, input: ByteArray): ByteArray {
        val x = salsaState(key)
        for (i in 0 until 4) x[6 + i] = le32(input, 4 * i)
        salsaRounds(x)
        val out = ByteArray(32)
        intArrayOf(0, 5, 10, 15, 6, 7, 8, 9).forEachIndexed { i, w -> put32(out, 4 * i, x[w]) }
        return out
    }

    private fun salsa20Block(key: ByteArray, nonce8: ByteArray, counter: Long): ByteArray {
        val x0 = salsaState(key)
        x0[6] = le32(nonce8, 0); x0[7] = le32(nonce8, 4); x0[8] = counter.toInt(); x0[9] = (counter ushr 32).toInt()
        val x = x0.copyOf(); salsaRounds(x)
        val out = ByteArray(64)
        for (i in 0 until 16) put32(out, 4 * i, x[i] + x0[i])
        return out
    }

    /** The XSalsa20 keystream of a 32-byte key and a 24-byte nonce. */
    @JvmStatic
    fun xsalsa20Stream(key: ByteArray, nonce24: ByteArray, length: Int): ByteArray {
        val sub = hsalsa20(key, nonce24.copyOfRange(0, 16)); val nonce8 = nonce24.copyOfRange(16, 24)
        val out = ByteArray(length); var off = 0; var c = 0L
        while (off < length) { val blk = salsa20Block(sub, nonce8, c++); val n = minOf(64, length - off); System.arraycopy(blk, 0, out, off, n); off += n }
        return out
    }

    /** Poly1305 one-time authenticator (RFC 8439 section 2.5). */
    @JvmStatic
    fun poly1305(key32: ByteArray, msg: ByteArray): ByteArray {
        val r = fromLe(key32.copyOfRange(0, 16)).and(BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16)); val s = fromLe(key32.copyOfRange(16, 32))
        val p = BigInteger.TWO.pow(130).subtract(BigInteger.valueOf(5))
        var acc = BigInteger.ZERO
        var i = 0
        while (i < msg.size) {
            val n = minOf(16, msg.size - i)
            acc = acc.add(fromLe(msg.copyOfRange(i, i + n)).setBit(8 * n)).multiply(r).mod(p)
            i += n
        }
        return toLe(acc.add(s).and(BigInteger.TWO.pow(128).subtract(BigInteger.ONE)), 16)
    }

    /** crypto_secretbox_easy: tag (16) || ciphertext. */
    @JvmStatic
    fun secretbox(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val stream = xsalsa20Stream(key, nonce, 32 + plaintext.size)
        val c = ByteArray(plaintext.size) { (plaintext[it].toInt() xor stream[32 + it].toInt()).toByte() }
        return poly1305(stream.copyOfRange(0, 32), c) + c
    }

    /** crypto_secretbox_open_easy: the plaintext, or null when the tag does not verify. */
    @JvmStatic
    fun secretboxOpen(key: ByteArray, nonce: ByteArray, boxed: ByteArray): ByteArray? {
        if (boxed.size < 16) return null
        val c = boxed.copyOfRange(16, boxed.size); val stream = xsalsa20Stream(key, nonce, 32 + c.size)
        if (!MessageDigest.isEqual(poly1305(stream.copyOfRange(0, 32), c), boxed.copyOfRange(0, 16))) return null
        return ByteArray(c.size) { (c[it].toInt() xor stream[32 + it].toInt()).toByte() }
    }

    private fun boxKey(sk: ByteArray, pk: ByteArray): ByteArray = hsalsa20(x25519(sk, pk), ByteArray(16))
    private fun sealedNonce(ephemeralPk: ByteArray, recipientPkX: ByteArray): ByteArray = Blake2b.digest(ephemeralPk + recipientPkX, 24)

    /** True when the field starts with the marker (it may still fail to open). */
    @JvmStatic fun isSealed(field: ByteArray): Boolean = field.size >= 4 && field.copyOfRange(0, 4).contentEquals(SEALED_MAGIC)

    /** Seal `plaintext` to the recipient's 32-byte Ed25519 public key. The ephemeral secret key is random unless given (tests). */
    @JvmStatic
    @JvmOverloads
    fun seal(plaintext: ByteArray, recipientPublicKey: ByteArray, ephemeralSecretKey: ByteArray? = null): ByteArray {
        val rpk = ed25519PublicKeyToX25519(recipientPublicKey)
        val esk = ephemeralSecretKey ?: ByteArray(32).also { SecureRandom().nextBytes(it) }
        require(esk.size == 32) { "ephemeral secret key must be 32 bytes" }
        val epk = x25519Base(esk)
        return SEALED_MAGIC + epk + secretbox(boxKey(esk, rpk), sealedNonce(epk, rpk), plaintext)
    }

    /** Open a sealed field with the recipient's 32-byte Ed25519 seed: the plaintext, or null when it is not a sealed message or the key does not open it. */
    @JvmStatic
    fun openSealed(field: ByteArray, recipientSeed: ByteArray): ByteArray? {
        if (!isSealed(field) || field.size < SEALED_OVERHEAD || recipientSeed.size != 32) return null
        val sk = ed25519SeedToX25519(recipientSeed); val pk = x25519Base(sk); val epk = field.copyOfRange(4, 36)
        return secretboxOpen(boxKey(sk, epk), sealedNonce(epk, pk), field.copyOfRange(36, field.size))
    }
}
