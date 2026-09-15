// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import java.math.BigInteger
import java.security.MessageDigest

/** Hex, base32 (no padding), base58/base58check (Bitcoin and Ripple alphabets), bech32/bech32m, SS58. */
object Encoding {
    const val BITCOIN_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    const val RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
    private const val B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val GEN = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)

    fun isHex(s: String, n: Int = 0): Boolean = s.length % 2 == 0 && (n <= 0 || s.length == n) && s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
    fun hexToBytes(s: String): ByteArray {
        require(isHex(s)) { "not valid hex" }
        return ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }
    fun bytesToHex(b: ByteArray): String = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    fun sha3(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA3-256").also { md -> parts.forEach { md.update(it) } }.digest()

    fun base32Encode(data: ByteArray): String {
        val out = StringBuilder(); var buf = 0; var bits = 0
        for (b in data) {
            buf = ((buf shl 8) or (b.toInt() and 0xff)) and 0x1fff; bits += 8
            while (bits >= 5) { bits -= 5; out.append(B32[(buf shr bits) and 31]) }
        }
        if (bits > 0) out.append(B32[(buf shl (5 - bits)) and 31])
        return out.toString()
    }
    fun base32Decode(s: String): ByteArray? {
        val out = ArrayList<Byte>(); var buf = 0; var bits = 0
        for (c in s) {
            val v = B32.indexOf(c); if (v < 0) return null
            buf = ((buf shl 5) or v) and 0x1fff; bits += 5
            if (bits >= 8) { bits -= 8; out.add(((buf shr bits) and 0xff).toByte()) }
        }
        return out.toByteArray()
    }

    fun base58Decode(s: String, alphabet: String = BITCOIN_ALPHABET): ByteArray? {
        var n = BigInteger.ZERO
        for (c in s) { val v = alphabet.indexOf(c); if (v < 0) return null; n = n.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(v.toLong())) }
        val body = if (n.signum() == 0) ByteArray(0) else n.toByteArray().let { if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        val zeros = s.takeWhile { it == alphabet[0] }.length
        return ByteArray(zeros) + body
    }
    fun base58Encode(data: ByteArray, alphabet: String = BITCOIN_ALPHABET): String {
        var n = BigInteger(1, data); val sb = StringBuilder()
        while (n.signum() > 0) { val d = n.divideAndRemainder(BigInteger.valueOf(58)); sb.append(alphabet[d[1].toInt()]); n = d[0] }
        for (b in data) { if (b != 0.toByte()) break; sb.append(alphabet[0]) }
        return sb.reverse().toString()
    }
    fun base58CheckDecode(s: String, alphabet: String = BITCOIN_ALPHABET): ByteArray? {
        val raw = base58Decode(s, alphabet) ?: return null
        if (raw.size < 5) return null
        val body = raw.copyOf(raw.size - 4)
        val sum = sha256(sha256(body))
        for (i in 0 until 4) if (sum[i] != raw[raw.size - 4 + i]) return null
        return body
    }

    private fun polymod(values: List<Int>): Int {
        var chk = 1
        for (v in values) { val b = chk ushr 25; chk = ((chk and 0x1ffffff) shl 5) xor v; for (i in 0 until 5) if ((b shr i) and 1 == 1) chk = chk xor GEN[i] }
        return chk
    }
    private fun hrpExpand(hrp: String) = hrp.map { it.code shr 5 } + 0 + hrp.map { it.code and 31 }

    /** Triple(hrp, 5-bit data without checksum, "bech32" | "bech32m"), or null. */
    fun bech32DecodeRaw(s: String): Triple<String, List<Int>, String>? {
        if (s.length > 1023 || (s.lowercase() != s && s.uppercase() != s)) return null
        val low = s.lowercase(); val pos = low.lastIndexOf('1')
        if (pos < 1 || pos + 7 > low.length) return null
        val hrp = low.substring(0, pos)
        val data = low.substring(pos + 1).map { CHARSET.indexOf(it).also { v -> if (v < 0) return null } }
        val enc = when (polymod(hrpExpand(hrp) + data)) { 1 -> "bech32"; 0x2bc830a3 -> "bech32m"; else -> return null }
        return Triple(hrp, data.dropLast(6), enc)
    }
    fun convertBits(data: List<Int>, from: Int, to: Int, pad: Boolean): List<Int>? {
        var acc = 0; var bits = 0; val out = ArrayList<Int>(); val maxv = (1 shl to) - 1
        for (v in data) {
            if (v < 0 || (v shr from) != 0) return null
            acc = (acc shl from) or v; bits += from
            while (bits >= to) { bits -= to; out.add((acc shr bits) and maxv) }
        }
        if (pad) { if (bits > 0) out.add((acc shl (to - bits)) and maxv) }
        else if (bits >= from || ((acc shl (to - bits)) and maxv) != 0) return null
        return out
    }
    /** Triple(hrp, witness version, program) of a segwit address, or null. */
    fun segwitDecode(s: String): Triple<String, Int, ByteArray>? {
        val (hrp, data, enc) = bech32DecodeRaw(s) ?: return null
        if (data.isEmpty()) return null
        val version = data[0]
        val prog = convertBits(data.drop(1), 5, 8, false) ?: return null
        if (prog.size < 2 || prog.size > 40 || version > 16) return null
        if (version == 0 && prog.size != 20 && prog.size != 32) return null
        if ((version == 0) != (enc == "bech32")) return null
        return Triple(hrp, version, prog.map { it.toByte() }.toByteArray())
    }
    /** Plain bech32 with an 8-bit payload (Cardano addresses). */
    fun bech32DecodePlain(s: String): Pair<String, ByteArray>? {
        val (hrp, data, enc) = bech32DecodeRaw(s) ?: return null
        if (enc != "bech32") return null
        val b = convertBits(data, 5, 8, false) ?: return null
        return hrp to b.map { it.toByte() }.toByteArray()
    }
    /** Pair(prefix, 32-byte account id) of an SS58 address; checksum = BLAKE2b-512("SS58PRE" || body)[0..1]. */
    fun ss58Decode(s: String): Pair<Int, ByteArray>? {
        val raw = base58Decode(s) ?: return null
        val r0 = raw.getOrNull(0)?.toInt()?.and(0xff) ?: return null
        val (plen, prefix) = when {
            raw.size >= 35 && r0 < 64 -> 1 to r0
            raw.size >= 36 && r0 in 64..127 -> 2 to (((r0 and 0x3f) shl 2) or ((raw[1].toInt() and 0xff) shr 6) or ((raw[1].toInt() and 0x3f) shl 8))
            else -> return null
        }
        val body = raw.copyOf(raw.size - 2)
        if (body.size - plen != 32) return null
        val sum = Blake2b.digest("SS58PRE".toByteArray() + body)
        if (sum[0] != raw[raw.size - 2] || sum[1] != raw[raw.size - 1]) return null
        return prefix to body.copyOfRange(plen, body.size)
    }
}
