// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** A 32-byte seed with its public key (spec/signing.md section 1). */
class KeyPair(seed: ByteArray) {
    val seed: ByteArray = seed.copyOf()
    val publicKey: ByteArray = Ed25519.publicKey(seed)
    /** The ZBC_ form of the public key. */
    val address: String get() = Address.encode(publicKey, "ZBC")
    /** The ZNK_ form of the same key. */
    val nodeAddress: String get() = Address.encode(publicKey, "ZNK")
    /** 36-byte typed account address: 00000000 || public key. */
    val accountBytes: ByteArray get() = Address.typed(AccountType.ZOOBC, publicKey)
    /** Detached Ed25519 signature (64 bytes). */
    fun sign(message: ByteArray): ByteArray = Ed25519.sign(message, seed)

    init { require(seed.size == 32) { "Private key must be 64 hex characters (32 bytes)" } }

    companion object {
        @JvmStatic fun fromHex(seedHex: String): KeyPair {
            require(Encoding.isHex(seedHex, 64)) { "Private key must be 64 hex characters (32 bytes)" }
            return KeyPair(Encoding.hexToBytes(seedHex))
        }
        @JvmStatic fun random(): KeyPair = KeyPair(ByteArray(32).also { SecureRandom().nextBytes(it) })
    }
}

/** BIP-39 mnemonics and SLIP-10 derivation along m/44'/883'/index'. */
object Wallet {
    const val ZOOBC_COIN_TYPE = 883

    /** True for 12, 15, 18, 21 or 24 English words with a valid checksum. */
    @JvmStatic fun validateMnemonic(mnemonic: String): Boolean {
        val words = mnemonic.trim().split(Regex("\\s+"))
        if (words.size !in listOf(12, 15, 18, 21, 24)) return false
        val bits = StringBuilder()
        for (w in words) { val i = Bip39Words.WORDS.indexOf(w); if (i < 0) return false; bits.append(i.toString(2).padStart(11, '0')) }
        val cs = words.size / 3
        val entropy = ByteArray((bits.length - cs) / 8) { i -> bits.substring(8 * i, 8 * i + 8).toInt(2).toByte() }
        val sum = MessageDigest.getInstance("SHA-256").digest(entropy)
        return bits.substring(bits.length - cs) == (sum[0].toInt() and 0xff).toString(2).padStart(8, '0').substring(0, cs)
    }

    @JvmStatic fun mnemonicFromEntropy(entropy: ByteArray): String {
        require(entropy.size in 16..32 && entropy.size % 4 == 0) { "entropy must be 16-32 bytes, a multiple of 4" }
        val bits = StringBuilder(entropy.joinToString("") { (it.toInt() and 0xff).toString(2).padStart(8, '0') })
        val sum = MessageDigest.getInstance("SHA-256").digest(entropy)
        bits.append((sum[0].toInt() and 0xff).toString(2).padStart(8, '0').substring(0, entropy.size / 4))
        return (0 until bits.length / 11).joinToString(" ") { Bip39Words.WORDS[bits.substring(11 * it, 11 * it + 11).toInt(2)] }
    }

    @JvmStatic @JvmOverloads fun generateMnemonic(words: Int = 24): String = mnemonicFromEntropy(ByteArray((words * 11 - words / 3) / 8).also { SecureRandom().nextBytes(it) })

    /** PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048, 64). */
    @JvmStatic @JvmOverloads fun mnemonicToSeed(mnemonic: String, passphrase: String = ""): ByteArray {
        val password = mnemonic.trim().split(Regex("\\s+")).joinToString(" ").toByteArray()
        val salt = ("mnemonic$passphrase").toByteArray()
        val mac = Mac.getInstance("HmacSHA512").also { it.init(SecretKeySpec(password, "HmacSHA512")) }
        var u = mac.doFinal(salt + byteArrayOf(0, 0, 0, 1))
        val t = u.copyOf()
        for (i in 1 until 2048) { u = mac.doFinal(u); for (j in t.indices) t[j] = (t[j].toInt() xor u[j].toInt()).toByte() }
        return t
    }

    /** SLIP-10 for Ed25519 along a hardened-only path such as m/44'/883'/0'; the 32-byte key. */
    @JvmStatic fun slip10Derive(path: String, seed: ByteArray): ByteArray {
        require(Regex("^m(/[0-9]+')+$").matches(path)) { "invalid derivation path: $path" }
        fun hmac(key: ByteArray, data: ByteArray) = Mac.getInstance("HmacSHA512").also { it.init(SecretKeySpec(key, "HmacSHA512")) }.doFinal(data)
        var digest = hmac("ed25519 seed".toByteArray(), seed)
        var key = digest.copyOf(32); var chain = digest.copyOfRange(32, 64)
        for (seg in path.split("/").drop(1)) {
            val index = seg.dropLast(1).toLong()
            require(index < 0x80000000L) { "path index too large" }
            val i = (index + 0x80000000L).toInt()
            val data = byteArrayOf(0) + key + byteArrayOf((i ushr 24).toByte(), (i ushr 16).toByte(), (i ushr 8).toByte(), i.toByte())
            digest = hmac(chain, data)
            key = digest.copyOf(32); chain = digest.copyOfRange(32, 64)
        }
        return key
    }

    /** Account [index] of a mnemonic wallet: m/44'/883'/index'. */
    @JvmStatic @JvmOverloads fun account(mnemonic: String, index: Int, passphrase: String = ""): Pair<KeyPair, String> {
        val path = "m/44'/$ZOOBC_COIN_TYPE'/$index'"
        return KeyPair(slip10Derive(path, mnemonicToSeed(mnemonic, passphrase))) to path
    }
}
