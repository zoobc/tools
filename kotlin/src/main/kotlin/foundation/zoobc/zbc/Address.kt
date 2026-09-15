// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import foundation.zoobc.zbc.Encoding.BITCOIN_ALPHABET
import foundation.zoobc.zbc.Encoding.RIPPLE_ALPHABET
import foundation.zoobc.zbc.Encoding.base58CheckDecode
import foundation.zoobc.zbc.Encoding.base58Decode
import foundation.zoobc.zbc.Encoding.bech32DecodePlain
import foundation.zoobc.zbc.Encoding.hexToBytes
import foundation.zoobc.zbc.Encoding.isHex
import foundation.zoobc.zbc.Encoding.segwitDecode
import foundation.zoobc.zbc.Encoding.ss58Decode

/** Account types (spec/addresses.md section 1). */
object AccountType {
    const val ZOOBC = 0; const val BITCOIN = 1; const val EMPTY = 2; const val ESTONIA_EID = 3; const val ETHEREUM = 4
    const val BITCOIN_P2PKH = 5; const val BITCOIN_P2SH = 6; const val BITCOIN_P2WPKH = 7; const val BITCOIN_P2WSH = 8; const val BITCOIN_TAPROOT = 9
    const val DATASET = 10; const val SOLANA = 11; const val POLKADOT = 12; const val CARDANO = 13; const val RIPPLE = 14; const val TRON = 15; const val TEZOS = 16

    fun name(t: Int): String = when (t) {
        0 -> "ZooBC"; 1 -> "Bitcoin"; 3 -> "Estonia eID"; 4 -> "Ethereum"; 5 -> "Bitcoin P2PKH"; 6 -> "Bitcoin P2SH"; 7 -> "Bitcoin P2WPKH"
        8 -> "Bitcoin P2WSH"; 9 -> "Bitcoin Taproot"; 10 -> "DataSet"; 11 -> "Solana"; 12 -> "Polkadot"; 13 -> "Cardano"; 14 -> "Ripple"
        15 -> "Tron"; 16 -> "Tezos"; else -> "type $t"
    }
}

/** A recipient as the envelope carries it. */
data class ParsedAddress(val type: Int, val payload: ByteArray, val display: String) {
    /** 4-byte type LE then the payload (36 bytes for a ZooBC account). */
    val bytes: ByteArray get() = Address.typed(type, payload)
    val typeName: String get() = AccountType.name(type)
}

/** The ZBC_/ZNK_/ZBS_ text form and every recipient form of spec/addresses.md. */
object Address {
    fun typed(type: Int, payload: ByteArray): ByteArray = Bytes.le32(type) + payload

    /** PREFIX_ + base32(payload || SHA3-256(payload || prefix)[0..2]) in seven groups of eight. */
    fun encode(payload: ByteArray, prefix: String = "ZBC"): String {
        require(payload.size == 32 && prefix.length == 3) { "address payload must be 32 bytes and the prefix 3 characters" }
        val check = Encoding.sha3(payload, prefix.toByteArray()).copyOf(3)
        val s = Encoding.base32Encode(payload + check)
        return prefix + (0 until 7).joinToString("") { "_" + s.substring(8 * it, 8 * it + 8) }
    }

    /** Pair(upper-case prefix, 32-byte payload) of PREFIX_... (separators _ or -, any case), or null. */
    fun decode(text: String): Pair<String, ByteArray>? {
        val norm = text.uppercase()
        if (norm.length < 4 || (norm[3] != '_' && norm[3] != '-')) return null
        val prefix = norm.substring(0, 3)
        val body = norm.substring(4).filter { it != '_' && it != '-' }
        if (body.length != 56) return null
        val raw = Encoding.base32Decode(body) ?: return null
        if (raw.size != 35) return null
        val payload = raw.copyOf(32)
        if (!Encoding.sha3(payload, prefix.toByteArray()).copyOf(3).contentEquals(raw.copyOfRange(32, 35))) return null
        return prefix to payload
    }

    private val chains = mapOf("zbc" to "zbc", "zoobc" to "zbc", "btc" to "btc", "bitcoin" to "btc", "eth" to "eth", "ethereum" to "eth", "evm" to "eth",
        "sol" to "sol", "solana" to "sol", "dot" to "dot", "polkadot" to "dot", "substrate" to "dot", "ada" to "ada", "cardano" to "ada",
        "xrp" to "xrp", "ripple" to "xrp", "trx" to "trx", "tron" to "trx", "xtz" to "xtz", "tezos" to "xtz", "zbs" to "zbs", "dataset" to "zbs")

    private fun zbcForm(a: String): ParsedAddress {
        val (prefix, payload) = decode(a) ?: throw IllegalArgumentException("invalid ZooBC address checksum")
        return ParsedAddress(if (prefix == "ZBS") AccountType.DATASET else AccountType.ZOOBC, payload, a)
    }

    private fun hinted(a: String, hint: String): ParsedAddress = when (hint) {
        "eth" -> { val h = a.removePrefix("0x").removePrefix("0X"); require(isHex(h, 40)) { "not a 20-byte Ethereum address" }; ParsedAddress(AccountType.ETHEREUM, hexToBytes(h), a) }
        "sol" -> { val d = base58Decode(a); require(d != null && d.size == 32) { "not a 32-byte Solana address" }; ParsedAddress(AccountType.SOLANA, d!!, a) }
        "dot" -> { val ss = ss58Decode(a) ?: throw IllegalArgumentException("not a valid SS58 address"); ParsedAddress(AccountType.POLKADOT, ss.second, a) }
        "zbc", "zbs" -> zbcForm(a)
        else -> auto(a)
    }

    private fun auto(a: String): ParsedAddress {
        if (a.length == 42 && (a.startsWith("0x") || a.startsWith("0X")) && isHex(a.substring(2), 40)) return ParsedAddress(AccountType.ETHEREUM, hexToBytes(a.substring(2)), a)
        if (a.length > 4 && (a[3] == '_' || a[3] == '-')) return zbcForm(a)
        val low5 = a.take(5).lowercase()
        if (low5.startsWith("bc1") || low5.startsWith("tb1") || low5.startsWith("bcrt1")) {
            val (_, version, prog) = segwitDecode(a) ?: throw IllegalArgumentException("invalid Bitcoin bech32 address")
            return when {
                version == 0 && prog.size == 20 -> ParsedAddress(AccountType.BITCOIN_P2WPKH, prog, a)
                version == 0 && prog.size == 32 -> ParsedAddress(AccountType.BITCOIN_P2WSH, prog, a)
                version == 1 && prog.size == 32 -> ParsedAddress(AccountType.BITCOIN_TAPROOT, prog, a)
                else -> throw IllegalArgumentException("unsupported Bitcoin witness program")
            }
        }
        if ((a[0] == '1' || a[0] == '3') && a.length in 26..35) {
            val raw = base58Decode(a)
            if (raw != null && raw.size == 25) {
                val body = base58CheckDecode(a)
                if (body != null && body.size == 21) {
                    if (body[0] == 0x00.toByte()) return ParsedAddress(AccountType.BITCOIN_P2PKH, body.copyOfRange(1, 21), a)
                    if (body[0] == 0x05.toByte()) return ParsedAddress(AccountType.BITCOIN_P2SH, body.copyOfRange(1, 21), a)
                }
            }
        }
        if (a.length > 5 && a.substring(0, 5).lowercase() == "addr1") {
            val d = bech32DecodePlain(a)
            if (d != null && d.first == "addr" && d.second.size == 29 && d.second[0] == 0x61.toByte()) return ParsedAddress(AccountType.CARDANO, d.second.copyOfRange(1, 29), a)
            throw IllegalArgumentException("invalid Cardano address (expected a mainnet enterprise addr1… address)")
        }
        if (a[0] == 'T' && a.length == 34) {
            val body = base58CheckDecode(a)
            if (body != null && body.size == 21 && body[0] == 0x41.toByte()) return ParsedAddress(AccountType.TRON, body.copyOfRange(1, 21), a)
            throw IllegalArgumentException("invalid Tron address")
        }
        if (a[0] == 'r' && a.length in 25..35) {
            val body = base58CheckDecode(a, RIPPLE_ALPHABET)
            if (body != null && body.size == 21 && body[0] == 0x00.toByte()) return ParsedAddress(AccountType.RIPPLE, body.copyOfRange(1, 21), a)
            throw IllegalArgumentException("invalid Ripple address")
        }
        if (a.startsWith("tz1")) {
            val body = base58CheckDecode(a)
            if (body != null && body.size == 23 && body[0] == 0x06.toByte() && body[1] == 0xa1.toByte() && body[2] == 0x9f.toByte()) return ParsedAddress(AccountType.TEZOS, body.copyOfRange(3, 23), a)
            throw IllegalArgumentException("invalid Tezos address")
        }
        ss58Decode(a)?.let { if (it.second.size == 32) return ParsedAddress(AccountType.POLKADOT, it.second, a) }
        if (a.length in 32..44) base58Decode(a, BITCOIN_ALPHABET)?.let { if (it.size == 32) return ParsedAddress(AccountType.SOLANA, it, a) }
        if (isHex(a, 64)) { val key = hexToBytes(a); return ParsedAddress(AccountType.ZOOBC, key, encode(key, "ZBC")) }
        throw IllegalArgumentException("unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos")
    }

    /** Read a recipient in the order of spec/addresses.md section 3; [chain] forces one reading (--chain). Throws IllegalArgumentException. */
    @JvmStatic @JvmOverloads
    fun parse(text: String, chain: String = ""): ParsedAddress {
        val a = text.trim()
        require(a.isNotEmpty()) { "empty address" }
        if (chain.isEmpty()) return auto(a)
        val hint = chains[chain.lowercase()] ?: throw IllegalArgumentException("unknown chain $chain")
        return try { hinted(a, hint) } catch (e: IllegalArgumentException) {
            val up = a.uppercase(); val low = a.lowercase()
            val plain = (a.length == 42 && (a.startsWith("0x") || a.startsWith("0X"))) || up.startsWith("ZBC") || up.startsWith("ZNK") || up.startsWith("ZBS") ||
                a[0] == '1' || a[0] == '3' || low.startsWith("bc1") || low.startsWith("tb1") || low.startsWith("bcrt1") || a.length == 64
            if (!plain) throw e
            auto(a)
        }
    }

    /** A registry key parameter: 64 hex (optionally 0x) or a ZNK_/ZBG_/ZBR_/ZBC_ text address; 32 bytes. */
    @JvmStatic
    fun parseKey32(text: String): ByteArray {
        if (text.length == 66 && text[3] == '_') return decode(text)?.second ?: throw IllegalArgumentException("invalid address checksum")
        val h = text.removePrefix("0x").removePrefix("0X")
        require(isHex(h, 64)) { "key must be a 64-hex string or a ZNK_/ZBG_/ZBR_ address" }
        return hexToBytes(h)
    }
}

/** Little-endian byte helpers. */
object Bytes {
    fun le32(v: Int): ByteArray = ByteArray(4) { i -> (v ushr (8 * i)).toByte() }
    fun le16(v: Int): ByteArray = ByteArray(2) { i -> (v ushr (8 * i)).toByte() }
    fun le64(v: Long): ByteArray = ByteArray(8) { i -> (v ushr (8 * i)).toByte() }
    fun readLe64(b: ByteArray, off: Int): Long { var v = 0L; for (i in 7 downTo 0) v = (v shl 8) or (b[off + i].toLong() and 0xff); return v }
}
