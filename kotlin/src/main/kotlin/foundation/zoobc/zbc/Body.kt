// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

/** Parameter validation and the generic body serialiser driven by spec/transactions (encodings of index.json). */
object Body {
    @JvmStatic fun parseInteger(value: String, kind: String, name: String): Long {
        val v = value.trim()
        if (!Regex("^-?\\d+$").matches(v)) throw ToolError.usage("$name must be a whole number, got \"$value\"")
        val n = v.toBigIntegerOrNull() ?: throw ToolError.usage("$name is out of range for $kind")
        val (lo, hi) = when (kind) {
            "uint64" -> java.math.BigInteger.ZERO to java.math.BigInteger("18446744073709551615")
            "uint32" -> java.math.BigInteger.ZERO to java.math.BigInteger.valueOf(0xffffffffL)
            "uint8" -> java.math.BigInteger.ZERO to java.math.BigInteger.valueOf(255)
            else -> java.math.BigInteger.valueOf(Long.MIN_VALUE) to java.math.BigInteger.valueOf(Long.MAX_VALUE)
        }
        if (n < lo || n > hi) throw ToolError.usage("$name is out of range for $kind")
        return n.toLong()
    }

    @JvmStatic fun splitList(s: String): List<String> = s.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    /** Check one value against its parameter kind; returns the value to keep. */
    @JvmStatic fun validateParam(p: ParamDef, value: String): String {
        when (p.kind) {
            "privkey" -> if (!Encoding.isHex(value, 64)) throw ToolError.usage("${p.name} must be 64 hex characters (a 32-byte private key)")
            "address" -> try { Address.parse(value) } catch (e: IllegalArgumentException) { throw ToolError.usage("invalid ${p.name}: ${e.message}") }
            "address_list" -> for (a in splitList(value)) try { Address.parse(a) } catch (e: IllegalArgumentException) { throw ToolError.usage("invalid ${p.name} entry $a: ${e.message}") }
            "key" -> try { Address.parseKey32(value) } catch (e: IllegalArgumentException) { throw ToolError.usage("invalid ${p.name}: ${e.message}") }
            "int64", "uint64", "uint32", "uint8" -> {
                val n = parseInteger(value, p.kind, p.name)
                if ((p.min != null && n < p.min) || (p.max != null && n > p.max)) throw ToolError.usage("${p.name} must be between ${p.min ?: "-inf"} and ${p.max ?: "inf"}")
                return value.trim()
            }
            "hex32" -> if (!Encoding.isHex(value, 64)) throw ToolError.usage("${p.name} must be 64 hex characters (32 bytes)")
            "hexbytes" -> if (!Encoding.isHex(value)) throw ToolError.usage("${p.name} must be hex")
        }
        return value
    }

    /** What the generic serialiser cannot read from the parameters. */
    class Context(val sender: KeyPair? = null, val files: Map<String, ByteArray> = emptyMap(), val computed: MutableMap<String, ByteArray> = mutableMapOf())

    private fun holds(whenExpr: String, params: Map<String, String>): Boolean {
        val m = Regex("^(\\w+) != (0|'')$").matchEntire(whenExpr) ?: throw ToolError.internal("unsupported condition $whenExpr")
        val v = params[m.groupValues[1]] ?: ""
        return if (m.groupValues[2] == "0") v.isNotEmpty() && (v.toLongOrNull() ?: 0L) != 0L else v.isNotEmpty()
    }

    /** Serialise one body field. */
    @JvmStatic fun encodeField(f: FieldDef, params: Map<String, String>, ctx: Context): ByteArray {
        ctx.computed[f.name]?.let { return it }
        var value = params[f.from] ?: ""
        if (f.when_zero != null && (value.isEmpty() || (value.toLongOrNull() ?: 0L) <= 0L)) value = params[f.when_zero] ?: "0"
        return when (f.encoding) {
            "u8" -> byteArrayOf(parseInteger(value, "uint8", f.name).toByte())
            "u16le" -> Bytes.le16(parseInteger(value, "uint32", f.name).toInt())
            "u32le" -> Bytes.le32(parseInteger(value, "uint32", f.name).toInt())
            "u64le" -> Bytes.le64(parseInteger(value, "int64", f.name))
            "hex" -> { val b = hexOrUsage(value, f.from); if (f.size != null && b.size != f.size) throw ToolError.usage("${f.from} must be ${f.size} bytes (${2 * f.size} hex)"); b }
            "hex16" -> { val b = hexOrUsage(value, f.from); Bytes.le16(b.size) + b }
            "bytes32" -> { val b = ctx.files[f.from] ?: hexOrUsage(value, f.from); Bytes.le32(b.size) + b }
            "str16" -> { val b = value.toByteArray(); Bytes.le16(b.size) + b }
            "str32" -> { val b = value.toByteArray(); Bytes.le32(b.size) + b }
            "address" -> addr(value, f.from).bytes
            "address_list" -> splitList(value).fold(ByteArray(0)) { acc, a -> acc + addr(a, f.from).bytes }
            "address_list8" -> { val items = splitList(value); if (items.size > 255) throw ToolError.usage("${f.from}: at most 255 entries"); items.fold(byteArrayOf(items.size.toByte())) { acc, a -> acc + addr(a, f.from).bytes } }
            "sender_address" -> (ctx.sender ?: throw ToolError.internal("no sender")).accountBytes
            "pubkey_of_key" -> try { KeyPair.fromHex(value).publicKey } catch (e: IllegalArgumentException) { throw ToolError.usage("${f.from} must be 64 hex characters (a 32-byte private key)") }
            "key32" -> try { Address.parseKey32(value) } catch (e: IllegalArgumentException) { throw ToolError.usage("invalid ${f.from}: ${e.message}") }
            "literal" -> Encoding.hexToBytes(f.value ?: "")
            "custom" -> throw ToolError.internal("field ${f.name} needs a custom hook")
            else -> throw ToolError.internal("unknown encoding ${f.encoding}")
        }
    }

    private fun hexOrUsage(v: String, name: String) = if (Encoding.isHex(v)) Encoding.hexToBytes(v) else throw ToolError.usage("$name must be hex")
    private fun addr(v: String, name: String) = try { Address.parse(v) } catch (e: IllegalArgumentException) { throw ToolError.usage("invalid $name: ${e.message}") }

    /** The whole body of a non-custom transaction. */
    @JvmStatic fun build(def: TxDef, params: Map<String, String>, ctx: Context): ByteArray {
        var out = ByteArray(0)
        for (f in def.body) {
            if (f.`when` != null && !holds(f.`when`, params)) continue
            out += encodeField(f, params, ctx)
        }
        return out
    }
}
