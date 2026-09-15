// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

/** The hand-written parts the descriptions mark computed or custom (spec/transactions/README.md). */
object Custom {
    /** The block a proof of ownership refers to. */
    data class ReferenceBlock(val hash: ByteArray, val height: Int)

    class Input(val def: TxDef, val params: Map<String, String>, val sender: KeyPair, val ctx: SigningContext, val timestamp: Long, val block: ReferenceBlock? = null)

    /** owner (36) || block hash (32) || height u32le, then the owner's signature over those bytes. */
    @JvmStatic fun proofOfOwnership(owner: KeyPair, block: ReferenceBlock): ByteArray {
        val msg = owner.accountBytes + block.hash + Bytes.le32(block.height)
        return msg + owner.sign(msg)
    }

    /** Fill ctx.computed for the fields the generic serialiser cannot produce; returns extra output fields. */
    @JvmStatic fun computeFields(input: Input, ctx: Body.Context): Map<String, JsonElement> {
        val p = input.params
        val extra = mutableMapOf<String, JsonElement>()
        when (input.def.command) {
            "store-file" -> {
                val pieces = if (Encoding.isHex(p["piece_ids"] ?: "")) Encoding.hexToBytes(p["piece_ids"]!!) else ByteArray(0)
                if (pieces.isEmpty() || pieces.size % 32 != 0) throw ToolError.usage("piece_ids must be a nonzero multiple of 32 bytes")
                ctx.computed["piece_count"] = Bytes.le32(pieces.size / 32)
                extra["piece_count"] = JsonPrimitive(pieces.size / 32)
            }
            "register-node", "update-node", "claim-node" -> {
                val block = input.block ?: throw ToolError.internal("proof of ownership needs the latest block")
                ctx.computed["proof_of_ownership"] = proofOfOwnership(input.sender, block)
                extra["node_znk"] = JsonPrimitive(KeyPair.fromHex(p["node_privkey"]!!).nodeAddress)
                extra["owner_zbc"] = JsonPrimitive(input.sender.address)
            }
            "fee-vote-reveal" -> {
                val info = Encoding.hexToBytes(p["recent_block_hash"]!!) + Bytes.le32(Body.parseInteger(p["recent_block_height"]!!, "uint32", "recent_block_height").toInt()) +
                    Bytes.le64(Body.parseInteger(p["fee_vote"]!!, "int64", "fee_vote"))
                val sig = input.sender.sign(info)
                ctx.computed["voter_signature"] = Bytes.le32(sig.size) + sig
            }
            "gateway-heartbeat" -> {
                val gw = try { KeyPair.fromHex(p["gateway_privkey"]!!) } catch (e: IllegalArgumentException) { throw ToolError.usage("gateway_privkey is not a valid key") }
                val h = Body.parseInteger(p["reference_height"]!!, "uint32", "reference_height")
                val hash = if (Encoding.isHex(p["reference_block_hash"] ?: "", 64)) Encoding.hexToBytes(p["reference_block_hash"]!!) else throw ToolError.usage("reference_block_hash must be 32 bytes (64 hex)")
                ctx.computed["signature"] = gw.sign(gw.publicKey + Bytes.le32(h.toInt()) + hash)
                extra["gateway_key"] = JsonPrimitive(Encoding.bytesToHex(gw.publicKey)); extra["reference_height"] = JsonPrimitive(h); extra["reference_block_hash"] = JsonPrimitive(p["reference_block_hash"]!!)
            }
        }
        return extra
    }

    /** SHA3-256(min u32le || nonce u64le || count u32le || sorted participant addresses). */
    @JvmStatic fun multisigAddress(participants: List<ByteArray>, nonce: Long, minSignatures: Int): ByteArray {
        val sorted = participants.sortedWith { a, b -> compareBytes(a, b) }
        return Encoding.sha3(Bytes.le32(minSignatures) + Bytes.le64(nonce) + Bytes.le32(sorted.size) + sorted.fold(ByteArray(0)) { acc, x -> acc + x })
    }
    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) { val d = (a[i].toInt() and 0xff) - (b[i].toInt() and 0xff); if (d != 0) return d }
        return a.size - b.size
    }

    /** The two fully custom bodies: multisig and app-settle. */
    @JvmStatic fun body(input: Input): Pair<ByteArray, Map<String, JsonElement>> = when (input.def.command) {
        "multisig" -> multisig(input)
        "app-settle" -> settle(input)
        else -> throw ToolError.internal("no custom body for ${input.def.command}")
    }

    private fun multisig(input: Input): Pair<ByteArray, Map<String, JsonElement>> {
        val p = input.params
        val participants = Body.splitList(p["participants"] ?: "").map { a -> try { Address.parse(a).bytes } catch (e: IllegalArgumentException) { throw ToolError.usage("Invalid participant address: $a") } }
        if (participants.isEmpty()) throw ToolError.usage("Need at least one participant")
        val minSigs = Body.parseInteger(p["min_signatures"]!!, "uint32", "min_signatures").toInt()
        val nonce = Body.parseInteger(p["nonce"].let { if (it.isNullOrEmpty()) "0" else it }, "int64", "nonce")
        val signers = Body.splitList(p["signer_privkeys"] ?: "")
        if (signers.isEmpty()) throw ToolError.usage("Need at least one signer key")
        val recipient = try { Address.parse(p["recipient"]!!) } catch (e: IllegalArgumentException) { throw ToolError.usage("Invalid recipient: ${e.message}") }
        val amount = Body.parseInteger(p["amount"]!!, "int64", "amount")
        val innerFee = Body.parseInteger(p["inner_fee"].let { if (it.isNullOrEmpty()) "10000000" else it }, "int64", "inner_fee")
        val ms = multisigAddress(participants, nonce, minSigs)
        val inner = Transaction.unsignedBytes(Transaction.SEND_ZBC, input.timestamp, Address.typed(AccountType.ZOOBC, ms), recipient.bytes, innerFee, Transaction.sendZbcBody(amount))
        val innerHash = Encoding.sha3(inner)
        val innerDigest = Transaction.signingDigest(inner, input.ctx)
        val sigs = signers.map { sk ->
            val kp = try { KeyPair.fromHex(sk) } catch (e: IllegalArgumentException) { throw ToolError.usage("Invalid signer key") }
            Encoding.bytesToHex(kp.accountBytes) to kp.sign(innerDigest)
        }.sortedBy { it.first }   // the node keeps them in a map ordered by address hex
        var body = Bytes.le32(1) + Bytes.le32(minSigs) + Bytes.le64(nonce) + Bytes.le32(participants.size) + participants.fold(ByteArray(0)) { acc, x -> acc + x }
        body += Bytes.le32(inner.size) + inner + Bytes.le32(1) + innerHash + Bytes.le32(sigs.size)
        for ((addr, sig) in sigs) body += Encoding.hexToBytes(addr) + Bytes.le32(sig.size) + sig
        val extra = mapOf("multisig_address" to JsonPrimitive(Encoding.bytesToHex(ms)), "multisig_zbc_address" to JsonPrimitive(Address.encode(ms, "ZBC")),
            "min_signatures" to JsonPrimitive(minSigs), "inner_tx_hash" to JsonPrimitive(Encoding.bytesToHex(innerHash)),
            "fund_hint" to JsonPrimitive("send ZBC to multisig_zbc_address before the signatures complete, else the inner tx stays in mempool"))
        return body to extra
    }

    private fun settle(input: Input): Pair<ByteArray, Map<String, JsonElement>> {
        val p = input.params
        val appId = Body.parseInteger(p["app_id"]!!, "int64", "app_id")
        val seats = try { listOf(KeyPair.fromHex(p["p0_privkey"]!!), KeyPair.fromHex(p["p1_privkey"]!!)) } catch (e: IllegalArgumentException) { throw ToolError.usage("seat keys must be 64 hex") }
        val turn = Body.parseInteger(p["opening_turn"].let { if (it.isNullOrEmpty()) "0" else it }, "uint8", "opening_turn").toInt()
        if (turn != 0 && turn != 1) throw ToolError.usage("opening_turn must be 0 or 1")
        val cells = Body.splitList(p["moves"] ?: "").map { Body.parseInteger(it, "uint8", "move").toInt() }
        if (cells.isEmpty()) throw ToolError.usage("no moves given")
        val state = ByteArray(9)
        var entries = ByteArray(0)
        cells.forEachIndexed { k, cell ->
            val seat = (turn + k) % 2
            if (cell > 8 || state[cell] != 0.toByte()) throw ToolError.usage("illegal move at seq ${k + 1}")
            val move = byteArrayOf(cell.toByte())
            val digest = Encoding.sha3(Bytes.le64(appId) + Bytes.le32(k + 1) + Encoding.sha3(state) + move)
            entries += byteArrayOf(seat.toByte()) + Bytes.le16(move.size) + move + seats[seat].sign(digest)
            state[cell] = (seat + 1).toByte()
        }
        val body = Bytes.le64(appId) + Bytes.le32(cells.size) + Bytes.le32(cells.size) + entries
        return body to mapOf("app_id" to JsonPrimitive(appId), "opening_turn" to JsonPrimitive(turn), "final_seq" to JsonPrimitive(cells.size))
    }
}
