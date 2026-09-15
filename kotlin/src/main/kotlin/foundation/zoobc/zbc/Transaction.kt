// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Escrow terms of a transfer (the --escrow-* options); [timeout] is an absolute Unix time in seconds. */
data class Escrow(val approver: String, val commission: Long = 0, val timeout: Long = 0, val instruction: String = "") {
    /** The escrow block of the envelope (spec/signing.md section 3). */
    fun toBytes(): ByteArray {
        val ins = instruction.toByteArray()
        return Address.parse(approver).bytes + Bytes.le64(commission) + Bytes.le64(timeout) + Bytes.le32(ins.size) + ins + byteArrayOf(0)
    }
    fun toPayload(): JsonObject = buildJsonObject {
        put("approver_address", Encoding.bytesToHex(Address.parse(approver).bytes)); put("commission", commission); put("timeout", timeout)
        if (instruction.isNotEmpty()) put("instruction", instruction)
    }
}

/** Which chain a signature is for: version 2 with its genesis hash, or 1 (legacy). */
data class SigningContext(val version: Int, val genesisHash: ByteArray = ByteArray(0)) {
    companion object {
        /** Reads --genesis: 64 hex, or "v1"/"legacy". */
        @JvmStatic fun of(genesis: String): SigningContext {
            if (genesis == "v1" || genesis == "legacy") return SigningContext(1)
            require(Encoding.isHex(genesis, 64)) { "--genesis must be the 64-hex genesis block hash (or 'v1' for the legacy digest)" }
            return SigningContext(2, Encoding.hexToBytes(genesis))
        }
    }
}

/** A built, signed and hashed transaction. */
class SignedTransaction(val unsigned: ByteArray, val digest: ByteArray, val signature: ByteArray, val bytes: ByteArray, val hash: ByteArray,
                        val payload: JsonObject, val signingVersion: Int, val genesisHash: ByteArray)

/** The envelope, chain-bound digest, signature, hash and submit payload (spec/signing.md). */
object Transaction {
    const val SEND_ZBC = 1; const val APPROVAL_ESCROW = 4
    const val APPROVE = 0; const val REJECT = 1; const val EXPIRE = 2
    val EMPTY_ACCOUNT: ByteArray get() = Bytes.le32(AccountType.EMPTY)

    /** Fields 1–11 of the envelope: what the digest covers. [recipient] is typed bytes or empty. */
    @JvmStatic @JvmOverloads
    fun unsignedBytes(type: Int, timestamp: Long, sender: ByteArray, recipient: ByteArray, fee: Long, body: ByteArray,
                      escrow: Escrow? = null, message: ByteArray = ByteArray(0), version: Int = 1): ByteArray {
        val rec = if (recipient.isEmpty() || recipient.all { it == 0.toByte() }) EMPTY_ACCOUNT else recipient
        return Bytes.le32(type) + byteArrayOf(version.toByte()) + Bytes.le64(timestamp) + sender + rec + Bytes.le64(fee) + Bytes.le32(body.size) + body +
            (escrow?.toBytes() ?: EMPTY_ACCOUNT) + Bytes.le32(message.size) + message
    }

    /** SHA3-256("ZBC-TX" || genesis || unsigned) for version 2; SHA3-256(unsigned) for version 1. */
    @JvmStatic fun signingDigest(unsigned: ByteArray, ctx: SigningContext): ByteArray =
        if (ctx.version == 2) Encoding.sha3("ZBC-TX".toByteArray(), ctx.genesisHash, unsigned) else Encoding.sha3(unsigned)

    @JvmStatic fun hash(unsigned: ByteArray, signature: ByteArray): ByteArray = Encoding.sha3(unsigned, signature)

    /** The int64 id: the first 8 bytes of the hash, little-endian, signed. */
    @JvmStatic fun id(hash: ByteArray): Long = Bytes.readLe64(hash, 0)

    /** Build, sign and hash a transaction for the chain of [ctx]. */
    @JvmStatic @JvmOverloads
    fun sign(type: Int, timestamp: Long, sender: KeyPair, recipient: ByteArray, fee: Long, body: ByteArray, ctx: SigningContext,
             escrow: Escrow? = null, message: ByteArray = ByteArray(0), version: Int = 1): SignedTransaction {
        val unsigned = unsignedBytes(type, timestamp, sender.accountBytes, recipient, fee, body, escrow, message, version)
        val digest = signingDigest(unsigned, ctx)
        val signature = sender.sign(digest)
        val full = unsigned + signature
        val recipientJson = when {
            recipient.isEmpty() -> ""
            recipient.size == 36 && recipient.copyOf(4).all { it == 0.toByte() } -> Encoding.bytesToHex(recipient.copyOfRange(4, 36))
            else -> Encoding.bytesToHex(recipient)
        }
        val payload = buildJsonObject {
            put("version", version); put("timestamp", timestamp); put("sender_account_address", Encoding.bytesToHex(sender.publicKey))
            put("recipient_account_address", recipientJson); put("transaction_type", type); put("fee", fee)
            put("transaction_body_bytes", Encoding.bytesToHex(body)); put("signature", Encoding.bytesToHex(signature))
            if (message.isNotEmpty()) put("message_hex", Encoding.bytesToHex(message))
            if (escrow != null) put("escrow", escrow.toPayload())
        }
        return SignedTransaction(unsigned, digest, signature, full, Encoding.sha3(full), payload, ctx.version, ctx.genesisHash)
    }

    /** The 8-byte amount. */
    @JvmStatic fun sendZbcBody(amount: Long): ByteArray = Bytes.le64(amount)

    /** approval u32le then the 32-byte escrowed transaction hash. */
    @JvmStatic fun approvalEscrowBody(approval: Int, escrowedHash: ByteArray): ByteArray {
        require(escrowedHash.size == 32) { "Transaction hash must be 64 hex characters (the escrowed transaction's SHA3-256 hash)" }
        return Bytes.le32(approval) + escrowedHash
    }
}

internal fun jsonString(s: String) = JsonPrimitive(s)
