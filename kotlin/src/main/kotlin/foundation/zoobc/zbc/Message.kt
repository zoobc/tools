// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

/**
 * Message signing (spec/signing.md sections 5 and 5a).
 *
 * ZBC-MSG-v2 binds the signature to one chain, the way transactions do since signing v2:
 * digest = SHA3-256("ZBC-MSG-v2" || genesis_hash (32) || message). New signatures are always v2.
 * ZBC-MSG-v1 (SHA3-256("ZBC-MSG" || message), no chain) is still accepted by [verify] until
 * [V1_SUNSET] (2026-12-01T00:00:00Z) and refused after.
 */
object Message {
    const val SCHEME = "ZBC-MSG-v2"
    const val SCHEME_V1 = "ZBC-MSG-v1"
    /** What [check] reports for a v1 signature that still verifies. */
    const val SCHEME_V1_ACCEPTED = "ZBC-MSG-v1 (accepted until 2026-12-01)"
    /** Unix seconds of 2026-12-01T00:00:00Z: v1 signatures are refused from here on. */
    const val V1_SUNSET = 1796083200L

    /** SHA3-256("ZBC-MSG-v2" || genesisHash || message); [genesisHash] must be the chain's 32-byte genesis block hash. */
    @JvmStatic fun digest(message: ByteArray, genesisHash: ByteArray): ByteArray {
        require(genesisHash.size == 32) { "ZBC-MSG-v2 needs the chain's 32-byte genesis hash" }
        return Encoding.sha3("ZBC-MSG-v2".toByteArray(), genesisHash, message)
    }

    /** SHA3-256("ZBC-MSG" || message): the legacy, chain-independent digest. */
    @JvmStatic fun digestV1(message: ByteArray): ByteArray = Encoding.sha3("ZBC-MSG".toByteArray(), message)

    data class Signed(val scheme: String, val genesisHash: String, val address: String, val publicKey: String, val messageHex: String, val digest: String, val signature: String)

    /** Sign [message] for the chain whose genesis block hash is [genesisHash] (ZBC-MSG-v2). */
    @JvmStatic fun sign(kp: KeyPair, message: ByteArray, genesisHash: ByteArray): Signed {
        val d = digest(message, genesisHash)
        return Signed(SCHEME, Encoding.bytesToHex(genesisHash), kp.address, Encoding.bytesToHex(kp.publicKey), Encoding.bytesToHex(message), Encoding.bytesToHex(d), Encoding.bytesToHex(kp.sign(d)))
    }

    /** The public key behind a ZBC_ address or 64 hex, or null. */
    @JvmStatic fun publicKeyOf(address: String): ByteArray? {
        if (Encoding.isHex(address, 64)) return Encoding.hexToBytes(address)
        val d = Address.decode(address) ?: return null
        return if (d.first == "ZBC") d.second else null
    }

    /** The outcome of [check]: [scheme] names what verified (v2, or v1 while accepted); [digest] is the one checked last. */
    data class Verified(val valid: Boolean, val scheme: String, val digest: ByteArray)

    /**
     * v2 first (when [genesisHash] is the chain's 32 bytes; null = chain unknown, v2 is skipped), then v1 while
     * [now] (unix seconds) is before [V1_SUNSET]. Never throws.
     */
    @JvmStatic @JvmOverloads
    fun check(address: String, message: ByteArray, signature: ByteArray, genesisHash: ByteArray?, now: Long = System.currentTimeMillis() / 1000): Verified {
        val pub = publicKeyOf(address)
        val ok = pub != null && signature.size == 64
        var digest = ByteArray(0)
        if (genesisHash != null && genesisHash.size == 32) {
            digest = digest(message, genesisHash)
            if (ok && Ed25519.verify(digest, signature, pub!!)) return Verified(true, SCHEME, digest)
        }
        if (now < V1_SUNSET) {
            val d1 = digestV1(message)
            if (ok && Ed25519.verify(d1, signature, pub!!)) return Verified(true, SCHEME_V1_ACCEPTED, d1)
        }
        return Verified(false, SCHEME, if (digest.isEmpty()) digestV1(message) else digest)
    }

    /** False for anything that does not verify (v2 for [genesisHash], or v1 until the sunset); never throws. */
    @JvmStatic @JvmOverloads
    fun verify(address: String, message: ByteArray, signature: ByteArray, genesisHash: ByteArray?, now: Long = System.currentTimeMillis() / 1000): Boolean =
        check(address, message, signature, genesisHash, now).valid
}
