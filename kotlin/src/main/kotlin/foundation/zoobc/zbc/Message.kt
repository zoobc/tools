// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

/** ZBC-MSG-v1 message signing (spec/signing.md section 5). */
object Message {
    const val SCHEME = "ZBC-MSG-v1"

    /** SHA3-256("ZBC-MSG" || message). */
    @JvmStatic fun digest(message: ByteArray): ByteArray = Encoding.sha3("ZBC-MSG".toByteArray(), message)

    data class Signed(val scheme: String, val address: String, val publicKey: String, val messageHex: String, val digest: String, val signature: String)

    @JvmStatic fun sign(kp: KeyPair, message: ByteArray): Signed {
        val d = digest(message)
        return Signed(SCHEME, kp.address, Encoding.bytesToHex(kp.publicKey), Encoding.bytesToHex(message), Encoding.bytesToHex(d), Encoding.bytesToHex(kp.sign(d)))
    }

    /** The public key behind a ZBC_ address or 64 hex, or null. */
    @JvmStatic fun publicKeyOf(address: String): ByteArray? {
        if (Encoding.isHex(address, 64)) return Encoding.hexToBytes(address)
        val d = Address.decode(address) ?: return null
        return if (d.first == "ZBC") d.second else null
    }

    /** False for anything that does not verify; never throws. */
    @JvmStatic fun verify(address: String, message: ByteArray, signature: ByteArray): Boolean {
        val pub = publicKeyOf(address) ?: return false
        return signature.size == 64 && Ed25519.verify(digest(message), signature, pub)
    }
}
