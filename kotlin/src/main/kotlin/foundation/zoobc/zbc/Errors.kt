// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Exit codes and error classes of spec/cli-contract.md section 5. */
object ExitCode {
    const val OK = 0; const val INTERNAL = 1; const val USAGE = 2; const val NODE_UNREACHABLE = 3; const val INSUFFICIENT_BALANCE = 4
    const val FEE_TOO_LOW = 5; const val REJECTED = 6; const val NOT_FOUND = 7; const val TIMEOUT = 8; const val NODE_BUSY = 9; const val VERIFY_FAILED = 10

    fun errorClass(code: Int): String = when (code) {
        0 -> "ok"; 2 -> "usage"; 3 -> "node_unreachable"; 4 -> "insufficient_balance"; 5 -> "fee_too_low"; 6 -> "rejected"
        7 -> "not_found"; 8 -> "timeout"; 9 -> "node_busy"; 10 -> "verify_failed"; else -> "internal"
    }

    /** Classify a node's rejection into an exit code (spec/api.md section 2). */
    fun classifyNodeError(httpCode: Int, text: String): Int {
        if (httpCode == 0) return NODE_UNREACHABLE
        if (httpCode >= 500) return NODE_BUSY
        val t = text.lowercase()
        return when {
            "fee too low" in t -> FEE_TOO_LOW
            "insufficient balance" in t || "insufficient spendable" in t || "account does not exist" in t -> INSUFFICIENT_BALANCE
            "not found" in t || "unknown token" in t || "unknown or expired token" in t || "unknown app" in t -> NOT_FOUND
            else -> REJECTED
        }
    }
}

/** An error that carries its exit code; [extra] is merged into the JSON error object. */
class ToolError(val code: Int, message: String, val extra: Map<String, JsonElement> = emptyMap()) : Exception(message) {
    fun toJson(): JsonObject = JsonObject(
        mapOf("success" to JsonPrimitive(false), "error" to JsonPrimitive(message ?: ""), "exit_code" to JsonPrimitive(code), "error_class" to JsonPrimitive(ExitCode.errorClass(code))) + extra
    )
    companion object {
        fun usage(message: String) = ToolError(ExitCode.USAGE, message)
        fun internal(message: String) = ToolError(ExitCode.INTERNAL, message)
    }
}
