// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** One command-line parameter of a transaction description (spec/transactions/README.md). */
@Serializable
data class ParamDef(val name: String, val kind: String, val required: Boolean, val default: String? = null, val help: String,
                    val min: Long? = null, val max: Long? = null)

/** One body field. */
@Serializable
data class FieldDef(val name: String, val encoding: String, val from: String, val size: Int? = null, val value: String? = null,
                    val `when`: String? = null, val computed: String? = null, val default_from: String? = null, val when_zero: String? = null)

/** One transaction description. */
@Serializable
data class TxDef(val name: String, val type: Int, val command: String, val binary: String? = null, val description: String,
                 val sender_key: String, val recipient: String, val options: List<String> = emptyList(), val needs_node: Boolean,
                 val custom: String? = null, val params: List<ParamDef>, val body: List<FieldDef>,
                 val example: Map<String, String> = emptyMap(), val notes: List<String> = emptyList())

/** The transaction descriptions, read from the spec files the build copies into the jar (zbc/transactions/). */
object Spec {
    private val json = Json { ignoreUnknownKeys = true }

    val commands: List<TxDef> by lazy {
        val index = json.parseToJsonElement(resource("zbc/transactions/index.json")).jsonObject
        index["transactions"]!!.jsonArray.map { it.jsonObject["command"]!!.jsonPrimitive.content }.sorted()
            .map { json.decodeFromString(TxDef.serializer(), resource("zbc/transactions/$it.json")) }
    }
    val byName: Map<String, TxDef> by lazy { commands.associateBy { it.command } }

    @JvmStatic fun command(name: String): TxDef? = byName[name]

    private fun resource(path: String): String =
        Spec::class.java.classLoader.getResourceAsStream(path)?.bufferedReader()?.readText() ?: throw IllegalStateException("missing resource $path")
}
