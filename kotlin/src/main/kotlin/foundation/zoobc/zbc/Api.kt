// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration

/** The node/gateway HTTP client (spec/api.md): node info, submit, status, transaction, account, latest block. */
class Client @JvmOverloads constructor(api: String = "http://localhost:8080", val timeoutSeconds: Long = 20) {
    val api: String = api.trimEnd('/')
    private val http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(timeoutSeconds)).build()

    /** One HTTP answer. */
    class Reply(val status: Int, val text: String, val json: JsonElement?) {
        fun body(): JsonElement = json ?: JsonPrimitive(text)
    }

    private fun call(method: String, path: String, body: String? = null): Reply {
        val b = HttpRequest.newBuilder(URI.create(api + path)).timeout(Duration.ofSeconds(timeoutSeconds)).header("Accept", "application/json").header("User-Agent", "zbc-cli/1.0")
        if (body != null) b.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)) else b.GET()
        val res = try { http.send(b.build(), HttpResponse.BodyHandlers.ofString()) }
        catch (e: java.net.http.HttpTimeoutException) { throw ToolError(ExitCode.TIMEOUT, "Timed out: $path on $api") }
        catch (e: Exception) { throw ToolError(ExitCode.NODE_UNREACHABLE, "Connection failed: $path on $api: ${e.message ?: e.javaClass.simpleName}") }
        val text = res.body()
        val json = try { Json.parseToJsonElement(text) } catch (e: Exception) { null }
        return Reply(res.statusCode(), text, json)
    }

    /** GET /api/v1/node/info. */
    fun nodeInfo(): JsonObject {
        val r = call("GET", "/api/v1/node/info")
        if (r.status != 200) throw ToolError(if (r.status >= 500) ExitCode.NODE_BUSY else ExitCode.NODE_UNREACHABLE,
            "cannot read /api/v1/node/info from $api (HTTP ${r.status}) to learn which chain to sign for; pass --genesis <hex> to sign for a known chain", mapOf("http_code" to JsonPrimitive(r.status)))
        return r.json?.jsonObject ?: JsonObject(emptyMap())
    }

    /** The chain's signing rule as the node reports it. */
    fun signingRule(): SigningContext {
        val info = nodeInfo()
        val sv = info["signing_version"]?.jsonPrimitive?.longOrNull ?: 1
        if (sv >= 2) {
            val g = info["genesis_hash"]?.jsonPrimitive?.content ?: ""
            if (!Encoding.isHex(g, 64)) throw ToolError.internal("node enforces chain-bound signing but reports no genesis hash; pass --genesis <hex>")
            return SigningContext(2, Encoding.hexToBytes(g))
        }
        return SigningContext(1)
    }

    /** POST /api/v1/transactions -> Pair(reply, accepted). Transport failures throw. */
    fun submit(payload: JsonObject): Pair<Reply, Boolean> {
        val r = call("POST", "/api/v1/transactions", payload.toString())
        return r to (r.status == 200 || r.status == 202)
    }

    /** Submit and throw a classified ToolError when the node rejects. */
    fun submitOrThrow(payload: JsonObject): Reply {
        val (r, ok) = submit(payload)
        if (!ok) throw rejectionError(r)
        return r
    }

    /** GET /api/v1/transactions/<hash>/status; a 404 answers status not_found rather than throwing. */
    fun status(hash: String): JsonObject {
        val r = call("GET", "/api/v1/transactions/$hash/status")
        if (r.status != 200 && r.status != 404) throw rejectionError(r)
        val out = mutableMapOf<String, JsonElement>("transaction_hash" to JsonPrimitive(hash), "status" to JsonPrimitive(if (r.status == 404) "not_found" else "unknown"))
        (r.json as? JsonObject)?.let { out.putAll(it) }
        out["http_code"] = JsonPrimitive(r.status)
        return JsonObject(out)
    }

    /** GET /api/v1/transactions/<hash>; exit 7 when unknown. */
    fun transaction(hash: String): JsonElement {
        val r = call("GET", "/api/v1/transactions/$hash")
        if (r.status != 200) throw rejectionError(r).let { if (r.status == 404) ToolError(ExitCode.NOT_FOUND, "Transaction not found", it.extra) else it }
        return r.body()
    }

    /** GET /api/v1/accounts/<address>; exit 7 when unknown. */
    fun account(address: String): JsonElement {
        val r = call("GET", "/api/v1/accounts/" + URLEncoder.encode(address, "UTF-8"))
        if (r.status != 200) throw rejectionError(r).let { if (r.status == 404) ToolError(ExitCode.NOT_FOUND, "Account not found", it.extra) else it }
        return r.body()
    }

    /** GET /api/v1/blocks/latest: the reference block for a proof of ownership (`block_hash`, or a gateway's `hash`). */
    fun latestBlock(): Custom.ReferenceBlock {
        val r = call("GET", "/api/v1/blocks/latest")
        val m = r.json as? JsonObject
        val h = (m?.get("block_hash") ?: m?.get("hash"))?.jsonPrimitive?.content ?: ""
        if (r.status != 200 || !Encoding.isHex(h, 64)) throw ToolError(ExitCode.INTERNAL, "Failed to fetch latest block from $api", mapOf("http_code" to JsonPrimitive(r.status)))
        return Custom.ReferenceBlock(Encoding.hexToBytes(h), (m?.get("height")?.jsonPrimitive?.longOrNull ?: 0L).toInt())
    }

    companion object {
        /** Classify a node's rejection reply (spec/api.md section 2). */
        @JvmStatic fun rejectionError(r: Reply): ToolError {
            val text = (r.json as? JsonObject)?.get("error")?.let { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content } ?: r.text
            return ToolError(ExitCode.classifyNodeError(r.status, text), text, mapOf("http_code" to JsonPrimitive(r.status), "api_response" to r.body()))
        }
    }
}
