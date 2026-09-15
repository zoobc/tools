// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc

import foundation.zoobc.zbc.cli.Cli
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

/** Every file in spec/vectors, through the library and in-process through the CLI. */
class VectorsTest {
    private val dir = File(System.getProperty("zbc.vectors") ?: "../spec/vectors")
    private fun load(name: String) = Json.parseToJsonElement(File(dir, name).readText()).jsonObject
    private fun s(o: JsonObject, k: String) = o[k]?.jsonPrimitive?.contentOrNull ?: ""
    private fun params(v: JsonObject) = v["params"]!!.jsonObject.mapValues { it.value.jsonPrimitive.content }

    private fun cli(args: List<String>, stdin: String = "", env: Map<String, String> = emptyMap()): Triple<Int, String, String> {
        val out = ByteArrayOutputStream(); val err = ByteArrayOutputStream()
        val io = Cli.Io(ByteArrayInputStream(stdin.toByteArray()), PrintStream(out, true), PrintStream(err, true), { env[it] }, false)
        val code = Cli.run(args, io)
        return Triple(code, out.toString(), err.toString())
    }

    @Test fun keysAndWallets() {
        val d = load("keys.json")
        for (x in d["seeds"]!!.jsonArray.map { it.jsonObject }) {
            val kp = KeyPair.fromHex(s(x, "seed"))
            assertEquals(s(x, "public_key"), Encoding.bytesToHex(kp.publicKey)); assertEquals(s(x, "address"), kp.address); assertEquals(s(x, "node_address"), kp.nodeAddress)
        }
        for (w in d["wallets"]!!.jsonArray.map { it.jsonObject }) {
            assertTrue(Wallet.validateMnemonic(s(w, "mnemonic")))
            for (a in w["accounts"]!!.jsonArray.map { it.jsonObject }) {
                val (kp, path) = Wallet.account(s(w, "mnemonic"), a["index"]!!.jsonPrimitive.content.toInt(), s(w, "passphrase"))
                assertEquals(s(a, "path"), path); assertEquals(s(a, "seed"), Encoding.bytesToHex(kp.seed)); assertEquals(s(a, "address"), kp.address); assertEquals(s(a, "node_address"), kp.nodeAddress)
            }
        }
    }

    @Test fun addresses() {
        for (v in load("addresses.json")["vectors"]!!.jsonArray.map { it.jsonObject }) {
            val input = s(v, "input"); val chain = s(v, "chain")
            if (v["valid"]!!.jsonPrimitive.booleanOrNull == true) {
                val p = Address.parse(input, chain)
                assertEquals(v["account_type"]!!.jsonPrimitive.content.toInt(), p.type, input); assertEquals(s(v, "address_bytes"), Encoding.bytesToHex(p.bytes), input)
            } else assertFails(input) { Address.parse(input, chain) }
        }
    }

    @Test fun messages() {
        val d = load("messages.json")
        for (v in d["vectors"]!!.jsonArray.map { it.jsonObject }) {
            val kp = KeyPair.fromHex(s(v, "seed")); val msg = Encoding.hexToBytes(s(v, "message_hex"))
            val sm = Message.sign(kp, msg)
            assertEquals(listOf(s(v, "address"), s(v, "public_key"), s(v, "digest"), s(v, "signature")), listOf(sm.address, sm.publicKey, sm.digest, sm.signature))
            assertTrue(Message.verify(s(v, "address"), msg, Encoding.hexToBytes(s(v, "signature"))))
        }
        for (n in d["invalid"]!!.jsonArray.map { it.jsonObject }) {
            val sig = if (Encoding.isHex(s(n, "signature"))) Encoding.hexToBytes(s(n, "signature")) else ByteArray(0)
            assertTrue(!Message.verify(s(n, "address"), s(n, "message").toByteArray(), sig), s(n, "case"))
        }
    }

    private fun checkSigned(v: JsonObject, body: ByteArray) {
        val name = s(v, "name"); val e = v["expected"]!!.jsonObject
        assertEquals(s(e, "body"), Encoding.bytesToHex(body), "$name body")
        val def = Spec.command(s(v, "command"))!!
        val kp = KeyPair.fromHex(s(v, "key"))
        val recipient = if (def.recipient == "required") Address.parse(params(v)["recipient"]!!).bytes else ByteArray(0)
        val escrow = (v["escrow"] as? JsonObject)?.let { Escrow(s(it, "approver"), it["commission"]!!.jsonPrimitive.content.toLong(), it["timeout"]!!.jsonPrimitive.content.toLong(), s(it, "instruction")) }
        val signed = Transaction.sign(v["type"]!!.jsonPrimitive.content.toInt(), v["timestamp"]!!.jsonPrimitive.content.toLong(), kp, recipient, v["fee"]!!.jsonPrimitive.content.toLong(), body,
            SigningContext.of(s(v, "genesis")), escrow, (v["message"]?.jsonPrimitive?.contentOrNull ?: "").toByteArray())
        assertEquals(s(e, "unsigned_bytes"), Encoding.bytesToHex(signed.unsigned), name); assertEquals(s(e, "digest"), Encoding.bytesToHex(signed.digest), name)
        assertEquals(s(e, "signature"), Encoding.bytesToHex(signed.signature), name); assertEquals(s(e, "transaction_bytes"), Encoding.bytesToHex(signed.bytes), name)
        assertEquals(s(e, "transaction_hash"), Encoding.bytesToHex(signed.hash), name); assertEquals(e["payload"], signed.payload, "$name payload")
    }

    @Test fun coreTransactions() {
        for (v in load("transactions.json")["vectors"]!!.jsonArray.map { it.jsonObject }) {
            val p = params(v)
            val body = if (s(v, "command") == "send-zbc") Transaction.sendZbcBody(p["amount"]!!.toLong()) else Transaction.approvalEscrowBody(p["approval"]!!.toInt(), Encoding.hexToBytes(p["transaction_hash"]!!))
            checkSigned(v, body)
        }
    }

    @Test fun allTransactionTypes() {
        for (v in load("transactions-all.json")["vectors"]!!.jsonArray.map { it.jsonObject }) {
            val def = Spec.command(s(v, "command"))!!; val p = params(v); val kp = KeyPair.fromHex(s(v, "key")); val ctx = SigningContext.of(s(v, "genesis"))
            val block = (v["reference_block"] as? JsonObject)?.let { Custom.ReferenceBlock(Encoding.hexToBytes(s(it, "block_hash")), it["height"]!!.jsonPrimitive.content.toInt()) }
            val input = Custom.Input(def, p, kp, ctx, v["timestamp"]!!.jsonPrimitive.content.toLong(), block)
            val body = if (def.custom == "multisig" || def.custom == "settle") Custom.body(input).first else {
                val files = (v["files"] as? JsonObject)?.mapValues { Encoding.hexToBytes(it.value.jsonPrimitive.content) } ?: emptyMap()
                val bc = Body.Context(kp, files); Custom.computeFields(input, bc); Body.build(def, p, bc)
            }
            checkSigned(v, body)
        }
    }

    @Test fun transactionId() { assertEquals(5427962248764179018L, Transaction.id(Encoding.hexToBytes("4ac2d11be8fe534bf2b2776fa7c1a3ece08e17f3b71e8d796545f5edde8b86fa"))) }

    @Test fun cliOfflineReproducesEveryVector() {
        val all = load("transactions.json")["vectors"]!!.jsonArray + load("transactions-all.json")["vectors"]!!.jsonArray
        for (v in all.map { it.jsonObject }) {
            val def = Spec.command(s(v, "command"))!!
            if (def.needs_node || def.params.any { it.kind == "file" }) continue
            val p = params(v)
            val args = mutableListOf(def.command, s(v, "key"))
            for (pd in def.params.drop(1)) { if (def.command == "liquid-payment" && pd.name == "token_id") continue; args.add(p[pd.name] ?: pd.default ?: "") }
            args.addAll(listOf("--fee", v["fee"]!!.jsonPrimitive.content, "--timestamp", v["timestamp"]!!.jsonPrimitive.content, "--genesis", s(v, "genesis"), "--offline"))
            v["message"]?.jsonPrimitive?.contentOrNull?.let { args.addAll(listOf("--message", it)) }
            (v["escrow"] as? JsonObject)?.let { e ->
                args.addAll(listOf("--escrow-approver", s(e, "approver"), "--escrow-commission", e["commission"]!!.jsonPrimitive.content, "--escrow-timeout", e["timeout"]!!.jsonPrimitive.content))
                s(e, "instruction").takeIf { it.isNotEmpty() }?.let { args.addAll(listOf("--escrow-instruction", it)) }
            }
            if (def.command == "liquid-payment" && (p["token_id"] ?: "0") != "0") args.addAll(listOf("--token", p["token_id"]!!))
            val (code, out, err) = cli(args)
            assertEquals(0, code, "${s(v, "name")}: $out$err")
            val j = Json.parseToJsonElement(out).jsonObject
            assertEquals(v["expected"]!!.jsonObject["transaction_hash"], j["transaction_hash"], s(v, "name"))
            assertEquals(v["expected"]!!.jsonObject["unsigned_bytes"], j["unsigned_bytes"], s(v, "name"))
            assertEquals(v["expected"]!!.jsonObject["payload"], j["payload"], s(v, "name"))
        }
    }

    @Test fun cliExitCodes() {
        for (c in load("cli.json")["vectors"]!!.jsonArray.map { it.jsonObject }) {
            val (code, out, err) = cli(c["args"]!!.jsonArray.map { it.jsonPrimitive.content }, c["stdin"]?.jsonPrimitive?.contentOrNull ?: "")
            assertEquals(c["exit_code"]!!.jsonPrimitive.content.toInt(), code, "${s(c, "case")}: $out$err")
            c["error_class"]?.jsonPrimitive?.contentOrNull?.let { assertEquals(it, Json.parseToJsonElement(out).jsonObject["error_class"]!!.jsonPrimitive.content, s(c, "case")) }
        }
    }

    @Test fun cliMessages() {
        val d = load("messages.json")
        for (v in d["vectors"]!!.jsonArray.map { it.jsonObject }) {
            val hexIn = v["hex_input"]!!.jsonPrimitive.booleanOrNull == true
            val msg = if (hexIn) s(v, "message_hex") else s(v, "message")
            val flag = if (hexIn) listOf("--hex") else emptyList()
            val (code, out, _) = cli(listOf("sign-message", s(v, "seed"), msg) + flag)
            assertEquals(0, code); assertEquals(s(v, "signature"), Json.parseToJsonElement(out).jsonObject["signature"]!!.jsonPrimitive.content)
            val (code2, out2, _) = cli(listOf("verify-message", s(v, "address"), msg, s(v, "signature")) + flag)
            assertEquals(0, code2); assertEquals(true, Json.parseToJsonElement(out2).jsonObject["valid"]!!.jsonPrimitive.booleanOrNull)
        }
        for (n in d["invalid"]!!.jsonArray.map { it.jsonObject }) assertEquals(n["exit_code"]!!.jsonPrimitive.content.toInt(), cli(listOf("verify-message", s(n, "address"), s(n, "message"), s(n, "signature"))).first, s(n, "case"))
    }

    @Test fun cliJsonInputAndEnvKey() {
        val v = load("transactions.json")["vectors"]!!.jsonArray[0].jsonObject; val p = params(v)
        val stdin = JsonObject(mapOf("sender_privkey" to JsonPrimitive(s(v, "key")), "recipient" to JsonPrimitive(p["recipient"]!!), "amount" to JsonPrimitive(p["amount"]!!),
            "fee" to v["fee"]!!, "timestamp" to v["timestamp"]!!, "offline" to JsonPrimitive(true))).toString()
        val (code, out, err) = cli(listOf("send-zbc", "--json-input", "--genesis", s(v, "genesis")), stdin)
        assertEquals(0, code, out + err); assertEquals(v["expected"]!!.jsonObject["transaction_hash"], Json.parseToJsonElement(out).jsonObject["transaction_hash"])
        for (args in listOf(listOf(p["recipient"]!!, p["amount"]!!), listOf("-", p["recipient"]!!, p["amount"]!!))) {
            val (c2, o2, e2) = cli(listOf("send-zbc") + args + listOf("--timestamp", v["timestamp"]!!.jsonPrimitive.content, "--genesis", s(v, "genesis"), "--offline"), env = mapOf("ZBC_KEY" to s(v, "key")))
            assertEquals(0, c2, o2 + e2); assertEquals(v["expected"]!!.jsonObject["transaction_hash"], Json.parseToJsonElement(o2).jsonObject["transaction_hash"])
        }
    }

    @Test fun cliUnreachableNode() {
        val v = load("transactions.json")["vectors"]!!.jsonArray[0].jsonObject; val p = params(v)
        val (code, out, _) = cli(listOf("send-zbc", s(v, "key"), p["recipient"]!!, "1", "--api", "http://127.0.0.1:9", "--genesis", "v1", "--timeout", "2"))
        assertEquals(3, code, out); assertEquals("node_unreachable", Json.parseToJsonElement(out).jsonObject["error_class"]!!.jsonPrimitive.content)
    }
}
