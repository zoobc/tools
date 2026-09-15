// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
package foundation.zoobc.zbc.cli

import foundation.zoobc.zbc.Address
import foundation.zoobc.zbc.Body
import foundation.zoobc.zbc.Client
import foundation.zoobc.zbc.Custom
import foundation.zoobc.zbc.Encoding
import foundation.zoobc.zbc.Escrow
import foundation.zoobc.zbc.ExitCode
import foundation.zoobc.zbc.KeyPair
import foundation.zoobc.zbc.Message
import foundation.zoobc.zbc.ParamDef
import foundation.zoobc.zbc.SigningContext
import foundation.zoobc.zbc.Spec
import foundation.zoobc.zbc.ToolError
import foundation.zoobc.zbc.Transaction
import foundation.zoobc.zbc.TxDef
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.BufferedReader
import java.io.InputStream
import java.io.PrintStream

/** zbc-cli: every transaction as a subcommand, plus sign-message and verify-message (spec/cli-contract.md). */
object Cli {
    private const val DEFAULT_FEE = 5_000_000L
    private val pretty = Json { prettyPrint = true; prettyPrintIndent = "  " }
    private val INT = Regex("^-?\\d+$")

    private fun category(cmd: String) = when (cmd) {
        "send-zbc", "liquid-payment", "liquid-payment-stop" -> "value"
        "transfer-token", "issue-token", "mint-token", "burn-token", "finance-token" -> "tokens"
        "swap-create", "swap-accept", "swap-cancel", "market-create", "order-place", "order-cancel" -> "exchange"
        "app-create", "app-join", "app-move", "app-resign", "app-claim", "app-settle" -> "apps"
        "store-file", "add-prepaid-storage", "dfs-create-file" -> "storage"
        "register-node", "update-node", "remove-node", "claim-node", "governance-vote" -> "node"
        "register-gateway", "unregister-gateway", "gateway-heartbeat", "archival-register", "archival-unregister", "relay-register", "relay-unregister" -> "gateway"
        "register-release", "revoke-release", "release-authority-propose", "release-authority-accept" -> "governance"
        "sign-message", "verify-message" -> "keys"
        else -> "other"
    }

    private val messageCommands: Map<String, Pair<String, List<ParamDef>>> = mapOf(
        "sign-message" to ("Sign a message with a private key (ZBC-MSG-v1, off-chain, no node needed)" to listOf(
            ParamDef("sender_privkey", "privkey", true, null, "Sender private key (64 hex)"), ParamDef("message", "string", true, null, "text to sign (hex bytes with --hex)"))),
        "verify-message" to ("Verify a ZBC-MSG-v1 message signature against a ZBC_ address (off-chain)" to listOf(
            ParamDef("address", "string", true, null, "signer's ZBC_ address (or 64-hex public key)"), ParamDef("message", "string", true, null, "the signed text (hex bytes with --hex)"),
            ParamDef("signature", "string", true, null, "64-byte Ed25519 signature, 128 hex"))),
    )

    private fun commandOf(cmd: String): Triple<String, List<ParamDef>, Int>? {
        messageCommands[cmd]?.let { return Triple(it.first, it.second, 0) }
        return Spec.command(cmd)?.let { Triple(it.description, it.params, it.type) }
    }

    /** Where a run reads and writes. */
    class Io(val stdin: InputStream, val stdout: PrintStream, val stderr: PrintStream, val env: (String) -> String?, val isTty: Boolean)

    private class Options(env: (String) -> String?) {
        var api = env("ZBC_API")?.takeIf { it.isNotEmpty() } ?: "http://localhost:8080"
        var fee = DEFAULT_FEE
        var timeout = env("ZBC_TIMEOUT")?.toLongOrNull()?.takeIf { it > 0 } ?: 20L
        var genesis = ""; var jsonInput = false; var verbose = false; var message: String? = null; var encrypt = false; var chain = ""
        var escrow: Escrow? = null; var hex = false; var offline = false; var timestamp: Long? = null; var token: String? = null; var help = false
    }

    private fun out(io: Io, v: JsonElement) = io.stdout.println(pretty.encodeToString(JsonElement.serializer(), v))
    private fun emitError(io: Io, e: ToolError, verbose: Boolean): Int { if (verbose) io.stderr.println("Error: ${e.message}") else out(io, e.toJson()); return e.code }

    private fun checkEscrow(e: Escrow) {
        if (e.approver.isEmpty()) throw ToolError.usage("Escrow requires --escrow-approver")
        if (e.timeout <= 0) throw ToolError.usage("Escrow requires --escrow-timeout > 0")
        if (e.commission < 0) throw ToolError.usage("Escrow commission cannot be negative")
    }

    private fun parseArgs(argv: List<String>, io: Io): Pair<List<String>, Options> {
        val o = Options(io.env)
        val positional = mutableListOf<String>()
        var approver = ""; var commission = 0L; var timeoutE = 0L; var instruction = ""; var escrowSeen = false
        var i = 0
        fun need(what: String = ""): String { if (i + 1 >= argv.size) throw ToolError.usage("${argv[i]} requires a value$what"); return argv[++i] }
        fun integer(s: String, what: String): Long = if (INT.matches(s)) s.toLongOrNull() ?: throw ToolError.usage(what) else throw ToolError.usage(what)
        while (i < argv.size) {
            when (val a = argv[i]) {
                "-v", "--verbose" -> o.verbose = true
                "--json" -> o.verbose = false
                "--json-input" -> o.jsonInput = true
                "--encrypt" -> o.encrypt = true
                "--hex" -> o.hex = true
                "--offline" -> o.offline = true
                "-h", "--help" -> o.help = true
                "--message" -> o.message = need()
                "--fee" -> o.fee = integer(need(), "--fee must be a whole number of atomic units")
                "--api" -> o.api = need()
                "--timeout", "--timeout-seconds" -> { val v = need(" (seconds)"); if (!Regex("^\\d+$").matches(v)) throw ToolError.usage("$a must be a whole number of seconds"); o.timeout = v.toLong(); if (o.timeout <= 0) throw ToolError.usage("$a must be > 0") }
                "--genesis" -> o.genesis = need()
                "--chain" -> o.chain = need()
                "--token" -> o.token = need()
                "--timestamp" -> { val n = integer(need(" (Unix seconds)"), "--timestamp must be a whole number of Unix seconds"); if (n <= 0) throw ToolError.usage("--timestamp must be > 0"); o.timestamp = n }
                "--escrow-approver" -> { approver = need(); escrowSeen = true }
                "--escrow-commission" -> { commission = integer(need(), "--escrow-commission must be a whole number of atomic units"); escrowSeen = true }
                "--escrow-timeout" -> { timeoutE = integer(need(), "--escrow-timeout must be a Unix timestamp in seconds"); escrowSeen = true }
                "--escrow-instruction" -> { instruction = need(); escrowSeen = true }
                else -> { if (a.length > 1 && a[0] == '-' && !a[1].isDigit() && a[1] != '.') throw ToolError.usage("Unknown option: $a"); positional.add(a) }
            }
            i++
        }
        if (o.offline && o.genesis.isEmpty() && io.env("ZOOBC_GENESIS_HASH").isNullOrEmpty()) throw ToolError.usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node")
        if (escrowSeen) { val e = Escrow(approver, commission, timeoutE, instruction); checkEscrow(e); o.escrow = e }
        return positional to o
    }

    private fun isPlaceholder(s: String) = s == "-" || s == "@env" || s == "env:ZBC_KEY"

    private fun resolveParams(params: List<ParamDef>, positional: List<String>, o: Options, io: Io): MutableMap<String, String> {
        val values = mutableMapOf<String, String>()
        val keyIsFirst = params.firstOrNull()?.name == "sender_privkey"
        val envKey = if (keyIsFirst) io.env("ZBC_KEY") ?: "" else ""
        if (o.jsonInput) {
            val text = io.stdin.bufferedReader().readText().trim()
            if (text.isEmpty()) throw ToolError.usage("No JSON input received on stdin")
            val j = try { Json.parseToJsonElement(text) as? JsonObject } catch (e: Exception) { null } ?: throw ToolError.usage("Invalid JSON input")
            for (p in params) {
                var v = when {
                    j.containsKey(p.name) -> j[p.name]!!.let { if (it is JsonPrimitive && it.isString) it.content else it.toString() }
                    !p.default.isNullOrEmpty() -> p.default
                    p.name == "sender_privkey" && envKey.isNotEmpty() -> envKey
                    p.required -> throw ToolError.usage("Missing required field: ${p.name}")
                    else -> ""
                }
                if (keyIsFirst && p.name == "sender_privkey" && isPlaceholder(v)) { if (envKey.isEmpty()) throw ToolError.usage("sender_privkey is '-' but ZBC_KEY is not set"); v = envKey }
                values[p.name] = v
            }
            fun num(k: String, what: String): Long? {
                val v = j[k] ?: return null
                val s = (v as? JsonPrimitive)?.content ?: ""
                if (!INT.matches(s)) throw ToolError.usage("$what must be a whole number")
                return s.toLong()
            }
            num("fee", "fee")?.let { o.fee = it }
            num("timeout_seconds", "timeout_seconds")?.let { if (it <= 0) throw ToolError.usage("timeout_seconds must be > 0"); o.timeout = it }
            num("timestamp", "timestamp")?.let { if (it <= 0) throw ToolError.usage("timestamp must be > 0"); o.timestamp = it }
            (j["offline"] as? JsonPrimitive)?.booleanOrNull?.let { o.offline = it }
            (j["api_url"] as? JsonPrimitive)?.takeIf { it.isString }?.let { o.api = it.content }
            (j["message"] as? JsonPrimitive)?.takeIf { it.isString }?.let { o.message = it.content }
            (j["hex"] as? JsonPrimitive)?.booleanOrNull?.let { o.hex = it }
            if ((j["verbose"] as? JsonPrimitive)?.booleanOrNull == true) o.verbose = true
            (j["escrow"] as? JsonObject)?.let { em ->
                val e = Escrow((em["approver"] as? JsonPrimitive)?.content ?: "", (em["commission"] as? JsonPrimitive)?.content?.toLongOrNull() ?: 0,
                    (em["timeout"] as? JsonPrimitive)?.content?.toLongOrNull() ?: 0, (em["instruction"] as? JsonPrimitive)?.content ?: "")
                checkEscrow(e); o.escrow = e
            }
            if (o.offline && o.genesis.isEmpty() && io.env("ZOOBC_GENESIS_HASH").isNullOrEmpty()) throw ToolError.usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node")
            return values
        }
        if (positional.isEmpty() && io.isTty && o.verbose) {
            val reader = BufferedReader(io.stdin.reader())
            for (p in params) {
                io.stdout.print("  ${p.help}${if (!p.default.isNullOrEmpty()) " [${p.default}]" else ""}: "); io.stdout.flush()
                var v = (reader.readLine() ?: "").trim().ifEmpty { p.default ?: "" }
                if (p.name == "sender_privkey" && (v.isEmpty() || isPlaceholder(v))) v = envKey
                if (p.required && v.isEmpty()) throw ToolError.usage("Missing required argument: ${p.name}")
                values[p.name] = v
            }
            return values
        }
        val pos = positional.toMutableList()
        if (keyIsFirst) {
            val required = params.count { it.required && it.default.isNullOrEmpty() }
            if (pos.isNotEmpty() && isPlaceholder(pos[0])) { if (envKey.isEmpty()) throw ToolError.usage("key argument is '-' but ZBC_KEY is not set"); pos[0] = envKey }
            else if (envKey.isNotEmpty() && pos.size + 1 == required) pos.add(0, envKey)
        }
        params.forEachIndexed { i, p ->
            values[p.name] = when {
                i < pos.size -> pos[i]
                !p.default.isNullOrEmpty() -> p.default
                p.required -> throw ToolError.usage("Missing required argument: ${p.name}${if (i == 0 && keyIsFirst) " (pass it, or set ZBC_KEY)" else ""}")
                else -> ""
            }
        }
        if (pos.size > params.size) {
            val feeArg = pos[params.size]
            if (!INT.matches(feeArg)) throw ToolError.usage("Fee must be a whole number of atomic units, got \"$feeArg\". The API endpoint is passed with --api URL, not as a positional argument.")
            o.fee = feeArg.toLong()
        }
        if (pos.size > params.size + 1) o.api = pos[params.size + 1]
        return values
    }

    private fun printList(io: Io) {
        val all = (Spec.commands.map { it.command to it.description } + messageCommands.map { it.key to it.value.first }).sortedBy { it.first }
        val groups = all.groupBy({ category(it.first) }, { "  %-26s%s".format(it.first, it.second) })
        io.stdout.print("ZooBC unified transaction CLI — ${all.size} commands.\n  Default: JSON in, JSON out.   --verbose: prompt each field + text output.\n  echo '{...}' | zbc-cli <cmd> --json-input     zbc-cli help <cmd>  (fields for one tx)\n\n")
        for (g in listOf("value", "tokens", "exchange", "apps", "storage", "account", "node", "gateway", "governance", "keys", "other")) groups[g]?.let { io.stdout.print("[$g]\n${it.joinToString("\n")}\n\n") }
        io.stdout.print("First param is the sender private key (or set ZBC_KEY and omit it / pass '-'); verify-message takes an address.\n`zbc-cli help <cmd>` shows a command's JSON fields; `zbc-cli <cmd> --help` the options, env vars and exit codes.\n")
    }

    private fun printHelp(cmd: String, io: Io): Int {
        val (desc, params, type) = commandOf(cmd) ?: run { io.stderr.println("Unknown command: $cmd (try `zbc-cli list`)"); return ExitCode.USAGE }
        io.stdout.println("$cmd — $desc  (tx type $type)\nJSON fields (default: JSON in/out; --json-input reads them on stdin; positional order matches):")
        val sample = params.associate { it.name to JsonPrimitive(it.default?.takeIf { d -> d.isNotEmpty() } ?: "...") }
        for (p in params) io.stdout.println("  %-18s%s%s%s".format(p.name, if (p.required) "(required) " else "(optional) ", p.help, if (!p.default.isNullOrEmpty()) "  [default: ${p.default}]" else ""))
        io.stdout.println("Sample: ${JsonObject(sample)}\nRun with --verbose to be prompted for each field and get human-readable output.")
        return 0
    }

    private const val USAGE_TEXT = """Options:
  -v, --verbose         Verbose output (default is JSON)
  --json-input          Read parameters from JSON on stdin
  --chain <name>        Read the recipient as this chain: zbc, btc, eth, sol, dot, ada, xrp, trx, xtz
  --message <text>      Optional transaction message
  --encrypt             Encrypt --message to the recipient (ZBC only)
  --genesis <hex|v1>    Sign for this chain (its genesis block hash) without asking the node; 'v1' = legacy unbound digest. Default: ask --api.
  --escrow-approver <addr>   Escrow approver address
  --escrow-commission <n>    Escrow commission (atomic units)
  --escrow-timeout <n>       Escrow timeout as a FUTURE Unix timestamp (seconds)
  --escrow-instruction <s>   Escrow instruction
  --fee <n>             Transaction fee (default: 5000000 = 0.05 ZBC)
  --api <url>           API endpoint (default: ${'$'}ZBC_API, else http://localhost:8080)
  --timeout <s>         Bound for each HTTP call, seconds (default: ${'$'}ZBC_TIMEOUT, else 20; also --timeout-seconds)
  --hex                 sign-message/verify-message: the message is hex bytes, not text
  --offline             Build, sign and hash, print unsigned_bytes, digest, signature, transaction_bytes and transaction_hash, exit 0 without submitting. Needs --genesis.
  --timestamp <n>       Transaction timestamp, Unix seconds (default: now)

Environment:
  ZBC_KEY               Sender private key (64 hex), used when the key argument is omitted or '-'
  ZBC_API, ZBC_TIMEOUT  Defaults for --api and --timeout
  ZOOBC_GENESIS_HASH    Default for --genesis

Exit codes:
  0 ok  1 internal  2 usage  3 node unreachable  4 insufficient balance  5 fee too low
  6 rejected by node  7 not found  8 timeout  9 node busy (5xx)  10 signature invalid
  JSON errors carry the same code as "exit_code" and its name as "error_class".
"""

    private fun printUsage(cmd: String, params: List<ParamDef>, io: Io) {
        val args = params.joinToString("") { if (it.required) " <${it.name}>" else " [${it.name}]" }
        val list = params.joinToString("") { "  %-22s%s\n".format(it.name, it.help) }
        io.stdout.print("zbc-cli $cmd\n\nUsage:\n  zbc-cli $cmd [options]$args [fee] [api_url]\n\n$USAGE_TEXT\nParameters:\n$list")
    }

    private fun messageBytes(text: String, hex: Boolean): ByteArray = if (!hex) text.toByteArray() else if (Encoding.isHex(text)) Encoding.hexToBytes(text) else throw ToolError.usage("--hex message is not valid hex")

    private fun runSignMessage(v: Map<String, String>, o: Options, io: Io): Int {
        val kp = try { KeyPair.fromHex(v["sender_privkey"]!!) } catch (e: IllegalArgumentException) { throw ToolError.usage("Private key must be 64 hex characters (32 bytes)") }
        val s = Message.sign(kp, messageBytes(v["message"]!!, o.hex))
        if (o.verbose) { io.stdout.print("Address:   ${s.address}\nDigest:    ${s.digest}\nSignature: ${s.signature}\n"); return 0 }
        val m = mutableMapOf<String, JsonElement>("success" to JsonPrimitive(true), "scheme" to JsonPrimitive(s.scheme), "address" to JsonPrimitive(s.address), "public_key" to JsonPrimitive(s.publicKey),
            "message_hex" to JsonPrimitive(s.messageHex), "digest" to JsonPrimitive(s.digest), "signature" to JsonPrimitive(s.signature))
        if (!o.hex) m["message"] = JsonPrimitive(v["message"]!!)
        out(io, JsonObject(m)); return 0
    }

    private fun runVerifyMessage(v: Map<String, String>, o: Options, io: Io): Int {
        val pub = Message.publicKeyOf(v["address"]!!) ?: throw ToolError.usage("address must be a ZBC_ account (Ed25519) address")
        val msg = messageBytes(v["message"]!!, o.hex)
        if (!Encoding.isHex(v["signature"]!!)) throw ToolError.usage("signature must be hex")
        if (v["signature"]!!.length != 128) throw ToolError.usage("signature must be 64 bytes (128 hex characters)")
        val valid = Message.verify(v["address"]!!, msg, Encoding.hexToBytes(v["signature"]!!))
        val address = Address.encode(pub, "ZBC")
        val code = if (valid) ExitCode.OK else ExitCode.VERIFY_FAILED
        if (o.verbose) { io.stdout.println("${if (valid) "VALID" else "INVALID"} signature for $address"); return code }
        out(io, JsonObject(mapOf("success" to JsonPrimitive(true), "valid" to JsonPrimitive(valid), "scheme" to JsonPrimitive(Message.SCHEME), "address" to JsonPrimitive(address),
            "digest" to JsonPrimitive(Encoding.bytesToHex(Message.digest(msg))), "exit_code" to JsonPrimitive(code), "error_class" to JsonPrimitive(ExitCode.errorClass(code)))))
        return code
    }

    private fun signingContext(o: Options, client: Client, io: Io): SigningContext {
        val g = o.genesis.ifEmpty { io.env("ZOOBC_GENESIS_HASH") ?: "" }
        if (g.isNotEmpty()) return try { SigningContext.of(g) } catch (e: IllegalArgumentException) { throw ToolError.usage(e.message ?: "bad --genesis") }
        return try { client.signingRule() } catch (e: ToolError) {
            if (e.code == ExitCode.NODE_UNREACHABLE || e.code == ExitCode.TIMEOUT)
                throw ToolError(e.code, "${if (e.code == ExitCode.TIMEOUT) "timed out reading" else "cannot read"} /api/v1/node/info from ${o.api} to learn which chain to sign for; pass --genesis <hex> to sign for a known chain")
            throw e
        }
    }

    private fun runTransaction(def: TxDef, v: MutableMap<String, String>, o: Options, io: Io): Int {
        for (p in def.params) { val cur = v[p.name] ?: ""; if (cur.isNotEmpty() || p.required) v[p.name] = Body.validateParam(p, cur) }
        if (o.encrypt) throw ToolError.usage("--encrypt is not available in this implementation yet; send the message in clear or use the C++ tools")
        val sender = try { KeyPair.fromHex(v[def.sender_key]!!) } catch (e: IllegalArgumentException) { throw ToolError.usage(e.message ?: "bad key") }
        val client = Client(o.api, o.timeout)
        val ctx = signingContext(o, client, io)
        val timestamp = o.timestamp ?: (System.currentTimeMillis() / 1000)
        var recipient = ByteArray(0)
        val extra = linkedMapOf<String, JsonElement>()
        if (def.recipient == "required") {
            val r = try { Address.parse(v["recipient"]!!, o.chain) } catch (e: IllegalArgumentException) { throw ToolError.usage("invalid recipient address: ${e.message}") }
            recipient = r.bytes; extra["recipient"] = JsonPrimitive(r.display); extra["recipient_type"] = JsonPrimitive(r.typeName)
        }
        o.token?.let { if (def.command != "liquid-payment") throw ToolError.usage("--token applies to liquid-payment only"); v["token_id"] = it }
        val files = mutableMapOf<String, ByteArray>()
        for (p in def.params) if (p.kind == "file") files[p.name] = try { java.io.File(v[p.name]!!).readBytes() } catch (e: Exception) { throw ToolError.usage("cannot read ${p.name}: ${v[p.name]}") }
        val block = if (def.needs_node) client.latestBlock() else null
        val input = Custom.Input(def, v, sender, ctx, timestamp, block)
        val body: ByteArray = if (def.custom == "multisig" || def.custom == "settle") {
            val (b, more) = Custom.body(input); extra.putAll(more); b
        } else {
            val bc = Body.Context(sender, files)
            extra.putAll(Custom.computeFields(input, bc))
            Body.build(def, v, bc)
        }
        for (p in def.params) {
            if (p.kind == "privkey" || p.kind == "file" || p.name == "recipient" || extra.containsKey(p.name)) continue
            val value = v[p.name] ?: ""
            extra[p.name] = if (p.kind in listOf("int64", "uint64", "uint32", "uint8") && INT.matches(value)) JsonPrimitive(value.toLong()) else JsonPrimitive(value)
        }
        if (def.command == "approve-escrow") {
            extra["escrowed_transaction_hash"] = JsonPrimitive(v["transaction_hash"]!!)
            extra["transaction_id"] = JsonPrimitive(Transaction.id(Encoding.hexToBytes(v["transaction_hash"]!!)))
            extra.remove("transaction_hash")
        }
        extra["sender"] = JsonPrimitive(sender.address)
        val signed = try { Transaction.sign(def.type, timestamp, sender, recipient, o.fee, body, ctx, o.escrow, (o.message ?: "").toByteArray()) }
                     catch (e: IllegalArgumentException) { throw ToolError.usage("Invalid escrow approver: ${e.message}") }
        val fields = linkedMapOf<String, JsonElement>("transaction_hash" to JsonPrimitive(Encoding.bytesToHex(signed.hash)), "transaction_type" to JsonPrimitive(def.type),
            "sender_account_address" to signed.payload["sender_account_address"]!!, "recipient_account_address" to signed.payload["recipient_account_address"]!!,
            "fee" to JsonPrimitive(o.fee), "timestamp" to JsonPrimitive(timestamp))
        val common = linkedMapOf<String, JsonElement>()
        o.message?.takeIf { it.isNotEmpty() }?.let { common["message"] = JsonPrimitive(it) }
        signed.payload["escrow"]?.let { common["escrow"] = it }
        common.putAll(extra)
        if (o.offline) {
            if (o.verbose) {
                val g = if (signed.genesisHash.isNotEmpty()) " (genesis ${Encoding.bytesToHex(signed.genesisHash)})" else ""
                io.stdout.print("OFFLINE: transaction built and signed, not submitted\n\nTransaction hash:  ${Encoding.bytesToHex(signed.hash)}\nSigning version:   ${signed.signingVersion}$g\nTimestamp:         $timestamp\n" +
                    "Unsigned bytes:    ${Encoding.bytesToHex(signed.unsigned)}\nDigest:            ${Encoding.bytesToHex(signed.digest)}\nSignature:         ${Encoding.bytesToHex(signed.signature)}\n" +
                    "Transaction bytes: ${Encoding.bytesToHex(signed.bytes)}\nPayload:           ${signed.payload}\n")
                return 0
            }
            val m = linkedMapOf<String, JsonElement>("success" to JsonPrimitive(true), "offline" to JsonPrimitive(true))
            m.putAll(fields); m["signing_version"] = JsonPrimitive(signed.signingVersion)
            if (signed.genesisHash.isNotEmpty()) m["genesis_hash"] = JsonPrimitive(Encoding.bytesToHex(signed.genesisHash))
            m["unsigned_bytes"] = JsonPrimitive(Encoding.bytesToHex(signed.unsigned)); m["digest"] = JsonPrimitive(Encoding.bytesToHex(signed.digest))
            m["signature"] = JsonPrimitive(Encoding.bytesToHex(signed.signature)); m["transaction_bytes"] = JsonPrimitive(Encoding.bytesToHex(signed.bytes)); m["payload"] = signed.payload
            m.putAll(common); out(io, JsonObject(m)); return 0
        }
        val (reply, accepted) = client.submit(signed.payload)
        if (!accepted) {
            val e = Client.rejectionError(reply)
            if (o.verbose) io.stderr.print("FAILED: Transaction submission rejected (${ExitCode.errorClass(e.code)})\nHTTP ${reply.status}: ${reply.text}\n") else out(io, e.toJson())
            return e.code
        }
        if (o.verbose) { io.stdout.print("SUCCESS: ${def.command} submitted!\n\nTransaction Hash: ${Encoding.bytesToHex(signed.hash)}\n"); return 0 }
        val m = linkedMapOf<String, JsonElement>("success" to JsonPrimitive(true)); m.putAll(fields); m["api_response"] = reply.body(); m.putAll(common)
        out(io, JsonObject(m)); return 0
    }

    /** The combined command; returns the exit code. */
    @JvmStatic fun run(args: List<String>, io: Io): Int {
        if (args.isEmpty()) {
            io.stdout.print("ZooBC unified transaction CLI\nUsage: zbc-cli <command> <params...> [--api URL] [--fee N] [--timeout S] [--verbose] [--json-input]\n       zbc-cli list   (show all commands)      zbc-cli <command> --help  (options, env vars, exit codes)\n")
            return ExitCode.USAGE
        }
        val cmd = args[0]
        if (cmd == "help" && args.size >= 2) return printHelp(args[1], io)
        if (cmd in listOf("list", "--help", "-h", "help")) { printList(io); return 0 }
        if (commandOf(cmd) == null) { io.stderr.println("Unknown command: $cmd (try `zbc-cli list`)"); return ExitCode.USAGE }
        return runTool(cmd, args.drop(1), io)
    }

    /** One command with its own arguments. */
    @JvmStatic fun runTool(cmd: String, args: List<String>, io: Io): Int {
        val (_, params, _) = commandOf(cmd) ?: run { io.stderr.println("Unknown command: $cmd (try `zbc-cli list`)"); return ExitCode.USAGE }
        var verbose = false
        return try {
            val (positional, o) = parseArgs(args, io)
            verbose = o.verbose
            if (o.help) { printUsage(cmd, params, io); return 0 }
            val values = resolveParams(params, positional, o, io)
            verbose = o.verbose
            when (cmd) { "sign-message" -> runSignMessage(values, o, io); "verify-message" -> runVerifyMessage(values, o, io); else -> runTransaction(Spec.command(cmd)!!, values, o, io) }
        } catch (e: ToolError) { emitError(io, e, verbose) } catch (e: Exception) { emitError(io, ToolError.internal(e.message ?: e.javaClass.simpleName), verbose) }
    }
}

fun main(args: Array<String>) {
    val io = Cli.Io(System.`in`, System.out, System.err, { System.getenv(it) }, System.console() != null)
    val code = Cli.run(args.toList(), io)
    System.out.flush()
    kotlin.system.exitProcess(code)
}
