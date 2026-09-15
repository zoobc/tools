// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Foundation

/// zbc-cli: every transaction as a subcommand, plus sign-message and verify-message (spec/cli-contract.md).
public enum Cli {
    static let defaultFee: Int64 = 5_000_000

    /// Where a run reads and writes.
    public struct Io {
        public var stdin: () -> String
        public var stdout: (String) -> Void
        public var stderr: (String) -> Void
        public var env: (String) -> String?
        public var isTty: Bool
        public init(stdin: @escaping () -> String, stdout: @escaping (String) -> Void, stderr: @escaping (String) -> Void, env: @escaping (String) -> String?, isTty: Bool) {
            self.stdin = stdin; self.stdout = stdout; self.stderr = stderr; self.env = env; self.isTty = isTty
        }
    }

    static func category(_ cmd: String) -> String {
        switch cmd {
        case "send-zbc", "liquid-payment", "liquid-payment-stop": return "value"
        case "transfer-token", "issue-token", "mint-token", "burn-token", "finance-token": return "tokens"
        case "swap-create", "swap-accept", "swap-cancel", "market-create", "order-place", "order-cancel": return "exchange"
        case "app-create", "app-join", "app-move", "app-resign", "app-claim", "app-settle": return "apps"
        case "store-file", "add-prepaid-storage", "dfs-create-file": return "storage"
        case "register-node", "update-node", "remove-node", "claim-node", "governance-vote": return "node"
        case "register-gateway", "unregister-gateway", "gateway-heartbeat", "archival-register", "archival-unregister", "relay-register", "relay-unregister": return "gateway"
        case "register-release", "revoke-release", "release-authority-propose", "release-authority-accept": return "governance"
        case "sign-message", "verify-message": return "keys"
        default: return "other"
        }
    }

    static let messageCommands: [(String, String, [ParamDef])] = [
        ("sign-message", "Sign a message with a private key (ZBC-MSG-v1, off-chain, no node needed)", [
            ParamDef(name: "sender_privkey", kind: "privkey", required: true, help: "Sender private key (64 hex)", default: nil, min: nil, max: nil),
            ParamDef(name: "message", kind: "string", required: true, help: "text to sign (hex bytes with --hex)", default: nil, min: nil, max: nil)]),
        ("verify-message", "Verify a ZBC-MSG-v1 message signature against a ZBC_ address (off-chain)", [
            ParamDef(name: "address", kind: "string", required: true, help: "signer's ZBC_ address (or 64-hex public key)", default: nil, min: nil, max: nil),
            ParamDef(name: "message", kind: "string", required: true, help: "the signed text (hex bytes with --hex)", default: nil, min: nil, max: nil),
            ParamDef(name: "signature", kind: "string", required: true, help: "64-byte Ed25519 signature, 128 hex", default: nil, min: nil, max: nil)]),
    ]

    static func commandOf(_ cmd: String) -> (String, [ParamDef], UInt32)? {
        if let m = messageCommands.first(where: { $0.0 == cmd }) { return (m.1, m.2, 0) }
        return Spec.command(cmd).map { ($0.description, $0.params, $0.type) }
    }

    struct Options {
        var api = "http://localhost:8080", fee = defaultFee, timeout: Double = 20, genesis = "", jsonInput = false, verbose = false
        var message: String? = nil, encrypt = false, chain = "", escrow: Escrow? = nil, hex = false, offline = false, timestamp: Int64? = nil, token: String? = nil, help = false
    }

    static func out(_ io: Io, _ pairs: [(String, Any)]) { io.stdout(JSONText.encode(pairs, indent: 2) + "\n") }
    static func emitError(_ io: Io, _ e: ToolError, verbose: Bool) -> Int {
        if verbose { io.stderr("Error: \(e.message)\n") } else { out(io, e.json.keys.sorted().map { ($0, e.json[$0]!) }.sorted { order($0.0) < order($1.0) }) }
        return e.code
    }
    private static func order(_ k: String) -> Int { ["success": 0, "error": 1, "exit_code": 2, "error_class": 3, "http_code": 4, "api_response": 5][k] ?? 9 }

    static func isInt(_ s: String) -> Bool { let d = s.hasPrefix("-") ? String(s.dropFirst()) : s; return !d.isEmpty && d.allSatisfy { $0.isASCII && $0.isNumber } }

    static func checkEscrow(_ e: Escrow) throws {
        if e.approver.isEmpty { throw ToolError.usage("Escrow requires --escrow-approver") }
        if e.timeout <= 0 { throw ToolError.usage("Escrow requires --escrow-timeout > 0") }
        if e.commission < 0 { throw ToolError.usage("Escrow commission cannot be negative") }
    }

    static func parseArgs(_ argv: [String], _ io: Io) throws -> ([String], Options) {
        var o = Options()
        if let a = io.env("ZBC_API"), !a.isEmpty { o.api = a }
        if let t = io.env("ZBC_TIMEOUT"), let n = Double(t), n > 0, t.allSatisfy({ $0.isNumber }) { o.timeout = n }
        var positional: [String] = []
        var escrow = Escrow(approver: ""); var escrowSeen = false
        var i = 0
        func need(_ what: String = "") throws -> String { guard i + 1 < argv.count else { throw ToolError.usage("\(argv[i]) requires a value\(what)") }; i += 1; return argv[i] }
        func integer(_ s: String, _ what: String) throws -> Int64 { guard isInt(s), let n = Int64(s) else { throw ToolError.usage(what) }; return n }
        while i < argv.count {
            let a = argv[i]
            switch a {
            case "-v", "--verbose": o.verbose = true
            case "--json": o.verbose = false
            case "--json-input": o.jsonInput = true
            case "--encrypt": o.encrypt = true
            case "--hex": o.hex = true
            case "--offline": o.offline = true
            case "-h", "--help": o.help = true
            case "--message": o.message = try need()
            case "--fee": o.fee = try integer(try need(), "--fee must be a whole number of atomic units")
            case "--api": o.api = try need()
            case "--timeout", "--timeout-seconds":
                let v = try need(" (seconds)")
                guard !v.isEmpty, v.allSatisfy({ $0.isASCII && $0.isNumber }), let n = Double(v) else { throw ToolError.usage("\(a) must be a whole number of seconds") }
                guard n > 0 else { throw ToolError.usage("\(a) must be > 0") }
                o.timeout = n
            case "--genesis": o.genesis = try need()
            case "--chain": o.chain = try need()
            case "--token": o.token = try need()
            case "--timestamp":
                let n = try integer(try need(" (Unix seconds)"), "--timestamp must be a whole number of Unix seconds")
                guard n > 0 else { throw ToolError.usage("--timestamp must be > 0") }
                o.timestamp = n
            case "--escrow-approver": escrow.approver = try need(); escrowSeen = true
            case "--escrow-commission": escrow.commission = try integer(try need(), "--escrow-commission must be a whole number of atomic units"); escrowSeen = true
            case "--escrow-timeout": escrow.timeout = try integer(try need(), "--escrow-timeout must be a Unix timestamp in seconds"); escrowSeen = true
            case "--escrow-instruction": escrow.instruction = try need(); escrowSeen = true
            default:
                let u = Array(a.utf8)
                if u.count > 1 && u[0] == UInt8(ascii: "-") && !(u[1] >= 48 && u[1] <= 57) && u[1] != UInt8(ascii: ".") { throw ToolError.usage("Unknown option: \(a)") }
                positional.append(a)
            }
            i += 1
        }
        if o.offline && o.genesis.isEmpty && (io.env("ZOOBC_GENESIS_HASH") ?? "").isEmpty { throw ToolError.usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node") }
        if escrowSeen { try checkEscrow(escrow); o.escrow = escrow }
        return (positional, o)
    }

    static func isPlaceholder(_ s: String) -> Bool { s == "-" || s == "@env" || s == "env:ZBC_KEY" }

    static func resolveParams(_ params: [ParamDef], _ positional: [String], _ o: inout Options, _ io: Io) throws -> [String: String] {
        var values: [String: String] = [:]
        let keyIsFirst = params.first?.name == "sender_privkey"
        let envKey = keyIsFirst ? (io.env("ZBC_KEY") ?? "") : ""
        if o.jsonInput {
            let text = io.stdin().trimmingCharacters(in: .whitespacesAndNewlines)
            if text.isEmpty { throw ToolError.usage("No JSON input received on stdin") }
            guard let j = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] else { throw ToolError.usage("Invalid JSON input") }
            for p in params {
                var v: String
                if let x = j[p.name] { v = (x as? String) ?? JSONText.encodeValue(x) }
                else if let d = p.default, !d.isEmpty { v = d }
                else if p.name == "sender_privkey" && !envKey.isEmpty { v = envKey }
                else if p.required { throw ToolError.usage("Missing required field: \(p.name)") }
                else { v = "" }
                if keyIsFirst && p.name == "sender_privkey" && isPlaceholder(v) { guard !envKey.isEmpty else { throw ToolError.usage("sender_privkey is '-' but ZBC_KEY is not set") }; v = envKey }
                values[p.name] = v
            }
            func num(_ k: String, _ what: String) throws -> Int64? {
                guard let x = j[k] else { return nil }
                let s = (x as? String) ?? ((x as? NSNumber).map { $0.stringValue } ?? "")
                guard isInt(s), let n = Int64(s) else { throw ToolError.usage("\(what) must be a whole number") }
                return n
            }
            if let n = try num("fee", "fee") { o.fee = n }
            if let n = try num("timeout_seconds", "timeout_seconds") { guard n > 0 else { throw ToolError.usage("timeout_seconds must be > 0") }; o.timeout = Double(n) }
            if let n = try num("timestamp", "timestamp") { guard n > 0 else { throw ToolError.usage("timestamp must be > 0") }; o.timestamp = n }
            if let b = j["offline"] as? Bool { o.offline = b }
            if let s = j["api_url"] as? String { o.api = s }
            if let s = j["message"] as? String { o.message = s }
            if let b = j["hex"] as? Bool { o.hex = b }
            if let b = j["verbose"] as? Bool, b { o.verbose = true }
            if let em = j["escrow"] as? [String: Any] {
                let e = Escrow(approver: em["approver"] as? String ?? "", commission: (em["commission"] as? NSNumber)?.int64Value ?? 0,
                               timeout: (em["timeout"] as? NSNumber)?.int64Value ?? 0, instruction: em["instruction"] as? String ?? "")
                try checkEscrow(e); o.escrow = e
            }
            if o.offline && o.genesis.isEmpty && (io.env("ZOOBC_GENESIS_HASH") ?? "").isEmpty { throw ToolError.usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node") }
            return values
        }
        if positional.isEmpty && io.isTty && o.verbose {
            let lines = io.stdin().split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            for (n, p) in params.enumerated() {
                io.stdout("  \(p.help)\((p.default ?? "").isEmpty ? "" : " [\(p.default!)]"): ")
                var v = (n < lines.count ? lines[n] : "").trimmingCharacters(in: .whitespaces)
                if v.isEmpty { v = p.default ?? "" }
                if p.name == "sender_privkey" && (v.isEmpty || isPlaceholder(v)) { v = envKey }
                if p.required && v.isEmpty { throw ToolError.usage("Missing required argument: \(p.name)") }
                values[p.name] = v
            }
            return values
        }
        var pos = positional
        if keyIsFirst {
            let required = params.filter { $0.required && ($0.default ?? "").isEmpty }.count
            if let f = pos.first, isPlaceholder(f) { guard !envKey.isEmpty else { throw ToolError.usage("key argument is '-' but ZBC_KEY is not set") }; pos[0] = envKey }
            else if !envKey.isEmpty && pos.count + 1 == required { pos.insert(envKey, at: 0) }
        }
        for (i, p) in params.enumerated() {
            if i < pos.count { values[p.name] = pos[i] }
            else if let d = p.default, !d.isEmpty { values[p.name] = d }
            else if p.required { throw ToolError.usage("Missing required argument: \(p.name)\(i == 0 && keyIsFirst ? " (pass it, or set ZBC_KEY)" : "")") }
            else { values[p.name] = "" }
        }
        if pos.count > params.count {
            let feeArg = pos[params.count]
            guard isInt(feeArg), let n = Int64(feeArg) else { throw ToolError.usage("Fee must be a whole number of atomic units, got \"\(feeArg)\". The API endpoint is passed with --api URL, not as a positional argument.") }
            o.fee = n
        }
        if pos.count > params.count + 1 { o.api = pos[params.count + 1] }
        return values
    }

    static func printList(_ io: Io) {
        let all = (Spec.commands.map { ($0.command, $0.description) } + messageCommands.map { ($0.0, $0.1) }).sorted { $0.0 < $1.0 }
        var groups: [String: [String]] = [:]
        for (cmd, desc) in all { groups[category(cmd), default: []].append("  " + cmd.padding(toLength: 26, withPad: " ", startingAt: 0) + desc) }
        var s = "ZooBC unified transaction CLI — \(all.count) commands.\n  Default: JSON in, JSON out.   --verbose: prompt each field + text output.\n  echo '{...}' | zbc-cli <cmd> --json-input     zbc-cli help <cmd>  (fields for one tx)\n\n"
        for g in ["value", "tokens", "exchange", "apps", "storage", "account", "node", "gateway", "governance", "keys", "other"] { if let lines = groups[g] { s += "[\(g)]\n" + lines.joined(separator: "\n") + "\n\n" } }
        s += "First param is the sender private key (or set ZBC_KEY and omit it / pass '-'); verify-message takes an address.\n`zbc-cli help <cmd>` shows a command's JSON fields; `zbc-cli <cmd> --help` the options, env vars and exit codes.\n"
        io.stdout(s)
    }

    static func printHelp(_ cmd: String, _ io: Io) -> Int {
        guard let (desc, params, type) = commandOf(cmd) else { io.stderr("Unknown command: \(cmd) (try `zbc-cli list`)\n"); return ExitCode.usage }
        var s = "\(cmd) — \(desc)  (tx type \(type))\nJSON fields (default: JSON in/out; --json-input reads them on stdin; positional order matches):\n"
        var sample: [(String, Any)] = []
        for p in params {
            s += "  " + p.name.padding(toLength: 18, withPad: " ", startingAt: 0) + (p.required ? "(required) " : "(optional) ") + p.help + ((p.default ?? "").isEmpty ? "" : "  [default: \(p.default!)]") + "\n"
            sample.append((p.name, (p.default ?? "").isEmpty ? "..." : p.default!))
        }
        s += "Sample: \(JSONText.encode(sample))\nRun with --verbose to be prompted for each field and get human-readable output.\n"
        io.stdout(s)
        return 0
    }

    static let usageText = """
    Options:
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
      --api <url>           API endpoint (default: $ZBC_API, else http://localhost:8080)
      --timeout <s>         Bound for each HTTP call, seconds (default: $ZBC_TIMEOUT, else 20; also --timeout-seconds)
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

    static func printUsage(_ cmd: String, _ params: [ParamDef], _ io: Io) {
        let args = params.map { $0.required ? " <\($0.name)>" : " [\($0.name)]" }.joined()
        let list = params.map { "  " + $0.name.padding(toLength: 22, withPad: " ", startingAt: 0) + $0.help + "\n" }.joined()
        io.stdout("zbc-cli \(cmd)\n\nUsage:\n  zbc-cli \(cmd) [options]\(args) [fee] [api_url]\n\n\(usageText)\nParameters:\n\(list)")
    }

    static func messageBytes(_ text: String, _ hex: Bool) throws -> [UInt8] {
        if !hex { return Array(text.utf8) }
        guard let b = Enc.unhex(text) else { throw ToolError.usage("--hex message is not valid hex") }
        return b
    }

    static func runSignMessage(_ v: [String: String], _ o: Options, _ io: Io) throws -> Int {
        guard let kp = try? KeyPair(hex: v["sender_privkey"]!) else { throw ToolError.usage("Private key must be 64 hex characters (32 bytes)") }
        let s = Message.sign(kp, try messageBytes(v["message"]!, o.hex))
        if o.verbose { io.stdout("Address:   \(s.address)\nDigest:    \(s.digest)\nSignature: \(s.signature)\n"); return 0 }
        var m: [(String, Any)] = [("success", true), ("scheme", s.scheme), ("address", s.address), ("public_key", s.publicKey), ("message_hex", s.messageHex), ("digest", s.digest), ("signature", s.signature)]
        if !o.hex { m.append(("message", v["message"]!)) }
        out(io, m); return 0
    }

    static func runVerifyMessage(_ v: [String: String], _ o: Options, _ io: Io) throws -> Int {
        guard let pub = Message.publicKey(of: v["address"]!) else { throw ToolError.usage("address must be a ZBC_ account (Ed25519) address") }
        let msg = try messageBytes(v["message"]!, o.hex)
        guard Enc.isHex(v["signature"]!) else { throw ToolError.usage("signature must be hex") }
        guard v["signature"]!.utf8.count == 128 else { throw ToolError.usage("signature must be 64 bytes (128 hex characters)") }
        let valid = Message.verify(v["address"]!, msg, Enc.unhex(v["signature"]!)!)
        let address = Address.encode(pub, prefix: "ZBC")!
        let code = valid ? ExitCode.ok : ExitCode.verifyFailed
        if o.verbose { io.stdout("\(valid ? "VALID" : "INVALID") signature for \(address)\n"); return code }
        out(io, [("success", true), ("valid", valid), ("scheme", Message.scheme), ("address", address), ("digest", Enc.hex(Message.digest(msg))), ("exit_code", code), ("error_class", ExitCode.errorClass(code))])
        return code
    }

    static func signingContext(_ o: Options, _ client: Client, _ io: Io) throws -> SigningContext {
        let g = o.genesis.isEmpty ? (io.env("ZOOBC_GENESIS_HASH") ?? "") : o.genesis
        if !g.isEmpty { do { return try SigningContext.of(g) } catch let e as Address.Invalid { throw ToolError.usage(e.message) } }
        do { return try client.signingRule() } catch let e as ToolError {
            if e.code == ExitCode.nodeUnreachable || e.code == ExitCode.timeout {
                throw ToolError(e.code, "\(e.code == ExitCode.timeout ? "timed out reading" : "cannot read") /api/v1/node/info from \(o.api) to learn which chain to sign for; pass --genesis <hex> to sign for a known chain")
            }
            throw e
        }
    }

    static func runTransaction(_ def: TxDef, _ vIn: [String: String], _ o: Options, _ io: Io) throws -> Int {
        var v = vIn
        for p in def.params { let cur = v[p.name] ?? ""; if !cur.isEmpty || p.required { v[p.name] = try Body.validateParam(p, cur) } }
        if o.encrypt { throw ToolError.usage("--encrypt is not available in this implementation yet; send the message in clear or use the C++ tools") }
        let sender: KeyPair
        do { sender = try KeyPair(hex: v[def.sender_key] ?? "") } catch let e as Address.Invalid { throw ToolError.usage(e.message) }
        let client = Client(api: o.api, timeoutSeconds: o.timeout)
        let ctx = try signingContext(o, client, io)
        let timestamp = o.timestamp ?? Int64(Date().timeIntervalSince1970)
        var recipient: [UInt8] = []
        var extra: [(String, Any)] = []
        if def.recipient == "required" {
            let r: ParsedAddress
            do { r = try Address.parse(v["recipient"]!, chain: o.chain) } catch let e as Address.Invalid { throw ToolError.usage("invalid recipient address: \(e.message)") }
            recipient = r.bytes; extra.append(("recipient", r.display)); extra.append(("recipient_type", r.typeName))
        }
        if let t = o.token { guard def.command == "liquid-payment" else { throw ToolError.usage("--token applies to liquid-payment only") }; v["token_id"] = t }
        var files: [String: [UInt8]] = [:]
        for p in def.params where p.kind == "file" {
            guard let d = FileManager.default.contents(atPath: v[p.name]!) else { throw ToolError.usage("cannot read \(p.name): \(v[p.name]!)") }
            files[p.name] = Array(d)
        }
        let block = def.needs_node ? try client.latestBlock() : nil
        let input = Custom.Input(def: def, params: v, sender: sender, ctx: ctx, timestamp: timestamp, block: block)
        let body: [UInt8]
        if def.custom == "multisig" || def.custom == "settle" {
            let (b, more) = try Custom.body(input); body = b; extra += more
        } else {
            let bc = Body.Context(sender: sender, files: files)
            extra += try Custom.computeFields(input, bc)
            body = try Body.build(def, v, bc)
        }
        for p in def.params where p.kind != "privkey" && p.kind != "file" && p.name != "recipient" && !extra.contains(where: { $0.0 == p.name }) {
            let val = v[p.name] ?? ""
            if ["int64", "uint64", "uint32", "uint8"].contains(p.kind), isInt(val), let n = Int64(val) { extra.append((p.name, n)) } else { extra.append((p.name, val)) }
        }
        if def.command == "approve-escrow" {
            extra.removeAll { $0.0 == "transaction_hash" }
            extra.append(("escrowed_transaction_hash", v["transaction_hash"]!)); extra.append(("transaction_id", Transaction.id(Enc.unhex(v["transaction_hash"]!)!)))
        }
        extra.append(("sender", sender.address))
        let signed: SignedTransaction
        do { signed = try Transaction.sign(type: def.type, timestamp: timestamp, sender: sender, recipient: recipient, fee: o.fee, body: body, ctx: ctx, escrow: o.escrow, message: Array((o.message ?? "").utf8)) }
        catch let e as Address.Invalid { throw ToolError.usage("Invalid escrow approver: \(e.message)") }
        let payload = signed.payloadDictionary
        let fields: [(String, Any)] = [("transaction_hash", Enc.hex(signed.hash)), ("transaction_type", Int(def.type)), ("sender_account_address", payload["sender_account_address"]!),
                                       ("recipient_account_address", payload["recipient_account_address"]!), ("fee", o.fee), ("timestamp", timestamp)]
        var common: [(String, Any)] = []
        if let m = o.message, !m.isEmpty { common.append(("message", m)) }
        if let e = payload["escrow"] { common.append(("escrow", e)) }
        common += extra
        if o.offline {
            if o.verbose {
                let g = signed.genesisHash.isEmpty ? "" : " (genesis \(Enc.hex(signed.genesisHash)))"
                io.stdout("OFFLINE: transaction built and signed, not submitted\n\nTransaction hash:  \(Enc.hex(signed.hash))\nSigning version:   \(signed.signingVersion)\(g)\nTimestamp:         \(timestamp)\nUnsigned bytes:    \(Enc.hex(signed.unsigned))\nDigest:            \(Enc.hex(signed.digest))\nSignature:         \(Enc.hex(signed.signature))\nTransaction bytes: \(Enc.hex(signed.bytes))\nPayload:           \(JSONText.encode(signed.payload))\n")
                return 0
            }
            var m: [(String, Any)] = [("success", true), ("offline", true)] + fields + [("signing_version", signed.signingVersion)]
            if !signed.genesisHash.isEmpty { m.append(("genesis_hash", Enc.hex(signed.genesisHash))) }
            m += [("unsigned_bytes", Enc.hex(signed.unsigned)), ("digest", Enc.hex(signed.digest)), ("signature", Enc.hex(signed.signature)), ("transaction_bytes", Enc.hex(signed.bytes)), ("payload", signed.payload)]
            m += common
            out(io, m); return 0
        }
        let (reply, accepted) = try client.submit(signed.payload)
        if !accepted {
            let e = Client.rejectionError(reply)
            if o.verbose { io.stderr("FAILED: Transaction submission rejected (\(ExitCode.errorClass(e.code)))\nHTTP \(reply.status): \(reply.text)\n") }
            else { out(io, [("success", false), ("error", e.message), ("exit_code", e.code), ("error_class", ExitCode.errorClass(e.code)), ("http_code", reply.status), ("api_response", reply.body)]) }
            return e.code
        }
        if o.verbose { io.stdout("SUCCESS: \(def.command) submitted!\n\nTransaction Hash: \(Enc.hex(signed.hash))\n"); return 0 }
        out(io, [("success", true)] + fields + [("api_response", reply.body)] + common)
        return 0
    }

    /// The combined command; returns the exit code.
    public static func run(_ args: [String], _ io: Io) -> Int {
        if args.isEmpty {
            io.stdout("ZooBC unified transaction CLI\nUsage: zbc-cli <command> <params...> [--api URL] [--fee N] [--timeout S] [--verbose] [--json-input]\n       zbc-cli list   (show all commands)      zbc-cli <command> --help  (options, env vars, exit codes)\n")
            return ExitCode.usage
        }
        let cmd = args[0]
        if cmd == "help" && args.count >= 2 { return printHelp(args[1], io) }
        if ["list", "--help", "-h", "help"].contains(cmd) { printList(io); return 0 }
        guard commandOf(cmd) != nil else { io.stderr("Unknown command: \(cmd) (try `zbc-cli list`)\n"); return ExitCode.usage }
        return runTool(cmd, Array(args.dropFirst()), io)
    }

    /// One command with its own arguments.
    public static func runTool(_ cmd: String, _ args: [String], _ io: Io) -> Int {
        guard let (_, params, _) = commandOf(cmd) else { io.stderr("Unknown command: \(cmd) (try `zbc-cli list`)\n"); return ExitCode.usage }
        var verbose = false
        do {
            let (positional, parsed) = try parseArgs(args, io)
            var o = parsed
            verbose = o.verbose
            if o.help { printUsage(cmd, params, io); return 0 }
            let values = try resolveParams(params, positional, &o, io)
            verbose = o.verbose
            switch cmd {
            case "sign-message": return try runSignMessage(values, o, io)
            case "verify-message": return try runVerifyMessage(values, o, io)
            default: return try runTransaction(Spec.command(cmd)!, values, o, io)
            }
        } catch let e as ToolError { return emitError(io, e, verbose: verbose) }
        catch { return emitError(io, ToolError.internalError("\(error)"), verbose: verbose) }
    }
}
