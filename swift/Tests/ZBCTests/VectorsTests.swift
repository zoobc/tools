// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Foundation
import XCTest
@testable import ZBC

/// Every file in spec/vectors, through the library and in-process through the CLI.
final class VectorsTests: XCTestCase {
    static let vectorsDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("spec").appendingPathComponent("vectors")

    func load(_ name: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Data(contentsOf: Self.vectorsDir.appendingPathComponent(name))) as! [String: Any]
    }
    func s(_ o: [String: Any], _ k: String) -> String { o[k] as? String ?? "" }
    func i64(_ v: Any?) -> Int64 { (v as? NSNumber)?.int64Value ?? Int64(v as? String ?? "") ?? 0 }
    func params(_ v: [String: Any]) -> [String: String] { (v["params"] as! [String: Any]).mapValues { $0 as? String ?? "" } }

    func cli(_ args: [String], stdin: String = "", env: [String: String] = [:]) -> (Int, String, String) {
        var out = "", err = ""
        let io = Cli.Io(stdin: { stdin }, stdout: { out += $0 }, stderr: { err += $0 }, env: { env[$0] }, isTty: false)
        let code = Cli.run(args, io)
        return (code, out, err)
    }
    func json(_ text: String) -> [String: Any] { (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] ?? [:] }
    func canonical(_ v: Any) -> String { String(decoding: try! JSONSerialization.data(withJSONObject: v, options: [.sortedKeys]), as: UTF8.self) }

    func testKeysAndWallets() throws {
        let d = try load("keys.json")
        for x in d["seeds"] as! [[String: Any]] {
            let kp = try KeyPair(hex: s(x, "seed"))
            XCTAssertEqual(Enc.hex(kp.publicKey), s(x, "public_key")); XCTAssertEqual(kp.address, s(x, "address")); XCTAssertEqual(kp.nodeAddress, s(x, "node_address"))
        }
        for w in d["wallets"] as! [[String: Any]] {
            XCTAssertTrue(Wallet.validateMnemonic(s(w, "mnemonic")))
            for a in w["accounts"] as! [[String: Any]] {
                let (kp, path) = try Wallet.account(s(w, "mnemonic"), index: Int(i64(a["index"])), passphrase: s(w, "passphrase"))
                XCTAssertEqual(path, s(a, "path")); XCTAssertEqual(Enc.hex(kp.seed), s(a, "seed")); XCTAssertEqual(kp.address, s(a, "address")); XCTAssertEqual(kp.nodeAddress, s(a, "node_address"))
            }
        }
    }

    func testAddresses() throws {
        for v in try load("addresses.json")["vectors"] as! [[String: Any]] {
            let input = s(v, "input"), chain = s(v, "chain")
            if v["valid"] as? Bool == true {
                let p = try Address.parse(input, chain: chain)
                XCTAssertEqual(Int64(p.type), i64(v["account_type"]), input); XCTAssertEqual(Enc.hex(p.bytes), s(v, "address_bytes"), input)
            } else {
                XCTAssertThrowsError(try Address.parse(input, chain: chain), input)
            }
        }
    }

    func testMessages() throws {
        let d = try load("messages.json")
        for v in d["vectors"] as! [[String: Any]] {
            let kp = try KeyPair(hex: s(v, "seed")); let msg = Enc.unhex(s(v, "message_hex"))!
            let sm = Message.sign(kp, msg)
            XCTAssertEqual([sm.address, sm.publicKey, sm.digest, sm.signature], [s(v, "address"), s(v, "public_key"), s(v, "digest"), s(v, "signature")])
            XCTAssertTrue(Message.verify(s(v, "address"), msg, Enc.unhex(s(v, "signature"))!))
        }
        for n in d["invalid"] as! [[String: Any]] {
            XCTAssertFalse(Message.verify(s(n, "address"), Array(s(n, "message").utf8), Enc.unhex(s(n, "signature")) ?? []), s(n, "case"))
        }
    }

    func checkSigned(_ v: [String: Any], _ body: [UInt8]) throws {
        let name = s(v, "name"); let e = v["expected"] as! [String: Any]
        XCTAssertEqual(Enc.hex(body), s(e, "body"), "\(name) body")
        let def = Spec.command(s(v, "command"))!
        let kp = try KeyPair(hex: s(v, "key"))
        let recipient = def.recipient == "required" ? try Address.parse(params(v)["recipient"]!).bytes : []
        var escrow: Escrow? = nil
        if let em = v["escrow"] as? [String: Any] { escrow = Escrow(approver: s(em, "approver"), commission: i64(em["commission"]), timeout: i64(em["timeout"]), instruction: s(em, "instruction")) }
        let signed = try Transaction.sign(type: UInt32(i64(v["type"])), timestamp: i64(v["timestamp"]), sender: kp, recipient: recipient, fee: i64(v["fee"]), body: body,
                                          ctx: try SigningContext.of(s(v, "genesis")), escrow: escrow, message: Array((v["message"] as? String ?? "").utf8))
        XCTAssertEqual(Enc.hex(signed.unsigned), s(e, "unsigned_bytes"), name); XCTAssertEqual(Enc.hex(signed.digest), s(e, "digest"), name)
        XCTAssertEqual(Enc.hex(signed.signature), s(e, "signature"), name); XCTAssertEqual(Enc.hex(signed.bytes), s(e, "transaction_bytes"), name)
        XCTAssertEqual(Enc.hex(signed.hash), s(e, "transaction_hash"), name)
        XCTAssertEqual(canonical(signed.payloadDictionary), canonical(e["payload"]!), "\(name) payload")
    }

    func testCoreTransactions() throws {
        for v in try load("transactions.json")["vectors"] as! [[String: Any]] {
            let p = params(v)
            let body = s(v, "command") == "send-zbc" ? Transaction.sendZBCBody(Int64(p["amount"]!)!) : try Transaction.approvalEscrowBody(UInt32(p["approval"]!)!, Enc.unhex(p["transaction_hash"]!)!)
            try checkSigned(v, body)
        }
    }

    func testAllTransactionTypes() throws {
        for v in try load("transactions-all.json")["vectors"] as! [[String: Any]] {
            let def = Spec.command(s(v, "command"))!; let p = params(v); let kp = try KeyPair(hex: s(v, "key")); let ctx = try SigningContext.of(s(v, "genesis"))
            var block: Custom.ReferenceBlock? = nil
            if let b = v["reference_block"] as? [String: Any] { block = Custom.ReferenceBlock(hash: Enc.unhex(s(b, "block_hash"))!, height: UInt32(i64(b["height"]))) }
            let input = Custom.Input(def: def, params: p, sender: kp, ctx: ctx, timestamp: i64(v["timestamp"]), block: block)
            let body: [UInt8]
            if def.custom == "multisig" || def.custom == "settle" { body = try Custom.body(input).0 }
            else {
                let files = (v["files"] as? [String: String] ?? [:]).mapValues { Enc.unhex($0)! }
                let bc = Body.Context(sender: kp, files: files)
                _ = try Custom.computeFields(input, bc)
                body = try Body.build(def, p, bc)
            }
            try checkSigned(v, body)
        }
    }

    func testTransactionId() { XCTAssertEqual(Transaction.id(Enc.unhex("4ac2d11be8fe534bf2b2776fa7c1a3ece08e17f3b71e8d796545f5edde8b86fa")!), 5427962248764179018) }

    func testCliOfflineReproducesEveryVector() throws {
        let all = (try load("transactions.json")["vectors"] as! [[String: Any]]) + (try load("transactions-all.json")["vectors"] as! [[String: Any]])
        for v in all {
            let def = Spec.command(s(v, "command"))!
            if def.needs_node || def.params.contains(where: { $0.kind == "file" }) { continue }
            let p = params(v)
            var args = [def.command, s(v, "key")]
            for pd in def.params.dropFirst() { if def.command == "liquid-payment" && pd.name == "token_id" { continue }; args.append(p[pd.name] ?? pd.default ?? "") }
            args += ["--fee", String(i64(v["fee"])), "--timestamp", String(i64(v["timestamp"])), "--genesis", s(v, "genesis"), "--offline"]
            if let m = v["message"] as? String { args += ["--message", m] }
            if let e = v["escrow"] as? [String: Any] {
                args += ["--escrow-approver", s(e, "approver"), "--escrow-commission", String(i64(e["commission"])), "--escrow-timeout", String(i64(e["timeout"]))]
                if !s(e, "instruction").isEmpty { args += ["--escrow-instruction", s(e, "instruction")] }
            }
            if def.command == "liquid-payment", let t = p["token_id"], t != "0" { args += ["--token", t] }
            let (code, out, err) = cli(args)
            XCTAssertEqual(code, 0, "\(s(v, "name")): \(out)\(err)")
            let j = json(out); let e = v["expected"] as! [String: Any]
            XCTAssertEqual(j["transaction_hash"] as? String, s(e, "transaction_hash"), s(v, "name"))
            XCTAssertEqual(j["unsigned_bytes"] as? String, s(e, "unsigned_bytes"), s(v, "name"))
            XCTAssertEqual(canonical(j["payload"] ?? ""), canonical(e["payload"]!), s(v, "name"))
        }
    }

    func testCliExitCodes() throws {
        for c in try load("cli.json")["vectors"] as! [[String: Any]] {
            let (code, out, err) = cli(c["args"] as! [String], stdin: c["stdin"] as? String ?? "")
            XCTAssertEqual(Int64(code), i64(c["exit_code"]), "\(s(c, "case")): \(out)\(err)")
            if let cls = c["error_class"] as? String { XCTAssertEqual(json(out)["error_class"] as? String, cls, s(c, "case")) }
        }
    }

    func testCliMessages() throws {
        let d = try load("messages.json")
        for v in d["vectors"] as! [[String: Any]] {
            let hexIn = v["hex_input"] as? Bool == true
            let msg = hexIn ? s(v, "message_hex") : s(v, "message")
            let flag = hexIn ? ["--hex"] : []
            let (code, out, _) = cli(["sign-message", s(v, "seed"), msg] + flag)
            XCTAssertEqual(code, 0); XCTAssertEqual(json(out)["signature"] as? String, s(v, "signature"))
            let (code2, out2, _) = cli(["verify-message", s(v, "address"), msg, s(v, "signature")] + flag)
            XCTAssertEqual(code2, 0); XCTAssertEqual(json(out2)["valid"] as? Bool, true)
        }
        for n in d["invalid"] as! [[String: Any]] {
            XCTAssertEqual(Int64(cli(["verify-message", s(n, "address"), s(n, "message"), s(n, "signature")]).0), i64(n["exit_code"]), s(n, "case"))
        }
    }

    func testCliJsonInputAndEnvKey() throws {
        let v = (try load("transactions.json")["vectors"] as! [[String: Any]])[0]; let p = params(v); let e = v["expected"] as! [String: Any]
        let stdin = JSONText.encode([("sender_privkey", s(v, "key")), ("recipient", p["recipient"]!), ("amount", p["amount"]!), ("fee", i64(v["fee"])), ("timestamp", i64(v["timestamp"])), ("offline", true)])
        let (code, out, err) = cli(["send-zbc", "--json-input", "--genesis", s(v, "genesis")], stdin: stdin)
        XCTAssertEqual(code, 0, out + err); XCTAssertEqual(json(out)["transaction_hash"] as? String, s(e, "transaction_hash"))
        for args in [[p["recipient"]!, p["amount"]!], ["-", p["recipient"]!, p["amount"]!]] {
            let (c2, o2, e2) = cli(["send-zbc"] + args + ["--timestamp", String(i64(v["timestamp"])), "--genesis", s(v, "genesis"), "--offline"], env: ["ZBC_KEY": s(v, "key")])
            XCTAssertEqual(c2, 0, o2 + e2); XCTAssertEqual(json(o2)["transaction_hash"] as? String, s(e, "transaction_hash"))
        }
    }

    func testCliUnreachableNode() throws {
        let v = (try load("transactions.json")["vectors"] as! [[String: Any]])[0]; let p = params(v)
        let (code, out, _) = cli(["send-zbc", s(v, "key"), p["recipient"]!, "1", "--api", "http://127.0.0.1:9", "--genesis", "v1", "--timeout", "2"])
        XCTAssertEqual(code, 3, out); XCTAssertEqual(json(out)["error_class"] as? String, "node_unreachable")
    }

    func testEncryption() throws {
        let d = try load("encryption.json")
        for k in d["keys"] as! [[String: Any]] {
            XCTAssertEqual(Enc.hex(Encryption.ed25519PublicKeyToX25519(Enc.unhex(s(k, "public_key"))!)!), s(k, "x25519_public_key"))
            XCTAssertEqual(Enc.hex(Encryption.ed25519SeedToX25519(Enc.unhex(s(k, "seed"))!)), s(k, "x25519_secret_key"))
            XCTAssertEqual(Enc.hex(Encryption.x25519Base(Enc.unhex(s(k, "x25519_secret_key"))!)!), s(k, "x25519_public_key"))
        }
        for v in d["sealed"] as! [[String: Any]] {
            let f = Encryption.seal(Enc.unhex(s(v, "plaintext_hex"))!, recipientPublicKey: Enc.unhex(s(v, "recipient_public_key"))!, ephemeralSecretKey: Enc.unhex(s(v, "ephemeral_secret_key"))!)!
            XCTAssertEqual(Enc.hex(f), s(v, "message_field"), s(v, "name"))
            XCTAssertEqual(Enc.hex(Encryption.openSealed(f, recipientSeed: Enc.unhex(s(v, "recipient_seed"))!)!), s(v, "plaintext_hex"), s(v, "name"))
        }
        for v in d["samples"] as! [[String: Any]] {
            XCTAssertEqual(Enc.hex(Encryption.openSealed(Enc.unhex(s(v, "message_field"))!, recipientSeed: Enc.unhex(s(v, "recipient_seed"))!)!), s(v, "plaintext_hex"), s(v, "name"))
        }
        for v in d["invalid"] as! [[String: Any]] {
            if let f = Enc.unhex(s(v, "message_field")) { XCTAssertNil(Encryption.openSealed(f, recipientSeed: Enc.unhex(s(v, "recipient_seed"))!), s(v, "case")) }
        }
        let kp = try KeyPair(hex: s((d["keys"] as! [[String: Any]])[0], "seed"))
        let f = Encryption.seal(Array("round trip".utf8), recipientPublicKey: kp.publicKey)!
        XCTAssertEqual(f.count, 10 + Encryption.sealedOverhead)
        XCTAssertEqual(Encryption.openSealed(f, recipientSeed: kp.seed), Array("round trip".utf8))
    }

    func testCliEncryptAndDecrypt() throws {
        let d = try load("encryption.json")
        let seed = s((d["keys"] as! [[String: Any]])[0], "seed")
        let smp = (d["samples"] as! [[String: Any]])[0]
        let (rc, out, err) = cli(["send-zbc", seed, s(smp, "recipient_address"), "1", "--message", s(smp, "plaintext"), "--encrypt", "--genesis", "v1", "--offline"])
        XCTAssertEqual(rc, 0, out + err)
        let j = json(out)
        XCTAssertEqual(s(j, "message"), s(smp, "plaintext"))
        let field = s(j["payload"] as! [String: Any], "message_hex")
        XCTAssertTrue(field.hasPrefix("5a424531") && field.utf8.count == 2 * (s(smp, "plaintext").utf8.count + 52))
        let (rc2, out2, err2) = cli(["decrypt-message", s(smp, "recipient_seed"), field])
        XCTAssertEqual(rc2, 0, out2 + err2)
        XCTAssertEqual(s(json(out2), "message"), s(smp, "plaintext"))
        for v in d["samples"] as! [[String: Any]] {
            let (c, o, _) = cli(["decrypt-message", s(v, "recipient_seed"), s(v, "message_field")])
            XCTAssertEqual(c, 0, s(v, "name")); XCTAssertEqual(s(json(o), "message_hex"), s(v, "plaintext_hex"), s(v, "name"))
        }
        for v in d["invalid"] as! [[String: Any]] {
            let (c, o, _) = cli(["decrypt-message", s(v, "recipient_seed"), s(v, "message_field")])
            XCTAssertEqual(Int64(c), i64(v["exit_code"]), s(v, "case") + ": " + o)
            XCTAssertEqual(s(json(o), "error_class"), s(v, "error_class"), s(v, "case"))
        }
        let (c3, _, _) = cli(["send-zbc", seed, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "1", "--message", "x", "--encrypt", "--genesis", "v1", "--offline"])
        XCTAssertEqual(c3, 2)
    }
}
