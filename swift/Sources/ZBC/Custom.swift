// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

/// The hand-written parts the descriptions mark computed or custom (spec/transactions/README.md).
public enum Custom {
    /// The block a proof of ownership refers to.
    public struct ReferenceBlock { public let hash: [UInt8]; public let height: UInt32; public init(hash: [UInt8], height: UInt32) { self.hash = hash; self.height = height } }

    public struct Input {
        public let def: TxDef, params: [String: String], sender: KeyPair, ctx: SigningContext, timestamp: Int64, block: ReferenceBlock?
        public init(def: TxDef, params: [String: String], sender: KeyPair, ctx: SigningContext, timestamp: Int64, block: ReferenceBlock? = nil) {
            self.def = def; self.params = params; self.sender = sender; self.ctx = ctx; self.timestamp = timestamp; self.block = block
        }
    }

    /// owner (36) || block hash (32) || height u32le, then the owner's signature over those bytes.
    public static func proofOfOwnership(_ owner: KeyPair, _ block: ReferenceBlock) -> [UInt8] {
        var msg = owner.accountBytes
        msg += block.hash; msg += LE.u32(block.height)
        return msg + owner.sign(msg)
    }

    /// Fill `ctx.computed` for the fields the generic serialiser cannot produce; returns extra output fields.
    public static func computeFields(_ input: Input, _ ctx: Body.Context) throws -> [(String, Any)] {
        let p = input.params
        var extra: [(String, Any)] = []
        switch input.def.command {
        case "store-file":
            let pieces = Enc.unhex(p["piece_ids"] ?? "") ?? []
            guard !pieces.isEmpty, pieces.count % 32 == 0 else { throw ToolError.usage("piece_ids must be a nonzero multiple of 32 bytes") }
            ctx.computed["piece_count"] = LE.u32(UInt32(pieces.count / 32))
            extra.append(("piece_count", pieces.count / 32))
        case "register-node", "update-node", "claim-node":
            guard let block = input.block else { throw ToolError.internalError("proof of ownership needs the latest block") }
            ctx.computed["proof_of_ownership"] = proofOfOwnership(input.sender, block)
            extra.append(("node_znk", try KeyPair(hex: p["node_privkey"] ?? "").nodeAddress))
            extra.append(("owner_zbc", input.sender.address))
        case "fee-vote-reveal":
            var info = Enc.unhex(p["recent_block_hash"] ?? "") ?? []
            info += LE.u32(UInt32(try Body.parseInteger(p["recent_block_height"] ?? "", kind: "uint32", name: "recent_block_height")))
            info += LE.i64(try Body.parseInteger(p["fee_vote"] ?? "", kind: "int64", name: "fee_vote"))
            let sig = input.sender.sign(info)
            ctx.computed["voter_signature"] = LE.u32(UInt32(sig.count)) + sig
        case "gateway-heartbeat":
            guard let gw = try? KeyPair(hex: p["gateway_privkey"] ?? "") else { throw ToolError.usage("gateway_privkey is not a valid key") }
            let h = try Body.parseInteger(p["reference_height"] ?? "", kind: "uint32", name: "reference_height")
            guard let hash = Enc.unhex(p["reference_block_hash"] ?? ""), hash.count == 32 else { throw ToolError.usage("reference_block_hash must be 32 bytes (64 hex)") }
            var hb = gw.publicKey
            hb += LE.u32(UInt32(h)); hb += hash
            ctx.computed["signature"] = gw.sign(hb)
            extra.append(("gateway_key", Enc.hex(gw.publicKey))); extra.append(("reference_height", h)); extra.append(("reference_block_hash", p["reference_block_hash"] ?? ""))
        default: break
        }
        return extra
    }

    /// SHA3-256(min u32le || nonce u64le || count u32le || sorted participant addresses).
    public static func multisigAddress(_ participants: [[UInt8]], nonce: Int64, minSignatures: UInt32) -> [UInt8] {
        let sorted = participants.sorted { $0.lexicographicallyPrecedes($1) }
        return SHA3.hash256(LE.u32(minSignatures) + LE.i64(nonce) + LE.u32(UInt32(sorted.count)) + sorted.flatMap { $0 })
    }

    /// The two fully custom bodies: multisig and app-settle.
    public static func body(_ input: Input) throws -> ([UInt8], [(String, Any)]) {
        switch input.def.command {
        case "multisig": return try multisig(input)
        case "app-settle": return try settle(input)
        default: throw ToolError.internalError("no custom body for \(input.def.command)")
        }
    }

    private static func multisig(_ input: Input) throws -> ([UInt8], [(String, Any)]) {
        let p = input.params
        var participants: [[UInt8]] = []
        for a in Body.splitList(p["participants"] ?? "") { guard let pa = try? Address.parse(a) else { throw ToolError.usage("Invalid participant address: \(a)") }; participants.append(pa.bytes) }
        guard !participants.isEmpty else { throw ToolError.usage("Need at least one participant") }
        let minSigs = UInt32(try Body.parseInteger(p["min_signatures"] ?? "", kind: "uint32", name: "min_signatures"))
        let nonce = try Body.parseInteger((p["nonce"] ?? "").isEmpty ? "0" : p["nonce"]!, kind: "int64", name: "nonce")
        let signers = Body.splitList(p["signer_privkeys"] ?? "")
        guard !signers.isEmpty else { throw ToolError.usage("Need at least one signer key") }
        let recipient: ParsedAddress
        do { recipient = try Address.parse(p["recipient"] ?? "") } catch let e as Address.Invalid { throw ToolError.usage("Invalid recipient: \(e.message)") }
        let amount = try Body.parseInteger(p["amount"] ?? "", kind: "int64", name: "amount")
        let innerFee = try Body.parseInteger((p["inner_fee"] ?? "").isEmpty ? "10000000" : p["inner_fee"]!, kind: "int64", name: "inner_fee")
        let ms = multisigAddress(participants, nonce: nonce, minSignatures: minSigs)
        let inner = try Transaction.unsignedBytes(type: Transaction.sendZBC, timestamp: input.timestamp, sender: Address.typed(AccountType.zoobc, ms), recipient: recipient.bytes, fee: innerFee, body: Transaction.sendZBCBody(amount))
        let innerHash = SHA3.hash256(inner)
        let innerDigest = Transaction.signingDigest(inner, input.ctx)
        var sigs: [(String, [UInt8])] = []
        for sk in signers { guard let kp = try? KeyPair(hex: sk) else { throw ToolError.usage("Invalid signer key") }; sigs.append((Enc.hex(kp.accountBytes), kp.sign(innerDigest))) }
        sigs.sort { $0.0 < $1.0 }   // the node keeps them in a map ordered by address hex
        var body: [UInt8] = LE.u32(1)
        body += LE.u32(minSigs); body += LE.i64(nonce); body += LE.u32(UInt32(participants.count))
        for a in participants { body += a }
        body += LE.u32(UInt32(inner.count)); body += inner; body += LE.u32(1); body += innerHash; body += LE.u32(UInt32(sigs.count))
        for (addr, sig) in sigs { body += Enc.unhex(addr)!; body += LE.u32(UInt32(sig.count)); body += sig }
        let extra: [(String, Any)] = [("multisig_address", Enc.hex(ms)), ("multisig_zbc_address", Address.encode(ms, prefix: "ZBC")!), ("min_signatures", Int(minSigs)),
                                      ("inner_tx_hash", Enc.hex(innerHash)), ("fund_hint", "send ZBC to multisig_zbc_address before the signatures complete, else the inner tx stays in mempool")]
        return (body, extra)
    }

    private static func settle(_ input: Input) throws -> ([UInt8], [(String, Any)]) {
        let p = input.params
        let appId = try Body.parseInteger(p["app_id"] ?? "", kind: "int64", name: "app_id")
        guard let p0 = try? KeyPair(hex: p["p0_privkey"] ?? ""), let p1 = try? KeyPair(hex: p["p1_privkey"] ?? "") else { throw ToolError.usage("seat keys must be 64 hex") }
        let seats = [p0, p1]
        let turn = Int(try Body.parseInteger((p["opening_turn"] ?? "").isEmpty ? "0" : p["opening_turn"]!, kind: "uint8", name: "opening_turn"))
        guard turn == 0 || turn == 1 else { throw ToolError.usage("opening_turn must be 0 or 1") }
        let cells = try Body.splitList(p["moves"] ?? "").map { Int(try Body.parseInteger($0, kind: "uint8", name: "move")) }
        guard !cells.isEmpty else { throw ToolError.usage("no moves given") }
        var state = [UInt8](repeating: 0, count: 9)
        var entries: [UInt8] = []
        for (k, cell) in cells.enumerated() {
            let seat = (turn + k) % 2
            guard cell <= 8, state[cell] == 0 else { throw ToolError.usage("illegal move at seq \(k + 1)") }
            let move: [UInt8] = [UInt8(cell)]
            var pre: [UInt8] = LE.i64(appId)
            pre += LE.u32(UInt32(k + 1)); pre += SHA3.hash256(state); pre += move
            let digest = SHA3.hash256(pre)
            entries.append(UInt8(seat)); entries += LE.u16(move.count); entries += move; entries += seats[seat].sign(digest)
            state[cell] = UInt8(seat + 1)
        }
        var body: [UInt8] = LE.i64(appId)
        body += LE.u32(UInt32(cells.count)); body += LE.u32(UInt32(cells.count)); body += entries
        return (body, [("app_id", appId), ("opening_turn", turn), ("final_seq", cells.count)])
    }
}
