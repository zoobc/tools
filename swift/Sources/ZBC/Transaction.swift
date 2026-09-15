// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Foundation

/// Escrow terms of a transfer (the --escrow-* options); `timeout` is an absolute Unix time in seconds.
public struct Escrow: Equatable {
    public var approver: String
    public var commission: Int64
    public var timeout: Int64
    public var instruction: String
    public init(approver: String, commission: Int64 = 0, timeout: Int64 = 0, instruction: String = "") {
        self.approver = approver; self.commission = commission; self.timeout = timeout; self.instruction = instruction
    }
    /// The escrow block of the envelope (spec/signing.md section 3).
    public func bytes() throws -> [UInt8] {
        let ins = Array(instruction.utf8)
        return try Address.parse(approver).bytes + LE.i64(commission) + LE.i64(timeout) + LE.u32(UInt32(ins.count)) + ins + [0]
    }
    /// The escrow object of the submit payload.
    public func payload() throws -> [String: Any] {
        var m: [String: Any] = ["approver_address": Enc.hex(try Address.parse(approver).bytes), "commission": commission, "timeout": timeout]
        if !instruction.isEmpty { m["instruction"] = instruction }
        return m
    }
}

/// Which chain a signature is for: version 2 with its genesis hash, or 1 (legacy).
public struct SigningContext: Equatable {
    public let version: Int
    public let genesisHash: [UInt8]
    public init(version: Int, genesisHash: [UInt8] = []) { self.version = version; self.genesisHash = genesisHash }
    /// Reads --genesis: 64 hex, or "v1"/"legacy".
    public static func of(_ genesis: String) throws -> SigningContext {
        if genesis == "v1" || genesis == "legacy" { return SigningContext(version: 1) }
        guard Enc.isHex(genesis, 64), let g = Enc.unhex(genesis) else { throw Address.Invalid(message: "--genesis must be the 64-hex genesis block hash (or 'v1' for the legacy digest)") }
        return SigningContext(version: 2, genesisHash: g)
    }
}

/// A built, signed and hashed transaction.
public struct SignedTransaction {
    public let unsigned: [UInt8], digest: [UInt8], signature: [UInt8], bytes: [UInt8], hash: [UInt8]
    /// The JSON object POST /api/v1/transactions takes (spec/api.md section 2), key order as the reference prints it.
    public let payload: [(String, Any)]
    public let signingVersion: Int, genesisHash: [UInt8]
    public var payloadDictionary: [String: Any] { Dictionary(uniqueKeysWithValues: payload) }
}

/// The envelope, chain-bound digest, signature, hash and submit payload (spec/signing.md).
public enum Transaction {
    public static let sendZBC: UInt32 = 1, approvalEscrow: UInt32 = 4
    public static let approve: UInt32 = 0, reject: UInt32 = 1, expire: UInt32 = 2
    public static var emptyAccount: [UInt8] { LE.i32(AccountType.empty) }

    /// Fields 1–11 of the envelope: what the digest covers. `recipient` is typed bytes or empty.
    public static func unsignedBytes(type: UInt32, timestamp: Int64, sender: [UInt8], recipient: [UInt8], fee: Int64, body: [UInt8],
                                     escrow: Escrow? = nil, message: [UInt8] = [], version: UInt8 = 1) throws -> [UInt8] {
        let rec = (recipient.isEmpty || recipient.allSatisfy { $0 == 0 }) ? emptyAccount : recipient
        return LE.u32(type) + [version] + LE.i64(timestamp) + sender + rec + LE.i64(fee) + LE.u32(UInt32(body.count)) + body
            + (try escrow?.bytes() ?? emptyAccount) + LE.u32(UInt32(message.count)) + message
    }

    /// SHA3-256("ZBC-TX" || genesis || unsigned) for version 2; SHA3-256(unsigned) for version 1.
    public static func signingDigest(_ unsigned: [UInt8], _ ctx: SigningContext) -> [UInt8] {
        ctx.version == 2 ? SHA3.hash256(Array("ZBC-TX".utf8), ctx.genesisHash, unsigned) : SHA3.hash256(unsigned)
    }

    public static func hash(_ unsigned: [UInt8], _ signature: [UInt8]) -> [UInt8] { SHA3.hash256(unsigned, signature) }

    /// The int64 id: the first 8 bytes of the hash, little-endian, signed.
    public static func id(_ hash: [UInt8]) -> Int64 { LE.readI64(hash, 0) }

    /// Build, sign and hash a transaction for the chain of `ctx`.
    public static func sign(type: UInt32, timestamp: Int64, sender: KeyPair, recipient: [UInt8], fee: Int64, body: [UInt8], ctx: SigningContext,
                            escrow: Escrow? = nil, message: [UInt8] = [], version: UInt8 = 1) throws -> SignedTransaction {
        let unsigned = try unsignedBytes(type: type, timestamp: timestamp, sender: sender.accountBytes, recipient: recipient, fee: fee, body: body, escrow: escrow, message: message, version: version)
        let digest = signingDigest(unsigned, ctx)
        let signature = sender.sign(digest)
        let full = unsigned + signature
        let recipientJson: String
        if recipient.isEmpty { recipientJson = "" }
        else if recipient.count == 36 && recipient[0..<4].allSatisfy({ $0 == 0 }) { recipientJson = Enc.hex(Array(recipient[4...])) }
        else { recipientJson = Enc.hex(recipient) }
        var payload: [(String, Any)] = [("version", Int(version)), ("timestamp", timestamp), ("sender_account_address", Enc.hex(sender.publicKey)),
            ("recipient_account_address", recipientJson), ("transaction_type", Int(type)), ("fee", fee), ("transaction_body_bytes", Enc.hex(body)), ("signature", Enc.hex(signature))]
        if !message.isEmpty { payload.append(("message_hex", Enc.hex(message))) }
        if let e = escrow { payload.append(("escrow", try e.payload())) }
        return SignedTransaction(unsigned: unsigned, digest: digest, signature: signature, bytes: full, hash: SHA3.hash256(full), payload: payload, signingVersion: ctx.version, genesisHash: ctx.genesisHash)
    }

    /// The 8-byte amount.
    public static func sendZBCBody(_ amount: Int64) -> [UInt8] { LE.i64(amount) }

    /// approval u32le then the 32-byte escrowed transaction hash.
    public static func approvalEscrowBody(_ approval: UInt32, _ escrowedHash: [UInt8]) throws -> [UInt8] {
        guard escrowedHash.count == 32 else { throw Address.Invalid(message: "Transaction hash must be 64 hex characters (the escrowed transaction's SHA3-256 hash)") }
        return LE.u32(approval) + escrowedHash
    }
}
