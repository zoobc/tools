// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

/// Account types (spec/addresses.md section 1).
public enum AccountType {
    public static let zoobc: Int32 = 0, bitcoin: Int32 = 1, empty: Int32 = 2, estoniaEID: Int32 = 3, ethereum: Int32 = 4
    public static let bitcoinP2PKH: Int32 = 5, bitcoinP2SH: Int32 = 6, bitcoinP2WPKH: Int32 = 7, bitcoinP2WSH: Int32 = 8, bitcoinTaproot: Int32 = 9
    public static let dataset: Int32 = 10, solana: Int32 = 11, polkadot: Int32 = 12, cardano: Int32 = 13, ripple: Int32 = 14, tron: Int32 = 15, tezos: Int32 = 16

    public static func name(_ t: Int32) -> String {
        switch t {
        case 0: return "ZooBC"; case 1: return "Bitcoin"; case 3: return "Estonia eID"; case 4: return "Ethereum"; case 5: return "Bitcoin P2PKH"
        case 6: return "Bitcoin P2SH"; case 7: return "Bitcoin P2WPKH"; case 8: return "Bitcoin P2WSH"; case 9: return "Bitcoin Taproot"; case 10: return "DataSet"
        case 11: return "Solana"; case 12: return "Polkadot"; case 13: return "Cardano"; case 14: return "Ripple"; case 15: return "Tron"; case 16: return "Tezos"
        default: return "type \(t)"
        }
    }
}

/// A recipient as the envelope carries it.
public struct ParsedAddress: Equatable {
    public let type: Int32
    public let payload: [UInt8]
    public let display: String
    /// 4-byte type LE then the payload (36 bytes for a ZooBC account).
    public var bytes: [UInt8] { Address.typed(type, payload) }
    public var typeName: String { AccountType.name(type) }
}

/// The ZBC_/ZNK_/ZBS_ text form and every recipient form of spec/addresses.md.
public enum Address {
    public static func typed(_ t: Int32, _ payload: [UInt8]) -> [UInt8] { LE.i32(t) + payload }

    /// PREFIX_ + base32(payload || SHA3-256(payload || prefix)[0..2]) in seven groups of eight.
    public static func encode(_ payload: [UInt8], prefix: String = "ZBC") -> String? {
        guard payload.count == 32, prefix.utf8.count == 3 else { return nil }
        let check = Array(SHA3.hash256(payload, Array(prefix.utf8))[0..<3])
        let s = Array(Enc.base32Encode(payload + check).utf8)
        var out = prefix
        for i in 0..<7 { out += "_" + String(decoding: s[(8 * i)..<(8 * i + 8)], as: UTF8.self) }
        return out
    }

    /// The 59 significant characters of a ZooBC address: separators (_ -) and whitespace dropped, upper case (addresses.md 2).
    public static func significant(_ text: String) -> [UInt8] {
        return Array(text.uppercased().utf8).filter { c in
            !(c == UInt8(ascii: "_") || c == UInt8(ascii: "-") || c == 0x20 || (c >= 0x09 && c <= 0x0d))
        }
    }

    /// (upper-case prefix, 32-byte payload) of a ZooBC address in any spelling, or nil.
    public static func decode(_ text: String) -> (String, [UInt8])? {
        let norm = significant(text)
        guard norm.count >= 3 else { return nil }
        let prefix = String(decoding: norm[0..<3], as: UTF8.self)
        let body = Array(norm[3...])
        guard body.count == 56, let raw = Enc.base32Decode(String(decoding: body, as: UTF8.self)), raw.count == 35 else { return nil }
        let payload = Array(raw[0..<32])
        let check = Array(SHA3.hash256(payload, Array(prefix.utf8))[0..<3])
        return check == Array(raw[32..<35]) ? (prefix, payload) : nil
    }

    private static let chains: [String: String] = ["zbc": "zbc", "zoobc": "zbc", "btc": "btc", "bitcoin": "btc", "eth": "eth", "ethereum": "eth", "evm": "eth",
        "sol": "sol", "solana": "sol", "dot": "dot", "polkadot": "dot", "substrate": "dot", "ada": "ada", "cardano": "ada", "xrp": "xrp", "ripple": "xrp",
        "trx": "trx", "tron": "trx", "xtz": "xtz", "tezos": "xtz", "zbs": "zbs", "dataset": "zbs"]

    public struct Invalid: Error { public let message: String }

    private static let b32Alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    /// Shape only: PREFIX then a separator, or the bare form: 59 significant characters, ZBC/ZBS prefix, base32 body.
    private static func looksZbc(_ a: String) -> Bool {
        let u = Array(a.utf8)
        if u.count > 4 && (u[3] == UInt8(ascii: "_") || u[3] == UInt8(ascii: "-")) { return true }
        let n = significant(a)
        guard n.count == 59 else { return false }
        let p = String(decoding: n[0..<3], as: UTF8.self)
        return (p == "ZBC" || p == "ZBS") && n[3...].allSatisfy { b32Alphabet.contains($0) }
    }

    private static func zbcForm(_ a: String) throws -> ParsedAddress {
        guard let d = decode(a) else { throw Invalid(message: "invalid ZooBC address checksum") }
        let (prefix, payload) = d
        return ParsedAddress(type: prefix == "ZBS" ? AccountType.dataset : AccountType.zoobc, payload: payload, display: a)
    }

    private static func hinted(_ a: String, _ hint: String) throws -> ParsedAddress {
        switch hint {
        case "eth":
            var h = a; if h.hasPrefix("0x") || h.hasPrefix("0X") { h = String(h.dropFirst(2)) }
            guard Enc.isHex(h, 40), let b = Enc.unhex(h) else { throw Invalid(message: "not a 20-byte Ethereum address") }
            return ParsedAddress(type: AccountType.ethereum, payload: b, display: a)
        case "sol":
            guard let d = Enc.base58Decode(a), d.count == 32 else { throw Invalid(message: "not a 32-byte Solana address") }
            return ParsedAddress(type: AccountType.solana, payload: d, display: a)
        case "dot":
            guard let ss = Enc.ss58Decode(a) else { throw Invalid(message: "not a valid SS58 address") }
            return ParsedAddress(type: AccountType.polkadot, payload: ss.1, display: a)
        case "zbc", "zbs": return try zbcForm(a)
        default: return try auto(a)
        }
    }

    private static func auto(_ a: String) throws -> ParsedAddress {
        let u = Array(a.utf8)
        if u.count == 42 && (a.hasPrefix("0x") || a.hasPrefix("0X")) && Enc.isHex(String(a.dropFirst(2)), 40) {
            return ParsedAddress(type: AccountType.ethereum, payload: Enc.unhex(String(a.dropFirst(2)))!, display: a)
        }
        if looksZbc(a) { return try zbcForm(a) }
        let low5 = String(a.prefix(5)).lowercased()
        if low5.hasPrefix("bc1") || low5.hasPrefix("tb1") || low5.hasPrefix("bcrt1") {
            guard let sw = Enc.segwitDecode(a) else { throw Invalid(message: "invalid Bitcoin bech32 address") }
            let (version, prog) = (sw.1, sw.2)
            switch (version, prog.count) {
            case (0, 20): return ParsedAddress(type: AccountType.bitcoinP2WPKH, payload: prog, display: a)
            case (0, 32): return ParsedAddress(type: AccountType.bitcoinP2WSH, payload: prog, display: a)
            case (1, 32): return ParsedAddress(type: AccountType.bitcoinTaproot, payload: prog, display: a)
            default: throw Invalid(message: "unsupported Bitcoin witness program")
            }
        }
        if (u[0] == UInt8(ascii: "1") || u[0] == UInt8(ascii: "3")) && u.count >= 26 && u.count <= 35 {
            if let raw = Enc.base58Decode(a), raw.count == 25, let body = Enc.base58CheckDecode(a), body.count == 21 {
                if body[0] == 0x00 { return ParsedAddress(type: AccountType.bitcoinP2PKH, payload: Array(body[1...]), display: a) }
                if body[0] == 0x05 { return ParsedAddress(type: AccountType.bitcoinP2SH, payload: Array(body[1...]), display: a) }
            }
        }
        if u.count > 5 && String(a.prefix(5)).lowercased() == "addr1" {
            if let d = Enc.bech32DecodePlain(a), d.0 == "addr", d.1.count == 29, d.1[0] == 0x61 { return ParsedAddress(type: AccountType.cardano, payload: Array(d.1[1...]), display: a) }
            throw Invalid(message: "invalid Cardano address (expected a mainnet enterprise addr1… address)")
        }
        if u[0] == UInt8(ascii: "T") && u.count == 34 {
            if let body = Enc.base58CheckDecode(a), body.count == 21, body[0] == 0x41 { return ParsedAddress(type: AccountType.tron, payload: Array(body[1...]), display: a) }
            throw Invalid(message: "invalid Tron address")
        }
        if u[0] == UInt8(ascii: "r") && u.count >= 25 && u.count <= 35 {
            if let body = Enc.base58CheckDecode(a, Enc.rippleAlphabet), body.count == 21, body[0] == 0x00 { return ParsedAddress(type: AccountType.ripple, payload: Array(body[1...]), display: a) }
            throw Invalid(message: "invalid Ripple address")
        }
        if a.hasPrefix("tz1") {
            if let body = Enc.base58CheckDecode(a), body.count == 23, body[0] == 0x06, body[1] == 0xa1, body[2] == 0x9f { return ParsedAddress(type: AccountType.tezos, payload: Array(body[3...]), display: a) }
            throw Invalid(message: "invalid Tezos address")
        }
        if let ss = Enc.ss58Decode(a), ss.1.count == 32 { return ParsedAddress(type: AccountType.polkadot, payload: ss.1, display: a) }
        if u.count >= 32 && u.count <= 44, let d = Enc.base58Decode(a), d.count == 32 { return ParsedAddress(type: AccountType.solana, payload: d, display: a) }
        if Enc.isHex(a, 64), let key = Enc.unhex(a) { return ParsedAddress(type: AccountType.zoobc, payload: key, display: encode(key, prefix: "ZBC")!) }
        throw Invalid(message: "unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos")
    }

    /// Read a recipient in the order of spec/addresses.md section 3; `chain` forces one reading (--chain).
    public static func parse(_ text: String, chain: String = "") throws -> ParsedAddress {
        let a = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if a.isEmpty { throw Invalid(message: "empty address") }
        if chain.isEmpty { return try auto(a) }
        guard let hint = chains[chain.lowercased()] else { throw Invalid(message: "unknown chain \(chain)") }
        do { return try hinted(a, hint) } catch let e as Invalid {
            let up = a.uppercased(), low = a.lowercased()
            let plain = (a.utf8.count == 42 && (a.hasPrefix("0x") || a.hasPrefix("0X"))) || up.hasPrefix("ZBC") || up.hasPrefix("ZNK") || up.hasPrefix("ZBS")
                || a.hasPrefix("1") || a.hasPrefix("3") || low.hasPrefix("bc1") || low.hasPrefix("tb1") || low.hasPrefix("bcrt1") || a.utf8.count == 64
            if !plain { throw e }
            return try auto(a)
        }
    }

    /// A registry key parameter: 64 hex (optionally 0x) or a ZNK_/ZBG_/ZBR_/ZBC_ text address; 32 bytes.
    public static func parseKey32(_ text: String) throws -> [UInt8] {
        let u = Array(text.utf8)
        if u.count == 66 && u[3] == UInt8(ascii: "_") {
            guard let d = decode(text) else { throw Invalid(message: "invalid address checksum") }
            return d.1
        }
        var h = text; if h.hasPrefix("0x") || h.hasPrefix("0X") { h = String(h.dropFirst(2)) }
        guard Enc.isHex(h, 64), let b = Enc.unhex(h) else { throw Invalid(message: "key must be a 64-hex string or a ZNK_/ZBG_/ZBR_ address") }
        return b
    }
}
