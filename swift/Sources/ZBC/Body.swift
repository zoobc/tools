// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Foundation

/// Parameter validation and the generic body serialiser driven by spec/transactions (encodings of index.json).
public enum Body {
    public static func parseInteger(_ value: String, kind: String, name: String) throws -> Int64 {
        let v = value.trimmingCharacters(in: .whitespaces)
        let digits = v.hasPrefix("-") ? String(v.dropFirst()) : v
        guard !digits.isEmpty, digits.allSatisfy({ $0.isASCII && $0.isNumber }) else { throw ToolError.usage("\(name) must be a whole number, got \"\(value)\"") }
        switch kind {
        case "uint64": guard let u = UInt64(v) else { throw ToolError.usage("\(name) is out of range for \(kind)") }; return Int64(bitPattern: u)
        case "uint32": guard let u = UInt32(v) else { throw ToolError.usage("\(name) is out of range for \(kind)") }; return Int64(u)
        case "uint8": guard let u = UInt8(v) else { throw ToolError.usage("\(name) is out of range for \(kind)") }; return Int64(u)
        default: guard let n = Int64(v) else { throw ToolError.usage("\(name) is out of range for \(kind)") }; return n
        }
    }

    public static func splitList(_ s: String) -> [String] { s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }

    /// Check one value against its parameter kind; returns the value to keep.
    public static func validateParam(_ p: ParamDef, _ value: String) throws -> String {
        switch p.kind {
        case "privkey": guard Enc.isHex(value, 64) else { throw ToolError.usage("\(p.name) must be 64 hex characters (a 32-byte private key)") }
        case "address": do { _ = try Address.parse(value) } catch let e as Address.Invalid { throw ToolError.usage("invalid \(p.name): \(e.message)") }
        case "address_list": for a in splitList(value) { do { _ = try Address.parse(a) } catch let e as Address.Invalid { throw ToolError.usage("invalid \(p.name) entry \(a): \(e.message)") } }
        case "key": do { _ = try Address.parseKey32(value) } catch let e as Address.Invalid { throw ToolError.usage("invalid \(p.name): \(e.message)") }
        case "int64", "uint64", "uint32", "uint8":
            let n = try parseInteger(value, kind: p.kind, name: p.name)
            if let lo = p.min, n < lo { throw ToolError.usage("\(p.name) must be between \(lo) and \(p.max.map(String.init) ?? "inf")") }
            if let hi = p.max, n > hi { throw ToolError.usage("\(p.name) must be between \(p.min.map(String.init) ?? "-inf") and \(hi)") }
            return value.trimmingCharacters(in: .whitespaces)
        case "hex32": guard Enc.isHex(value, 64) else { throw ToolError.usage("\(p.name) must be 64 hex characters (32 bytes)") }
        case "hexbytes": guard Enc.isHex(value) else { throw ToolError.usage("\(p.name) must be hex") }
        default: break
        }
        return value
    }

    /// What the generic serialiser cannot read from the parameters.
    public final class Context {
        public var sender: KeyPair?
        public var files: [String: [UInt8]]
        public var computed: [String: [UInt8]]
        public init(sender: KeyPair? = nil, files: [String: [UInt8]] = [:], computed: [String: [UInt8]] = [:]) { self.sender = sender; self.files = files; self.computed = computed }
    }

    private static func holds(_ when: String, _ params: [String: String]) throws -> Bool {
        let parts = when.components(separatedBy: " != ")
        guard parts.count == 2 else { throw ToolError.internalError("unsupported condition \(when)") }
        let v = params[parts[0]] ?? ""
        if parts[1] == "0" { return !v.isEmpty && (Int64(v) ?? 0) != 0 }
        if parts[1] == "''" { return !v.isEmpty }
        throw ToolError.internalError("unsupported condition \(when)")
    }

    private static func hexOrUsage(_ v: String, _ name: String) throws -> [UInt8] { guard let b = Enc.unhex(v) else { throw ToolError.usage("\(name) must be hex") }; return b }
    private static func addr(_ v: String, _ name: String) throws -> ParsedAddress { do { return try Address.parse(v) } catch let e as Address.Invalid { throw ToolError.usage("invalid \(name): \(e.message)") } }

    /// Serialise one body field.
    public static func encodeField(_ f: FieldDef, _ params: [String: String], _ ctx: Context) throws -> [UInt8] {
        if let v = ctx.computed[f.name] { return v }
        var value = params[f.from] ?? ""
        if let wz = f.when_zero, value.isEmpty || (Int64(value) ?? 0) <= 0 { value = params[wz] ?? "0" }
        switch f.encoding {
        case "u8": return [UInt8(try parseInteger(value, kind: "uint8", name: f.name))]
        case "u16le": return LE.u16(Int(try parseInteger(value, kind: "uint32", name: f.name)))
        case "u32le": return LE.u32(UInt32(try parseInteger(value, kind: "uint32", name: f.name)))
        case "u64le": return LE.i64(try parseInteger(value, kind: "int64", name: f.name))
        case "hex":
            let b = try hexOrUsage(value, f.from)
            if let size = f.size, b.count != size { throw ToolError.usage("\(f.from) must be \(size) bytes (\(2 * size) hex)") }
            return b
        case "hex16": let b = try hexOrUsage(value, f.from); return LE.u16(b.count) + b
        case "bytes32": let b = try ctx.files[f.from] ?? hexOrUsage(value, f.from); return LE.u32(UInt32(b.count)) + b
        case "str16": let b = Array(value.utf8); return LE.u16(b.count) + b
        case "str32": let b = Array(value.utf8); return LE.u32(UInt32(b.count)) + b
        case "address": return try addr(value, f.from).bytes
        case "address_list": return try splitList(value).flatMap { try addr($0, f.from).bytes }
        case "address_list8":
            let items = splitList(value)
            if items.count > 255 { throw ToolError.usage("\(f.from): at most 255 entries") }
            return [UInt8(items.count)] + (try items.flatMap { try addr($0, f.from).bytes })
        case "sender_address": guard let s = ctx.sender else { throw ToolError.internalError("no sender") }; return s.accountBytes
        case "pubkey_of_key": guard let kp = try? KeyPair(hex: value) else { throw ToolError.usage("\(f.from) must be 64 hex characters (a 32-byte private key)") }; return kp.publicKey
        case "key32": do { return try Address.parseKey32(value) } catch let e as Address.Invalid { throw ToolError.usage("invalid \(f.from): \(e.message)") }
        case "literal": return Enc.unhex(f.value ?? "") ?? []
        case "custom": throw ToolError.internalError("field \(f.name) needs a custom hook")
        default: throw ToolError.internalError("unknown encoding \(f.encoding)")
        }
    }

    /// The whole body of a non-custom transaction.
    public static func build(_ def: TxDef, _ params: [String: String], _ ctx: Context) throws -> [UInt8] {
        var out: [UInt8] = []
        for f in def.body {
            if let w = f.when, !(try holds(w, params)) { continue }
            out += try encodeField(f, params, ctx)
        }
        return out
    }
}
