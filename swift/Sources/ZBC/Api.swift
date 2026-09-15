// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The node/gateway HTTP client (spec/api.md): node info, submit, status, transaction, account, latest block.
public final class Client {
    public let api: String
    public let timeoutSeconds: Double
    private let session: URLSession

    public init(api: String = "http://localhost:8080", timeoutSeconds: Double = 20) {
        self.api = api.hasSuffix("/") ? String(api.dropLast()) : api
        self.timeoutSeconds = timeoutSeconds
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeoutSeconds
        cfg.timeoutIntervalForResource = timeoutSeconds
        session = URLSession(configuration: cfg)
    }

    /// One HTTP answer.
    public struct Reply {
        public let status: Int, text: String, json: Any?
        public var body: Any { json ?? text }
    }

    private func call(_ method: String, _ path: String, body: Data? = nil) throws -> Reply {
        guard let url = URL(string: api + path) else { throw ToolError.usage("bad API URL: \(api)") }
        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("zbc-cli/1.0", forHTTPHeaderField: "User-Agent")
        if let b = body { req.httpBody = b; req.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let sem = DispatchSemaphore(value: 0)
        let box = ResultBox()
        session.dataTask(with: req) { d, r, e in box.set(d, r, e); sem.signal() }.resume()
        sem.wait()
        let result = box.get()
        if let e = result.2 {
            let ns = e as NSError
            if ns.code == NSURLErrorTimedOut { throw ToolError(ExitCode.timeout, "Timed out: \(path) on \(api)") }
            throw ToolError(ExitCode.nodeUnreachable, "Connection failed: \(path) on \(api): \(ns.localizedDescription)")
        }
        let status = (result.1 as? HTTPURLResponse)?.statusCode ?? 0
        let text = String(decoding: result.0 ?? Data(), as: UTF8.self)
        let json = result.0.flatMap { try? JSONSerialization.jsonObject(with: $0) }
        return Reply(status: status, text: text, json: json)
    }

    /// GET /api/v1/node/info.
    public func nodeInfo() throws -> [String: Any] {
        let r = try call("GET", "/api/v1/node/info")
        guard r.status == 200 else {
            throw ToolError(r.status >= 500 ? ExitCode.nodeBusy : ExitCode.nodeUnreachable,
                            "cannot read /api/v1/node/info from \(api) (HTTP \(r.status)) to learn which chain to sign for; pass --genesis <hex> to sign for a known chain", extra: ["http_code": r.status])
        }
        return r.json as? [String: Any] ?? [:]
    }

    /// The chain's signing rule as the node reports it.
    public func signingRule() throws -> SigningContext {
        let info = try nodeInfo()
        let sv = (info["signing_version"] as? NSNumber)?.intValue ?? 1
        if sv >= 2 {
            guard let g = info["genesis_hash"] as? String, Enc.isHex(g, 64) else { throw ToolError.internalError("node enforces chain-bound signing but reports no genesis hash; pass --genesis <hex>") }
            return SigningContext(version: 2, genesisHash: Enc.unhex(g)!)
        }
        return SigningContext(version: 1)
    }

    /// POST /api/v1/transactions -> (reply, accepted). Transport failures throw.
    public func submit(_ payload: [(String, Any)]) throws -> (Reply, Bool) {
        let r = try call("POST", "/api/v1/transactions", body: JSONText.encode(payload).data(using: .utf8))
        return (r, r.status == 200 || r.status == 202)
    }

    /// Submit and throw a classified error when the node rejects.
    public func submitOrThrow(_ payload: [(String, Any)]) throws -> Reply {
        let (r, ok) = try submit(payload)
        if !ok { throw Client.rejectionError(r) }
        return r
    }

    /// GET /api/v1/transactions/<hash>/status; a 404 answers status not_found rather than throwing.
    public func status(_ hash: String) throws -> [String: Any] {
        let r = try call("GET", "/api/v1/transactions/\(hash)/status")
        guard r.status == 200 || r.status == 404 else { throw Client.rejectionError(r) }
        var out: [String: Any] = ["transaction_hash": hash, "status": r.status == 404 ? "not_found" : "unknown"]
        if let m = r.json as? [String: Any] { for (k, v) in m { out[k] = v } }
        out["http_code"] = r.status
        return out
    }

    /// GET /api/v1/transactions/<hash>; exit 7 when unknown.
    public func transaction(_ hash: String) throws -> Any {
        let r = try call("GET", "/api/v1/transactions/\(hash)")
        guard r.status == 200 else {
            var e = Client.rejectionError(r)
            if r.status == 404 { e.code = ExitCode.notFound; e.message = "Transaction not found" }
            throw e
        }
        return r.body
    }

    /// GET /api/v1/accounts/<address>; exit 7 when unknown.
    public func account(_ address: String) throws -> Any {
        let r = try call("GET", "/api/v1/accounts/\(address.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? address)")
        guard r.status == 200 else {
            var e = Client.rejectionError(r)
            if r.status == 404 { e.code = ExitCode.notFound; e.message = "Account not found" }
            throw e
        }
        return r.body
    }

    /// GET /api/v1/blocks/latest: the reference block for a proof of ownership (`block_hash`, or a gateway's `hash`).
    public func latestBlock() throws -> Custom.ReferenceBlock {
        let r = try call("GET", "/api/v1/blocks/latest")
        let m = r.json as? [String: Any] ?? [:]
        let h = (m["block_hash"] as? String) ?? (m["hash"] as? String) ?? ""
        guard r.status == 200, Enc.isHex(h, 64) else { throw ToolError(ExitCode.internalError, "Failed to fetch latest block from \(api)", extra: ["http_code": r.status]) }
        return Custom.ReferenceBlock(hash: Enc.unhex(h)!, height: UInt32((m["height"] as? NSNumber)?.int64Value ?? 0))
    }

    /// Classify a node's rejection reply (spec/api.md section 2).
    public static func rejectionError(_ r: Reply) -> ToolError {
        let text = ((r.json as? [String: Any])?["error"] as? String) ?? r.text
        return ToolError(ExitCode.classifyNodeError(r.status, text), text, extra: ["http_code": r.status, "api_response": r.body])
    }
}

/// A thread-safe holder for the URLSession completion values.
private final class ResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: (Data?, URLResponse?, Error?) = (nil, nil, nil)
    func set(_ d: Data?, _ r: URLResponse?, _ e: Error?) { lock.lock(); value = (d, r, e); lock.unlock() }
    func get() -> (Data?, URLResponse?, Error?) { lock.lock(); defer { lock.unlock() }; return value }
}

/// JSON text with the key order given (JSONSerialization sorts or shuffles; the tools print the contract's order).
public enum JSONText {
    public static func encode(_ pairs: [(String, Any)], indent: Int = 0, level: Int = 0) -> String {
        let pad = indent > 0 ? String(repeating: " ", count: indent * (level + 1)) : ""
        let end = indent > 0 ? "\n" + String(repeating: " ", count: indent * level) : ""
        let sep = indent > 0 ? ",\n" : ","
        let items = pairs.map { "\(indent > 0 ? "\n" + pad : "")\(quote($0.0)):\(indent > 0 ? " " : "")\(encodeValue($0.1, indent: indent, level: level + 1))" }
        return "{" + items.joined(separator: sep) + end + "}"
    }
    public static func encodeValue(_ v: Any, indent: Int = 0, level: Int = 0) -> String {
        // Dynamic types first: on Linux an NSNumber holding 1 also casts to Bool, so `as Bool` alone lies.
        let t = type(of: v)
        if t == Bool.self { return (v as! Bool) ? "true" : "false" }
        if t == Int.self { return String(v as! Int) }
        if t == Int64.self { return String(v as! Int64) }
        if t == UInt32.self { return String(v as! UInt32) }
        if t == Int32.self { return String(v as! Int32) }
        if t == UInt64.self { return String(v as! UInt64) }
        switch v {
        case let s as String: return quote(s)
        case let n as NSNumber:
            if "\(type(of: n))".contains("Boolean") { return n.boolValue ? "true" : "false" }
            return n.stringValue
        case let n as Double: return n == n.rounded() && abs(n) < 1e15 ? String(Int64(n)) : String(n)
        case let p as [(String, Any)]: return encode(p, indent: indent, level: level)
        case let d as [String: Any]: return encode(d.keys.sorted().map { ($0, d[$0]!) }, indent: indent, level: level)
        case let a as [Any]:
            let pad = indent > 0 ? String(repeating: " ", count: indent * (level + 1)) : ""
            let end = indent > 0 ? "\n" + String(repeating: " ", count: indent * level) : ""
            return "[" + a.map { (indent > 0 ? "\n" + pad : "") + encodeValue($0, indent: indent, level: level + 1) }.joined(separator: ",") + end + "]"
        case is NSNull: return "null"
        default: return quote(String(describing: v))
        }
    }
    public static func quote(_ s: String) -> String {
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""; case "\\": out += "\\\\"; case "\n": out += "\\n"; case "\r": out += "\\r"; case "\t": out += "\\t"
            default: if u.value < 0x20 { out += String(format: "\\u%04x", u.value) } else { out.unicodeScalars.append(u) }
            }
        }
        return out + "\""
    }
}
