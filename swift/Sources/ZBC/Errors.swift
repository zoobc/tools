// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

/// Exit codes and error classes of spec/cli-contract.md section 5.
public enum ExitCode {
    public static let ok = 0, internalError = 1, usage = 2, nodeUnreachable = 3, insufficientBalance = 4, feeTooLow = 5
    public static let rejected = 6, notFound = 7, timeout = 8, nodeBusy = 9, verifyFailed = 10

    public static func errorClass(_ code: Int) -> String {
        switch code {
        case 0: return "ok"; case 2: return "usage"; case 3: return "node_unreachable"; case 4: return "insufficient_balance"; case 5: return "fee_too_low"
        case 6: return "rejected"; case 7: return "not_found"; case 8: return "timeout"; case 9: return "node_busy"; case 10: return "verify_failed"
        default: return "internal"
        }
    }

    /// Classify a node's rejection into an exit code (spec/api.md section 2).
    public static func classifyNodeError(_ httpCode: Int, _ text: String) -> Int {
        if httpCode == 0 { return nodeUnreachable }
        if httpCode >= 500 { return nodeBusy }
        let t = text.lowercased()
        if t.contains("fee too low") { return feeTooLow }
        if t.contains("insufficient balance") || t.contains("insufficient spendable") || t.contains("account does not exist") { return insufficientBalance }
        if t.contains("not found") || t.contains("unknown token") || t.contains("unknown or expired token") || t.contains("unknown app") { return notFound }
        return rejected
    }
}

/// An error that carries its exit code; `extra` is merged into the JSON error object.
public struct ToolError: Error {
    public var code: Int
    public var message: String
    public var extra: [String: Any]
    public init(_ code: Int, _ message: String, extra: [String: Any] = [:]) { self.code = code; self.message = message; self.extra = extra }
    public static func usage(_ message: String) -> ToolError { ToolError(ExitCode.usage, message) }
    public static func internalError(_ message: String) -> ToolError { ToolError(ExitCode.internalError, message) }
    /// The JSON error object of the contract (section 4).
    public var json: [String: Any] {
        var m: [String: Any] = ["success": false, "error": message, "exit_code": code, "error_class": ExitCode.errorClass(code)]
        for (k, v) in extra { m[k] = v }
        return m
    }
}
