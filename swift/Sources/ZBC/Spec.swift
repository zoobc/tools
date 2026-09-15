// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

import Foundation

/// One command-line parameter of a transaction description (spec/transactions/README.md).
public struct ParamDef: Decodable {
    public let name: String, kind: String, required: Bool, help: String
    public let `default`: String?, min: Int64?, max: Int64?
}

/// One body field.
public struct FieldDef: Decodable {
    public let name: String, encoding: String, from: String
    public let size: Int?, value: String?, when: String?, computed: String?, default_from: String?, when_zero: String?
}

/// One transaction description.
public struct TxDef: Decodable {
    public let name: String, type: UInt32, command: String, binary: String?, description: String, sender_key: String, recipient: String
    public let options: [String], needs_node: Bool, custom: String?, params: [ParamDef], body: [FieldDef]
    public let example: [String: String], notes: [String]
}

/// The transaction descriptions embedded from spec/transactions (CommandsGen.swift).
public enum Spec {
    public static let commands: [TxDef] = try! JSONDecoder().decode([TxDef].self, from: Data(commandsJSON.utf8))
    public static let byName: [String: TxDef] = Dictionary(uniqueKeysWithValues: commands.map { ($0.command, $0) })
    public static func command(_ name: String) -> TxDef? { byName[name] }
}
