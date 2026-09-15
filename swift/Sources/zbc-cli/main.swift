// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// zbc-cli: every ZooBC transaction as a subcommand, plus sign-message and verify-message.
import Foundation
import ZBC

let io = Cli.Io(
    stdin: { String(decoding: FileHandle.standardInput.readDataToEndOfFile(), as: UTF8.self) },
    stdout: { FileHandle.standardOutput.write(Data($0.utf8)) },
    stderr: { FileHandle.standardError.write(Data($0.utf8)) },
    env: { ProcessInfo.processInfo.environment[$0] },
    isTty: isatty(0) != 0)
exit(Int32(Cli.run(Array(CommandLine.arguments.dropFirst()), io)))
