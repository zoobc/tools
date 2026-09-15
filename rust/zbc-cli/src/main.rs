// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! zbc-cli: every ZooBC transaction as a subcommand, plus sign-message and verify-message.

fn main() {
    std::process::exit(zbc::cli::run(&std::env::args().skip(1).collect::<Vec<_>>()));
}
