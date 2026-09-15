// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// Shared output-mode convention for ZooBC OUTPUT-ONLY tools (key/address/account generators).
// Mirrors the tx tools' contract so every tool behaves the same:
//   * default output is JSON (machine-friendly, safe for scripts / command substitution),
//   * when stdout is an interactive terminal (a human is watching) it auto-switches to
//     human-readable, so `zbc-key-gen` in a terminal is readable while `X=$(zbc-key-gen)` is JSON,
//   * -v / --verbose forces human-readable, --json forces JSON, --help / -h prints help.
#include <string>
#include <cstdio>
#include <unistd.h>

namespace zbctool {

struct Mode {
    bool verbose = false;  // human-readable output (else JSON)
    bool help = false;     // --help / -h was given
};

// Parse the shared -v/--verbose, --json, --help/-h flags. Positional/other args are left for the
// tool to parse itself. stdout-tty auto-selects human output unless --json overrides.
inline Mode parse_mode(int argc, char** argv) {
    Mode m;
    bool force_json = false, force_verbose = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") m.help = true;
        else if (a == "-v" || a == "--verbose") force_verbose = true;
        else if (a == "--json") force_json = true;
    }
    m.verbose = force_verbose || (!force_json && isatty(fileno(stdout)));
    return m;
}

// True if `a` is one of the shared flags (so a tool can skip them when reading its positionals).
inline bool is_mode_flag(const std::string& a) {
    return a == "-h" || a == "--help" || a == "-v" || a == "--verbose" || a == "--json";
}

}  // namespace zbctool
