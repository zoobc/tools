// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// j72 / j75: the fault record of the block being applied on this thread.
//
// BlockService::PushBlock opens one for the whole apply; a read or a write inside it that fails on this node is
// recorded here (the first one), and the apply refuses the block before it commits. Recorded: a consensus parameter
// that is malformed or cannot be read (consensus::Params::Get), an account, token or oracle row that cannot be read
// (AccountState), and every write this node's storage could not do (Database: an INSERT, UPDATE, DELETE or REPLACE
// that failed busy, locked, read-only, on I/O, corrupt or full; not a constraint or a schema refusal, which every
// node running the same code meets alike). Nothing computed from a read that did
// not happen, or after a write that did not happen, is committed. Outside any apply (the API, the mempool,
// validation) nothing is recorded: the caller gets its usual answer and the next block is unaffected. Nested applies
// each keep their own.
#include <string>

namespace zoobc {

class ApplyScope {
public:
    ApplyScope() : outer_(Current()) { Current() = this; }
    ~ApplyScope() { Current() = outer_; }
    ApplyScope(const ApplyScope&) = delete;
    ApplyScope& operator=(const ApplyScope&) = delete;
    // The first fault of this apply (empty when none).
    const std::string& Fault() const { return fault_; }
    // Record a read or a write that failed, when a block is being applied on this thread (else nothing).
    static void Note(const std::string& why) { if (auto* s = Current(); s && s->fault_.empty()) s->fault_ = why; }
    // True while a block is being applied on this thread.
    static bool Active() { return Current() != nullptr; }
private:
    static ApplyScope*& Current() { thread_local ApplyScope* current = nullptr; return current; }
    ApplyScope* outer_;
    std::string fault_;
};

}  // namespace zoobc
