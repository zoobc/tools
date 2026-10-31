// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#pragma once
// The chain clock: the one place consensus code asks "what time is it now".
//
// Block validity is defined in block time; the few places that compare block time with the wall
// clock (the validator's future bound, the candidate pool's selection windows, the producer's turn
// timing, and from 0.5.8 the acceptance gate on the apply path) read it here, so a test can set the
// clock and offer a block stamped ahead of or behind "now" (protocol review 2026-10-21, items 2 F8
// and 3 F7: no test ever did, which is why the two-hour hole of 2 F1 was never visible). The daemon
// calls DisableTestOverrides() first thing in main(): a node's clock is the system clock, always.
#include <chrono>
#include <cstdint>
#include <mutex>

namespace zoobc {

class Clock {
public:
    // Seconds since the epoch, as the system clock says, unless a test set the time.
    static int64_t Now() {
        {
            std::lock_guard<std::mutex> lock(Mutex());
            auto& st = State();
            if (st.enabled && st.set) return st.now;
        }
        return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    // Tests: pin "now".
    static void SetTestNow(int64_t now) {
        std::lock_guard<std::mutex> lock(Mutex());
        State().set = true;
        State().now = now;
    }
    static void ClearTestNow() {
        std::lock_guard<std::mutex> lock(Mutex());
        State().set = false;
    }
    // The daemon: no test clock, whatever is called later.
    static void DisableTestOverrides() {
        std::lock_guard<std::mutex> lock(Mutex());
        State().enabled = false;
        State().set = false;
    }

private:
    struct StateT { bool enabled = true; bool set = false; int64_t now = 0; };
    static StateT& State() { static StateT s; return s; }
    static std::mutex& Mutex() { static std::mutex m; return m; }
};

}  // namespace zoobc
