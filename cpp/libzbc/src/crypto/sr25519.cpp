// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

#include "zoobc/crypto/sr25519.h"
#include <cstring>
#include <sodium.h>

namespace zoobc {
namespace crypto {

namespace {

// ---------------- Keccak-f[1600] (tiny_sha3 style; operates on 25 LE 64-bit lanes) ----------------
static inline uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL };
static const int KECCAK_ROTC[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
static const int KECCAK_PILN[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

void keccakf(uint64_t st[25]) {
    for (int r = 0; r < 24; r++) {
        uint64_t bc[5], t;
        for (int i = 0; i < 5; i++) bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i = 0; i < 5; i++) { t = bc[(i+4)%5] ^ rotl64(bc[(i+1)%5], 1); for (int j = 0; j < 25; j += 5) st[j+i] ^= t; }
        t = st[1];
        for (int i = 0; i < 24; i++) { int j = KECCAK_PILN[i]; bc[0] = st[j]; st[j] = rotl64(t, KECCAK_ROTC[i]); t = bc[0]; }
        for (int j = 0; j < 25; j += 5) { for (int i = 0; i < 5; i++) bc[i] = st[j+i]; for (int i = 0; i < 5; i++) st[j+i] ^= (~bc[(i+1)%5]) & bc[(i+2)%5]; }
        st[0] ^= KECCAK_RC[r];
    }
}

// run keccak-f on STROBE's 200-byte state (state bytes ↔ LE 64-bit lanes)
void keccakF1600(uint8_t state[200]) {
    uint64_t lanes[25];
    for (int i = 0; i < 25; i++) { uint64_t v = 0; for (int j = 0; j < 8; j++) v |= (uint64_t)state[i*8+j] << (8*j); lanes[i] = v; }
    keccakf(lanes);
    for (int i = 0; i < 25; i++) { uint64_t v = lanes[i]; for (int j = 0; j < 8; j++) state[i*8+j] = (uint8_t)(v >> (8*j)); }
}

// ---------------- STROBE-128 (port of merlin/src/strobe.rs) ----------------
static const uint8_t STROBE_R = 166;
enum { FLAG_I = 1, FLAG_A = 1<<1, FLAG_C = 1<<2, FLAG_T = 1<<3, FLAG_M = 1<<4, FLAG_K = 1<<5 };

struct Strobe128 {
    uint8_t state[200];
    uint8_t pos = 0;
    uint8_t pos_begin = 0;
    uint8_t cur_flags = 0;

    explicit Strobe128(const uint8_t* label, size_t label_len) {
        std::memset(state, 0, sizeof(state));
        const uint8_t head[6] = {1, (uint8_t)(STROBE_R + 2), 1, 0, 1, 96};
        std::memcpy(state, head, 6);
        std::memcpy(state + 6, "STROBEv1.0.2", 12);
        keccakF1600(state);
        meta_ad(label, label_len, false);
    }

    void run_f() {
        state[pos] ^= pos_begin;
        state[pos + 1] ^= 0x04;
        state[STROBE_R + 1] ^= 0x80;
        keccakF1600(state);
        pos = 0; pos_begin = 0;
    }
    void absorb(const uint8_t* data, size_t n) {
        for (size_t i = 0; i < n; i++) { state[pos] ^= data[i]; pos++; if (pos == STROBE_R) run_f(); }
    }
    void squeeze(uint8_t* data, size_t n) {
        for (size_t i = 0; i < n; i++) { data[i] = state[pos]; state[pos] = 0; pos++; if (pos == STROBE_R) run_f(); }
    }
    void begin_op(uint8_t flags, bool more) {
        if (more) return;  // continuing the same op; merlin asserts flags match — always true on our paths
        // T flag (transport) is unused here.
        uint8_t old_begin = pos_begin;
        pos_begin = pos + 1;
        cur_flags = flags;
        uint8_t framing[2] = {old_begin, flags};
        absorb(framing, 2);
        bool force_f = (flags & (FLAG_C | FLAG_K)) != 0;
        if (force_f && pos != 0) run_f();
    }
    void meta_ad(const uint8_t* data, size_t n, bool more) { begin_op(FLAG_M | FLAG_A, more); absorb(data, n); }
    void ad(const uint8_t* data, size_t n, bool more)      { begin_op(FLAG_A, more);          absorb(data, n); }
    void prf(uint8_t* data, size_t n, bool more)           { begin_op(FLAG_I | FLAG_A | FLAG_C, more); squeeze(data, n); }
};

// ---------------- Merlin Transcript (port of merlin/src/transcript.rs) ----------------
struct Transcript {
    Strobe128 strobe;
    explicit Transcript(const char* label)
        : strobe(reinterpret_cast<const uint8_t*>("Merlin v1.0"), 11) {
        append_message(reinterpret_cast<const uint8_t*>("dom-sep"), 7,
                       reinterpret_cast<const uint8_t*>(label), std::strlen(label));
    }
    void append_message(const uint8_t* label, size_t llen, const uint8_t* msg, size_t mlen) {
        uint8_t len_le[4] = {(uint8_t)(mlen), (uint8_t)(mlen>>8), (uint8_t)(mlen>>16), (uint8_t)(mlen>>24)};
        strobe.meta_ad(label, llen, false);
        strobe.meta_ad(len_le, 4, true);
        strobe.ad(msg, mlen, false);
    }
    void challenge_bytes(const uint8_t* label, size_t llen, uint8_t* dest, size_t dlen) {
        uint8_t len_le[4] = {(uint8_t)(dlen), (uint8_t)(dlen>>8), (uint8_t)(dlen>>16), (uint8_t)(dlen>>24)};
        strobe.meta_ad(label, llen, false);
        strobe.meta_ad(len_le, 4, true);
        strobe.prf(dest, dlen, false);
    }
};

inline void am(Transcript& t, const char* label, const uint8_t* msg, size_t mlen) {
    t.append_message(reinterpret_cast<const uint8_t*>(label), std::strlen(label), msg, mlen);
}

}  // namespace

bool Sr25519Verify(const std::vector<uint8_t>& public_key,
                   const std::vector<uint8_t>& context,
                   const std::vector<uint8_t>& message,
                   const std::vector<uint8_t>& signature) {
    if (public_key.size() != 32 || signature.size() != 64) return false;

    // schnorrkel signature = R(32) ‖ s(32); the high bit of s[31] is a "this is schnorrkel" marker.
    uint8_t R[32]; std::memcpy(R, signature.data(), 32);
    uint8_t s[32]; std::memcpy(s, signature.data() + 32, 32);
    if ((s[31] & 0x80) == 0) return false;   // marker bit must be set
    s[31] &= 0x7f;

    // require s canonical (< group order L): reduce(s‖0) must equal s
    uint8_t s64[64]; std::memcpy(s64, s, 32); std::memset(s64 + 32, 0, 32);
    uint8_t s_red[32]; crypto_core_ristretto255_scalar_reduce(s_red, s64);
    if (sodium_memcmp(s_red, s, 32) != 0) return false;

    // Transcript:  signing_context("substrate").bytes(message)  then  verify()
    Transcript t("SigningContext");
    am(t, "", context.data(), context.size());
    am(t, "sign-bytes", message.data(), message.size());
    am(t, "proto-name", reinterpret_cast<const uint8_t*>("Schnorr-sig"), 11);
    am(t, "sign:pk", public_key.data(), 32);
    am(t, "sign:R", R, 32);

    uint8_t challenge64[64];
    t.challenge_bytes(reinterpret_cast<const uint8_t*>("sign:c"), 6, challenge64, 64);
    uint8_t k[32]; crypto_core_ristretto255_scalar_reduce(k, challenge64);  // from_bytes_mod_order_wide

    // R' = s·B − k·PK ; valid iff R'.compress() == R
    uint8_t sB[32], kPK[32], Rp[32];
    if (crypto_scalarmult_ristretto255_base(sB, s) != 0) return false;
    if (crypto_scalarmult_ristretto255(kPK, k, public_key.data()) != 0) return false;
    if (crypto_core_ristretto255_sub(Rp, sB, kPK) != 0) return false;
    return sodium_memcmp(Rp, R, 32) == 0;
}

}  // namespace crypto
}  // namespace zoobc
