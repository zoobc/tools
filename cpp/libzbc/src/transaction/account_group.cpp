// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Account groups (types 55-58): wire codec, consent digests and consent verification.
// docs/ACCOUNT_GROUPS.md. The group STATE (tables, resolution, moves) is in account_group_state.cpp.
#include "zoobc/transaction/account_group.h"

#include <cstring>
#include <set>

#include "zoobc/common/chain_identity.h"
#include "zoobc/common/constants.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/signature.h"
#include "zoobc/transaction/account_state.h"
#include "zoobc/transaction/multisignature_service.h"
#include "zoobc/util/transaction_util.h"

namespace zoobc {
namespace transaction {
namespace group {

namespace {

void putU16(std::vector<uint8_t>& b, uint16_t v) { b.push_back(v & 0xff); b.push_back(v >> 8); }
void putU32(std::vector<uint8_t>& b, uint32_t v) { for (int i = 0; i < 4; i++) b.push_back((v >> (8 * i)) & 0xff); }
void putU64(std::vector<uint8_t>& b, uint64_t v) { for (int i = 0; i < 8; i++) b.push_back((v >> (8 * i)) & 0xff); }
void putAddr(std::vector<uint8_t>& b, const std::vector<uint8_t>& a) {
    b.push_back(static_cast<uint8_t>(a.size()));
    b.insert(b.end(), a.begin(), a.end());
}

// Bounds-checked reader: every read fails cleanly on truncation instead of reading past the end.
struct Reader {
    const std::vector<uint8_t>& b;
    size_t p = 0;
    bool ok = true;
    explicit Reader(const std::vector<uint8_t>& bytes) : b(bytes) {}
    bool need(size_t n) { if (!ok || p + n > b.size()) { ok = false; return false; } return true; }
    uint8_t u8() { if (!need(1)) return 0; return b[p++]; }
    uint16_t u16() { if (!need(2)) return 0; uint16_t v = b[p] | (static_cast<uint16_t>(b[p + 1]) << 8); p += 2; return v; }
    uint32_t u32() { if (!need(4)) return 0; uint32_t v = 0; for (int i = 0; i < 4; i++) v |= static_cast<uint32_t>(b[p + i]) << (8 * i); p += 4; return v; }
    uint64_t u64() { if (!need(8)) return 0; uint64_t v = 0; for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(b[p + i]) << (8 * i); p += 8; return v; }
    std::vector<uint8_t> bytes(size_t n) {
        if (!need(n)) return {};
        std::vector<uint8_t> v(b.begin() + static_cast<std::ptrdiff_t>(p), b.begin() + static_cast<std::ptrdiff_t>(p + n));
        p += n;
        return v;
    }
    std::vector<uint8_t> addr() {
        const size_t n = u8();
        if (n == 0) { ok = false; return {}; }
        return bytes(n);
    }
    bool done() const { return ok && p == b.size(); }
};

Error bad(const std::string& what) { return Error{ErrorCode::ValidationError, what}; }

bool readProof(Reader& r, ConsentProof& out) {
    out.kind = r.u8();
    if (out.kind == 0 || out.kind == 2) {
        const uint16_t n = r.u16();
        out.signature = r.bytes(n);
        return r.ok && n > 0;
    }
    if (out.kind == 1) {
        out.minimum_signatures = r.u32();
        out.multisig_nonce = static_cast<int64_t>(r.u64());
        const uint8_t n = r.u8();
        for (uint8_t i = 0; i < n && r.ok; i++) {
            auto a = r.addr();
            const uint16_t sl = r.u16();
            auto s = r.bytes(sl);
            out.participants.emplace_back(std::move(a), std::move(s));
        }
        return r.ok && n > 0;
    }
    return false;
}

Result<std::vector<uint8_t>> consentDigest(const char* tag, const std::vector<uint8_t>& first,
                                           const std::vector<uint8_t>& second,
                                           uint32_t valid_until, uint32_t seq) {
    if (!chain::Identity::IsSet())
        return Error{ErrorCode::Internal, "Chain identity not initialised: cannot compute a group consent digest"};
    const auto& genesis = chain::Identity::GenesisHash();
    const auto a = AccountState::CanonicalAccountKey(first);
    const auto b = AccountState::CanonicalAccountKey(second);
    std::vector<uint8_t> pre(tag, tag + std::strlen(tag));
    pre.insert(pre.end(), genesis.begin(), genesis.end());
    putAddr(pre, a);
    putAddr(pre, b);
    putU32(pre, valid_until);
    putU32(pre, seq);
    return crypto::Hash::SHA3_256(pre);
}

}  // namespace

std::vector<uint8_t> EncodeProof(const ConsentProof& p) {
    std::vector<uint8_t> b;
    b.push_back(p.kind);
    if (p.kind == 0 || p.kind == 2) {
        putU16(b, static_cast<uint16_t>(p.signature.size()));
        b.insert(b.end(), p.signature.begin(), p.signature.end());
    } else {
        putU32(b, p.minimum_signatures);
        putU64(b, static_cast<uint64_t>(p.multisig_nonce));
        b.push_back(static_cast<uint8_t>(p.participants.size()));
        for (const auto& [a, s] : p.participants) {
            putAddr(b, a);
            putU16(b, static_cast<uint16_t>(s.size()));
            b.insert(b.end(), s.begin(), s.end());
        }
    }
    return b;
}

std::vector<uint8_t> EncodeLinkBody(const LinkBody& x) {
    std::vector<uint8_t> b{x.version};
    putAddr(b, x.member);
    putU32(b, x.valid_until_height);
    putU32(b, x.link_seq);
    auto p = EncodeProof(x.proof);
    b.insert(b.end(), p.begin(), p.end());
    return b;
}

std::vector<uint8_t> EncodeUnlinkBody(const UnlinkBody& x) {
    std::vector<uint8_t> b{x.version};
    putAddr(b, x.member);
    return b;
}

std::vector<uint8_t> EncodePermissionsBody(const PermissionsBody& x) {
    std::vector<uint8_t> b{x.version};
    putAddr(b, x.member);
    b.push_back(x.flags);
    putU64(b, static_cast<uint64_t>(x.spend_limit));
    putU32(b, x.period_blocks);
    return b;
}

std::vector<uint8_t> EncodeControlBody(const ControlBody& x) {
    std::vector<uint8_t> b{x.version};
    putAddr(b, x.new_controller);
    putU32(b, x.valid_until_height);
    putU32(b, x.link_seq);
    auto p = EncodeProof(x.proof);
    b.insert(b.end(), p.begin(), p.end());
    return b;
}

Result<LinkBody> ParseLinkBody(const std::vector<uint8_t>& bytes) {
    Reader r(bytes);
    LinkBody x;
    x.version = r.u8();
    if (r.ok && x.version != kBodyVersion) return bad("LinkAccount: unsupported body version");
    x.member = r.addr();
    x.valid_until_height = r.u32();
    x.link_seq = r.u32();
    if (!readProof(r, x.proof)) return bad("LinkAccount: malformed consent proof");
    if (!r.done()) return bad("LinkAccount: truncated body or trailing bytes");
    return x;
}

Result<UnlinkBody> ParseUnlinkBody(const std::vector<uint8_t>& bytes) {
    Reader r(bytes);
    UnlinkBody x;
    x.version = r.u8();
    if (r.ok && x.version != kBodyVersion) return bad("UnlinkAccount: unsupported body version");
    x.member = r.addr();
    if (!r.done()) return bad("UnlinkAccount: truncated body or trailing bytes");
    return x;
}

Result<PermissionsBody> ParsePermissionsBody(const std::vector<uint8_t>& bytes) {
    Reader r(bytes);
    PermissionsBody x;
    x.version = r.u8();
    if (r.ok && x.version != kBodyVersion) return bad("SetMemberPermissions: unsupported body version");
    x.member = r.addr();
    x.flags = r.u8();
    x.spend_limit = static_cast<int64_t>(r.u64());
    x.period_blocks = r.u32();
    if (!r.done()) return bad("SetMemberPermissions: truncated body or trailing bytes");
    return x;
}

Result<ControlBody> ParseControlBody(const std::vector<uint8_t>& bytes) {
    Reader r(bytes);
    ControlBody x;
    x.version = r.u8();
    if (r.ok && x.version != kBodyVersion) return bad("TransferGroupControl: unsupported body version");
    x.new_controller = r.addr();
    x.valid_until_height = r.u32();
    x.link_seq = r.u32();
    if (!readProof(r, x.proof)) return bad("TransferGroupControl: malformed consent proof");
    if (!r.done()) return bad("TransferGroupControl: truncated body or trailing bytes");
    return x;
}

Result<std::vector<uint8_t>> LinkConsentDigest(const std::vector<uint8_t>& controller,
                                               const std::vector<uint8_t>& member,
                                               uint32_t valid_until_height, uint32_t link_seq) {
    return consentDigest("ZBC-GROUP-LINK", controller, member, valid_until_height, link_seq);
}

Result<std::vector<uint8_t>> ControlConsentDigest(const std::vector<uint8_t>& current_controller,
                                                  const std::vector<uint8_t>& new_controller,
                                                  uint32_t valid_until_height, uint32_t link_seq) {
    return consentDigest("ZBC-GROUP-CONTROL", current_controller, new_controller, valid_until_height, link_seq);
}

Result<void> VerifyConsent(const std::vector<uint8_t>& digest, const ConsentProof& proof,
                           const std::vector<uint8_t>& signer) {
    if (proof.kind == 0) {
        auto v = crypto::Signature::VerifySignature(digest, proof.signature, signer);
        if (v.IsErr() || !v.Value())
            return bad("the consent signature does not verify for " + std::string("the consenting address"));
        return Result<void>();
    }
    if (proof.kind == 2) {
        // An Ethereum wallet (MetaMask) will not sign a bare 32-byte hash; it signs through
        // personal_sign, which hashes "\x19Ethereum Signed Message:\n32" || digest. Only for an
        // Ethereum-typed address, where that is genuinely how its key signs.
        if (signer.size() < 4 || util::TransactionUtil::ExtractAccountType(signer) != util::TransactionUtil::ACCOUNT_TYPE_ETH)
            return bad("consent proof kind 2 (personal_sign) is for an Ethereum address");
        static const std::string kPrefix = std::string("\x19") + "Ethereum Signed Message:\n32";
        std::vector<uint8_t> payload(kPrefix.begin(), kPrefix.end());
        payload.insert(payload.end(), digest.begin(), digest.end());
        auto v = crypto::Signature::VerifySignature(payload, proof.signature, signer);
        if (v.IsErr() || !v.Value()) return bad("the personal_sign consent does not verify for the consenting address");
        return Result<void>();
    }
    if (proof.kind != 1) return bad("unknown consent proof kind");
    // A multisig address consents through its participants, exactly as it signs a transaction.
    if (proof.participants.empty() || proof.participants.size() > 255)
        return bad("multisig consent: no participants");
    if (proof.minimum_signatures == 0 || proof.minimum_signatures > proof.participants.size())
        return bad("multisig consent: threshold out of range");
    std::vector<std::vector<uint8_t>> addrs;
    std::set<std::vector<uint8_t>> seen;
    for (const auto& [a, s] : proof.participants) {
        (void)s;
        if (!seen.insert(a).second) return bad("multisig consent: duplicate participant");
        addrs.push_back(a);
    }
    const auto derived = MultisignatureService::GenerateMultisigAddress(addrs, proof.multisig_nonce,
                                                                        proof.minimum_signatures);
    if (derived.empty() ||
        AccountState::CanonicalAccountKey(derived) != AccountState::CanonicalAccountKey(signer))
        return bad("multisig consent: the participants, threshold and nonce do not hash to the consenting address");
    uint32_t valid = 0;
    for (const auto& [a, s] : proof.participants) {
        if (s.empty()) continue;
        auto v = crypto::Signature::VerifySignature(digest, s, a);
        if (v.IsOk() && v.Value()) valid++;
    }
    if (valid < proof.minimum_signatures)
        return bad("multisig consent: " + std::to_string(valid) + " valid participant signatures, " +
                   std::to_string(proof.minimum_signatures) + " required");
    return Result<void>();
}

bool IsNonSigningType(const std::vector<uint8_t>& address) {
    if (address.size() == 32) return false;   // legacy ZBC key
    if (address.size() < 4) return true;
    const int32_t t = util::TransactionUtil::ExtractAccountType(address);
    return t == 2 || t == 3 || t == 8 || t == 10;
}

bool IsGroupManagementType(TransactionType t) {
    return t == TransactionType::LinkAccount || t == TransactionType::UnlinkAccount ||
           t == TransactionType::SetMemberPermissions || t == TransactionType::TransferGroupControl;
}

bool IsControllerOnlyType(TransactionType t) {
    return t == TransactionType::LinkAccount || t == TransactionType::SetMemberPermissions ||
           t == TransactionType::TransferGroupControl || t == TransactionType::SetSplitPolicy ||
           t == TransactionType::SetTransactPolicy;
}

uint64_t RecordWeight(const std::vector<uint8_t>& controller,
                      const std::vector<std::vector<uint8_t>>& member_addresses) {
    uint64_t w = constants::ACCOUNT_GROUP_RECORD_BASE_BYTES + controller.size();
    for (const auto& m : member_addresses) w += m.size() + constants::ACCOUNT_GROUP_MEMBER_ENTRY_BYTES;
    return w;
}

}  // namespace group
}  // namespace transaction
}  // namespace zoobc
