// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Air-gap signing (owner request 2026-11-01). Every transaction a role key signs (the release authority, the
// treasury, a market maker) can be built on the ONLINE machine without the key, signed on an OFFLINE computer that
// shows what it signs, and sent back online:
//
//   online   zbc-cli <command> <params without the key> --unsigned --from <account> [--api URL | --genesis HEX]
//              -> an UNSIGNED file (format zbc-unsigned-v1): the unsigned transaction bytes, the chain's genesis
//                 hash, the digest to sign and a human summary
//   offline  zbc-cli sign-tx <file|folder>... [--yes] [--genesis HEX]
//              -> decodes the bytes ITSELF and refuses a file whose summary, digest, chain or sender does not
//                 match them; shows the summary, asks "sign? [y/N]", writes the SIGNED file (zbc-signed-v1:
//                 the same plus the signature and the exact JSON body the node takes)
//   online   zbc-cli submit <file|folder>... [--api URL] [--wait]
//              -> checks each signature against its bytes and the node's chain before anything is sent; posts
//                 them in file-name order; with --wait each must be in a block before the next is sent (one
//                 transaction per account per block, TX1)
//
// What moves on the USB stick: UNSIGNED and SIGNED files and this program. What never moves: the key. One file
// format and one signer for every role operation (docs/AIRGAP-SIGNING.md). scripts/mac/zbc-anchor writes the
// same UNSIGNED files in Python for the page anchors and the wallet announcement; its summary must be the one
// summarize() below computes from the same bytes, or sign-tx refuses the file.
#ifndef ZOOBC_TOOLS_AIRGAP_H
#define ZOOBC_TOOLS_AIRGAP_H

#include "tx_common.h"
#include "zoobc/transaction/batch_rules.h"
#include <filesystem>
#include <fstream>
#include <map>
#ifndef _WIN32
#include <termios.h>
#include <unistd.h>
#endif

namespace airgap {
using namespace txc;
using TU = zoobc::util::TransactionUtil;

inline constexpr const char* UNSIGNED_FORMAT = "zbc-unsigned-v1";
inline constexpr const char* SIGNED_FORMAT = "zbc-signed-v1";
// An UNSIGNED file is valid for a day by default (a version-3 transaction, expiry 86400, rule tx_expiry_field):
// it is carried to another computer and back, and a folder of them goes out one block apart. --expiry overrides.
inline constexpr uint32_t DEFAULT_EXPIRY = 86400;
// The wallet update notice (scripts/mac/zbc-anchor --announce-wallet, wallet V1.79+): its value carries a
// signature by the publisher key over this canonical string. An exported notice leaves "sig" empty and
// sign-tx fills it with the same key that signs the transaction (see fill_wallet_notice).
inline constexpr const char* WALLET_NOTICE_PROPERTY = "wallet.release";
inline constexpr const char* WALLET_NOTICE_TAG = "ZBC-UPDATE-NOTICE-v1";

// A refusal carrying the exit code the command leaves with.
struct Refusal : std::runtime_error {
    int code;
    Refusal(int c, const std::string& m) : std::runtime_error(m), code(c) {}
};
[[noreturn]] inline void refuse(int code, const std::string& msg) { throw Refusal(code, msg); }

// ---------------------------------------------------------------------------------------------------------------
// Human formats. The summary is compared field by field between the file and the bytes, and zbc-anchor computes
// it in Python, so every value is a string written exactly as below.
// ---------------------------------------------------------------------------------------------------------------
inline std::string decimal8(int64_t atomic) {
    const bool neg = atomic < 0;
    const uint64_t a = neg ? (uint64_t)(-(atomic + 1)) + 1 : (uint64_t)atomic;
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%s%llu.%08llu", neg ? "-" : "", (unsigned long long)(a / 100000000ULL),
                  (unsigned long long)(a % 100000000ULL));
    return buf;
}
inline std::string zbc_amount(int64_t atomic) { return decimal8(atomic) + " ZBC"; }
inline std::string utc(int64_t ts) {
    std::time_t t = static_cast<std::time_t>(ts);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[40];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm);
    return buf;
}
inline std::string utc_iso(int64_t ts) {
    std::string s = utc(ts);   // "YYYY-MM-DD HH:MM:SS UTC" -> "YYYY-MM-DDTHH:MM:SSZ"
    return s.substr(0, 10) + "T" + s.substr(11, 8) + "Z";
}
inline std::string hexs(const std::vector<uint8_t>& b) { return bytes_to_hex(b); }
inline std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
inline bool is_hex(const std::string& s) {
    if (s.empty() || s.size() % 2) return false;
    for (char c : s) if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    return true;
}
// Printable means ASCII 0x20-0x7E and at most 512 bytes: shown as text. Anything else is shown by length and
// SHA-256, so a terminal never interprets bytes from a file it is asked to trust.
inline bool printable(const std::string& s) {
    if (s.size() > 512) return false;
    for (unsigned char c : s) if (c < 0x20 || c > 0x7e) return false;
    return true;
}
inline std::string sha256_hex(const std::string& s) {
    auto h = zoobc::crypto::Hash::SHA256(std::vector<uint8_t>(s.begin(), s.end()));
    return h.IsOk() ? hexs(h.Value()) : std::string();
}
inline std::string token(int64_t id) { return id == 0 ? std::string("0 (ZBC)") : std::to_string(id); }

inline const std::map<uint32_t, std::string>& type_names() {
    static const std::map<uint32_t, std::string> m = {
        {0,"Empty"},{1,"SendZBC"},{2,"NodeRegistration"},{3,"SetupAccountDataset"},{4,"ApprovalEscrow"},{5,"MultiSignature"},
        {6,"LiquidPayment"},{7,"FeeVoteCommitment"},{8,"DFSCreateFile"},{9,"AddPrepaidStorage"},{10,"IssueToken"},{11,"TransferToken"},
        {12,"MintToken"},{13,"BurnToken"},{14,"FinanceToken"},{15,"CreateTrigger"},{16,"CancelTrigger"},{17,"AttestEvent"},
        {18,"CreateSwapOffer"},{19,"AcceptSwapOffer"},{20,"CancelSwapOffer"},{21,"CreateMarket"},{22,"PlaceOrder"},{23,"CancelOrder"},
        {24,"CreateApp"},{25,"JoinApp"},{26,"AppMove"},{27,"ResignApp"},{28,"ClaimAppTimeout"},{29,"ScheduledTransfer"},
        {30,"CancelSchedule"},{31,"ReassignSchedule"},{32,"RegisterRelease"},{33,"ReleaseAuthorityPropose"},{34,"ReleaseAuthorityAccept"},
        {35,"RevokeRelease"},{36,"RegisterGateway"},{37,"GatewayHeartbeat"},{38,"UnregisterGateway"},{39,"SettleApp"},{40,"StoreFile"},
        {41,"SubmitStorageProof"},{42,"TransferDataset"},{43,"SetDatasetPolicy"},{44,"AcceptDataset"},{45,"DeleteDataset"},
        {46,"RegisterArchival"},{47,"UnregisterArchival"},{48,"RegisterRelay"},{49,"UnregisterRelay"},{50,"SetTransactPolicy"},
        {51,"SetConsensusParam"},{52,"FundLongevity"},{53,"CancelLongevity"},{54,"SetSplitPolicy"},{55,"LinkAccount"},{56,"UnlinkAccount"},
        {57,"SetMemberPermissions"},{58,"TransferGroupControl"},{59,"QueueAttendance"},{60,"EquivocationReport"},{61,"RollCall"},
        {257,"SendZBCBatch"},{258,"NodeRegistrationUpdate"},{259,"RemoveAccountDataset"},{260,"EscrowRequest"},{262,"LiquidPaymentStop"},
        {263,"FeeVoteReveal"},{264,"DFSUpdateFile"},{267,"TransferTokenBatch"},{296,"FundStoredFile"},{297,"SubmitStorageProofBatch"},
        {309,"CloseLongevity"},{514,"RemoveNodeRegistration"},{516,"DeclineEscrowRequest"},{520,"DFSDeleteFile"},{770,"ClaimNodeRegistration"},
    };
    return m;
}
inline std::string type_name(uint32_t t) {
    auto it = type_names().find(t);
    return (it == type_names().end() ? std::string("unknown type") : it->second) + " (" + std::to_string(t) + ")";
}

// A typed account (4-byte type, then its key or hash) as a person reads it.
inline std::string account(const std::vector<uint8_t>& a) {
    if (a.empty()) return "none";
    if (a.size() < 4) return "malformed " + hexs(a);
    const int32_t type = (int32_t)((uint32_t)a[0] | ((uint32_t)a[1] << 8) | ((uint32_t)a[2] << 16) | ((uint32_t)a[3] << 24));
    const std::vector<uint8_t> p(a.begin() + 4, a.end());
    if (type == TU::ACCOUNT_TYPE_ZBC && p.size() == 32) return zoobc::crypto::ZoobcAddress::Encode(p, "ZBC");
    if (type == TU::ACCOUNT_TYPE_DATASET && p.size() == 32) return zoobc::crypto::ZoobcAddress::Encode(p, "ZBS");
    if (type == TU::ACCOUNT_TYPE_ETH && p.size() == 20) return zoobc::crypto::EthereumSignature::ToChecksumAddress(p);
    return zoobc::crypto::AccountTypeName(type) + " account " + hexs(p);
}

// ---------------------------------------------------------------------------------------------------------------
// Body decoding: the signer reads the body from the bytes, never from the file's text.
// ---------------------------------------------------------------------------------------------------------------
struct Reader {
    const std::vector<uint8_t>& b;
    size_t o = 0;
    explicit Reader(const std::vector<uint8_t>& bytes) : b(bytes) {}
    void need(size_t n) const { if (o + n > b.size()) throw std::runtime_error("body too short"); }
    uint8_t u8() { need(1); return b[o++]; }
    uint16_t u16() { need(2); uint16_t v = (uint16_t)(b[o] | (b[o + 1] << 8)); o += 2; return v; }
    uint32_t u32() { need(4); uint32_t v = 0; for (int i = 3; i >= 0; --i) v = (v << 8) | b[o + i]; o += 4; return v; }
    uint64_t u64() { need(8); uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | b[o + i]; o += 8; return v; }
    int64_t i64() { return static_cast<int64_t>(u64()); }
    std::vector<uint8_t> bytes(size_t n) { need(n); std::vector<uint8_t> v(b.begin() + o, b.begin() + o + n); o += n; return v; }
    std::string str(size_t n) { auto v = bytes(n); return std::string(v.begin(), v.end()); }
    std::vector<uint8_t> typed() {   // a typed account: 4-byte type, then that type's key length
        need(4);
        const int32_t t = (int32_t)((uint32_t)b[o] | ((uint32_t)b[o + 1] << 8) | ((uint32_t)b[o + 2] << 16) | ((uint32_t)b[o + 3] << 24));
        return bytes(4 + TU::GetAccountPublicKeyLength(t));
    }
    bool done() const { return o == b.size(); }
};

inline void text_field(json& out, const std::string& name, const std::string& v) {
    if (printable(v)) out[name] = v;
    else { out[name + "_bytes"] = std::to_string(v.size()); out[name + "_sha256"] = sha256_hex(v); }
}
inline void optional_survival(Reader& r, json& out, bool flag_byte) {
    if (r.done()) return;
    if (flag_byte) r.u8();
    out["survival"] = zbc_amount(r.i64());
}
inline std::string order_flags(uint8_t f) {
    std::string s = (f & 1) ? "market" : "limit";
    if (f & 2) s += ", post-only";
    if (f & ~3) s += ", other flags " + std::to_string(f & ~3);
    return s;
}
inline std::string unix_or(int64_t t, const char* zero) { return t == 0 ? std::string(zero) : utc(t); }

inline json decode_body(uint32_t type, const std::vector<uint8_t>& body) {
    json out = json::object();
    Reader r(body);
    try {
        switch (type) {
        case 1: out["amount"] = zbc_amount(r.i64()); break;
        case 3: case 259: {
            out["property"] = r.str(r.u32());
            text_field(out, "value", r.str(r.u32()));
            break; }
        case 10: {
            const uint8_t dec = r.u8(), fl = r.u8(); const int64_t sup = r.i64(), bk = r.i64();
            out["decimals"] = std::to_string(dec); out["flags"] = std::to_string(fl);
            out["supply_atomic"] = std::to_string(sup); out["backing"] = zbc_amount(bk);
            text_field(out, "symbol", r.str(r.u16())); text_field(out, "name", r.str(r.u16()));
            optional_survival(r, out, false);
            break; }
        case 11: case 12: case 13:
            out["token_id"] = token(r.i64()); out["amount_atomic"] = std::to_string(r.i64());
            optional_survival(r, out, true);
            break;
        case 14:
            out["token_id"] = token(r.i64());
            if (!r.done()) out["amount"] = zbc_amount(r.i64());
            break;
        case 18: {
            out["give_token"] = token(r.i64()); out["give_amount_atomic"] = std::to_string(r.i64());
            out["want_token"] = token(r.i64()); out["want_amount_atomic"] = std::to_string(r.i64());
            out["expiry"] = unix_or(r.i64(), "none");
            if (!r.done()) { const uint32_t n = r.u32(); out["counterparty"] = account(r.bytes(n)); }
            else out["counterparty"] = "anyone (open offer)";
            break; }
        case 19: case 20: out["offer_id"] = std::to_string(r.i64()); break;
        case 21:
            out["base_token"] = token(r.i64()); out["quote_token"] = token(r.i64());
            out["deposit_atomic"] = std::to_string(r.i64());
            break;
        case 22: {
            out["market_id"] = std::to_string(r.i64());
            const uint8_t side = r.u8();
            out["side"] = side == 0 ? "buy" : side == 1 ? "sell" : "unknown (" + std::to_string(side) + ")";
            out["price"] = decimal8(r.i64());
            out["amount_atomic"] = std::to_string(r.i64());
            out["flags"] = order_flags(r.u8());
            out["expiry"] = unix_or(r.i64(), "good till cancelled");
            break; }
        case 23: out["order_id"] = std::to_string(r.i64()); break;
        case 32:
            text_field(out, "release_version", r.str(r.u32()));
            out["manifest_hash"] = hexs(r.bytes(32));
            out["release_address"] = account(r.typed());
            break;
        case 33: out["new_authority"] = account(r.typed()); break;
        case 34: break;
        case 35: text_field(out, "release_version", r.str(r.u32())); break;
        case 36:
            out["gateway_key"] = hexs(r.bytes(32));
            text_field(out, "domain", r.str(r.u32())); text_field(out, "url", r.str(r.u32()));
            break;
        case 38: out["gateway_key"] = hexs(r.bytes(32)); break;
        case 257: {
            auto p = zoobc::transaction::batch::ParsePayments(body);
            if (p.IsErr()) throw std::runtime_error(p.GetError().ToString());
            json list = json::array(); int64_t total = 0;
            for (const auto& x : p.Value()) { list.push_back({{"recipient", account(x.recipient)}, {"amount", zbc_amount(x.amount)}}); total += x.amount; }
            out["payments"] = list; out["total"] = zbc_amount(total);
            return out; }
        case 267: {
            auto p = zoobc::transaction::batch::ParseTokenTransfers(body);
            if (p.IsErr()) throw std::runtime_error(p.GetError().ToString());
            json list = json::array();
            for (const auto& x : p.Value())
                list.push_back({{"token_id", token(x.token_id)}, {"recipient", account(x.recipient)}, {"amount_atomic", std::to_string(x.amount)}});
            out["transfers"] = list;
            return out; }
        default:
            return json{{"not_decoded", "this signer does not decode type " + std::to_string(type) + ": check the body another way"},
                        {"body_bytes", std::to_string(body.size())}, {"body_hex", hexs(body)}};
        }
    } catch (const std::exception& e) {
        return json{{"not_decoded", std::string("the body does not read as this type: ") + e.what()},
                    {"body_bytes", std::to_string(body.size())}, {"body_hex", hexs(body)}};
    }
    if (!r.done()) out["trailing_bytes_hex"] = hexs(std::vector<uint8_t>(body.begin() + r.o, body.end()));
    return out;
}

// The window a block may carry the transaction in after its timestamp: its stated expiry (version 3), else the
// hour (TransactionUtil::ExpiryWindow).
inline int64_t expiry_window(const zoobc::model::Transaction& tx) {
    return (tx.version >= 3 && tx.expiry > 0) ? static_cast<int64_t>(tx.expiry) : 3600;
}

// What a person must see before signing, computed from the bytes alone.
inline json summarize(const zoobc::model::Transaction& tx) {
    const uint32_t type = static_cast<uint32_t>(tx.transaction_type);
    json s = {
        {"transaction", type_name(type)},
        {"sender", account(tx.sender_account_address)},
        {"recipient", account(tx.recipient_account_address)},
        {"fee", zbc_amount(tx.fee)},
        {"timestamp", utc(tx.timestamp)},
        {"valid_until", utc(tx.timestamp + expiry_window(tx))},
        {"body", decode_body(type, tx.transaction_body_bytes)},
    };
    if (tx.survival != 0) s["survival"] = zbc_amount(tx.survival);
    if (tx.escrow) {
        const auto& e = *tx.escrow;
        json ej = {{"approver", account(e.approver_address)}, {"commission", zbc_amount(e.commission)}, {"timeout", utc(e.timeout)}};
        if (!e.instruction.empty()) text_field(ej, "instruction", e.instruction);
        if (e.multi_party) ej["escrow_request_id"] = std::to_string(e.escrow_request_id);
        s["escrow"] = ej;
    }
    if (!tx.message.empty()) {
        const std::string m(tx.message.begin(), tx.message.end());
        if (printable(m)) s["message"] = m; else s["message_hex"] = hexs(tx.message);
    }
    return s;
}

// The unsigned bytes as a transaction: they must read as one, and serialise back to exactly themselves (no
// trailing bytes, nothing the parser skipped), or what the signer shows is not what it would sign.
inline zoobc::model::Transaction parse_exact(const std::vector<uint8_t>& bytes) {
    auto p = TU::ParseTransactionBytes(bytes, false);
    if (p.IsErr()) refuse(exit_code::VERIFY_FAILED, "the bytes are not a transaction: " + p.GetError().ToString());
    auto back = TU::GetTransactionBytes(p.Value(), false);
    if (back.IsErr() || back.Value() != bytes)
        refuse(exit_code::VERIFY_FAILED, "the bytes are not exactly one transaction (extra or unreadable bytes)");
    return p.Value();
}

// The JSON body POST /api/v1/transactions takes: what build_json_payload writes for the same transaction.
inline json payload_of(const zoobc::model::Transaction& tx, const std::vector<uint8_t>& signature) {
    json p = {
        {"version", tx.version},
        {"timestamp", tx.timestamp},
        {"sender_account_address", hexs(tx.sender_account_address)},
        {"recipient_account_address", hexs(tx.recipient_account_address)},
        {"transaction_type", static_cast<uint32_t>(tx.transaction_type)},
        {"fee", tx.fee},
        {"transaction_body_bytes", hexs(tx.transaction_body_bytes)},
        {"signature", hexs(signature)},
    };
    if (!tx.message.empty()) p["message_hex"] = hexs(tx.message);
    if (tx.escrow) {
        const auto& e = *tx.escrow;
        json ej = {{"approver_address", hexs(e.approver_address)}, {"commission", e.commission}, {"timeout", e.timeout}};
        if (!e.instruction.empty()) ej["instruction"] = e.instruction;
        if (e.multi_party) { ej["multi_party"] = true; ej["escrow_request_id"] = std::to_string(e.escrow_request_id); }
        p["escrow"] = ej;
    }
    if (tx.version >= 2) p["survival"] = tx.survival;
    if (tx.version >= 3) p["expiry"] = tx.expiry;
    return p;
}

inline std::vector<uint8_t> digest_for(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& genesis) {
    auto d = TU::SigningDigest(bytes, genesis);
    if (d.IsErr()) refuse(exit_code::INTERNAL, "digest: " + d.GetError().ToString());
    return d.Value();
}

// ---------------------------------------------------------------------------------------------------------------
// --unsigned: the UNSIGNED file (run_transaction hands the bytes here instead of signing them)
// ---------------------------------------------------------------------------------------------------------------
inline std::string default_note() {
    return "Air-gap signing: carry this file to the offline computer and run `zbc-cli sign-tx <this file>`; "
           "bring the SIGNED file back and run `zbc-cli submit <signed file> --wait`.";
}

inline int emit_unsigned(const ParsedParams& params, const std::vector<uint8_t>& tx_bytes,
                         const std::function<void(const std::string&)>& emit_error) {
    try {
        const auto& ctx = signing_context();
        if (ctx.version != 2 || ctx.genesis_hash.size() != 32)
            return fail(emit_error, exit_code::USAGE,
                        "--unsigned signs for one chain (signing v2): give --genesis <64 hex>, or --api a node of that chain");
        const auto tx = parse_exact(tx_bytes);
        if (tx.sender_account_address.size() != 36 || tx.sender_account_address[0] || tx.sender_account_address[1] ||
            tx.sender_account_address[2] || tx.sender_account_address[3])
            return fail(emit_error, exit_code::USAGE, "--unsigned: the sender must be a ZBC_ account (an Ed25519 key signs it)");
        json doc = {
            {"format", UNSIGNED_FORMAT},
            {"chain_genesis", hexs(ctx.genesis_hash)},
            {"signing_version", 2},
            {"tx_type", static_cast<uint32_t>(tx.transaction_type)},
            {"command", params.unsigned_command},
            {"sender_account_address", hexs(tx.sender_account_address)},
            {"unsigned_tx_hex", hexs(tx_bytes)},
            {"digest", hexs(digest_for(tx_bytes, ctx.genesis_hash))},
            {"summary", summarize(tx)},
            {"created", utc_iso(static_cast<int64_t>(std::time(nullptr)))},
            {"note", params.unsigned_note.empty() ? default_note() : params.unsigned_note},
        };
        std::cout << doc.dump(2) << std::endl;
        return exit_code::OK;
    } catch (const Refusal& r) {
        return fail(emit_error, r.code, r.what());
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Files: one, several, or every *.json of a folder (not recursive), in name order.
// ---------------------------------------------------------------------------------------------------------------
struct Loaded {
    std::string path;
    json doc;
};
inline std::vector<Loaded> load_files(const std::vector<std::string>& args, const std::string& want_format, bool& from_folder) {
    namespace fs = std::filesystem;
    std::vector<Loaded> out;
    from_folder = false;
    for (const auto& a : args) {
        std::error_code ec;
        std::vector<std::string> paths;
        const bool folder = fs::is_directory(a, ec);
        if (folder) {
            from_folder = true;
            for (const auto& e : fs::directory_iterator(a, ec))
                if (e.is_regular_file() && e.path().extension() == ".json") paths.push_back(e.path().string());
            std::sort(paths.begin(), paths.end());
        } else if (fs::is_regular_file(a, ec)) {
            paths.push_back(a);
        } else {
            refuse(exit_code::USAGE, "no such file or folder: " + a);
        }
        for (const auto& p : paths) {
            std::ifstream f(p);
            std::stringstream ss; ss << f.rdbuf();
            json d = json::parse(ss.str(), nullptr, false);
            const std::string fmt = (d.is_object() && d.contains("format") && d["format"].is_string()) ? d["format"].get<std::string>() : "";
            if (fmt == want_format) { out.push_back({p, d}); continue; }
            if (folder) continue;   // a folder holds other files too (drafts, the other kind): skip them
            if (fmt == UNSIGNED_FORMAT) refuse(exit_code::USAGE, p + " is UNSIGNED: sign it on the offline computer first (zbc-cli sign-tx)");
            if (fmt == SIGNED_FORMAT) refuse(exit_code::USAGE, p + " is already SIGNED: send it with zbc-cli submit");
            refuse(exit_code::USAGE, p + " is not a " + want_format + " file");
        }
    }
    if (args.size() > 1) from_folder = true;
    return out;
}
inline std::string str_field(const json& d, const char* k, const std::string& file) {
    if (!d.contains(k) || !d[k].is_string()) refuse(exit_code::USAGE, file + ": no \"" + k + "\" field");
    return d[k].get<std::string>();
}
inline std::vector<uint8_t> hex_field(const json& d, const char* k, const std::string& file, size_t len = 0) {
    std::string s = lower(str_field(d, k, file));
    if (!is_hex(s)) refuse(exit_code::VERIFY_FAILED, file + ": \"" + k + "\" is not hex");
    auto b = hex_to_bytes(s);
    if (len && b.size() != len) refuse(exit_code::VERIFY_FAILED, file + ": \"" + k + "\" must be " + std::to_string(len) + " bytes");
    return b;
}

// Everything a file claims, checked against its bytes. Returns the transaction the bytes are.
struct Checked {
    std::string path;
    json doc;
    std::vector<uint8_t> bytes, genesis;
    zoobc::model::Transaction tx;
    json summary;
};
inline Checked check_unsigned(const Loaded& l, const std::string& expect_genesis) {
    Checked c; c.path = l.path; c.doc = l.doc;
    const json& d = l.doc;
    if (!d.contains("signing_version") || !d["signing_version"].is_number_integer() || d["signing_version"].get<int>() != 2)
        refuse(exit_code::VERIFY_FAILED, l.path + ": signing_version is not 2; this signer signs chain-bound transactions only");
    c.genesis = hex_field(d, "chain_genesis", l.path, 32);
    if (!expect_genesis.empty() && lower(expect_genesis) != hexs(c.genesis))
        refuse(exit_code::VERIFY_FAILED, l.path + ": the file is for chain " + hexs(c.genesis) + ", not the chain you named (" +
                                         lower(expect_genesis) + "); not signing");
    c.bytes = hex_field(d, "unsigned_tx_hex", l.path);
    try { c.tx = parse_exact(c.bytes); }
    catch (const Refusal& r) { refuse(r.code, l.path + ": " + r.what()); }
    if (!d.contains("tx_type") || !d["tx_type"].is_number_integer() || d["tx_type"].get<uint32_t>() != static_cast<uint32_t>(c.tx.transaction_type))
        refuse(exit_code::VERIFY_FAILED, l.path + ": tx_type does not match the bytes (they are " + type_name(static_cast<uint32_t>(c.tx.transaction_type)) + ")");
    if (lower(str_field(d, "sender_account_address", l.path)) != hexs(c.tx.sender_account_address))
        refuse(exit_code::VERIFY_FAILED, l.path + ": sender_account_address does not match the bytes");
    if (hex_field(d, "digest", l.path, 32) != digest_for(c.bytes, c.genesis))
        refuse(exit_code::VERIFY_FAILED, l.path + ": the digest does not match the bytes and the chain (tampered file?); not signing");
    c.summary = summarize(c.tx);
    if (!d.contains("summary") || d["summary"] != c.summary)
        refuse(exit_code::VERIFY_FAILED, l.path + ": the summary in the file does not match what the bytes say (tampered file?); not signing.\n"
                                         "  the bytes say: " + c.summary.dump());
    return c;
}

// The wallet update notice (zbc-anchor --announce-wallet): a SetupAccountDataset of wallet.release whose value
// is {"version","url","sha256","published","sig":""}. The empty sig is the signer's to fill: Ed25519 by this
// same key over "ZBC-UPDATE-NOTICE-v1|<version>|<sha256>|<url>|<published>" (scripts/mac/zbc-anchor).
struct Notice { bool present = false; std::string value, canon; };
inline Notice wallet_notice(const zoobc::model::Transaction& tx) {
    Notice n;
    if (static_cast<uint32_t>(tx.transaction_type) != 3) return n;
    auto body = TU::ParseSetupAccountDatasetBodyBytes(tx.transaction_body_bytes);
    if (body.IsErr() || body.Value().property != WALLET_NOTICE_PROPERTY) return n;
    json v = json::parse(body.Value().value, nullptr, false);
    if (!v.is_object() || !v.contains("sig") || v["sig"] != "") return n;
    if (!v.contains("published") || !v["published"].is_number_integer()) return n;
    const std::string& val = body.Value().value;
    const std::string hole = "\"sig\":\"\"";
    if (val.find(hole) == std::string::npos || val.find(hole) != val.rfind(hole)) return n;
    n.present = true;
    n.value = val;
    n.canon = std::string(WALLET_NOTICE_TAG) + "|" + v.value("version", "") + "|" + lower(v.value("sha256", "")) + "|" +
              v.value("url", "") + "|" + v["published"].dump();
    return n;
}
inline std::vector<uint8_t> fill_wallet_notice(zoobc::model::Transaction tx, const Notice& n, const zoobc::crypto::KeyPair& kp) {
    auto sig = Signature::Sign(std::vector<uint8_t>(n.canon.begin(), n.canon.end()), kp.private_key);
    if (sig.IsErr()) refuse(exit_code::INTERNAL, "cannot sign the wallet notice: " + sig.GetError().ToString());
    std::string value = n.value;
    const std::string hole = "\"sig\":\"\"";
    value.replace(value.find(hole), hole.size(), "\"sig\":\"" + hexs(sig.Value()) + "\"");
    tx.transaction_body_bytes = TU::GetSetupAccountDatasetBodyBytes(WALLET_NOTICE_PROPERTY, value);
    tx.transaction_body_length = static_cast<uint32_t>(tx.transaction_body_bytes.size());
    auto b = TU::GetTransactionBytes(tx, false);
    if (b.IsErr()) refuse(exit_code::INTERNAL, "cannot rebuild the notice transaction: " + b.GetError().ToString());
    return b.Value();
}

// ---------------------------------------------------------------------------------------------------------------
// The key and the answer: never in argv. ZBC_KEY, else typed without echo at a terminal, else the first line of
// stdin (a script pipes "<key>\ny\n"); the answer is the next line.
// ---------------------------------------------------------------------------------------------------------------
inline std::string read_line_stdin() { std::string s; if (!std::getline(std::cin, s)) return ""; if (!s.empty() && s.back() == '\r') s.pop_back(); return s; }
inline std::string read_key(const std::string& prompt) {
    if (const char* k = std::getenv("ZBC_KEY"); k && *k) return k;
    std::string s;
#ifndef _WIN32
    if (is_stdin_terminal()) {
        std::cerr << prompt << std::flush;
        termios old{}; tcgetattr(STDIN_FILENO, &old);
        termios quiet = old; quiet.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
        s = read_line_stdin();
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        std::cerr << std::endl;
        return s;
    }
#endif
    std::cerr << prompt << "(read from stdin)" << std::endl;
    return read_line_stdin();
}
inline zoobc::crypto::KeyPair key_pair(std::string k) {
    k.erase(0, k.find_first_not_of(" \t"));
    k.erase(k.find_last_not_of(" \t\r\n") + 1);
    if (k.rfind("0x", 0) == 0) k = k.substr(2);
    if (k.size() != 64 || !is_hex(k)) refuse(exit_code::USAGE, "the key must be 64 hex characters (a 32-byte seed); nothing was signed");
    auto kp = derive_zbc_keypair(k);
    if (kp.IsErr()) refuse(exit_code::USAGE, kp.GetError().ToString());
    return kp.Value();
}

inline void print_summary(std::ostream& o, const json& s, const std::string& indent) {
    auto line = [&](const std::string& k, const std::string& v) {
        o << indent << k << std::string(k.size() < 18 ? 18 - k.size() : 1, ' ') << v << "\n";
    };
    const char* order[] = {"transaction", "sender", "recipient", "fee", "survival", "timestamp", "valid_until", "message", "message_hex"};
    for (const char* k : order)
        if (s.contains(k)) line(k, s[k].is_string() ? s[k].get<std::string>() : s[k].dump());
    if (s.contains("escrow")) for (auto& [k, v] : s["escrow"].items()) line("escrow " + k, v.is_string() ? v.get<std::string>() : v.dump());
    if (s.contains("body")) for (auto& [k, v] : s["body"].items()) {
        if (v.is_array()) { line(k, std::to_string(v.size()) + " item(s)"); for (const auto& e : v) o << indent << "  - " << e.dump() << "\n"; }
        else line(k, v.is_string() ? v.get<std::string>() : v.dump());
    }
}

inline std::string signed_name(const std::string& path) {
    namespace fs = std::filesystem;
    const fs::path p(path);
    std::string f = p.filename().string();
    f = (f.rfind("UNSIGNED-", 0) == 0) ? "SIGNED-" + f.substr(9) : "SIGNED-" + f;
    return (p.parent_path() / f).string();
}

inline void sign_tx_usage(std::ostream& o) {
    o << "zbc-cli sign-tx <UNSIGNED file|folder>... [--yes] [--genesis <64 hex>]\n"
         "  Air-gap signing, on the OFFLINE computer. Reads UNSIGNED files (zbc-unsigned-v1, written by\n"
         "  `zbc-cli <command> ... --unsigned --from <account>` or zbc-anchor --export-unsigned), decodes each\n"
         "  transaction from its bytes, refuses a file whose summary, digest, chain or sender does not match\n"
         "  them, shows what will be signed, asks \"sign? [y/N]\", and writes the SIGNED file (zbc-signed-v1).\n"
         "  One file: the SIGNED JSON on stdout. Several files or a folder: SIGNED-<name> beside each\n"
         "  (UNSIGNED-x.json -> SIGNED-x.json); files another key must sign are left alone.\n"
         "  The key: ZBC_KEY, else typed without echo (never an argument). A script pipes \"<key>\\ny\\n\".\n"
         "  --yes            sign without asking (after reviewing the summary another way)\n"
         "  --genesis <hex>  refuse any file that is not for this chain\n"
         "  Exit codes: 0 signed, 2 usage / not signed, 10 refused (tampered file, wrong key, wrong chain).\n";
}

inline int sign_tx_command(int argc, char** argv) {
    std::vector<std::string> args; bool yes = false; std::string expect_genesis;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--help" || a == "-h") { sign_tx_usage(std::cout); return exit_code::OK; }
        if (a == "--yes" || a == "-y") { yes = true; continue; }
        if (a == "--genesis") {
            if (i + 1 >= argc) { std::cerr << "Error: --genesis requires a value\n"; return exit_code::USAGE; }
            expect_genesis = argv[++i];
            if (!is_hex(expect_genesis) || expect_genesis.size() != 64) { std::cerr << "Error: --genesis must be 64 hex characters\n"; return exit_code::USAGE; }
            continue;
        }
        if (a.size() > 1 && a[0] == '-') { std::cerr << "Error: unknown option " << a << " (the key is never an argument: set ZBC_KEY or type it when asked)\n"; return exit_code::USAGE; }
        args.push_back(a);
    }
    if (args.empty()) { sign_tx_usage(std::cerr); return exit_code::USAGE; }
    try {
        bool many = false;
        auto files = load_files(args, UNSIGNED_FORMAT, many);
        if (files.empty()) refuse(exit_code::USAGE, "no UNSIGNED files (format zbc-unsigned-v1) in " + args[0]);
        std::vector<Checked> txs;
        for (const auto& f : files) txs.push_back(check_unsigned(f, expect_genesis));

        std::ostream& o = std::cerr;
        o << "Air-gap signing: " << txs.size() << " transaction(s)\n";
        for (size_t i = 0; i < txs.size(); ++i) {
            const auto& c = txs[i];
            o << "\n[" << (i + 1) << "] " << std::filesystem::path(c.path).filename().string() << "\n";
            o << "    chain genesis     " << hexs(c.genesis) << "\n";
            print_summary(o, c.summary, "    ");
            if (wallet_notice(c.tx).present)
                o << "    + the wallet update notice in this value is signed too, by this key: its empty \"sig\" gets\n"
                     "      Ed25519 over \"" << wallet_notice(c.tx).canon << "\"\n";
            if (c.doc.contains("note") && c.doc["note"].is_string() && !c.doc["note"].get<std::string>().empty())
                o << "    note (from the online machine, NOT checked): " << c.doc["note"].get<std::string>() << "\n";
            const int64_t now = static_cast<int64_t>(std::time(nullptr));
            if (c.tx.timestamp + expiry_window(c.tx) < now)
                o << "    !! by this computer's clock (" << utc(now) << ") it is already past valid_until: the chain will refuse it\n";
        }
        o << "\n";
        const auto kp = key_pair(read_key("key (64 hex, not shown): "));
        std::vector<uint8_t> me = {0, 0, 0, 0}; me.insert(me.end(), kp.public_key.begin(), kp.public_key.end());
        const std::string me_zbc = zoobc::crypto::ZoobcAddress::Encode(kp.public_key, "ZBC");
        std::vector<const Checked*> mine;
        for (const auto& c : txs) {
            if (c.tx.sender_account_address == me) mine.push_back(&c);
            else o << "  " << std::filesystem::path(c.path).filename().string() << ": not this key's (its sender is "
                   << account(c.tx.sender_account_address) << "); left alone\n";
        }
        if (mine.empty())
            refuse(exit_code::VERIFY_FAILED, "WRONG KEY: this key is " + me_zbc + ", and no file here is that account's to sign; nothing was signed");
        o << "Signing " << mine.size() << " transaction(s) as " << me_zbc << ". sign? [y/N] " << std::flush;
        if (!yes) {
            std::string ans = lower(read_line_stdin());
            ans.erase(0, ans.find_first_not_of(" \t"));
            ans.erase(ans.find_last_not_of(" \t") + 1);
            if (ans != "y" && ans != "yes") { o << "\nnot signed\n"; return exit_code::USAGE; }
        } else o << "y (--yes)\n";

        json written = json::array();
        for (const auto* c : mine) {
            std::vector<uint8_t> bytes = c->bytes;
            zoobc::model::Transaction tx = c->tx;
            if (auto n = wallet_notice(tx); n.present) { bytes = fill_wallet_notice(tx, n, kp); tx = parse_exact(bytes); }
            const auto digest = digest_for(bytes, c->genesis);
            auto sig = Signature::Sign(digest, kp.private_key);
            if (sig.IsErr()) refuse(exit_code::INTERNAL, "signing failed: " + sig.GetError().ToString());
            std::vector<uint8_t> full(bytes); full.insert(full.end(), sig.Value().begin(), sig.Value().end());
            auto h = zoobc::crypto::Hash::SHA3_256(full);
            json d = c->doc;
            d["format"] = SIGNED_FORMAT;
            d["unsigned_tx_hex"] = hexs(bytes);
            d["digest"] = hexs(digest);
            d["summary"] = summarize(tx);
            d["signature"] = hexs(sig.Value());
            d["transaction_hash"] = h.IsOk() ? hexs(h.Value()) : std::string();
            d["transaction_bytes"] = hexs(full);
            d["payload"] = payload_of(tx, sig.Value());
            d["signed"] = utc_iso(static_cast<int64_t>(std::time(nullptr)));
            if (!many) { std::cout << d.dump(2) << std::endl; o << "signed\n"; return exit_code::OK; }
            const std::string out = signed_name(c->path);
            std::ofstream f(out);
            f << d.dump(2) << "\n";
            if (!f) refuse(exit_code::INTERNAL, "cannot write " + out);
            o << "  signed: " << out << "\n";
            written.push_back(out);
        }
        std::cout << json{{"success", true}, {"signed", written}, {"signer", me_zbc}}.dump(2) << std::endl;
        return exit_code::OK;
    } catch (const Refusal& r) {
        std::cerr << "REFUSED: " << r.what() << std::endl;
        return r.code;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return exit_code::INTERNAL;
    }
}

// ---------------------------------------------------------------------------------------------------------------
// submit: every file checked first (its signature against its bytes, its chain against the node's), then posted
// in name order; the first refusal stops the run.
// ---------------------------------------------------------------------------------------------------------------
inline void submit_usage(std::ostream& o) {
    o << "zbc-cli submit <SIGNED file|folder>... [--api URL] [--wait] [--wait-seconds N] [--timeout S]\n"
         "  Air-gap signing, on the ONLINE machine: sends SIGNED files (zbc-signed-v1, from zbc-cli sign-tx) in\n"
         "  file-name order. Before anything is sent, each signature is checked against its bytes and each file's\n"
         "  chain against the node's. The first refusal stops the run.\n"
         "  --wait            send the next file only once the previous one is in a block (a block carries one\n"
         "                    transaction per account), and print its height\n"
         "  --wait-seconds N  how long to wait for each block (default 180)\n"
         "  --api URL         the node or gateway (default ZBC_API, else http://localhost:8080)\n"
         "  Output: one JSON object on stdout ({\"results\": [...]}), progress on stderr.\n"
         "  Exit codes: 0 sent, 2 usage, 3 node unreachable, 4-7 the node refused (as for every command),\n"
         "  8 not in a block in time, 10 a file that does not verify or is for another chain.\n";
}

struct NodeGet { int status = 0; json body; };
inline NodeGet node_get(const std::string& api, const std::string& path) {
    NodeGet g;
    try {
        const ApiTarget t = parse_api_url(api);
        auto res = with_api_client(t, [&](auto& c) { return c.Get((t.path_prefix + path).c_str()); });
        if (!res) return g;
        g.status = res->status;
        g.body = json::parse(res->body, nullptr, false);
    } catch (...) {}
    return g;
}

inline int submit_command(int argc, char** argv) {
    std::vector<std::string> args; bool wait = false; int wait_seconds = 180;
    std::string api = "http://localhost:8080";
    if (const char* e = std::getenv("ZBC_API"); e && *e) api = e;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        auto value = [&](const char* what) -> std::string {
            if (i + 1 >= argc) throw Refusal(exit_code::USAGE, std::string(what) + " requires a value");
            return argv[++i];
        };
        try {
            if (a == "--help" || a == "-h") { submit_usage(std::cout); return exit_code::OK; }
            else if (a == "--wait") wait = true;
            else if (a == "--api") api = value("--api");
            else if (a == "--wait-seconds") wait_seconds = static_cast<int>(parse_whole_u64(value("--wait-seconds"), "--wait-seconds", 86400));
            else if (a == "--timeout" || a == "--timeout-seconds") http_timeout_seconds() = static_cast<int>(parse_whole_u64(value("--timeout"), "--timeout", 3600));
            else if (a.size() > 1 && a[0] == '-') throw Refusal(exit_code::USAGE, "unknown option " + a);
            else args.push_back(a);
        } catch (const Refusal& r) { std::cerr << "Error: " << r.what() << "\n"; return r.code; }
        catch (const std::exception& e) { std::cerr << "Error: " << e.what() << "\n"; return exit_code::USAGE; }
    }
    if (args.empty()) { submit_usage(std::cerr); return exit_code::USAGE; }
    json results = json::array();
    auto finish = [&](int code, const std::string& err) {
        json out = {{"success", code == exit_code::OK}, {"api", api}, {"results", results}};
        if (code != exit_code::OK) { out["exit_code"] = code; out["error_class"] = exit_code::name(code); out["error"] = err; }
        std::cout << out.dump(2) << std::endl;
        return code;
    };
    struct Ready { std::string path; json payload; std::string hash, label; std::vector<uint8_t> genesis; };
    std::vector<Ready> todo;
    try {
        bool many = false;
        auto files = load_files(args, SIGNED_FORMAT, many);
        if (files.empty()) refuse(exit_code::USAGE, "no SIGNED files (format zbc-signed-v1) in " + args[0]);
        for (const auto& l : files) {
            const json& d = l.doc;
            Ready r; r.path = l.path;
            r.genesis = hex_field(d, "chain_genesis", l.path, 32);
            const auto bytes = hex_field(d, "unsigned_tx_hex", l.path);
            const auto sig = hex_field(d, "signature", l.path, 64);
            zoobc::model::Transaction tx;
            try { tx = parse_exact(bytes); } catch (const Refusal& e) { refuse(e.code, l.path + ": " + e.what()); }
            const auto& s = tx.sender_account_address;
            if (s.size() != 36 || s[0] || s[1] || s[2] || s[3]) refuse(exit_code::VERIFY_FAILED, l.path + ": not a ZBC_ sender; not sent");
            auto v = Signature::Verify(digest_for(bytes, r.genesis), sig, std::vector<uint8_t>(s.begin() + 4, s.end()));
            if (v.IsErr() || !v.Value()) refuse(exit_code::VERIFY_FAILED, l.path + ": the signature does not verify against the bytes; not sent");
            if (!d.contains("payload") || d["payload"] != payload_of(tx, sig))
                refuse(exit_code::VERIFY_FAILED, l.path + ": the payload is not the signed transaction; not sent");
            std::vector<uint8_t> full(bytes); full.insert(full.end(), sig.begin(), sig.end());
            auto h = zoobc::crypto::Hash::SHA3_256(full);
            r.hash = h.IsOk() ? hexs(h.Value()) : "";
            r.payload = d["payload"];
            const json sm = summarize(tx);
            r.label = sm["transaction"].get<std::string>() + " from " + sm["sender"].get<std::string>();
            todo.push_back(r);
        }
        const auto info = node_get(api, "/api/v1/node/info");
        if (info.status != 200 || !info.body.is_object())
            refuse(exit_code::UNREACHABLE, "cannot read " + api + "/api/v1/node/info to learn the node's chain; nothing was sent");
        const std::string node_gen = lower(info.body.value("genesis_hash", std::string()));
        for (const auto& r : todo)
            if (hexs(r.genesis) != node_gen)
                refuse(exit_code::VERIFY_FAILED, r.path + " is for chain " + hexs(r.genesis) + ", the node at " + api +
                                                 " serves " + (node_gen.empty() ? std::string("an unknown chain") : node_gen) + "; nothing was sent");
    } catch (const Refusal& r) {
        std::cerr << "REFUSED: " << r.what() << std::endl;
        return finish(r.code, r.what());
    }

    for (size_t i = 0; i < todo.size(); ++i) {
        const auto& r = todo[i];
        std::cerr << "[" << (i + 1) << "/" << todo.size() << "] " << std::filesystem::path(r.path).filename().string()
                  << ": " << r.label << "\n";
        auto sr = submit_transaction(api, r.payload.dump());
        json row = {{"file", r.path}, {"transaction_hash", r.hash}};
        if (!sr.ok && sr.http_code == 0) {
            const int code = classify_transport_error(sr.transport_error);
            row["status"] = "not sent"; results.push_back(row);
            std::cerr << "  cannot reach " << api << ": " << sr.response_body << "\n";
            return finish(code, "cannot reach " + api + ": " + sr.response_body);
        }
        if (!sr.ok) {
            std::string text = sr.response_body;
            if (sr.response_json.is_object() && sr.response_json.contains("error") && sr.response_json["error"].is_string())
                text = sr.response_json["error"].get<std::string>();
            const int code = classify_node_error(sr.http_code, text);
            row["status"] = "refused"; row["http_code"] = sr.http_code; row["error"] = text; results.push_back(row);
            std::cerr << "  REFUSED by the node (HTTP " << sr.http_code << "): " << text << "\n  nothing after it was sent\n";
            return finish(code, text);
        }
        row["status"] = "accepted";
        std::cerr << "  accepted: " << r.hash << "\n";
        if (wait) {
            bool in_block = false; int64_t height = -1; std::string why;
            const auto start = std::time(nullptr);
            while (std::time(nullptr) - start < wait_seconds) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                auto g = node_get(api, "/api/v1/transactions/" + r.hash + "/status");
                if (!g.body.is_object()) continue;
                const std::string st = g.body.value("status", std::string());
                if (st == "confirmed") { in_block = true; height = g.body.value("block_height", int64_t{-1}); break; }
                if (st == "rejected") { why = g.body.value("reason", g.body.value("description", std::string("rejected"))); break; }
            }
            row["in_block"] = in_block;
            if (in_block) { row["block_height"] = height; std::cerr << "  in block " << height << "\n"; }
            results.push_back(row);
            if (!in_block) {
                const std::string err = why.empty() ? "not in a block after " + std::to_string(wait_seconds) + " s; nothing after it was sent"
                                                    : "the node dropped it: " + why + "; nothing after it was sent";
                std::cerr << "  " << err << "\n";
                return finish(why.empty() ? exit_code::TIMEOUT : exit_code::REJECTED, err);
            }
        } else {
            results.push_back(row);
        }
    }
    return finish(exit_code::OK, "");
}

}  // namespace airgap

#endif  // ZOOBC_TOOLS_AIRGAP_H
