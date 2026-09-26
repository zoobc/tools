// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// zbc-multisig-offline: N-of-M multisig with every participant signing on their own machine.
//
// zbc-multisig takes every participant's private key in one process, which only works when one
// person holds all the keys. This tool splits the same MultiSignature (type 5) transaction into
// steps that each run where the key lives, and only the last step touches the network:
//
//   address  (participant, offline)  print the participant address a key signs as
//   prepare  (anyone)                build a signing package: participants, threshold, nonce, the
//                                    unsigned inner transaction, the chain it binds to, and the
//                                    exact digest to sign. Online only to read the genesis hash
//                                    (--api); fully offline with --genesis-hash.
//   sign     (participant, offline)  check the package, show what it pays and to whom, sign the
//                                    digest with this participant's key, write a signature file.
//   combine  (anyone, offline)       verify every signature file, refuse duplicates, strangers,
//                                    wrong digests and too few signatures, then build the type-5
//                                    transaction and sign its outer envelope with the submitter
//                                    key (the submitter pays the outer fee).
//   submit   (anyone, online)        check the node serves the package's chain, then post.
//
// What the chain checks (src/transaction/transaction_executor.cpp ExecuteMultiSignature and
// MultisignatureService::CheckMultisigComplete): the outer transaction is an ordinary transaction
// signed by its sender, who pays the outer fee. Its body carries the participants + threshold +
// nonce (the multisig address is re-derived from them, never taken from the caller), the unsigned
// inner transaction, and a map participant -> signature. A signature counts only when the signer is
// a listed participant AND it verifies against SHA3-256("ZBC-TX" ‖ genesis ‖ inner bytes). With
// the threshold met the inner transaction executes in the same block, from the multisig account.
// Nothing requires the participants to be online together or to sign in the same transaction.
//
// File formats: see docs/MULTISIG_OFFLINE.md.

#include "tx_common.h"
#include "zoobc/transaction/multisignature_service.h"
#include "zoobc/crypto/hash.h"
#include "zoobc/crypto/signature.h"
#include <fstream>
#include <map>
#include <set>

using namespace txc;

namespace {

constexpr const char* PACKAGE_FORMAT = "zbc-multisig-package-v1";
constexpr const char* SIGNATURE_FORMAT = "zbc-multisig-signature-v1";
constexpr const char* SIGNED_FORMAT = "zbc-multisig-transaction-v1";
constexpr int64_t ATOMIC_PER_ZBC = 100000000;
constexpr int64_t DEFAULT_INNER_FEE = 10000000;   // 0.1 ZBC offered; honest-fee refunds the excess

using TU = zoobc::util::TransactionUtil;
using MS = zoobc::transaction::MultisignatureService;

// Inner transaction types ExecuteMultiSignature executes once the threshold is met. Any other type
// fails the inner execution, the block producer drops the whole type-5 transaction, and nothing
// happens: refuse it here instead of letting participants sign something that cannot run.
const std::map<uint32_t, std::string>& supported_inner_types() {
    static const std::map<uint32_t, std::string> m = {
        {static_cast<uint32_t>(zoobc::TransactionType::SendZBC), "SendZBC"},
        {static_cast<uint32_t>(zoobc::TransactionType::NodeRegistration), "NodeRegistration"},
        {static_cast<uint32_t>(zoobc::TransactionType::NodeRegistrationUpdate), "NodeRegistrationUpdate"},
        {static_cast<uint32_t>(zoobc::TransactionType::RemoveNodeRegistration), "RemoveNodeRegistration"},
        {static_cast<uint32_t>(zoobc::TransactionType::ClaimNodeRegistration), "ClaimNodeRegistration"},
    };
    return m;
}

std::string supported_types_text() {
    std::string s;
    for (const auto& [t, n] : supported_inner_types()) s += (s.empty() ? "" : ", ") + n + " (" + std::to_string(t) + ")";
    return s;
}

// A refusal: carries the exit code the tool leaves with.
struct Refusal : std::runtime_error {
    int code;
    Refusal(int c, const std::string& m) : std::runtime_error(m), code(c) {}
};
[[noreturn]] void refuse(int code, const std::string& msg) { throw Refusal(code, msg); }

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}
bool is_hex(const std::string& s) {
    if (s.size() % 2) return false;
    for (char c : s) if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    return true;
}
std::vector<uint8_t> strict_hex(const std::string& in, const std::string& what, size_t want_len = 0) {
    std::string s = in;
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) s = s.substr(2);
    if (!is_hex(s)) refuse(exit_code::USAGE, what + " must be hex");
    auto b = hex_to_bytes(s);
    if (want_len && b.size() != want_len)
        refuse(exit_code::USAGE, what + " must be " + std::to_string(want_len) + " bytes (" +
                                     std::to_string(want_len * 2) + " hex characters)");
    return b;
}
int64_t parse_i64(const std::string& s, const std::string& what, int64_t min_value) {
    size_t used = 0;
    int64_t v = 0;
    try { v = std::stoll(s, &used); } catch (...) { used = 0; }
    if (s.empty() || used != s.size()) refuse(exit_code::USAGE, what + " must be a whole number, got '" + s + "'");
    if (v < min_value) refuse(exit_code::USAGE, what + " must be >= " + std::to_string(min_value));
    return v;
}
std::string zbc_amount(int64_t atomic) {
    std::ostringstream o;
    o << (atomic < 0 ? "-" : "") << std::llabs(atomic) / ATOMIC_PER_ZBC << "."
      << std::setw(8) << std::setfill('0') << std::llabs(atomic) % ATOMIC_PER_ZBC << " ZBC";
    return o.str();
}
uint32_t read_u32le(const std::vector<uint8_t>& b) {
    return b.size() < 4 ? 0 : (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

json read_json_file(const std::string& path, const std::string& what) {
    std::ifstream f(path);
    if (!f) refuse(exit_code::USAGE, "cannot read " + what + " file: " + path);
    std::stringstream ss;
    ss << f.rdbuf();
    auto j = json::parse(ss.str(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) refuse(exit_code::USAGE, what + " file is not a JSON object: " + path);
    return j;
}
void write_json_file(const std::string& path, const json& j) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) refuse(exit_code::USAGE, "cannot write " + path);
    f << j.dump(2) << "\n";
    if (!f) refuse(exit_code::INTERNAL, "failed writing " + path);
}
std::string jstr(const json& j, const char* key, const std::string& what) {
    if (!j.contains(key) || !j.at(key).is_string()) refuse(exit_code::USAGE, what + ": field '" + key + "' missing");
    return j.at(key).get<std::string>();
}
int64_t jint(const json& j, const char* key, const std::string& what) {
    if (!j.contains(key) || !j.at(key).is_number_integer()) refuse(exit_code::USAGE, what + ": field '" + key + "' missing");
    return j.at(key).get<int64_t>();
}

// ---------------------------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------------------------

struct Args {
    std::string command;
    std::vector<std::string> positional;
    std::map<std::string, std::vector<std::string>> opts;
    bool json_output = true;
    bool yes = false;
    bool help = false;

    bool has(const std::string& k) const { return opts.count(k) && !opts.at(k).empty(); }
    std::string get(const std::string& k, const std::string& def = "") const { return has(k) ? opts.at(k).back() : def; }
    std::vector<std::string> all(const std::string& k) const { return has(k) ? opts.at(k) : std::vector<std::string>{}; }
};

const std::set<std::string>& value_options() {
    static const std::set<std::string> s = {
        "--participants", "--participant", "--threshold", "--nonce", "--to", "--amount", "--type",
        "--body-hex", "--recipient", "--inner-fee", "--message", "--timestamp", "--genesis-hash",
        "--genesis", "--api", "--out", "--key-file", "--key", "--key-type", "--submitter-key-file",
        "--submitter-key", "--fee", "--timeout", "--timeout-seconds"};
    return s;
}

Args parse_args(int argc, char* argv[]) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "--json") { a.json_output = true; continue; }
        if (s == "-v" || s == "--verbose") { a.json_output = false; continue; }
        if (s == "--yes" || s == "-y") { a.yes = true; continue; }
        if (s == "--help" || s == "-h") { a.help = true; continue; }
        std::string key = s, val;
        bool inline_val = false;
        if (s.rfind("--", 0) == 0) {
            if (auto eq = s.find('='); eq != std::string::npos) { key = s.substr(0, eq); val = s.substr(eq + 1); inline_val = true; }
            if (!value_options().count(key)) refuse(exit_code::USAGE, "Unknown option: " + key);
            if (!inline_val) {
                if (i + 1 >= argc) refuse(exit_code::USAGE, key + " requires a value");
                val = argv[++i];
            }
            if (key == "--genesis") key = "--genesis-hash";
            if (key == "--timeout-seconds") key = "--timeout";
            a.opts[key].push_back(val);
            continue;
        }
        if (a.command.empty()) a.command = s; else a.positional.push_back(s);
    }
    return a;
}

void print_usage() {
    std::cout <<
R"(zbc-multisig-offline: N-of-M ZooBC multisig where each participant signs on their own machine

Usage:
  zbc-multisig-offline address  [--key-file F] [--key-type zbc|eth|btc]
  zbc-multisig-offline prepare  --participants A,B,C --threshold N [--nonce N]
                                (--to ADDR --amount ATOMIC | --type N --body-hex HEX [--recipient ADDR])
                                [--inner-fee ATOMIC] [--message TEXT] [--timestamp S]
                                (--genesis-hash HEX | --api URL) --out PACKAGE.json
  zbc-multisig-offline sign     PACKAGE.json [--key-file F] [--key-type zbc|eth|btc]
                                [--genesis-hash HEX] [--yes] --out SIGNATURE.json
  zbc-multisig-offline combine  PACKAGE.json SIGNATURE.json... [--submitter-key-file F]
                                [--fee ATOMIC] [--timestamp S] --out SIGNED.json
  zbc-multisig-offline submit   SIGNED.json [--api URL]

Network: only `submit` (always) and `prepare --api` (to read the genesis hash) connect to a node.
address, sign and combine never open a connection.

Keys (64-hex secret seed; never pass one on the command line on a shared machine):
  --key-file F            file holding the seed (or a JSON object with "private_key"/"seed")
  ZBC_KEY                 the seed, when no --key-file / --key is given
  --key HEX               the seed in argv (visible in `ps`; tests only)
  --key-type T            zbc (ed25519, default), eth (secp256k1, 0x address), btc (secp256k1,
                          P2PKH 1... / P2WPKH bc1q... address)
  combine: --submitter-key-file / --submitter-key / ZBC_KEY = the ZBC account that signs the
           outer transaction and pays its fee (--fee, default 5000000 = 0.05 ZBC).

Options:
  --genesis-hash HEX      the chain to bind to (prepare: instead of asking --api; sign: refuse a
                          package for any other chain)
  --api URL               node API (default: $ZBC_API, else http://localhost:8080)
  --timeout S             HTTP bound in seconds (default: $ZBC_TIMEOUT, else 20)
  --yes                   sign without the interactive confirmation (required when stdin is not a
                          terminal)
  --json / -v             JSON result on stdout (default) / human-readable output

Exit codes: 0 ok, 1 internal, 2 usage, 3 node unreachable, 6 node rejected, 8 timeout, 9 node busy,
10 refused (bad/duplicate/foreign signature, not a participant, below threshold, wrong chain,
tampered package).
)";
}

// ---------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------

enum class KeyKind { ZBC, ETH, BTC };

struct Key {
    KeyKind kind = KeyKind::ZBC;
    std::vector<uint8_t> seed;        // 32 bytes
    std::vector<uint8_t> ed_secret;   // ed25519 64-byte secret (ZBC)
    std::vector<uint8_t> pubkey;      // ed25519 32 / secp256k1 64 uncompressed (ETH) / 33 compressed (BTC)
    std::vector<uint8_t> account;     // the account address the key signs as (type prefix + payload)
    std::vector<std::vector<uint8_t>> alt_accounts;  // other account forms the same key controls
    std::string display;
    std::string kind_label;
};

KeyKind parse_key_kind(const std::string& s) {
    auto t = lower(s);
    if (t.empty() || t == "zbc" || t == "ed25519") return KeyKind::ZBC;
    if (t == "eth" || t == "ethereum") return KeyKind::ETH;
    if (t == "btc" || t == "bitcoin") return KeyKind::BTC;
    refuse(exit_code::USAGE, "--key-type must be zbc, eth or btc");
}

std::vector<uint8_t> with_type(int32_t type, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out;
    TU::WriteInt32LE(out, type);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::string read_key_material(const Args& a, const std::string& file_opt, const std::string& key_opt,
                              const std::string& who) {
    std::string raw;
    if (a.has(file_opt)) {
        std::ifstream f(a.get(file_opt));
        if (!f) refuse(exit_code::USAGE, "cannot read " + who + " key file: " + a.get(file_opt));
        std::stringstream ss;
        ss << f.rdbuf();
        raw = trim(ss.str());
        if (!raw.empty() && raw[0] == '{') {
            auto j = json::parse(raw, nullptr, false);
            raw.clear();
            if (j.is_object())
                for (const char* k : {"private_key", "privkey", "seed", "secret"})
                    if (j.contains(k) && j[k].is_string()) { raw = j[k].get<std::string>(); break; }
            if (raw.empty()) refuse(exit_code::USAGE, who + " key file is JSON without a private_key/seed field");
        }
    } else if (a.has(key_opt)) {
        raw = a.get(key_opt);
    } else if (const char* env = std::getenv("ZBC_KEY"); env && *env) {
        raw = env;
    } else {
        refuse(exit_code::USAGE, who + " key missing: pass " + file_opt + " <file> or set ZBC_KEY");
    }
    raw = trim(raw);
    if (raw.rfind("0x", 0) == 0) raw = raw.substr(2);
    if (raw.size() != 64 || !is_hex(raw)) refuse(exit_code::USAGE, who + " key must be 64 hex characters (a 32-byte seed)");
    return raw;
}

Key load_key(const std::string& seed_hex, KeyKind kind) {
    Key k;
    k.kind = kind;
    k.seed = hex_to_bytes(seed_hex);
    if (kind == KeyKind::ZBC) {
        auto kp = derive_zbc_keypair(seed_hex);
        if (!kp.IsOk()) refuse(exit_code::USAGE, kp.GetError().ToString());
        k.ed_secret = kp.Value().private_key;
        k.pubkey = kp.Value().public_key;
        k.account = with_type(TU::ACCOUNT_TYPE_ZBC, k.pubkey);
        k.display = zoobc::crypto::ZoobcAddress::Encode(k.pubkey, "ZBC");
        k.kind_label = "zbc (ed25519)";
    } else if (kind == KeyKind::ETH) {
        zoobc::crypto::EthereumSignature eth;
        auto pk = eth.GetPublicKeyFromPrivateKey(k.seed);
        if (!pk.IsOk()) refuse(exit_code::USAGE, "invalid eth key: " + pk.GetError().ToString());
        k.pubkey = pk.Value();
        auto a20 = zoobc::crypto::EthereumSignature::GetAddress20(k.pubkey);
        k.account = with_type(TU::ACCOUNT_TYPE_ETH, a20);
        k.display = zoobc::crypto::EthereumSignature::ToChecksumAddress(a20);
        k.kind_label = "eth (secp256k1)";
    } else {
        zoobc::crypto::BitcoinSignature btc;
        auto pk = btc.GetPublicKeyFromPrivateKey(k.seed);
        if (!pk.IsOk()) refuse(exit_code::USAGE, "invalid btc key: " + pk.GetError().ToString());
        k.pubkey = pk.Value();
        auto h = zoobc::crypto::BitcoinSignature::Hash160(k.pubkey);
        if (!h.IsOk()) refuse(exit_code::INTERNAL, "hash160 failed");
        k.account = with_type(TU::ACCOUNT_TYPE_BTC_P2PKH, h.Value());
        k.alt_accounts = {with_type(TU::ACCOUNT_TYPE_BTC_P2WPKH, h.Value())};
        k.display = btc.GetAddressFromPublicKey("", k.pubkey);
        k.kind_label = "btc (secp256k1)";
    }
    return k;
}

// Sign the 32-byte digest in the form the node's Signature::VerifySignature expects for this key's
// account type.
std::vector<uint8_t> sign_digest(const Key& k, const std::vector<uint8_t>& digest) {
    if (k.kind == KeyKind::ZBC) {
        auto s = Signature::Sign(digest, k.ed_secret);
        if (!s.IsOk()) refuse(exit_code::INTERNAL, "signing failed: " + s.GetError().ToString());
        return s.Value();
    }
    if (k.kind == KeyKind::ETH) {
        zoobc::crypto::EthereumSignature eth;   // applies Keccak-256 itself, as the node's recovery does
        auto s = eth.Sign(k.seed, digest);
        if (!s.IsOk()) refuse(exit_code::INTERNAL, "signing failed: " + s.GetError().ToString());
        return s.Value();
    }
    zoobc::crypto::BitcoinSignature btc;        // applies double-SHA256 itself, matching Verify
    auto s = btc.Sign(k.seed, digest);
    if (!s.IsOk()) refuse(exit_code::INTERNAL, "signing failed: " + s.GetError().ToString());
    // [2-byte LE pubkey length][compressed pubkey][signature] — the key rides in the signature.
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(k.pubkey.size() & 0xff));
    out.push_back(static_cast<uint8_t>((k.pubkey.size() >> 8) & 0xff));
    out.insert(out.end(), k.pubkey.begin(), k.pubkey.end());
    out.insert(out.end(), s.Value().begin(), s.Value().end());
    return out;
}

// The node's own verifier: exactly what CheckMultisigComplete runs.
bool node_verifies(const std::vector<uint8_t>& digest, const std::vector<uint8_t>& sig,
                   const std::vector<uint8_t>& account) {
    auto r = Signature::VerifySignature(digest, sig, account);
    return r.IsOk() && r.Value();
}

// ---------------------------------------------------------------------------------------------
// Participants and the signing package
// ---------------------------------------------------------------------------------------------

struct Participant {
    std::string display;
    std::vector<uint8_t> account;
    std::string type_label;
};

Participant parse_participant(const std::string& text) {
    auto r = parse_address(trim(text));
    if (!r.IsOk()) refuse(exit_code::USAGE, "invalid participant address '" + text + "': " + r.GetError().ToString());
    Participant p;
    p.account = r.Value().address;
    p.type_label = r.Value().type_label;
    const int32_t type = static_cast<int32_t>(read_u32le(p.account));
    // The body parser reads each participant as type + GetAccountPublicKeyLength(type) bytes; any
    // other length would shift every field after it.
    if (p.account.size() != 4 + TU::GetAccountPublicKeyLength(type))
        refuse(exit_code::USAGE, "participant '" + text + "' has no fixed-size account form the multisig body can carry");
    if (type == TU::ACCOUNT_TYPE_EMPTY || type == TU::ACCOUNT_TYPE_DATASET || type == TU::ACCOUNT_TYPE_BTC_P2WSH ||
        type == TU::ACCOUNT_TYPE_BTC_P2SH || type == TU::ACCOUNT_TYPE_ESTONIA_EID)
        refuse(exit_code::USAGE, "participant '" + text + "' (" + p.type_label + ") is an account type that cannot sign");
    p.display = r.Value().display;
    if (type == TU::ACCOUNT_TYPE_ZBC)
        p.display = zoobc::crypto::ZoobcAddress::Encode(std::vector<uint8_t>(p.account.begin() + 4, p.account.end()), "ZBC");
    return p;
}

// Everything a package says, re-derived and checked. Nothing in the human-readable part is
// trusted: it must match what the bytes say or the package is refused.
struct Package {
    json doc;
    std::vector<Participant> participants;
    uint32_t threshold = 0;
    int64_t nonce = 0;
    std::vector<uint8_t> multisig_hash;       // 32-byte GenerateMultisigAddress
    std::string multisig_display;             // ZBC_... form of the hash
    std::vector<uint8_t> genesis;
    std::vector<uint8_t> inner_bytes;
    std::vector<uint8_t> inner_hash;          // SHA3-256(inner) — the key signatures are stored under
    std::vector<uint8_t> digest;              // SHA3-256("ZBC-TX" ‖ genesis ‖ inner) — what is signed
    zoobc::model::Transaction inner;
    json details;                             // recomputed from the bytes
};

std::string display_account(const std::vector<uint8_t>& account, const std::string& hint) {
    if (account.size() == 36 && read_u32le(account) == static_cast<uint32_t>(TU::ACCOUNT_TYPE_ZBC))
        return zoobc::crypto::ZoobcAddress::Encode(std::vector<uint8_t>(account.begin() + 4, account.end()), "ZBC");
    if (!hint.empty()) {
        auto r = parse_address(hint);
        if (r.IsOk() && r.Value().address == account) return hint;
    }
    return bytes_to_hex(account);
}

json describe_inner(const zoobc::model::Transaction& tx, const std::string& recipient_hint) {
    const uint32_t type = static_cast<uint32_t>(tx.transaction_type);
    auto it = supported_inner_types().find(type);
    json d = {
        {"transaction_type", type},
        {"transaction_type_name", it != supported_inner_types().end() ? it->second : "unsupported"},
        {"inner_fee", tx.fee},
        {"inner_fee_zbc", zbc_amount(tx.fee)},
        {"timestamp", tx.timestamp},
        {"body_hex", bytes_to_hex(tx.transaction_body_bytes)},
    };
    if (!tx.recipient_account_address.empty()) {
        d["recipient"] = display_account(tx.recipient_account_address, recipient_hint);
        d["recipient_account_hex"] = bytes_to_hex(tx.recipient_account_address);
    }
    if (tx.transaction_type == zoobc::TransactionType::SendZBC && tx.transaction_body_bytes.size() == 8) {
        const int64_t amount = TU::ReadInt64LE(tx.transaction_body_bytes.data());
        d["amount"] = amount;
        d["amount_zbc"] = zbc_amount(amount);
    }
    if (!tx.message.empty()) d["message"] = std::string(tx.message.begin(), tx.message.end());
    return d;
}

std::vector<uint8_t> derive_multisig(const std::vector<Participant>& ps, int64_t nonce, uint32_t threshold) {
    std::vector<std::vector<uint8_t>> accts;
    for (const auto& p : ps) accts.push_back(p.account);
    auto h = MS::GenerateMultisigAddress(accts, nonce, threshold);
    if (h.size() != 32) refuse(exit_code::INTERNAL, "multisig address derivation failed");
    return h;
}

void check_participant_set(const std::vector<Participant>& ps, int64_t threshold) {
    if (ps.size() < 2) refuse(exit_code::USAGE, "a multisig needs at least 2 participants");
    std::set<std::vector<uint8_t>> seen;
    for (const auto& p : ps)
        if (!seen.insert(p.account).second) refuse(exit_code::USAGE, "participant listed twice: " + p.display);
    if (threshold < 1 || threshold > static_cast<int64_t>(ps.size()))
        refuse(exit_code::USAGE, "threshold must be between 1 and the participant count (" + std::to_string(ps.size()) + ")");
}

Package load_package(const std::string& path) {
    Package p;
    p.doc = read_json_file(path, "package");
    const std::string what = "package " + path;
    if (p.doc.value("format", "") != PACKAGE_FORMAT)
        refuse(exit_code::USAGE, what + " is not a " + std::string(PACKAGE_FORMAT) + " file");
    const json& ms = p.doc.at("multisig");
    if (!ms.contains("participants") || !ms["participants"].is_array()) refuse(exit_code::USAGE, what + ": no participants");
    for (const auto& pj : ms["participants"]) {
        Participant part = parse_participant(jstr(pj, "address", what));
        if (lower(jstr(pj, "account_hex", what)) != bytes_to_hex(part.account))
            refuse(exit_code::VERIFY_FAILED, what + ": participant " + part.display + " does not match its account_hex (tampered package)");
        p.participants.push_back(part);
    }
    const int64_t threshold = jint(ms, "threshold", what);
    check_participant_set(p.participants, threshold);
    p.threshold = static_cast<uint32_t>(threshold);
    p.nonce = jint(ms, "nonce", what);
    p.multisig_hash = derive_multisig(p.participants, p.nonce, p.threshold);
    p.multisig_display = zoobc::crypto::ZoobcAddress::Encode(p.multisig_hash, "ZBC");
    if (lower(jstr(ms, "multisig_address_hex", what)) != bytes_to_hex(p.multisig_hash) ||
        jstr(ms, "multisig_address", what) != p.multisig_display)
        refuse(exit_code::VERIFY_FAILED, what + ": multisig address does not derive from its participants/nonce/threshold (tampered package)");

    p.genesis = strict_hex(jstr(p.doc, "genesis_hash", what), "genesis_hash", 32);
    p.inner_bytes = strict_hex(jstr(p.doc, "unsigned_transaction_bytes", what), "unsigned_transaction_bytes");
    auto parsed = TU::ParseTransactionBytes(p.inner_bytes, false);
    if (!parsed.IsOk()) refuse(exit_code::VERIFY_FAILED, what + ": inner transaction does not parse: " + parsed.GetError().ToString());
    p.inner = parsed.Value();
    auto again = TU::GetTransactionBytes(p.inner, false);
    if (!again.IsOk() || again.Value() != p.inner_bytes)
        refuse(exit_code::VERIFY_FAILED, what + ": inner transaction bytes are not in canonical form");
    if (p.inner.sender_account_address != with_type(TU::ACCOUNT_TYPE_ZBC, p.multisig_hash))
        refuse(exit_code::VERIFY_FAILED, what + ": inner transaction is not sent from the multisig account; the chain would refuse it");
    if (!supported_inner_types().count(static_cast<uint32_t>(p.inner.transaction_type)))
        refuse(exit_code::VERIFY_FAILED, what + ": inner transaction type " + std::to_string(static_cast<uint32_t>(p.inner.transaction_type)) +
                                          " cannot execute inside a multisig (supported: " + supported_types_text() + ")");
    p.inner_hash = zoobc::crypto::Hash::SHA3_256(p.inner_bytes).Value();
    auto dg = TU::SigningDigest(p.inner_bytes, p.genesis);
    if (!dg.IsOk()) refuse(exit_code::INTERNAL, dg.GetError().ToString());
    p.digest = dg.Value();
    if (lower(jstr(p.doc, "inner_transaction_hash", what)) != bytes_to_hex(p.inner_hash))
        refuse(exit_code::VERIFY_FAILED, what + ": inner_transaction_hash does not match the inner bytes (tampered package)");
    if (lower(jstr(p.doc, "digest", what)) != bytes_to_hex(p.digest))
        refuse(exit_code::VERIFY_FAILED, what + ": digest does not match SHA3-256(\"ZBC-TX\" | genesis | inner bytes) (tampered package)");

    const json& stated = p.doc.at("details");
    p.details = describe_inner(p.inner, stated.value("recipient", ""));
    for (const char* k : {"transaction_type", "inner_fee", "timestamp", "body_hex", "recipient_account_hex", "amount", "message"}) {
        const bool a = stated.contains(k), b = p.details.contains(k);
        if (a != b || (a && stated.at(k) != p.details.at(k)))
            refuse(exit_code::VERIFY_FAILED, what + ": details." + k + " does not match the inner transaction bytes (tampered package)");
    }
    if (stated.contains("recipient") && stated.at("recipient") != p.details.at("recipient"))
        refuse(exit_code::VERIFY_FAILED, what + ": details.recipient does not match the inner transaction bytes (tampered package)");
    return p;
}

void print_details(std::ostream& o, const Package& p) {
    const auto& d = p.details;
    o << "  Chain (genesis):   " << bytes_to_hex(p.genesis) << "\n"
      << "  Multisig account:  " << p.multisig_display << "  (" << p.threshold << " of "
      << p.participants.size() << ", nonce " << p.nonce << ")\n"
      << "  Participants:\n";
    for (size_t i = 0; i < p.participants.size(); ++i)
        o << "    " << (i + 1) << ". " << p.participants[i].display << "  [" << p.participants[i].type_label << "]\n";
    o << "  Transaction:       " << d.value("transaction_type_name", "") << " (type " << d.value("transaction_type", 0u) << ")\n";
    if (d.contains("recipient")) o << "  Recipient:         " << d["recipient"].get<std::string>() << "\n";
    if (d.contains("amount")) o << "  Amount:            " << d["amount_zbc"].get<std::string>() << "  (" << d["amount"].get<int64_t>() << " atomic)\n";
    o << "  Inner fee (max):   " << d["inner_fee_zbc"].get<std::string>() << "  (paid by the multisig account)\n";
    if (d.contains("message")) o << "  Message:           " << d["message"].get<std::string>() << "\n";
    if (!d.contains("amount")) o << "  Body (hex):        " << d["body_hex"].get<std::string>() << "\n";
    o << "  Digest to sign:    " << bytes_to_hex(p.digest) << "\n";
}

// ---------------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------------

int cmd_address(const Args& a) {
    const KeyKind kind = parse_key_kind(a.get("--key-type"));
    Key k = load_key(read_key_material(a, "--key-file", "--key", "participant"), kind);
    json out = {{"success", true}, {"command", "address"}, {"key_type", lower(a.get("--key-type", "zbc"))},
                {"address", k.display}, {"account_hex", bytes_to_hex(k.account)}};
    if (kind == KeyKind::BTC) out["also_accepted_account_hex"] = {bytes_to_hex(k.alt_accounts[0])};
    if (a.json_output) std::cout << out.dump(2) << "\n";
    else std::cout << k.display << "\n";
    return 0;
}

int cmd_prepare(const Args& a) {
    if (!a.has("--out")) refuse(exit_code::USAGE, "prepare: --out <package.json> is required");
    std::vector<std::string> ptexts;
    for (const auto& list : a.all("--participants")) {
        std::stringstream ss(list);
        std::string item;
        while (std::getline(ss, item, ',')) if (!trim(item).empty()) ptexts.push_back(trim(item));
    }
    for (const auto& one : a.all("--participant")) ptexts.push_back(trim(one));
    std::vector<Participant> ps;
    for (const auto& t : ptexts) ps.push_back(parse_participant(t));
    if (!a.has("--threshold")) refuse(exit_code::USAGE, "prepare: --threshold is required");
    const int64_t threshold = parse_i64(a.get("--threshold"), "--threshold", 1);
    check_participant_set(ps, threshold);
    const int64_t nonce = parse_i64(a.get("--nonce", "0"), "--nonce", 0);
    const auto ms_hash = derive_multisig(ps, nonce, static_cast<uint32_t>(threshold));

    // Inner transaction.
    uint32_t type = 0;
    std::vector<uint8_t> body, recipient;
    std::string recipient_hint;
    if (a.has("--to") || a.has("--amount")) {
        if (a.has("--type") || a.has("--body-hex")) refuse(exit_code::USAGE, "prepare: use either --to/--amount or --type/--body-hex");
        if (!a.has("--to") || !a.has("--amount")) refuse(exit_code::USAGE, "prepare: a send needs both --to and --amount");
        type = static_cast<uint32_t>(zoobc::TransactionType::SendZBC);
        const int64_t amount = parse_i64(a.get("--amount"), "--amount", 1);
        body = TU::GetSendZBCBodyBytes(amount);
        recipient_hint = a.get("--to");
    } else if (a.has("--type")) {
        type = static_cast<uint32_t>(parse_i64(a.get("--type"), "--type", 0));
        body = a.has("--body-hex") ? strict_hex(a.get("--body-hex"), "--body-hex") : std::vector<uint8_t>{};
        recipient_hint = a.get("--recipient");
    } else {
        refuse(exit_code::USAGE, "prepare: give the inner transaction: --to ADDR --amount ATOMIC, or --type N --body-hex HEX");
    }
    if (!supported_inner_types().count(type))
        refuse(exit_code::USAGE, "inner transaction type " + std::to_string(type) + " cannot execute inside a multisig (supported: " + supported_types_text() + ")");
    if (!recipient_hint.empty()) {
        auto r = parse_address(recipient_hint);
        if (!r.IsOk()) refuse(exit_code::USAGE, "invalid recipient '" + recipient_hint + "': " + r.GetError().ToString());
        recipient = r.Value().address;
    }
    if (type == static_cast<uint32_t>(zoobc::TransactionType::SendZBC) && recipient.empty())
        refuse(exit_code::USAGE, "a SendZBC needs a recipient");
    const int64_t inner_fee = parse_i64(a.get("--inner-fee", std::to_string(DEFAULT_INNER_FEE)), "--inner-fee", 1);
    const std::string message = a.get("--message");
    if (message.size() > 256) refuse(exit_code::USAGE, "--message is limited to 256 bytes");
    const int64_t ts = a.has("--timestamp") ? parse_i64(a.get("--timestamp"), "--timestamp", 1)
                                            : static_cast<int64_t>(std::time(nullptr));

    // The chain: from --genesis-hash (offline) or the node's /node/info.
    std::vector<uint8_t> genesis;
    std::string genesis_source;
    if (a.has("--genesis-hash")) {
        genesis = strict_hex(a.get("--genesis-hash"), "--genesis-hash", 32);
        genesis_source = "--genesis-hash";
    } else {
        std::string api = a.get("--api");
        if (api.empty()) if (const char* e = std::getenv("ZBC_API"); e && *e) api = e;
        if (api.empty()) api = "http://localhost:8080";
        int code = 0;
        std::string err;
        auto emit = [&](const std::string& m) { err = m; };
        if (!ensure_signing_context(api, "", emit)) refuse(last_exit_code() ? last_exit_code() : exit_code::UNREACHABLE, err);
        if (signing_context().version != 2)
            refuse(exit_code::REJECTED, "node at " + api + " does not enforce chain-bound signing (v2); multisig participants always sign the v2 digest");
        genesis = signing_context().genesis_hash;
        genesis_source = api;
        (void)code;
    }

    std::vector<uint8_t> msg(message.begin(), message.end());
    auto inner = build_transaction_bytes_multikey(1, ts, with_type(TU::ACCOUNT_TYPE_ZBC, ms_hash), recipient,
                                                  type, inner_fee, body, {}, msg);
    auto parsed = TU::ParseTransactionBytes(inner, false);
    if (!parsed.IsOk()) refuse(exit_code::USAGE, "the inner transaction does not parse: " + parsed.GetError().ToString());
    auto inner_hash = zoobc::crypto::Hash::SHA3_256(inner).Value();
    auto digest = TU::SigningDigest(inner, genesis).Value();

    json participants = json::array();
    for (const auto& p : ps)
        participants.push_back({{"address", p.display}, {"account_hex", bytes_to_hex(p.account)}, {"type", p.type_label}});
    const std::string ms_display = zoobc::crypto::ZoobcAddress::Encode(ms_hash, "ZBC");
    json pkg = {
        {"format", PACKAGE_FORMAT},
        {"genesis_hash", bytes_to_hex(genesis)},
        {"signing_version", 2},
        {"multisig", {{"participants", participants}, {"threshold", threshold}, {"nonce", nonce},
                      {"multisig_address", ms_display}, {"multisig_address_hex", bytes_to_hex(ms_hash)}}},
        {"details", describe_inner(parsed.Value(), recipient_hint)},
        {"unsigned_transaction_bytes", bytes_to_hex(inner)},
        {"inner_transaction_hash", bytes_to_hex(inner_hash)},
        {"digest", bytes_to_hex(digest)},
        {"digest_rule", "SHA3-256(\"ZBC-TX\" | genesis_hash | unsigned_transaction_bytes)"},
    };
    write_json_file(a.get("--out"), pkg);
    // Read it back through the same checks every signer will run.
    Package check = load_package(a.get("--out"));

    if (a.json_output) {
        json out = {{"success", true}, {"command", "prepare"}, {"file", a.get("--out")},
                    {"genesis_source", genesis_source}, {"multisig_address", ms_display},
                    {"multisig_address_hex", bytes_to_hex(ms_hash)}, {"threshold", threshold},
                    {"participants", ps.size()}, {"digest", bytes_to_hex(digest)},
                    {"inner_transaction_hash", bytes_to_hex(inner_hash)}, {"details", check.details},
                    {"fund_hint", "the multisig account pays amount + inner fee: fund " + ms_display + " before submitting"}};
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Signing package written: " << a.get("--out") << "\n";
        print_details(std::cout, check);
        std::cout << "Fund " << ms_display << " with at least amount + inner fee before submitting.\n";
    }
    return 0;
}

int cmd_sign(const Args& a) {
    if (a.positional.size() != 1) refuse(exit_code::USAGE, "sign: exactly one package file expected");
    if (!a.has("--out")) refuse(exit_code::USAGE, "sign: --out <signature.json> is required");
    Package p = load_package(a.positional[0]);
    if (a.has("--genesis-hash")) {
        auto want = strict_hex(a.get("--genesis-hash"), "--genesis-hash", 32);
        if (want != p.genesis)
            refuse(exit_code::VERIFY_FAILED, "the package is for chain " + bytes_to_hex(p.genesis) +
                                             ", not the chain you expect (" + bytes_to_hex(want) + "); not signing");
    }
    const KeyKind kind = parse_key_kind(a.get("--key-type"));
    Key k = load_key(read_key_material(a, "--key-file", "--key", "participant"), kind);

    auto sig = sign_digest(k, p.digest);
    // Which participant is this key? Ask the node's verifier, not a byte compare: that is the
    // question the chain will ask.
    const Participant* me = nullptr;
    size_t idx = 0;
    for (size_t i = 0; i < p.participants.size(); ++i)
        if (node_verifies(p.digest, sig, p.participants[i].account)) { me = &p.participants[i]; idx = i; break; }
    if (!me)
        refuse(exit_code::VERIFY_FAILED, "this key (" + k.display + ", " + k.kind_label +
                                         ") is not a participant of multisig " + p.multisig_display + "; not signing");

    // Show what is being signed. The details come from the bytes, not from the package's text.
    std::ostream& o = a.json_output ? std::cerr : std::cout;
    o << "ZooBC multisig signing request (" << a.positional[0] << ")\n";
    print_details(o, p);
    o << "  Signing as:        " << me->display << "  (participant " << (idx + 1) << " of " << p.participants.size() << ")\n";
    if (!a.yes) {
        if (!is_stdin_terminal()) refuse(exit_code::USAGE, "sign: stdin is not a terminal; review the details above and pass --yes to sign");
        std::cerr << "Sign this transaction? Type 'yes' to sign: " << std::flush;
        std::string answer;
        std::getline(std::cin, answer);
        if (lower(trim(answer)) != "yes") refuse(exit_code::USAGE, "not signed (answer was not 'yes')");
    }

    json sigdoc = {
        {"format", SIGNATURE_FORMAT},
        {"participant", me->display},
        {"participant_account_hex", bytes_to_hex(me->account)},
        {"key_type", lower(a.get("--key-type", "zbc"))},
        {"signature", bytes_to_hex(sig)},
        {"digest", bytes_to_hex(p.digest)},
        {"inner_transaction_hash", bytes_to_hex(p.inner_hash)},
        {"genesis_hash", bytes_to_hex(p.genesis)},
        {"multisig_address", p.multisig_display},
    };
    write_json_file(a.get("--out"), sigdoc);
    if (a.json_output) {
        json out = {{"success", true}, {"command", "sign"}, {"file", a.get("--out")}, {"participant", me->display},
                    {"multisig_address", p.multisig_display}, {"digest", bytes_to_hex(p.digest)}, {"details", p.details}};
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Signature written: " << a.get("--out") << "\n";
    }
    return 0;
}

int cmd_combine(const Args& a) {
    if (a.positional.size() < 2) refuse(exit_code::USAGE, "combine: a package file and at least one signature file expected");
    if (!a.has("--out")) refuse(exit_code::USAGE, "combine: --out <signed.json> is required");
    Package p = load_package(a.positional[0]);

    std::map<std::string, std::vector<uint8_t>> sigs;   // hex(account) -> signature
    json signers = json::array();
    for (size_t i = 1; i < a.positional.size(); ++i) {
        const std::string& f = a.positional[i];
        json s = read_json_file(f, "signature");
        if (s.value("format", "") != SIGNATURE_FORMAT) refuse(exit_code::USAGE, f + " is not a " + std::string(SIGNATURE_FORMAT) + " file");
        if (lower(jstr(s, "genesis_hash", f)) != bytes_to_hex(p.genesis))
            refuse(exit_code::VERIFY_FAILED, f + ": signed for chain " + jstr(s, "genesis_hash", f) + ", the package is for " + bytes_to_hex(p.genesis));
        if (lower(jstr(s, "digest", f)) != bytes_to_hex(p.digest))
            refuse(exit_code::VERIFY_FAILED, f + ": signs a different digest; it belongs to another package");
        const auto acct = strict_hex(jstr(s, "participant_account_hex", f), f + ": participant_account_hex");
        const Participant* who = nullptr;
        for (const auto& part : p.participants) if (part.account == acct) who = &part;
        if (!who) refuse(exit_code::VERIFY_FAILED, f + ": " + jstr(s, "participant", f) + " is not a participant of " + p.multisig_display);
        const std::string key = bytes_to_hex(acct);
        if (sigs.count(key)) refuse(exit_code::VERIFY_FAILED, f + ": a second signature from " + who->display + " (duplicate)");
        const auto sig = strict_hex(jstr(s, "signature", f), f + ": signature");
        if (!node_verifies(p.digest, sig, acct))
            refuse(exit_code::VERIFY_FAILED, f + ": the signature of " + who->display + " does not verify against the package digest");
        sigs[key] = sig;
        signers.push_back(who->display);
    }
    if (sigs.size() < p.threshold)
        refuse(exit_code::VERIFY_FAILED, "only " + std::to_string(sigs.size()) + " valid signature(s); multisig " +
                                         p.multisig_display + " needs " + std::to_string(p.threshold));

    // The type-5 body: participants + threshold + nonce, the unsigned inner transaction, and the
    // signatures keyed by participant account (hex), collected under SHA3-256(inner).
    zoobc::model::MultiSignatureTransactionBody body;
    zoobc::model::MultiSignatureInfo info;
    info.minimum_signatures = p.threshold;
    info.nonce = p.nonce;
    for (const auto& part : p.participants) info.addresses.push_back(part.account);
    body.multi_signature_info = info;
    body.unsigned_transaction_bytes = p.inner_bytes;
    zoobc::model::SignatureInfo si;
    si.transaction_hash = p.inner_hash;
    for (const auto& [k, v] : sigs) si.signatures[k] = v;
    body.signature_info = si;
    const auto body_bytes = MS::GetBodyBytes(body);

    // Re-parse the body as the node will and count as CheckMultisigComplete does.
    auto rb = MS::ParseBodyBytes(body_bytes);
    if (!rb.IsOk() || !rb.Value().multi_signature_info || !rb.Value().signature_info ||
        rb.Value().multi_signature_info->multisig_address != p.multisig_hash ||
        rb.Value().unsigned_transaction_bytes != p.inner_bytes)
        refuse(exit_code::INTERNAL, "the built multisig body does not round-trip through the node's parser");
    uint32_t counted = 0;
    for (const auto& [hexaddr, sig] : rb.Value().signature_info->signatures) {
        auto acct = hex_to_bytes(hexaddr);
        bool listed = std::any_of(p.participants.begin(), p.participants.end(), [&](const Participant& x) { return x.account == acct; });
        if (listed && node_verifies(p.digest, sig, acct)) ++counted;
    }
    if (counted < p.threshold) refuse(exit_code::INTERNAL, "the built body carries fewer verifying signatures than the threshold");

    // Outer envelope: an ordinary transaction from the submitter, who pays the outer fee.
    Key sub = load_key(read_key_material(a, "--submitter-key-file", "--submitter-key", "submitter"), KeyKind::ZBC);
    const int64_t fee = parse_i64(a.get("--fee", "5000000"), "--fee", 1);
    const int64_t ts = a.has("--timestamp") ? parse_i64(a.get("--timestamp"), "--timestamp", 1)
                                            : static_cast<int64_t>(std::time(nullptr));
    const uint32_t type5 = static_cast<uint32_t>(zoobc::TransactionType::MultiSignature);
    auto outer = build_transaction_bytes(1, ts, sub.pubkey, {}, type5, fee, body_bytes, {}, {});
    auto outer_digest = TU::SigningDigest(outer, p.genesis).Value();
    auto outer_sig = Signature::Sign(outer_digest, sub.ed_secret);
    if (!outer_sig.IsOk()) refuse(exit_code::INTERNAL, "signing the outer transaction failed");
    auto tx_hash = calculate_tx_hash(outer, outer_sig.Value()).Value();
    std::vector<uint8_t> full(outer);
    full.insert(full.end(), outer_sig.Value().begin(), outer_sig.Value().end());
    const std::string payload = build_json_payload(1, ts, sub.pubkey, {}, type5, fee, body_bytes, outer_sig.Value(), {}, json());

    json signed_doc = {
        {"format", SIGNED_FORMAT},
        {"genesis_hash", bytes_to_hex(p.genesis)},
        {"transaction_hash", bytes_to_hex(tx_hash)},
        {"multisig_address", p.multisig_display},
        {"threshold", p.threshold},
        {"signers", signers},
        {"inner_transaction_hash", bytes_to_hex(p.inner_hash)},
        {"details", p.details},
        {"submitter", sub.display},
        {"fee", fee},
        {"timestamp", ts},
        {"transaction_bytes", bytes_to_hex(full)},
        {"payload", json::parse(payload)},
    };
    write_json_file(a.get("--out"), signed_doc);
    if (a.json_output) {
        json out = {{"success", true}, {"command", "combine"}, {"file", a.get("--out")},
                    {"transaction_hash", bytes_to_hex(tx_hash)}, {"multisig_address", p.multisig_display},
                    {"signatures", sigs.size()}, {"threshold", p.threshold}, {"signers", signers},
                    {"submitter", sub.display}, {"fee", fee}};
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Signed multisig transaction written: " << a.get("--out") << "\n"
                  << "  Transaction hash: " << bytes_to_hex(tx_hash) << "\n"
                  << "  Signatures:       " << sigs.size() << " (threshold " << p.threshold << ")\n"
                  << "  Submitter:        " << sub.display << " pays " << zbc_amount(fee) << "\n";
    }
    return 0;
}

int cmd_submit(const Args& a) {
    if (a.positional.size() != 1) refuse(exit_code::USAGE, "submit: exactly one signed transaction file expected");
    const std::string f = a.positional[0];
    json s = read_json_file(f, "signed transaction");
    if (s.value("format", "") != SIGNED_FORMAT) refuse(exit_code::USAGE, f + " is not a " + std::string(SIGNED_FORMAT) + " file");
    if (!s.contains("payload") || !s["payload"].is_object()) refuse(exit_code::USAGE, f + ": no payload");
    const std::string genesis = lower(jstr(s, "genesis_hash", f));

    std::string api = a.get("--api");
    if (api.empty()) if (const char* e = std::getenv("ZBC_API"); e && *e) api = e;
    if (api.empty()) api = "http://localhost:8080";

    // The node must serve the chain the signatures bind to; anything else would be refused anyway.
    std::string err;
    auto emit = [&](const std::string& m) { err = m; };
    if (!ensure_signing_context(api, "", emit)) refuse(last_exit_code() ? last_exit_code() : exit_code::UNREACHABLE, err);
    if (signing_context().version != 2 || bytes_to_hex(signing_context().genesis_hash) != genesis)
        refuse(exit_code::VERIFY_FAILED, "node at " + api + " serves chain " +
               (signing_context().version == 2 ? bytes_to_hex(signing_context().genesis_hash) : std::string("(signing v1)")) +
               "; this transaction is signed for " + genesis + ". Not submitted.");

    auto r = submit_transaction(api, s["payload"].dump());
    if (!r.ok && r.http_code == 0) refuse(classify_transport_error(r.transport_error), "failed to submit: " + r.response_body);
    if (!r.ok) {
        std::string text = r.response_body;
        if (r.response_json.is_object() && r.response_json.contains("error") && r.response_json["error"].is_string())
            text = r.response_json["error"].get<std::string>();
        const int code = classify_node_error(r.http_code, text);
        json out = {{"success", false}, {"http_code", r.http_code}, {"error", text}, {"exit_code", code},
                    {"error_class", exit_code::name(code)}, {"api_response", r.response_json}};
        if (a.json_output) std::cout << out.dump(2) << "\n";
        else std::cerr << "FAILED (" << exit_code::name(code) << "): HTTP " << r.http_code << ": " << text << "\n";
        return code;
    }
    if (a.json_output) {
        json out = {{"success", true}, {"command", "submit"}, {"transaction_hash", s.value("transaction_hash", "")},
                    {"multisig_address", s.value("multisig_address", "")}, {"api_response", r.response_json},
                    {"note", "accepted for the pool (HTTP " + std::to_string(r.http_code) + "); check /api/v1/transactions/<hash> for inclusion"}};
        std::cout << out.dump(2) << "\n";
    } else {
        std::cout << "Submitted: " << s.value("transaction_hash", "") << " (HTTP " << r.http_code << ")\n";
    }
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    bool json_output = true;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "-v" || s == "--verbose") json_output = false;
        if (s == "--json") json_output = true;
    }
    auto emit_error = make_emitter(json_output);
    try {
        Args a = parse_args(argc, argv);
        if (a.help || a.command.empty() || a.command == "help") { print_usage(); return a.command.empty() && !a.help ? exit_code::USAGE : 0; }
        if (a.has("--timeout")) {
            http_timeout_seconds() = static_cast<int>(parse_i64(a.get("--timeout"), "--timeout", 1));
        } else if (const char* t = std::getenv("ZBC_TIMEOUT"); t && *t) {
            try { int v = std::stoi(t); if (v > 0) http_timeout_seconds() = v; } catch (...) {}
        }
        if (!init_sodium(emit_error)) return exit_code::INTERNAL;
        if (a.command == "address") return cmd_address(a);
        if (a.command == "prepare") return cmd_prepare(a);
        if (a.command == "sign") return cmd_sign(a);
        if (a.command == "combine") return cmd_combine(a);
        if (a.command == "submit") return cmd_submit(a);
        refuse(exit_code::USAGE, "unknown command '" + a.command + "' (address, prepare, sign, combine, submit)");
    } catch (const Refusal& r) {
        return fail(emit_error, r.code, r.what());
    } catch (const std::exception& e) {
        return fail(emit_error, exit_code::INTERNAL, e.what());
    }
}
