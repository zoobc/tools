# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""zbc-cli: every transaction as a subcommand, plus sign-message and verify-message (spec/cli-contract.md)."""
import json
import os
import re
import sys
import time
from typing import Dict, List, Optional, Tuple

from ._commands import COMMANDS, COMMAND_BY_NAME
from .address import is_hex, parse_address
from .api import Client
from .body import build_body, validate_param
from .custom import compute_fields, custom_body
from .errors import INTERNAL, NODE_UNREACHABLE, OK, TIMEOUT, USAGE, VERIFY_FAILED, ToolError, classify_node_error, usage
from .encryption import is_sealed, open_sealed, seal
from .keys import key_pair
from .message import SCHEME, message_digest, public_key_of_address, sign_message, verify_message
from .transaction import Escrow, SigningContext, sign_transaction, transaction_id

DEFAULT_FEE = 5000000
CATEGORY = {
    "send-zbc": "value", "liquid-payment": "value", "liquid-payment-stop": "value",
    "transfer-token": "tokens", "issue-token": "tokens", "mint-token": "tokens", "burn-token": "tokens", "finance-token": "tokens",
    "swap-create": "exchange", "swap-accept": "exchange", "swap-cancel": "exchange", "market-create": "exchange", "order-place": "exchange", "order-cancel": "exchange",
    "app-create": "apps", "app-join": "apps", "app-move": "apps", "app-resign": "apps", "app-claim": "apps", "app-settle": "apps",
    "store-file": "storage", "add-prepaid-storage": "storage", "dfs-create-file": "storage",
    "register-node": "node", "update-node": "node", "remove-node": "node", "claim-node": "node", "governance-vote": "node",
    "register-gateway": "gateway", "unregister-gateway": "gateway", "gateway-heartbeat": "gateway", "archival-register": "gateway",
    "archival-unregister": "gateway", "relay-register": "gateway", "relay-unregister": "gateway",
    "register-release": "governance", "revoke-release": "governance", "release-authority-propose": "governance", "release-authority-accept": "governance",
    "sign-message": "keys", "verify-message": "keys", "decrypt-message": "keys",
}
MESSAGE_COMMANDS = {
    "sign-message": ("Sign a message with a private key (ZBC-MSG-v1, off-chain, no node needed)", [
        {"name": "sender_privkey", "kind": "privkey", "required": True, "help": "Sender private key (64 hex)"},
        {"name": "message", "kind": "string", "required": True, "help": "text to sign (hex bytes with --hex)"}]),
    "verify-message": ("Verify a ZBC-MSG-v1 message signature against a ZBC_ address (off-chain)", [
        {"name": "address", "kind": "string", "required": True, "help": "signer's ZBC_ address (or 64-hex public key)"},
        {"name": "message", "kind": "string", "required": True, "help": "the signed text (hex bytes with --hex)"},
        {"name": "signature", "kind": "string", "required": True, "help": "64-byte Ed25519 signature, 128 hex"}]),
    "decrypt-message": ("Decrypt a transaction message sealed with --encrypt, with the recipient's private key (off-chain)", [
        {"name": "sender_privkey", "kind": "privkey", "required": True, "help": "the recipient's private key (64 hex); '-' or omitted = ZBC_KEY"},
        {"name": "message_hex", "kind": "string", "required": True, "help": "the transaction's message field as hex: ZBE1 then the sealed box"}]),
}
_INT = re.compile(r"^-?\d+$")


class Options:
    def __init__(self):
        self.api = os.environ.get("ZBC_API") or "http://localhost:8080"
        self.fee = DEFAULT_FEE
        self.timeout = 20
        env_to = os.environ.get("ZBC_TIMEOUT", "")
        if _INT.match(env_to) and int(env_to) > 0:
            self.timeout = int(env_to)
        self.genesis = ""
        self.json_input = self.verbose = self.encrypt = self.hex = self.offline = self.help = False
        self.message: Optional[str] = None
        self.chain = ""
        self.escrow: Optional[dict] = None
        self.timestamp: Optional[int] = None
        self.token: Optional[str] = None


def _out(obj) -> None:
    sys.stdout.write(json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def _emit_error(e: ToolError, verbose: bool) -> int:
    if verbose:
        sys.stderr.write("Error: %s\n" % e.message)
    else:
        _out(e.to_json())
    return e.code


def parse_args(argv: List[str]) -> Tuple[List[str], Options]:
    o, positional, escrow = Options(), [], {}
    i = 0

    def need(what=""):
        if i + 1 >= len(argv):
            raise usage("%s requires a value%s" % (argv[i], what))
        return argv[i + 1]

    def integer(s, what):
        if not _INT.match(s):
            raise usage(what)
        return int(s)

    while i < len(argv):
        a = argv[i]
        if a in ("-v", "--verbose"):
            o.verbose = True
        elif a == "--json":
            o.verbose = False
        elif a == "--json-input":
            o.json_input = True
        elif a == "--encrypt":
            o.encrypt = True
        elif a == "--hex":
            o.hex = True
        elif a == "--offline":
            o.offline = True
        elif a in ("-h", "--help"):
            o.help = True
        elif a == "--message":
            o.message = need(); i += 1
        elif a == "--fee":
            o.fee = integer(need(), "--fee must be a whole number of atomic units"); i += 1
        elif a == "--api":
            o.api = need(); i += 1
        elif a in ("--timeout", "--timeout-seconds"):
            v = need(" (seconds)"); i += 1
            if not re.match(r"^\d+$", v):
                raise usage("%s must be a whole number of seconds" % a)
            o.timeout = int(v)
            if o.timeout <= 0:
                raise usage("%s must be > 0" % a)
        elif a == "--genesis":
            o.genesis = need(); i += 1
        elif a == "--chain":
            o.chain = need(); i += 1
        elif a == "--token":
            o.token = need(); i += 1
        elif a == "--timestamp":
            v = need(" (Unix seconds)"); i += 1
            o.timestamp = integer(v, "--timestamp must be a whole number of Unix seconds")
            if o.timestamp <= 0:
                raise usage("--timestamp must be > 0")
        elif a == "--escrow-approver":
            escrow["approver"] = need(); i += 1
        elif a == "--escrow-commission":
            escrow["commission"] = integer(need(), "--escrow-commission must be a whole number of atomic units"); i += 1
        elif a == "--escrow-timeout":
            escrow["timeout"] = integer(need(), "--escrow-timeout must be a Unix timestamp in seconds"); i += 1
        elif a == "--escrow-instruction":
            escrow["instruction"] = need(); i += 1
        elif len(a) > 1 and a[0] == "-" and not (a[1].isdigit() or a[1] == "."):
            raise usage("Unknown option: " + a)
        else:
            positional.append(a)
        i += 1
    if o.offline and not o.genesis and not os.environ.get("ZOOBC_GENESIS_HASH"):
        raise usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node")
    if escrow:
        o.escrow = _check_escrow(escrow)
    return positional, o


def _check_escrow(e: dict) -> dict:
    if not e.get("approver"):
        raise usage("Escrow requires --escrow-approver")
    if not e.get("timeout") or e["timeout"] <= 0:
        raise usage("Escrow requires --escrow-timeout > 0")
    if e.get("commission", 0) < 0:
        raise usage("Escrow commission cannot be negative")
    e.setdefault("commission", 0)
    e.setdefault("instruction", "")
    return e


def _is_placeholder(s: str) -> bool:
    return s in ("-", "@env", "env:ZBC_KEY")


def resolve_params(params: List[dict], positional: List[str], o: Options) -> Dict[str, str]:
    values: Dict[str, str] = {}
    key_is_first = bool(params) and params[0]["name"] == "sender_privkey"
    env_key = os.environ.get("ZBC_KEY", "") if key_is_first else ""
    if o.json_input:
        text = sys.stdin.read().strip()
        if not text:
            raise usage("No JSON input received on stdin")
        try:
            j = json.loads(text)
        except ValueError:
            raise usage("Invalid JSON input")
        if not isinstance(j, dict):
            raise usage("Invalid JSON input")
        for p in params:
            if p["name"] in j:
                v = j[p["name"]]
                values[p["name"]] = v if isinstance(v, str) else json.dumps(v)
            elif p.get("default"):
                values[p["name"]] = p["default"]
            elif p["name"] == "sender_privkey" and env_key:
                values[p["name"]] = env_key
            elif p["required"]:
                raise usage("Missing required field: " + p["name"])
            else:
                values[p["name"]] = ""
            if key_is_first and p["name"] == "sender_privkey" and _is_placeholder(values[p["name"]]):
                if not env_key:
                    raise usage("sender_privkey is '-' but ZBC_KEY is not set")
                values[p["name"]] = env_key

        def num(k, what):
            if k not in j:
                return None
            s = str(j[k]) if isinstance(j[k], (int, str)) and not isinstance(j[k], bool) else ""
            if not _INT.match(s):
                raise usage("%s must be a whole number" % what)
            return int(s)

        fee = num("fee", "fee")
        if fee is not None:
            o.fee = fee
        to = num("timeout_seconds", "timeout_seconds")
        if to is not None:
            if to <= 0:
                raise usage("timeout_seconds must be > 0")
            o.timeout = to
        ts = num("timestamp", "timestamp")
        if ts is not None:
            if ts <= 0:
                raise usage("timestamp must be > 0")
            o.timestamp = ts
        if isinstance(j.get("offline"), bool):
            o.offline = j["offline"]
        if isinstance(j.get("api_url"), str):
            o.api = j["api_url"]
        if isinstance(j.get("message"), str):
            o.message = j["message"]
        if isinstance(j.get("hex"), bool):
            o.hex = j["hex"]
        if j.get("verbose") is True:
            o.verbose = True
        if isinstance(j.get("escrow"), dict):
            e = dict(j["escrow"])
            for k in ("commission", "timeout"):
                if k in e:
                    e[k] = int(e[k])
            o.escrow = _check_escrow(e)
        if o.offline and not o.genesis and not os.environ.get("ZOOBC_GENESIS_HASH"):
            raise usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node")
        return values
    if not positional and sys.stdin.isatty() and o.verbose:
        for p in params:
            answer = input("  %s%s: " % (p["help"], " [%s]" % p["default"] if p.get("default") else "")).strip()
            values[p["name"]] = answer or p.get("default", "")
            if p["name"] == "sender_privkey" and (not values[p["name"]] or _is_placeholder(values[p["name"]])):
                values[p["name"]] = env_key
            if p["required"] and not values[p["name"]]:
                raise usage("Missing required argument: " + p["name"])
        return values
    pos = list(positional)
    if key_is_first:
        required = sum(1 for p in params if p["required"] and not p.get("default"))
        if pos and _is_placeholder(pos[0]):
            if not env_key:
                raise usage("key argument is '-' but ZBC_KEY is not set")
            pos[0] = env_key
        elif env_key and len(pos) + 1 == required:
            pos.insert(0, env_key)
    for i, p in enumerate(params):
        if i < len(pos):
            values[p["name"]] = pos[i]
        elif p.get("default"):
            values[p["name"]] = p["default"]
        elif p["required"]:
            raise usage("Missing required argument: " + p["name"] + (" (pass it, or set ZBC_KEY)" if i == 0 and key_is_first else ""))
        else:
            values[p["name"]] = ""
    extra = pos[len(params):]
    if extra:
        if not _INT.match(extra[0]):
            raise usage('Fee must be a whole number of atomic units, got "%s". The API endpoint is passed with --api URL, not as a positional argument.' % extra[0])
        o.fee = int(extra[0])
    if len(extra) > 1:
        o.api = extra[1]
    return values


def _command(cmd: str):
    if cmd in MESSAGE_COMMANDS:
        desc, params = MESSAGE_COMMANDS[cmd]
        return desc, params, 0
    d = COMMAND_BY_NAME.get(cmd)
    return (d["description"], d["params"], d["type"]) if d else None


def print_list() -> None:
    groups: Dict[str, List[str]] = {}
    entries = [(c["command"], c["description"]) for c in COMMANDS] + [(k, v[0]) for k, v in MESSAGE_COMMANDS.items()]
    for cmd, desc in sorted(entries):
        groups.setdefault(CATEGORY.get(cmd, "other"), []).append("  %-26s%s" % (cmd, desc))
    out = ["ZooBC unified transaction CLI — %d commands." % len(entries), "  Default: JSON in, JSON out.   --verbose: prompt each field + text output.",
           "  echo '{...}' | zbc-cli <cmd> --json-input     zbc-cli help <cmd>  (fields for one tx)", ""]
    for g in ("value", "tokens", "exchange", "apps", "storage", "account", "node", "gateway", "governance", "keys", "other"):
        if g in groups:
            out += ["[%s]" % g] + groups[g] + [""]
    out += ["First param is the sender private key (or set ZBC_KEY and omit it / pass '-'); verify-message takes an address.",
            "`zbc-cli help <cmd>` shows a command's JSON fields; `zbc-cli <cmd> --help` the options, env vars and exit codes."]
    sys.stdout.write("\n".join(out) + "\n")


def print_help(cmd: str) -> int:
    c = _command(cmd)
    if not c:
        sys.stderr.write("Unknown command: %s (try `zbc-cli list`)\n" % cmd)
        return USAGE
    desc, params, tx_type = c
    lines = ["%s — %s  (tx type %d)" % (cmd, desc, tx_type), "JSON fields (default: JSON in/out; --json-input reads them on stdin; positional order matches):"]
    sample = {}
    for p in params:
        lines.append("  %-18s%s%s%s" % (p["name"], "(required) " if p["required"] else "(optional) ", p["help"], "  [default: %s]" % p["default"] if p.get("default") else ""))
        sample[p["name"]] = p.get("default") or "..."
    lines += ["Sample: " + json.dumps(sample), "Run with --verbose to be prompted for each field and get human-readable output."]
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


USAGE_TEXT = """Options:
  -v, --verbose         Verbose output (default is JSON)
  --json-input          Read parameters from JSON on stdin
  --chain <name>        Read the recipient as this chain: zbc, btc, eth, sol, dot, ada, xrp, trx, xtz
  --message <text>      Optional transaction message
  --encrypt             Encrypt --message to the recipient (ZBC only)
  --genesis <hex|v1>    Sign for this chain (its genesis block hash) without asking the node; 'v1' = legacy unbound digest. Default: ask --api.
  --escrow-approver <addr>   Escrow approver address
  --escrow-commission <n>    Escrow commission (atomic units)
  --escrow-timeout <n>       Escrow timeout as a FUTURE Unix timestamp (seconds)
  --escrow-instruction <s>   Escrow instruction
  --fee <n>             Transaction fee (default: 5000000 = 0.05 ZBC)
  --api <url>           API endpoint (default: $ZBC_API, else http://localhost:8080)
  --timeout <s>         Bound for each HTTP call, seconds (default: $ZBC_TIMEOUT, else 20; also --timeout-seconds)
  --hex                 sign-message/verify-message: the message is hex bytes, not text
  --offline             Build, sign and hash, print unsigned_bytes, digest, signature, transaction_bytes and transaction_hash, exit 0 without submitting. Needs --genesis.
  --timestamp <n>       Transaction timestamp, Unix seconds (default: now)

Environment:
  ZBC_KEY               Sender private key (64 hex), used when the key argument is omitted or '-'
  ZBC_API, ZBC_TIMEOUT  Defaults for --api and --timeout
  ZOOBC_GENESIS_HASH    Default for --genesis

Exit codes:
  0 ok  1 internal  2 usage  3 node unreachable  4 insufficient balance  5 fee too low
  6 rejected by node  7 not found  8 timeout  9 node busy (5xx)  10 signature invalid
  JSON errors carry the same code as "exit_code" and its name as "error_class".
"""


def print_usage(cmd: str, params: List[dict]) -> None:
    args = "".join(" <%s>" % p["name"] if p["required"] else " [%s]" % p["name"] for p in params)
    sys.stdout.write("zbc-cli %s\n\nUsage:\n  zbc-cli %s [options]%s [fee] [api_url]\n\n%s\nParameters:\n%s\n" % (
        cmd, cmd, args, USAGE_TEXT, "\n".join("  %-22s%s" % (p["name"], p["help"]) for p in params)))


def _message_bytes(text: str, hex_input: bool) -> bytes:
    if not hex_input:
        return text.encode()
    if not is_hex(text):
        raise usage("--hex message is not valid hex")
    return bytes.fromhex(text)


def run_sign_message(v: Dict[str, str], o: Options) -> int:
    if not is_hex(v["sender_privkey"], 64):
        raise usage("Private key must be 64 hex characters (32 bytes)")
    s = sign_message(v["sender_privkey"], _message_bytes(v["message"], o.hex))
    if o.verbose:
        sys.stdout.write("Address:   %s\nDigest:    %s\nSignature: %s\n" % (s["address"], s["digest"], s["signature"]))
    else:
        out = {"success": True, **s}
        if not o.hex:
            out["message"] = v["message"]
        _out(out)
    return 0


def run_verify_message(v: Dict[str, str], o: Options) -> int:
    pub = public_key_of_address(v["address"])
    if pub is None:
        raise usage("address must be a ZBC_ account (Ed25519) address")
    msg = _message_bytes(v["message"], o.hex)
    if not is_hex(v["signature"]):
        raise usage("signature must be hex")
    if len(v["signature"]) != 128:
        raise usage("signature must be 64 bytes (128 hex characters)")
    valid = verify_message(v["address"], msg, v["signature"])
    address = parse_address(pub.hex()).display
    code = OK if valid else VERIFY_FAILED
    if o.verbose:
        sys.stdout.write("%s signature for %s\n" % ("VALID" if valid else "INVALID", address))
    else:
        _out({"success": True, "valid": valid, "scheme": SCHEME, "address": address, "digest": message_digest(msg).hex(),
              "exit_code": code, "error_class": "ok" if valid else "verify_failed"})
    return code


def run_decrypt_message(v: Dict[str, str], o: Options) -> int:
    if not is_hex(v["sender_privkey"], 64):
        raise usage("Private key must be 64 hex characters (32 bytes)")
    if not is_hex(v["message_hex"]):
        raise usage("message_hex must be hex")
    field = bytes.fromhex(v["message_hex"])
    if not is_sealed(field):
        raise usage("message is not encrypted (no ZBE1 prefix)")
    plaintext = open_sealed(field, bytes.fromhex(v["sender_privkey"]))
    if plaintext is None:
        raise ToolError(VERIFY_FAILED, "decryption failed: the key does not open this message, or it is corrupted")
    text = plaintext.decode("utf-8", "replace")
    if o.verbose:
        sys.stdout.write(text + "\n")
    else:
        _out({"success": True, "recipient": key_pair(v["sender_privkey"]).address, "message": text, "message_hex": plaintext.hex()})
    return 0


def _signing_context(o: Options, client: Client) -> SigningContext:
    g = o.genesis or os.environ.get("ZOOBC_GENESIS_HASH", "")
    if g:
        try:
            return SigningContext.of(g)
        except ValueError as e:
            raise usage(str(e))
    try:
        return client.signing_rule()
    except ToolError as e:
        if e.code in (NODE_UNREACHABLE, TIMEOUT):
            raise ToolError(e.code, "%s /api/v1/node/info from %s to learn which chain to sign for; pass --genesis <hex> to sign for a known chain"
                            % ("timed out reading" if e.code == TIMEOUT else "cannot read", o.api))
        raise


def run_transaction(spec: dict, v: Dict[str, str], o: Options) -> int:
    for p in spec["params"]:
        if v.get(p["name"], "") != "" or p["required"]:
            v[p["name"]] = validate_param(p, v.get(p["name"], ""))
    sender = key_pair(v[spec["sender_key"]])
    client = Client(o.api, o.timeout)
    ctx = _signing_context(o, client)
    timestamp = o.timestamp if o.timestamp is not None else int(time.time())
    recipient, extra = b"", {}
    if spec["recipient"] == "required":
        try:
            r = parse_address(v["recipient"], o.chain)
        except ValueError as e:
            raise usage("invalid recipient address: %s" % e)
        recipient = r.bytes
        extra["recipient"], extra["recipient_type"] = r.display, r.type_name
    if o.token is not None:
        if spec["command"] != "liquid-payment":
            raise usage("--token applies to liquid-payment only")
        v["token_id"] = o.token
    files = {}
    for p in spec["params"]:
        if p["kind"] == "file":
            try:
                with open(v[p["name"]], "rb") as fh:
                    files[p["name"]] = fh.read()
            except OSError:
                raise usage("cannot read %s: %s" % (p["name"], v[p["name"]]))
    reference = client.latest_block() if spec["needs_node"] else None
    if spec["custom"] in ("multisig", "settle"):
        body, more = custom_body(spec, v, sender, ctx, timestamp)
        extra.update(more)
    else:
        computed: Dict[str, bytes] = {}
        extra.update(compute_fields(spec, v, sender, computed, reference))
        body = build_body(spec, v, sender, files, computed)
    for p in spec["params"]:
        if p["kind"] not in ("privkey", "file") and p["name"] not in extra and p["name"] != "recipient":
            val = v[p["name"]]
            extra[p["name"]] = int(val) if p["kind"] in ("int64", "uint64", "uint32", "uint8") and _INT.match(val) else val
    if spec["command"] == "approve-escrow":
        extra["escrowed_transaction_hash"] = v["transaction_hash"]
        extra["transaction_id"] = transaction_id(bytes.fromhex(v["transaction_hash"]))
        extra.pop("transaction_hash", None)
    extra["sender"] = sender.address
    escrow = Escrow(o.escrow["approver"], o.escrow["commission"], o.escrow["timeout"], o.escrow["instruction"]) if o.escrow else None
    message_bytes = (o.message or "").encode()
    if o.encrypt and message_bytes:   # --encrypt: seal the message to the recipient's key (signing.md 8)
        if len(recipient) != 36:
            raise usage("--encrypt is only supported for ZBC recipients")
        message_bytes = seal(message_bytes, recipient[4:])
    try:
        signed = sign_transaction(spec["type"], timestamp, sender, recipient, o.fee, body, ctx, escrow, message_bytes)
    except ValueError as e:
        raise usage("Invalid escrow approver: %s" % e)
    fields = {"transaction_hash": signed.hash.hex(), "transaction_type": spec["type"], "sender_account_address": signed.payload["sender_account_address"],
              "recipient_account_address": signed.payload["recipient_account_address"], "fee": o.fee, "timestamp": timestamp}
    common = {}
    if o.message:
        common["message"] = o.message
    if "escrow" in signed.payload:
        common["escrow"] = signed.payload["escrow"]
    common.update(extra)
    if o.offline:
        if o.verbose:
            sys.stdout.write("OFFLINE: transaction built and signed, not submitted\n\nTransaction hash:  %s\nSigning version:   %d%s\nTimestamp:         %d\n"
                             "Unsigned bytes:    %s\nDigest:            %s\nSignature:         %s\nTransaction bytes: %s\nPayload:           %s\n" % (
                                 fields["transaction_hash"], signed.signing_version, " (genesis %s)" % signed.genesis_hash.hex() if signed.genesis_hash else "",
                                 timestamp, signed.unsigned.hex(), signed.digest.hex(), signed.signature.hex(), signed.bytes.hex(), json.dumps(signed.payload)))
        else:
            out = {"success": True, "offline": True, **fields, "signing_version": signed.signing_version}
            if signed.genesis_hash:
                out["genesis_hash"] = signed.genesis_hash.hex()
            out.update(unsigned_bytes=signed.unsigned.hex(), digest=signed.digest.hex(), signature=signed.signature.hex(),
                       transaction_bytes=signed.bytes.hex(), payload=signed.payload, **common)
            _out(out)
        return 0
    status, body_json, accepted = client.submit(signed.payload)
    if not accepted:
        text = body_json.get("error") if isinstance(body_json, dict) and isinstance(body_json.get("error"), str) else str(body_json)
        err = ToolError(classify_node_error(status, text), text, http_code=status, api_response=body_json)
        if o.verbose:
            sys.stderr.write("FAILED: Transaction submission rejected (%s)\nHTTP %d: %s\n" % (error_class_of(err), status, text))
        else:
            _out(err.to_json())
        return err.code
    if o.verbose:
        sys.stdout.write("SUCCESS: %s submitted!\n\nTransaction Hash: %s\n" % (spec["command"], fields["transaction_hash"]))
    else:
        _out({"success": True, **fields, "api_response": body_json, **common})
    return 0


def error_class_of(e: ToolError) -> str:
    from .errors import error_class
    return error_class(e.code)


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        sys.stdout.write("ZooBC unified transaction CLI\nUsage: zbc-cli <command> <params...> [--api URL] [--fee N] [--timeout S] [--verbose] [--json-input]\n"
                         "       zbc-cli list   (show all commands)      zbc-cli <command> --help  (options, env vars, exit codes)\n")
        return USAGE
    cmd = argv[0]
    if cmd == "help" and len(argv) >= 2:
        return print_help(argv[1])
    if cmd in ("list", "--help", "-h", "help"):
        print_list()
        return 0
    c = _command(cmd)
    if not c:
        sys.stderr.write("Unknown command: %s (try `zbc-cli list`)\n" % cmd)
        return USAGE
    verbose = False
    try:
        positional, o = parse_args(argv[1:])
        verbose = o.verbose
        if o.help:
            print_usage(cmd, c[1])
            return 0
        values = resolve_params(c[1], positional, o)
        verbose = o.verbose
        if cmd == "sign-message":
            return run_sign_message(values, o)
        if cmd == "verify-message":
            return run_verify_message(values, o)
        if cmd == "decrypt-message":
            return run_decrypt_message(values, o)
        return run_transaction(COMMAND_BY_NAME[cmd], values, o)
    except ToolError as e:
        return _emit_error(e, verbose)
    except Exception as e:  # noqa: BLE001 - anything else is an internal error, reported as such
        return _emit_error(ToolError(INTERNAL, str(e)), verbose)


if __name__ == "__main__":
    sys.exit(main())
