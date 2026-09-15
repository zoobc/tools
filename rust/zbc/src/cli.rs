// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! zbc-cli: every transaction as a subcommand, plus sign-message and verify-message (spec/cli-contract.md).
//! `run` is the combined command; `run_tool` runs one command as its own program. Both write to
//! the process's stdout/stderr and return the exit code; `run_with` takes explicit streams for tests.

use crate::address::{encode_zbc_address, parse_address};
use crate::api::{rejection_error, Client};
use crate::body::{build_body, validate_param, BodyContext, Params};
use crate::custom::{compute_fields, custom_body, CustomInput};
use crate::encoding::is_hex;
use crate::errors::*;
use crate::keys::KeyPair;
use crate::message::{message_digest, public_key_of_address, sign_message, verify_message, SCHEME};
use crate::spec::{command, commands, ParamDef, TxDef};
use crate::transaction::{sign_transaction, transaction_id, Escrow, SigningContext, Unsigned};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_FEE: i64 = 5_000_000;

fn category(cmd: &str) -> &'static str {
    match cmd {
        "send-zbc" | "liquid-payment" | "liquid-payment-stop" => "value",
        "transfer-token" | "issue-token" | "mint-token" | "burn-token" | "finance-token" => "tokens",
        "swap-create" | "swap-accept" | "swap-cancel" | "market-create" | "order-place" | "order-cancel" => "exchange",
        "app-create" | "app-join" | "app-move" | "app-resign" | "app-claim" | "app-settle" => "apps",
        "store-file" | "add-prepaid-storage" | "dfs-create-file" => "storage",
        "register-node" | "update-node" | "remove-node" | "claim-node" | "governance-vote" => "node",
        "register-gateway" | "unregister-gateway" | "gateway-heartbeat" | "archival-register" | "archival-unregister" | "relay-register" | "relay-unregister" => "gateway",
        "register-release" | "revoke-release" | "release-authority-propose" | "release-authority-accept" => "governance",
        "sign-message" | "verify-message" => "keys",
        _ => "other",
    }
}

fn message_commands() -> Vec<(&'static str, &'static str, Vec<ParamDef>)> {
    let p = |name: &str, kind: &str, help: &str| ParamDef { name: name.into(), kind: kind.into(), required: true, default: None, help: help.into(), min: None, max: None };
    vec![
        ("sign-message", "Sign a message with a private key (ZBC-MSG-v1, off-chain, no node needed)",
         vec![p("sender_privkey", "privkey", "Sender private key (64 hex)"), p("message", "string", "text to sign (hex bytes with --hex)")]),
        ("verify-message", "Verify a ZBC-MSG-v1 message signature against a ZBC_ address (off-chain)",
         vec![p("address", "string", "signer's ZBC_ address (or 64-hex public key)"), p("message", "string", "the signed text (hex bytes with --hex)"),
              p("signature", "string", "64-byte Ed25519 signature, 128 hex")]),
    ]
}

fn command_of(cmd: &str) -> Option<(String, Vec<ParamDef>, u32)> {
    for (name, desc, params) in message_commands() {
        if name == cmd {
            return Some((desc.to_string(), params, 0));
        }
    }
    command(cmd).map(|d| (d.description.clone(), d.params.clone(), d.tx_type))
}

/// Where the command reads its input and writes its output.
pub struct Io<'a> {
    pub stdin: &'a mut dyn Read,
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub is_tty: bool,
}

#[derive(Default)]
struct Options {
    api: String,
    fee: i64,
    timeout: u64,
    genesis: String,
    json_input: bool,
    verbose: bool,
    message: Option<String>,
    encrypt: bool,
    chain: String,
    escrow: Option<Escrow>,
    hex: bool,
    offline: bool,
    timestamp: Option<i64>,
    token: Option<String>,
    help: bool,
}

fn is_int(s: &str) -> bool {
    let d = s.strip_prefix('-').unwrap_or(s);
    !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit())
}

fn out(io: &mut Io, v: &Value) {
    let _ = writeln!(io.stdout, "{}", serde_json::to_string_pretty(v).unwrap());
}

fn emit_error(io: &mut Io, e: &ToolError, verbose: bool) -> i32 {
    if verbose {
        let _ = writeln!(io.stderr, "Error: {}", e.message);
    } else {
        out(io, &e.to_json());
    }
    e.code
}

fn check_escrow(e: &Escrow) -> Result<(), ToolError> {
    if e.approver.is_empty() {
        return Err(usage("Escrow requires --escrow-approver"));
    }
    if e.timeout <= 0 {
        return Err(usage("Escrow requires --escrow-timeout > 0"));
    }
    if e.commission < 0 {
        return Err(usage("Escrow commission cannot be negative"));
    }
    Ok(())
}

fn parse_args(argv: &[String], io: &Io) -> Result<(Vec<String>, Options), ToolError> {
    let mut o = Options { api: (io.env)("ZBC_API").filter(|s| !s.is_empty()).unwrap_or_else(|| "http://localhost:8080".into()), fee: DEFAULT_FEE, timeout: 20, ..Default::default() };
    if let Some(t) = (io.env)("ZBC_TIMEOUT") {
        if let Ok(n) = t.parse::<u64>() {
            if n > 0 {
                o.timeout = n;
            }
        }
    }
    let mut positional = Vec::new();
    let mut escrow = Escrow { approver: String::new(), commission: 0, timeout: 0, instruction: String::new() };
    let mut escrow_seen = false;
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        let mut need = |what: &str| -> Result<String, ToolError> {
            if i + 1 >= argv.len() {
                return Err(usage(format!("{a} requires a value{what}")));
            }
            i += 1;
            Ok(argv[i].clone())
        };
        let integer = |s: &str, what: &str| -> Result<i64, ToolError> { if is_int(s) { s.parse().map_err(|_| usage(what)) } else { Err(usage(what)) } };
        match a {
            "-v" | "--verbose" => o.verbose = true,
            "--json" => o.verbose = false,
            "--json-input" => o.json_input = true,
            "--encrypt" => o.encrypt = true,
            "--hex" => o.hex = true,
            "--offline" => o.offline = true,
            "-h" | "--help" => o.help = true,
            "--message" => o.message = Some(need("")?),
            "--fee" => o.fee = integer(&need("")?, "--fee must be a whole number of atomic units")?,
            "--api" => o.api = need("")?,
            "--timeout" | "--timeout-seconds" => {
                let v = need(" (seconds)")?;
                if !v.bytes().all(|c| c.is_ascii_digit()) || v.is_empty() {
                    return Err(usage(format!("{a} must be a whole number of seconds")));
                }
                o.timeout = v.parse().map_err(|_| usage(format!("{a} must be a whole number of seconds")))?;
                if o.timeout == 0 {
                    return Err(usage(format!("{a} must be > 0")));
                }
            }
            "--genesis" => o.genesis = need("")?,
            "--chain" => o.chain = need("")?,
            "--token" => o.token = Some(need("")?),
            "--timestamp" => {
                let n = integer(&need(" (Unix seconds)")?, "--timestamp must be a whole number of Unix seconds")?;
                if n <= 0 {
                    return Err(usage("--timestamp must be > 0"));
                }
                o.timestamp = Some(n);
            }
            "--escrow-approver" => { escrow.approver = need("")?; escrow_seen = true; }
            "--escrow-commission" => { escrow.commission = integer(&need("")?, "--escrow-commission must be a whole number of atomic units")?; escrow_seen = true; }
            "--escrow-timeout" => { escrow.timeout = integer(&need("")?, "--escrow-timeout must be a Unix timestamp in seconds")?; escrow_seen = true; }
            "--escrow-instruction" => { escrow.instruction = need("")?; escrow_seen = true; }
            _ => {
                let b = a.as_bytes();
                if b.len() > 1 && b[0] == b'-' && !b[1].is_ascii_digit() && b[1] != b'.' {
                    return Err(usage(format!("Unknown option: {a}")));
                }
                positional.push(a.to_string());
            }
        }
        i += 1;
    }
    if o.offline && o.genesis.is_empty() && (io.env)("ZOOBC_GENESIS_HASH").map_or(true, |s| s.is_empty()) {
        return Err(usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node"));
    }
    if escrow_seen {
        check_escrow(&escrow)?;
        o.escrow = Some(escrow);
    }
    Ok((positional, o))
}

fn is_placeholder(s: &str) -> bool {
    s == "-" || s == "@env" || s == "env:ZBC_KEY"
}

fn resolve_params(params: &[ParamDef], positional: &[String], o: &mut Options, io: &mut Io) -> Result<Params, ToolError> {
    let mut values: Params = HashMap::new();
    let key_is_first = params.first().is_some_and(|p| p.name == "sender_privkey");
    let env_key = if key_is_first { (io.env)("ZBC_KEY").unwrap_or_default() } else { String::new() };
    if o.json_input {
        let mut text = String::new();
        let _ = io.stdin.read_to_string(&mut text);
        let text = text.trim();
        if text.is_empty() {
            return Err(usage("No JSON input received on stdin"));
        }
        let j: Value = serde_json::from_str(text).map_err(|_| usage("Invalid JSON input"))?;
        let j = j.as_object().ok_or_else(|| usage("Invalid JSON input"))?;
        for p in params {
            let v = match j.get(&p.name) {
                Some(Value::String(s)) => s.clone(),
                Some(v) => v.to_string(),
                None if p.default.as_deref().is_some_and(|d| !d.is_empty()) => p.default.clone().unwrap(),
                None if p.name == "sender_privkey" && !env_key.is_empty() => env_key.clone(),
                None if p.required => return Err(usage(format!("Missing required field: {}", p.name))),
                None => String::new(),
            };
            let v = if key_is_first && p.name == "sender_privkey" && is_placeholder(&v) {
                if env_key.is_empty() {
                    return Err(usage("sender_privkey is '-' but ZBC_KEY is not set"));
                }
                env_key.clone()
            } else { v };
            values.insert(p.name.clone(), v);
        }
        let num = |k: &str, what: &str| -> Result<Option<i64>, ToolError> {
            match j.get(k) {
                None => Ok(None),
                Some(Value::Number(n)) if n.is_i64() => Ok(n.as_i64()),
                Some(Value::String(s)) if is_int(s) => Ok(s.parse().ok()),
                Some(_) => Err(usage(format!("{what} must be a whole number"))),
            }
        };
        if let Some(n) = num("fee", "fee")? { o.fee = n; }
        if let Some(n) = num("timeout_seconds", "timeout_seconds")? {
            if n <= 0 { return Err(usage("timeout_seconds must be > 0")); }
            o.timeout = n as u64;
        }
        if let Some(n) = num("timestamp", "timestamp")? {
            if n <= 0 { return Err(usage("timestamp must be > 0")); }
            o.timestamp = Some(n);
        }
        if let Some(Value::Bool(b)) = j.get("offline") { o.offline = *b; }
        if let Some(Value::String(s)) = j.get("api_url") { o.api = s.clone(); }
        if let Some(Value::String(s)) = j.get("message") { o.message = Some(s.clone()); }
        if let Some(Value::Bool(b)) = j.get("hex") { o.hex = *b; }
        if let Some(Value::Bool(true)) = j.get("verbose") { o.verbose = true; }
        if let Some(Value::Object(em)) = j.get("escrow") {
            let e = Escrow {
                approver: em.get("approver").and_then(Value::as_str).unwrap_or("").to_string(),
                commission: em.get("commission").and_then(Value::as_i64).unwrap_or(0),
                timeout: em.get("timeout").and_then(Value::as_i64).unwrap_or(0),
                instruction: em.get("instruction").and_then(Value::as_str).unwrap_or("").to_string(),
            };
            check_escrow(&e)?;
            o.escrow = Some(e);
        }
        if o.offline && o.genesis.is_empty() && (io.env)("ZOOBC_GENESIS_HASH").map_or(true, |s| s.is_empty()) {
            return Err(usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node"));
        }
        return Ok(values);
    }
    if positional.is_empty() && io.is_tty && o.verbose {
        for p in params {
            let def = p.default.as_deref().filter(|d| !d.is_empty()).map(|d| format!(" [{d}]")).unwrap_or_default();
            let _ = write!(io.stdout, "  {}{}: ", p.help, def);
            let _ = io.stdout.flush();
            let mut line = String::new();
            let mut buf = [0u8; 1];
            while io.stdin.read(&mut buf).map_or(false, |n| n == 1) && buf[0] != b'\n' {
                line.push(buf[0] as char);
            }
            let mut v = line.trim().to_string();
            if v.is_empty() {
                v = p.default.clone().unwrap_or_default();
            }
            if p.name == "sender_privkey" && (v.is_empty() || is_placeholder(&v)) {
                v = env_key.clone();
            }
            if p.required && v.is_empty() {
                return Err(usage(format!("Missing required argument: {}", p.name)));
            }
            values.insert(p.name.clone(), v);
        }
        return Ok(values);
    }
    let mut pos: Vec<String> = positional.to_vec();
    if key_is_first {
        let required = params.iter().filter(|p| p.required && p.default.as_deref().map_or(true, |d| d.is_empty())).count();
        if pos.first().is_some_and(|s| is_placeholder(s)) {
            if env_key.is_empty() {
                return Err(usage("key argument is '-' but ZBC_KEY is not set"));
            }
            pos[0] = env_key.clone();
        } else if !env_key.is_empty() && pos.len() + 1 == required {
            pos.insert(0, env_key.clone());
        }
    }
    for (i, p) in params.iter().enumerate() {
        let v = if i < pos.len() {
            pos[i].clone()
        } else if let Some(d) = p.default.as_deref().filter(|d| !d.is_empty()) {
            d.to_string()
        } else if p.required {
            let hint = if i == 0 && key_is_first { " (pass it, or set ZBC_KEY)" } else { "" };
            return Err(usage(format!("Missing required argument: {}{hint}", p.name)));
        } else {
            String::new()
        };
        values.insert(p.name.clone(), v);
    }
    if pos.len() > params.len() {
        let fee_arg = &pos[params.len()];
        if !is_int(fee_arg) {
            return Err(usage(format!("Fee must be a whole number of atomic units, got \"{fee_arg}\". The API endpoint is passed with --api URL, not as a positional argument.")));
        }
        o.fee = fee_arg.parse().map_err(|_| usage("Fee is out of range"))?;
    }
    if pos.len() > params.len() + 1 {
        o.api = pos[params.len() + 1].clone();
    }
    Ok(values)
}

fn print_list(io: &mut Io) {
    let mut all: Vec<(String, String)> = commands().iter().map(|c| (c.command.clone(), c.description.clone())).collect();
    for (n, d, _) in message_commands() {
        all.push((n.to_string(), d.to_string()));
    }
    all.sort();
    let mut groups: HashMap<&str, Vec<String>> = HashMap::new();
    for (cmd, desc) in &all {
        groups.entry(category(cmd)).or_default().push(format!("  {cmd:<26}{desc}"));
    }
    let _ = write!(io.stdout, "ZooBC unified transaction CLI — {} commands.\n  Default: JSON in, JSON out.   --verbose: prompt each field + text output.\n  echo '{{...}}' | zbc-cli <cmd> --json-input     zbc-cli help <cmd>  (fields for one tx)\n\n", all.len());
    for g in ["value", "tokens", "exchange", "apps", "storage", "account", "node", "gateway", "governance", "keys", "other"] {
        if let Some(lines) = groups.get(g) {
            let _ = write!(io.stdout, "[{g}]\n{}\n\n", lines.join("\n"));
        }
    }
    let _ = write!(io.stdout, "First param is the sender private key (or set ZBC_KEY and omit it / pass '-'); verify-message takes an address.\n`zbc-cli help <cmd>` shows a command's JSON fields; `zbc-cli <cmd> --help` the options, env vars and exit codes.\n");
}

fn print_help(cmd: &str, io: &mut Io) -> i32 {
    let Some((desc, params, tx_type)) = command_of(cmd) else {
        let _ = writeln!(io.stderr, "Unknown command: {cmd} (try `zbc-cli list`)");
        return USAGE;
    };
    let _ = writeln!(io.stdout, "{cmd} — {desc}  (tx type {tx_type})\nJSON fields (default: JSON in/out; --json-input reads them on stdin; positional order matches):");
    let mut sample = Map::new();
    for p in &params {
        let req = if p.required { "(required) " } else { "(optional) " };
        let def = p.default.as_deref().filter(|d| !d.is_empty()).map(|d| format!("  [default: {d}]")).unwrap_or_default();
        let _ = writeln!(io.stdout, "  {:<18}{req}{}{def}", p.name, p.help);
        sample.insert(p.name.clone(), json!(p.default.clone().filter(|d| !d.is_empty()).unwrap_or_else(|| "...".into())));
    }
    let _ = writeln!(io.stdout, "Sample: {}\nRun with --verbose to be prompted for each field and get human-readable output.", Value::Object(sample));
    0
}

const USAGE_TEXT: &str = "Options:
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
  JSON errors carry the same code as \"exit_code\" and its name as \"error_class\".
";

fn print_usage(cmd: &str, params: &[ParamDef], io: &mut Io) {
    let args: String = params.iter().map(|p| if p.required { format!(" <{}>", p.name) } else { format!(" [{}]", p.name) }).collect();
    let list: String = params.iter().map(|p| format!("  {:<22}{}\n", p.name, p.help)).collect();
    let _ = write!(io.stdout, "zbc-cli {cmd}\n\nUsage:\n  zbc-cli {cmd} [options]{args} [fee] [api_url]\n\n{USAGE_TEXT}\nParameters:\n{list}");
}

fn message_bytes(text: &str, hex_in: bool) -> Result<Vec<u8>, ToolError> {
    if !hex_in {
        return Ok(text.as_bytes().to_vec());
    }
    if !is_hex(text, 0) {
        return Err(usage("--hex message is not valid hex"));
    }
    Ok(hex::decode(text).unwrap())
}

fn run_sign_message(v: &Params, o: &Options, io: &mut Io) -> Result<i32, ToolError> {
    let kp = KeyPair::from_hex(&v["sender_privkey"]).map_err(|_| usage("Private key must be 64 hex characters (32 bytes)"))?;
    let s = sign_message(&kp, &message_bytes(&v["message"], o.hex)?);
    if o.verbose {
        let _ = write!(io.stdout, "Address:   {}\nDigest:    {}\nSignature: {}\n", s.address, s.digest, s.signature);
        return Ok(0);
    }
    let mut m = Map::new();
    m.insert("success".into(), json!(true));
    m.insert("scheme".into(), json!(s.scheme));
    m.insert("address".into(), json!(s.address));
    m.insert("public_key".into(), json!(s.public_key));
    m.insert("message_hex".into(), json!(s.message_hex));
    m.insert("digest".into(), json!(s.digest));
    m.insert("signature".into(), json!(s.signature));
    if !o.hex {
        m.insert("message".into(), json!(v["message"]));
    }
    out(io, &Value::Object(m));
    Ok(0)
}

fn run_verify_message(v: &Params, o: &Options, io: &mut Io) -> Result<i32, ToolError> {
    let pub_key = public_key_of_address(&v["address"]).ok_or_else(|| usage("address must be a ZBC_ account (Ed25519) address"))?;
    let msg = message_bytes(&v["message"], o.hex)?;
    if !is_hex(&v["signature"], 0) {
        return Err(usage("signature must be hex"));
    }
    if v["signature"].len() != 128 {
        return Err(usage("signature must be 64 bytes (128 hex characters)"));
    }
    let valid = verify_message(&v["address"], &msg, &hex::decode(&v["signature"]).unwrap());
    let address = encode_zbc_address(&pub_key, "ZBC").unwrap();
    let code = if valid { OK } else { VERIFY_FAILED };
    if o.verbose {
        let _ = writeln!(io.stdout, "{} signature for {address}", if valid { "VALID" } else { "INVALID" });
        return Ok(code);
    }
    out(io, &json!({"success": true, "valid": valid, "scheme": SCHEME, "address": address, "digest": hex::encode(message_digest(&msg)),
                    "exit_code": code, "error_class": error_class(code)}));
    Ok(code)
}

fn signing_context(o: &Options, client: &Client, io: &Io) -> Result<SigningContext, ToolError> {
    let g = if o.genesis.is_empty() { (io.env)("ZOOBC_GENESIS_HASH").unwrap_or_default() } else { o.genesis.clone() };
    if !g.is_empty() {
        return SigningContext::of(&g).map_err(usage);
    }
    client.signing_rule().map_err(|e| {
        if e.code == NODE_UNREACHABLE || e.code == TIMEOUT {
            let verb = if e.code == TIMEOUT { "timed out reading" } else { "cannot read" };
            ToolError::new(e.code, format!("{verb} /api/v1/node/info from {} to learn which chain to sign for; pass --genesis <hex> to sign for a known chain", o.api))
        } else { e }
    })
}

fn run_transaction(def: &TxDef, v: &mut Params, o: &Options, io: &mut Io) -> Result<i32, ToolError> {
    for p in &def.params {
        let cur = v.get(&p.name).cloned().unwrap_or_default();
        if !cur.is_empty() || p.required {
            v.insert(p.name.clone(), validate_param(p, &cur)?);
        }
    }
    if o.encrypt {
        return Err(usage("--encrypt is not available in this implementation yet; send the message in clear or use the C++ tools"));
    }
    let sender = KeyPair::from_hex(&v[&def.sender_key]).map_err(usage)?;
    let client = Client::new(&o.api, o.timeout);
    let ctx = signing_context(o, &client, io)?;
    let timestamp = o.timestamp.unwrap_or_else(|| SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0));
    let mut recipient = Vec::new();
    let mut extra = Map::new();
    if def.recipient == "required" {
        let r = parse_address(&v["recipient"], &o.chain).map_err(|e| usage(format!("invalid recipient address: {e}")))?;
        recipient = r.bytes();
        extra.insert("recipient".into(), json!(r.display));
        extra.insert("recipient_type".into(), json!(r.type_name()));
    }
    if let Some(t) = &o.token {
        if def.command != "liquid-payment" {
            return Err(usage("--token applies to liquid-payment only"));
        }
        v.insert("token_id".into(), t.clone());
    }
    let mut files = HashMap::new();
    for p in &def.params {
        if p.kind == "file" {
            let b = std::fs::read(&v[&p.name]).map_err(|_| usage(format!("cannot read {}: {}", p.name, v[&p.name])))?;
            files.insert(p.name.clone(), b);
        }
    }
    let block = if def.needs_node { Some(client.latest_block()?) } else { None };
    let input = CustomInput { def, params: v, sender: &sender, ctx: &ctx, timestamp, block: block.as_ref() };
    let body = if matches!(def.custom.as_deref(), Some("multisig") | Some("settle")) {
        let (b, more) = custom_body(&input)?;
        extra.extend(more);
        b
    } else {
        let mut bc = BodyContext { sender: Some(sender.clone()), files, computed: HashMap::new() };
        extra.extend(compute_fields(&input, &mut bc)?);
        build_body(def, v, &bc)?
    };
    for p in &def.params {
        if p.kind == "privkey" || p.kind == "file" || p.name == "recipient" || extra.contains_key(&p.name) {
            continue;
        }
        let val = v.get(&p.name).cloned().unwrap_or_default();
        let is_num = matches!(p.kind.as_str(), "int64" | "uint64" | "uint32" | "uint8") && is_int(&val);
        extra.insert(p.name.clone(), if is_num { json!(val.parse::<i64>().unwrap_or(0)) } else { json!(val) });
    }
    if def.command == "approve-escrow" {
        extra.insert("escrowed_transaction_hash".into(), json!(v["transaction_hash"]));
        extra.insert("transaction_id".into(), json!(transaction_id(&hex::decode(&v["transaction_hash"]).unwrap())));
        extra.remove("transaction_hash");
    }
    extra.insert("sender".into(), json!(sender.address()));
    let tx = Unsigned { tx_type: def.tx_type, timestamp, sender: sender.account_bytes(), recipient, fee: o.fee, body, escrow: o.escrow.clone(),
                        message: o.message.clone().unwrap_or_default().into_bytes(), version: 1 };
    let signed = sign_transaction(&tx, &sender, &ctx).map_err(|e| usage(format!("Invalid escrow approver: {e}")))?;
    let mut fields = Map::new();
    fields.insert("transaction_hash".into(), json!(hex::encode(signed.hash)));
    fields.insert("transaction_type".into(), json!(def.tx_type));
    fields.insert("sender_account_address".into(), json!(signed.payload.sender_account_address));
    fields.insert("recipient_account_address".into(), json!(signed.payload.recipient_account_address));
    fields.insert("fee".into(), json!(o.fee));
    fields.insert("timestamp".into(), json!(timestamp));
    let mut common = Map::new();
    if let Some(m) = &o.message {
        if !m.is_empty() {
            common.insert("message".into(), json!(m));
        }
    }
    if let Some(e) = &signed.payload.escrow {
        common.insert("escrow".into(), serde_json::to_value(e).unwrap());
    }
    common.extend(extra);
    if o.offline {
        if o.verbose {
            let g = if signed.genesis_hash.is_empty() { String::new() } else { format!(" (genesis {})", hex::encode(&signed.genesis_hash)) };
            let _ = write!(io.stdout, "OFFLINE: transaction built and signed, not submitted\n\nTransaction hash:  {}\nSigning version:   {}{g}\nTimestamp:         {timestamp}\nUnsigned bytes:    {}\nDigest:            {}\nSignature:         {}\nTransaction bytes: {}\nPayload:           {}\n",
                hex::encode(signed.hash), signed.signing_version, hex::encode(&signed.unsigned), hex::encode(signed.digest), hex::encode(signed.signature), hex::encode(&signed.bytes), serde_json::to_string(&signed.payload).unwrap());
            return Ok(0);
        }
        let mut m = Map::new();
        m.insert("success".into(), json!(true));
        m.insert("offline".into(), json!(true));
        m.extend(fields);
        m.insert("signing_version".into(), json!(signed.signing_version));
        if !signed.genesis_hash.is_empty() {
            m.insert("genesis_hash".into(), json!(hex::encode(&signed.genesis_hash)));
        }
        m.insert("unsigned_bytes".into(), json!(hex::encode(&signed.unsigned)));
        m.insert("digest".into(), json!(hex::encode(signed.digest)));
        m.insert("signature".into(), json!(hex::encode(signed.signature)));
        m.insert("transaction_bytes".into(), json!(hex::encode(&signed.bytes)));
        m.insert("payload".into(), serde_json::to_value(&signed.payload).unwrap());
        m.extend(common);
        out(io, &Value::Object(m));
        return Ok(0);
    }
    let (reply, accepted) = client.submit(&signed.payload)?;
    if !accepted {
        let e = rejection_error(&reply);
        if o.verbose {
            let _ = write!(io.stderr, "FAILED: Transaction submission rejected ({})\nHTTP {}: {}\n", error_class(e.code), reply.status, reply.text);
        } else {
            out(io, &e.to_json());
        }
        return Ok(e.code);
    }
    if o.verbose {
        let _ = write!(io.stdout, "SUCCESS: {} submitted!\n\nTransaction Hash: {}\n", def.command, hex::encode(signed.hash));
        return Ok(0);
    }
    let mut m = Map::new();
    m.insert("success".into(), json!(true));
    m.extend(fields);
    m.insert("api_response".into(), reply.body());
    m.extend(common);
    out(io, &Value::Object(m));
    Ok(0)
}

/// The combined command with explicit streams (what the tests use).
pub fn run_with(args: &[String], io: &mut Io) -> i32 {
    if args.is_empty() {
        let _ = write!(io.stdout, "ZooBC unified transaction CLI\nUsage: zbc-cli <command> <params...> [--api URL] [--fee N] [--timeout S] [--verbose] [--json-input]\n       zbc-cli list   (show all commands)      zbc-cli <command> --help  (options, env vars, exit codes)\n");
        return USAGE;
    }
    let cmd = args[0].as_str();
    if cmd == "help" && args.len() >= 2 {
        return print_help(&args[1], io);
    }
    if matches!(cmd, "list" | "--help" | "-h" | "help") {
        print_list(io);
        return 0;
    }
    if command_of(cmd).is_none() {
        let _ = writeln!(io.stderr, "Unknown command: {cmd} (try `zbc-cli list`)");
        return USAGE;
    }
    run_tool_with(cmd, &args[1..], io)
}

/// One command with explicit streams.
pub fn run_tool_with(cmd: &str, args: &[String], io: &mut Io) -> i32 {
    let Some((_, params, _)) = command_of(cmd) else {
        let _ = writeln!(io.stderr, "Unknown command: {cmd} (try `zbc-cli list`)");
        return USAGE;
    };
    let mut verbose = false;
    let result = (|| -> Result<i32, ToolError> {
        let (positional, mut o) = parse_args(args, io)?;
        verbose = o.verbose;
        if o.help {
            print_usage(cmd, &params, io);
            return Ok(0);
        }
        let mut values = resolve_params(&params, &positional, &mut o, io)?;
        verbose = o.verbose;
        match cmd {
            "sign-message" => run_sign_message(&values, &o, io),
            "verify-message" => run_verify_message(&values, &o, io),
            _ => run_transaction(command(cmd).unwrap(), &mut values, &o, io),
        }
    })();
    match result {
        Ok(code) => code,
        Err(e) => emit_error(io, &e, verbose),
    }
}

fn process_io<F: FnOnce(&mut Io) -> i32>(f: F) -> i32 {
    use std::io::IsTerminal;
    let is_tty = std::io::stdin().is_terminal();
    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let env = |k: &str| std::env::var(k).ok();
    let mut io = Io { stdin: &mut stdin, stdout: &mut stdout, stderr: &mut stderr, env: &env, is_tty };
    let code = f(&mut io);
    let _ = io.stdout.flush();
    code
}

/// zbc-cli on the process's streams: arguments without the program name. Returns the exit code.
pub fn run(args: &[String]) -> i32 {
    process_io(|io| run_with(args, io))
}

/// One command on the process's streams (the per-tool programs use it).
pub fn run_tool(cmd: &str, args: &[String]) -> i32 {
    process_io(|io| run_tool_with(cmd, args, io))
}
