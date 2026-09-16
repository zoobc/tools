#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** zbc-cli: every transaction as a subcommand, plus sign-message and verify-message (spec/cli-contract.md). */
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { Client } from "./api.js";
import { parseAddress } from "./address.js";
import { buildBody, validateParam, BodyContext } from "./body.js";
import { computeFields, customBody } from "./custom.js";
import { ExitCode, ToolError, usage } from "./errors.js";
import { keyPairFromSeed, KeyPair } from "./keys.js";
import { MESSAGE_SIGNING_SCHEME, messageDigest, publicKeyOfAddress, signMessage, verifyMessage } from "./message.js";
import { COMMANDS, COMMAND_BY_NAME } from "./generated/commands.js";
import { EscrowTerms, SigningContext, signingContext, signTransaction, transactionId, UnsignedTransaction } from "./transaction.js";
import { bytesToHex, fromUtf8, hexToBytes, isHex, utf8 } from "./util/bytes.js";
import { isSealed, openSealed, seal } from "./encryption.js";
import { stringifyJson } from "./util/json.js";
import { ParamDef, TxDef } from "./spec.js";

interface Options {
  api: string; fee: bigint; timeout: number; genesis: string; jsonInput: boolean; verbose: boolean;
  message: string | null; encrypt: boolean; chain: string; escrow: Partial<EscrowTerms> & { set: boolean };
  hex: boolean; offline: boolean; timestamp: bigint | null; token: string | null; help: boolean;
}
const DEFAULT_FEE = 5000000n;

const CATEGORY: Record<string, string> = {
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
};
const MESSAGE_COMMANDS: Record<string, { desc: string; params: ParamDef[] }> = {
  "sign-message": { desc: "Sign a message with a private key (ZBC-MSG-v1, off-chain, no node needed)", params: [
    { name: "sender_privkey", kind: "privkey", required: true, help: "Sender private key (64 hex)" },
    { name: "message", kind: "string", required: true, help: "text to sign (hex bytes with --hex)" }] },
  "verify-message": { desc: "Verify a ZBC-MSG-v1 message signature against a ZBC_ address (off-chain)", params: [
    { name: "address", kind: "string", required: true, help: "signer's ZBC_ address (or 64-hex public key)" },
    { name: "message", kind: "string", required: true, help: "the signed text (hex bytes with --hex)" },
    { name: "signature", kind: "string", required: true, help: "64-byte Ed25519 signature, 128 hex" }] },
  "decrypt-message": { desc: "Decrypt a transaction message sealed with --encrypt, with the recipient's private key (off-chain)", params: [
    { name: "sender_privkey", kind: "privkey", required: true, help: "the recipient's private key (64 hex); '-' or omitted = ZBC_KEY" },
    { name: "message_hex", kind: "string", required: true, help: "the transaction's message field as hex: ZBE1 then the sealed box" }] },
};

// ---- output ----------------------------------------------------------------------------------------
function jsonOut(o: unknown): void { process.stdout.write(stringifyJson(o, 2) + "\n"); }
function emitError(e: ToolError, verbose: boolean): number {
  if (verbose) process.stderr.write("Error: " + e.message + "\n"); else jsonOut(e.toJSON());
  return e.code;
}

// ---- argument parsing -------------------------------------------------------------------------------
function parseArgs(argv: string[]): { positional: string[]; o: Options } {
  const o: Options = { api: process.env.ZBC_API || "http://localhost:8080", fee: DEFAULT_FEE, timeout: 20, genesis: "", jsonInput: false, verbose: false,
                       message: null, encrypt: false, chain: "", escrow: { set: false }, hex: false, offline: false, timestamp: null, token: null, help: false };
  if (process.env.ZBC_TIMEOUT && /^\d+$/.test(process.env.ZBC_TIMEOUT) && Number(process.env.ZBC_TIMEOUT) > 0) o.timeout = Number(process.env.ZBC_TIMEOUT);
  const positional: string[] = [];
  const need = (i: number, what: string): string => { if (i + 1 >= argv.length) throw usage(`${argv[i]} requires a value${what}`); return argv[i + 1]; };
  const integer = (s: string, what: string): bigint => { if (!/^-?\d+$/.test(s)) throw usage(what); return BigInt(s); };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "-v": case "--verbose": o.verbose = true; break;
      case "--json": o.verbose = false; break;
      case "--json-input": o.jsonInput = true; break;
      case "--encrypt": o.encrypt = true; break;
      case "--hex": o.hex = true; break;
      case "--offline": o.offline = true; break;
      case "-h": case "--help": o.help = true; break;
      case "--message": o.message = need(i, ""); i++; break;
      case "--fee": o.fee = integer(need(i, ""), "--fee must be a whole number of atomic units"); i++; break;
      case "--api": o.api = need(i, ""); i++; break;
      case "--timeout": case "--timeout-seconds": {
        const v = need(i, " (seconds)"); i++;
        if (!/^\d+$/.test(v)) throw usage(`${a} must be a whole number of seconds`);
        o.timeout = Number(v); if (o.timeout <= 0) throw usage(`${a} must be > 0`); break;
      }
      case "--genesis": o.genesis = need(i, ""); i++; break;
      case "--chain": o.chain = need(i, ""); i++; break;
      case "--token": o.token = need(i, ""); i++; break;
      case "--timestamp": {
        const v = need(i, " (Unix seconds)"); i++;
        o.timestamp = integer(v, "--timestamp must be a whole number of Unix seconds");
        if (o.timestamp <= 0n) throw usage("--timestamp must be > 0"); break;
      }
      case "--escrow-approver": o.escrow.approver = need(i, ""); o.escrow.set = true; i++; break;
      case "--escrow-commission": o.escrow.commission = integer(need(i, ""), "--escrow-commission must be a whole number of atomic units"); o.escrow.set = true; i++; break;
      case "--escrow-timeout": o.escrow.timeout = integer(need(i, ""), "--escrow-timeout must be a Unix timestamp in seconds"); o.escrow.set = true; i++; break;
      case "--escrow-instruction": o.escrow.instruction = need(i, ""); o.escrow.set = true; i++; break;
      default:
        if (a.length > 1 && a[0] === "-" && !/[0-9.]/.test(a[1])) throw usage("Unknown option: " + a);
        positional.push(a);
    }
  }
  if (o.offline && !o.genesis && !process.env.ZOOBC_GENESIS_HASH) throw usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node");
  if (o.escrow.set) {
    if (!o.escrow.approver) throw usage("Escrow requires --escrow-approver");
    if (!o.escrow.timeout || o.escrow.timeout <= 0n) throw usage("Escrow requires --escrow-timeout > 0");
    if ((o.escrow.commission ?? 0n) < 0n) throw usage("Escrow commission cannot be negative");
    o.escrow.commission ??= 0n;
  }
  return { positional, o };
}

const isKeyPlaceholder = (s: string): boolean => s === "-" || s === "@env" || s === "env:ZBC_KEY";

/** Resolve parameter values from positionals, stdin JSON or prompts. */
async function resolveParams(params: ParamDef[], positional: string[], o: Options): Promise<{ values: Record<string, string>; extraPositional: string[] }> {
  const values: Record<string, string> = {};
  const keyIsFirst = params.length > 0 && params[0].name === "sender_privkey";
  const envKey = keyIsFirst ? (process.env.ZBC_KEY || "") : "";
  let extraPositional: string[] = [];
  if (o.jsonInput) {
    const text = readFileSync(0, "utf8").trim();
    if (!text) throw usage("No JSON input received on stdin");
    let j: Record<string, unknown>;
    try { j = JSON.parse(text); } catch { throw usage("Invalid JSON input"); }
    if (typeof j !== "object" || j === null || Array.isArray(j)) throw usage("Invalid JSON input");
    for (const p of params) {
      if (p.name in j) values[p.name] = typeof j[p.name] === "string" ? (j[p.name] as string) : JSON.stringify(j[p.name]);
      else if (p.default !== undefined && p.default !== "") values[p.name] = p.default;
      else if (p.name === "sender_privkey" && envKey) values[p.name] = envKey;
      else if (p.required) throw usage("Missing required field: " + p.name);
      else values[p.name] = "";
      if (keyIsFirst && p.name === "sender_privkey" && isKeyPlaceholder(values[p.name])) {
        if (!envKey) throw usage("sender_privkey is '-' but ZBC_KEY is not set");
        values[p.name] = envKey;
      }
    }
    const num = (k: string, what: string): bigint | null => {
      if (!(k in j)) return null;
      const v = j[k]; const s = typeof v === "number" ? String(v) : typeof v === "string" ? v : "";
      if (!/^-?\d+$/.test(s)) throw usage(`${what} must be a whole number`);
      return BigInt(s);
    };
    const fee = num("fee", "fee"); if (fee !== null) o.fee = fee;
    const to = num("timeout_seconds", "timeout_seconds"); if (to !== null) { if (to <= 0n) throw usage("timeout_seconds must be > 0"); o.timeout = Number(to); }
    const ts = num("timestamp", "timestamp"); if (ts !== null) { if (ts <= 0n) throw usage("timestamp must be > 0"); o.timestamp = ts; }
    if (typeof j.offline === "boolean") o.offline = j.offline;
    if (typeof j.api_url === "string") o.api = j.api_url;
    if (typeof j.message === "string") o.message = j.message;
    if (typeof j.hex === "boolean") o.hex = j.hex;
    if (j.verbose === true) o.verbose = true;
    if (j.escrow && typeof j.escrow === "object") {
      const e = j.escrow as Record<string, unknown>;
      o.escrow.set = true;
      if (typeof e.approver === "string") o.escrow.approver = e.approver;
      if (e.commission !== undefined) o.escrow.commission = BigInt(String(e.commission));
      if (e.timeout !== undefined) o.escrow.timeout = BigInt(String(e.timeout));
      if (typeof e.instruction === "string") o.escrow.instruction = e.instruction;
      if (!o.escrow.approver) throw usage("Escrow requires --escrow-approver");
      if (!o.escrow.timeout || o.escrow.timeout <= 0n) throw usage("Escrow requires --escrow-timeout > 0");
      o.escrow.commission ??= 0n;
    }
    if (o.offline && !o.genesis && !process.env.ZOOBC_GENESIS_HASH) throw usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node");
    return { values, extraPositional };
  }
  if (positional.length === 0 && process.stdin.isTTY && o.verbose) {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    for (const p of params) {
      const answer = (await rl.question(`  ${p.help}${p.default ? ` [${p.default}]` : ""}: `)).trim();
      values[p.name] = answer || p.default || "";
      if (p.required && !values[p.name] && !(p.name === "sender_privkey" && envKey)) { rl.close(); throw usage("Missing required argument: " + p.name); }
      if (p.name === "sender_privkey" && (!values[p.name] || isKeyPlaceholder(values[p.name]))) values[p.name] = envKey;
    }
    rl.close();
    return { values, extraPositional };
  }
  const pos = positional.slice();
  if (keyIsFirst) {
    const required = params.filter((p) => p.required && !p.default).length;
    if (pos.length > 0 && isKeyPlaceholder(pos[0])) {
      if (!envKey) throw usage("key argument is '-' but ZBC_KEY is not set");
      pos[0] = envKey;
    } else if (envKey && pos.length + 1 === required) pos.unshift(envKey);
  }
  params.forEach((p, i) => {
    if (i < pos.length) values[p.name] = pos[i];
    else if (p.default !== undefined && p.default !== "") values[p.name] = p.default;
    else if (p.required) throw usage("Missing required argument: " + p.name + (i === 0 && keyIsFirst ? " (pass it, or set ZBC_KEY)" : ""));
    else values[p.name] = "";
  });
  extraPositional = pos.slice(params.length);
  if (extraPositional.length > 0) {
    const feeArg = extraPositional[0];
    if (!/^-?\d+$/.test(feeArg)) throw usage(`Fee must be a whole number of atomic units, got "${feeArg}". The API endpoint is passed with --api URL, not as a positional argument.`);
    o.fee = BigInt(feeArg);
  }
  if (extraPositional.length > 1) o.api = extraPositional[1];
  return { values, extraPositional };
}

// ---- help --------------------------------------------------------------------------------------------
function printList(): void {
  const groups: Record<string, string[]> = {};
  const all = [...COMMANDS.map((c) => [c.command, c.description] as const), ...Object.entries(MESSAGE_COMMANDS).map(([k, v]) => [k, v.desc] as const)];
  for (const [cmd, desc] of all.sort((a, b) => a[0].localeCompare(b[0]))) (groups[CATEGORY[cmd] ?? "other"] ??= []).push(`  ${cmd.padEnd(26)}${desc}`);
  let out = `ZooBC unified transaction CLI — ${all.length} commands.\n  Default: JSON in, JSON out.   --verbose: prompt each field + text output.\n` +
            `  echo '{...}' | zbc-cli <cmd> --json-input     zbc-cli help <cmd>  (fields for one tx)\n\n`;
  for (const g of ["value", "tokens", "exchange", "apps", "storage", "account", "node", "gateway", "governance", "keys", "other"]) {
    if (groups[g]) out += `[${g}]\n${groups[g].join("\n")}\n\n`;
  }
  out += "First param is the sender private key (or set ZBC_KEY and omit it / pass '-'); verify-message takes an address.\n" +
         "`zbc-cli help <cmd>` shows a command's JSON fields; `zbc-cli <cmd> --help` the options, env vars and exit codes.\n";
  process.stdout.write(out);
}
function commandParams(cmd: string): { desc: string; params: ParamDef[]; type: number } | null {
  const m = MESSAGE_COMMANDS[cmd];
  if (m) return { desc: m.desc, params: m.params, type: 0 };
  const d = COMMAND_BY_NAME.get(cmd);
  return d ? { desc: d.description, params: d.params, type: d.type } : null;
}
function printHelp(cmd: string): number {
  const c = commandParams(cmd);
  if (!c) { process.stderr.write(`Unknown command: ${cmd} (try \`zbc-cli list\`)\n`); return ExitCode.usage; }
  let out = `${cmd} — ${c.desc}  (tx type ${c.type})\nJSON fields (default: JSON in/out; --json-input reads them on stdin; positional order matches):\n`;
  const sample: Record<string, string> = {};
  for (const p of c.params) {
    out += `  ${p.name.padEnd(18)}${p.required ? "(required) " : "(optional) "}${p.help}${p.default ? `  [default: ${p.default}]` : ""}\n`;
    sample[p.name] = p.default || "...";
  }
  out += `Sample: ${JSON.stringify(sample)}\nRun with --verbose to be prompted for each field and get human-readable output.\n`;
  process.stdout.write(out);
  return 0;
}
function printUsage(cmd: string, params: ParamDef[]): void {
  const out = `zbc-cli ${cmd}\n\nUsage:\n  zbc-cli ${cmd} [options]${params.map((p) => (p.required ? ` <${p.name}>` : ` [${p.name}]`)).join("")} [fee] [api_url]\n\n` +
`Options:
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

Parameters:
${params.map((p) => `  ${p.name.padEnd(22)}${p.help}`).join("\n")}
`;
  process.stdout.write(out);
}

// ---- message commands ------------------------------------------------------------------------------
function messageBytes(text: string, hex: boolean): Uint8Array {
  if (!hex) return utf8(text);
  if (!isHex(text)) throw usage("--hex message is not valid hex");
  return hexToBytes(text);
}
function runSignMessage(v: Record<string, string>, o: Options): number {
  if (!isHex(v.sender_privkey, 64)) throw usage("Private key must be 64 hex characters (32 bytes)");
  const msg = messageBytes(v.message, o.hex);
  const s = signMessage(v.sender_privkey, msg);
  if (o.verbose) process.stdout.write(`Address:   ${s.address}\nDigest:    ${s.digest}\nSignature: ${s.signature}\n`);
  else jsonOut({ success: true, ...s, ...(o.hex ? {} : { message: v.message }) });
  return 0;
}
function runVerifyMessage(v: Record<string, string>, o: Options): number {
  const pub = publicKeyOfAddress(v.address);
  if (!pub) throw usage("address must be a ZBC_ account (Ed25519) address");
  const msg = messageBytes(v.message, o.hex);
  if (!isHex(v.signature)) throw usage("signature must be hex");
  if (v.signature.length !== 128) throw usage("signature must be 64 bytes (128 hex characters)");
  const valid = verifyMessage(v.address, msg, v.signature);
  const address = parseAddress(bytesToHex(pub)).display;
  const code = valid ? ExitCode.ok : ExitCode.verify_failed;
  if (o.verbose) process.stdout.write(`${valid ? "VALID" : "INVALID"} signature for ${address}\n`);
  else jsonOut({ success: true, valid, scheme: MESSAGE_SIGNING_SCHEME, address, digest: bytesToHex(messageDigest(msg)), exit_code: code, error_class: valid ? "ok" : "verify_failed" });
  return code;
}

function runDecryptMessage(v: Record<string, string>, o: Options): number {
  if (!isHex(v.sender_privkey, 64)) throw usage("Private key must be 64 hex characters (32 bytes)");
  if (!isHex(v.message_hex)) throw usage("message_hex must be hex");
  const field = hexToBytes(v.message_hex);
  if (!isSealed(field)) throw usage("message is not encrypted (no ZBE1 prefix)");
  const plaintext = openSealed(field, hexToBytes(v.sender_privkey));
  if (plaintext === null) throw new ToolError(ExitCode.verify_failed, "decryption failed: the key does not open this message, or it is corrupted");
  const recipient = keyPairFromSeed(v.sender_privkey).address;
  if (o.verbose) process.stdout.write(fromUtf8(plaintext) + "\n");
  else jsonOut({ success: true, recipient, message: fromUtf8(plaintext), message_hex: bytesToHex(plaintext) });
  return 0;
}

// ---- transactions ----------------------------------------------------------------------------------
async function resolveSigningContext(o: Options, client: Client): Promise<SigningContext> {
  const g = o.genesis || process.env.ZOOBC_GENESIS_HASH || "";
  if (g) { try { return signingContext(g); } catch (e) { throw usage((e as Error).message); } }
  try { return await client.signingRule(); } catch (e) {
    if (e instanceof ToolError && (e.code === ExitCode.node_unreachable || e.code === ExitCode.timeout))
      throw new ToolError(e.code, `${e.code === ExitCode.timeout ? "timed out reading" : "cannot read"} /api/v1/node/info from ${o.api} to learn which chain to sign for; pass --genesis <hex> to sign for a known chain`);
    throw e;
  }
}

async function runTransaction(def: TxDef, v: Record<string, string>, o: Options): Promise<number> {
  for (const p of def.params) if (v[p.name] !== "" || p.required) v[p.name] = validateParam(p, v[p.name]);
  const sender: KeyPair = keyPairFromSeed(v[def.sender_key]);
  const client = new Client({ api: o.api, timeoutSeconds: o.timeout });
  const ctx = await resolveSigningContext(o, client);
  const timestamp = o.timestamp ?? BigInt(Math.floor(Date.now() / 1000));
  let recipient: Uint8Array = new Uint8Array();
  const extra: Record<string, unknown> = {};
  if (def.recipient === "required") {
    let r; try { r = parseAddress(v.recipient, o.chain); } catch (e) { throw usage("invalid recipient address: " + (e as Error).message); }
    recipient = r.bytes; extra.recipient = r.display; extra.recipient_type = r.typeName;
  }
  if (o.token !== null) { if (def.command !== "liquid-payment") throw usage("--token applies to liquid-payment only"); v.token_id = o.token; }
  const files: Record<string, string> = {};
  for (const p of def.params) if (p.kind === "file") {
    try { files[p.name] = bytesToHex(new Uint8Array(readFileSync(v[p.name]))); } catch { throw usage(`cannot read ${p.name}: ${v[p.name]}`); }
  }
  const bodyCtx: BodyContext = { sender, files, computed: {} };
  const custom = { def, params: v, sender, ctx, timestamp, referenceBlock: def.needs_node ? await client.latestBlock() : undefined };
  let body: Uint8Array;
  if (def.custom === "multisig" || def.custom === "settle") {
    const r = customBody(custom); body = r.body; Object.assign(extra, r.extra);
  } else {
    Object.assign(extra, computeFields(custom, bodyCtx));
    body = buildBody(def, v, bodyCtx);
  }
  for (const p of def.params) if (p.kind !== "privkey" && p.kind !== "file" && !(p.name in extra) && p.name !== "recipient") {
    const val = v[p.name];
    extra[p.name] = /^(int64|uint64|uint32|uint8)$/.test(p.kind) && /^-?\d+$/.test(val) ? BigInt(val) : val;
  }
  if (def.command === "approve-escrow") {
    extra.escrowed_transaction_hash = v.transaction_hash; extra.transaction_id = transactionId(hexToBytes(v.transaction_hash)); delete extra.transaction_hash;
  }
  extra.sender = sender.address;
  let messageBytes = o.message ? utf8(o.message) : undefined;
  if (o.encrypt && messageBytes && messageBytes.length) {   // --encrypt: seal the message to the recipient's key (signing.md 8)
    if (recipient.length !== 36) throw usage("--encrypt is only supported for ZBC recipients");
    messageBytes = seal(messageBytes, recipient.subarray(4));
  }
  const tx: UnsignedTransaction = { type: def.type, timestamp, sender: sender.accountBytes, recipient, fee: o.fee, body,
                                    escrow: o.escrow.set ? (o.escrow as EscrowTerms) : null, message: messageBytes };
  let signed;
  try { signed = signTransaction(tx, sender, ctx); } catch (e) { throw usage("Invalid escrow approver: " + (e as Error).message); }
  const fields = { transaction_hash: bytesToHex(signed.hash), transaction_type: def.type, sender_account_address: signed.payload.sender_account_address,
                   recipient_account_address: signed.payload.recipient_account_address, fee: o.fee, timestamp };
  const common = { ...(o.message ? { message: o.message } : {}), ...(signed.payload.escrow ? { escrow: signed.payload.escrow } : {}), ...extra };
  if (o.offline) {
    if (o.verbose) {
      process.stdout.write(`OFFLINE: transaction built and signed, not submitted\n\nTransaction hash:  ${fields.transaction_hash}\nSigning version:   ${signed.signingVersion}` +
        (signed.genesisHash ? ` (genesis ${bytesToHex(signed.genesisHash)})` : "") + `\nTimestamp:         ${timestamp}\nUnsigned bytes:    ${bytesToHex(signed.unsigned)}\n` +
        `Digest:            ${bytesToHex(signed.digest)}\nSignature:         ${bytesToHex(signed.signature)}\nTransaction bytes: ${bytesToHex(signed.bytes)}\nPayload:           ${stringifyJson(signed.payload)}\n`);
    } else {
      jsonOut({ success: true, offline: true, ...fields, signing_version: signed.signingVersion, ...(signed.genesisHash ? { genesis_hash: bytesToHex(signed.genesisHash) } : {}),
                unsigned_bytes: bytesToHex(signed.unsigned), digest: bytesToHex(signed.digest), signature: bytesToHex(signed.signature),
                transaction_bytes: bytesToHex(signed.bytes), payload: signed.payload, ...common });
    }
    return 0;
  }
  const r = await client.submit(signed.payload);
  if (!r.accepted) {
    const j = r.body as { error?: unknown } | null;
    const text = j && typeof j === "object" && typeof j.error === "string" ? j.error : r.text;
    const err = new ToolError(classify(r.http_code, text), text, { http_code: r.http_code, api_response: r.body });
    if (o.verbose) process.stderr.write(`FAILED: Transaction submission rejected (${err.errorClass})\nHTTP ${r.http_code}: ${r.text}\n`); else jsonOut(err.toJSON());
    return err.code;
  }
  if (o.verbose) process.stdout.write(`SUCCESS: ${def.command} submitted!\n\nTransaction Hash: ${fields.transaction_hash}\n`);
  else jsonOut({ success: true, ...fields, api_response: r.body, ...common });
  return 0;
}
import { classifyNodeError as classify } from "./errors.js";

// ---- main --------------------------------------------------------------------------------------------
export async function main(argv: string[]): Promise<number> {
  if (argv.length === 0) {
    process.stdout.write("ZooBC unified transaction CLI\nUsage: zbc-cli <command> <params...> [--api URL] [--fee N] [--timeout S] [--verbose] [--json-input]\n" +
                         "       zbc-cli list   (show all commands)      zbc-cli <command> --help  (options, env vars, exit codes)\n");
    return ExitCode.usage;
  }
  const cmd = argv[0];
  if (cmd === "help" && argv.length >= 2) return printHelp(argv[1]);
  if (cmd === "list" || cmd === "--help" || cmd === "-h" || cmd === "help") { printList(); return 0; }
  const c = commandParams(cmd);
  if (!c) { process.stderr.write(`Unknown command: ${cmd} (try \`zbc-cli list\`)\n`); return ExitCode.usage; }
  let verbose = false;
  try {
    const { positional, o } = parseArgs(argv.slice(1));
    verbose = o.verbose;
    if (o.help) { printUsage(cmd, c.params); return 0; }
    const { values } = await resolveParams(c.params, positional, o);
    verbose = o.verbose;
    if (cmd === "sign-message") return runSignMessage(values, o);
    if (cmd === "verify-message") return runVerifyMessage(values, o);
    if (cmd === "decrypt-message") return runDecryptMessage(values, o);
    return await runTransaction(COMMAND_BY_NAME.get(cmd)!, values, o);
  } catch (e) {
    if (e instanceof ToolError) return emitError(e, verbose);
    return emitError(new ToolError(ExitCode.internal, e instanceof Error ? e.message : String(e)), verbose);
  }
}

const isMain = process.argv[1] && /(^|[\\/])(cli\.js|zbc-cli)$/.test(process.argv[1]);
if (isMain) main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
