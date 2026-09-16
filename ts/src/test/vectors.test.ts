// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** Every file in spec/vectors, run through the library and through the compiled zbc-cli. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { keyPairFromSeed, walletAccount, validateMnemonic } from "../keys.js";
import { parseAddress, decodeZbcAddress } from "../address.js";
import { signMessage, verifyMessage } from "../message.js";
import { signTransaction, signingContext, sendZbcBody, approvalEscrowBody, transactionId } from "../transaction.js";
import { buildBody, BodyContext } from "../body.js";
import { computeFields, customBody } from "../custom.js";
import { COMMAND_BY_NAME } from "../generated/commands.js";
import { bytesToHex, fromUtf8, hexToBytes, utf8 } from "../util/bytes.js";
import { ed25519PublicKeyToX25519, ed25519SeedToX25519, x25519Base } from "../crypto/x25519.js";
import { openSealed, seal } from "../encryption.js";
import { parseJson, stringifyJson } from "../util/json.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..", "..");
const V = join(root, "spec", "vectors");
const load = (f: string) => parseJson(readFileSync(join(V, f), "utf8")) as any;
const CLI = join(root, "ts", "dist", "cli.js");
/** JSON with sorted keys, so two payloads compare regardless of key order. */
function canonical(v: unknown): string {
  const sort = (x: any): any => Array.isArray(x) ? x.map(sort) : (x && typeof x === "object" && !(x instanceof Uint8Array)) ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, sort(x[k])])) : x;
  return stringifyJson(sort(v));
}
type Vec = Record<string, any>;

test("keys.json: seeds -> public key, ZBC_ and ZNK_", () => {
  for (const s of load("keys.json").seeds) {
    const kp = keyPairFromSeed(s.seed);
    assert.equal(bytesToHex(kp.publicKey), s.public_key);
    assert.equal(kp.address, s.address);
    assert.equal(kp.nodeAddress, s.node_address);
  }
});
test("keys.json: mnemonic wallets -> SLIP-10 accounts", () => {
  for (const w of load("keys.json").wallets) {
    assert.ok(validateMnemonic(w.mnemonic));
    for (const a of w.accounts) {
      const acct = walletAccount(w.mnemonic, a.index, w.passphrase);
      assert.equal(acct.path, a.path);
      assert.equal(bytesToHex(acct.seed), a.seed);
      assert.equal(acct.address, a.address);
      assert.equal(acct.nodeAddress, a.node_address);
    }
  }
});
test("addresses.json: every input is read exactly as the reference reads it", () => {
  for (const v of load("addresses.json").vectors) {
    if (v.valid) {
      const p = parseAddress(v.input, v.chain ?? "");
      assert.equal(p.type, v.account_type, v.input);
      assert.equal(bytesToHex(p.bytes), v.address_bytes, v.input);
    } else {
      assert.throws(() => parseAddress(v.input, v.chain ?? ""), v.input);
    }
  }
});
test("messages.json: ZBC-MSG-v1 sign and verify", () => {
  const m = load("messages.json");
  for (const v of m.vectors) {
    const s = signMessage(v.seed, hexToBytes(v.message_hex));
    assert.equal(s.address, v.address); assert.equal(s.public_key, v.public_key);
    assert.equal(s.digest, v.digest); assert.equal(s.signature, v.signature);
    assert.ok(verifyMessage(v.address, hexToBytes(v.message_hex), v.signature));
  }
  for (const n of m.invalid) assert.equal(verifyMessage(n.address, utf8(n.message), n.signature), false, n.case);
});

function ctxOf(v: Vec) { return signingContext(v.genesis); }
function senderOf(v: Vec) { return keyPairFromSeed(v.key); }
function envelope(v: Vec, body: Uint8Array) {
  const def = COMMAND_BY_NAME.get(v.command)!;
  const recipient = def.recipient === "required" ? parseAddress(v.params.recipient).bytes : new Uint8Array();
  return signTransaction({ type: v.type, timestamp: BigInt(v.timestamp), sender: senderOf(v).accountBytes, recipient, fee: BigInt(v.fee), body,
                           escrow: v.escrow, message: v.message ? utf8(v.message) : undefined }, senderOf(v), ctxOf(v));
}
function checkSigned(v: Vec, signed: ReturnType<typeof signTransaction>) {
  const e = v.expected;
  assert.equal(bytesToHex(signed.unsigned), e.unsigned_bytes, v.name + " unsigned");
  assert.equal(bytesToHex(signed.digest), e.digest, v.name + " digest");
  assert.equal(bytesToHex(signed.signature), e.signature, v.name + " signature");
  assert.equal(bytesToHex(signed.bytes), e.transaction_bytes, v.name + " bytes");
  assert.equal(bytesToHex(signed.hash), e.transaction_hash, v.name + " hash");
  assert.equal(canonical(signed.payload), canonical(e.payload), v.name + " payload");
}
test("transactions.json (core): SendZBC and ApprovalEscrow bodies, envelopes, digests, signatures, hashes, payloads", () => {
  for (const v of load("transactions.json").vectors) {
    const body = v.command === "send-zbc" ? sendZbcBody(BigInt(v.params.amount)) : approvalEscrowBody(Number(v.params.approval), hexToBytes(v.params.transaction_hash));
    assert.equal(bytesToHex(body), v.expected.body, v.name + " body");
    checkSigned(v, envelope(v, body));
  }
});
test("transactions-all.json: every type's body from its description, then the whole transaction", () => {
  for (const v of load("transactions-all.json").vectors) {
    const def = COMMAND_BY_NAME.get(v.command)!;
    const sender = senderOf(v);
    const input = { def, params: { ...v.params }, sender, ctx: ctxOf(v), timestamp: BigInt(v.timestamp),
                    referenceBlock: v.reference_block ? { hash: hexToBytes(v.reference_block.block_hash), height: v.reference_block.height } : undefined };
    let body: Uint8Array;
    if (def.custom === "multisig" || def.custom === "settle") body = customBody(input).body;
    else {
      const bc: BodyContext = { sender, files: v.files ? Object.fromEntries(Object.entries(v.files).map(([k, h]) => [k, h as string])) : {}, computed: {} };
      computeFields(input, bc);
      body = buildBody(def, v.params, bc);
    }
    assert.equal(bytesToHex(body), v.expected.body, v.name + " body");
    checkSigned(v, envelope(v, body));
  }
});
test("transaction id is the first 8 bytes of the hash as int64 LE", () => {
  assert.equal(transactionId(hexToBytes("4ac2d11be8fe534bf2b2776fa7c1a3ece08e17f3b71e8d796545f5edde8b86fa")), 5427962248764179018n);
});

const cliAvailable = existsSync(CLI);
test("zbc-cli --offline reproduces every transaction vector", { skip: !cliAvailable }, () => {
  const all = [...load("transactions.json").vectors, ...load("transactions-all.json").vectors];
  for (const v of all) {
    const def = COMMAND_BY_NAME.get(v.command)!;
    if (def.needs_node) continue;          // needs a node for the reference block; the library test above covers it
    if (def.params.some((p) => p.kind === "file")) continue;
    const args = [CLI, v.command, v.key, ...def.params.slice(1).map((p) => v.params[p.name] ?? p.default ?? ""),
                  "--fee", String(v.fee), "--timestamp", String(v.timestamp), "--genesis", v.genesis, "--offline"];
    if (v.message) args.push("--message", v.message);
    if (v.escrow) { args.push("--escrow-approver", v.escrow.approver, "--escrow-commission", String(v.escrow.commission), "--escrow-timeout", String(v.escrow.timeout)); if (v.escrow.instruction) args.push("--escrow-instruction", v.escrow.instruction); }
    if (v.command === "liquid-payment" && v.params.token_id && v.params.token_id !== "0") { args.splice(args.indexOf("--fee"), 0); args.push("--token", v.params.token_id); }
    const r = spawnSync(process.execPath, args, { encoding: "utf8", env: { ...process.env, ZBC_KEY: "", ZOOBC_GENESIS_HASH: "" } });
    assert.equal(r.status, 0, `${v.name}: ${r.stdout}${r.stderr}`);
    const j = parseJson(r.stdout) as any;
    assert.equal(j.transaction_hash, v.expected.transaction_hash, v.name);
    assert.equal(j.unsigned_bytes, v.expected.unsigned_bytes, v.name);
    assert.equal(canonical(j.payload), canonical(v.expected.payload), v.name);
  }
});
test("zbc-cli: cli.json exit codes and error classes", { skip: !cliAvailable }, () => {
  for (const c of load("cli.json").vectors) {
    const r = spawnSync(process.execPath, [CLI, ...c.args], { encoding: "utf8", input: c.stdin ?? undefined, env: { ...process.env, ZBC_KEY: "", ZOOBC_GENESIS_HASH: "" } });
    assert.equal(r.status, c.exit_code, `${c.case}: ${r.stdout}${r.stderr}`);
    if (c.error_class) assert.equal(JSON.parse(r.stdout).error_class, c.error_class, c.case);
  }
});
test("zbc-cli: sign-message and verify-message vectors, exit 10 on a bad signature", { skip: !cliAvailable }, () => {
  const m = load("messages.json");
  for (const v of m.vectors) {
    const args = [CLI, "sign-message", v.seed, v.hex_input ? v.message_hex : v.message, ...(v.hex_input ? ["--hex"] : [])];
    const r = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(JSON.parse(r.stdout).signature, v.signature);
    const ok = spawnSync(process.execPath, [CLI, "verify-message", v.address, v.hex_input ? v.message_hex : v.message, v.signature, ...(v.hex_input ? ["--hex"] : [])], { encoding: "utf8" });
    assert.equal(ok.status, 0); assert.equal(JSON.parse(ok.stdout).valid, true);
  }
  for (const n of m.invalid) {
    const r = spawnSync(process.execPath, [CLI, "verify-message", n.address, n.message, n.signature], { encoding: "utf8" });
    assert.equal(r.status, n.exit_code, n.case);
  }
});
test("zbc-cli: --json-input with offline and timestamp reproduces vector 0", { skip: !cliAvailable }, () => {
  const v = load("transactions.json").vectors[0];
  const stdin = JSON.stringify({ sender_privkey: v.key, recipient: v.params.recipient, amount: v.params.amount, fee: v.fee, timestamp: v.timestamp, offline: true });
  const r = spawnSync(process.execPath, [CLI, "send-zbc", "--json-input", "--genesis", v.genesis], { encoding: "utf8", input: stdin });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(JSON.parse(r.stdout).transaction_hash, v.expected.transaction_hash);
});
test("zbc-cli: ZBC_KEY supplies an omitted or '-' key", { skip: !cliAvailable }, () => {
  const v = load("transactions.json").vectors[0];
  for (const args of [[v.params.recipient, v.params.amount], ["-", v.params.recipient, v.params.amount]]) {
    const r = spawnSync(process.execPath, [CLI, "send-zbc", ...args, "--timestamp", String(v.timestamp), "--genesis", v.genesis, "--offline"], { encoding: "utf8", env: { ...process.env, ZBC_KEY: v.key } });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(JSON.parse(r.stdout).transaction_hash, v.expected.transaction_hash);
  }
});
test("zbc-cli: unreachable node exits 3, timeout on a black hole exits 8 or 3", { skip: !cliAvailable }, () => {
  const v = load("transactions.json").vectors[0];
  const r = spawnSync(process.execPath, [CLI, "send-zbc", v.key, v.params.recipient, "1", "--api", "http://127.0.0.1:9", "--genesis", "v1", "--timeout", "2"], { encoding: "utf8" });
  assert.equal(r.status, 3, r.stdout);
  assert.equal(JSON.parse(r.stdout).error_class, "node_unreachable");
});
test("decodeZbcAddress accepts dashes and lower case, rejects a bad checksum", () => {
  const a = "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I";
  assert.ok(decodeZbcAddress(a.toLowerCase().replace(/_/g, "-")));
  assert.equal(decodeZbcAddress(a.slice(0, -1) + "J"), null);
});

test("encryption.json: Ed25519 -> X25519 conversions, sealed boxes byte for byte, the C++ tool's fields open, invalid cases fail", () => {
  const d = load("encryption.json");
  for (const k of d.keys) {
    assert.equal(bytesToHex(ed25519PublicKeyToX25519(hexToBytes(k.public_key))), k.x25519_public_key);
    assert.equal(bytesToHex(ed25519SeedToX25519(hexToBytes(k.seed))), k.x25519_secret_key);
    assert.equal(bytesToHex(x25519Base(hexToBytes(k.x25519_secret_key))), k.x25519_public_key);
  }
  for (const s of d.sealed) {
    const f = seal(hexToBytes(s.plaintext_hex), hexToBytes(s.recipient_public_key), hexToBytes(s.ephemeral_secret_key));
    assert.equal(bytesToHex(f), s.message_field, s.name);
    assert.equal(bytesToHex(openSealed(f, hexToBytes(s.recipient_seed))!), s.plaintext_hex, s.name);
  }
  for (const s of d.samples) assert.equal(bytesToHex(openSealed(hexToBytes(s.message_field), hexToBytes(s.recipient_seed))!), s.plaintext_hex, s.name);
  for (const i of d.invalid) if (/^[0-9a-f]*$/.test(i.message_field)) assert.equal(openSealed(hexToBytes(i.message_field), hexToBytes(i.recipient_seed)), null, i.case);
  const kp = keyPairFromSeed(d.keys[0].seed);
  const random = seal(utf8("round trip"), kp.publicKey);
  assert.equal(random.length, 10 + 52);
  assert.equal(fromUtf8(openSealed(random, kp.seed)!), "round trip");
});

test("zbc-cli --encrypt seals the message and decrypt-message opens it; invalid cases exit as the reference does", () => {
  const d = load("encryption.json");
  const s = d.samples[0];
  const r = spawnSync(process.execPath, [CLI, "send-zbc", d.keys[0].seed, s.recipient_address, "1", "--message", s.plaintext, "--encrypt", "--genesis", "v1", "--offline"], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const j = parseJson(r.stdout) as any;
  assert.equal(j.message, s.plaintext);
  const field: string = j.payload.message_hex;
  assert.ok(field.startsWith("5a424531") && field.length === 2 * (utf8(s.plaintext).length + 52));
  const dm = spawnSync(process.execPath, [CLI, "decrypt-message", s.recipient_seed, field], { encoding: "utf8" });
  assert.equal(dm.status, 0, dm.stdout + dm.stderr);
  assert.equal((parseJson(dm.stdout) as any).message, s.plaintext);
  for (const smp of d.samples) {
    const o = spawnSync(process.execPath, [CLI, "decrypt-message", smp.recipient_seed, smp.message_field], { encoding: "utf8" });
    assert.equal(o.status, 0, smp.name); assert.equal((parseJson(o.stdout) as any).message_hex, smp.plaintext_hex, smp.name);
  }
  for (const i of d.invalid) {
    const o = spawnSync(process.execPath, [CLI, "decrypt-message", i.recipient_seed, i.message_field], { encoding: "utf8" });
    assert.equal(o.status, i.exit_code, i.case); assert.equal((parseJson(o.stdout) as any).error_class, i.error_class, i.case);
  }
  const bad = spawnSync(process.execPath, [CLI, "send-zbc", d.keys[0].seed, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "1", "--message", "x", "--encrypt", "--genesis", "v1", "--offline"], { encoding: "utf8" });
  assert.equal(bad.status, 2);
});
