// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
// Load the bundle the way a page would (a plain script defining a global) and run the vectors it
// can run without a node: keys, addresses, messages, the core transactions. node js/test.cjs
const fs = require("node:fs"), path = require("node:path"), assert = require("node:assert/strict");
const ZBC = require(path.join(__dirname, "zbc.js"));
const V = path.join(__dirname, "..", "spec", "vectors");
const load = (f) => ZBC.parseJson(fs.readFileSync(path.join(V, f), "utf8"));
let n = 0;
for (const s of load("keys.json").seeds) { const kp = ZBC.keyPairFromSeed(s.seed); assert.equal(kp.address, s.address); assert.equal(kp.nodeAddress, s.node_address); n++; }
for (const w of load("keys.json").wallets) for (const a of w.accounts) { assert.equal(ZBC.walletAccount(w.mnemonic, a.index, w.passphrase).address, a.address); n++; }
for (const v of load("addresses.json").vectors) {
  if (v.valid) assert.equal(ZBC.bytesToHex(ZBC.parseAddress(v.input, v.chain ?? "").bytes), v.address_bytes, v.input);
  else assert.throws(() => ZBC.parseAddress(v.input, v.chain ?? ""), v.input);
  n++;
}
{
  const m = load("messages.json");
  for (const v of m.vectors) { const s = ZBC.signMessage(v.seed, ZBC.hexToBytes(v.message_hex), v.genesis_hash); assert.equal(s.signature, v.signature); assert.equal(s.scheme, "ZBC-MSG-v2"); assert.equal(s.genesis_hash, v.genesis_hash); assert.ok(ZBC.verifyMessage(v.address, ZBC.hexToBytes(v.message_hex), v.signature, v.genesis_hash)); n++; }
  for (const v of m.legacy_v1) {   // ZBC-MSG-v1 verifies until the sunset (2026-12-01T00:00:00Z), never after
    const r = ZBC.verifyMessageDetailed(v.address, ZBC.hexToBytes(v.message_hex), v.signature, m.vectors[0].genesis_hash, ZBC.MESSAGE_SIGNING_V1_SUNSET - 1);
    assert.ok(r.valid, v.message); assert.equal(r.scheme, "ZBC-MSG-v1 (accepted until 2026-12-01)");
    assert.equal(ZBC.verifyMessage(v.address, ZBC.hexToBytes(v.message_hex), v.signature, m.vectors[0].genesis_hash, ZBC.MESSAGE_SIGNING_V1_SUNSET), false, v.message); n++;
  }
  for (const i of m.invalid) { assert.equal(ZBC.verifyMessage(i.address, ZBC.utf8(i.message), i.signature, i.genesis_hash), false, i.case); n++; }
}
for (const v of load("transactions.json").vectors) {
  const kp = ZBC.keyPairFromSeed(v.key);
  const body = v.command === "send-zbc" ? ZBC.sendZbcBody(BigInt(v.params.amount)) : ZBC.approvalEscrowBody(Number(v.params.approval), ZBC.hexToBytes(v.params.transaction_hash));
  const recipient = v.command === "send-zbc" ? ZBC.parseAddress(v.params.recipient).bytes : new Uint8Array();
  const tx = ZBC.signTransaction({ type: v.type, timestamp: BigInt(v.timestamp), sender: kp.accountBytes, recipient, fee: BigInt(v.fee), body, escrow: v.escrow, message: v.message ? ZBC.utf8(v.message) : undefined }, kp, ZBC.signingContext(v.genesis));
  assert.equal(ZBC.bytesToHex(tx.hash), v.expected.transaction_hash, v.name); n++;
}
for (const v of load("transactions-all.json").vectors) {   // proof of ownership signed by the NODE key (spec/signing.md 6)
  if (!v.reference_block) continue;
  const def = ZBC.COMMAND_BY_NAME.get(v.command), sender = ZBC.keyPairFromSeed(v.key);
  const bc = { sender, files: {}, computed: {} };
  ZBC.computeFields({ def, params: { ...v.params }, sender, ctx: ZBC.signingContext(v.genesis), timestamp: BigInt(v.timestamp), referenceBlock: { hash: ZBC.hexToBytes(v.reference_block.block_hash), height: v.reference_block.height } }, bc);
  assert.equal(ZBC.bytesToHex(ZBC.buildBody(def, v.params, bc)), v.expected.body, v.name); n++;
}
assert.ok(typeof ZBC.Client === "function" && ZBC.COMMANDS.length >= 58);
for (const s of load("encryption.json").sealed) { const f = ZBC.seal(ZBC.hexToBytes(s.plaintext_hex), ZBC.hexToBytes(s.recipient_public_key), ZBC.hexToBytes(s.ephemeral_secret_key)); assert.equal(ZBC.bytesToHex(f), s.message_field); assert.equal(ZBC.bytesToHex(ZBC.openSealed(f, ZBC.hexToBytes(s.recipient_seed))), s.plaintext_hex); n++; }
for (const s of load("encryption.json").samples) { assert.equal(ZBC.bytesToHex(ZBC.openSealed(ZBC.hexToBytes(s.message_field), ZBC.hexToBytes(s.recipient_seed))), s.plaintext_hex); n++; }
console.log(`js/zbc.js: ${n} vector checks passed`);
