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
for (const v of load("messages.json").vectors) { const s = ZBC.signMessage(v.seed, ZBC.hexToBytes(v.message_hex)); assert.equal(s.signature, v.signature); assert.ok(ZBC.verifyMessage(v.address, ZBC.hexToBytes(v.message_hex), v.signature)); n++; }
for (const v of load("transactions.json").vectors) {
  const kp = ZBC.keyPairFromSeed(v.key);
  const body = v.command === "send-zbc" ? ZBC.sendZbcBody(BigInt(v.params.amount)) : ZBC.approvalEscrowBody(Number(v.params.approval), ZBC.hexToBytes(v.params.transaction_hash));
  const recipient = v.command === "send-zbc" ? ZBC.parseAddress(v.params.recipient).bytes : new Uint8Array();
  const tx = ZBC.signTransaction({ type: v.type, timestamp: BigInt(v.timestamp), sender: kp.accountBytes, recipient, fee: BigInt(v.fee), body, escrow: v.escrow, message: v.message ? ZBC.utf8(v.message) : undefined }, kp, ZBC.signingContext(v.genesis));
  assert.equal(ZBC.bytesToHex(tx.hash), v.expected.transaction_hash, v.name); n++;
}
assert.ok(typeof ZBC.Client === "function" && ZBC.COMMANDS.length >= 58);
console.log(`js/zbc.js: ${n} vector checks passed`);
