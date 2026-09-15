// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/**
 * The hand-written parts the descriptions mark `computed` or `custom` (spec/transactions/README.md):
 * proof of ownership, the fee-vote and heartbeat signatures, the store-file piece count, the
 * multisig body and the settle-app vouchers. Everything else is data-driven (body.ts).
 */
import { sha3_256 } from "./crypto/sha3.js";
import { sign } from "./crypto/ed25519.js";
import { keyPairFromSeed, KeyPair } from "./keys.js";
import { parseAddress } from "./address.js";
import { usage } from "./errors.js";
import { signingDigest, SigningContext, unsignedBytes, TransactionType } from "./transaction.js";
import { ByteWriter, bytesToHex, concat, hexToBytes, isHex } from "./util/bytes.js";
import { parseInteger, splitList, BodyContext } from "./body.js";
import { TxDef } from "./spec.js";

export interface CustomInput {
  def: TxDef;
  params: Record<string, string>;
  sender: KeyPair;
  ctx: SigningContext;
  /** The envelope timestamp (a multisig inner transaction shares it). */
  timestamp: bigint;
  /** The reference block for a proof of ownership, fetched by the caller when `needs_node`. */
  referenceBlock?: { hash: Uint8Array; height: number };
}

/** Proof of ownership: owner address (36) ‖ block hash (32) ‖ height u32le, signed by the owner (spec/signing.md 6). */
export function proofOfOwnership(owner: KeyPair, block: { hash: Uint8Array; height: number }): Uint8Array {
  const msg = new ByteWriter().bytes(owner.accountBytes).bytes(block.hash).u32(block.height).finish();
  return concat(msg, sign(msg, owner.seed));
}

/** Fill `ctx.computed` for the fields the generic serialiser cannot produce. Returns extra output fields. */
export function computeFields(input: CustomInput, body: BodyContext): Record<string, unknown> {
  const { def, params, sender } = input;
  const computed: Record<string, Uint8Array> = (body.computed ??= {});
  const extra: Record<string, unknown> = {};
  switch (def.command) {
    case "store-file": {
      const pieces = hexToBytes(params.piece_ids ?? "");
      if (pieces.length === 0 || pieces.length % 32 !== 0) throw usage("piece_ids must be a nonzero multiple of 32 bytes");
      computed.piece_count = new ByteWriter().u32(pieces.length / 32).finish();
      extra.piece_count = pieces.length / 32;
      break;
    }
    case "register-node": case "update-node": case "claim-node": {
      if (!input.referenceBlock) throw new Error("proof of ownership needs the latest block");
      computed.proof_of_ownership = proofOfOwnership(sender, input.referenceBlock);
      const node = keyPairFromSeed(params.node_privkey);
      extra.node_znk = node.nodeAddress; extra.owner_zbc = sender.address;
      break;
    }
    case "fee-vote-reveal": {
      const info = new ByteWriter().bytes(hexToBytes(params.recent_block_hash)).u32(Number(parseInteger(params.recent_block_height, "uint32", "recent_block_height")))
        .i64(parseInteger(params.fee_vote, "int64", "fee_vote")).finish();
      const sig = sign(info, sender.seed);
      computed.voter_signature = new ByteWriter().u32(sig.length).bytes(sig).finish();
      break;
    }
    case "gateway-heartbeat": {
      if (!isHex(params.gateway_privkey, 64)) throw usage("gateway_privkey is not a valid key");
      const gw = keyPairFromSeed(params.gateway_privkey);
      const h = parseInteger(params.reference_height, "uint32", "reference_height");
      const hash = hexToBytes(params.reference_block_hash);
      if (hash.length !== 32) throw usage("reference_block_hash must be 32 bytes (64 hex)");
      const msg = new ByteWriter().bytes(gw.publicKey).u32(Number(h)).bytes(hash).finish();
      computed.signature = sign(msg, gw.seed);
      extra.gateway_key = bytesToHex(gw.publicKey); extra.reference_height = Number(h); extra.reference_block_hash = params.reference_block_hash;
      break;
    }
  }
  return extra;
}

/** Whole-body builders for the two fully custom types. */
export function customBody(input: CustomInput): { body: Uint8Array; extra: Record<string, unknown> } {
  switch (input.def.command) {
    case "multisig": return multisigBody(input);
    case "app-settle": return settleBody(input);
    default: throw new Error("no custom body for " + input.def.command);
  }
}

/** SHA3-256(min u32le ‖ nonce u64le ‖ count u32le ‖ sorted participant addresses). */
export function multisigAddress(participants: Uint8Array[], nonce: bigint, minSignatures: number): Uint8Array {
  const sorted = participants.slice().sort(compareBytes);
  const w = new ByteWriter().u32(minSignatures).i64(nonce).u32(sorted.length);
  for (const a of sorted) w.bytes(a);
  return sha3_256(w.finish());
}
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

function multisigBody(input: CustomInput): { body: Uint8Array; extra: Record<string, unknown> } {
  const p = input.params;
  const participants = splitList(p.participants).map((a) => parseAddress(a).bytes);
  if (participants.length === 0) throw usage("Need at least one participant");
  const minSigs = Number(parseInteger(p.min_signatures, "uint32", "min_signatures"));
  const nonce = parseInteger(p.nonce || "0", "int64", "nonce");
  const signers = splitList(p.signer_privkeys);
  if (signers.length === 0) throw usage("Need at least one signer key");
  const recipient = parseAddress(p.recipient);
  const amount = parseInteger(p.amount, "int64", "amount");
  const innerFee = parseInteger(p.inner_fee || "10000000", "int64", "inner_fee");
  const msAddr = multisigAddress(participants, nonce, minSigs);
  const innerSender = new ByteWriter().u32(0).bytes(msAddr).finish();
  const inner = unsignedBytes({ type: TransactionType.SendZBC, timestamp: input.timestamp, sender: innerSender, recipient: recipient.bytes,
                                fee: innerFee, body: new ByteWriter().i64(amount).finish() });
  const innerHash = sha3_256(inner);
  const innerDigest = signingDigest(inner, input.ctx);
  const sigs: [string, Uint8Array][] = [];
  for (const sk of signers) {
    if (!isHex(sk, 64)) throw usage("Invalid signer key");
    const kp = keyPairFromSeed(sk);
    sigs.push([bytesToHex(kp.accountBytes), sign(innerDigest, kp.seed)]);
  }
  sigs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));   // the node keeps them in a map ordered by address hex
  const w = new ByteWriter().u32(1).u32(minSigs).i64(nonce).u32(participants.length);
  for (const a of participants) w.bytes(a);
  w.u32(inner.length).bytes(inner).u32(1).bytes(innerHash).u32(sigs.length);
  for (const [addrHex, sig] of sigs) w.bytes(hexToBytes(addrHex)).u32(sig.length).bytes(sig);
  const extra = { multisig_address: bytesToHex(msAddr), multisig_zbc_address: parseAddress(bytesToHex(msAddr)).display, min_signatures: minSigs,
                  inner_tx_hash: bytesToHex(innerHash), fund_hint: "send ZBC to multisig_zbc_address before the signatures complete, else the inner tx stays in mempool" };
  return { body: w.finish(), extra };
}

function settleBody(input: CustomInput): { body: Uint8Array; extra: Record<string, unknown> } {
  const p = input.params;
  const appId = parseInteger(p.app_id, "int64", "app_id");
  if (!isHex(p.p0_privkey, 64) || !isHex(p.p1_privkey, 64)) throw usage("seat keys must be 64 hex");
  const seats = [keyPairFromSeed(p.p0_privkey), keyPairFromSeed(p.p1_privkey)];
  const turn = Number(parseInteger(p.opening_turn || "0", "uint8", "opening_turn"));
  if (turn !== 0 && turn !== 1) throw usage("opening_turn must be 0 or 1");
  const cells = splitList(p.moves).map((c) => Number(parseInteger(c, "uint8", "move")));
  if (cells.length === 0) throw usage("no moves given");
  const state = new Uint8Array(9);
  const entries: Uint8Array[] = [];
  cells.forEach((cell, k) => {
    const seat = (turn + k) % 2;
    if (cell < 0 || cell > 8 || state[cell] !== 0) throw usage(`illegal move at seq ${k + 1}`);
    const move = new Uint8Array([cell]);
    const digest = sha3_256(new ByteWriter().i64(appId).u32(k + 1).bytes(sha3_256(state)).bytes(move).finish());
    const sig = sign(digest, seats[seat].seed);
    entries.push(new ByteWriter().u8(seat).u16(move.length).bytes(move).bytes(sig).finish());
    state[cell] = seat + 1;
  });
  const w = new ByteWriter().i64(appId).u32(cells.length).u32(cells.length);
  for (const e of entries) w.bytes(e);
  return { body: w.finish(), extra: { app_id: Number(appId), opening_turn: turn, final_seq: cells.length } };
}
