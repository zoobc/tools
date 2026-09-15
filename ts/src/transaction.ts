// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** The transaction envelope, escrow block, chain-bound digest, signature, hash and submit payload (spec/signing.md). */
import { sha3_256 } from "./crypto/sha3.js";
import { sign } from "./crypto/ed25519.js";
import { keyPairFromSeed, KeyPair } from "./keys.js";
import { parseAddress, AccountType } from "./address.js";
import { ByteWriter, bytesToHex, concat, hexToBytes, isHex, readI64LE, utf8 } from "./util/bytes.js";

export const TX_SIGNING_TAG = utf8("ZBC-TX");
export const EMPTY_ACCOUNT = new ByteWriter().u32(AccountType.Empty).finish();

/** Escrow terms of a transfer (the `--escrow-*` options). `timeout` is an absolute Unix time in seconds. */
export interface EscrowTerms {
  approver: string;
  commission: bigint | number;
  timeout: bigint | number;
  instruction?: string;
}

/** Which chain a signature is for: version 2 with its genesis hash, or the legacy version 1. */
export type SigningContext = { version: 2; genesisHash: Uint8Array } | { version: 1 };

export function signingContext(genesis: string | Uint8Array): SigningContext {
  if (typeof genesis === "string") {
    if (genesis === "v1" || genesis === "legacy") return { version: 1 };
    if (!isHex(genesis, 64)) throw new Error("--genesis must be the 64-hex genesis block hash (or 'v1' for the legacy digest)");
    return { version: 2, genesisHash: hexToBytes(genesis) };
  }
  if (genesis.length !== 32) throw new Error("genesis hash must be 32 bytes");
  return { version: 2, genesisHash: genesis };
}

export interface UnsignedTransaction {
  type: number;
  timestamp: bigint | number;
  /** 36-byte typed sender account (00000000 ‖ public key). */
  sender: Uint8Array;
  /** Typed recipient bytes, or empty for none. */
  recipient: Uint8Array;
  fee: bigint | number;
  body: Uint8Array;
  escrow?: EscrowTerms | null;
  /** Raw message bytes (UTF-8 text, or sealed bytes), or empty. */
  message?: Uint8Array;
  version?: number;
}

/** The escrow block of the envelope (spec/signing.md section 3). */
export function escrowBytes(e: EscrowTerms): Uint8Array {
  const approver = parseAddress(e.approver);
  const instruction = utf8(e.instruction ?? "");
  return new ByteWriter().bytes(approver.bytes).i64(e.commission).i64(e.timeout).u32(instruction.length).bytes(instruction).u8(0).finish();
}

/** Fields 1–11 of the envelope: the bytes the digest covers. */
export function unsignedBytes(tx: UnsignedTransaction): Uint8Array {
  const w = new ByteWriter().u32(tx.type).u8(tx.version ?? 1).i64(tx.timestamp).bytes(tx.sender);
  const recipientEmpty = tx.recipient.length === 0 || tx.recipient.every((b) => b === 0);
  w.bytes(recipientEmpty ? EMPTY_ACCOUNT : tx.recipient);
  w.i64(tx.fee).u32(tx.body.length).bytes(tx.body);
  if (tx.escrow) w.bytes(escrowBytes(tx.escrow)); else w.bytes(EMPTY_ACCOUNT);
  const msg = tx.message ?? new Uint8Array();
  w.u32(msg.length).bytes(msg);
  return w.finish();
}

/** SHA3-256("ZBC-TX" ‖ genesis ‖ unsigned) for version 2; SHA3-256(unsigned) for version 1. */
export function signingDigest(unsigned: Uint8Array, ctx: SigningContext): Uint8Array {
  return ctx.version === 2 ? sha3_256(concat(TX_SIGNING_TAG, ctx.genesisHash, unsigned)) : sha3_256(unsigned);
}

export function transactionHash(unsigned: Uint8Array, signature: Uint8Array): Uint8Array {
  return sha3_256(concat(unsigned, signature));
}

/** The int64 id: the first 8 bytes of the hash, little-endian, signed. */
export function transactionId(hash: Uint8Array): bigint {
  return readI64LE(hash, 0);
}

export interface SignedTransaction {
  unsigned: Uint8Array;
  digest: Uint8Array;
  signature: Uint8Array;
  bytes: Uint8Array;
  hash: Uint8Array;
  payload: SubmitPayload;
  signingVersion: 1 | 2;
  genesisHash?: Uint8Array;
}

/** The JSON object `POST /api/v1/transactions` takes (spec/api.md section 2). */
export interface SubmitPayload {
  version: number;
  timestamp: bigint;
  sender_account_address: string;
  recipient_account_address: string;
  transaction_type: number;
  fee: bigint;
  transaction_body_bytes: string;
  signature: string;
  message_hex?: string;
  escrow?: { approver_address: string; commission: bigint; timeout: bigint; instruction?: string };
}

/** Build, sign and hash a transaction for the chain of `ctx`. */
export function signTransaction(tx: UnsignedTransaction, key: KeyPair | Uint8Array | string, ctx: SigningContext): SignedTransaction {
  const kp = key instanceof Uint8Array || typeof key === "string" ? keyPairFromSeed(key) : key;
  const unsigned = unsignedBytes(tx);
  const digest = signingDigest(unsigned, ctx);
  const signature = sign(digest, kp.seed);
  const bytes = concat(unsigned, signature);
  const hash = sha3_256(bytes);
  const recipientForJson = tx.recipient.length === 0 ? "" : (tx.recipient.length === 36 && tx.recipient[0] === 0 && tx.recipient[1] === 0 && tx.recipient[2] === 0 && tx.recipient[3] === 0)
    ? bytesToHex(tx.recipient.slice(4)) : bytesToHex(tx.recipient);
  const payload: SubmitPayload = {
    version: tx.version ?? 1, timestamp: BigInt(tx.timestamp), sender_account_address: bytesToHex(tx.sender.slice(4)),
    recipient_account_address: recipientForJson, transaction_type: tx.type, fee: BigInt(tx.fee),
    transaction_body_bytes: bytesToHex(tx.body), signature: bytesToHex(signature),
  };
  if (tx.message && tx.message.length) payload.message_hex = bytesToHex(tx.message);
  if (tx.escrow) {
    payload.escrow = { approver_address: bytesToHex(parseAddress(tx.escrow.approver).bytes), commission: BigInt(tx.escrow.commission), timeout: BigInt(tx.escrow.timeout) };
    if (tx.escrow.instruction) payload.escrow.instruction = tx.escrow.instruction;
  }
  return { unsigned, digest, signature, bytes, hash, payload, signingVersion: ctx.version, genesisHash: ctx.version === 2 ? ctx.genesisHash : undefined };
}

// ---- the two core bodies ------------------------------------------------------------------------
export const TransactionType = { SendZBC: 1, ApprovalEscrow: 4 } as const;

export function sendZbcBody(amount: bigint | number): Uint8Array {
  return new ByteWriter().i64(amount).finish();
}

export const EscrowApproval = { approve: 0, reject: 1, expire: 2 } as const;
export function approvalEscrowBody(approval: number, escrowedTransactionHash: Uint8Array): Uint8Array {
  if (escrowedTransactionHash.length !== 32) throw new Error("Transaction hash must be 64 hex characters (the escrowed transaction's SHA3-256 hash)");
  return new ByteWriter().u32(approval).bytes(escrowedTransactionHash).finish();
}
