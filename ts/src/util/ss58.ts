// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** SS58 (Polkadot) address decoding: base58, 1- or 2-byte prefix, 32-byte account id, 2-byte BLAKE2b checksum. */
import { base58Decode } from "./base58.js";
import { blake2b } from "../crypto/blake2b.js";
import { concat, utf8 } from "./bytes.js";

export function ss58Decode(s: string): { prefix: number; accountId: Uint8Array } | null {
  const raw = base58Decode(s);
  if (!raw) return null;
  let prefixLen: number, prefix: number;
  if (raw.length >= 35 && raw[0] < 64) { prefixLen = 1; prefix = raw[0]; }
  else if (raw.length >= 36 && raw[0] >= 64 && raw[0] < 128) {
    prefixLen = 2;
    prefix = ((raw[0] & 0x3f) << 2) | (raw[1] >> 6) | ((raw[1] & 0x3f) << 8);
  } else return null;
  const bodyLen = raw.length - 2;
  if (bodyLen - prefixLen !== 32) return null;
  const sum = blake2b(concat(utf8("SS58PRE"), raw.slice(0, bodyLen)), 64);
  if (sum[0] !== raw[bodyLen] || sum[1] !== raw[bodyLen + 1]) return null;
  return { prefix, accountId: raw.slice(prefixLen, bodyLen) };
}
