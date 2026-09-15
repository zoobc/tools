// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** Base58 (Bitcoin and Ripple alphabets) and base58check. */
import { sha256d } from "../crypto/sha2.js";

export const BITCOIN_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export const RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

export function base58Decode(s: string, alphabet = BITCOIN_ALPHABET): Uint8Array | null {
  if (s.length === 0) return new Uint8Array();
  let n = 0n;
  for (const c of s) {
    const v = alphabet.indexOf(c);
    if (v < 0) return null;
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) { bytes.push(Number(n & 0xffn)); n >>= 8n; }
  bytes.reverse();
  let zeros = 0;
  for (const c of s) { if (c === alphabet[0]) zeros++; else break; }
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes]);
}

export function base58Encode(b: Uint8Array, alphabet = BITCOIN_ALPHABET): string {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let s = "";
  while (n > 0n) { s = alphabet[Number(n % 58n)] + s; n /= 58n; }
  for (const x of b) { if (x === 0) s = alphabet[0] + s; else break; }
  return s;
}

/** Payload without its 4-byte SHA-256d checksum, or null when the checksum fails. */
export function base58CheckDecode(s: string, alphabet = BITCOIN_ALPHABET): Uint8Array | null {
  const raw = base58Decode(s, alphabet);
  if (!raw || raw.length < 5) return null;
  const body = raw.slice(0, raw.length - 4), sum = sha256d(body);
  for (let i = 0; i < 4; i++) if (sum[i] !== raw[raw.length - 4 + i]) return null;
  return body;
}
