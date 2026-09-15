// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** RFC 4648 base32 without padding, as the ZBC_ address form uses it. */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(data: Uint8Array): string {
  let out = "", buf = 0, bits = 0;
  for (const b of data) {
    buf = ((buf << 8) | b) & 0x1fff; bits += 8;
    while (bits >= 5) { bits -= 5; out += ALPHABET[(buf >> bits) & 31]; }
  }
  if (bits > 0) out += ALPHABET[(buf << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Uint8Array {
  const out: number[] = [];
  let buf = 0, bits = 0;
  for (const c of s) {
    const v = ALPHABET.indexOf(c);
    if (v < 0) throw new Error("not base32");
    buf = ((buf << 5) | v) & 0x1fff; bits += 5;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
  }
  return new Uint8Array(out);
}
