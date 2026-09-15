// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** Bech32 (BIP 173) and bech32m (BIP 350) decoding; segwit and plain (Cardano) forms. */
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function polymod(values: number[]): number {
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

/** Returns hrp, the 5-bit data (without checksum) and which encoding verified, or null. */
export function bech32DecodeRaw(s: string): { hrp: string; data: number[]; encoding: "bech32" | "bech32m" } | null {
  if (s.length > 1023) return null;
  const lower = s.toLowerCase();
  if (lower !== s && s.toUpperCase() !== s) return null;
  const pos = lower.lastIndexOf("1");
  if (pos < 1 || pos + 7 > lower.length) return null;
  const hrp = lower.slice(0, pos);
  const data: number[] = [];
  for (const c of lower.slice(pos + 1)) {
    const v = CHARSET.indexOf(c);
    if (v < 0) return null;
    data.push(v);
  }
  const pm = polymod(hrpExpand(hrp).concat(data));
  const encoding = pm === 1 ? "bech32" : pm === 0x2bc830a3 ? "bech32m" : null;
  if (!encoding) return null;
  return { hrp, data: data.slice(0, data.length - 6), encoding };
}

export function convertBits(data: number[], from: number, to: number, pad: boolean): number[] | null {
  let acc = 0, bits = 0;
  const out: number[] = [];
  const maxv = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || v >> from) return null;
    acc = (acc << from) | v; bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
  }
  if (pad) { if (bits > 0) out.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) return null;
  return out;
}

/** Segwit address -> witness version and program, or null. */
export function segwitDecode(s: string): { hrp: string; version: number; program: Uint8Array } | null {
  const d = bech32DecodeRaw(s);
  if (!d || d.data.length < 1) return null;
  const version = d.data[0];
  const prog = convertBits(d.data.slice(1), 5, 8, false);
  if (!prog || prog.length < 2 || prog.length > 40) return null;
  if (version > 16) return null;
  if (version === 0 && prog.length !== 20 && prog.length !== 32) return null;
  if ((version === 0 && d.encoding !== "bech32") || (version !== 0 && d.encoding !== "bech32m")) return null;
  return { hrp: d.hrp, version, program: new Uint8Array(prog) };
}

/** Plain bech32 (no witness version), 8-bit payload; used for Cardano addresses. */
export function bech32DecodePlain(s: string): { hrp: string; bytes: Uint8Array } | null {
  const d = bech32DecodeRaw(s);
  if (!d || d.encoding !== "bech32") return null;
  const bytes = convertBits(d.data, 5, 8, false);
  if (!bytes) return null;
  return { hrp: d.hrp, bytes: new Uint8Array(bytes) };
}
