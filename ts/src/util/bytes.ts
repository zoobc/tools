// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** Byte helpers: hex, UTF-8, concatenation, little-endian integers. */

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.slice(2) : hex;
  if (h.length % 2 !== 0) throw new Error("hex must have an even length");
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const v = parseInt(h.slice(2 * i, 2 * i + 2), 16);
    if (Number.isNaN(v) || !/^[0-9a-fA-F]{2}$/.test(h.slice(2 * i, 2 * i + 2))) throw new Error("not valid hex");
    out[i] = v;
  }
  return out;
}

export function isHex(s: string, length?: number): boolean {
  return /^[0-9a-fA-F]*$/.test(s) && s.length % 2 === 0 && (length === undefined || s.length === length);
}

const HEX = "0123456789abcdef";
export function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i++) s += HEX[b[i] >> 4] + HEX[b[i] & 15];
  return s;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** Little-endian writers, appending to a growable buffer. */
export class ByteWriter {
  private parts: Uint8Array[] = [];
  bytes(b: Uint8Array): this { this.parts.push(b); return this; }
  u8(v: number): this { this.parts.push(new Uint8Array([v & 0xff])); return this; }
  u16(v: number): this { this.parts.push(new Uint8Array([v & 0xff, (v >>> 8) & 0xff])); return this; }
  u32(v: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v >>> 0, true);
    this.parts.push(b);
    return this;
  }
  /** int64 or uint64 as 8 little-endian bytes (two's complement for negatives). */
  i64(v: bigint | number): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, BigInt(v)), true);
    this.parts.push(b);
    return this;
  }
  finish(): Uint8Array { return concat(...this.parts); }
}

export function readU32LE(b: Uint8Array, off: number): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off, true);
}
export function readI64LE(b: Uint8Array, off: number): bigint {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigInt64(off, true);
}
