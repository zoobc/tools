// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** NaCl's crypto_secretbox: HSalsa20, XSalsa20 and Poly1305, and the tag || ciphertext box layout. */

const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);   // "expand 32-byte k"
const ROUNDS: [number, number, number, number][] = [[0, 4, 8, 12], [5, 9, 13, 1], [10, 14, 2, 6], [15, 3, 7, 11], [0, 1, 2, 3], [5, 6, 7, 4], [10, 11, 8, 9], [15, 12, 13, 14]];

function u32le(b: Uint8Array, off: number): number { return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0; }
function putU32le(out: Uint8Array, off: number, v: number): void { out[off] = v & 0xff; out[off + 1] = (v >>> 8) & 0xff; out[off + 2] = (v >>> 16) & 0xff; out[off + 3] = (v >>> 24) & 0xff; }
function rotl(v: number, c: number): number { return ((v << c) | (v >>> (32 - c))) >>> 0; }

function salsaRounds(x: Uint32Array): void {
  for (let i = 0; i < 10; i++) for (const [a, b, c, d] of ROUNDS) {
    x[b] ^= rotl((x[a] + x[d]) >>> 0, 7); x[c] ^= rotl((x[b] + x[a]) >>> 0, 9);
    x[d] ^= rotl((x[c] + x[b]) >>> 0, 13); x[a] ^= rotl((x[d] + x[c]) >>> 0, 18);
  }
}

/** HSalsa20(key 32, input 16) -> 32 bytes. */
export function hsalsa20(key: Uint8Array, input: Uint8Array): Uint8Array {
  const x = new Uint32Array(16);
  x[0] = SIGMA[0]; x[5] = SIGMA[1]; x[10] = SIGMA[2]; x[15] = SIGMA[3];
  for (let i = 0; i < 4; i++) { x[1 + i] = u32le(key, 4 * i); x[11 + i] = u32le(key, 16 + 4 * i); x[6 + i] = u32le(input, 4 * i); }
  salsaRounds(x);
  const out = new Uint8Array(32);
  [0, 5, 10, 15, 6, 7, 8, 9].forEach((w, i) => putU32le(out, 4 * i, x[w]));
  return out;
}

function salsa20Block(key: Uint8Array, nonce8: Uint8Array, counter: number): Uint8Array {
  const x0 = new Uint32Array(16);
  x0[0] = SIGMA[0]; x0[5] = SIGMA[1]; x0[10] = SIGMA[2]; x0[15] = SIGMA[3];
  for (let i = 0; i < 4; i++) { x0[1 + i] = u32le(key, 4 * i); x0[11 + i] = u32le(key, 16 + 4 * i); }
  x0[6] = u32le(nonce8, 0); x0[7] = u32le(nonce8, 4); x0[8] = counter >>> 0; x0[9] = Math.floor(counter / 0x100000000) >>> 0;
  const x = new Uint32Array(x0); salsaRounds(x);
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) putU32le(out, 4 * i, (x[i] + x0[i]) >>> 0);
  return out;
}

/** The XSalsa20 keystream: HSalsa20 subkey from the first 16 nonce bytes, Salsa20 with the last 8. */
export function xsalsa20Stream(key: Uint8Array, nonce24: Uint8Array, length: number): Uint8Array {
  const sub = hsalsa20(key, nonce24.subarray(0, 16)), nonce8 = nonce24.subarray(16, 24);
  const out = new Uint8Array(length);
  for (let i = 0, c = 0; i < length; i += 64, c++) out.set(salsa20Block(sub, nonce8, c).subarray(0, Math.min(64, length - i)), i);
  return out;
}

/** Poly1305 one-time authenticator (RFC 8439 section 2.5) on bigint. */
export function poly1305(key32: Uint8Array, msg: Uint8Array): Uint8Array {
  const le = (b: Uint8Array): bigint => { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; };
  const r = le(key32.subarray(0, 16)) & 0x0ffffffc0ffffffc0ffffffc0fffffffn, s = le(key32.subarray(16, 32));
  const p = (1n << 130n) - 5n;
  let acc = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    const blk = msg.subarray(i, Math.min(i + 16, msg.length));
    acc = (acc + le(blk) + (1n << BigInt(8 * blk.length))) * r % p;
  }
  let t = (acc + s) & ((1n << 128n) - 1n);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) { out[i] = Number(t & 0xffn); t >>= 8n; }
  return out;
}

/** crypto_secretbox_easy: tag (16) || ciphertext. */
export function secretbox(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const stream = xsalsa20Stream(key, nonce, 32 + plaintext.length);
  const c = new Uint8Array(plaintext.length);
  for (let i = 0; i < c.length; i++) c[i] = plaintext[i] ^ stream[32 + i];
  const out = new Uint8Array(16 + c.length); out.set(poly1305(stream.subarray(0, 32), c), 0); out.set(c, 16);
  return out;
}

/** crypto_secretbox_open_easy: the plaintext, or null when the tag does not verify. */
export function secretboxOpen(key: Uint8Array, nonce: Uint8Array, boxed: Uint8Array): Uint8Array | null {
  if (boxed.length < 16) return null;
  const c = boxed.subarray(16), stream = xsalsa20Stream(key, nonce, 32 + c.length);
  const tag = poly1305(stream.subarray(0, 32), c);
  let diff = 0; for (let i = 0; i < 16; i++) diff |= tag[i] ^ boxed[i];
  if (diff !== 0) return null;
  const out = new Uint8Array(c.length);
  for (let i = 0; i < c.length; i++) out[i] = c[i] ^ stream[32 + i];
  return out;
}
