// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/**
 * Ed25519 (RFC 8032) on BigInt: public key from a 32-byte seed, detached signatures, verification.
 * Scalar multiplication is a fixed-length double-and-add whose branches do not depend on secret
 * bits at the JavaScript level; BigInt arithmetic itself is not constant time, so keep secrets on
 * machines you trust, as with any pure-JavaScript signer.
 */
import { sha512 } from "./sha2.js";
import { concat } from "../util/bytes.js";

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const D = -121665n * inv(121666n) % P;
const I = pow(2n, (P - 1n) / 4n);          // sqrt(-1)
const GY = 4n * inv(5n) % P;
const GX = recoverX(GY, 0n);

function mod(a: bigint): bigint { const r = a % P; return r < 0n ? r + P : r; }
function pow(b: bigint, e: bigint): bigint {
  let r = 1n; b = mod(b);
  while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; }
  return r;
}
function inv(a: bigint): bigint { return pow(a, P - 2n); }
function recoverX(y: bigint, sign: bigint): bigint {
  const y2 = y * y % P;
  const u = mod(y2 - 1n), v = mod(D * y2 + 1n);
  let x = pow(u * inv(v), (P + 3n) / 8n);
  if (mod(v * x * x - u) !== 0n) x = x * I % P;
  if (mod(v * x * x - u) !== 0n) throw new Error("not a point on the curve");
  if ((x & 1n) !== sign) x = P - x;
  return x;
}

/** Extended coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z, xy = T/Z. */
type Pt = [bigint, bigint, bigint, bigint];
const ZERO: Pt = [0n, 1n, 1n, 0n];
const G: Pt = [GX, GY, 1n, GX * GY % P];
function add(p: Pt, q: Pt): Pt {
  const [X1, Y1, Z1, T1] = p, [X2, Y2, Z2, T2] = q;
  const A = mod((Y1 - X1) * (Y2 - X2)), B = mod((Y1 + X1) * (Y2 + X2));
  const C = mod(2n * T1 * T2 * D), Dd = mod(2n * Z1 * Z2);
  const E = B - A, F = Dd - C, Gg = Dd + C, H = B + A;
  return [mod(E * F), mod(Gg * H), mod(F * Gg), mod(E * H)];
}
function dbl(p: Pt): Pt { return add(p, p); }
function mul(p: Pt, s: bigint): Pt {
  let r: Pt = ZERO, q: Pt = p;
  for (let i = 0; i < 256; i++) {
    const bit = (s >> BigInt(i)) & 1n;
    const sum = add(r, q);
    r = bit === 1n ? sum : r;   // both the sum and the doubling are computed every round
    q = dbl(q);
  }
  return r;
}
function encode(p: Pt): Uint8Array {
  const zi = inv(p[2]);
  const x = p[0] * zi % P, y = p[1] * zi % P;
  const out = new Uint8Array(32);
  let v = y | ((x & 1n) << 255n);
  for (let i = 0; i < 32; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function decode(b: Uint8Array): Pt {
  if (b.length !== 32) throw new Error("point must be 32 bytes");
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(b[i]);
  const sign = y >> 255n; y &= (1n << 255n) - 1n;
  if (y >= P) throw new Error("non-canonical point");
  const x = recoverX(y, sign);
  if (x === 0n && sign === 1n) throw new Error("non-canonical point");
  return [x, y, 1n, x * y % P];
}
function leToBig(b: Uint8Array): bigint { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; }
function bigToLe(v: bigint, n: number): Uint8Array { const o = new Uint8Array(n); for (let i = 0; i < n; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; }
function clamp(h: Uint8Array): bigint {
  const k = h.slice(0, 32); k[0] &= 248; k[31] &= 127; k[31] |= 64;
  return leToBig(k);
}

/** The 32-byte public key of a 32-byte seed. */
export function publicKeyFromSeed(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  return encode(mul(G, clamp(sha512(seed))));
}

/** Detached 64-byte signature of `msg` with the 32-byte seed. */
export function sign(msg: Uint8Array, seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) throw new Error("seed must be 32 bytes");
  const h = sha512(seed);
  const a = clamp(h);
  const prefix = h.slice(32);
  const A = encode(mul(G, a));
  const r = leToBig(sha512(concat(prefix, msg))) % L;
  const R = encode(mul(G, r));
  const k = leToBig(sha512(concat(R, A, msg))) % L;
  const S = (r + k * a) % L;
  return concat(R, bigToLe(S, 32));
}

/** True when `sig` is a valid signature of `msg` by `publicKey`. Never throws. */
export function verify(msg: Uint8Array, sig: Uint8Array, publicKey: Uint8Array): boolean {
  try {
    if (sig.length !== 64 || publicKey.length !== 32) return false;
    const A = decode(publicKey);
    const R = decode(sig.slice(0, 32));
    const S = leToBig(sig.slice(32));
    if (S >= L) return false;
    const k = leToBig(sha512(concat(sig.slice(0, 32), publicKey, msg))) % L;
    const lhs = encode(mul(G, S));
    const rhs = encode(add(R, mul(A, k)));
    let d = 0;
    for (let i = 0; i < 32; i++) d |= lhs[i] ^ rhs[i];
    return d === 0;
  } catch {
    return false;
  }
}
