// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** X25519 (RFC 7748) on bigint: the Montgomery ladder over Curve25519, and the Ed25519 -> X25519 key conversions. */
import { sha512 } from "./sha2.js";

const P = (1n << 255n) - 19n;
const A24 = 121665n;

function mod(a: bigint): bigint { const r = a % P; return r < 0n ? r + P : r; }
function pow(b: bigint, e: bigint): bigint { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = r * b % P; b = b * b % P; e >>= 1n; } return r; }
function leToBig(b: Uint8Array): bigint { let v = 0n; for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; }
function bigToLe(v: bigint, n: number): Uint8Array { const o = new Uint8Array(n); for (let i = 0; i < n; i++) { o[i] = Number(v & 0xffn); v >>= 8n; } return o; }

/** X25519(scalar, u): 32 bytes. The scalar is clamped as the RFC prescribes. */
export function x25519(scalar: Uint8Array, u: Uint8Array): Uint8Array {
  const k = new Uint8Array(scalar); k[0] &= 248; k[31] &= 127; k[31] |= 64;
  const s = leToBig(k);
  const x1 = leToBig(u) & ((1n << 255n) - 1n);
  let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n;
  for (let t = 254; t >= 0; t--) {
    const kt = (s >> BigInt(t)) & 1n;
    swap ^= kt;
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    swap = kt;
    const a = mod(x2 + z2), aa = a * a % P, b = mod(x2 - z2), bb = b * b % P, e = mod(aa - bb);
    const c = mod(x3 + z3), d = mod(x3 - z3), da = d * a % P, cb = c * b % P;
    x3 = pow(mod(da + cb), 2n); z3 = x1 * pow(mod(da - cb), 2n) % P;
    x2 = aa * bb % P; z2 = e * mod(aa + A24 * e) % P;
  }
  if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
  return bigToLe(x2 * pow(z2, P - 2n) % P, 32);
}

/** The X25519 public key of a scalar: X25519(scalar, 9). */
export function x25519Base(scalar: Uint8Array): Uint8Array { const nine = new Uint8Array(32); nine[0] = 9; return x25519(scalar, nine); }

/** Ed25519 public key -> X25519 public key: u = (1 + y) / (1 - y) mod p. */
export function ed25519PublicKeyToX25519(pk: Uint8Array): Uint8Array {
  const y = leToBig(pk) & ((1n << 255n) - 1n);
  return bigToLe(mod(1n + y) * pow(mod(1n - y), P - 2n) % P, 32);
}

/** Ed25519 seed -> X25519 secret key: the clamped first half of SHA-512(seed). */
export function ed25519SeedToX25519(seed: Uint8Array): Uint8Array {
  const h = sha512(seed).slice(0, 32); h[0] &= 248; h[31] &= 127; h[31] |= 64; return h;
}
