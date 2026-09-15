// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** SHA-256 and SHA-512 (FIPS 180-4), HMAC and PBKDF2 over SHA-512. Pure TypeScript. */

const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(msg: Uint8Array): Uint8Array {
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const padLen = (((msg.length + 9 + 63) >> 6) << 6);
  const p = new Uint8Array(padLen);
  p.set(msg); p[msg.length] = 0x80;
  const dv = new DataView(p.buffer);
  dv.setUint32(padLen - 8, Math.floor((msg.length * 8) / 0x100000000), false);
  dv.setUint32(padLen - 4, (msg.length * 8) >>> 0, false);
  const w = new Uint32Array(64);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + 4 * i, false);
    for (let i = 16; i < 64; i++) {
      const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
      const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(4 * i, h[i], false);
  return out;
}

export function sha256d(msg: Uint8Array): Uint8Array { return sha256(sha256(msg)); }

// SHA-512 with 64-bit words held as (hi, lo) pairs of uint32.
const K512 = [
  0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn, 0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n, 0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n, 0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
  0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n, 0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
  0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn, 0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
  0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n, 0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n, 0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn, 0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
  0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n, 0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
  0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn, 0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n,
];
const K512H = new Uint32Array(80), K512L = new Uint32Array(80);
for (let i = 0; i < 80; i++) { K512H[i] = Number(K512[i] >> 32n); K512L[i] = Number(K512[i] & 0xffffffffn); }

export function sha512(msg: Uint8Array): Uint8Array {
  const H = new Uint32Array([0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
                             0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179]);
  const padLen = (((msg.length + 17 + 127) >> 7) << 7);
  const p = new Uint8Array(padLen);
  p.set(msg); p[msg.length] = 0x80;
  const dv = new DataView(p.buffer);
  const bits = BigInt(msg.length) * 8n;
  dv.setUint32(padLen - 8, Number((bits >> 32n) & 0xffffffffn), false);
  dv.setUint32(padLen - 4, Number(bits & 0xffffffffn), false);
  const wh = new Uint32Array(80), wl = new Uint32Array(80);
  for (let off = 0; off < padLen; off += 128) {
    for (let i = 0; i < 16; i++) { wh[i] = dv.getUint32(off + 8 * i, false); wl[i] = dv.getUint32(off + 8 * i + 4, false); }
    for (let i = 16; i < 80; i++) {
      // s0 = rotr1 ^ rotr8 ^ shr7 of w[i-15]
      let xh = wh[i - 15], xl = wl[i - 15];
      const s0h = (((xh >>> 1) | (xl << 31)) ^ ((xh >>> 8) | (xl << 24)) ^ (xh >>> 7)) >>> 0;
      const s0l = (((xl >>> 1) | (xh << 31)) ^ ((xl >>> 8) | (xh << 24)) ^ ((xl >>> 7) | (xh << 25))) >>> 0;
      // s1 = rotr19 ^ rotr61 ^ shr6 of w[i-2]
      xh = wh[i - 2]; xl = wl[i - 2];
      const s1h = (((xh >>> 19) | (xl << 13)) ^ ((xl >>> 29) | (xh << 3)) ^ (xh >>> 6)) >>> 0;
      const s1l = (((xl >>> 19) | (xh << 13)) ^ ((xh >>> 29) | (xl << 3)) ^ ((xl >>> 6) | (xh << 26))) >>> 0;
      let lo = (wl[i - 16] + s0l) >>> 0; let carry = lo < wl[i - 16] ? 1 : 0;
      let hi = (wh[i - 16] + s0h + carry) >>> 0;
      let lo2 = (lo + wl[i - 7]) >>> 0; carry = lo2 < lo ? 1 : 0; hi = (hi + wh[i - 7] + carry) >>> 0; lo = lo2;
      lo2 = (lo + s1l) >>> 0; carry = lo2 < lo ? 1 : 0; hi = (hi + s1h + carry) >>> 0; lo = lo2;
      wh[i] = hi; wl[i] = lo;
    }
    let ah = H[0], al = H[1], bh = H[2], bl = H[3], ch = H[4], cl = H[5], dh = H[6], dl = H[7];
    let eh = H[8], el = H[9], fh = H[10], fl = H[11], gh = H[12], gl = H[13], hh = H[14], hl = H[15];
    for (let i = 0; i < 80; i++) {
      // S1 = rotr14 ^ rotr18 ^ rotr41 (e)
      const S1h = (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23))) >>> 0;
      const S1l = (((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23))) >>> 0;
      const chh = ((eh & fh) ^ (~eh & gh)) >>> 0, chl = ((el & fl) ^ (~el & gl)) >>> 0;
      // t1 = h + S1 + ch + K + w
      let lo = (hl + S1l) >>> 0, c = lo < hl ? 1 : 0, hi = (hh + S1h + c) >>> 0;
      let lo2 = (lo + chl) >>> 0; c = lo2 < lo ? 1 : 0; hi = (hi + chh + c) >>> 0; lo = lo2;
      lo2 = (lo + K512L[i]) >>> 0; c = lo2 < lo ? 1 : 0; hi = (hi + K512H[i] + c) >>> 0; lo = lo2;
      lo2 = (lo + wl[i]) >>> 0; c = lo2 < lo ? 1 : 0; hi = (hi + wh[i] + c) >>> 0; lo = lo2;
      const t1h = hi, t1l = lo;
      // S0 = rotr28 ^ rotr34 ^ rotr39 (a)
      const S0h = (((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25))) >>> 0;
      const S0l = (((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25))) >>> 0;
      const majh = ((ah & bh) ^ (ah & ch) ^ (bh & ch)) >>> 0, majl = ((al & bl) ^ (al & cl) ^ (bl & cl)) >>> 0;
      const t2l = (S0l + majl) >>> 0, t2h = (S0h + majh + (t2l < S0l ? 1 : 0)) >>> 0;
      hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;
      el = (dl + t1l) >>> 0; eh = (dh + t1h + (el < dl ? 1 : 0)) >>> 0;
      dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;
      al = (t1l + t2l) >>> 0; ah = (t1h + t2h + (al < t1l ? 1 : 0)) >>> 0;
    }
    const add = (i: number, xh: number, xl: number) => { const l = (H[i + 1] + xl) >>> 0; H[i] = (H[i] + xh + (l < xl ? 1 : 0)) >>> 0; H[i + 1] = l; };
    add(0, ah, al); add(2, bh, bl); add(4, ch, cl); add(6, dh, dl); add(8, eh, el); add(10, fh, fl); add(12, gh, gl); add(14, hh, hl);
  }
  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) ov.setUint32(4 * i, H[i], false);
  return out;
}

export function hmacSha512(key: Uint8Array, msg: Uint8Array): Uint8Array {
  const k = new Uint8Array(128);
  k.set(key.length > 128 ? sha512(key) : key);
  const ipad = new Uint8Array(128 + msg.length), opad = new Uint8Array(128 + 64);
  for (let i = 0; i < 128; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
  ipad.set(msg, 128);
  opad.set(sha512(ipad), 128);
  return sha512(opad);
}

/** PBKDF2-HMAC-SHA512, as BIP-39 needs it (2048 rounds, 64 bytes). */
export function pbkdf2Sha512(password: Uint8Array, salt: Uint8Array, iterations: number, dkLen: number): Uint8Array {
  const out = new Uint8Array(dkLen);
  const blocks = Math.ceil(dkLen / 64);
  for (let b = 1; b <= blocks; b++) {
    const s = new Uint8Array(salt.length + 4);
    s.set(salt); new DataView(s.buffer).setUint32(salt.length, b, false);
    let u = hmacSha512(password, s);
    const t = new Uint8Array(u);
    for (let i = 1; i < iterations; i++) {
      u = hmacSha512(password, u);
      for (let j = 0; j < 64; j++) t[j] ^= u[j];
    }
    out.set(t.subarray(0, Math.min(64, dkLen - 64 * (b - 1))), 64 * (b - 1));
  }
  return out;
}
