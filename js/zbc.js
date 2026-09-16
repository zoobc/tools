// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
// ZooBC tools 0.1.0, built from ts/ by scripts/bundle.mjs. Defines the global ZBC. Do not edit.
"use strict";
var ZBC = (() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __defNormalProp = (obj, key, value) => key in obj ? __defProp(obj, key, { enumerable: true, configurable: true, writable: true, value }) : obj[key] = value;
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toCommonJS = (mod2) => __copyProps(__defProp({}, "__esModule", { value: true }), mod2);
  var __publicField = (obj, key, value) => __defNormalProp(obj, typeof key !== "symbol" ? key + "" : key, value);

  // src/index.ts
  var index_exports = {};
  __export(index_exports, {
    AccountType: () => AccountType,
    BIP39_WORDS: () => BIP39_WORDS,
    ByteWriter: () => ByteWriter,
    COMMANDS: () => COMMANDS,
    COMMAND_BY_NAME: () => COMMAND_BY_NAME,
    Client: () => Client,
    EMPTY_ACCOUNT: () => EMPTY_ACCOUNT,
    EscrowApproval: () => EscrowApproval,
    ExitCode: () => ExitCode,
    MESSAGE_SIGNING_SCHEME: () => MESSAGE_SIGNING_SCHEME,
    TX_SIGNING_TAG: () => TX_SIGNING_TAG,
    ToolError: () => ToolError,
    TransactionType: () => TransactionType,
    ZOOBC_COIN_TYPE: () => ZOOBC_COIN_TYPE,
    accountTypeName: () => accountTypeName,
    approvalEscrowBody: () => approvalEscrowBody,
    base32Decode: () => base32Decode,
    base32Encode: () => base32Encode,
    base58CheckDecode: () => base58CheckDecode,
    base58Decode: () => base58Decode,
    base58Encode: () => base58Encode,
    bech32DecodePlain: () => bech32DecodePlain,
    blake2b: () => blake2b,
    buildBody: () => buildBody,
    bytesToHex: () => bytesToHex,
    chainOf: () => chainOf,
    classifyNodeError: () => classifyNodeError,
    computeFields: () => computeFields,
    concat: () => concat,
    customBody: () => customBody,
    decodeZbcAddress: () => decodeZbcAddress,
    ed25519Sign: () => sign,
    ed25519Verify: () => verify,
    encodeField: () => encodeField,
    encodeZbcAddress: () => encodeZbcAddress,
    errorClassOf: () => errorClassOf,
    escrowBytes: () => escrowBytes,
    fromUtf8: () => fromUtf8,
    generateMnemonic: () => generateMnemonic,
    hexToBytes: () => hexToBytes,
    hmacSha512: () => hmacSha512,
    isHex: () => isHex,
    isZbcAddress: () => isZbcAddress,
    keyPairFromSeed: () => keyPairFromSeed,
    messageDigest: () => messageDigest,
    mnemonicFromEntropy: () => mnemonicFromEntropy,
    mnemonicToSeed: () => mnemonicToSeed,
    multisigAddress: () => multisigAddress,
    parseAddress: () => parseAddress,
    parseInteger: () => parseInteger,
    parseJson: () => parseJson,
    parseKey32: () => parseKey32,
    payloadLength: () => payloadLength,
    pbkdf2Sha512: () => pbkdf2Sha512,
    proofOfOwnership: () => proofOfOwnership,
    publicKeyFromSeed: () => publicKeyFromSeed,
    publicKeyHex: () => publicKeyHex,
    publicKeyOfAddress: () => publicKeyOfAddress,
    randomSeed: () => randomSeed,
    seedFromHex: () => seedFromHex,
    seedHex: () => seedHex,
    segwitDecode: () => segwitDecode,
    sendZbcBody: () => sendZbcBody,
    sha256: () => sha256,
    sha3_256: () => sha3_256,
    sha512: () => sha512,
    signMessage: () => signMessage,
    signTransaction: () => signTransaction,
    signingContext: () => signingContext,
    signingDigest: () => signingDigest,
    slip10Derive: () => slip10Derive,
    splitList: () => splitList,
    ss58Decode: () => ss58Decode,
    stringifyJson: () => stringifyJson,
    transactionHash: () => transactionHash,
    transactionId: () => transactionId,
    typedAddress: () => typedAddress,
    unsignedBytes: () => unsignedBytes,
    usage: () => usage,
    utf8: () => utf8,
    validateMnemonic: () => validateMnemonic,
    validateParam: () => validateParam,
    verifyMessage: () => verifyMessage,
    walletAccount: () => walletAccount,
    zbcSignificant: () => zbcSignificant
  });

  // src/crypto/sha3.ts
  var RC = [
    0x0000000000000001n,
    0x0000000000008082n,
    0x800000000000808an,
    0x8000000080008000n,
    0x000000000000808bn,
    0x0000000080000001n,
    0x8000000080008081n,
    0x8000000000008009n,
    0x000000000000008an,
    0x0000000000000088n,
    0x0000000080008009n,
    0x000000008000000an,
    0x000000008000808bn,
    0x800000000000008bn,
    0x8000000000008089n,
    0x8000000000008003n,
    0x8000000000008002n,
    0x8000000000000080n,
    0x000000000000800an,
    0x800000008000000an,
    0x8000000080008081n,
    0x8000000000008080n,
    0x0000000080000001n,
    0x8000000080008008n
  ];
  var ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
  var M64 = (1n << 64n) - 1n;
  var rotl = (x, n) => n === 0 ? x : (x << BigInt(n) | x >> BigInt(64 - n)) & M64;
  function keccakF(s) {
    for (let round = 0; round < 24; round++) {
      const c = [0n, 0n, 0n, 0n, 0n];
      for (let x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
      for (let x = 0; x < 5; x++) {
        const d = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
        for (let y = 0; y < 25; y += 5) s[x + y] ^= d;
      }
      const b = new Array(25);
      for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y], ROT[x + 5 * y]);
      for (let y = 0; y < 25; y += 5) for (let x = 0; x < 5; x++) s[x + y] = b[x + y] ^ ~b[(x + 1) % 5 + y] & M64 & b[(x + 2) % 5 + y];
      s[0] ^= RC[round];
    }
  }
  function sha3_256(msg) {
    const rate = 136;
    const s = new Array(25).fill(0n);
    const padded = new Uint8Array(Math.ceil((msg.length + 1) / rate) * rate);
    padded.set(msg);
    padded[msg.length] ^= 6;
    padded[padded.length - 1] ^= 128;
    for (let off = 0; off < padded.length; off += rate) {
      for (let i = 0; i < rate / 8; i++) {
        let lane = 0n;
        for (let j = 7; j >= 0; j--) lane = lane << 8n | BigInt(padded[off + 8 * i + j]);
        s[i] ^= lane;
      }
      keccakF(s);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 4; i++) {
      let lane = s[i];
      for (let j = 0; j < 8; j++) {
        out[8 * i + j] = Number(lane & 0xffn);
        lane >>= 8n;
      }
    }
    return out;
  }

  // src/util/base32.ts
  var ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  function base32Encode(data) {
    let out = "", buf = 0, bits = 0;
    for (const b of data) {
      buf = (buf << 8 | b) & 8191;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        out += ALPHABET[buf >> bits & 31];
      }
    }
    if (bits > 0) out += ALPHABET[buf << 5 - bits & 31];
    return out;
  }
  function base32Decode(s) {
    const out = [];
    let buf = 0, bits = 0;
    for (const c of s) {
      const v = ALPHABET.indexOf(c);
      if (v < 0) throw new Error("not base32");
      buf = (buf << 5 | v) & 8191;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        out.push(buf >> bits & 255);
      }
    }
    return new Uint8Array(out);
  }

  // src/crypto/sha2.ts
  var K256 = new Uint32Array([
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
  ]);
  function sha256(msg) {
    const h = new Uint32Array([1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225]);
    const padLen = msg.length + 9 + 63 >> 6 << 6;
    const p = new Uint8Array(padLen);
    p.set(msg);
    p[msg.length] = 128;
    const dv = new DataView(p.buffer);
    dv.setUint32(padLen - 8, Math.floor(msg.length * 8 / 4294967296), false);
    dv.setUint32(padLen - 4, msg.length * 8 >>> 0, false);
    const w = new Uint32Array(64);
    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + 4 * i, false);
      for (let i = 16; i < 64; i++) {
        const s0 = (w[i - 15] >>> 7 | w[i - 15] << 25) ^ (w[i - 15] >>> 18 | w[i - 15] << 14) ^ w[i - 15] >>> 3;
        const s1 = (w[i - 2] >>> 17 | w[i - 2] << 15) ^ (w[i - 2] >>> 19 | w[i - 2] << 13) ^ w[i - 2] >>> 10;
        w[i] = w[i - 16] + s0 + w[i - 7] + s1 >>> 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7);
        const ch = e & f ^ ~e & g;
        const t1 = hh + S1 + ch + K256[i] + w[i] >>> 0;
        const S0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10);
        const maj = a & b ^ a & c ^ b & c;
        const t2 = S0 + maj >>> 0;
        hh = g;
        g = f;
        f = e;
        e = d + t1 >>> 0;
        d = c;
        c = b;
        b = a;
        a = t1 + t2 >>> 0;
      }
      h[0] = h[0] + a >>> 0;
      h[1] = h[1] + b >>> 0;
      h[2] = h[2] + c >>> 0;
      h[3] = h[3] + d >>> 0;
      h[4] = h[4] + e >>> 0;
      h[5] = h[5] + f >>> 0;
      h[6] = h[6] + g >>> 0;
      h[7] = h[7] + hh >>> 0;
    }
    const out = new Uint8Array(32);
    const ov = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) ov.setUint32(4 * i, h[i], false);
    return out;
  }
  function sha256d(msg) {
    return sha256(sha256(msg));
  }
  var K512 = [
    0x428a2f98d728ae22n,
    0x7137449123ef65cdn,
    0xb5c0fbcfec4d3b2fn,
    0xe9b5dba58189dbbcn,
    0x3956c25bf348b538n,
    0x59f111f1b605d019n,
    0x923f82a4af194f9bn,
    0xab1c5ed5da6d8118n,
    0xd807aa98a3030242n,
    0x12835b0145706fben,
    0x243185be4ee4b28cn,
    0x550c7dc3d5ffb4e2n,
    0x72be5d74f27b896fn,
    0x80deb1fe3b1696b1n,
    0x9bdc06a725c71235n,
    0xc19bf174cf692694n,
    0xe49b69c19ef14ad2n,
    0xefbe4786384f25e3n,
    0x0fc19dc68b8cd5b5n,
    0x240ca1cc77ac9c65n,
    0x2de92c6f592b0275n,
    0x4a7484aa6ea6e483n,
    0x5cb0a9dcbd41fbd4n,
    0x76f988da831153b5n,
    0x983e5152ee66dfabn,
    0xa831c66d2db43210n,
    0xb00327c898fb213fn,
    0xbf597fc7beef0ee4n,
    0xc6e00bf33da88fc2n,
    0xd5a79147930aa725n,
    0x06ca6351e003826fn,
    0x142929670a0e6e70n,
    0x27b70a8546d22ffcn,
    0x2e1b21385c26c926n,
    0x4d2c6dfc5ac42aedn,
    0x53380d139d95b3dfn,
    0x650a73548baf63den,
    0x766a0abb3c77b2a8n,
    0x81c2c92e47edaee6n,
    0x92722c851482353bn,
    0xa2bfe8a14cf10364n,
    0xa81a664bbc423001n,
    0xc24b8b70d0f89791n,
    0xc76c51a30654be30n,
    0xd192e819d6ef5218n,
    0xd69906245565a910n,
    0xf40e35855771202an,
    0x106aa07032bbd1b8n,
    0x19a4c116b8d2d0c8n,
    0x1e376c085141ab53n,
    0x2748774cdf8eeb99n,
    0x34b0bcb5e19b48a8n,
    0x391c0cb3c5c95a63n,
    0x4ed8aa4ae3418acbn,
    0x5b9cca4f7763e373n,
    0x682e6ff3d6b2b8a3n,
    0x748f82ee5defb2fcn,
    0x78a5636f43172f60n,
    0x84c87814a1f0ab72n,
    0x8cc702081a6439ecn,
    0x90befffa23631e28n,
    0xa4506cebde82bde9n,
    0xbef9a3f7b2c67915n,
    0xc67178f2e372532bn,
    0xca273eceea26619cn,
    0xd186b8c721c0c207n,
    0xeada7dd6cde0eb1en,
    0xf57d4f7fee6ed178n,
    0x06f067aa72176fban,
    0x0a637dc5a2c898a6n,
    0x113f9804bef90daen,
    0x1b710b35131c471bn,
    0x28db77f523047d84n,
    0x32caab7b40c72493n,
    0x3c9ebe0a15c9bebcn,
    0x431d67c49c100d4cn,
    0x4cc5d4becb3e42b6n,
    0x597f299cfc657e2an,
    0x5fcb6fab3ad6faecn,
    0x6c44198c4a475817n
  ];
  var K512H = new Uint32Array(80);
  var K512L = new Uint32Array(80);
  for (let i = 0; i < 80; i++) {
    K512H[i] = Number(K512[i] >> 32n);
    K512L[i] = Number(K512[i] & 0xffffffffn);
  }
  function sha512(msg) {
    const H = new Uint32Array([
      1779033703,
      4089235720,
      3144134277,
      2227873595,
      1013904242,
      4271175723,
      2773480762,
      1595750129,
      1359893119,
      2917565137,
      2600822924,
      725511199,
      528734635,
      4215389547,
      1541459225,
      327033209
    ]);
    const padLen = msg.length + 17 + 127 >> 7 << 7;
    const p = new Uint8Array(padLen);
    p.set(msg);
    p[msg.length] = 128;
    const dv = new DataView(p.buffer);
    const bits = BigInt(msg.length) * 8n;
    dv.setUint32(padLen - 8, Number(bits >> 32n & 0xffffffffn), false);
    dv.setUint32(padLen - 4, Number(bits & 0xffffffffn), false);
    const wh = new Uint32Array(80), wl = new Uint32Array(80);
    for (let off = 0; off < padLen; off += 128) {
      for (let i = 0; i < 16; i++) {
        wh[i] = dv.getUint32(off + 8 * i, false);
        wl[i] = dv.getUint32(off + 8 * i + 4, false);
      }
      for (let i = 16; i < 80; i++) {
        let xh = wh[i - 15], xl = wl[i - 15];
        const s0h = ((xh >>> 1 | xl << 31) ^ (xh >>> 8 | xl << 24) ^ xh >>> 7) >>> 0;
        const s0l = ((xl >>> 1 | xh << 31) ^ (xl >>> 8 | xh << 24) ^ (xl >>> 7 | xh << 25)) >>> 0;
        xh = wh[i - 2];
        xl = wl[i - 2];
        const s1h = ((xh >>> 19 | xl << 13) ^ (xl >>> 29 | xh << 3) ^ xh >>> 6) >>> 0;
        const s1l = ((xl >>> 19 | xh << 13) ^ (xh >>> 29 | xl << 3) ^ (xl >>> 6 | xh << 26)) >>> 0;
        let lo = wl[i - 16] + s0l >>> 0;
        let carry = lo < wl[i - 16] ? 1 : 0;
        let hi = wh[i - 16] + s0h + carry >>> 0;
        let lo2 = lo + wl[i - 7] >>> 0;
        carry = lo2 < lo ? 1 : 0;
        hi = hi + wh[i - 7] + carry >>> 0;
        lo = lo2;
        lo2 = lo + s1l >>> 0;
        carry = lo2 < lo ? 1 : 0;
        hi = hi + s1h + carry >>> 0;
        lo = lo2;
        wh[i] = hi;
        wl[i] = lo;
      }
      let ah = H[0], al = H[1], bh = H[2], bl = H[3], ch = H[4], cl = H[5], dh = H[6], dl = H[7];
      let eh = H[8], el = H[9], fh = H[10], fl = H[11], gh = H[12], gl = H[13], hh = H[14], hl = H[15];
      for (let i = 0; i < 80; i++) {
        const S1h = ((eh >>> 14 | el << 18) ^ (eh >>> 18 | el << 14) ^ (el >>> 9 | eh << 23)) >>> 0;
        const S1l = ((el >>> 14 | eh << 18) ^ (el >>> 18 | eh << 14) ^ (eh >>> 9 | el << 23)) >>> 0;
        const chh = (eh & fh ^ ~eh & gh) >>> 0, chl = (el & fl ^ ~el & gl) >>> 0;
        let lo = hl + S1l >>> 0, c = lo < hl ? 1 : 0, hi = hh + S1h + c >>> 0;
        let lo2 = lo + chl >>> 0;
        c = lo2 < lo ? 1 : 0;
        hi = hi + chh + c >>> 0;
        lo = lo2;
        lo2 = lo + K512L[i] >>> 0;
        c = lo2 < lo ? 1 : 0;
        hi = hi + K512H[i] + c >>> 0;
        lo = lo2;
        lo2 = lo + wl[i] >>> 0;
        c = lo2 < lo ? 1 : 0;
        hi = hi + wh[i] + c >>> 0;
        lo = lo2;
        const t1h = hi, t1l = lo;
        const S0h = ((ah >>> 28 | al << 4) ^ (al >>> 2 | ah << 30) ^ (al >>> 7 | ah << 25)) >>> 0;
        const S0l = ((al >>> 28 | ah << 4) ^ (ah >>> 2 | al << 30) ^ (ah >>> 7 | al << 25)) >>> 0;
        const majh = (ah & bh ^ ah & ch ^ bh & ch) >>> 0, majl = (al & bl ^ al & cl ^ bl & cl) >>> 0;
        const t2l = S0l + majl >>> 0, t2h = S0h + majh + (t2l < S0l ? 1 : 0) >>> 0;
        hh = gh;
        hl = gl;
        gh = fh;
        gl = fl;
        fh = eh;
        fl = el;
        el = dl + t1l >>> 0;
        eh = dh + t1h + (el < dl ? 1 : 0) >>> 0;
        dh = ch;
        dl = cl;
        ch = bh;
        cl = bl;
        bh = ah;
        bl = al;
        al = t1l + t2l >>> 0;
        ah = t1h + t2h + (al < t1l ? 1 : 0) >>> 0;
      }
      const add2 = (i, xh, xl) => {
        const l = H[i + 1] + xl >>> 0;
        H[i] = H[i] + xh + (l < xl ? 1 : 0) >>> 0;
        H[i + 1] = l;
      };
      add2(0, ah, al);
      add2(2, bh, bl);
      add2(4, ch, cl);
      add2(6, dh, dl);
      add2(8, eh, el);
      add2(10, fh, fl);
      add2(12, gh, gl);
      add2(14, hh, hl);
    }
    const out = new Uint8Array(64);
    const ov = new DataView(out.buffer);
    for (let i = 0; i < 16; i++) ov.setUint32(4 * i, H[i], false);
    return out;
  }
  function hmacSha512(key, msg) {
    const k = new Uint8Array(128);
    k.set(key.length > 128 ? sha512(key) : key);
    const ipad = new Uint8Array(128 + msg.length), opad = new Uint8Array(128 + 64);
    for (let i = 0; i < 128; i++) {
      ipad[i] = k[i] ^ 54;
      opad[i] = k[i] ^ 92;
    }
    ipad.set(msg, 128);
    opad.set(sha512(ipad), 128);
    return sha512(opad);
  }
  function pbkdf2Sha512(password, salt, iterations, dkLen) {
    const out = new Uint8Array(dkLen);
    const blocks = Math.ceil(dkLen / 64);
    for (let b = 1; b <= blocks; b++) {
      const s = new Uint8Array(salt.length + 4);
      s.set(salt);
      new DataView(s.buffer).setUint32(salt.length, b, false);
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

  // src/util/base58.ts
  var BITCOIN_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  var RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
  function base58Decode(s, alphabet = BITCOIN_ALPHABET) {
    if (s.length === 0) return new Uint8Array();
    let n = 0n;
    for (const c of s) {
      const v = alphabet.indexOf(c);
      if (v < 0) return null;
      n = n * 58n + BigInt(v);
    }
    const bytes = [];
    while (n > 0n) {
      bytes.push(Number(n & 0xffn));
      n >>= 8n;
    }
    bytes.reverse();
    let zeros = 0;
    for (const c of s) {
      if (c === alphabet[0]) zeros++;
      else break;
    }
    return new Uint8Array([...new Array(zeros).fill(0), ...bytes]);
  }
  function base58Encode(b, alphabet = BITCOIN_ALPHABET) {
    let n = 0n;
    for (const x of b) n = n << 8n | BigInt(x);
    let s = "";
    while (n > 0n) {
      s = alphabet[Number(n % 58n)] + s;
      n /= 58n;
    }
    for (const x of b) {
      if (x === 0) s = alphabet[0] + s;
      else break;
    }
    return s;
  }
  function base58CheckDecode(s, alphabet = BITCOIN_ALPHABET) {
    const raw = base58Decode(s, alphabet);
    if (!raw || raw.length < 5) return null;
    const body = raw.slice(0, raw.length - 4), sum = sha256d(body);
    for (let i = 0; i < 4; i++) if (sum[i] !== raw[raw.length - 4 + i]) return null;
    return body;
  }

  // src/util/bech32.ts
  var CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  var GEN = [996825010, 642813549, 513874426, 1027748829, 705979059];
  function polymod(values) {
    let chk = 1;
    for (const v of values) {
      const b = chk >>> 25;
      chk = (chk & 33554431) << 5 ^ v;
      for (let i = 0; i < 5; i++) if (b >> i & 1) chk ^= GEN[i];
    }
    return chk >>> 0;
  }
  function hrpExpand(hrp) {
    const out = [];
    for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
    out.push(0);
    for (const c of hrp) out.push(c.charCodeAt(0) & 31);
    return out;
  }
  function bech32DecodeRaw(s) {
    if (s.length > 1023) return null;
    const lower = s.toLowerCase();
    if (lower !== s && s.toUpperCase() !== s) return null;
    const pos = lower.lastIndexOf("1");
    if (pos < 1 || pos + 7 > lower.length) return null;
    const hrp = lower.slice(0, pos);
    const data = [];
    for (const c of lower.slice(pos + 1)) {
      const v = CHARSET.indexOf(c);
      if (v < 0) return null;
      data.push(v);
    }
    const pm = polymod(hrpExpand(hrp).concat(data));
    const encoding = pm === 1 ? "bech32" : pm === 734539939 ? "bech32m" : null;
    if (!encoding) return null;
    return { hrp, data: data.slice(0, data.length - 6), encoding };
  }
  function convertBits(data, from, to, pad) {
    let acc = 0, bits = 0;
    const out = [];
    const maxv = (1 << to) - 1;
    for (const v of data) {
      if (v < 0 || v >> from) return null;
      acc = acc << from | v;
      bits += from;
      while (bits >= to) {
        bits -= to;
        out.push(acc >> bits & maxv);
      }
    }
    if (pad) {
      if (bits > 0) out.push(acc << to - bits & maxv);
    } else if (bits >= from || acc << to - bits & maxv) return null;
    return out;
  }
  function segwitDecode(s) {
    const d = bech32DecodeRaw(s);
    if (!d || d.data.length < 1) return null;
    const version = d.data[0];
    const prog = convertBits(d.data.slice(1), 5, 8, false);
    if (!prog || prog.length < 2 || prog.length > 40) return null;
    if (version > 16) return null;
    if (version === 0 && prog.length !== 20 && prog.length !== 32) return null;
    if (version === 0 && d.encoding !== "bech32" || version !== 0 && d.encoding !== "bech32m") return null;
    return { hrp: d.hrp, version, program: new Uint8Array(prog) };
  }
  function bech32DecodePlain(s) {
    const d = bech32DecodeRaw(s);
    if (!d || d.encoding !== "bech32") return null;
    const bytes = convertBits(d.data, 5, 8, false);
    if (!bytes) return null;
    return { hrp: d.hrp, bytes: new Uint8Array(bytes) };
  }

  // src/crypto/blake2b.ts
  var IV = [
    0x6a09e667f3bcc908n,
    0xbb67ae8584caa73bn,
    0x3c6ef372fe94f82bn,
    0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n,
    0x9b05688c2b3e6c1fn,
    0x1f83d9abfb41bd6bn,
    0x5be0cd19137e2179n
  ];
  var SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]
  ];
  var M642 = (1n << 64n) - 1n;
  var rotr = (x, n) => (x >> n | x << 64n - n) & M642;
  function blake2b(msg, outLen = 64) {
    const h = IV.slice();
    h[0] ^= 0x01010000n ^ BigInt(outLen);
    const padded = new Uint8Array(Math.max(128, Math.ceil(msg.length / 128) * 128));
    padded.set(msg);
    const dv = new DataView(padded.buffer);
    for (let off = 0; off < padded.length; off += 128) {
      const last = off + 128 >= padded.length;
      const t = BigInt(last ? msg.length : off + 128);
      const m = [];
      for (let i = 0; i < 16; i++) m.push(dv.getBigUint64(off + 8 * i, true));
      const v = h.concat(IV);
      v[12] ^= t & M642;
      v[13] ^= t >> 64n;
      if (last) v[14] = ~v[14] & M642;
      const G2 = (a, b, c, d, x, y) => {
        v[a] = v[a] + v[b] + x & M642;
        v[d] = rotr(v[d] ^ v[a], 32n);
        v[c] = v[c] + v[d] & M642;
        v[b] = rotr(v[b] ^ v[c], 24n);
        v[a] = v[a] + v[b] + y & M642;
        v[d] = rotr(v[d] ^ v[a], 16n);
        v[c] = v[c] + v[d] & M642;
        v[b] = rotr(v[b] ^ v[c], 63n);
      };
      for (let r = 0; r < 12; r++) {
        const s = SIGMA[r];
        G2(0, 4, 8, 12, m[s[0]], m[s[1]]);
        G2(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G2(2, 6, 10, 14, m[s[4]], m[s[5]]);
        G2(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G2(0, 5, 10, 15, m[s[8]], m[s[9]]);
        G2(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G2(2, 7, 8, 13, m[s[12]], m[s[13]]);
        G2(3, 4, 9, 14, m[s[14]], m[s[15]]);
      }
      for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    }
    const out = new Uint8Array(outLen);
    for (let i = 0; i < outLen; i++) out[i] = Number(h[i >> 3] >> BigInt(8 * (i & 7)) & 0xffn);
    return out;
  }

  // src/util/bytes.ts
  function hexToBytes(hex) {
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
  function isHex(s, length) {
    return /^[0-9a-fA-F]*$/.test(s) && s.length % 2 === 0 && (length === void 0 || s.length === length);
  }
  var HEX = "0123456789abcdef";
  function bytesToHex(b) {
    let s = "";
    for (let i = 0; i < b.length; i++) s += HEX[b[i] >> 4] + HEX[b[i] & 15];
    return s;
  }
  function utf8(s) {
    return new TextEncoder().encode(s);
  }
  function fromUtf8(b) {
    return new TextDecoder().decode(b);
  }
  function concat(...parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return out;
  }
  var ByteWriter = class {
    constructor() {
      __publicField(this, "parts", []);
    }
    bytes(b) {
      this.parts.push(b);
      return this;
    }
    u8(v) {
      this.parts.push(new Uint8Array([v & 255]));
      return this;
    }
    u16(v) {
      this.parts.push(new Uint8Array([v & 255, v >>> 8 & 255]));
      return this;
    }
    u32(v) {
      const b = new Uint8Array(4);
      new DataView(b.buffer).setUint32(0, v >>> 0, true);
      this.parts.push(b);
      return this;
    }
    /** int64 or uint64 as 8 little-endian bytes (two's complement for negatives). */
    i64(v) {
      const b = new Uint8Array(8);
      new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, BigInt(v)), true);
      this.parts.push(b);
      return this;
    }
    finish() {
      return concat(...this.parts);
    }
  };
  function readI64LE(b, off) {
    return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigInt64(off, true);
  }

  // src/util/ss58.ts
  function ss58Decode(s) {
    const raw = base58Decode(s);
    if (!raw) return null;
    let prefixLen, prefix;
    if (raw.length >= 35 && raw[0] < 64) {
      prefixLen = 1;
      prefix = raw[0];
    } else if (raw.length >= 36 && raw[0] >= 64 && raw[0] < 128) {
      prefixLen = 2;
      prefix = (raw[0] & 63) << 2 | raw[1] >> 6 | (raw[1] & 63) << 8;
    } else return null;
    const bodyLen = raw.length - 2;
    if (bodyLen - prefixLen !== 32) return null;
    const sum = blake2b(concat(utf8("SS58PRE"), raw.slice(0, bodyLen)), 64);
    if (sum[0] !== raw[bodyLen] || sum[1] !== raw[bodyLen + 1]) return null;
    return { prefix, accountId: raw.slice(prefixLen, bodyLen) };
  }

  // src/address.ts
  var AccountType = {
    ZooBC: 0,
    Bitcoin: 1,
    Empty: 2,
    EstoniaEID: 3,
    Ethereum: 4,
    BitcoinP2PKH: 5,
    BitcoinP2SH: 6,
    BitcoinP2WPKH: 7,
    BitcoinP2WSH: 8,
    BitcoinTaproot: 9,
    DataSet: 10,
    Solana: 11,
    Polkadot: 12,
    Cardano: 13,
    Ripple: 14,
    Tron: 15,
    Tezos: 16
  };
  var TYPE_NAMES = {
    0: "ZooBC",
    1: "Bitcoin",
    3: "Estonia eID",
    4: "Ethereum",
    5: "Bitcoin P2PKH",
    6: "Bitcoin P2SH",
    7: "Bitcoin P2WPKH",
    8: "Bitcoin P2WSH",
    9: "Bitcoin Taproot",
    10: "DataSet",
    11: "Solana",
    12: "Polkadot",
    13: "Cardano",
    14: "Ripple",
    15: "Tron",
    16: "Tezos"
  };
  function accountTypeName(t) {
    return TYPE_NAMES[t] ?? `type ${t}`;
  }
  function payloadLength(t) {
    switch (t) {
      case 1:
      case 5:
      case 6:
      case 7:
      case 14:
      case 15:
      case 16:
      case 4:
        return 20;
      case 13:
        return 28;
      default:
        return 32;
    }
  }
  function encodeZbcAddress(payload, prefix = "ZBC") {
    if (payload.length !== 32) throw new Error("address payload must be 32 bytes");
    if (prefix.length !== 3) throw new Error("prefix must be 3 characters");
    const check = sha3_256(concat(payload, utf8(prefix))).slice(0, 3);
    const b32 = base32Encode(concat(payload, check));
    let out = prefix;
    for (let i = 0; i < 7; i++) out += "_" + b32.slice(8 * i, 8 * i + 8);
    return out;
  }
  function zbcSignificant(text) {
    return text.replace(/[-_\s]/g, "").toUpperCase();
  }
  function decodeZbcAddress(text) {
    const norm = zbcSignificant(text);
    if (norm.length < 3) return null;
    const prefix = norm.slice(0, 3);
    const body = norm.slice(3);
    if (body.length !== 56) return null;
    let raw;
    try {
      raw = base32Decode(body);
    } catch {
      return null;
    }
    if (raw.length !== 35) return null;
    const payload = raw.slice(0, 32);
    const check = sha3_256(concat(payload, utf8(prefix))).slice(0, 3);
    if (check[0] !== raw[32] || check[1] !== raw[33] || check[2] !== raw[34]) return null;
    return { prefix, payload };
  }
  function isZbcAddress(text, prefix) {
    const d = decodeZbcAddress(text);
    return d !== null && (prefix === void 0 || d.prefix === prefix.toUpperCase());
  }
  function typed(type, payload, display) {
    return { type, payload, bytes: new ByteWriter().u32(type).bytes(payload).finish(), typeName: accountTypeName(type), display };
  }
  function typedAddress(type, payload) {
    return new ByteWriter().u32(type).bytes(payload).finish();
  }
  function chainOf(name) {
    const n = name.toLowerCase();
    const map = {
      zbc: "zbc",
      zoobc: "zbc",
      btc: "btc",
      bitcoin: "btc",
      eth: "eth",
      ethereum: "eth",
      evm: "eth",
      sol: "sol",
      solana: "sol",
      dot: "dot",
      polkadot: "dot",
      substrate: "dot",
      ada: "ada",
      cardano: "ada",
      xrp: "xrp",
      ripple: "xrp",
      trx: "trx",
      tron: "trx",
      xtz: "xtz",
      tezos: "xtz",
      zbs: "zbs",
      dataset: "zbs"
    };
    return map[n] ?? null;
  }
  function parseAddress(input, chain = "") {
    const a = input.trim();
    if (a === "") throw new Error("empty address");
    const hint = chain ? chainOf(chain) : null;
    if (chain && !hint) throw new Error(`unknown chain ${chain}`);
    if (hint) {
      try {
        return parseHinted(a, hint);
      } catch (e) {
        const up = a.toUpperCase();
        const plain = a.length === 42 && (a.startsWith("0x") || a.startsWith("0X")) || up.startsWith("ZBC") || up.startsWith("ZNK") || up.startsWith("ZBS") || a[0] === "1" || a[0] === "3" || /^(bc1|tb1|bcrt1)/i.test(a) || a.length === 64;
        if (!plain) throw e;
        return parseAddress(a);
      }
    }
    return parseAuto(a);
  }
  function parseHinted(a, hint) {
    if (hint === "eth") {
      const h = a.startsWith("0x") || a.startsWith("0X") ? a.slice(2) : a;
      if (!isHex(h, 40)) throw new Error("not a 20-byte Ethereum address");
      return typed(AccountType.Ethereum, hexToBytes(h), a);
    }
    if (hint === "sol") {
      const d = base58Decode(a);
      if (!d || d.length !== 32) throw new Error("not a 32-byte Solana address");
      return typed(AccountType.Solana, d, a);
    }
    if (hint === "dot") {
      const ss = ss58Decode(a);
      if (!ss) throw new Error("not a valid SS58 address");
      return typed(AccountType.Polkadot, ss.accountId, a);
    }
    if (hint === "zbc" || hint === "zbs") return zbcForm(a);
    return parseAuto(a);
  }
  function looksZbc(a) {
    if (a.length > 4 && (a[3] === "_" || a[3] === "-")) return true;
    const n = zbcSignificant(a);
    return n.length === 59 && (n.startsWith("ZBC") || n.startsWith("ZBS")) && /^[A-Z2-7]+$/.test(n.slice(3));
  }
  function parseAuto(a) {
    if (a.length === 42 && (a.startsWith("0x") || a.startsWith("0X")) && isHex(a.slice(2), 40)) return typed(AccountType.Ethereum, hexToBytes(a.slice(2)), a);
    if (looksZbc(a)) return zbcForm(a);
    const low5 = a.slice(0, 5).toLowerCase();
    if (low5.startsWith("bc1") || low5.startsWith("tb1") || low5.startsWith("bcrt1")) {
      const d = segwitDecode(a);
      if (!d) throw new Error("invalid Bitcoin bech32 address");
      if (d.version === 0 && d.program.length === 20) return typed(AccountType.BitcoinP2WPKH, d.program, a);
      if (d.version === 0 && d.program.length === 32) return typed(AccountType.BitcoinP2WSH, d.program, a);
      if (d.version === 1 && d.program.length === 32) return typed(AccountType.BitcoinTaproot, d.program, a);
      throw new Error("unsupported Bitcoin witness program");
    }
    if ((a[0] === "1" || a[0] === "3") && a.length >= 26 && a.length <= 35) {
      const raw = base58Decode(a);
      if (raw && raw.length === 25) {
        const body = base58CheckDecode(a);
        if (body && body.length === 21) {
          if (body[0] === 0) return typed(AccountType.BitcoinP2PKH, body.slice(1), a);
          if (body[0] === 5) return typed(AccountType.BitcoinP2SH, body.slice(1), a);
        }
      }
    }
    if (a.length > 5 && a.slice(0, 5).toLowerCase() === "addr1") {
      const d = bech32DecodePlain(a);
      if (d && d.hrp === "addr" && d.bytes.length === 29 && d.bytes[0] === 97) return typed(AccountType.Cardano, d.bytes.slice(1), a);
      throw new Error("invalid Cardano address (expected a mainnet enterprise addr1\u2026 address)");
    }
    if (a[0] === "T" && a.length === 34) {
      const body = base58CheckDecode(a);
      if (body && body.length === 21 && body[0] === 65) return typed(AccountType.Tron, body.slice(1), a);
      throw new Error("invalid Tron address");
    }
    if (a[0] === "r" && a.length >= 25 && a.length <= 35) {
      const body = base58CheckDecode(a, RIPPLE_ALPHABET);
      if (body && body.length === 21 && body[0] === 0) return typed(AccountType.Ripple, body.slice(1), a);
      throw new Error("invalid Ripple address");
    }
    if (a.startsWith("tz1")) {
      const body = base58CheckDecode(a);
      if (body && body.length === 23 && body[0] === 6 && body[1] === 161 && body[2] === 159) return typed(AccountType.Tezos, body.slice(3), a);
      throw new Error("invalid Tezos address");
    }
    {
      const ss = ss58Decode(a);
      if (ss && ss.accountId.length === 32) return typed(AccountType.Polkadot, ss.accountId, a);
    }
    if (a.length >= 32 && a.length <= 44) {
      const d = base58Decode(a);
      if (d && d.length === 32) return typed(AccountType.Solana, d, a);
    }
    if (isHex(a, 64)) {
      const key = hexToBytes(a);
      return typed(AccountType.ZooBC, key, encodeZbcAddress(key, "ZBC"));
    }
    throw new Error("unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos");
  }
  function zbcForm(a) {
    const d = decodeZbcAddress(a);
    if (!d) throw new Error("invalid ZooBC address checksum");
    if (d.prefix === "ZBS") return typed(AccountType.DataSet, d.payload, a);
    return typed(AccountType.ZooBC, d.payload, a);
  }
  function parseKey32(input) {
    if (input.length === 66 && input[3] === "_") {
      const d = decodeZbcAddress(input);
      if (!d) throw new Error("invalid address checksum");
      return d.payload;
    }
    const h = input.startsWith("0x") || input.startsWith("0X") ? input.slice(2) : input;
    if (!isHex(h, 64)) throw new Error("key must be a 64-hex string or a ZNK_/ZBG_/ZBR_ address");
    return hexToBytes(h);
  }

  // src/crypto/ed25519.ts
  var P = (1n << 255n) - 19n;
  var L = (1n << 252n) + 27742317777372353535851937790883648493n;
  var D = -121665n * inv(121666n) % P;
  var I = pow(2n, (P - 1n) / 4n);
  var GY = 4n * inv(5n) % P;
  var GX = recoverX(GY, 0n);
  function mod(a) {
    const r = a % P;
    return r < 0n ? r + P : r;
  }
  function pow(b, e) {
    let r = 1n;
    b = mod(b);
    while (e > 0n) {
      if (e & 1n) r = r * b % P;
      b = b * b % P;
      e >>= 1n;
    }
    return r;
  }
  function inv(a) {
    return pow(a, P - 2n);
  }
  function recoverX(y, sign2) {
    const y2 = y * y % P;
    const u = mod(y2 - 1n), v = mod(D * y2 + 1n);
    let x = pow(u * inv(v), (P + 3n) / 8n);
    if (mod(v * x * x - u) !== 0n) x = x * I % P;
    if (mod(v * x * x - u) !== 0n) throw new Error("not a point on the curve");
    if ((x & 1n) !== sign2) x = P - x;
    return x;
  }
  var ZERO = [0n, 1n, 1n, 0n];
  var G = [GX, GY, 1n, GX * GY % P];
  function add(p, q) {
    const [X1, Y1, Z1, T1] = p, [X2, Y2, Z2, T2] = q;
    const A = mod((Y1 - X1) * (Y2 - X2)), B = mod((Y1 + X1) * (Y2 + X2));
    const C = mod(2n * T1 * T2 * D), Dd = mod(2n * Z1 * Z2);
    const E = B - A, F = Dd - C, Gg = Dd + C, H = B + A;
    return [mod(E * F), mod(Gg * H), mod(F * Gg), mod(E * H)];
  }
  function dbl(p) {
    return add(p, p);
  }
  function mul(p, s) {
    let r = ZERO, q = p;
    for (let i = 0; i < 256; i++) {
      const bit = s >> BigInt(i) & 1n;
      const sum = add(r, q);
      r = bit === 1n ? sum : r;
      q = dbl(q);
    }
    return r;
  }
  function encode(p) {
    const zi = inv(p[2]);
    const x = p[0] * zi % P, y = p[1] * zi % P;
    const out = new Uint8Array(32);
    let v = y | (x & 1n) << 255n;
    for (let i = 0; i < 32; i++) {
      out[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return out;
  }
  function decode(b) {
    if (b.length !== 32) throw new Error("point must be 32 bytes");
    let y = 0n;
    for (let i = 31; i >= 0; i--) y = y << 8n | BigInt(b[i]);
    const sign2 = y >> 255n;
    y &= (1n << 255n) - 1n;
    if (y >= P) throw new Error("non-canonical point");
    const x = recoverX(y, sign2);
    if (x === 0n && sign2 === 1n) throw new Error("non-canonical point");
    return [x, y, 1n, x * y % P];
  }
  function leToBig(b) {
    let v = 0n;
    for (let i = b.length - 1; i >= 0; i--) v = v << 8n | BigInt(b[i]);
    return v;
  }
  function bigToLe(v, n) {
    const o = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      o[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    return o;
  }
  function clamp(h) {
    const k = h.slice(0, 32);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    return leToBig(k);
  }
  function publicKeyFromSeed(seed) {
    if (seed.length !== 32) throw new Error("seed must be 32 bytes");
    return encode(mul(G, clamp(sha512(seed))));
  }
  function sign(msg, seed) {
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
  function verify(msg, sig, publicKey) {
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

  // src/util/bip39-words.ts
  var BIP39_WORDS = [
    "abandon",
    "ability",
    "able",
    "about",
    "above",
    "absent",
    "absorb",
    "abstract",
    "absurd",
    "abuse",
    "access",
    "accident",
    "account",
    "accuse",
    "achieve",
    "acid",
    "acoustic",
    "acquire",
    "across",
    "act",
    "action",
    "actor",
    "actress",
    "actual",
    "adapt",
    "add",
    "addict",
    "address",
    "adjust",
    "admit",
    "adult",
    "advance",
    "advice",
    "aerobic",
    "affair",
    "afford",
    "afraid",
    "again",
    "age",
    "agent",
    "agree",
    "ahead",
    "aim",
    "air",
    "airport",
    "aisle",
    "alarm",
    "album",
    "alcohol",
    "alert",
    "alien",
    "all",
    "alley",
    "allow",
    "almost",
    "alone",
    "alpha",
    "already",
    "also",
    "alter",
    "always",
    "amateur",
    "amazing",
    "among",
    "amount",
    "amused",
    "analyst",
    "anchor",
    "ancient",
    "anger",
    "angle",
    "angry",
    "animal",
    "ankle",
    "announce",
    "annual",
    "another",
    "answer",
    "antenna",
    "antique",
    "anxiety",
    "any",
    "apart",
    "apology",
    "appear",
    "apple",
    "approve",
    "april",
    "arch",
    "arctic",
    "area",
    "arena",
    "argue",
    "arm",
    "armed",
    "armor",
    "army",
    "around",
    "arrange",
    "arrest",
    "arrive",
    "arrow",
    "art",
    "artefact",
    "artist",
    "artwork",
    "ask",
    "aspect",
    "assault",
    "asset",
    "assist",
    "assume",
    "asthma",
    "athlete",
    "atom",
    "attack",
    "attend",
    "attitude",
    "attract",
    "auction",
    "audit",
    "august",
    "aunt",
    "author",
    "auto",
    "autumn",
    "average",
    "avocado",
    "avoid",
    "awake",
    "aware",
    "away",
    "awesome",
    "awful",
    "awkward",
    "axis",
    "baby",
    "bachelor",
    "bacon",
    "badge",
    "bag",
    "balance",
    "balcony",
    "ball",
    "bamboo",
    "banana",
    "banner",
    "bar",
    "barely",
    "bargain",
    "barrel",
    "base",
    "basic",
    "basket",
    "battle",
    "beach",
    "bean",
    "beauty",
    "because",
    "become",
    "beef",
    "before",
    "begin",
    "behave",
    "behind",
    "believe",
    "below",
    "belt",
    "bench",
    "benefit",
    "best",
    "betray",
    "better",
    "between",
    "beyond",
    "bicycle",
    "bid",
    "bike",
    "bind",
    "biology",
    "bird",
    "birth",
    "bitter",
    "black",
    "blade",
    "blame",
    "blanket",
    "blast",
    "bleak",
    "bless",
    "blind",
    "blood",
    "blossom",
    "blouse",
    "blue",
    "blur",
    "blush",
    "board",
    "boat",
    "body",
    "boil",
    "bomb",
    "bone",
    "bonus",
    "book",
    "boost",
    "border",
    "boring",
    "borrow",
    "boss",
    "bottom",
    "bounce",
    "box",
    "boy",
    "bracket",
    "brain",
    "brand",
    "brass",
    "brave",
    "bread",
    "breeze",
    "brick",
    "bridge",
    "brief",
    "bright",
    "bring",
    "brisk",
    "broccoli",
    "broken",
    "bronze",
    "broom",
    "brother",
    "brown",
    "brush",
    "bubble",
    "buddy",
    "budget",
    "buffalo",
    "build",
    "bulb",
    "bulk",
    "bullet",
    "bundle",
    "bunker",
    "burden",
    "burger",
    "burst",
    "bus",
    "business",
    "busy",
    "butter",
    "buyer",
    "buzz",
    "cabbage",
    "cabin",
    "cable",
    "cactus",
    "cage",
    "cake",
    "call",
    "calm",
    "camera",
    "camp",
    "can",
    "canal",
    "cancel",
    "candy",
    "cannon",
    "canoe",
    "canvas",
    "canyon",
    "capable",
    "capital",
    "captain",
    "car",
    "carbon",
    "card",
    "cargo",
    "carpet",
    "carry",
    "cart",
    "case",
    "cash",
    "casino",
    "castle",
    "casual",
    "cat",
    "catalog",
    "catch",
    "category",
    "cattle",
    "caught",
    "cause",
    "caution",
    "cave",
    "ceiling",
    "celery",
    "cement",
    "census",
    "century",
    "cereal",
    "certain",
    "chair",
    "chalk",
    "champion",
    "change",
    "chaos",
    "chapter",
    "charge",
    "chase",
    "chat",
    "cheap",
    "check",
    "cheese",
    "chef",
    "cherry",
    "chest",
    "chicken",
    "chief",
    "child",
    "chimney",
    "choice",
    "choose",
    "chronic",
    "chuckle",
    "chunk",
    "churn",
    "cigar",
    "cinnamon",
    "circle",
    "citizen",
    "city",
    "civil",
    "claim",
    "clap",
    "clarify",
    "claw",
    "clay",
    "clean",
    "clerk",
    "clever",
    "click",
    "client",
    "cliff",
    "climb",
    "clinic",
    "clip",
    "clock",
    "clog",
    "close",
    "cloth",
    "cloud",
    "clown",
    "club",
    "clump",
    "cluster",
    "clutch",
    "coach",
    "coast",
    "coconut",
    "code",
    "coffee",
    "coil",
    "coin",
    "collect",
    "color",
    "column",
    "combine",
    "come",
    "comfort",
    "comic",
    "common",
    "company",
    "concert",
    "conduct",
    "confirm",
    "congress",
    "connect",
    "consider",
    "control",
    "convince",
    "cook",
    "cool",
    "copper",
    "copy",
    "coral",
    "core",
    "corn",
    "correct",
    "cost",
    "cotton",
    "couch",
    "country",
    "couple",
    "course",
    "cousin",
    "cover",
    "coyote",
    "crack",
    "cradle",
    "craft",
    "cram",
    "crane",
    "crash",
    "crater",
    "crawl",
    "crazy",
    "cream",
    "credit",
    "creek",
    "crew",
    "cricket",
    "crime",
    "crisp",
    "critic",
    "crop",
    "cross",
    "crouch",
    "crowd",
    "crucial",
    "cruel",
    "cruise",
    "crumble",
    "crunch",
    "crush",
    "cry",
    "crystal",
    "cube",
    "culture",
    "cup",
    "cupboard",
    "curious",
    "current",
    "curtain",
    "curve",
    "cushion",
    "custom",
    "cute",
    "cycle",
    "dad",
    "damage",
    "damp",
    "dance",
    "danger",
    "daring",
    "dash",
    "daughter",
    "dawn",
    "day",
    "deal",
    "debate",
    "debris",
    "decade",
    "december",
    "decide",
    "decline",
    "decorate",
    "decrease",
    "deer",
    "defense",
    "define",
    "defy",
    "degree",
    "delay",
    "deliver",
    "demand",
    "demise",
    "denial",
    "dentist",
    "deny",
    "depart",
    "depend",
    "deposit",
    "depth",
    "deputy",
    "derive",
    "describe",
    "desert",
    "design",
    "desk",
    "despair",
    "destroy",
    "detail",
    "detect",
    "develop",
    "device",
    "devote",
    "diagram",
    "dial",
    "diamond",
    "diary",
    "dice",
    "diesel",
    "diet",
    "differ",
    "digital",
    "dignity",
    "dilemma",
    "dinner",
    "dinosaur",
    "direct",
    "dirt",
    "disagree",
    "discover",
    "disease",
    "dish",
    "dismiss",
    "disorder",
    "display",
    "distance",
    "divert",
    "divide",
    "divorce",
    "dizzy",
    "doctor",
    "document",
    "dog",
    "doll",
    "dolphin",
    "domain",
    "donate",
    "donkey",
    "donor",
    "door",
    "dose",
    "double",
    "dove",
    "draft",
    "dragon",
    "drama",
    "drastic",
    "draw",
    "dream",
    "dress",
    "drift",
    "drill",
    "drink",
    "drip",
    "drive",
    "drop",
    "drum",
    "dry",
    "duck",
    "dumb",
    "dune",
    "during",
    "dust",
    "dutch",
    "duty",
    "dwarf",
    "dynamic",
    "eager",
    "eagle",
    "early",
    "earn",
    "earth",
    "easily",
    "east",
    "easy",
    "echo",
    "ecology",
    "economy",
    "edge",
    "edit",
    "educate",
    "effort",
    "egg",
    "eight",
    "either",
    "elbow",
    "elder",
    "electric",
    "elegant",
    "element",
    "elephant",
    "elevator",
    "elite",
    "else",
    "embark",
    "embody",
    "embrace",
    "emerge",
    "emotion",
    "employ",
    "empower",
    "empty",
    "enable",
    "enact",
    "end",
    "endless",
    "endorse",
    "enemy",
    "energy",
    "enforce",
    "engage",
    "engine",
    "enhance",
    "enjoy",
    "enlist",
    "enough",
    "enrich",
    "enroll",
    "ensure",
    "enter",
    "entire",
    "entry",
    "envelope",
    "episode",
    "equal",
    "equip",
    "era",
    "erase",
    "erode",
    "erosion",
    "error",
    "erupt",
    "escape",
    "essay",
    "essence",
    "estate",
    "eternal",
    "ethics",
    "evidence",
    "evil",
    "evoke",
    "evolve",
    "exact",
    "example",
    "excess",
    "exchange",
    "excite",
    "exclude",
    "excuse",
    "execute",
    "exercise",
    "exhaust",
    "exhibit",
    "exile",
    "exist",
    "exit",
    "exotic",
    "expand",
    "expect",
    "expire",
    "explain",
    "expose",
    "express",
    "extend",
    "extra",
    "eye",
    "eyebrow",
    "fabric",
    "face",
    "faculty",
    "fade",
    "faint",
    "faith",
    "fall",
    "false",
    "fame",
    "family",
    "famous",
    "fan",
    "fancy",
    "fantasy",
    "farm",
    "fashion",
    "fat",
    "fatal",
    "father",
    "fatigue",
    "fault",
    "favorite",
    "feature",
    "february",
    "federal",
    "fee",
    "feed",
    "feel",
    "female",
    "fence",
    "festival",
    "fetch",
    "fever",
    "few",
    "fiber",
    "fiction",
    "field",
    "figure",
    "file",
    "film",
    "filter",
    "final",
    "find",
    "fine",
    "finger",
    "finish",
    "fire",
    "firm",
    "first",
    "fiscal",
    "fish",
    "fit",
    "fitness",
    "fix",
    "flag",
    "flame",
    "flash",
    "flat",
    "flavor",
    "flee",
    "flight",
    "flip",
    "float",
    "flock",
    "floor",
    "flower",
    "fluid",
    "flush",
    "fly",
    "foam",
    "focus",
    "fog",
    "foil",
    "fold",
    "follow",
    "food",
    "foot",
    "force",
    "forest",
    "forget",
    "fork",
    "fortune",
    "forum",
    "forward",
    "fossil",
    "foster",
    "found",
    "fox",
    "fragile",
    "frame",
    "frequent",
    "fresh",
    "friend",
    "fringe",
    "frog",
    "front",
    "frost",
    "frown",
    "frozen",
    "fruit",
    "fuel",
    "fun",
    "funny",
    "furnace",
    "fury",
    "future",
    "gadget",
    "gain",
    "galaxy",
    "gallery",
    "app",
    "gap",
    "garage",
    "garbage",
    "garden",
    "garlic",
    "garment",
    "gas",
    "gasp",
    "gate",
    "gather",
    "gauge",
    "gaze",
    "general",
    "genius",
    "genre",
    "gentle",
    "genuine",
    "gesture",
    "ghost",
    "giant",
    "gift",
    "giggle",
    "ginger",
    "giraffe",
    "girl",
    "give",
    "glad",
    "glance",
    "glare",
    "glass",
    "glide",
    "glimpse",
    "globe",
    "gloom",
    "glory",
    "glove",
    "glow",
    "glue",
    "goat",
    "goddess",
    "gold",
    "good",
    "goose",
    "gorilla",
    "gospel",
    "gossip",
    "govern",
    "gown",
    "grab",
    "grace",
    "grain",
    "grant",
    "grape",
    "grass",
    "gravity",
    "great",
    "green",
    "grid",
    "grief",
    "grit",
    "grocery",
    "group",
    "grow",
    "grunt",
    "guard",
    "guess",
    "guide",
    "guilt",
    "guitar",
    "gun",
    "gym",
    "habit",
    "hair",
    "half",
    "hammer",
    "hamster",
    "hand",
    "happy",
    "harbor",
    "hard",
    "harsh",
    "harvest",
    "hat",
    "have",
    "hawk",
    "hazard",
    "head",
    "health",
    "heart",
    "heavy",
    "hedgehog",
    "height",
    "hello",
    "helmet",
    "help",
    "hen",
    "hero",
    "hidden",
    "high",
    "hill",
    "hint",
    "hip",
    "hire",
    "history",
    "hobby",
    "hockey",
    "hold",
    "hole",
    "holiday",
    "hollow",
    "home",
    "honey",
    "hood",
    "hope",
    "horn",
    "horror",
    "horse",
    "hospital",
    "host",
    "hotel",
    "hour",
    "hover",
    "hub",
    "huge",
    "human",
    "humble",
    "humor",
    "hundred",
    "hungry",
    "hunt",
    "hurdle",
    "hurry",
    "hurt",
    "husband",
    "hybrid",
    "ice",
    "icon",
    "idea",
    "identify",
    "idle",
    "ignore",
    "ill",
    "illegal",
    "illness",
    "image",
    "imitate",
    "immense",
    "immune",
    "impact",
    "impose",
    "improve",
    "impulse",
    "inch",
    "include",
    "income",
    "increase",
    "index",
    "indicate",
    "indoor",
    "industry",
    "infant",
    "inflict",
    "inform",
    "inhale",
    "inherit",
    "initial",
    "inject",
    "injury",
    "inmate",
    "inner",
    "innocent",
    "input",
    "inquiry",
    "insane",
    "insect",
    "inside",
    "inspire",
    "install",
    "intact",
    "interest",
    "into",
    "invest",
    "invite",
    "involve",
    "iron",
    "island",
    "isolate",
    "issue",
    "item",
    "ivory",
    "jacket",
    "jaguar",
    "jar",
    "jazz",
    "jealous",
    "jeans",
    "jelly",
    "jewel",
    "job",
    "join",
    "joke",
    "journey",
    "joy",
    "judge",
    "juice",
    "jump",
    "jungle",
    "junior",
    "junk",
    "just",
    "kangaroo",
    "keen",
    "keep",
    "ketchup",
    "key",
    "kick",
    "kid",
    "kidney",
    "kind",
    "kingdom",
    "kiss",
    "kit",
    "kitchen",
    "kite",
    "kitten",
    "kiwi",
    "knee",
    "knife",
    "knock",
    "know",
    "lab",
    "label",
    "labor",
    "ladder",
    "lady",
    "lake",
    "lamp",
    "language",
    "laptop",
    "large",
    "later",
    "latin",
    "laugh",
    "laundry",
    "lava",
    "law",
    "lawn",
    "lawsuit",
    "layer",
    "lazy",
    "leader",
    "leaf",
    "learn",
    "leave",
    "lecture",
    "left",
    "leg",
    "legal",
    "legend",
    "leisure",
    "lemon",
    "lend",
    "length",
    "lens",
    "leopard",
    "lesson",
    "letter",
    "level",
    "liar",
    "liberty",
    "library",
    "license",
    "life",
    "lift",
    "light",
    "like",
    "limb",
    "limit",
    "link",
    "lion",
    "liquid",
    "list",
    "little",
    "live",
    "lizard",
    "load",
    "loan",
    "lobster",
    "local",
    "lock",
    "logic",
    "lonely",
    "long",
    "loop",
    "lottery",
    "loud",
    "lounge",
    "love",
    "loyal",
    "lucky",
    "luggage",
    "lumber",
    "lunar",
    "lunch",
    "luxury",
    "lyrics",
    "machine",
    "mad",
    "magic",
    "magnet",
    "maid",
    "mail",
    "main",
    "major",
    "make",
    "mammal",
    "man",
    "manage",
    "mandate",
    "mango",
    "mansion",
    "manual",
    "maple",
    "marble",
    "march",
    "margin",
    "marine",
    "market",
    "marriage",
    "mask",
    "mass",
    "master",
    "match",
    "material",
    "math",
    "matrix",
    "matter",
    "maximum",
    "maze",
    "meadow",
    "mean",
    "measure",
    "meat",
    "mechanic",
    "medal",
    "media",
    "melody",
    "melt",
    "member",
    "memory",
    "mention",
    "menu",
    "mercy",
    "merge",
    "merit",
    "merry",
    "mesh",
    "message",
    "metal",
    "method",
    "middle",
    "midnight",
    "milk",
    "million",
    "mimic",
    "mind",
    "minimum",
    "minor",
    "minute",
    "miracle",
    "mirror",
    "misery",
    "miss",
    "mistake",
    "mix",
    "mixed",
    "mixture",
    "mobile",
    "model",
    "modify",
    "mom",
    "moment",
    "monitor",
    "monkey",
    "monster",
    "month",
    "moon",
    "moral",
    "more",
    "morning",
    "mosquito",
    "mother",
    "motion",
    "motor",
    "mountain",
    "mouse",
    "move",
    "movie",
    "much",
    "muffin",
    "mule",
    "multiply",
    "muscle",
    "museum",
    "mushroom",
    "music",
    "must",
    "mutual",
    "myself",
    "mystery",
    "myth",
    "naive",
    "name",
    "napkin",
    "narrow",
    "nasty",
    "nation",
    "nature",
    "near",
    "neck",
    "need",
    "negative",
    "neglect",
    "neither",
    "nephew",
    "nerve",
    "nest",
    "net",
    "network",
    "neutral",
    "never",
    "news",
    "next",
    "nice",
    "night",
    "noble",
    "noise",
    "nominee",
    "noodle",
    "normal",
    "north",
    "nose",
    "notable",
    "note",
    "nothing",
    "notice",
    "novel",
    "now",
    "nuclear",
    "number",
    "nurse",
    "nut",
    "oak",
    "obey",
    "object",
    "oblige",
    "obscure",
    "observe",
    "obtain",
    "obvious",
    "occur",
    "ocean",
    "october",
    "odor",
    "off",
    "offer",
    "office",
    "often",
    "oil",
    "okay",
    "old",
    "olive",
    "olympic",
    "omit",
    "once",
    "one",
    "onion",
    "online",
    "only",
    "open",
    "opera",
    "opinion",
    "oppose",
    "option",
    "orange",
    "orbit",
    "orchard",
    "order",
    "ordinary",
    "organ",
    "orient",
    "original",
    "orphan",
    "ostrich",
    "other",
    "outdoor",
    "outer",
    "output",
    "outside",
    "oval",
    "oven",
    "over",
    "own",
    "owner",
    "oxygen",
    "oyster",
    "ozone",
    "pact",
    "paddle",
    "page",
    "pair",
    "palace",
    "palm",
    "panda",
    "panel",
    "panic",
    "panther",
    "paper",
    "parade",
    "parent",
    "park",
    "parrot",
    "party",
    "pass",
    "patch",
    "path",
    "patient",
    "patrol",
    "pattern",
    "pause",
    "pave",
    "payment",
    "peace",
    "peanut",
    "pear",
    "peasant",
    "pelican",
    "pen",
    "penalty",
    "pencil",
    "people",
    "pepper",
    "perfect",
    "permit",
    "person",
    "pet",
    "phone",
    "photo",
    "phrase",
    "physical",
    "piano",
    "picnic",
    "picture",
    "piece",
    "pig",
    "pigeon",
    "pill",
    "pilot",
    "pink",
    "pioneer",
    "pipe",
    "pistol",
    "pitch",
    "pizza",
    "place",
    "planet",
    "plastic",
    "plate",
    "play",
    "please",
    "pledge",
    "pluck",
    "plug",
    "plunge",
    "poem",
    "poet",
    "point",
    "polar",
    "pole",
    "police",
    "pond",
    "pony",
    "pool",
    "popular",
    "portion",
    "position",
    "possible",
    "post",
    "potato",
    "pottery",
    "poverty",
    "powder",
    "power",
    "practice",
    "praise",
    "predict",
    "prefer",
    "prepare",
    "present",
    "pretty",
    "prevent",
    "price",
    "pride",
    "primary",
    "print",
    "priority",
    "prison",
    "private",
    "prize",
    "problem",
    "process",
    "produce",
    "profit",
    "program",
    "project",
    "promote",
    "proof",
    "property",
    "prosper",
    "protect",
    "proud",
    "provide",
    "public",
    "pudding",
    "pull",
    "pulp",
    "pulse",
    "pumpkin",
    "punch",
    "pupil",
    "puppy",
    "purchase",
    "purity",
    "purpose",
    "purse",
    "push",
    "put",
    "puzzle",
    "pyramid",
    "quality",
    "quantum",
    "quarter",
    "question",
    "quick",
    "quit",
    "quiz",
    "quote",
    "rabbit",
    "raccoon",
    "race",
    "rack",
    "radar",
    "radio",
    "rail",
    "rain",
    "raise",
    "rally",
    "ramp",
    "ranch",
    "random",
    "range",
    "rapid",
    "rare",
    "rate",
    "rather",
    "raven",
    "raw",
    "razor",
    "ready",
    "real",
    "reason",
    "rebel",
    "rebuild",
    "recall",
    "receive",
    "recipe",
    "record",
    "recycle",
    "reduce",
    "reflect",
    "reform",
    "refuse",
    "region",
    "regret",
    "regular",
    "reject",
    "relax",
    "release",
    "relief",
    "rely",
    "remain",
    "remember",
    "remind",
    "remove",
    "render",
    "renew",
    "rent",
    "reopen",
    "repair",
    "repeat",
    "replace",
    "report",
    "require",
    "rescue",
    "resemble",
    "resist",
    "resource",
    "response",
    "result",
    "retire",
    "retreat",
    "return",
    "reunion",
    "reveal",
    "review",
    "reward",
    "rhythm",
    "rib",
    "ribbon",
    "rice",
    "rich",
    "ride",
    "ridge",
    "rifle",
    "right",
    "rigid",
    "ring",
    "riot",
    "ripple",
    "risk",
    "ritual",
    "rival",
    "river",
    "road",
    "roast",
    "robot",
    "robust",
    "rocket",
    "romance",
    "roof",
    "rookie",
    "room",
    "rose",
    "rotate",
    "rough",
    "round",
    "route",
    "royal",
    "rubber",
    "rude",
    "rug",
    "rule",
    "run",
    "runway",
    "rural",
    "sad",
    "saddle",
    "sadness",
    "safe",
    "sail",
    "salad",
    "salmon",
    "salon",
    "salt",
    "salute",
    "same",
    "sample",
    "sand",
    "satisfy",
    "satoshi",
    "sauce",
    "sausage",
    "save",
    "say",
    "scale",
    "scan",
    "scare",
    "scatter",
    "scene",
    "scheme",
    "school",
    "science",
    "scissors",
    "scorpion",
    "scout",
    "scrap",
    "screen",
    "script",
    "scrub",
    "sea",
    "search",
    "season",
    "seat",
    "second",
    "secret",
    "section",
    "security",
    "seed",
    "seek",
    "segment",
    "select",
    "sell",
    "seminar",
    "senior",
    "sense",
    "sentence",
    "series",
    "service",
    "session",
    "settle",
    "setup",
    "seven",
    "shadow",
    "shaft",
    "shallow",
    "share",
    "shed",
    "shell",
    "sheriff",
    "shield",
    "shift",
    "shine",
    "ship",
    "shiver",
    "shock",
    "shoe",
    "shoot",
    "shop",
    "short",
    "shoulder",
    "shove",
    "shrimp",
    "shrug",
    "shuffle",
    "shy",
    "sibling",
    "sick",
    "side",
    "siege",
    "sight",
    "sign",
    "silent",
    "silk",
    "silly",
    "silver",
    "similar",
    "simple",
    "since",
    "sing",
    "siren",
    "sister",
    "situate",
    "six",
    "size",
    "skate",
    "sketch",
    "ski",
    "skill",
    "skin",
    "skirt",
    "skull",
    "slab",
    "slam",
    "sleep",
    "slender",
    "slice",
    "slide",
    "slight",
    "slim",
    "slogan",
    "slot",
    "slow",
    "slush",
    "small",
    "smart",
    "smile",
    "smoke",
    "smooth",
    "snack",
    "snake",
    "snap",
    "sniff",
    "snow",
    "soap",
    "soccer",
    "social",
    "sock",
    "soda",
    "soft",
    "solar",
    "soldier",
    "solid",
    "solution",
    "solve",
    "someone",
    "song",
    "soon",
    "sorry",
    "sort",
    "soul",
    "sound",
    "soup",
    "source",
    "south",
    "space",
    "spare",
    "spatial",
    "spawn",
    "speak",
    "special",
    "speed",
    "spell",
    "spend",
    "sphere",
    "spice",
    "spider",
    "spike",
    "spin",
    "spirit",
    "split",
    "spoil",
    "sponsor",
    "spoon",
    "sport",
    "spot",
    "spray",
    "spread",
    "spring",
    "spy",
    "square",
    "squeeze",
    "squirrel",
    "stable",
    "stadium",
    "staff",
    "stage",
    "stairs",
    "stamp",
    "stand",
    "start",
    "state",
    "stay",
    "steak",
    "steel",
    "stem",
    "step",
    "stereo",
    "stick",
    "still",
    "sting",
    "stock",
    "stomach",
    "stone",
    "stool",
    "story",
    "stove",
    "strategy",
    "street",
    "strike",
    "strong",
    "struggle",
    "student",
    "stuff",
    "stumble",
    "style",
    "subject",
    "submit",
    "subway",
    "success",
    "such",
    "sudden",
    "suffer",
    "sugar",
    "suggest",
    "suit",
    "summer",
    "sun",
    "sunny",
    "sunset",
    "super",
    "supply",
    "supreme",
    "sure",
    "surface",
    "surge",
    "surprise",
    "surround",
    "survey",
    "suspect",
    "sustain",
    "swallow",
    "swamp",
    "swap",
    "swarm",
    "swear",
    "sweet",
    "swift",
    "swim",
    "swing",
    "switch",
    "sword",
    "symbol",
    "symptom",
    "syrup",
    "system",
    "table",
    "tackle",
    "tag",
    "tail",
    "talent",
    "talk",
    "tank",
    "tape",
    "target",
    "task",
    "taste",
    "tattoo",
    "taxi",
    "teach",
    "team",
    "tell",
    "ten",
    "tenant",
    "tennis",
    "tent",
    "term",
    "test",
    "text",
    "thank",
    "that",
    "theme",
    "then",
    "theory",
    "there",
    "they",
    "thing",
    "this",
    "thought",
    "three",
    "thrive",
    "throw",
    "thumb",
    "thunder",
    "ticket",
    "tide",
    "tiger",
    "tilt",
    "timber",
    "time",
    "tiny",
    "tip",
    "tired",
    "tissue",
    "title",
    "toast",
    "tobacco",
    "today",
    "toddler",
    "toe",
    "together",
    "toilet",
    "token",
    "tomato",
    "tomorrow",
    "tone",
    "tongue",
    "tonight",
    "tool",
    "tooth",
    "top",
    "topic",
    "topple",
    "torch",
    "tornado",
    "tortoise",
    "toss",
    "total",
    "tourist",
    "toward",
    "tower",
    "town",
    "toy",
    "track",
    "trade",
    "traffic",
    "tragic",
    "train",
    "transfer",
    "trap",
    "trash",
    "travel",
    "tray",
    "treat",
    "tree",
    "trend",
    "trial",
    "tribe",
    "trick",
    "trigger",
    "trim",
    "trip",
    "trophy",
    "trouble",
    "truck",
    "true",
    "truly",
    "trumpet",
    "trust",
    "truth",
    "try",
    "tube",
    "tuition",
    "tumble",
    "tuna",
    "tunnel",
    "turkey",
    "turn",
    "turtle",
    "twelve",
    "twenty",
    "twice",
    "twin",
    "twist",
    "two",
    "type",
    "typical",
    "ugly",
    "umbrella",
    "unable",
    "unaware",
    "uncle",
    "uncover",
    "under",
    "undo",
    "unfair",
    "unfold",
    "unhappy",
    "uniform",
    "unique",
    "unit",
    "universe",
    "unknown",
    "unlock",
    "until",
    "unusual",
    "unveil",
    "update",
    "upgrade",
    "uphold",
    "upon",
    "upper",
    "upset",
    "urban",
    "urge",
    "usage",
    "use",
    "used",
    "useful",
    "useless",
    "usual",
    "utility",
    "vacant",
    "vacuum",
    "vague",
    "valid",
    "valley",
    "valve",
    "van",
    "vanish",
    "vapor",
    "various",
    "vast",
    "vault",
    "vehicle",
    "velvet",
    "vendor",
    "venture",
    "venue",
    "verb",
    "verify",
    "version",
    "very",
    "vessel",
    "veteran",
    "viable",
    "vibrant",
    "vicious",
    "victory",
    "video",
    "view",
    "village",
    "vintage",
    "violin",
    "virtual",
    "virus",
    "visa",
    "visit",
    "visual",
    "vital",
    "vivid",
    "vocal",
    "voice",
    "void",
    "volcano",
    "volume",
    "vote",
    "voyage",
    "wage",
    "wagon",
    "wait",
    "walk",
    "wall",
    "walnut",
    "want",
    "warfare",
    "warm",
    "warrior",
    "wash",
    "wasp",
    "waste",
    "water",
    "wave",
    "way",
    "wealth",
    "weapon",
    "wear",
    "weasel",
    "weather",
    "web",
    "wedding",
    "weekend",
    "weird",
    "welcome",
    "west",
    "wet",
    "whale",
    "what",
    "wheat",
    "wheel",
    "when",
    "where",
    "whip",
    "whisper",
    "wide",
    "width",
    "wife",
    "wild",
    "will",
    "win",
    "window",
    "wine",
    "wing",
    "wink",
    "winner",
    "winter",
    "wire",
    "wisdom",
    "wise",
    "wish",
    "witness",
    "wolf",
    "woman",
    "wonder",
    "wood",
    "wool",
    "word",
    "work",
    "world",
    "worry",
    "worth",
    "wrap",
    "wreck",
    "wrestle",
    "wrist",
    "write",
    "wrong",
    "yard",
    "year",
    "yellow",
    "you",
    "young",
    "youth",
    "zebra",
    "zero",
    "zone",
    "zoo"
  ];

  // src/keys.ts
  function keyPairFromSeed(seed) {
    const s = typeof seed === "string" ? seedFromHex(seed) : seed;
    if (s.length !== 32) throw new Error("Private key must be 64 hex characters (32 bytes)");
    const publicKey = publicKeyFromSeed(s);
    return {
      seed: s,
      publicKey,
      address: encodeZbcAddress(publicKey, "ZBC"),
      nodeAddress: encodeZbcAddress(publicKey, "ZNK"),
      accountBytes: typedAddress(AccountType.ZooBC, publicKey)
    };
  }
  function seedFromHex(hex) {
    if (!isHex(hex, 64)) throw new Error("Private key must be 64 hex characters (32 bytes)");
    return hexToBytes(hex);
  }
  function randomSeed() {
    const s = new Uint8Array(32);
    globalThis.crypto.getRandomValues(s);
    return s;
  }
  function validateMnemonic(mnemonic) {
    const words = mnemonic.trim().split(/\s+/);
    if (![12, 15, 18, 21, 24].includes(words.length)) return false;
    let bits = "";
    for (const w of words) {
      const i = BIP39_WORDS.indexOf(w);
      if (i < 0) return false;
      bits += i.toString(2).padStart(11, "0");
    }
    const cs = words.length / 3;
    const entropy = new Uint8Array((bits.length - cs) / 8);
    for (let i = 0; i < entropy.length; i++) entropy[i] = parseInt(bits.slice(8 * i, 8 * i + 8), 2);
    const hash = sha256(entropy);
    return bits.slice(bits.length - cs) === hash[0].toString(2).padStart(8, "0").slice(0, cs);
  }
  function mnemonicFromEntropy(entropy) {
    if (entropy.length < 16 || entropy.length > 32 || entropy.length % 4 !== 0) throw new Error("entropy must be 16-32 bytes");
    let bits = "";
    for (const b of entropy) bits += b.toString(2).padStart(8, "0");
    const cs = entropy.length / 4;
    bits += sha256(entropy)[0].toString(2).padStart(8, "0").slice(0, cs);
    const words = [];
    for (let i = 0; i < bits.length / 11; i++) words.push(BIP39_WORDS[parseInt(bits.slice(11 * i, 11 * i + 11), 2)]);
    return words.join(" ");
  }
  function generateMnemonic(words = 24) {
    const entropy = new Uint8Array((words * 11 - words / 3) / 8);
    globalThis.crypto.getRandomValues(entropy);
    return mnemonicFromEntropy(entropy);
  }
  function mnemonicToSeed(mnemonic, passphrase = "") {
    return pbkdf2Sha512(utf8(mnemonic.trim().split(/\s+/).join(" ")), utf8("mnemonic" + passphrase), 2048, 64);
  }
  function slip10Derive(path, seed) {
    if (!/^m(\/[0-9]+')+$/.test(path)) throw new Error("invalid derivation path: " + path);
    let I2 = hmacSha512(utf8("ed25519 seed"), seed);
    let key = I2.slice(0, 32), chain = I2.slice(32);
    for (const seg of path.split("/").slice(1)) {
      const index = Number(seg.slice(0, -1));
      if (index >= 2147483648) throw new Error("path index too large");
      const data = new Uint8Array(37);
      data.set(key, 1);
      new DataView(data.buffer).setUint32(33, index + 2147483648, false);
      I2 = hmacSha512(chain, data);
      key = I2.slice(0, 32);
      chain = I2.slice(32);
    }
    return key;
  }
  var ZOOBC_COIN_TYPE = 883;
  function walletAccount(mnemonic, index, passphrase = "") {
    const path = `m/44'/${ZOOBC_COIN_TYPE}'/${index}'`;
    const seed = slip10Derive(path, mnemonicToSeed(mnemonic, passphrase));
    return { ...keyPairFromSeed(seed), index, path };
  }
  var seedHex = (kp) => bytesToHex(kp.seed);
  var publicKeyHex = (kp) => bytesToHex(kp.publicKey);

  // src/message.ts
  var MESSAGE_SIGNING_SCHEME = "ZBC-MSG-v1";
  var TAG = utf8("ZBC-MSG");
  function messageDigest(message) {
    return sha3_256(concat(TAG, message));
  }
  function signMessage(seed, message) {
    const kp = keyPairFromSeed(seed);
    const digest = messageDigest(message);
    return {
      scheme: MESSAGE_SIGNING_SCHEME,
      address: kp.address,
      public_key: bytesToHex(kp.publicKey),
      message_hex: bytesToHex(message),
      digest: bytesToHex(digest),
      signature: bytesToHex(sign(digest, kp.seed))
    };
  }
  function verifyMessage(address, message, signature) {
    const pub = publicKeyOfAddress(address);
    if (!pub) return false;
    const sig = typeof signature === "string" ? isHex(signature, 128) ? hexToBytes(signature) : null : signature;
    if (!sig || sig.length !== 64) return false;
    return verify(messageDigest(message), sig, pub);
  }
  function publicKeyOfAddress(address) {
    if (isHex(address, 64)) return hexToBytes(address);
    const d = decodeZbcAddress(address);
    return d && d.prefix === "ZBC" ? d.payload : null;
  }

  // src/transaction.ts
  var TX_SIGNING_TAG = utf8("ZBC-TX");
  var EMPTY_ACCOUNT = new ByteWriter().u32(AccountType.Empty).finish();
  function signingContext(genesis) {
    if (typeof genesis === "string") {
      if (genesis === "v1" || genesis === "legacy") return { version: 1 };
      if (!isHex(genesis, 64)) throw new Error("--genesis must be the 64-hex genesis block hash (or 'v1' for the legacy digest)");
      return { version: 2, genesisHash: hexToBytes(genesis) };
    }
    if (genesis.length !== 32) throw new Error("genesis hash must be 32 bytes");
    return { version: 2, genesisHash: genesis };
  }
  function escrowBytes(e) {
    const approver = parseAddress(e.approver);
    const instruction = utf8(e.instruction ?? "");
    return new ByteWriter().bytes(approver.bytes).i64(e.commission).i64(e.timeout).u32(instruction.length).bytes(instruction).u8(0).finish();
  }
  function unsignedBytes(tx) {
    const w = new ByteWriter().u32(tx.type).u8(tx.version ?? 1).i64(tx.timestamp).bytes(tx.sender);
    const recipientEmpty = tx.recipient.length === 0 || tx.recipient.every((b) => b === 0);
    w.bytes(recipientEmpty ? EMPTY_ACCOUNT : tx.recipient);
    w.i64(tx.fee).u32(tx.body.length).bytes(tx.body);
    if (tx.escrow) w.bytes(escrowBytes(tx.escrow));
    else w.bytes(EMPTY_ACCOUNT);
    const msg = tx.message ?? new Uint8Array();
    w.u32(msg.length).bytes(msg);
    return w.finish();
  }
  function signingDigest(unsigned, ctx) {
    return ctx.version === 2 ? sha3_256(concat(TX_SIGNING_TAG, ctx.genesisHash, unsigned)) : sha3_256(unsigned);
  }
  function transactionHash(unsigned, signature) {
    return sha3_256(concat(unsigned, signature));
  }
  function transactionId(hash) {
    return readI64LE(hash, 0);
  }
  function signTransaction(tx, key, ctx) {
    const kp = key instanceof Uint8Array || typeof key === "string" ? keyPairFromSeed(key) : key;
    const unsigned = unsignedBytes(tx);
    const digest = signingDigest(unsigned, ctx);
    const signature = sign(digest, kp.seed);
    const bytes = concat(unsigned, signature);
    const hash = sha3_256(bytes);
    const recipientForJson = tx.recipient.length === 0 ? "" : tx.recipient.length === 36 && tx.recipient[0] === 0 && tx.recipient[1] === 0 && tx.recipient[2] === 0 && tx.recipient[3] === 0 ? bytesToHex(tx.recipient.slice(4)) : bytesToHex(tx.recipient);
    const payload = {
      version: tx.version ?? 1,
      timestamp: BigInt(tx.timestamp),
      sender_account_address: bytesToHex(tx.sender.slice(4)),
      recipient_account_address: recipientForJson,
      transaction_type: tx.type,
      fee: BigInt(tx.fee),
      transaction_body_bytes: bytesToHex(tx.body),
      signature: bytesToHex(signature)
    };
    if (tx.message && tx.message.length) payload.message_hex = bytesToHex(tx.message);
    if (tx.escrow) {
      payload.escrow = { approver_address: bytesToHex(parseAddress(tx.escrow.approver).bytes), commission: BigInt(tx.escrow.commission), timeout: BigInt(tx.escrow.timeout) };
      if (tx.escrow.instruction) payload.escrow.instruction = tx.escrow.instruction;
    }
    return { unsigned, digest, signature, bytes, hash, payload, signingVersion: ctx.version, genesisHash: ctx.version === 2 ? ctx.genesisHash : void 0 };
  }
  var TransactionType = { SendZBC: 1, ApprovalEscrow: 4 };
  function sendZbcBody(amount) {
    return new ByteWriter().i64(amount).finish();
  }
  var EscrowApproval = { approve: 0, reject: 1, expire: 2 };
  function approvalEscrowBody(approval, escrowedTransactionHash) {
    if (escrowedTransactionHash.length !== 32) throw new Error("Transaction hash must be 64 hex characters (the escrowed transaction's SHA3-256 hash)");
    return new ByteWriter().u32(approval).bytes(escrowedTransactionHash).finish();
  }

  // src/errors.ts
  var ExitCode = {
    ok: 0,
    internal: 1,
    usage: 2,
    node_unreachable: 3,
    insufficient_balance: 4,
    fee_too_low: 5,
    rejected: 6,
    not_found: 7,
    timeout: 8,
    node_busy: 9,
    verify_failed: 10
  };
  function errorClassOf(code) {
    for (const [k, v] of Object.entries(ExitCode)) if (v === code) return k;
    return "internal";
  }
  var ToolError = class extends Error {
    constructor(code, message, extra = {}) {
      super(message);
      __publicField(this, "code");
      __publicField(this, "extra");
      this.code = code;
      this.extra = extra;
    }
    get errorClass() {
      return errorClassOf(this.code);
    }
    toJSON() {
      return { success: false, error: this.message, exit_code: this.code, error_class: this.errorClass, ...this.extra };
    }
  };
  var usage = (msg) => new ToolError(ExitCode.usage, msg);
  function classifyNodeError(httpCode, text) {
    if (httpCode === 0) return ExitCode.node_unreachable;
    if (httpCode >= 500) return ExitCode.node_busy;
    const t = text.toLowerCase();
    if (t.includes("fee too low")) return ExitCode.fee_too_low;
    if (t.includes("insufficient balance") || t.includes("insufficient spendable") || t.includes("account does not exist")) return ExitCode.insufficient_balance;
    if (t.includes("not found") || t.includes("unknown token") || t.includes("unknown or expired token") || t.includes("unknown app")) return ExitCode.not_found;
    return ExitCode.rejected;
  }

  // src/util/json.ts
  var MARK = "~bigint~";
  function stringifyJson(value, indent) {
    const text = JSON.stringify(value, (_k, v) => typeof v === "bigint" ? MARK + v.toString() + MARK : v, indent);
    return text.replace(/"~bigint~(-?\d+)~bigint~"/g, "$1");
  }
  function parseJson(text) {
    const marked = text.replace(/(:\s*|\[\s*|,\s*)(-?\d{16,})(?=\s*[,}\]])/g, (_m, pre, num) => `${pre}"${MARK}${num}${MARK}"`);
    return JSON.parse(marked, (_k, v) => typeof v === "string" && v.startsWith(MARK) ? BigInt(v.slice(MARK.length, -MARK.length)) : v);
  }

  // src/api.ts
  var Client = class {
    constructor(opts = {}) {
      __publicField(this, "api");
      __publicField(this, "timeoutSeconds");
      __publicField(this, "f");
      this.api = (opts.api ?? "http://localhost:8080").replace(/\/+$/, "");
      this.timeoutSeconds = opts.timeoutSeconds ?? 20;
      this.f = opts.fetch ?? globalThis.fetch;
      if (!this.f) throw new Error("no fetch available");
    }
    async call(method, path, body) {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), this.timeoutSeconds * 1e3);
      try {
        const res = await this.f(this.api + path, {
          method,
          body,
          signal: ctl.signal,
          headers: body === void 0 ? { Accept: "application/json", "User-Agent": "zbc-cli/1.0" } : { Accept: "application/json", "User-Agent": "zbc-cli/1.0", "Content-Type": "application/json" }
        });
        const text = await res.text();
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {
          json = null;
        }
        return { status: res.status, text, json };
      } catch (e) {
        const aborted = e instanceof Error && e.name === "AbortError";
        throw new ToolError(
          aborted ? ExitCode.timeout : ExitCode.node_unreachable,
          (aborted ? "Timed out: " : "Connection failed: ") + path + " on " + this.api + (aborted ? "" : ": " + describe(e))
        );
      } finally {
        clearTimeout(timer);
      }
    }
    /** GET /api/v1/node/info. */
    async nodeInfo() {
      const r = await this.call("GET", "/api/v1/node/info");
      if (r.status !== 200) throw new ToolError(
        r.status >= 500 ? ExitCode.node_busy : ExitCode.node_unreachable,
        `cannot read /api/v1/node/info from ${this.api} (HTTP ${r.status}) to learn which chain to sign for; pass --genesis <hex> to sign for a known chain`,
        { http_code: r.status }
      );
      return r.json;
    }
    /** The chain's signing rule as the node reports it: `{version: 2, genesisHash}` or `{version: 1}`. */
    async signingRule() {
      const info = await this.nodeInfo();
      const sv = Number(info.signing_version ?? 1);
      if (sv >= 2) {
        const g = String(info.genesis_hash ?? "");
        if (!isHex(g, 64)) throw new ToolError(ExitCode.internal, "node enforces chain-bound signing but reports no genesis hash; pass --genesis <hex>");
        return { version: 2, genesisHash: hexToBytes(g) };
      }
      return { version: 1 };
    }
    /** POST /api/v1/transactions. Resolves for any HTTP answer; throws ToolError on transport failure. */
    async submit(payload) {
      const r = await this.call("POST", "/api/v1/transactions", stringifyJson(payload));
      return { http_code: r.status, body: r.json ?? r.text, text: r.text, accepted: r.status === 200 || r.status === 202 };
    }
    /** Submit and throw a classified ToolError when the node rejects. */
    async submitOrThrow(payload) {
      const r = await this.submit(payload);
      if (!r.accepted) {
        const j = r.body;
        const text = j && typeof j === "object" && typeof j.error === "string" ? j.error : r.text;
        throw new ToolError(classifyNodeError(r.http_code, text), text, { http_code: r.http_code, api_response: r.body });
      }
      return r;
    }
    /** GET /api/v1/transactions/<hash>/status. A 404 answers `not_found` rather than throwing. */
    async status(hash) {
      const r = await this.call("GET", `/api/v1/transactions/${hash}/status`);
      const j = r.json ?? {};
      if (r.status !== 200 && r.status !== 404) throw new ToolError(classifyNodeError(r.status, r.text), r.text, { http_code: r.status, api_response: r.json ?? r.text });
      return { transaction_hash: hash, status: String(j.status ?? (r.status === 404 ? "not_found" : "unknown")), ...j, http_code: r.status };
    }
    /** GET /api/v1/transactions/<hash>: the transaction, or a ToolError with exit 7 when unknown. */
    async transaction(hash) {
      const r = await this.call("GET", `/api/v1/transactions/${hash}`);
      if (r.status !== 200) throw new ToolError(r.status === 404 ? ExitCode.not_found : classifyNodeError(r.status, r.text), r.status === 404 ? "Transaction not found" : r.text, { http_code: r.status, api_response: r.json ?? r.text });
      return r.json;
    }
    /** GET /api/v1/accounts/<address>: balances, or a ToolError with exit 7 when the account is unknown. */
    async account(address) {
      const r = await this.call("GET", `/api/v1/accounts/${encodeURIComponent(address)}`);
      if (r.status !== 200) throw new ToolError(r.status === 404 ? ExitCode.not_found : classifyNodeError(r.status, r.text), r.status === 404 ? "Account not found" : r.text, { http_code: r.status, api_response: r.json ?? r.text });
      return r.json;
    }
    /** GET /api/v1/blocks/latest: the reference block for a proof of ownership (`block_hash` or a gateway's `hash`). */
    async latestBlock() {
      const r = await this.call("GET", "/api/v1/blocks/latest");
      const j = r.json ?? {};
      const h = String(j.block_hash ?? j.hash ?? "");
      if (r.status !== 200 || !isHex(h, 64)) throw new ToolError(ExitCode.internal, "Failed to fetch latest block from " + this.api, { http_code: r.status });
      return { hash: hexToBytes(h), height: Number(j.height ?? 0) };
    }
  };
  function describe(e) {
    if (e instanceof Error) {
      const cause = e.cause;
      return e.message + (cause instanceof Error ? " (" + cause.message + ")" : "");
    }
    return String(e);
  }

  // src/body.ts
  var INT_LIMITS = {
    int64: [-(1n << 63n), (1n << 63n) - 1n],
    uint64: [0n, (1n << 64n) - 1n],
    uint32: [0n, (1n << 32n) - 1n],
    uint8: [0n, 255n]
  };
  function parseInteger(value, kind, name) {
    if (!/^-?\d+$/.test(value.trim())) throw usage(`${name} must be a whole number, got "${value}"`);
    const v = BigInt(value.trim());
    const lim = INT_LIMITS[kind] ?? INT_LIMITS.int64;
    if (v < lim[0] || v > lim[1]) throw usage(`${name} is out of range for ${kind}`);
    return v;
  }
  function validateParam(p, value) {
    switch (p.kind) {
      case "privkey":
        if (!isHex(value, 64)) throw usage(`${p.name} must be 64 hex characters (a 32-byte private key)`);
        return value;
      case "address":
        try {
          parseAddress(value);
        } catch (e) {
          throw usage(`invalid ${p.name}: ${e.message}`);
        }
        return value;
      case "address_list":
        for (const a of splitList(value)) {
          try {
            parseAddress(a);
          } catch (e) {
            throw usage(`invalid ${p.name} entry ${a}: ${e.message}`);
          }
        }
        return value;
      case "key":
        try {
          parseKey32(value);
        } catch (e) {
          throw usage(`invalid ${p.name}: ${e.message}`);
        }
        return value;
      case "int64":
      case "uint64":
      case "uint32":
      case "uint8": {
        const n = parseInteger(value, p.kind, p.name);
        if (p.min !== void 0 && n < BigInt(p.min) || p.max !== void 0 && n > BigInt(p.max))
          throw usage(`${p.name} must be between ${p.min ?? "-inf"} and ${p.max ?? "inf"}`);
        return value.trim();
      }
      case "hex32":
        if (!isHex(value, 64)) throw usage(`${p.name} must be 64 hex characters (32 bytes)`);
        return value;
      case "hexbytes":
        if (!isHex(value)) throw usage(`${p.name} must be hex`);
        return value;
      case "string":
      case "file":
        return value;
      default:
        return value;
    }
  }
  function splitList(s) {
    return s.split(",").map((x) => x.trim()).filter((x) => x.length > 0);
  }
  function conditionHolds(when, params) {
    const m = /^(\w+) != (0|'')$/.exec(when);
    if (!m) throw new Error("unsupported condition " + when);
    const v = params[m[1]] ?? "";
    return m[2] === "0" ? BigInt(v || "0") !== 0n : v !== "";
  }
  function encodeField(f, params, ctx) {
    const w = new ByteWriter();
    if (ctx.computed && f.name in ctx.computed) return ctx.computed[f.name];
    let value = params[f.from] ?? "";
    if (f.when_zero && (value === "" || BigInt(value) <= 0n)) value = params[f.when_zero] ?? "0";
    switch (f.encoding) {
      case "u8":
        return w.u8(Number(parseInteger(value, "uint8", f.name))).finish();
      case "u16le":
        return w.u16(Number(parseInteger(value, "uint32", f.name))).finish();
      case "u32le":
        return w.u32(Number(parseInteger(value, "uint32", f.name))).finish();
      case "u64le":
        return w.i64(parseInteger(value, "int64", f.name)).finish();
      case "hex": {
        const b = hexToBytes(value);
        if (f.size !== void 0 && b.length !== f.size) throw usage(`${f.from} must be ${f.size} bytes (${2 * f.size} hex)`);
        return b;
      }
      case "hex16": {
        const b = hexToBytes(value);
        return w.u16(b.length).bytes(b).finish();
      }
      case "bytes32": {
        const b = hexToBytes(ctx.files && f.from in ctx.files ? ctx.files[f.from] : value);
        return w.u32(b.length).bytes(b).finish();
      }
      case "str16": {
        const b = utf8(value);
        return w.u16(b.length).bytes(b).finish();
      }
      case "str32": {
        const b = utf8(value);
        return w.u32(b.length).bytes(b).finish();
      }
      case "address":
        return parseAddress(value).bytes;
      case "address_list": {
        for (const a of splitList(value)) w.bytes(parseAddress(a).bytes);
        return w.finish();
      }
      case "address_list8": {
        const items = splitList(value);
        if (items.length > 255) throw usage(`${f.from}: at most 255 entries`);
        w.u8(items.length);
        for (const a of items) w.bytes(parseAddress(a).bytes);
        return w.finish();
      }
      case "sender_address":
        return ctx.sender.accountBytes;
      case "pubkey_of_key": {
        if (!isHex(value, 64)) throw usage(`${f.from} must be 64 hex characters (a 32-byte private key)`);
        return keyPairFromSeed(value).publicKey;
      }
      case "key32":
        return parseKey32(value);
      case "literal":
        return hexToBytes(f.value ?? "");
      case "custom":
        throw new Error(`field ${f.name} of ${f.from} needs a custom hook`);
      default:
        throw new Error("unknown encoding " + f.encoding);
    }
  }
  function buildBody(def, params, ctx) {
    const w = new ByteWriter();
    for (const f of def.body) {
      if (f.when && !conditionHolds(f.when, params)) continue;
      w.bytes(encodeField(f, params, ctx));
    }
    return w.finish();
  }

  // src/custom.ts
  function proofOfOwnership(owner, block) {
    const msg = new ByteWriter().bytes(owner.accountBytes).bytes(block.hash).u32(block.height).finish();
    return concat(msg, sign(msg, owner.seed));
  }
  function computeFields(input, body) {
    const { def, params, sender } = input;
    const computed = body.computed ?? (body.computed = {});
    const extra = {};
    switch (def.command) {
      case "store-file": {
        const pieces = hexToBytes(params.piece_ids ?? "");
        if (pieces.length === 0 || pieces.length % 32 !== 0) throw usage("piece_ids must be a nonzero multiple of 32 bytes");
        computed.piece_count = new ByteWriter().u32(pieces.length / 32).finish();
        extra.piece_count = pieces.length / 32;
        break;
      }
      case "register-node":
      case "update-node":
      case "claim-node": {
        if (!input.referenceBlock) throw new Error("proof of ownership needs the latest block");
        computed.proof_of_ownership = proofOfOwnership(sender, input.referenceBlock);
        const node = keyPairFromSeed(params.node_privkey);
        extra.node_znk = node.nodeAddress;
        extra.owner_zbc = sender.address;
        break;
      }
      case "fee-vote-reveal": {
        const info = new ByteWriter().bytes(hexToBytes(params.recent_block_hash)).u32(Number(parseInteger(params.recent_block_height, "uint32", "recent_block_height"))).i64(parseInteger(params.fee_vote, "int64", "fee_vote")).finish();
        const sig = sign(info, sender.seed);
        computed.voter_signature = new ByteWriter().u32(sig.length).bytes(sig).finish();
        break;
      }
      case "gateway-heartbeat": {
        if (!isHex(params.gateway_privkey, 64)) throw usage("gateway_privkey is not a valid key");
        const gw = keyPairFromSeed(params.gateway_privkey);
        const h = parseInteger(params.reference_height, "uint32", "reference_height");
        const hash = hexToBytes(params.reference_block_hash);
        if (hash.length !== 32) throw usage("reference_block_hash must be 32 bytes (64 hex)");
        const msg = new ByteWriter().bytes(gw.publicKey).u32(Number(h)).bytes(hash).finish();
        computed.signature = sign(msg, gw.seed);
        extra.gateway_key = bytesToHex(gw.publicKey);
        extra.reference_height = Number(h);
        extra.reference_block_hash = params.reference_block_hash;
        break;
      }
    }
    return extra;
  }
  function customBody(input) {
    switch (input.def.command) {
      case "multisig":
        return multisigBody(input);
      case "app-settle":
        return settleBody(input);
      default:
        throw new Error("no custom body for " + input.def.command);
    }
  }
  function multisigAddress(participants, nonce, minSignatures) {
    const sorted = participants.slice().sort(compareBytes);
    const w = new ByteWriter().u32(minSignatures).i64(nonce).u32(sorted.length);
    for (const a of sorted) w.bytes(a);
    return sha3_256(w.finish());
  }
  function compareBytes(a, b) {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
  }
  function multisigBody(input) {
    const p = input.params;
    const participants = splitList(p.participants).map((a) => parseAddress(a).bytes);
    if (participants.length === 0) throw usage("Need at least one participant");
    const minSigs = Number(parseInteger(p.min_signatures, "uint32", "min_signatures"));
    const nonce = parseInteger(p.nonce || "0", "int64", "nonce");
    const signers = splitList(p.signer_privkeys);
    if (signers.length === 0) throw usage("Need at least one signer key");
    const recipient = parseAddress(p.recipient);
    const amount = parseInteger(p.amount, "int64", "amount");
    const innerFee = parseInteger(p.inner_fee || "10000000", "int64", "inner_fee");
    const msAddr = multisigAddress(participants, nonce, minSigs);
    const innerSender = new ByteWriter().u32(0).bytes(msAddr).finish();
    const inner = unsignedBytes({
      type: TransactionType.SendZBC,
      timestamp: input.timestamp,
      sender: innerSender,
      recipient: recipient.bytes,
      fee: innerFee,
      body: new ByteWriter().i64(amount).finish()
    });
    const innerHash = sha3_256(inner);
    const innerDigest = signingDigest(inner, input.ctx);
    const sigs = [];
    for (const sk of signers) {
      if (!isHex(sk, 64)) throw usage("Invalid signer key");
      const kp = keyPairFromSeed(sk);
      sigs.push([bytesToHex(kp.accountBytes), sign(innerDigest, kp.seed)]);
    }
    sigs.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
    const w = new ByteWriter().u32(1).u32(minSigs).i64(nonce).u32(participants.length);
    for (const a of participants) w.bytes(a);
    w.u32(inner.length).bytes(inner).u32(1).bytes(innerHash).u32(sigs.length);
    for (const [addrHex, sig] of sigs) w.bytes(hexToBytes(addrHex)).u32(sig.length).bytes(sig);
    const extra = {
      multisig_address: bytesToHex(msAddr),
      multisig_zbc_address: parseAddress(bytesToHex(msAddr)).display,
      min_signatures: minSigs,
      inner_tx_hash: bytesToHex(innerHash),
      fund_hint: "send ZBC to multisig_zbc_address before the signatures complete, else the inner tx stays in mempool"
    };
    return { body: w.finish(), extra };
  }
  function settleBody(input) {
    const p = input.params;
    const appId = parseInteger(p.app_id, "int64", "app_id");
    if (!isHex(p.p0_privkey, 64) || !isHex(p.p1_privkey, 64)) throw usage("seat keys must be 64 hex");
    const seats = [keyPairFromSeed(p.p0_privkey), keyPairFromSeed(p.p1_privkey)];
    const turn = Number(parseInteger(p.opening_turn || "0", "uint8", "opening_turn"));
    if (turn !== 0 && turn !== 1) throw usage("opening_turn must be 0 or 1");
    const cells = splitList(p.moves).map((c) => Number(parseInteger(c, "uint8", "move")));
    if (cells.length === 0) throw usage("no moves given");
    const state = new Uint8Array(9);
    const entries = [];
    cells.forEach((cell, k) => {
      const seat = (turn + k) % 2;
      if (cell < 0 || cell > 8 || state[cell] !== 0) throw usage(`illegal move at seq ${k + 1}`);
      const move = new Uint8Array([cell]);
      const digest = sha3_256(new ByteWriter().i64(appId).u32(k + 1).bytes(sha3_256(state)).bytes(move).finish());
      const sig = sign(digest, seats[seat].seed);
      entries.push(new ByteWriter().u8(seat).u16(move.length).bytes(move).bytes(sig).finish());
      state[cell] = seat + 1;
    });
    const w = new ByteWriter().i64(appId).u32(cells.length).u32(cells.length);
    for (const e of entries) w.bytes(e);
    return { body: w.finish(), extra: { app_id: Number(appId), opening_turn: turn, final_seq: cells.length } };
  }

  // src/generated/commands.ts
  var COMMANDS = [
    {
      "name": "AcceptDataset",
      "type": 44,
      "command": "accept-dataset",
      "binary": null,
      "description": "Accept a pending dataset transfer.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "object_id",
          "kind": "hex32",
          "required": true,
          "help": "dataset object id"
        }
      ],
      "body": [
        {
          "name": "object_id",
          "encoding": "hex",
          "from": "object_id",
          "size": 32
        }
      ],
      "example": {
        "object_id": "1111111111111111111111111111111111111111111111111111111111111111"
      },
      "notes": []
    },
    {
      "name": "AddPrepaidStorage",
      "type": 9,
      "command": "add-prepaid-storage",
      "binary": "zbc-storage-prepay",
      "description": "Fund the account's prepaid storage balance (dataset rent).",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "atomic ZBC"
        }
      ],
      "body": [
        {
          "name": "amount",
          "encoding": "u64le",
          "from": "amount"
        }
      ],
      "example": {
        "amount": "100000000"
      },
      "notes": []
    },
    {
      "name": "ClaimAppTimeout",
      "type": 28,
      "command": "app-claim",
      "binary": "zbc-app-claim",
      "description": "Claim the win when an opponent missed the per-move deadline.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "app_id",
          "kind": "int64",
          "required": true,
          "help": "app id"
        }
      ],
      "body": [
        {
          "name": "app_id",
          "encoding": "u64le",
          "from": "app_id"
        }
      ],
      "example": {
        "app_id": "5"
      },
      "notes": []
    },
    {
      "name": "CreateApp",
      "type": 24,
      "command": "app-create",
      "binary": "zbc-app-create",
      "description": "Open an on-chain app (game): type, stake, seats, optional params and opponent.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "app_type",
          "kind": "uint8",
          "required": true,
          "help": "1 tic-tac-toe, 3 connect-4, 6 gomoku, 16 dice, 17 coin flip"
        },
        {
          "name": "stake_token",
          "kind": "int64",
          "required": true,
          "help": "0 = ZBC"
        },
        {
          "name": "stake_amount",
          "kind": "int64",
          "required": true,
          "help": "stake (atomic)"
        },
        {
          "name": "seats",
          "kind": "uint8",
          "required": false,
          "help": "2 = player vs player, 1 = solo",
          "default": "2"
        },
        {
          "name": "params_hex",
          "kind": "hexbytes",
          "required": false,
          "help": "app parameters (solo bet, e.g. coin flip choice '00')",
          "default": ""
        },
        {
          "name": "opponent_hex",
          "kind": "hexbytes",
          "required": false,
          "help": "36-byte opponent account bytes (open seat if empty); a single byte 01 marks a state-channel app",
          "default": ""
        }
      ],
      "body": [
        {
          "name": "app_type",
          "encoding": "u8",
          "from": "app_type"
        },
        {
          "name": "stake_token",
          "encoding": "u64le",
          "from": "stake_token"
        },
        {
          "name": "stake_amount",
          "encoding": "u64le",
          "from": "stake_amount"
        },
        {
          "name": "seats",
          "encoding": "u8",
          "from": "seats"
        },
        {
          "name": "params_hex",
          "encoding": "hex16",
          "from": "params_hex"
        },
        {
          "name": "opponent_hex",
          "encoding": "hex",
          "from": "opponent_hex",
          "when": "opponent_hex != ''"
        }
      ],
      "example": {
        "app_type": "1",
        "stake_token": "0",
        "stake_amount": "100000000",
        "seats": "2",
        "params_hex": "",
        "opponent_hex": ""
      },
      "notes": [
        "zbc-app-create takes (app_type, stake_token, stake_amount, seats, channel) and cannot pass params or an opponent."
      ]
    },
    {
      "name": "JoinApp",
      "type": 25,
      "command": "app-join",
      "binary": "zbc-app-join",
      "description": "Join an open app seat, locking an equal stake.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "app_id",
          "kind": "int64",
          "required": true,
          "help": "app id"
        }
      ],
      "body": [
        {
          "name": "app_id",
          "encoding": "u64le",
          "from": "app_id"
        }
      ],
      "example": {
        "app_id": "5"
      },
      "notes": []
    },
    {
      "name": "AppMove",
      "type": 26,
      "command": "app-move",
      "binary": "zbc-app-move",
      "description": "Submit one move.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "app_id",
          "kind": "int64",
          "required": true,
          "help": "app id"
        },
        {
          "name": "move_hex",
          "kind": "hexbytes",
          "required": true,
          "help": "move bytes, e.g. tic-tac-toe cell 4 = '04'"
        }
      ],
      "body": [
        {
          "name": "app_id",
          "encoding": "u64le",
          "from": "app_id"
        },
        {
          "name": "move_hex",
          "encoding": "hex16",
          "from": "move_hex"
        }
      ],
      "example": {
        "app_id": "5",
        "move_hex": "04"
      },
      "notes": []
    },
    {
      "name": "ResignApp",
      "type": 27,
      "command": "app-resign",
      "binary": "zbc-app-resign",
      "description": "Resign; your stake share goes to the opponent(s).",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "app_id",
          "kind": "int64",
          "required": true,
          "help": "app id"
        }
      ],
      "body": [
        {
          "name": "app_id",
          "encoding": "u64le",
          "from": "app_id"
        }
      ],
      "example": {
        "app_id": "5"
      },
      "notes": []
    },
    {
      "name": "SettleApp",
      "type": 39,
      "command": "app-settle",
      "binary": "zbc-app-settle",
      "description": "Settle a two-seat tic-tac-toe state channel: replay the signed moves on chain.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": "settle",
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "app_id",
          "kind": "int64",
          "required": true,
          "help": "the channel app id"
        },
        {
          "name": "p0_privkey",
          "kind": "privkey",
          "required": true,
          "help": "seat 0 key, signs seat 0 vouchers"
        },
        {
          "name": "p1_privkey",
          "kind": "privkey",
          "required": true,
          "help": "seat 1 key"
        },
        {
          "name": "opening_turn",
          "kind": "uint8",
          "required": false,
          "help": "seat that moves first, 0 or 1",
          "default": "0",
          "min": 0,
          "max": 1
        },
        {
          "name": "moves",
          "kind": "string",
          "required": true,
          "help": "cells in play order, comma-separated, e.g. 0,3,1,4,2"
        }
      ],
      "body": [
        {
          "name": "app_id",
          "encoding": "u64le",
          "from": "app_id"
        },
        {
          "name": "count",
          "encoding": "u32le",
          "from": "moves",
          "computed": "number of moves"
        },
        {
          "name": "final_seq",
          "encoding": "u32le",
          "from": "moves",
          "computed": "number of moves"
        },
        {
          "name": "entries",
          "encoding": "custom",
          "from": "moves",
          "computed": "per move: seat u8, move_bytes hex16, 64-byte voucher signature = Ed25519(seat key, SHA3-256(app_id u64le \u2016 seq u32le \u2016 SHA3-256(9-byte board before the move) \u2016 move_bytes)); the board marks cells with seat+1"
        }
      ],
      "example": {
        "app_id": "5",
        "p0_privkey": "1111111111111111111111111111111111111111111111111111111111111111",
        "p1_privkey": "2222222222222222222222222222222222222222222222222222222222222222",
        "opening_turn": "0",
        "moves": "0,3,1,4,2"
      },
      "notes": []
    },
    {
      "name": "ApprovalEscrow",
      "type": 4,
      "command": "approve-escrow",
      "binary": "zbc-escrow-approve",
      "description": "Approve (0), reject (1) or expire (2) an escrowed transaction, named by its full hash.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "approval",
          "kind": "uint32",
          "required": true,
          "help": "0 = approve, 1 = reject, 2 = expire",
          "min": 0,
          "max": 2
        },
        {
          "name": "transaction_hash",
          "kind": "hex32",
          "required": true,
          "help": "the escrowed transaction's hash, 64 hex"
        }
      ],
      "body": [
        {
          "name": "approval",
          "encoding": "u32le",
          "from": "approval"
        },
        {
          "name": "transaction_hash",
          "encoding": "hex",
          "from": "transaction_hash",
          "size": 32
        }
      ],
      "example": {
        "approval": "0",
        "transaction_hash": "1111111111111111111111111111111111111111111111111111111111111111"
      },
      "notes": [
        "The tool reports escrowed_transaction_hash and transaction_id (int64 of the escrowed hash) next to its own transaction_hash."
      ]
    },
    {
      "name": "RegisterArchival",
      "type": 46,
      "command": "archival-register",
      "binary": "zbc-archival-register",
      "description": "Announce a registered node as archival: it serves history and the read API.",
      "sender_key": "owner_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "owner_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key (64 hex). Named owner_privkey: ZBC_KEY does not apply, pass it explicitly"
        },
        {
          "name": "node_public_key",
          "kind": "key",
          "required": true,
          "help": "the node's ZNK_ address or 64 hex"
        },
        {
          "name": "domain",
          "kind": "string",
          "required": true,
          "help": "public domain"
        },
        {
          "name": "url",
          "kind": "string",
          "required": true,
          "help": "public API base URL"
        }
      ],
      "body": [
        {
          "name": "node_public_key",
          "encoding": "key32",
          "from": "node_public_key"
        },
        {
          "name": "domain",
          "encoding": "str32",
          "from": "domain"
        },
        {
          "name": "url",
          "encoding": "str32",
          "from": "url"
        }
      ],
      "example": {
        "node_public_key": "2222222222222222222222222222222222222222222222222222222222222222",
        "domain": "archive.example.org",
        "url": "https://archive.example.org"
      },
      "notes": [
        "No zbc-cli subcommand."
      ]
    },
    {
      "name": "UnregisterArchival",
      "type": 47,
      "command": "archival-unregister",
      "binary": "zbc-archival-unregister",
      "description": "Withdraw an archival announcement; the node stays registered.",
      "sender_key": "owner_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "owner_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key (64 hex). Named owner_privkey: ZBC_KEY does not apply, pass it explicitly"
        },
        {
          "name": "node_public_key",
          "kind": "key",
          "required": true,
          "help": "the node's ZNK_ address or 64 hex"
        }
      ],
      "body": [
        {
          "name": "node_public_key",
          "encoding": "key32",
          "from": "node_public_key"
        }
      ],
      "example": {
        "node_public_key": "2222222222222222222222222222222222222222222222222222222222222222"
      },
      "notes": [
        "No zbc-cli subcommand."
      ]
    },
    {
      "name": "AttestEvent",
      "type": 17,
      "command": "attest-event",
      "binary": "zbc-event-attest",
      "description": "Oracle attestation of an external (event_id, value) by an authorised node account.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "event_id",
          "kind": "string",
          "required": true,
          "help": "external event id"
        },
        {
          "name": "value",
          "kind": "string",
          "required": true,
          "help": "attested value"
        }
      ],
      "body": [
        {
          "name": "event_id",
          "encoding": "str32",
          "from": "event_id"
        },
        {
          "name": "value",
          "encoding": "str32",
          "from": "value"
        }
      ],
      "example": {
        "event_id": "match-2026-09-16",
        "value": "home"
      },
      "notes": []
    },
    {
      "name": "BurnToken",
      "type": 13,
      "command": "burn-token",
      "binary": "zbc-token-burn",
      "description": "Burn a token; reclaims backing when redeemable.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "token_id",
          "kind": "int64",
          "required": true,
          "help": "token id"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "amount (atomic)"
        }
      ],
      "body": [
        {
          "name": "token_id",
          "encoding": "u64le",
          "from": "token_id"
        },
        {
          "name": "amount",
          "encoding": "u64le",
          "from": "amount"
        }
      ],
      "example": {
        "token_id": "123456789",
        "amount": "1000"
      },
      "notes": []
    },
    {
      "name": "CancelLongevity",
      "type": 53,
      "command": "cancel-longevity",
      "binary": "zbc-cancel-longevity",
      "description": "Cancel a longevity sponsorship you created; the remainder is refunded.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "target_tx_id",
          "kind": "int64",
          "required": true,
          "help": "the sponsored transaction's int64 id"
        }
      ],
      "body": [
        {
          "name": "target_tx_id",
          "encoding": "u64le",
          "from": "target_tx_id"
        }
      ],
      "example": {
        "target_tx_id": "-1234567890123456789"
      },
      "notes": [
        "No zbc-cli subcommand."
      ]
    },
    {
      "name": "CancelSchedule",
      "type": 30,
      "command": "cancel-schedule",
      "binary": null,
      "description": "Cancel a scheduled transfer (sender) or decline it (recipient).",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "schedule_id",
          "kind": "int64",
          "required": true,
          "help": "schedule id"
        }
      ],
      "body": [
        {
          "name": "schedule_id",
          "encoding": "u64le",
          "from": "schedule_id"
        }
      ],
      "example": {
        "schedule_id": "11"
      },
      "notes": []
    },
    {
      "name": "CancelTrigger",
      "type": 16,
      "command": "cancel-trigger",
      "binary": "zbc-trigger-cancel",
      "description": "Cancel a pending trigger you own; the locked amount is refunded.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "trigger_id",
          "kind": "int64",
          "required": true,
          "help": "trigger id"
        }
      ],
      "body": [
        {
          "name": "trigger_id",
          "encoding": "u64le",
          "from": "trigger_id"
        }
      ],
      "example": {
        "trigger_id": "77"
      },
      "notes": []
    },
    {
      "name": "ClaimNodeRegistration",
      "type": 770,
      "command": "claim-node",
      "binary": "zbc-node-claim",
      "description": "Claim the locked balance of a removed or expired node registration.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": true,
      "custom": "proof_of_ownership",
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "node_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the node's private key"
        }
      ],
      "body": [
        {
          "name": "node_public_key",
          "encoding": "pubkey_of_key",
          "from": "node_privkey"
        },
        {
          "name": "proof_of_ownership",
          "encoding": "custom",
          "from": "proof_of_ownership",
          "computed": "as register-node"
        }
      ],
      "example": {
        "node_privkey": "2222222222222222222222222222222222222222222222222222222222222222"
      },
      "notes": [
        "zbc-node-claim takes (node_privkey, owner_privkey)."
      ]
    },
    {
      "name": "CreateTrigger",
      "type": 15,
      "command": "create-trigger",
      "binary": "zbc-trigger-create",
      "description": "Lock amount now and send it to recipient at fire_height, or when an oracle event resolves.",
      "sender_key": "sender_privkey",
      "recipient": "required",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "recipient",
          "kind": "address",
          "required": true,
          "help": "where the scheduled SendZBC pays"
        },
        {
          "name": "fire_height",
          "kind": "int64",
          "required": true,
          "help": "future block height"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "atomic ZBC locked now"
        },
        {
          "name": "event_id",
          "kind": "string",
          "required": false,
          "help": "oracle event id; when set the trigger fires on the event",
          "default": ""
        }
      ],
      "body": [
        {
          "name": "fire_height",
          "encoding": "u64le",
          "from": "fire_height"
        },
        {
          "name": "amount",
          "encoding": "u64le",
          "from": "amount"
        },
        {
          "name": "event_id",
          "encoding": "str32",
          "from": "event_id",
          "when": "event_id != ''"
        }
      ],
      "example": {
        "recipient": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I",
        "fire_height": "100000",
        "amount": "100000000",
        "event_id": ""
      },
      "notes": []
    },
    {
      "name": "DeleteDataset",
      "type": 45,
      "command": "delete-dataset",
      "binary": null,
      "description": "Delete a dataset object and refund its deposit.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "object_id",
          "kind": "hex32",
          "required": true,
          "help": "dataset object id"
        }
      ],
      "body": [
        {
          "name": "object_id",
          "encoding": "hex",
          "from": "object_id",
          "size": 32
        }
      ],
      "example": {
        "object_id": "1111111111111111111111111111111111111111111111111111111111111111"
      },
      "notes": []
    },
    {
      "name": "DFSCreateFile",
      "type": 8,
      "command": "dfs-create-file",
      "binary": "zbc-dfs-create-file",
      "description": "Create an on-chain file at path with the given content (up to 64 KB).",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "path",
          "kind": "string",
          "required": true,
          "help": "absolute path, e.g. /docs/readme.txt"
        },
        {
          "name": "content_file",
          "kind": "file",
          "required": true,
          "help": "local file whose bytes become the content"
        }
      ],
      "body": [
        {
          "name": "path",
          "encoding": "str32",
          "from": "path"
        },
        {
          "name": "content",
          "encoding": "bytes32",
          "from": "content_file",
          "computed": "the file's bytes"
        }
      ],
      "example": {
        "path": "/docs/hello.txt",
        "content_file": "<a file containing the 12 bytes 'hello zoobc\\n'>"
      },
      "notes": []
    },
    {
      "name": "EscrowRequest",
      "type": 260,
      "command": "escrow-request",
      "binary": "zbc-escrow-request",
      "description": "Recipient-initiated escrow: ask proposed_sender to pay amount through an approver.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "proposed_sender",
          "kind": "address",
          "required": true,
          "help": "who is asked to pay"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "proposed amount (atomic units)"
        },
        {
          "name": "approver",
          "kind": "address",
          "required": true,
          "help": "third-party approver"
        },
        {
          "name": "commission",
          "kind": "int64",
          "required": false,
          "help": "approver commission (atomic units)",
          "default": "0"
        },
        {
          "name": "timeout",
          "kind": "int64",
          "required": true,
          "help": "escrow timeout, future Unix seconds"
        },
        {
          "name": "instruction",
          "kind": "string",
          "required": false,
          "help": "instructions",
          "default": ""
        },
        {
          "name": "expiry",
          "kind": "int64",
          "required": false,
          "help": "request expiry; 0 = same as timeout",
          "default": "0"
        }
      ],
      "body": [
        {
          "name": "proposed_sender",
          "encoding": "address",
          "from": "proposed_sender"
        },
        {
          "name": "amount",
          "encoding": "u64le",
          "from": "amount"
        },
        {
          "name": "approver",
          "encoding": "address",
          "from": "approver"
        },
        {
          "name": "commission",
          "encoding": "u64le",
          "from": "commission"
        },
        {
          "name": "timeout",
          "encoding": "u64le",
          "from": "timeout"
        },
        {
          "name": "instruction",
          "encoding": "str32",
          "from": "instruction"
        },
        {
          "name": "expiry",
          "encoding": "u64le",
          "from": "expiry",
          "default_from": "timeout",
          "when_zero": "timeout"
        }
      ],
      "example": {
        "proposed_sender": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I",
        "amount": "250000000",
        "approver": "ZBC_L2HLFDOM_VKKKTEXX_C2P2M6LG_EB6ZNKSV_356SJUWW_5QPVHDE7_EFJA3PEX",
        "commission": "1000",
        "timeout": "1800000000",
        "instruction": "pay on delivery",
        "expiry": "0"
      },
      "notes": [
        "zbc-escrow-request names its first field requester_privkey; zbc-cli uses sender_privkey (ZBC_KEY applies there)."
      ]
    },
    {
      "name": "FeeVoteCommitment",
      "type": 7,
      "command": "fee-vote-commit",
      "binary": "zbc-fee-vote-commit",
      "description": "Commit a hashed fee vote during the commit phase.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "vote_hash",
          "kind": "hex32",
          "required": true,
          "help": "32-byte vote hash"
        }
      ],
      "body": [
        {
          "name": "vote_hash",
          "encoding": "hex",
          "from": "vote_hash",
          "size": 32
        }
      ],
      "example": {
        "vote_hash": "1111111111111111111111111111111111111111111111111111111111111111"
      },
      "notes": []
    },
    {
      "name": "FeeVoteReveal",
      "type": 263,
      "command": "fee-vote-reveal",
      "binary": "zbc-fee-vote-reveal",
      "description": "Reveal the fee vote during the reveal phase; the body carries the sender's signature over the 44 vote bytes.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": "voter_signature",
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "recent_block_hash",
          "kind": "hex32",
          "required": true,
          "help": "reference block hash"
        },
        {
          "name": "recent_block_height",
          "kind": "uint32",
          "required": true,
          "help": "reference block height"
        },
        {
          "name": "fee_vote",
          "kind": "int64",
          "required": true,
          "help": "proposed fee multiplier"
        }
      ],
      "body": [
        {
          "name": "recent_block_hash",
          "encoding": "hex",
          "from": "recent_block_hash",
          "size": 32
        },
        {
          "name": "recent_block_height",
          "encoding": "u32le",
          "from": "recent_block_height"
        },
        {
          "name": "fee_vote",
          "encoding": "u64le",
          "from": "fee_vote"
        },
        {
          "name": "voter_signature",
          "encoding": "bytes32",
          "from": "voter_signature",
          "computed": "u32le length (64) then Ed25519(sender seed, the 44 bytes above), no tag"
        }
      ],
      "example": {
        "recent_block_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "recent_block_height": "1000",
        "fee_vote": "3"
      },
      "notes": []
    },
    {
      "name": "FinanceToken",
      "type": 14,
      "command": "finance-token",
      "binary": "zbc-token-finance",
      "description": "Top up a token's survival financing; the fee buys persistence.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "token_id",
          "kind": "int64",
          "required": true,
          "help": "token id"
        }
      ],
      "body": [
        {
          "name": "token_id",
          "encoding": "u64le",
          "from": "token_id"
        }
      ],
      "example": {
        "token_id": "123456789"
      },
      "notes": []
    },
    {
      "name": "FundLongevity",
      "type": 52,
      "command": "fund-longevity",
      "binary": "zbc-fund-longevity",
      "description": "Attach a rent deposit to a transaction so pruning keeps it.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "target_tx_id",
          "kind": "int64",
          "required": true,
          "help": "the transaction to keep, as its int64 id"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "deposit (atomic), minimum 0.1 ZBC"
        }
      ],
      "body": [
        {
          "name": "target_tx_id",
          "encoding": "u64le",
          "from": "target_tx_id"
        },
        {
          "name": "amount",
          "encoding": "u64le",
          "from": "amount"
        }
      ],
      "example": {
        "target_tx_id": "-1234567890123456789",
        "amount": "10000000"
      },
      "notes": [
        "No zbc-cli subcommand."
      ]
    },
    {
      "name": "GatewayHeartbeat",
      "type": 37,
      "command": "gateway-heartbeat",
      "binary": null,
      "description": "Liveness proof signed by the gateway key over a recent block; any account may relay it.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": "gateway_signature",
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "gateway_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the gateway's own private key"
        },
        {
          "name": "reference_height",
          "kind": "uint32",
          "required": true,
          "help": "height of a recent confirmed block"
        },
        {
          "name": "reference_block_hash",
          "kind": "hex32",
          "required": true,
          "help": "that block's hash"
        }
      ],
      "body": [
        {
          "name": "gateway_key",
          "encoding": "pubkey_of_key",
          "from": "gateway_privkey"
        },
        {
          "name": "reference_height",
          "encoding": "u32le",
          "from": "reference_height"
        },
        {
          "name": "reference_block_hash",
          "encoding": "hex",
          "from": "reference_block_hash",
          "size": 32
        },
        {
          "name": "signature",
          "encoding": "hex",
          "from": "signature",
          "size": 64,
          "computed": "Ed25519(gateway seed, the 68 bytes above), no tag"
        }
      ],
      "example": {
        "gateway_privkey": "2222222222222222222222222222222222222222222222222222222222222222",
        "reference_height": "41154",
        "reference_block_hash": "1111111111111111111111111111111111111111111111111111111111111111"
      },
      "notes": []
    },
    {
      "name": "SetConsensusParam",
      "type": 51,
      "command": "governance-vote",
      "binary": "zbc-governance-vote",
      "description": "A registry node votes a value for a governable parameter (2/3 of the registry must agree).",
      "sender_key": "node_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "node_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key (64 hex). Named node_privkey: ZBC_KEY does not apply, pass it explicitly"
        },
        {
          "name": "parameter",
          "kind": "string",
          "required": true,
          "help": "parameter name"
        },
        {
          "name": "value",
          "kind": "int64",
          "required": true,
          "help": "the value voted for, raw units"
        }
      ],
      "body": [
        {
          "name": "parameter",
          "encoding": "str32",
          "from": "parameter"
        },
        {
          "name": "value",
          "encoding": "u64le",
          "from": "value"
        }
      ],
      "example": {
        "parameter": "min_fee",
        "value": "2500000"
      },
      "notes": [
        "No zbc-cli subcommand; the node's own key signs."
      ]
    },
    {
      "name": "IssueToken",
      "type": 10,
      "command": "issue-token",
      "binary": "zbc-token-issue",
      "description": "Issue a token backed by ZBC.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "symbol",
          "kind": "string",
          "required": true,
          "help": "2-10 upper-case letters or digits, not a reserved symbol"
        },
        {
          "name": "name",
          "kind": "string",
          "required": true,
          "help": "token name"
        },
        {
          "name": "decimals",
          "kind": "uint8",
          "required": true,
          "help": "0-8, display only",
          "min": 0,
          "max": 8
        },
        {
          "name": "supply",
          "kind": "int64",
          "required": true,
          "help": "total supply (atomic, 10^8 per unit)"
        },
        {
          "name": "backing",
          "kind": "int64",
          "required": true,
          "help": "ZBC locked as backing (atomic); 0 = unbacked"
        },
        {
          "name": "flags",
          "kind": "uint8",
          "required": false,
          "help": "bit0 redeemable, bit1 mintable, bit3 unbacked",
          "default": "1"
        }
      ],
      "body": [
        {
          "name": "decimals",
          "encoding": "u8",
          "from": "decimals"
        },
        {
          "name": "flags",
          "encoding": "u8",
          "from": "flags"
        },
        {
          "name": "supply",
          "encoding": "u64le",
          "from": "supply"
        },
        {
          "name": "backing",
          "encoding": "u64le",
          "from": "backing"
        },
        {
          "name": "symbol",
          "encoding": "str16",
          "from": "symbol"
        },
        {
          "name": "name",
          "encoding": "str16",
          "from": "name"
        }
      ],
      "example": {
        "symbol": "GOLD",
        "name": "Gold token",
        "decimals": "2",
        "supply": "100000000000",
        "backing": "100000000",
        "flags": "1"
      },
      "notes": []
    },
    {
      "name": "LiquidPaymentStop",
      "type": 262,
      "command": "liquid-payment-stop",
      "binary": "zbc-liquid-stop",
      "description": "Stop a liquid payment; the vested part goes to the recipient, the rest back.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "transaction_id",
          "kind": "int64",
          "required": true,
          "help": "the liquid payment's transaction id (first 8 bytes of its hash, int64 LE; often negative)"
        }
      ],
      "body": [
        {
          "name": "transaction_id",
          "encoding": "u64le",
          "from": "transaction_id"
        }
      ],
      "example": {
        "transaction_id": "-1234567890123456789"
      },
      "notes": []
    },
    {
      "name": "LiquidPayment",
      "type": 6,
      "command": "liquid-payment",
      "binary": "zbc-liquid-pay",
      "description": "Stream ZBC (or a token) to a recipient, vesting linearly over complete_minutes.",
      "sender_key": "sender_privkey",
      "recipient": "required",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "recipient",
          "kind": "address",
          "required": true,
          "help": "recipient address"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "amount (atomic units)"
        },
        {
          "name": "complete_minutes",
          "kind": "uint64",
          "required": true,
          "help": "minutes until fully vested"
        },
        {
          "name": "token_id",
          "kind": "int64",
          "required": false,
          "help": "token to stream instead of ZBC (--token); 0 = ZBC",
          "default": "0"
        }
      ],
      "body": [
        {
          "name": "amount",
          "encoding": "u64le",
          "from": "amount"
        },
        {
          "name": "complete_minutes",
          "encoding": "u64le",
          "from": "complete_minutes"
        },
        {
          "name": "token_id",
          "encoding": "u64le",
          "from": "token_id",
          "when": "token_id != 0"
        }
      ],
      "example": {
        "recipient": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I",
        "amount": "500000000",
        "complete_minutes": "60"
      },
      "notes": [
        "zbc-cli liquid-payment always streams ZBC; the token_id field comes from zbc-liquid-pay --token <id>."
      ]
    },
    {
      "name": "CreateMarket",
      "type": 21,
      "command": "market-create",
      "binary": "zbc-market-create",
      "description": "Open a (base, quote) order-book market, paying a rent deposit.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "base_token",
          "kind": "int64",
          "required": true,
          "help": "base token, 0 = ZBC"
        },
        {
          "name": "quote_token",
          "kind": "int64",
          "required": true,
          "help": "quote token, 0 = ZBC"
        },
        {
          "name": "deposit",
          "kind": "int64",
          "required": false,
          "help": "rent deposit (atomic)",
          "default": "0"
        }
      ],
      "body": [
        {
          "name": "base_token",
          "encoding": "u64le",
          "from": "base_token"
        },
        {
          "name": "quote_token",
          "encoding": "u64le",
          "from": "quote_token"
        },
        {
          "name": "deposit",
          "encoding": "u64le",
          "from": "deposit"
        }
      ],
      "example": {
        "base_token": "123456789",
        "quote_token": "0",
        "deposit": "100000000"
      },
      "notes": []
    },
    {
      "name": "MintToken",
      "type": 12,
      "command": "mint-token",
      "binary": "zbc-token-mint",
      "description": "Mint more of a mintable token (adds backing).",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "token_id",
          "kind": "int64",
          "required": true,
          "help": "token id"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "amount (atomic)"
        }
      ],
      "body": [
        {
          "name": "token_id",
          "encoding": "u64le",
          "from": "token_id"
        },
        {
          "name": "amount",
          "encoding": "u64le",
          "from": "amount"
        }
      ],
      "example": {
        "token_id": "123456789",
        "amount": "1000"
      },
      "notes": []
    },
    {
      "name": "MultiSignature",
      "type": 5,
      "command": "multisig",
      "binary": "zbc-multisig",
      "description": "N-of-M multisig SendZBC: the inner transaction plus the participant signatures gathered so far.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": "multisig",
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "participants",
          "kind": "address_list",
          "required": true,
          "help": "comma-separated participant addresses"
        },
        {
          "name": "min_signatures",
          "kind": "uint32",
          "required": true,
          "help": "signatures required (N of M)"
        },
        {
          "name": "nonce",
          "kind": "int64",
          "required": false,
          "help": "multisig account nonce",
          "default": "0"
        },
        {
          "name": "signer_privkeys",
          "kind": "string",
          "required": true,
          "help": "comma-separated participant keys that sign now"
        },
        {
          "name": "recipient",
          "kind": "address",
          "required": true,
          "help": "inner SendZBC recipient"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "inner amount (atomic)"
        },
        {
          "name": "inner_fee",
          "kind": "int64",
          "required": false,
          "help": "inner fee (atomic)",
          "default": "10000000"
        }
      ],
      "body": [
        {
          "name": "info_present",
          "encoding": "literal",
          "from": "info_present",
          "value": "01000000"
        },
        {
          "name": "min_signatures",
          "encoding": "u32le",
          "from": "min_signatures"
        },
        {
          "name": "nonce",
          "encoding": "u64le",
          "from": "nonce"
        },
        {
          "name": "participant_count",
          "encoding": "u32le",
          "from": "participants",
          "computed": "number of participants"
        },
        {
          "name": "participants",
          "encoding": "address_list",
          "from": "participants",
          "computed": "each 36-byte address, in the order given"
        },
        {
          "name": "inner",
          "encoding": "bytes32",
          "from": "inner",
          "computed": "the inner unsigned SendZBC envelope: sender = 36-byte address whose 32-byte key is the multisig address, timestamp = --timestamp or now, fee = inner_fee, body = amount u64le, no escrow, no message"
        },
        {
          "name": "signatures_present",
          "encoding": "literal",
          "from": "signatures_present",
          "value": "01000000"
        },
        {
          "name": "inner_hash",
          "encoding": "hex",
          "from": "inner_hash",
          "size": 32,
          "computed": "SHA3-256(inner) (bare, no tag)"
        },
        {
          "name": "signature_count",
          "encoding": "u32le",
          "from": "signature_count",
          "computed": "number of signer keys"
        },
        {
          "name": "signatures",
          "encoding": "custom",
          "from": "signatures",
          "computed": "sorted by the signer's 36-byte address hex: address (36) \u2016 u32le 64 \u2016 Ed25519(signer seed, signing digest of the inner bytes per signing.md section 4)"
        }
      ],
      "example": {
        "participants": "ZBC_L2HLFDOM_VKKKTEXX_C2P2M6LG_EB6ZNKSV_356SJUWW_5QPVHDE7_EFJA3PEX,ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I",
        "min_signatures": "1",
        "nonce": "0",
        "signer_privkeys": "1111111111111111111111111111111111111111111111111111111111111111",
        "recipient": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I",
        "amount": "1000",
        "inner_fee": "10000000"
      },
      "notes": [
        "multisig address = SHA3-256(min_signatures u32le \u2016 nonce u64le \u2016 count u32le \u2016 the participant addresses sorted bytewise).",
        "The multisig account must be funded (send ZBC to its ZBC_ form) before the inner transaction can execute."
      ]
    },
    {
      "name": "CancelOrder",
      "type": 23,
      "command": "order-cancel",
      "binary": "zbc-order-cancel",
      "description": "Cancel a resting order; the held remainder is refunded.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "order_id",
          "kind": "int64",
          "required": true,
          "help": "order id"
        }
      ],
      "body": [
        {
          "name": "order_id",
          "encoding": "u64le",
          "from": "order_id"
        }
      ],
      "example": {
        "order_id": "99"
      },
      "notes": []
    },
    {
      "name": "PlaceOrder",
      "type": 22,
      "command": "order-place",
      "binary": "zbc-order-place",
      "description": "Place a limit or market order on a market.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "market_id",
          "kind": "int64",
          "required": true,
          "help": "market id"
        },
        {
          "name": "side",
          "kind": "uint8",
          "required": true,
          "help": "0 = buy, 1 = sell"
        },
        {
          "name": "price",
          "kind": "int64",
          "required": true,
          "help": "quote per base, scaled by 10^8"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "base amount (atomic)"
        },
        {
          "name": "flags",
          "kind": "uint8",
          "required": false,
          "help": "bit0 market order, bit1 post-only",
          "default": "0"
        },
        {
          "name": "expiry",
          "kind": "int64",
          "required": false,
          "help": "Unix seconds, 0 = good till cancelled",
          "default": "0"
        }
      ],
      "body": [
        {
          "name": "market_id",
          "encoding": "u64le",
          "from": "market_id"
        },
        {
          "name": "side",
          "encoding": "u8",
          "from": "side"
        },
        {
          "name": "price",
          "encoding": "u64le",
          "from": "price"
        },
        {
          "name": "amount",
          "encoding": "u64le",
          "from": "amount"
        },
        {
          "name": "flags",
          "encoding": "u8",
          "from": "flags"
        },
        {
          "name": "expiry",
          "encoding": "u64le",
          "from": "expiry"
        }
      ],
      "example": {
        "market_id": "7",
        "side": "0",
        "price": "150000000",
        "amount": "1000",
        "flags": "0",
        "expiry": "0"
      },
      "notes": []
    },
    {
      "name": "ReassignSchedule",
      "type": 31,
      "command": "reassign-schedule",
      "binary": null,
      "description": "Redirect a schedule's future fires to a new recipient.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "schedule_id",
          "kind": "int64",
          "required": true,
          "help": "schedule id"
        },
        {
          "name": "new_recipient",
          "kind": "address",
          "required": true,
          "help": "new recipient"
        }
      ],
      "body": [
        {
          "name": "schedule_id",
          "encoding": "u64le",
          "from": "schedule_id"
        },
        {
          "name": "new_recipient",
          "encoding": "address",
          "from": "new_recipient"
        }
      ],
      "example": {
        "schedule_id": "11",
        "new_recipient": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I"
      },
      "notes": []
    },
    {
      "name": "RegisterGateway",
      "type": 36,
      "command": "register-gateway",
      "binary": "zbc-gateway-register",
      "description": "Announce a gateway you run, locking the registration stake.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "gateway_key",
          "kind": "key",
          "required": true,
          "help": "gateway public key: 64 hex (zbc-cli) or ZBG_ address (zbc-gateway-register)"
        },
        {
          "name": "domain",
          "kind": "string",
          "required": true,
          "help": "public domain, 1-256 chars"
        },
        {
          "name": "url",
          "kind": "string",
          "required": true,
          "help": "base URL"
        }
      ],
      "body": [
        {
          "name": "gateway_key",
          "encoding": "key32",
          "from": "gateway_key"
        },
        {
          "name": "domain",
          "encoding": "str32",
          "from": "domain"
        },
        {
          "name": "url",
          "encoding": "str32",
          "from": "url"
        }
      ],
      "example": {
        "gateway_key": "2222222222222222222222222222222222222222222222222222222222222222",
        "domain": "gw.example.org",
        "url": "https://gw.example.org"
      },
      "notes": [
        "zbc-gateway-register names its first field owner_privkey."
      ]
    },
    {
      "name": "NodeRegistration",
      "type": 2,
      "command": "register-node",
      "binary": "zbc-node-register",
      "description": "Register a node with a locked stake; the owner proves control of the node key.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": true,
      "custom": "proof_of_ownership",
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "node_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the node's private key; its public key goes in the body"
        },
        {
          "name": "locked_balance",
          "kind": "int64",
          "required": true,
          "help": "stake to lock (atomic)"
        }
      ],
      "body": [
        {
          "name": "node_public_key",
          "encoding": "pubkey_of_key",
          "from": "node_privkey"
        },
        {
          "name": "owner",
          "encoding": "sender_address",
          "from": "owner",
          "computed": "the owner's 36-byte account"
        },
        {
          "name": "locked_balance",
          "encoding": "u64le",
          "from": "locked_balance"
        },
        {
          "name": "proof_of_ownership",
          "encoding": "custom",
          "from": "proof_of_ownership",
          "computed": "136 bytes: owner address (36) \u2016 latest block hash (32) \u2016 latest block height u32le \u2016 Ed25519(owner seed, those 72 bytes); block from GET /api/v1/blocks/latest"
        }
      ],
      "example": {
        "node_privkey": "2222222222222222222222222222222222222222222222222222222222222222",
        "locked_balance": "100000000000"
      },
      "notes": [
        "zbc-node-register takes (node_privkey, owner_privkey, locked_balance): node key first, then the owner key that signs."
      ]
    },
    {
      "name": "RegisterRelease",
      "type": 32,
      "command": "register-release",
      "binary": null,
      "description": "Publish a signed binary release (release authority only).",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "version",
          "kind": "string",
          "required": true,
          "help": "release version, 1-256 chars"
        },
        {
          "name": "manifest_hash",
          "kind": "hex32",
          "required": true,
          "help": "manifest hash"
        },
        {
          "name": "release_address",
          "kind": "address",
          "required": true,
          "help": "the release's on-chain address"
        }
      ],
      "body": [
        {
          "name": "version",
          "encoding": "str32",
          "from": "version"
        },
        {
          "name": "manifest_hash",
          "encoding": "hex",
          "from": "manifest_hash",
          "size": 32
        },
        {
          "name": "release_address",
          "encoding": "address",
          "from": "release_address"
        }
      ],
      "example": {
        "version": "0.4.2",
        "manifest_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "release_address": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I"
      },
      "notes": []
    },
    {
      "name": "RegisterRelay",
      "type": 48,
      "command": "relay-register",
      "binary": "zbc-relay-register",
      "description": "Announce a relay a gateway runs.",
      "sender_key": "owner_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "owner_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key (64 hex). Named owner_privkey: ZBC_KEY does not apply, pass it explicitly"
        },
        {
          "name": "relay_key",
          "kind": "key",
          "required": true,
          "help": "the relay's ZBR_ address or 64 hex"
        },
        {
          "name": "gateway_key",
          "kind": "key",
          "required": true,
          "help": "the ZBG_ address or 64 hex of the gateway it serves"
        },
        {
          "name": "domain",
          "kind": "string",
          "required": true,
          "help": "public domain"
        },
        {
          "name": "url",
          "kind": "string",
          "required": true,
          "help": "base URL"
        }
      ],
      "body": [
        {
          "name": "relay_key",
          "encoding": "key32",
          "from": "relay_key"
        },
        {
          "name": "gateway_key",
          "encoding": "key32",
          "from": "gateway_key"
        },
        {
          "name": "domain",
          "encoding": "str32",
          "from": "domain"
        },
        {
          "name": "url",
          "encoding": "str32",
          "from": "url"
        }
      ],
      "example": {
        "relay_key": "1111111111111111111111111111111111111111111111111111111111111111",
        "gateway_key": "2222222222222222222222222222222222222222222222222222222222222222",
        "domain": "relay.example.org",
        "url": "https://relay.example.org"
      },
      "notes": [
        "No zbc-cli subcommand."
      ]
    },
    {
      "name": "UnregisterRelay",
      "type": 49,
      "command": "relay-unregister",
      "binary": "zbc-relay-unregister",
      "description": "Withdraw a relay announcement.",
      "sender_key": "owner_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "owner_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key (64 hex). Named owner_privkey: ZBC_KEY does not apply, pass it explicitly"
        },
        {
          "name": "relay_key",
          "kind": "key",
          "required": true,
          "help": "the relay's ZBR_ address or 64 hex"
        }
      ],
      "body": [
        {
          "name": "relay_key",
          "encoding": "key32",
          "from": "relay_key"
        }
      ],
      "example": {
        "relay_key": "1111111111111111111111111111111111111111111111111111111111111111"
      },
      "notes": [
        "No zbc-cli subcommand."
      ]
    },
    {
      "name": "ReleaseAuthorityAccept",
      "type": 34,
      "command": "release-authority-accept",
      "binary": null,
      "description": "Accept a pending release-authority handover. Empty body.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        }
      ],
      "body": [],
      "example": {},
      "notes": []
    },
    {
      "name": "ReleaseAuthorityPropose",
      "type": 33,
      "command": "release-authority-propose",
      "binary": null,
      "description": "Propose handing the release authority to another account.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "new_authority",
          "kind": "address",
          "required": true,
          "help": "proposed new authority"
        }
      ],
      "body": [
        {
          "name": "new_authority",
          "encoding": "address",
          "from": "new_authority"
        }
      ],
      "example": {
        "new_authority": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I"
      },
      "notes": []
    },
    {
      "name": "RemoveAccountDataset",
      "type": 259,
      "command": "remove-dataset",
      "binary": "zbc-dataset-remove",
      "description": "Deactivate a key-value property; same body layout as setup-dataset.",
      "sender_key": "sender_privkey",
      "recipient": "required",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "recipient",
          "kind": "address",
          "required": true,
          "help": "dataset subject address"
        },
        {
          "name": "property",
          "kind": "string",
          "required": true,
          "help": "key"
        },
        {
          "name": "value",
          "kind": "string",
          "required": true,
          "help": "value"
        }
      ],
      "body": [
        {
          "name": "property",
          "encoding": "str32",
          "from": "property"
        },
        {
          "name": "value",
          "encoding": "str32",
          "from": "value"
        },
        {
          "name": "setter",
          "encoding": "sender_address",
          "from": "setter",
          "computed": "the sender's 36-byte account"
        },
        {
          "name": "recipient",
          "encoding": "address",
          "from": "recipient"
        }
      ],
      "example": {
        "recipient": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I",
        "property": "role",
        "value": "tester"
      },
      "notes": []
    },
    {
      "name": "RemoveNodeRegistration",
      "type": 514,
      "command": "remove-node",
      "binary": "zbc-node-remove",
      "description": "Remove a node from the registry; the locked balance returns to the owner.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "node_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the node's private key; its public key is the body"
        }
      ],
      "body": [
        {
          "name": "node_public_key",
          "encoding": "pubkey_of_key",
          "from": "node_privkey"
        }
      ],
      "example": {
        "node_privkey": "2222222222222222222222222222222222222222222222222222222222222222"
      },
      "notes": [
        "zbc-node-remove takes (node_privkey, owner_privkey)."
      ]
    },
    {
      "name": "RevokeRelease",
      "type": 35,
      "command": "revoke-release",
      "binary": null,
      "description": "Revoke a published release.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "version",
          "kind": "string",
          "required": true,
          "help": "version to revoke"
        }
      ],
      "body": [
        {
          "name": "version",
          "encoding": "str32",
          "from": "version"
        }
      ],
      "example": {
        "version": "0.4.2"
      },
      "notes": []
    },
    {
      "name": "ScheduledTransfer",
      "type": 29,
      "command": "scheduled-transfer",
      "binary": null,
      "description": "Recurring or vested transfers to a recipient.",
      "sender_key": "sender_privkey",
      "recipient": "required",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "recipient",
          "kind": "address",
          "required": true,
          "help": "paid on each fire"
        },
        {
          "name": "token_id",
          "kind": "int64",
          "required": false,
          "help": "0 = ZBC",
          "default": "0"
        },
        {
          "name": "per_fire_amount",
          "kind": "int64",
          "required": true,
          "help": "amount per fire (atomic), > 0"
        },
        {
          "name": "interval_seconds",
          "kind": "int64",
          "required": false,
          "help": "seconds between fires",
          "default": "0"
        },
        {
          "name": "remaining_fires",
          "kind": "uint32",
          "required": true,
          "help": "number of fires, >= 1"
        },
        {
          "name": "cliff_seconds",
          "kind": "int64",
          "required": false,
          "help": "delay before the first fire",
          "default": "0"
        },
        {
          "name": "funding_mode",
          "kind": "uint8",
          "required": false,
          "help": "0 pre-lock now, 1 pull at fire",
          "default": "0"
        },
        {
          "name": "cancel_policy",
          "kind": "uint8",
          "required": false,
          "help": "0 or 1",
          "default": "0"
        },
        {
          "name": "end_time",
          "kind": "int64",
          "required": false,
          "help": "Unix-seconds cutoff, 0 = none",
          "default": "0"
        }
      ],
      "body": [
        {
          "name": "token_id",
          "encoding": "u64le",
          "from": "token_id"
        },
        {
          "name": "per_fire_amount",
          "encoding": "u64le",
          "from": "per_fire_amount"
        },
        {
          "name": "interval_seconds",
          "encoding": "u64le",
          "from": "interval_seconds"
        },
        {
          "name": "remaining_fires",
          "encoding": "u32le",
          "from": "remaining_fires"
        },
        {
          "name": "cliff_seconds",
          "encoding": "u64le",
          "from": "cliff_seconds"
        },
        {
          "name": "funding_mode",
          "encoding": "u8",
          "from": "funding_mode"
        },
        {
          "name": "cancel_policy",
          "encoding": "u8",
          "from": "cancel_policy"
        },
        {
          "name": "end_time",
          "encoding": "u64le",
          "from": "end_time"
        },
        {
          "name": "reserved",
          "encoding": "literal",
          "from": "reserved",
          "value": "00"
        }
      ],
      "example": {
        "recipient": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I",
        "token_id": "0",
        "per_fire_amount": "100000000",
        "interval_seconds": "86400",
        "remaining_fires": "3",
        "cliff_seconds": "0",
        "funding_mode": "0",
        "cancel_policy": "0",
        "end_time": "0"
      },
      "notes": []
    },
    {
      "name": "SendZBC",
      "type": 1,
      "command": "send-zbc",
      "binary": "zbc-send",
      "description": "Send ZBC from the sender to a recipient; optionally escrowed.",
      "sender_key": "sender_privkey",
      "recipient": "required",
      "options": [
        "message",
        "encrypt",
        "escrow",
        "chain"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "recipient",
          "kind": "address",
          "required": true,
          "help": "recipient address (ZBC_, 64 hex, or another chain's address)"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "amount in atomic units (1 ZBC = 100000000)"
        }
      ],
      "body": [
        {
          "name": "amount",
          "encoding": "u64le",
          "from": "amount"
        }
      ],
      "example": {
        "recipient": "ZBC_L2HLFDOM_VKKKTEXX_C2P2M6LG_EB6ZNKSV_356SJUWW_5QPVHDE7_EFJA3PEX",
        "amount": "100000000"
      },
      "notes": [
        "zbc-send also accepts --liquid <minutes>, which makes it a LiquidPayment (type 6) instead."
      ]
    },
    {
      "name": "SetDatasetPolicy",
      "type": 43,
      "command": "set-dataset-policy",
      "binary": null,
      "description": "Set a dataset object's manage policy and edit its access lists.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "object_id",
          "kind": "hex32",
          "required": true,
          "help": "dataset object id"
        },
        {
          "name": "mode",
          "kind": "uint8",
          "required": true,
          "help": "0 owner-only, 1 whitelist, 2 blacklist, 3 open",
          "min": 0,
          "max": 3
        },
        {
          "name": "add",
          "kind": "address_list",
          "required": false,
          "help": "comma-separated addresses to add (max 255)",
          "default": ""
        },
        {
          "name": "remove",
          "kind": "address_list",
          "required": false,
          "help": "comma-separated addresses to remove (max 255)",
          "default": ""
        }
      ],
      "body": [
        {
          "name": "object_id",
          "encoding": "hex",
          "from": "object_id",
          "size": 32
        },
        {
          "name": "mode",
          "encoding": "u8",
          "from": "mode"
        },
        {
          "name": "add",
          "encoding": "address_list8",
          "from": "add"
        },
        {
          "name": "remove",
          "encoding": "address_list8",
          "from": "remove"
        }
      ],
      "example": {
        "object_id": "1111111111111111111111111111111111111111111111111111111111111111",
        "mode": "1",
        "add": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I",
        "remove": ""
      },
      "notes": []
    },
    {
      "name": "SetupAccountDataset",
      "type": 3,
      "command": "setup-dataset",
      "binary": "zbc-dataset-setup",
      "description": "Set a key-value property on an account (the recipient is the subject).",
      "sender_key": "sender_privkey",
      "recipient": "required",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "recipient",
          "kind": "address",
          "required": true,
          "help": "dataset subject address"
        },
        {
          "name": "property",
          "kind": "string",
          "required": true,
          "help": "key"
        },
        {
          "name": "value",
          "kind": "string",
          "required": true,
          "help": "value"
        }
      ],
      "body": [
        {
          "name": "property",
          "encoding": "str32",
          "from": "property"
        },
        {
          "name": "value",
          "encoding": "str32",
          "from": "value"
        },
        {
          "name": "setter",
          "encoding": "sender_address",
          "from": "setter",
          "computed": "the sender's 36-byte account"
        },
        {
          "name": "recipient",
          "encoding": "address",
          "from": "recipient"
        }
      ],
      "example": {
        "recipient": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I",
        "property": "role",
        "value": "tester"
      },
      "notes": []
    },
    {
      "name": "StoreFile",
      "type": 40,
      "command": "store-file",
      "binary": null,
      "description": "Anchor a decentralised-storage manifest (root and piece ids) with a rent deposit.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "file_root",
          "kind": "hex32",
          "required": true,
          "help": "manifest root hash"
        },
        {
          "name": "total_size",
          "kind": "int64",
          "required": true,
          "help": "file size in bytes"
        },
        {
          "name": "piece_size",
          "kind": "uint32",
          "required": true,
          "help": "piece size in bytes"
        },
        {
          "name": "deposit",
          "kind": "int64",
          "required": true,
          "help": "rent deposit (atomic)"
        },
        {
          "name": "piece_ids",
          "kind": "hexbytes",
          "required": true,
          "help": "piece id hashes concatenated, n x 32 bytes"
        }
      ],
      "body": [
        {
          "name": "file_root",
          "encoding": "hex",
          "from": "file_root",
          "size": 32
        },
        {
          "name": "total_size",
          "encoding": "u64le",
          "from": "total_size"
        },
        {
          "name": "piece_size",
          "encoding": "u32le",
          "from": "piece_size"
        },
        {
          "name": "deposit",
          "encoding": "u64le",
          "from": "deposit"
        },
        {
          "name": "piece_count",
          "encoding": "u32le",
          "from": "piece_ids",
          "computed": "len(piece_ids) / 32"
        },
        {
          "name": "piece_ids",
          "encoding": "hex",
          "from": "piece_ids"
        }
      ],
      "example": {
        "file_root": "1111111111111111111111111111111111111111111111111111111111111111",
        "total_size": "4096",
        "piece_size": "2048",
        "deposit": "100000000",
        "piece_ids": "11111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222"
      },
      "notes": []
    },
    {
      "name": "AcceptSwapOffer",
      "type": 19,
      "command": "swap-accept",
      "binary": "zbc-swap-accept",
      "description": "Fill an open swap offer.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "offer_id",
          "kind": "int64",
          "required": true,
          "help": "offer id"
        }
      ],
      "body": [
        {
          "name": "offer_id",
          "encoding": "u64le",
          "from": "offer_id"
        }
      ],
      "example": {
        "offer_id": "42"
      },
      "notes": []
    },
    {
      "name": "CancelSwapOffer",
      "type": 20,
      "command": "swap-cancel",
      "binary": "zbc-swap-cancel",
      "description": "Cancel your open swap offer; the held amount is refunded.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "offer_id",
          "kind": "int64",
          "required": true,
          "help": "offer id"
        }
      ],
      "body": [
        {
          "name": "offer_id",
          "encoding": "u64le",
          "from": "offer_id"
        }
      ],
      "example": {
        "offer_id": "42"
      },
      "notes": []
    },
    {
      "name": "CreateSwapOffer",
      "type": 18,
      "command": "swap-create",
      "binary": "zbc-swap-create",
      "description": "Offer give_amount of give_token for want_amount of want_token; the give side is held.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "give_token",
          "kind": "int64",
          "required": true,
          "help": "token to give, 0 = ZBC"
        },
        {
          "name": "give_amount",
          "kind": "int64",
          "required": true,
          "help": "atomic"
        },
        {
          "name": "want_token",
          "kind": "int64",
          "required": true,
          "help": "token wanted, 0 = ZBC"
        },
        {
          "name": "want_amount",
          "kind": "int64",
          "required": true,
          "help": "atomic"
        },
        {
          "name": "expiry",
          "kind": "int64",
          "required": false,
          "help": "Unix seconds, 0 = good till cancelled",
          "default": "0"
        }
      ],
      "body": [
        {
          "name": "give_token",
          "encoding": "u64le",
          "from": "give_token"
        },
        {
          "name": "give_amount",
          "encoding": "u64le",
          "from": "give_amount"
        },
        {
          "name": "want_token",
          "encoding": "u64le",
          "from": "want_token"
        },
        {
          "name": "want_amount",
          "encoding": "u64le",
          "from": "want_amount"
        },
        {
          "name": "expiry",
          "encoding": "u64le",
          "from": "expiry"
        }
      ],
      "example": {
        "give_token": "0",
        "give_amount": "100000000",
        "want_token": "123456789",
        "want_amount": "5000",
        "expiry": "0"
      },
      "notes": []
    },
    {
      "name": "TransferDataset",
      "type": 42,
      "command": "transfer-dataset",
      "binary": null,
      "description": "Propose transferring a dataset object to a new owner.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "object_id",
          "kind": "hex32",
          "required": true,
          "help": "dataset object id = the creating transaction hash"
        },
        {
          "name": "new_owner",
          "kind": "address",
          "required": true,
          "help": "new owner"
        }
      ],
      "body": [
        {
          "name": "object_id",
          "encoding": "hex",
          "from": "object_id",
          "size": 32
        },
        {
          "name": "new_owner",
          "encoding": "address",
          "from": "new_owner"
        }
      ],
      "example": {
        "object_id": "1111111111111111111111111111111111111111111111111111111111111111",
        "new_owner": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I"
      },
      "notes": []
    },
    {
      "name": "TransferToken",
      "type": 11,
      "command": "transfer-token",
      "binary": "zbc-token-transfer",
      "description": "Transfer a token to a recipient.",
      "sender_key": "sender_privkey",
      "recipient": "required",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "recipient",
          "kind": "address",
          "required": true,
          "help": "recipient address"
        },
        {
          "name": "token_id",
          "kind": "int64",
          "required": true,
          "help": "token id"
        },
        {
          "name": "amount",
          "kind": "int64",
          "required": true,
          "help": "amount (atomic), > 0"
        }
      ],
      "body": [
        {
          "name": "token_id",
          "encoding": "u64le",
          "from": "token_id"
        },
        {
          "name": "amount",
          "encoding": "u64le",
          "from": "amount"
        }
      ],
      "example": {
        "recipient": "ZBC_2BFLEMTU_FO2KWOQT_NC6UMFPE_43ICESVX_DIAWXL4F_ECRTFSLX_Q43UIV2I",
        "token_id": "-4611686018427387904",
        "amount": "500"
      },
      "notes": []
    },
    {
      "name": "UnregisterGateway",
      "type": 38,
      "command": "unregister-gateway",
      "binary": "zbc-gateway-unregister",
      "description": "Withdraw a gateway you registered; the stake is refunded.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": false,
      "custom": null,
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "gateway_key",
          "kind": "key",
          "required": true,
          "help": "gateway public key"
        }
      ],
      "body": [
        {
          "name": "gateway_key",
          "encoding": "key32",
          "from": "gateway_key"
        }
      ],
      "example": {
        "gateway_key": "2222222222222222222222222222222222222222222222222222222222222222"
      },
      "notes": [
        "zbc-gateway-unregister names its first field owner_privkey."
      ]
    },
    {
      "name": "NodeRegistrationUpdate",
      "type": 258,
      "command": "update-node",
      "binary": "zbc-node-update",
      "description": "Change a node registration's locked balance.",
      "sender_key": "sender_privkey",
      "recipient": "none",
      "options": [
        "message",
        "encrypt"
      ],
      "needs_node": true,
      "custom": "proof_of_ownership",
      "params": [
        {
          "name": "sender_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the signing key: 32-byte Ed25519 seed as 64 hex; '-' or omitted = ZBC_KEY"
        },
        {
          "name": "node_privkey",
          "kind": "privkey",
          "required": true,
          "help": "the node's private key"
        },
        {
          "name": "locked_balance",
          "kind": "int64",
          "required": true,
          "help": "new stake (atomic)"
        }
      ],
      "body": [
        {
          "name": "node_public_key",
          "encoding": "pubkey_of_key",
          "from": "node_privkey"
        },
        {
          "name": "locked_balance",
          "encoding": "u64le",
          "from": "locked_balance"
        },
        {
          "name": "proof_of_ownership",
          "encoding": "custom",
          "from": "proof_of_ownership",
          "computed": "as register-node"
        }
      ],
      "example": {
        "node_privkey": "2222222222222222222222222222222222222222222222222222222222222222",
        "locked_balance": "200000000000"
      },
      "notes": [
        "zbc-node-update takes (node_privkey, owner_privkey, new_locked_balance)."
      ]
    }
  ];
  var COMMAND_BY_NAME = new Map(COMMANDS.map((c) => [c.command, c]));
  return __toCommonJS(index_exports);
})();
if (typeof module !== "undefined" && module.exports) module.exports = ZBC;
