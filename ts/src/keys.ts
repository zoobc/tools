// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** Keys: seed -> key pair -> addresses; BIP-39 + SLIP-10 wallets (spec/signing.md section 1). */
import { publicKeyFromSeed } from "./crypto/ed25519.js";
import { hmacSha512, pbkdf2Sha512, sha256 } from "./crypto/sha2.js";
import { encodeZbcAddress, typedAddress, AccountType } from "./address.js";
import { bytesToHex, concat, hexToBytes, isHex, utf8 } from "./util/bytes.js";
import { BIP39_WORDS } from "./util/bip39-words.js";

export interface KeyPair {
  /** The 32-byte seed (what the tools call the private key). */
  seed: Uint8Array;
  publicKey: Uint8Array;
  /** `ZBC_` form of the public key. */
  address: string;
  /** `ZNK_` form, the node-key spelling of the same key. */
  nodeAddress: string;
  /** 36-byte typed account address: 00000000 ‖ public key. */
  accountBytes: Uint8Array;
}

export function keyPairFromSeed(seed: Uint8Array | string): KeyPair {
  const s = typeof seed === "string" ? seedFromHex(seed) : seed;
  if (s.length !== 32) throw new Error("Private key must be 64 hex characters (32 bytes)");
  const publicKey = publicKeyFromSeed(s);
  return { seed: s, publicKey, address: encodeZbcAddress(publicKey, "ZBC"), nodeAddress: encodeZbcAddress(publicKey, "ZNK"),
           accountBytes: typedAddress(AccountType.ZooBC, publicKey) };
}

export function seedFromHex(hex: string): Uint8Array {
  if (!isHex(hex, 64)) throw new Error("Private key must be 64 hex characters (32 bytes)");
  return hexToBytes(hex);
}

/** A fresh random seed from the platform's CSPRNG (Node and browsers). */
export function randomSeed(): Uint8Array {
  const s = new Uint8Array(32);
  globalThis.crypto.getRandomValues(s);
  return s;
}

// ---- BIP-39 and SLIP-10 -----------------------------------------------------------------------
/** True for 12, 15, 18, 21 or 24 words of the English list with a valid checksum. */
export function validateMnemonic(mnemonic: string): boolean {
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

/** Entropy (16–32 bytes, multiple of 4) -> mnemonic. */
export function mnemonicFromEntropy(entropy: Uint8Array): string {
  if (entropy.length < 16 || entropy.length > 32 || entropy.length % 4 !== 0) throw new Error("entropy must be 16-32 bytes");
  let bits = "";
  for (const b of entropy) bits += b.toString(2).padStart(8, "0");
  const cs = entropy.length / 4;
  bits += sha256(entropy)[0].toString(2).padStart(8, "0").slice(0, cs);
  const words: string[] = [];
  for (let i = 0; i < bits.length / 11; i++) words.push(BIP39_WORDS[parseInt(bits.slice(11 * i, 11 * i + 11), 2)]);
  return words.join(" ");
}

export function generateMnemonic(words: 12 | 15 | 18 | 21 | 24 = 24): string {
  const entropy = new Uint8Array((words * 11 - words / 3) / 8);
  globalThis.crypto.getRandomValues(entropy);
  return mnemonicFromEntropy(entropy);
}

/** BIP-39 seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048, 64). */
export function mnemonicToSeed(mnemonic: string, passphrase = ""): Uint8Array {
  return pbkdf2Sha512(utf8(mnemonic.trim().split(/\s+/).join(" ")), utf8("mnemonic" + passphrase), 2048, 64);
}

/** SLIP-10 for Ed25519 along a hardened-only path such as m/44'/883'/0'. Returns the 32-byte key. */
export function slip10Derive(path: string, seed: Uint8Array): Uint8Array {
  if (!/^m(\/[0-9]+')+$/.test(path)) throw new Error("invalid derivation path: " + path);
  let I = hmacSha512(utf8("ed25519 seed"), seed);
  let key = I.slice(0, 32), chain = I.slice(32);
  for (const seg of path.split("/").slice(1)) {
    const index = Number(seg.slice(0, -1));
    if (index >= 0x80000000) throw new Error("path index too large");
    const data = new Uint8Array(37);
    data.set(key, 1);
    new DataView(data.buffer).setUint32(33, index + 0x80000000, false);
    I = hmacSha512(chain, data);
    key = I.slice(0, 32); chain = I.slice(32);
  }
  return key;
}

export const ZOOBC_COIN_TYPE = 883;
export interface WalletAccount extends KeyPair { index: number; path: string }

/** Account `index` of a mnemonic wallet: m/44'/883'/index'. */
export function walletAccount(mnemonic: string, index: number, passphrase = ""): WalletAccount {
  const path = `m/44'/${ZOOBC_COIN_TYPE}'/${index}'`;
  const seed = slip10Derive(path, mnemonicToSeed(mnemonic, passphrase));
  return { ...keyPairFromSeed(seed), index, path };
}

export const seedHex = (kp: KeyPair): string => bytesToHex(kp.seed);
export const publicKeyHex = (kp: KeyPair): string => bytesToHex(kp.publicKey);
export { concat };
