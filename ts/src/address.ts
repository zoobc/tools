// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** Account addresses: the ZBC_/ZNK_/ZBS_ text form and every recipient form of spec/addresses.md. */
import { sha3_256 } from "./crypto/sha3.js";
import { base32Decode, base32Encode } from "./util/base32.js";
import { base58CheckDecode, base58Decode, RIPPLE_ALPHABET } from "./util/base58.js";
import { bech32DecodePlain, segwitDecode } from "./util/bech32.js";
import { ss58Decode } from "./util/ss58.js";
import { ByteWriter, concat, hexToBytes, isHex, utf8 } from "./util/bytes.js";

export const AccountType = {
  ZooBC: 0, Bitcoin: 1, Empty: 2, EstoniaEID: 3, Ethereum: 4, BitcoinP2PKH: 5, BitcoinP2SH: 6, BitcoinP2WPKH: 7,
  BitcoinP2WSH: 8, BitcoinTaproot: 9, DataSet: 10, Solana: 11, Polkadot: 12, Cardano: 13, Ripple: 14, Tron: 15, Tezos: 16,
} as const;

const TYPE_NAMES: Record<number, string> = {
  0: "ZooBC", 1: "Bitcoin", 3: "Estonia eID", 4: "Ethereum", 5: "Bitcoin P2PKH", 6: "Bitcoin P2SH", 7: "Bitcoin P2WPKH",
  8: "Bitcoin P2WSH", 9: "Bitcoin Taproot", 10: "DataSet", 11: "Solana", 12: "Polkadot", 13: "Cardano", 14: "Ripple", 15: "Tron", 16: "Tezos",
};
export function accountTypeName(t: number): string { return TYPE_NAMES[t] ?? `type ${t}`; }

/** Payload length by account type, as the node parses an envelope. */
export function payloadLength(t: number): number {
  switch (t) {
    case 1: case 5: case 6: case 7: case 14: case 15: case 16: case 4: return 20;
    case 13: return 28;
    default: return 32;
  }
}

/** `PREFIX_` + base32(payload ‖ SHA3-256(payload ‖ prefix)[0..3]) in seven groups of eight. */
export function encodeZbcAddress(payload: Uint8Array, prefix = "ZBC"): string {
  if (payload.length !== 32) throw new Error("address payload must be 32 bytes");
  if (prefix.length !== 3) throw new Error("prefix must be 3 characters");
  const check = sha3_256(concat(payload, utf8(prefix))).slice(0, 3);
  const b32 = base32Encode(concat(payload, check));
  let out = prefix;
  for (let i = 0; i < 7; i++) out += "_" + b32.slice(8 * i, 8 * i + 8);
  return out;
}

/** Decode `PREFIX_...` (separators `_`/`-`, any case). Returns the 32-byte payload and the upper-case prefix, or null. */
/** The 59 significant characters of a ZooBC address: separators (_ -) and whitespace dropped, upper case (addresses.md 2). */
export function zbcSignificant(text: string): string {
  return text.replace(/[-_\s]/g, "").toUpperCase();
}

/** (upper-case prefix, 32-byte payload) of a ZooBC address in any spelling, or null. */
export function decodeZbcAddress(text: string): { prefix: string; payload: Uint8Array } | null {
  const norm = zbcSignificant(text);
  if (norm.length < 3) return null;
  const prefix = norm.slice(0, 3);
  const body = norm.slice(3);
  if (body.length !== 56) return null;
  let raw: Uint8Array;
  try { raw = base32Decode(body); } catch { return null; }
  if (raw.length !== 35) return null;
  const payload = raw.slice(0, 32);
  const check = sha3_256(concat(payload, utf8(prefix))).slice(0, 3);
  if (check[0] !== raw[32] || check[1] !== raw[33] || check[2] !== raw[34]) return null;
  return { prefix, payload };
}

export function isZbcAddress(text: string, prefix?: string): boolean {
  const d = decodeZbcAddress(text);
  return d !== null && (prefix === undefined || d.prefix === prefix.toUpperCase());
}

/** A recipient as the envelope carries it: typed bytes, the type and a display string. */
export interface ParsedAddress {
  type: number;
  /** 4-byte little-endian type followed by the payload. */
  bytes: Uint8Array;
  payload: Uint8Array;
  typeName: string;
  display: string;
}
function typed(type: number, payload: Uint8Array, display: string): ParsedAddress {
  return { type, payload, bytes: new ByteWriter().u32(type).bytes(payload).finish(), typeName: accountTypeName(type), display };
}
export function typedAddress(type: number, payload: Uint8Array): Uint8Array {
  return new ByteWriter().u32(type).bytes(payload).finish();
}

export type Chain = "zbc" | "btc" | "eth" | "sol" | "dot" | "ada" | "xrp" | "trx" | "xtz" | "zbs";
export function chainOf(name: string): Chain | null {
  const n = name.toLowerCase();
  const map: Record<string, Chain> = {
    zbc: "zbc", zoobc: "zbc", btc: "btc", bitcoin: "btc", eth: "eth", ethereum: "eth", evm: "eth", sol: "sol", solana: "sol",
    dot: "dot", polkadot: "dot", substrate: "dot", ada: "ada", cardano: "ada", xrp: "xrp", ripple: "xrp", trx: "trx", tron: "trx",
    xtz: "xtz", tezos: "xtz", zbs: "zbs", dataset: "zbs",
  };
  return map[n] ?? null;
}

/**
 * Read a recipient string in the order of spec/addresses.md section 3. Throws on anything
 * unrecognised. `chain` forces one reading (the `--chain` option).
 */
export function parseAddress(input: string, chain: string = ""): ParsedAddress {
  const a = input.trim();
  if (a === "") throw new Error("empty address");
  const hint = chain ? chainOf(chain) : null;
  if (chain && !hint) throw new Error(`unknown chain ${chain}`);
  if (hint) {
    // The reference tries the hinted reading first and, when that fails, still accepts the plain
    // forms (0x…, ZBC_/ZNK_/ZBS_ text, Bitcoin, 64 hex) before giving up.
    try { return parseHinted(a, hint); } catch (e) {
      const up = a.toUpperCase();
      const plain = (a.length === 42 && (a.startsWith("0x") || a.startsWith("0X"))) || up.startsWith("ZBC") || up.startsWith("ZNK") || up.startsWith("ZBS")
        || a[0] === "1" || a[0] === "3" || /^(bc1|tb1|bcrt1)/i.test(a) || a.length === 64;
      if (!plain) throw e;
      return parseAddress(a);
    }
  }
  return parseAuto(a);
}

function parseHinted(a: string, hint: Chain): ParsedAddress {
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
  return parseAuto(a);   // btc, ada, xrp, trx, xtz: the reference has no forced reading, detection decides
}

/** Shape only: PREFIX then a separator, or the bare form: 59 significant characters, ZBC/ZBS prefix, base32 body. */
function looksZbc(a: string): boolean {
  if (a.length > 4 && (a[3] === "_" || a[3] === "-")) return true;
  const n = zbcSignificant(a);
  return n.length === 59 && (n.startsWith("ZBC") || n.startsWith("ZBS")) && /^[A-Z2-7]+$/.test(n.slice(3));
}

function parseAuto(a: string): ParsedAddress {
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
        if (body[0] === 0x00) return typed(AccountType.BitcoinP2PKH, body.slice(1), a);
        if (body[0] === 0x05) return typed(AccountType.BitcoinP2SH, body.slice(1), a);
      }
    }
  }
  if (a.length > 5 && a.slice(0, 5).toLowerCase() === "addr1") {
    const d = bech32DecodePlain(a);
    if (d && d.hrp === "addr" && d.bytes.length === 29 && d.bytes[0] === 0x61) return typed(AccountType.Cardano, d.bytes.slice(1), a);
    throw new Error("invalid Cardano address (expected a mainnet enterprise addr1… address)");
  }
  if (a[0] === "T" && a.length === 34) {
    const body = base58CheckDecode(a);
    if (body && body.length === 21 && body[0] === 0x41) return typed(AccountType.Tron, body.slice(1), a);
    throw new Error("invalid Tron address");
  }
  if (a[0] === "r" && a.length >= 25 && a.length <= 35) {
    const body = base58CheckDecode(a, RIPPLE_ALPHABET);
    if (body && body.length === 21 && body[0] === 0x00) return typed(AccountType.Ripple, body.slice(1), a);
    throw new Error("invalid Ripple address");
  }
  if (a.startsWith("tz1")) {
    const body = base58CheckDecode(a);
    if (body && body.length === 23 && body[0] === 0x06 && body[1] === 0xa1 && body[2] === 0x9f) return typed(AccountType.Tezos, body.slice(3), a);
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

function zbcForm(a: string): ParsedAddress {
  const d = decodeZbcAddress(a);
  if (!d) throw new Error("invalid ZooBC address checksum");
  if (d.prefix === "ZBS") return typed(AccountType.DataSet, d.payload, a);
  return typed(AccountType.ZooBC, d.payload, a);
}

/** A registry key parameter: 64 hex (optionally 0x) or a ZNK_/ZBG_/ZBR_/ZBC_ text address. 32 bytes. */
export function parseKey32(input: string): Uint8Array {
  if (input.length === 66 && input[3] === "_") {
    const d = decodeZbcAddress(input);
    if (!d) throw new Error("invalid address checksum");
    return d.payload;
  }
  const h = input.startsWith("0x") || input.startsWith("0X") ? input.slice(2) : input;
  if (!isHex(h, 64)) throw new Error("key must be a 64-hex string or a ZNK_/ZBG_/ZBR_ address");
  return hexToBytes(h);
}
