// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/**
 * Parameter validation and the generic body serialiser, driven by the transaction descriptions
 * of spec/transactions (the encodings of index.json). Fields marked `computed` are produced by
 * the hooks in custom.ts.
 */
import { parseAddress, parseKey32 } from "./address.js";
import { keyPairFromSeed, KeyPair } from "./keys.js";
import { usage } from "./errors.js";
import { ByteWriter, hexToBytes, isHex, utf8 } from "./util/bytes.js";
import { FieldDef, ParamDef, TxDef } from "./spec.js";

const INT_LIMITS: Record<string, [bigint, bigint]> = {
  int64: [-(1n << 63n), (1n << 63n) - 1n], uint64: [0n, (1n << 64n) - 1n], uint32: [0n, (1n << 32n) - 1n], uint8: [0n, 255n],
};

export function parseInteger(value: string, kind: string, name: string): bigint {
  if (!/^-?\d+$/.test(value.trim())) throw usage(`${name} must be a whole number, got "${value}"`);
  const v = BigInt(value.trim());
  const lim = INT_LIMITS[kind] ?? INT_LIMITS.int64;
  if (v < lim[0] || v > lim[1]) throw usage(`${name} is out of range for ${kind}`);
  return v;
}

/** Check one parameter value against its kind; returns the value to keep (trimmed where it matters). */
export function validateParam(p: ParamDef, value: string): string {
  switch (p.kind) {
    case "privkey":
      if (!isHex(value, 64)) throw usage(`${p.name} must be 64 hex characters (a 32-byte private key)`);
      return value;
    case "address":
      try { parseAddress(value); } catch (e) { throw usage(`invalid ${p.name}: ${(e as Error).message}`); }
      return value;
    case "address_list":
      for (const a of splitList(value)) { try { parseAddress(a); } catch (e) { throw usage(`invalid ${p.name} entry ${a}: ${(e as Error).message}`); } }
      return value;
    case "key":
      try { parseKey32(value); } catch (e) { throw usage(`invalid ${p.name}: ${(e as Error).message}`); }
      return value;
    case "int64": case "uint64": case "uint32": case "uint8": {
      const n = parseInteger(value, p.kind, p.name);
      if ((p.min !== undefined && n < BigInt(p.min)) || (p.max !== undefined && n > BigInt(p.max)))
        throw usage(`${p.name} must be between ${p.min ?? "-inf"} and ${p.max ?? "inf"}`);
      return value.trim();
    }
    case "hex32":
      if (!isHex(value, 64)) throw usage(`${p.name} must be 64 hex characters (32 bytes)`);
      return value;
    case "hexbytes":
      if (!isHex(value)) throw usage(`${p.name} must be hex`);
      return value;
    case "string": case "file":
      return value;
    default:
      return value;
  }
}

export function splitList(s: string): string[] {
  return s.split(",").map((x) => x.trim()).filter((x) => x.length > 0);
}

export interface BodyContext {
  /** The signing key pair (for `sender_address`). */
  sender: KeyPair;
  /** Bytes of `file` parameters, by parameter name, as hex. */
  files?: Record<string, string>;
  /** Values produced by custom hooks, by field name. */
  computed?: Record<string, Uint8Array>;
}

function conditionHolds(when: string, params: Record<string, string>): boolean {
  const m = /^(\w+) != (0|'')$/.exec(when);
  if (!m) throw new Error("unsupported condition " + when);
  const v = params[m[1]] ?? "";
  return m[2] === "0" ? BigInt(v || "0") !== 0n : v !== "";
}

/** Serialise one body field. */
export function encodeField(f: FieldDef, params: Record<string, string>, ctx: BodyContext): Uint8Array {
  const w = new ByteWriter();
  if (ctx.computed && f.name in ctx.computed) return ctx.computed[f.name];
  let value = params[f.from] ?? "";
  if (f.when_zero && (value === "" || BigInt(value) <= 0n)) value = params[f.when_zero] ?? "0";
  switch (f.encoding) {
    case "u8": return w.u8(Number(parseInteger(value, "uint8", f.name))).finish();
    case "u16le": return w.u16(Number(parseInteger(value, "uint32", f.name))).finish();
    case "u32le": return w.u32(Number(parseInteger(value, "uint32", f.name))).finish();
    case "u64le": return w.i64(parseInteger(value, "int64", f.name)).finish();
    case "hex": {
      const b = hexToBytes(value);
      if (f.size !== undefined && b.length !== f.size) throw usage(`${f.from} must be ${f.size} bytes (${2 * f.size} hex)`);
      return b;
    }
    case "hex16": { const b = hexToBytes(value); return w.u16(b.length).bytes(b).finish(); }
    case "bytes32": {
      const b = hexToBytes(ctx.files && f.from in ctx.files ? ctx.files[f.from] : value);
      return w.u32(b.length).bytes(b).finish();
    }
    case "str16": { const b = utf8(value); return w.u16(b.length).bytes(b).finish(); }
    case "str32": { const b = utf8(value); return w.u32(b.length).bytes(b).finish(); }
    case "address": return parseAddress(value).bytes;
    case "address_list": { for (const a of splitList(value)) w.bytes(parseAddress(a).bytes); return w.finish(); }
    case "address_list8": {
      const items = splitList(value);
      if (items.length > 255) throw usage(`${f.from}: at most 255 entries`);
      w.u8(items.length);
      for (const a of items) w.bytes(parseAddress(a).bytes);
      return w.finish();
    }
    case "sender_address": return ctx.sender.accountBytes;
    case "pubkey_of_key": {
      if (!isHex(value, 64)) throw usage(`${f.from} must be 64 hex characters (a 32-byte private key)`);
      return keyPairFromSeed(value).publicKey;
    }
    case "key32": return parseKey32(value);
    case "literal": return hexToBytes(f.value ?? "");
    case "custom": throw new Error(`field ${f.name} of ${f.from} needs a custom hook`);
    default: throw new Error("unknown encoding " + f.encoding);
  }
}

/** The whole body of a non-custom transaction (custom hooks may pre-fill `ctx.computed`). */
export function buildBody(def: TxDef, params: Record<string, string>, ctx: BodyContext): Uint8Array {
  const w = new ByteWriter();
  for (const f of def.body) {
    if (f.when && !conditionHolds(f.when, params)) continue;
    w.bytes(encodeField(f, params, ctx));
  }
  return w.finish();
}
