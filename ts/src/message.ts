// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/**
 * Message signing (spec/signing.md sections 5 and 5a).
 *   ZBC-MSG-v2: digest = SHA3-256("ZBC-MSG-v2" ‖ genesis_hash (32) ‖ message), bound to one chain.
 *   ZBC-MSG-v1: digest = SHA3-256("ZBC-MSG" ‖ message); verified until the sunset, never produced.
 */
import { sha3_256 } from "./crypto/sha3.js";
import { sign, verify } from "./crypto/ed25519.js";
import { keyPairFromSeed } from "./keys.js";
import { decodeZbcAddress, encodeZbcAddress } from "./address.js";
import { bytesToHex, concat, hexToBytes, isHex, utf8 } from "./util/bytes.js";

export const MESSAGE_SIGNING_SCHEME = "ZBC-MSG-v2";
export const MESSAGE_SIGNING_SCHEME_V1 = "ZBC-MSG-v1";
/** 2026-12-01T00:00:00Z: v1 signatures verify before this Unix second and are refused from it on. */
export const MESSAGE_SIGNING_V1_SUNSET = 1796083200;
const TAG_V2 = utf8("ZBC-MSG-v2");
const TAG_V1 = utf8("ZBC-MSG");

/** The 32-byte genesis hash from bytes or 64 hex; throws on anything else. */
function genesisBytes(genesis: Uint8Array | string): Uint8Array {
  const g = typeof genesis === "string" ? (isHex(genesis, 64) ? hexToBytes(genesis) : null) : genesis;
  if (!g || g.length !== 32) throw new Error("ZBC-MSG-v2 binds the signature to one chain: it needs the chain's genesis hash (32 bytes, 64 hex)");
  return g;
}

/** ZBC-MSG-v2 digest. */
export function messageDigest(message: Uint8Array, genesis: Uint8Array | string): Uint8Array {
  return sha3_256(concat(TAG_V2, genesisBytes(genesis), message));
}
/** ZBC-MSG-v1 digest (legacy, verify only). */
export function messageDigestV1(message: Uint8Array): Uint8Array {
  return sha3_256(concat(TAG_V1, message));
}

export interface SignedMessage {
  scheme: string; genesis_hash: string; address: string; public_key: string; message_hex: string; digest: string; signature: string;
}

/** Sign for one chain (its genesis hash as bytes or 64 hex). Always ZBC-MSG-v2. */
export function signMessage(seed: Uint8Array | string, message: Uint8Array, genesis: Uint8Array | string): SignedMessage {
  const kp = keyPairFromSeed(seed);
  const g = genesisBytes(genesis);
  const digest = messageDigest(message, g);
  return { scheme: MESSAGE_SIGNING_SCHEME, genesis_hash: bytesToHex(g), address: kp.address, public_key: bytesToHex(kp.publicKey),
           message_hex: bytesToHex(message), digest: bytesToHex(digest), signature: bytesToHex(sign(digest, kp.seed)) };
}

export interface MessageVerification {
  valid: boolean;
  /** "ZBC-MSG-v2", or "ZBC-MSG-v1 (accepted until 2026-12-01)" when only the legacy digest verified. */
  scheme: string;
  /** The digest that verified; the v2 digest (or the v1 digest without a genesis) when nothing did. */
  digest: Uint8Array;
}

/**
 * v2 first (needs the chain's genesis; without one v2 is not tried), then v1 while `now` (Unix seconds,
 * default the clock) is before MESSAGE_SIGNING_V1_SUNSET. `address` is a ZBC_ address or a 64-hex public key.
 */
export function verifyMessageDetailed(address: string, message: Uint8Array, signature: Uint8Array | string,
                                      genesis?: Uint8Array | string, now: number = Math.floor(Date.now() / 1000)): MessageVerification {
  const pub = publicKeyOfAddress(address);
  const sig = typeof signature === "string" ? (isHex(signature, 128) ? hexToBytes(signature) : null) : signature;
  const ok = (digest: Uint8Array) => !!pub && !!sig && sig.length === 64 && verify(digest, sig, pub);
  let digest: Uint8Array | null = null;
  if (genesis !== undefined) {
    let g: Uint8Array | null = null;
    try { g = genesisBytes(genesis); } catch { g = null; }
    if (g) { digest = messageDigest(message, g); if (ok(digest)) return { valid: true, scheme: MESSAGE_SIGNING_SCHEME, digest }; }
  }
  if (now < MESSAGE_SIGNING_V1_SUNSET) {
    const d1 = messageDigestV1(message);
    if (ok(d1)) return { valid: true, scheme: MESSAGE_SIGNING_SCHEME_V1 + " (accepted until 2026-12-01)", digest: d1 };
  }
  return { valid: false, scheme: MESSAGE_SIGNING_SCHEME, digest: digest ?? messageDigestV1(message) };
}

/** True when the signature verifies (v2 for `genesis`, or v1 before the sunset). False for anything else. */
export function verifyMessage(address: string, message: Uint8Array, signature: Uint8Array | string,
                              genesis?: Uint8Array | string, now?: number): boolean {
  return verifyMessageDetailed(address, message, signature, genesis, now).valid;
}

/** The public key behind a ZBC_ address or 64 hex, or null. */
export function publicKeyOfAddress(address: string): Uint8Array | null {
  if (isHex(address, 64)) return hexToBytes(address);
  const d = decodeZbcAddress(address);
  return d && d.prefix === "ZBC" ? d.payload : null;
}
export { encodeZbcAddress };
