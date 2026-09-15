// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** ZBC-MSG-v1 message signing (spec/signing.md section 5). */
import { sha3_256 } from "./crypto/sha3.js";
import { sign, verify } from "./crypto/ed25519.js";
import { keyPairFromSeed } from "./keys.js";
import { decodeZbcAddress, encodeZbcAddress } from "./address.js";
import { bytesToHex, concat, hexToBytes, isHex, utf8 } from "./util/bytes.js";

export const MESSAGE_SIGNING_SCHEME = "ZBC-MSG-v1";
const TAG = utf8("ZBC-MSG");

export function messageDigest(message: Uint8Array): Uint8Array {
  return sha3_256(concat(TAG, message));
}

export interface SignedMessage {
  scheme: string; address: string; public_key: string; message_hex: string; digest: string; signature: string;
}

export function signMessage(seed: Uint8Array | string, message: Uint8Array): SignedMessage {
  const kp = keyPairFromSeed(seed);
  const digest = messageDigest(message);
  return { scheme: MESSAGE_SIGNING_SCHEME, address: kp.address, public_key: bytesToHex(kp.publicKey),
           message_hex: bytesToHex(message), digest: bytesToHex(digest), signature: bytesToHex(sign(digest, kp.seed)) };
}

/** `address` is a ZBC_ address or a 64-hex public key. Returns false for anything that does not verify. */
export function verifyMessage(address: string, message: Uint8Array, signature: Uint8Array | string): boolean {
  const pub = publicKeyOfAddress(address);
  if (!pub) return false;
  const sig = typeof signature === "string" ? (isHex(signature, 128) ? hexToBytes(signature) : null) : signature;
  if (!sig || sig.length !== 64) return false;
  return verify(messageDigest(message), sig, pub);
}

/** The public key behind a ZBC_ address or 64 hex, or null. */
export function publicKeyOfAddress(address: string): Uint8Array | null {
  if (isHex(address, 64)) return hexToBytes(address);
  const d = decodeZbcAddress(address);
  return d && d.prefix === "ZBC" ? d.payload : null;
}
export { encodeZbcAddress };
