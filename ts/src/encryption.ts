// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** Sealed transaction messages (spec/signing.md section 8): 'ZBE1' || libsodium sealed box to the recipient's converted key. */
import { blake2b } from "./crypto/blake2b.js";
import { hsalsa20, secretbox, secretboxOpen } from "./crypto/salsa.js";
import { ed25519PublicKeyToX25519, ed25519SeedToX25519, x25519, x25519Base } from "./crypto/x25519.js";
import { concat } from "./util/bytes.js";

/** The 4-byte marker in front of a sealed message field. */
export const SEALED_MAGIC = new Uint8Array([0x5a, 0x42, 0x45, 0x31]);   // "ZBE1"
/** How much longer a sealed field is than its plaintext: marker 4 + ephemeral key 32 + tag 16. */
export const SEALED_OVERHEAD = 52;

/** True when the field starts with the marker (it may still fail to open). */
export function isSealed(field: Uint8Array): boolean {
  return field.length >= 4 && field[0] === 0x5a && field[1] === 0x42 && field[2] === 0x45 && field[3] === 0x31;
}

function boxKey(sk: Uint8Array, pk: Uint8Array): Uint8Array { return hsalsa20(x25519(sk, pk), new Uint8Array(16)); }
function nonceOf(ephemeralPk: Uint8Array, recipientPkX: Uint8Array): Uint8Array { return blake2b(concat(ephemeralPk, recipientPkX), 24); }

/** Seal `plaintext` to the recipient's 32-byte Ed25519 public key. The ephemeral secret key is random unless given (tests). */
export function seal(plaintext: Uint8Array, recipientPublicKey: Uint8Array, ephemeralSecretKey?: Uint8Array): Uint8Array {
  if (recipientPublicKey.length !== 32) throw new Error("recipient public key must be 32 bytes");
  const esk = ephemeralSecretKey ?? globalThis.crypto.getRandomValues(new Uint8Array(32));
  if (esk.length !== 32) throw new Error("ephemeral secret key must be 32 bytes");
  const rpk = ed25519PublicKeyToX25519(recipientPublicKey), epk = x25519Base(esk);
  return concat(SEALED_MAGIC, epk, secretbox(boxKey(esk, rpk), nonceOf(epk, rpk), plaintext));
}

/** Open a sealed field with the recipient's 32-byte Ed25519 seed: the plaintext, or null when it is not a sealed message or the key does not open it. */
export function openSealed(field: Uint8Array, recipientSeed: Uint8Array): Uint8Array | null {
  if (!isSealed(field) || field.length < SEALED_OVERHEAD || recipientSeed.length !== 32) return null;
  const sk = ed25519SeedToX25519(recipientSeed), pk = x25519Base(sk), epk = field.subarray(4, 36);
  return secretboxOpen(boxKey(sk, epk), nonceOf(epk, pk), field.subarray(36));
}
