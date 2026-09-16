<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/**
 * Sealed transaction messages (spec/signing.md section 8): "ZBE1" || libsodium sealed box to the recipient's
 * Ed25519 key converted to X25519. PHP ships libsodium, so this is the reference construction itself.
 */
final class Encryption
{
    /** The 4-byte marker in front of a sealed message field. */
    public const SEALED_MAGIC = 'ZBE1';
    /** How much longer a sealed field is than its plaintext: marker 4 + ephemeral key 32 + tag 16. */
    public const SEALED_OVERHEAD = 52;

    /** Ed25519 public key -> X25519 public key of the same point: u = (1 + y) / (1 - y) mod p. */
    public static function ed25519PublicKeyToX25519(string $publicKey): string
    {
        if (strlen($publicKey) !== 32) { throw new \InvalidArgumentException('public key must be 32 bytes'); }
        return sodium_crypto_sign_ed25519_pk_to_curve25519($publicKey);
    }

    /** Ed25519 seed -> X25519 secret key: the clamped first half of SHA-512(seed). */
    public static function ed25519SeedToX25519(string $seed): string
    {
        if (strlen($seed) !== 32) { throw new \InvalidArgumentException('seed must be 32 bytes'); }
        return sodium_crypto_sign_ed25519_sk_to_curve25519(sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed)));
    }

    /** The X25519 public key of a scalar: X25519(scalar, 9). */
    public static function x25519Base(string $scalar): string { return sodium_crypto_scalarmult_base($scalar); }

    /** True when the field starts with the marker (it may still fail to open). */
    public static function isSealed(string $field): bool { return strlen($field) >= 4 && substr($field, 0, 4) === self::SEALED_MAGIC; }

    /**
     * Seal $plaintext to the recipient's 32-byte Ed25519 public key. With an ephemeral secret key given (tests) the
     * box is rebuilt step by step as crypto_box_seal does it; without one libsodium draws the key itself.
     */
    public static function seal(string $plaintext, string $recipientPublicKey, ?string $ephemeralSecretKey = null): string
    {
        $rpk = self::ed25519PublicKeyToX25519($recipientPublicKey);
        if ($ephemeralSecretKey === null) { return self::SEALED_MAGIC . sodium_crypto_box_seal($plaintext, $rpk); }
        if (strlen($ephemeralSecretKey) !== 32) { throw new \InvalidArgumentException('ephemeral secret key must be 32 bytes'); }
        $epk = sodium_crypto_scalarmult_base($ephemeralSecretKey);
        $nonce = sodium_crypto_generichash($epk . $rpk, '', 24);
        $box = sodium_crypto_box($plaintext, $nonce, sodium_crypto_box_keypair_from_secretkey_and_publickey($ephemeralSecretKey, $rpk));
        return self::SEALED_MAGIC . $epk . $box;
    }

    /** The plaintext of a sealed field opened with the recipient's 32-byte seed, or null when it is not a sealed message or the key does not open it. */
    public static function openSealed(string $field, string $recipientSeed): ?string
    {
        if (!self::isSealed($field) || strlen($field) < self::SEALED_OVERHEAD || strlen($recipientSeed) !== 32) { return null; }
        $sk = self::ed25519SeedToX25519($recipientSeed);
        $pair = sodium_crypto_box_keypair_from_secretkey_and_publickey($sk, sodium_crypto_scalarmult_base($sk));
        $plain = sodium_crypto_box_seal_open(substr($field, 4), $pair);
        return $plain === false ? null : $plain;
    }
}
