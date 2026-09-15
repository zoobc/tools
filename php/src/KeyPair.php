<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** A 32-byte seed with its public key (spec/signing.md section 1). Ed25519 comes from ext-sodium. */
final class KeyPair
{
    public readonly string $seed;
    public readonly string $publicKey;
    private readonly string $secret;

    public function __construct(string $seed)
    {
        if (strlen($seed) !== 32) { throw new \InvalidArgumentException('Private key must be 64 hex characters (32 bytes)'); }
        $kp = sodium_crypto_sign_seed_keypair($seed);
        $this->seed = $seed;
        $this->publicKey = sodium_crypto_sign_publickey($kp);
        $this->secret = sodium_crypto_sign_secretkey($kp);
    }
    public static function fromHex(string $seedHex): self
    {
        if (!Encoding::isHex($seedHex, 64)) { throw new \InvalidArgumentException('Private key must be 64 hex characters (32 bytes)'); }
        return new self(hex2bin($seedHex));
    }
    public static function random(): self { return new self(random_bytes(32)); }

    /** The ZBC_ form of the public key. */
    public function address(): string { return Address::encode($this->publicKey, 'ZBC'); }
    /** The ZNK_ form of the same key. */
    public function nodeAddress(): string { return Address::encode($this->publicKey, 'ZNK'); }
    /** 36-byte typed account address: 00000000 || public key. */
    public function accountBytes(): string { return Address::typed(Address::ZOOBC, $this->publicKey); }
    /** Detached Ed25519 signature (64 bytes). */
    public function sign(string $message): string { return sodium_crypto_sign_detached($message, $this->secret); }

    /** Ed25519 verification that never throws. */
    public static function verify(string $message, string $signature, string $publicKey): bool
    {
        if (strlen($signature) !== 64 || strlen($publicKey) !== 32) { return false; }
        try { return sodium_crypto_sign_verify_detached($signature, $message, $publicKey); } catch (\SodiumException) { return false; }
    }
}
