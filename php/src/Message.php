<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/**
 * ZBC-MSG-v2 message signing (spec/signing.md section 5a): the digest binds the message to one chain,
 *   digest = SHA3-256('ZBC-MSG-v2' || genesis_hash (32) || message), signature = Ed25519(seed, digest).
 * ZBC-MSG-v1 (section 5, SHA3-256('ZBC-MSG' || message)) is still verified until V1_SUNSET, never produced.
 */
final class Message
{
    public const SCHEME = 'ZBC-MSG-v2';
    public const SCHEME_V1 = 'ZBC-MSG-v1';
    /** 2026-12-01T00:00:00Z: v1 signatures are refused from here on. */
    public const V1_SUNSET = 1796083200;

    /** The legacy v1 digest: SHA3-256('ZBC-MSG' || message). */
    public static function digest(string $message): string { return Encoding::sha3('ZBC-MSG', $message); }

    /** The v2 digest; $genesisHash is the chain's genesis block hash, 32 raw bytes. */
    public static function digestV2(string $message, string $genesisHash): string
    {
        if (strlen($genesisHash) !== 32) { throw new \InvalidArgumentException("ZBC-MSG-v2 needs the chain's genesis hash (32 bytes)"); }
        return Encoding::sha3('ZBC-MSG-v2', $genesisHash, $message);
    }

    /** Sign for one chain: returns scheme, genesis_hash, address, public_key, message_hex, digest, signature. */
    public static function sign(KeyPair $kp, string $message, string $genesisHash): array
    {
        $d = self::digestV2($message, $genesisHash);
        return ['scheme' => self::SCHEME, 'genesis_hash' => bin2hex($genesisHash), 'address' => $kp->address(), 'public_key' => bin2hex($kp->publicKey),
                'message_hex' => bin2hex($message), 'digest' => bin2hex($d), 'signature' => bin2hex($kp->sign($d))];
    }

    /** The public key behind a ZBC_ address or 64 hex, or null. */
    public static function publicKeyOf(string $address): ?string
    {
        if (Encoding::isHex($address, 64)) { return hex2bin($address); }
        $d = Address::decode($address);
        return ($d !== null && $d[0] === 'ZBC') ? $d[1] : null;
    }

    /**
     * The scheme the signature verifies under: SCHEME when $genesisHash (32 bytes) is given and the v2 digest verifies,
     * else SCHEME_V1 while $now (default: the clock) is before V1_SUNSET; null for anything else, never throws.
     */
    public static function verify(string $address, string $message, string $signature, ?string $genesisHash = null, ?int $now = null): ?string
    {
        $pub = self::publicKeyOf($address);
        if ($pub === null || strlen($signature) !== 64) { return null; }
        if ($genesisHash !== null && strlen($genesisHash) === 32 && KeyPair::verify(self::digestV2($message, $genesisHash), $signature, $pub)) { return self::SCHEME; }
        if (($now ?? time()) < self::V1_SUNSET && KeyPair::verify(self::digest($message), $signature, $pub)) { return self::SCHEME_V1; }
        return null;
    }
}
