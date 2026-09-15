<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** ZBC-MSG-v1 message signing (spec/signing.md section 5). */
final class Message
{
    public const SCHEME = 'ZBC-MSG-v1';

    /** SHA3-256('ZBC-MSG' || message). */
    public static function digest(string $message): string { return Encoding::sha3('ZBC-MSG', $message); }

    /** Sign: returns scheme, address, public_key, message_hex, digest, signature. */
    public static function sign(KeyPair $kp, string $message): array
    {
        $d = self::digest($message);
        return ['scheme' => self::SCHEME, 'address' => $kp->address(), 'public_key' => bin2hex($kp->publicKey), 'message_hex' => bin2hex($message),
                'digest' => bin2hex($d), 'signature' => bin2hex($kp->sign($d))];
    }

    /** The public key behind a ZBC_ address or 64 hex, or null. */
    public static function publicKeyOf(string $address): ?string
    {
        if (Encoding::isHex($address, 64)) { return hex2bin($address); }
        $d = Address::decode($address);
        return ($d !== null && $d[0] === 'ZBC') ? $d[1] : null;
    }

    /** False for anything that does not verify; never throws. */
    public static function verify(string $address, string $message, string $signature): bool
    {
        $pub = self::publicKeyOf($address);
        return $pub !== null && KeyPair::verify(self::digest($message), $signature, $pub);
    }
}
