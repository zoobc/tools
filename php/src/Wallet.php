<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** BIP-39 mnemonics and SLIP-10 derivation along m/44'/883'/index'. */
final class Wallet
{
    public const ZOOBC_COIN_TYPE = 883;

    /** True for 12, 15, 18, 21 or 24 English words with a valid checksum. */
    public static function validateMnemonic(string $mnemonic): bool
    {
        $words = preg_split('/\s+/', trim($mnemonic));
        if (!in_array(count($words), [12, 15, 18, 21, 24], true)) { return false; }
        $bits = '';
        $index = array_flip(Bip39Words::WORDS);
        foreach ($words as $w) { if (!isset($index[$w])) { return false; } $bits .= str_pad(decbin($index[$w]), 11, '0', STR_PAD_LEFT); }
        $cs = intdiv(count($words), 3);
        $entropy = '';
        for ($i = 0; $i + 8 <= strlen($bits) - $cs; $i += 8) { $entropy .= chr(bindec(substr($bits, $i, 8))); }
        return substr($bits, -$cs) === substr(str_pad(decbin(ord(hash('sha256', $entropy, true)[0])), 8, '0', STR_PAD_LEFT), 0, $cs);
    }

    public static function mnemonicFromEntropy(string $entropy): string
    {
        $n = strlen($entropy);
        if ($n < 16 || $n > 32 || $n % 4 !== 0) { throw new \InvalidArgumentException('entropy must be 16-32 bytes, a multiple of 4'); }
        $bits = '';
        foreach (str_split($entropy) as $c) { $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT); }
        $bits .= substr(str_pad(decbin(ord(hash('sha256', $entropy, true)[0])), 8, '0', STR_PAD_LEFT), 0, intdiv($n, 4));
        $words = [];
        for ($i = 0; $i + 11 <= strlen($bits); $i += 11) { $words[] = Bip39Words::WORDS[bindec(substr($bits, $i, 11))]; }
        return implode(' ', $words);
    }

    public static function generateMnemonic(int $words = 24): string { return self::mnemonicFromEntropy(random_bytes(intdiv($words * 11 - intdiv($words, 3), 8))); }

    /** PBKDF2-HMAC-SHA512(mnemonic, 'mnemonic' + passphrase, 2048, 64). */
    public static function mnemonicToSeed(string $mnemonic, string $passphrase = ''): string
    {
        return hash_pbkdf2('sha512', implode(' ', preg_split('/\s+/', trim($mnemonic))), 'mnemonic' . $passphrase, 2048, 64, true);
    }

    /** SLIP-10 for Ed25519 along a hardened-only path such as m/44'/883'/0'; the 32-byte key. */
    public static function slip10Derive(string $path, string $seed): string
    {
        if (!preg_match("/^m(\\/[0-9]+')+$/", $path)) { throw new \InvalidArgumentException("invalid derivation path: $path"); }
        $digest = hash_hmac('sha512', $seed, 'ed25519 seed', true);
        $key = substr($digest, 0, 32); $chain = substr($digest, 32);
        foreach (array_slice(explode('/', $path), 1) as $seg) {
            $index = (int) substr($seg, 0, -1);
            if ($index >= 0x80000000) { throw new \InvalidArgumentException('path index too large'); }
            $digest = hash_hmac('sha512', "\0" . $key . pack('N', $index + 0x80000000), $chain, true);
            $key = substr($digest, 0, 32); $chain = substr($digest, 32);
        }
        return $key;
    }

    /** Account $index of a mnemonic wallet: m/44'/883'/index'. Returns [KeyPair, path]. */
    public static function account(string $mnemonic, int $index, string $passphrase = ''): array
    {
        $path = "m/44'/" . self::ZOOBC_COIN_TYPE . "'/$index'";
        return [new KeyPair(self::slip10Derive($path, self::mnemonicToSeed($mnemonic, $passphrase))), $path];
    }
}
