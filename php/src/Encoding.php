<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** Hex, base32 (no padding), base58/base58check (Bitcoin and Ripple alphabets), bech32/bech32m, SS58, little-endian integers. */
final class Encoding
{
    public const BITCOIN_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    public const RIPPLE_ALPHABET = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
    private const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    private const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    public static function isHex(string $s, int $n = 0): bool
    {
        return strlen($s) % 2 === 0 && ($n <= 0 || strlen($s) === $n) && ctype_xdigit($s === '' ? '0' : $s);
    }

    public static function sha3(string ...$parts): string { return hash('sha3-256', implode('', $parts), true); }

    public static function le16(int $v): string { return pack('v', $v & 0xffff); }
    public static function le32(int $v): string { return pack('V', $v & 0xffffffff); }
    /** int64 as 8 bytes LE (two's complement). */
    public static function le64(int $v): string { return pack('P', $v); }
    public static function readLe64(string $b, int $off): int { return unpack('q', substr($b, $off, 8))[1]; }

    public static function base32Encode(string $data): string
    {
        $out = ''; $buf = 0; $bits = 0;
        foreach (str_split($data) as $c) {
            $buf = (($buf << 8) | ord($c)) & 0x1fff; $bits += 8;
            while ($bits >= 5) { $bits -= 5; $out .= self::B32[($buf >> $bits) & 31]; }
        }
        if ($bits > 0) { $out .= self::B32[($buf << (5 - $bits)) & 31]; }
        return $out;
    }

    public static function base32Decode(string $s): ?string
    {
        $out = ''; $buf = 0; $bits = 0;
        foreach (str_split($s) as $c) {
            $v = strpos(self::B32, $c); if ($v === false) { return null; }
            $buf = (($buf << 5) | $v) & 0x1fff; $bits += 5;
            if ($bits >= 8) { $bits -= 8; $out .= chr(($buf >> $bits) & 0xff); }
        }
        return $out;
    }

    public static function base58Decode(string $s, string $alphabet = self::BITCOIN_ALPHABET): ?string
    {
        $big = [];   // little-endian base-256 digits
        foreach (str_split($s === '' ? '' : $s) as $c) {
            $carry = strpos($alphabet, $c); if ($carry === false) { return null; }
            foreach ($big as $i => $d) { $v = $d * 58 + $carry; $big[$i] = $v & 0xff; $carry = $v >> 8; }
            while ($carry > 0) { $big[] = $carry & 0xff; $carry >>= 8; }
        }
        $zeros = strlen($s) - strlen(ltrim($s, $alphabet[0]));
        return str_repeat("\0", $zeros) . implode('', array_map('chr', array_reverse($big)));
    }

    public static function base58Encode(string $data, string $alphabet = self::BITCOIN_ALPHABET): string
    {
        $digits = [];
        foreach (str_split($data) as $c) {
            $carry = ord($c);
            foreach ($digits as $i => $d) { $v = ($d << 8) + $carry; $digits[$i] = $v % 58; $carry = intdiv($v, 58); }
            while ($carry > 0) { $digits[] = $carry % 58; $carry = intdiv($carry, 58); }
        }
        $zeros = strlen($data) - strlen(ltrim($data, "\0"));
        $out = str_repeat($alphabet[0], $zeros);
        foreach (array_reverse($digits) as $d) { $out .= $alphabet[$d]; }
        return $out;
    }

    /** The payload without its 4-byte SHA-256d checksum, or null. */
    public static function base58CheckDecode(string $s, string $alphabet = self::BITCOIN_ALPHABET): ?string
    {
        $raw = self::base58Decode($s, $alphabet);
        if ($raw === null || strlen($raw) < 5) { return null; }
        $body = substr($raw, 0, -4);
        return substr(hash('sha256', hash('sha256', $body, true), true), 0, 4) === substr($raw, -4) ? $body : null;
    }

    private static function polymod(array $values): int
    {
        $chk = 1;
        foreach ($values as $v) {
            $b = $chk >> 25; $chk = (($chk & 0x1ffffff) << 5) ^ $v;
            for ($i = 0; $i < 5; $i++) { if (($b >> $i) & 1) { $chk ^= self::GEN[$i]; } }
        }
        return $chk;
    }

    private static function hrpExpand(string $hrp): array
    {
        $out = [];
        foreach (str_split($hrp) as $c) { $out[] = ord($c) >> 5; }
        $out[] = 0;
        foreach (str_split($hrp) as $c) { $out[] = ord($c) & 31; }
        return $out;
    }

    /** [hrp, 5-bit data without checksum, 'bech32'|'bech32m'], or null. */
    public static function bech32DecodeRaw(string $s): ?array
    {
        if (strlen($s) > 1023 || (strtolower($s) !== $s && strtoupper($s) !== $s)) { return null; }
        $low = strtolower($s); $pos = strrpos($low, '1');
        if ($pos === false || $pos < 1 || $pos + 7 > strlen($low)) { return null; }
        $hrp = substr($low, 0, $pos); $data = [];
        foreach (str_split(substr($low, $pos + 1)) as $c) { $v = strpos(self::CHARSET, $c); if ($v === false) { return null; } $data[] = $v; }
        $pm = self::polymod(array_merge(self::hrpExpand($hrp), $data));
        $enc = $pm === 1 ? 'bech32' : ($pm === 0x2bc830a3 ? 'bech32m' : null);
        if ($enc === null) { return null; }
        return [$hrp, array_slice($data, 0, -6), $enc];
    }

    public static function convertBits(array $data, int $from, int $to, bool $pad): ?array
    {
        $acc = 0; $bits = 0; $out = []; $maxv = (1 << $to) - 1;
        foreach ($data as $v) {
            if ($v < 0 || ($v >> $from) !== 0) { return null; }
            $acc = ($acc << $from) | $v; $bits += $from;
            while ($bits >= $to) { $bits -= $to; $out[] = ($acc >> $bits) & $maxv; }
        }
        if ($pad) { if ($bits > 0) { $out[] = ($acc << ($to - $bits)) & $maxv; } }
        elseif ($bits >= $from || (($acc << ($to - $bits)) & $maxv) !== 0) { return null; }
        return $out;
    }

    /** [hrp, witness version, program] of a segwit address, or null. */
    public static function segwitDecode(string $s): ?array
    {
        $d = self::bech32DecodeRaw($s);
        if ($d === null || count($d[1]) === 0) { return null; }
        [$hrp, $data, $enc] = $d;
        $version = $data[0];
        $prog = self::convertBits(array_slice($data, 1), 5, 8, false);
        if ($prog === null || count($prog) < 2 || count($prog) > 40 || $version > 16) { return null; }
        if ($version === 0 && count($prog) !== 20 && count($prog) !== 32) { return null; }
        if (($version === 0) !== ($enc === 'bech32')) { return null; }
        return [$hrp, $version, implode('', array_map('chr', $prog))];
    }

    /** Plain bech32 with an 8-bit payload (Cardano addresses): [hrp, bytes] or null. */
    public static function bech32DecodePlain(string $s): ?array
    {
        $d = self::bech32DecodeRaw($s);
        if ($d === null || $d[2] !== 'bech32') { return null; }
        $b = self::convertBits($d[1], 5, 8, false);
        return $b === null ? null : [$d[0], implode('', array_map('chr', $b))];
    }

    /** [prefix, 32-byte account id] of an SS58 address; checksum = BLAKE2b-512('SS58PRE' || body)[0..1]. */
    public static function ss58Decode(string $s): ?array
    {
        $raw = self::base58Decode($s);
        if ($raw === null || $raw === '') { return null; }
        $r0 = ord($raw[0]);
        if (strlen($raw) >= 35 && $r0 < 64) { $plen = 1; $prefix = $r0; }
        elseif (strlen($raw) >= 36 && $r0 >= 64 && $r0 < 128) { $plen = 2; $prefix = (($r0 & 0x3f) << 2) | (ord($raw[1]) >> 6) | ((ord($raw[1]) & 0x3f) << 8); }
        else { return null; }
        $body = substr($raw, 0, -2);
        if (strlen($body) - $plen !== 32) { return null; }
        $sum = sodium_crypto_generichash('SS58PRE' . $body, '', 64);
        if ($sum[0] !== $raw[-2] || $sum[1] !== $raw[-1]) { return null; }
        return [$prefix, substr($body, $plen)];
    }
}
