<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** Account types, the ZBC_/ZNK_/ZBS_ text form and every recipient form of spec/addresses.md. */
final class Address
{
    public const ZOOBC = 0, BITCOIN = 1, EMPTY = 2, ESTONIA_EID = 3, ETHEREUM = 4, BITCOIN_P2PKH = 5, BITCOIN_P2SH = 6, BITCOIN_P2WPKH = 7;
    public const BITCOIN_P2WSH = 8, BITCOIN_TAPROOT = 9, DATASET = 10, SOLANA = 11, POLKADOT = 12, CARDANO = 13, RIPPLE = 14, TRON = 15, TEZOS = 16;
    private const NAMES = [0 => 'ZooBC', 1 => 'Bitcoin', 3 => 'Estonia eID', 4 => 'Ethereum', 5 => 'Bitcoin P2PKH', 6 => 'Bitcoin P2SH', 7 => 'Bitcoin P2WPKH',
        8 => 'Bitcoin P2WSH', 9 => 'Bitcoin Taproot', 10 => 'DataSet', 11 => 'Solana', 12 => 'Polkadot', 13 => 'Cardano', 14 => 'Ripple', 15 => 'Tron', 16 => 'Tezos'];
    private const CHAINS = ['zbc' => 'zbc', 'zoobc' => 'zbc', 'btc' => 'btc', 'bitcoin' => 'btc', 'eth' => 'eth', 'ethereum' => 'eth', 'evm' => 'eth',
        'sol' => 'sol', 'solana' => 'sol', 'dot' => 'dot', 'polkadot' => 'dot', 'substrate' => 'dot', 'ada' => 'ada', 'cardano' => 'ada',
        'xrp' => 'xrp', 'ripple' => 'xrp', 'trx' => 'trx', 'tron' => 'trx', 'xtz' => 'xtz', 'tezos' => 'xtz', 'zbs' => 'zbs', 'dataset' => 'zbs'];

    public static function typeName(int $t): string { return self::NAMES[$t] ?? "type $t"; }
    public static function typed(int $t, string $payload): string { return Encoding::le32($t) . $payload; }

    /** PREFIX_ + base32(payload || SHA3-256(payload || prefix)[0..2]) in seven groups of eight. */
    public static function encode(string $payload, string $prefix = 'ZBC'): string
    {
        if (strlen($payload) !== 32 || strlen($prefix) !== 3) { throw new \InvalidArgumentException('address payload must be 32 bytes and the prefix 3 characters'); }
        $s = Encoding::base32Encode($payload . substr(Encoding::sha3($payload, $prefix), 0, 3));
        $out = $prefix;
        for ($i = 0; $i < 7; $i++) { $out .= '_' . substr($s, 8 * $i, 8); }
        return $out;
    }

    /** [upper-case prefix, 32-byte payload] of PREFIX_... (separators _ or -, any case), or null. */
    /** The 59 significant characters of a ZooBC address: separators (_ -) and whitespace dropped, upper case (addresses.md 2). */
    public static function significant(string $text): string
    {
        return strtoupper((string) preg_replace('/[-_\s]/', '', $text));
    }

    /** [upper-case prefix, 32-byte payload] of a ZooBC address in any spelling, or null. */
    public static function decode(string $text): ?array
    {
        $norm = self::significant($text);
        if (strlen($norm) < 3) { return null; }
        $prefix = substr($norm, 0, 3);
        $body = substr($norm, 3);
        if (strlen($body) !== 56) { return null; }
        $raw = Encoding::base32Decode($body);
        if ($raw === null || strlen($raw) !== 35) { return null; }
        $payload = substr($raw, 0, 32);
        return substr(Encoding::sha3($payload, $prefix), 0, 3) === substr($raw, 32) ? [$prefix, $payload] : null;
    }

    /** Shape only: PREFIX then a separator, or the bare form: 59 significant characters, ZBC/ZBS prefix, base32 body. */
    private static function looksZbc(string $a): bool
    {
        if (strlen($a) > 4 && ($a[3] === '_' || $a[3] === '-')) { return true; }
        $n = self::significant($a);
        return strlen($n) === 59 && (str_starts_with($n, 'ZBC') || str_starts_with($n, 'ZBS')) && preg_match('/^[A-Z2-7]{56}$/', substr($n, 3)) === 1;
    }

    private static function zbcForm(string $a): ParsedAddress
    {
        $d = self::decode($a);
        if ($d === null) { throw new \InvalidArgumentException('invalid ZooBC address checksum'); }
        return new ParsedAddress($d[0] === 'ZBS' ? self::DATASET : self::ZOOBC, $d[1], $a);
    }

    private static function hinted(string $a, string $hint): ParsedAddress
    {
        switch ($hint) {
            case 'eth':
                $h = preg_replace('/^0[xX]/', '', $a);
                if (!Encoding::isHex($h, 40)) { throw new \InvalidArgumentException('not a 20-byte Ethereum address'); }
                return new ParsedAddress(self::ETHEREUM, hex2bin($h), $a);
            case 'sol':
                $d = Encoding::base58Decode($a);
                if ($d === null || strlen($d) !== 32) { throw new \InvalidArgumentException('not a 32-byte Solana address'); }
                return new ParsedAddress(self::SOLANA, $d, $a);
            case 'dot':
                $ss = Encoding::ss58Decode($a);
                if ($ss === null) { throw new \InvalidArgumentException('not a valid SS58 address'); }
                return new ParsedAddress(self::POLKADOT, $ss[1], $a);
            case 'zbc': case 'zbs':
                return self::zbcForm($a);
        }
        return self::auto($a);
    }

    private static function auto(string $a): ParsedAddress
    {
        if (strlen($a) === 42 && preg_match('/^0[xX]/', $a) && Encoding::isHex(substr($a, 2), 40)) { return new ParsedAddress(self::ETHEREUM, hex2bin(substr($a, 2)), $a); }
        if (self::looksZbc($a)) { return self::zbcForm($a); }
        $low5 = strtolower(substr($a, 0, 5));
        if (str_starts_with($low5, 'bc1') || str_starts_with($low5, 'tb1') || str_starts_with($low5, 'bcrt1')) {
            $d = Encoding::segwitDecode($a);
            if ($d === null) { throw new \InvalidArgumentException('invalid Bitcoin bech32 address'); }
            [, $version, $prog] = $d;
            if ($version === 0 && strlen($prog) === 20) { return new ParsedAddress(self::BITCOIN_P2WPKH, $prog, $a); }
            if ($version === 0 && strlen($prog) === 32) { return new ParsedAddress(self::BITCOIN_P2WSH, $prog, $a); }
            if ($version === 1 && strlen($prog) === 32) { return new ParsedAddress(self::BITCOIN_TAPROOT, $prog, $a); }
            throw new \InvalidArgumentException('unsupported Bitcoin witness program');
        }
        if (($a[0] === '1' || $a[0] === '3') && strlen($a) >= 26 && strlen($a) <= 35) {
            $raw = Encoding::base58Decode($a);
            if ($raw !== null && strlen($raw) === 25) {
                $body = Encoding::base58CheckDecode($a);
                if ($body !== null && strlen($body) === 21) {
                    if ($body[0] === "\x00") { return new ParsedAddress(self::BITCOIN_P2PKH, substr($body, 1), $a); }
                    if ($body[0] === "\x05") { return new ParsedAddress(self::BITCOIN_P2SH, substr($body, 1), $a); }
                }
            }
        }
        if (strlen($a) > 5 && strtolower(substr($a, 0, 5)) === 'addr1') {
            $d = Encoding::bech32DecodePlain($a);
            if ($d !== null && $d[0] === 'addr' && strlen($d[1]) === 29 && $d[1][0] === "\x61") { return new ParsedAddress(self::CARDANO, substr($d[1], 1), $a); }
            throw new \InvalidArgumentException('invalid Cardano address (expected a mainnet enterprise addr1… address)');
        }
        if ($a[0] === 'T' && strlen($a) === 34) {
            $body = Encoding::base58CheckDecode($a);
            if ($body !== null && strlen($body) === 21 && $body[0] === "\x41") { return new ParsedAddress(self::TRON, substr($body, 1), $a); }
            throw new \InvalidArgumentException('invalid Tron address');
        }
        if ($a[0] === 'r' && strlen($a) >= 25 && strlen($a) <= 35) {
            $body = Encoding::base58CheckDecode($a, Encoding::RIPPLE_ALPHABET);
            if ($body !== null && strlen($body) === 21 && $body[0] === "\x00") { return new ParsedAddress(self::RIPPLE, substr($body, 1), $a); }
            throw new \InvalidArgumentException('invalid Ripple address');
        }
        if (str_starts_with($a, 'tz1')) {
            $body = Encoding::base58CheckDecode($a);
            if ($body !== null && strlen($body) === 23 && substr($body, 0, 3) === "\x06\xa1\x9f") { return new ParsedAddress(self::TEZOS, substr($body, 3), $a); }
            throw new \InvalidArgumentException('invalid Tezos address');
        }
        $ss = Encoding::ss58Decode($a);
        if ($ss !== null && strlen($ss[1]) === 32) { return new ParsedAddress(self::POLKADOT, $ss[1], $a); }
        if (strlen($a) >= 32 && strlen($a) <= 44) {
            $d = Encoding::base58Decode($a);
            if ($d !== null && strlen($d) === 32) { return new ParsedAddress(self::SOLANA, $d, $a); }
        }
        if (Encoding::isHex($a, 64)) { $key = hex2bin($a); return new ParsedAddress(self::ZOOBC, $key, self::encode($key, 'ZBC')); }
        throw new \InvalidArgumentException('unrecognised address. Supported: ZooBC (ZBC_/ZBS_), Bitcoin, Ethereum, Solana, Polkadot, Cardano, Ripple, Tron, Tezos');
    }

    /** Read a recipient in the order of spec/addresses.md section 3; $chain forces one reading (--chain). Throws InvalidArgumentException. */
    public static function parse(string $text, string $chain = ''): ParsedAddress
    {
        $a = trim($text);
        if ($a === '') { throw new \InvalidArgumentException('empty address'); }
        if ($chain === '') { return self::auto($a); }
        $hint = self::CHAINS[strtolower($chain)] ?? throw new \InvalidArgumentException("unknown chain $chain");
        try { return self::hinted($a, $hint); } catch (\InvalidArgumentException $e) {
            $up = strtoupper($a); $low = strtolower($a);
            $plain = (strlen($a) === 42 && preg_match('/^0[xX]/', $a)) || str_starts_with($up, 'ZBC') || str_starts_with($up, 'ZNK') || str_starts_with($up, 'ZBS')
                || $a[0] === '1' || $a[0] === '3' || str_starts_with($low, 'bc1') || str_starts_with($low, 'tb1') || str_starts_with($low, 'bcrt1') || strlen($a) === 64;
            if (!$plain) { throw $e; }
            return self::auto($a);
        }
    }

    /** A registry key parameter: 64 hex (optionally 0x) or a ZNK_/ZBG_/ZBR_/ZBC_ text address; 32 bytes. */
    public static function parseKey32(string $text): string
    {
        if (strlen($text) === 66 && $text[3] === '_') {
            $d = self::decode($text);
            if ($d === null) { throw new \InvalidArgumentException('invalid address checksum'); }
            return $d[1];
        }
        $h = preg_replace('/^0[xX]/', '', $text);
        if (!Encoding::isHex($h, 64)) { throw new \InvalidArgumentException('key must be a 64-hex string or a ZNK_/ZBG_/ZBR_ address'); }
        return hex2bin($h);
    }
}
