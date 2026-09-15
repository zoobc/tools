<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** Parameter validation and the generic body serialiser driven by spec/transactions (encodings of index.json). */
final class Body
{
    public static function parseInteger(string $value, string $kind, string $name): int
    {
        $v = trim($value);
        if (!preg_match('/^-?\d+$/', $v)) { throw ToolError::usage("$name must be a whole number, got \"$value\""); }
        [$lo, $hi] = match ($kind) {
            'uint64' => ['0', '18446744073709551615'], 'uint32' => ['0', '4294967295'], 'uint8' => ['0', '255'],
            default => ['-9223372036854775808', '9223372036854775807'],
        };
        if (self::cmp($v, $lo) < 0 || self::cmp($v, $hi) > 0) { throw ToolError::usage("$name is out of range for $kind"); }
        if ($kind === 'uint64' && self::cmp($v, '9223372036854775807') > 0) {
            // two's complement wrap into PHP's int64, as pack('P') expects
            return (int) self::decSub($v, '18446744073709551616');
        }
        return (int) $v;
    }

    /** Compare two decimal integer strings without bcmath. */
    private static function cmp(string $a, string $b): int
    {
        $na = str_starts_with($a, '-'); $nb = str_starts_with($b, '-');
        if ($na !== $nb) { return $na ? -1 : 1; }
        $a = ltrim(ltrim($a, '-'), '0') ?: '0'; $b = ltrim(ltrim($b, '-'), '0') ?: '0';
        $c = strlen($a) <=> strlen($b) ?: strcmp($a, $b);
        return $na ? -$c : $c;
    }

    public static function splitList(string $s): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $s)), fn($x) => $x !== ''));
    }

    /** Check one value against its parameter kind; returns the value to keep. */
    public static function validateParam(array $p, string $value): string
    {
        switch ($p['kind']) {
            case 'privkey': if (!Encoding::isHex($value, 64)) { throw ToolError::usage("{$p['name']} must be 64 hex characters (a 32-byte private key)"); } break;
            case 'address': try { Address::parse($value); } catch (\InvalidArgumentException $e) { throw ToolError::usage("invalid {$p['name']}: {$e->getMessage()}"); } break;
            case 'address_list': foreach (self::splitList($value) as $a) { try { Address::parse($a); } catch (\InvalidArgumentException $e) { throw ToolError::usage("invalid {$p['name']} entry $a: {$e->getMessage()}"); } } break;
            case 'key': try { Address::parseKey32($value); } catch (\InvalidArgumentException $e) { throw ToolError::usage("invalid {$p['name']}: {$e->getMessage()}"); } break;
            case 'int64': case 'uint64': case 'uint32': case 'uint8':
                $n = self::parseInteger($value, $p['kind'], $p['name']);
                if ((isset($p['min']) && $n < $p['min']) || (isset($p['max']) && $n > $p['max'])) { throw ToolError::usage("{$p['name']} must be between " . ($p['min'] ?? '-inf') . ' and ' . ($p['max'] ?? 'inf')); }
                return trim($value);
            case 'hex32': if (!Encoding::isHex($value, 64)) { throw ToolError::usage("{$p['name']} must be 64 hex characters (32 bytes)"); } break;
            case 'hexbytes': if (!Encoding::isHex($value)) { throw ToolError::usage("{$p['name']} must be hex"); } break;
        }
        return $value;
    }

    private static function holds(string $when, array $params): bool
    {
        if (!preg_match("/^(\\w+) != (0|'')$/", $when, $m)) { throw ToolError::internal("unsupported condition $when"); }
        $v = $params[$m[1]] ?? '';
        return $m[2] === '0' ? ($v !== '' && (int) $v !== 0) : $v !== '';
    }

    private static function hexOrUsage(string $v, string $name): string
    {
        if (!Encoding::isHex($v)) { throw ToolError::usage("$name must be hex"); }
        return hex2bin($v);
    }

    private static function addr(string $v, string $name): ParsedAddress
    {
        try { return Address::parse($v); } catch (\InvalidArgumentException $e) { throw ToolError::usage("invalid $name: {$e->getMessage()}"); }
    }

    /** Serialise one body field. */
    public static function encodeField(array $f, array $params, BodyContext $ctx): string
    {
        if (isset($ctx->computed[$f['name']])) { return $ctx->computed[$f['name']]; }
        $value = $params[$f['from']] ?? '';
        if (isset($f['when_zero']) && ($value === '' || (int) $value <= 0)) { $value = $params[$f['when_zero']] ?? '0'; }
        switch ($f['encoding']) {
            case 'u8': return chr(self::parseInteger($value, 'uint8', $f['name']));
            case 'u16le': return Encoding::le16(self::parseInteger($value, 'uint32', $f['name']));
            case 'u32le': return Encoding::le32(self::parseInteger($value, 'uint32', $f['name']));
            case 'u64le': return Encoding::le64(self::parseInteger($value, 'int64', $f['name']));
            case 'hex':
                $b = self::hexOrUsage($value, $f['from']);
                if (isset($f['size']) && strlen($b) !== $f['size']) { throw ToolError::usage("{$f['from']} must be {$f['size']} bytes (" . (2 * $f['size']) . ' hex)'); }
                return $b;
            case 'hex16': $b = self::hexOrUsage($value, $f['from']); return Encoding::le16(strlen($b)) . $b;
            case 'bytes32': $b = $ctx->files[$f['from']] ?? self::hexOrUsage($value, $f['from']); return Encoding::le32(strlen($b)) . $b;
            case 'str16': return Encoding::le16(strlen($value)) . $value;
            case 'str32': return Encoding::le32(strlen($value)) . $value;
            case 'address': return self::addr($value, $f['from'])->bytes();
            case 'address_list': return implode('', array_map(fn($a) => self::addr($a, $f['from'])->bytes(), self::splitList($value)));
            case 'address_list8':
                $items = self::splitList($value);
                if (count($items) > 255) { throw ToolError::usage("{$f['from']}: at most 255 entries"); }
                return chr(count($items)) . implode('', array_map(fn($a) => self::addr($a, $f['from'])->bytes(), $items));
            case 'sender_address': return ($ctx->sender ?? throw ToolError::internal('no sender'))->accountBytes();
            case 'pubkey_of_key': try { return KeyPair::fromHex($value)->publicKey; } catch (\InvalidArgumentException) { throw ToolError::usage("{$f['from']} must be 64 hex characters (a 32-byte private key)"); }
            case 'key32': try { return Address::parseKey32($value); } catch (\InvalidArgumentException $e) { throw ToolError::usage("invalid {$f['from']}: {$e->getMessage()}"); }
            case 'literal': return hex2bin($f['value'] ?? '') ?: '';
            case 'custom': throw ToolError::internal("field {$f['name']} needs a custom hook");
        }
        throw ToolError::internal("unknown encoding {$f['encoding']}");
    }

    /** The whole body of a non-custom transaction. */
    public static function build(array $def, array $params, BodyContext $ctx): string
    {
        $out = '';
        foreach ($def['body'] as $f) {
            if (isset($f['when']) && !self::holds($f['when'], $params)) { continue; }
            $out .= self::encodeField($f, $params, $ctx);
        }
        return $out;
    }

    /** Decimal subtraction of two non-negative integer strings (a - b, a >= b) without bcmath. */
    private static function decSub(string $a, string $b): string
    {
        $a = str_pad($a, max(strlen($a), strlen($b)), '0', STR_PAD_LEFT); $b = str_pad($b, strlen($a), '0', STR_PAD_LEFT);
        $out = ''; $borrow = 0;
        for ($i = strlen($a) - 1; $i >= 0; $i--) {
            $d = (int) $a[$i] - (int) $b[$i] - $borrow;
            if ($d < 0) { $d += 10; $borrow = 1; } else { $borrow = 0; }
            $out = $d . $out;
        }
        $out = ltrim($out, '0');
        return $out === '' ? '0' : '-' . $out;
    }
}
