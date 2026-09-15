<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** Exit codes and error classes of spec/cli-contract.md section 5. */
final class ExitCode
{
    public const OK = 0, INTERNAL = 1, USAGE = 2, NODE_UNREACHABLE = 3, INSUFFICIENT_BALANCE = 4, FEE_TOO_LOW = 5;
    public const REJECTED = 6, NOT_FOUND = 7, TIMEOUT = 8, NODE_BUSY = 9, VERIFY_FAILED = 10;

    public static function errorClass(int $code): string
    {
        return [0 => 'ok', 2 => 'usage', 3 => 'node_unreachable', 4 => 'insufficient_balance', 5 => 'fee_too_low', 6 => 'rejected',
                7 => 'not_found', 8 => 'timeout', 9 => 'node_busy', 10 => 'verify_failed'][$code] ?? 'internal';
    }

    /** Classify a node's rejection into an exit code (spec/api.md section 2). */
    public static function classifyNodeError(int $httpCode, string $text): int
    {
        if ($httpCode === 0) { return self::NODE_UNREACHABLE; }
        if ($httpCode >= 500) { return self::NODE_BUSY; }
        $t = strtolower($text);
        if (str_contains($t, 'fee too low')) { return self::FEE_TOO_LOW; }
        if (str_contains($t, 'insufficient balance') || str_contains($t, 'insufficient spendable') || str_contains($t, 'account does not exist')) { return self::INSUFFICIENT_BALANCE; }
        if (str_contains($t, 'not found') || str_contains($t, 'unknown token') || str_contains($t, 'unknown or expired token') || str_contains($t, 'unknown app')) { return self::NOT_FOUND; }
        return self::REJECTED;
    }
}
