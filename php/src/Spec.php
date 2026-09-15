<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** The transaction descriptions of spec/transactions, embedded by bin/gen-commands.php into commands_gen.php. */
final class Spec
{
    private static ?array $commands = null;
    private static ?array $byName = null;

    /** @return array<int, array> every description, in command order */
    public static function commands(): array
    {
        if (self::$commands === null) {
            self::$commands = require __DIR__ . '/commands_gen.php';
            self::$byName = array_column(self::$commands, null, 'command');
        }
        return self::$commands;
    }

    public static function command(string $name): ?array
    {
        self::commands();
        return self::$byName[$name] ?? null;
    }
}
