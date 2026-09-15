<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** Where a run reads and writes; tests pass buffers, bin/zbc-cli the real streams. */
final class Io
{
    /** @param callable(): string $stdin  @param callable(string): void $stdout  @param callable(string): void $stderr  @param callable(string): ?string $env */
    public function __construct(public $stdin, public $stdout, public $stderr, public $env, public bool $isTty) {}
}
