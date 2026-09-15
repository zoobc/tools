<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** One HTTP answer. */
final class Reply
{
    public function __construct(public readonly int $status, public readonly string $text, public readonly mixed $json) {}
    public function body(): mixed { return $this->json ?? $this->text; }
}
