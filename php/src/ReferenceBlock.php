<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** The block a proof of ownership refers to. */
final class ReferenceBlock
{
    public function __construct(public readonly string $hash, public readonly int $height) {}
}
