<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** What the generic serialiser cannot read from the parameters. */
final class BodyContext
{
    public function __construct(public ?KeyPair $sender = null, public array $files = [], public array $computed = []) {}
}
