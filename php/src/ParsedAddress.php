<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** A recipient as the envelope carries it. */
final class ParsedAddress
{
    public function __construct(public readonly int $type, public readonly string $payload, public readonly string $display) {}
    /** 4-byte type LE then the payload (36 bytes for a ZooBC account). */
    public function bytes(): string { return Address::typed($this->type, $this->payload); }
    public function typeName(): string { return Address::typeName($this->type); }
}
