<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** A recipient as the envelope carries it. */
final class ParsedAddress
{
    /** $label: set by the fallback reading, which names the type its own way ("ETH (compact)", "ZBC", ...). */
    public function __construct(public readonly int $type, public readonly string $payload, public readonly string $display, public readonly ?string $label = null) {}
    /** 4-byte type LE then the payload (36 bytes for a ZooBC account). */
    public function bytes(): string { return Address::typed($this->type, $this->payload); }
    /** The recipient_type the tools print: the account type's name, or the fallback reading's label. */
    public function typeName(): string { return $this->label ?? Address::typeName($this->type); }
}
