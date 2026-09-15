<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** A built, signed and hashed transaction. */
final class SignedTransaction
{
    public function __construct(public readonly string $unsigned, public readonly string $digest, public readonly string $signature, public readonly string $bytes,
                                public readonly string $hash, public readonly array $payload, public readonly int $signingVersion, public readonly string $genesisHash) {}
}
