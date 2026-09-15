<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** Which chain a signature is for: version 2 with its genesis hash, or 1 (legacy). */
final class SigningContext
{
    public function __construct(public readonly int $version, public readonly string $genesisHash = '') {}
    /** Reads --genesis: 64 hex, or 'v1'/'legacy'. */
    public static function of(string $genesis): self
    {
        if ($genesis === 'v1' || $genesis === 'legacy') { return new self(1); }
        if (!Encoding::isHex($genesis, 64)) { throw new \InvalidArgumentException("--genesis must be the 64-hex genesis block hash (or 'v1' for the legacy digest)"); }
        return new self(2, hex2bin($genesis));
    }
}
