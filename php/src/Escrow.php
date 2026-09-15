<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** Escrow terms of a transfer (the --escrow-* options); $timeout is an absolute Unix time in seconds. */
final class Escrow
{
    public function __construct(public readonly string $approver, public readonly int $commission = 0, public readonly int $timeout = 0, public readonly string $instruction = '') {}
    /** The escrow block of the envelope (spec/signing.md section 3). */
    public function bytes(): string
    {
        return Address::parse($this->approver)->bytes() . Encoding::le64($this->commission) . Encoding::le64($this->timeout)
            . Encoding::le32(strlen($this->instruction)) . $this->instruction . "\0";
    }
    /** The escrow object of the submit payload. */
    public function payload(): array
    {
        $m = ['approver_address' => bin2hex(Address::parse($this->approver)->bytes()), 'commission' => $this->commission, 'timeout' => $this->timeout];
        if ($this->instruction !== '') { $m['instruction'] = $this->instruction; }
        return $m;
    }
}
