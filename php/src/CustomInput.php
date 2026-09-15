<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** What the hand-written parts need. */
final class CustomInput
{
    public function __construct(public readonly array $def, public readonly array $params, public readonly KeyPair $sender, public readonly SigningContext $ctx,
                                public readonly int $timestamp, public readonly ?ReferenceBlock $block = null) {}
}
