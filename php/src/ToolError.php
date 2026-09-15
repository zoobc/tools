<?php
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
declare(strict_types=1);

namespace Zoobc\Zbc;

/** An error that carries its exit code; $extra is merged into the JSON error object. */
final class ToolError extends \Exception
{
    public function __construct(int $code, string $message, public readonly array $extra = [])
    {
        parent::__construct($message, $code);
    }
    public static function usage(string $message): self { return new self(ExitCode::USAGE, $message); }
    public static function internal(string $message): self { return new self(ExitCode::INTERNAL, $message); }
    /** The JSON error object of the contract (section 4). */
    public function toArray(): array
    {
        return ['success' => false, 'error' => $this->getMessage(), 'exit_code' => $this->getCode(), 'error_class' => ExitCode::errorClass($this->getCode())] + $this->extra;
    }
}
