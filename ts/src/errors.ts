// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** Exit codes and error classes of spec/cli-contract.md section 5. */

export const ExitCode = {
  ok: 0, internal: 1, usage: 2, node_unreachable: 3, insufficient_balance: 4, fee_too_low: 5,
  rejected: 6, not_found: 7, timeout: 8, node_busy: 9, verify_failed: 10,
} as const;
export type ErrorClass = keyof typeof ExitCode;

export function errorClassOf(code: number): ErrorClass {
  for (const [k, v] of Object.entries(ExitCode)) if (v === code) return k as ErrorClass;
  return "internal";
}

/** An error that carries its exit code; `extra` is merged into the JSON error object. */
export class ToolError extends Error {
  readonly code: number;
  readonly extra: Record<string, unknown>;
  constructor(code: number, message: string, extra: Record<string, unknown> = {}) {
    super(message);
    this.code = code;
    this.extra = extra;
  }
  get errorClass(): ErrorClass { return errorClassOf(this.code); }
  toJSON(): Record<string, unknown> {
    return { success: false, error: this.message, exit_code: this.code, error_class: this.errorClass, ...this.extra };
  }
}
export const usage = (msg: string): ToolError => new ToolError(ExitCode.usage, msg);

/** Classify a node's rejection text into an exit code (spec/api.md section 2). */
export function classifyNodeError(httpCode: number, text: string): number {
  if (httpCode === 0) return ExitCode.node_unreachable;
  if (httpCode >= 500) return ExitCode.node_busy;
  const t = text.toLowerCase();
  if (t.includes("fee too low")) return ExitCode.fee_too_low;
  if (t.includes("insufficient balance") || t.includes("insufficient spendable") || t.includes("account does not exist")) return ExitCode.insufficient_balance;
  if (t.includes("not found") || t.includes("unknown token") || t.includes("unknown or expired token") || t.includes("unknown app")) return ExitCode.not_found;
  return ExitCode.rejected;
}
