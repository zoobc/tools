// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** The shape of spec/transactions/*.json, as embedded by scripts/gen-commands.mjs into generated/commands.ts. */

export interface ParamDef { name: string; kind: string; required: boolean; default?: string; help: string; min?: number; max?: number }
export interface FieldDef {
  name: string; encoding: string; from: string;
  size?: number; value?: string; when?: string; computed?: string; default_from?: string; when_zero?: string;
}
export interface TxDef {
  name: string; type: number; command: string; binary: string | null; description: string;
  sender_key: string; recipient: "required" | "none"; options: string[]; needs_node: boolean; custom: string | null;
  params: ParamDef[]; body: FieldDef[]; example: Record<string, string>; notes: string[];
}
