// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
/** JSON with exact integers: a bigint is written as a bare number, however large (amounts and fees are int64). */
const MARK = "~bigint~";
export function stringifyJson(value: unknown, indent?: number): string {
  const text = JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? MARK + v.toString() + MARK : v), indent);
  return text.replace(/"~bigint~(-?\d+)~bigint~"/g, "$1");
}
/** Parse JSON keeping integers beyond 2^53 exact (as bigint); other numbers stay numbers. */
export function parseJson(text: string): unknown {
  const marked = text.replace(/(:\s*|\[\s*|,\s*)(-?\d{16,})(?=\s*[,}\]])/g, (_m, pre, num) => `${pre}"${MARK}${num}${MARK}"`);
  return JSON.parse(marked, (_k, v) => (typeof v === "string" && v.startsWith(MARK) ? BigInt(v.slice(MARK.length, -MARK.length)) : v));
}
