# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Exit codes and error classes of spec/cli-contract.md section 5."""

OK, INTERNAL, USAGE, NODE_UNREACHABLE, INSUFFICIENT_BALANCE, FEE_TOO_LOW = 0, 1, 2, 3, 4, 5
REJECTED, NOT_FOUND, TIMEOUT, NODE_BUSY, VERIFY_FAILED = 6, 7, 8, 9, 10
NAMES = {0: "ok", 1: "internal", 2: "usage", 3: "node_unreachable", 4: "insufficient_balance", 5: "fee_too_low",
         6: "rejected", 7: "not_found", 8: "timeout", 9: "node_busy", 10: "verify_failed"}


def error_class(code: int) -> str:
    return NAMES.get(code, "internal")


class ToolError(Exception):
    """An error that carries its exit code; `extra` is merged into the JSON error object."""

    def __init__(self, code: int, message: str, **extra):
        super().__init__(message)
        self.code, self.message, self.extra = code, message, extra

    def to_json(self) -> dict:
        return {"success": False, "error": self.message, "exit_code": self.code, "error_class": error_class(self.code), **self.extra}


def usage(message: str) -> ToolError:
    return ToolError(USAGE, message)


def classify_node_error(http_code: int, text: str) -> int:
    """Classify a node's rejection into an exit code (spec/api.md section 2)."""
    if http_code == 0:
        return NODE_UNREACHABLE
    if http_code >= 500:
        return NODE_BUSY
    t = text.lower()
    if "fee too low" in t:
        return FEE_TOO_LOW
    if "insufficient balance" in t or "insufficient spendable" in t or "account does not exist" in t:
        return INSUFFICIENT_BALANCE
    if "not found" in t or "unknown token" in t or "unknown or expired token" in t or "unknown app" in t:
        return NOT_FOUND
    return REJECTED
