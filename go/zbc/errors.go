// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"fmt"
	"strings"
)

// Exit codes of spec/cli-contract.md section 5.
const (
	ExitOK                  = 0
	ExitInternal            = 1
	ExitUsage               = 2
	ExitNodeUnreachable     = 3
	ExitInsufficientBalance = 4
	ExitFeeTooLow           = 5
	ExitRejected            = 6
	ExitNotFound            = 7
	ExitTimeout             = 8
	ExitNodeBusy            = 9
	ExitVerifyFailed        = 10
)

var exitNames = map[int]string{0: "ok", 1: "internal", 2: "usage", 3: "node_unreachable", 4: "insufficient_balance",
	5: "fee_too_low", 6: "rejected", 7: "not_found", 8: "timeout", 9: "node_busy", 10: "verify_failed"}

// ErrorClass is the contract's name of an exit code.
func ErrorClass(code int) string {
	if n, ok := exitNames[code]; ok {
		return n
	}
	return "internal"
}

// ToolError carries its exit code; Extra is merged into the JSON error object.
type ToolError struct {
	Code    int
	Message string
	Extra   map[string]any
}

func (e *ToolError) Error() string { return e.Message }

// JSON is the error object of the contract (section 4).
func (e *ToolError) JSON() map[string]any {
	out := map[string]any{"success": false, "error": e.Message, "exit_code": e.Code, "error_class": ErrorClass(e.Code)}
	for k, v := range e.Extra {
		out[k] = v
	}
	return out
}

// Usage is a usage error (exit 2).
func Usage(format string, a ...any) *ToolError {
	return &ToolError{Code: ExitUsage, Message: fmt.Sprintf(format, a...)}
}

// Internal is an internal error (exit 1).
func Internal(format string, a ...any) *ToolError {
	return &ToolError{Code: ExitInternal, Message: fmt.Sprintf(format, a...)}
}

// ClassifyNodeError maps a node's rejection to an exit code (spec/api.md section 2).
func ClassifyNodeError(httpCode int, text string) int {
	if httpCode == 0 {
		return ExitNodeUnreachable
	}
	if httpCode >= 500 {
		return ExitNodeBusy
	}
	t := strings.ToLower(text)
	switch {
	case strings.Contains(t, "fee too low"):
		return ExitFeeTooLow
	case strings.Contains(t, "insufficient balance"), strings.Contains(t, "insufficient spendable"), strings.Contains(t, "account does not exist"):
		return ExitInsufficientBalance
	case strings.Contains(t, "not found"), strings.Contains(t, "unknown token"), strings.Contains(t, "unknown or expired token"), strings.Contains(t, "unknown app"):
		return ExitNotFound
	}
	return ExitRejected
}
