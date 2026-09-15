// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

// Command zbc-cli is every ZooBC transaction as a subcommand, plus sign-message and verify-message.
package main

import (
	"os"

	"github.com/zoobc/tools/go/cli"
)

func main() { os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
