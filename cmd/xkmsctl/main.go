// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

func main() {
	// Before anything constructs protected memory: a debugger or a same-user
	// process must not be able to read it through ptrace or /proc/<pid>/mem.
	if _, err := secure.HardenProcess(nil); err != nil {
		fmt.Fprintf(os.Stderr, "xkmsctl: process hardening: %v\n", err)
		os.Exit(1)
	}

	os.Exit(run(os.Stderr))
}

// run executes the command tree and prints the error the root command silences.
func run(stderr io.Writer) int {
	if err := Execute(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}
