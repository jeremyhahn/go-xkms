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

	if err := Execute(); err != nil {
		os.Exit(1)
	}
}
