// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// pin_test.go exercises PINStoreNotFoundError only through errors.As,
// asserting on its Dir field; it never renders the error's own message.
// This file closes that gap: it is the CLI text a user actually sees when a
// pin subcommand hits an uninitialized data directory, so a change to its
// wording is a behavior change worth catching.
package cmd

import (
	"strings"
	"testing"
)

func TestPINStoreNotFoundError_Error(t *testing.T) {
	err := &PINStoreNotFoundError{Dir: "/data/pin"}

	got := err.Error()

	for _, want := range []string{
		"/data/pin",
		"not initialized",
		"xkey pin set-so",
		"--data-dir",
		"XKEY_DATA_DIR",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Error() = %q, want it to contain %q", got, want)
		}
	}
}

func TestPINStoreNotFoundError_Error_EmptyDir(t *testing.T) {
	err := &PINStoreNotFoundError{}

	got := err.Error()

	if !strings.Contains(got, "pin: no PIN state directory at") {
		t.Errorf("Error() = %q, want the fixed prefix even with an empty Dir", got)
	}
}
