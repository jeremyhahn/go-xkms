// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package luks

import (
	"os"
	"testing"
)

// TestMain replaces the kernel keyring probe with one that passes for the
// whole package. The unit tests exercise filesystem and argument failures of
// Create and Unlock, and the host's seccomp profile must not decide whether
// those pass: a container that blocks the keyring syscalls would otherwise
// turn every Create refusal into a keyring refusal. Tests that exercise the
// preflight itself install their own probe.
func TestMain(m *testing.M) {
	checkKeyringAvailable = func() error { return nil }
	os.Exit(m.Run())
}
