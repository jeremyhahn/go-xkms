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

// bootstrap_noise_run_test.go exercises the "xkmsctl bootstrap noise" Run
// closures (generate-key, show-key, show-spki-pin), which just read flags
// and delegate to the already-tested named functions.
package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestNoiseGenerateKeyCmd_Run(t *testing.T) {
	cmd := noiseGenerateKeyCmd
	_ = cmd.Flags().Set("output", filepath.Join(t.TempDir(), "noise.key"))
	captureStdout(t, func() {
		cmd.Run(cmd, nil)
	})
}

// TestNoiseGenerateKeyCmd_RunNoOutput checks the flag plumbing for the ruling
// that the key only ever lands in a file: an empty --output has to reach the
// error path, not fall back to printing.
func TestNoiseGenerateKeyCmd_RunNoOutput(t *testing.T) {
	cmd := noiseGenerateKeyCmd
	_ = cmd.Flags().Set("output", "")

	var stderr string
	code := captureExit(t, func() {
		stderr = captureStderr(t, func() { cmd.Run(cmd, nil) })
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for missing --output, got %d", code)
	}
	// Which error, not just that one occurred — see the note in
	// TestNoiseGenerateKey_RequiresOutputFile.
	if !strings.Contains(stderr, "--output is required") {
		t.Errorf("expected the missing-output error specifically, got: %s", stderr)
	}
}

func TestNoiseShowKeyCmd_Run(t *testing.T) {
	cmd := noiseShowKeyCmd
	_ = cmd.Flags().Set("key-file", "")
	_ = cmd.Flags().Set("key-hex", "")
	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for no key input, got %d", code)
	}
}

func TestNoiseShowSPKIPinCmd_Run(t *testing.T) {
	cmd := noiseShowSPKIPinCmd
	_ = cmd.Flags().Set("cert-file", "")
	code := captureExit(t, func() {
		cmd.Run(cmd, nil)
	})
	if code != 1 {
		t.Errorf("expected exit code 1 for no cert-file, got %d", code)
	}
}
