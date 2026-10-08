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
	"os"
	"strings"
	"testing"
)

// TestCanonicalSurface_InitEnvFallback verifies that XKMS_*
// environment variables resolve as canonical fallbacks.
func TestCanonicalSurface_InitEnvFallback(t *testing.T) {
	t.Setenv("XKMS_SO_PIN", "envso")
	t.Setenv("XKMS_BARRIER_STRATEGY", "tpm2")
	t.Setenv("XKMS_HOSTNAME", "env.example.com")
	t.Setenv("XKMS_SANS", "env.example.com")

	f, err := parseInitFlags([]string{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	resolveInitEnvFallbacks(f)
	if f.soPin != "envso" {
		t.Fatalf("env PIN fallback failed: %+v", f)
	}
	if f.barrierStrategy != "tpm2" {
		t.Fatalf("env strategy fallback failed: %+v", f)
	}
	if f.hostname != "env.example.com" {
		t.Fatalf("env hostname fallback failed: %+v", f)
	}
}

// TestCanonicalSurface_InitHelpMentionsCanonicalFlags verifies the help
// text exposes every canonical flag name; this acts as the shell-test
// equivalent for the xkmsd binary.
func TestCanonicalSurface_InitHelpMentionsCanonicalFlags(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = oldStderr })

	// Trigger Usage by parsing -h which causes flag.ContinueOnError
	// to return an error.
	_, parseErr := parseInitFlags([]string{"--help"})
	_ = parseErr
	_ = w.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	help := string(buf[:n])

	for _, flag := range []string{
		"--so-pin", "--barrier-strategy", "--hostname", "--sans",
	} {
		// PrintDefaults uses single dash for go flag; we accept either.
		if !strings.Contains(help, flag) && !strings.Contains(help, strings.TrimPrefix(flag, "-")) {
			t.Errorf("help text missing canonical flag %s; help:\n%s", flag, help)
		}
	}
}
