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
	"errors"
	"os"
	"strings"
	"testing"
)

// TestCanonicalSurface_InitParsesCanonicalFlags exercises the canonical
// flag set per docs/08-bootstrap-auth-architecture.md §6 and confirms
// the xkmsd init parser accepts every flag.
func TestCanonicalSurface_InitParsesCanonicalFlags(t *testing.T) {
	flags, err := parseInitFlags([]string{
		"--so-pin", "so",
		"--user-pin", "user",
		"--barrier-strategy", "shamir",
		"--shares", "5",
		"--threshold", "3",
		"--hostname", "node.example.com",
		"--sans", "node.example.com,node.lan",
		"--admin-bundle", "/tmp/bundle.pem",
	})
	if err != nil {
		t.Fatalf("canonical init flags rejected: %v", err)
	}
	if flags.soPin != "so" || flags.userPin != "user" {
		t.Fatalf("PIN parsing failed: %+v", flags)
	}
	if flags.barrierStrategy != "shamir" || flags.shares != 5 || flags.threshold != 3 {
		t.Fatalf("strategy/threshold parsing failed: %+v", flags)
	}
	if flags.hostname != "node.example.com" || flags.adminBundle != "/tmp/bundle.pem" {
		t.Fatalf("hostname/admin-bundle parsing failed: %+v", flags)
	}
}

// TestCanonicalSurface_InitRejectsBadStrategy verifies the validator
// rejects unknown strategies.
func TestCanonicalSurface_InitRejectsBadStrategy(t *testing.T) {
	f := &initFlags{
		soPin:           "so",
		userPin:         "user",
		barrierStrategy: "totally-bogus",
	}
	if err := validateInitFlags(f); !errors.Is(err, ErrInvalidBarrierStrategy) {
		t.Fatalf("expected ErrInvalidBarrierStrategy, got %v", err)
	}
}

// TestCanonicalSurface_InitShamirRequiresShares verifies that
// --barrier-strategy=shamir without --shares is rejected.
func TestCanonicalSurface_InitShamirRequiresShares(t *testing.T) {
	f := &initFlags{
		soPin:           "so",
		userPin:         "user",
		barrierStrategy: "shamir",
	}
	if err := validateInitFlags(f); !errors.Is(err, ErrShamirSharesRequired) {
		t.Fatalf("expected ErrShamirSharesRequired, got %v", err)
	}
}

// TestCanonicalSurface_InitShamirRequiresThreshold verifies that
// --barrier-strategy=shamir without --threshold is rejected.
func TestCanonicalSurface_InitShamirRequiresThreshold(t *testing.T) {
	f := &initFlags{
		soPin:           "so",
		userPin:         "user",
		barrierStrategy: "shamir",
		shares:          5,
	}
	if err := validateInitFlags(f); !errors.Is(err, ErrShamirThresholdRequired) {
		t.Fatalf("expected ErrShamirThresholdRequired, got %v", err)
	}
}

// TestCanonicalSurface_InitNonShamirRejectsShares verifies that
// supplying --shares with a non-shamir strategy is rejected.
func TestCanonicalSurface_InitNonShamirRejectsShares(t *testing.T) {
	f := &initFlags{
		soPin:           "so",
		userPin:         "user",
		barrierStrategy: "tpm2",
		shares:          5,
	}
	if err := validateInitFlags(f); !errors.Is(err, ErrSharesRequiresShamir) {
		t.Fatalf("expected ErrSharesRequiresShamir, got %v", err)
	}
}

// TestCanonicalSurface_InitEnvFallback verifies that XKMS_*
// environment variables resolve as canonical fallbacks.
func TestCanonicalSurface_InitEnvFallback(t *testing.T) {
	t.Setenv("XKMS_SO_PIN", "envso")
	t.Setenv("XKMS_USER_PIN", "envuser")
	t.Setenv("XKMS_BARRIER_STRATEGY", "shamir")
	t.Setenv("XKMS_SHARES", "5")
	t.Setenv("XKMS_THRESHOLD", "3")
	t.Setenv("XKMS_HOSTNAME", "env.example.com")
	t.Setenv("XKMS_SANS", "env.example.com")
	t.Setenv("XKMS_ADMIN_BUNDLE", "/tmp/env-bundle")

	f, err := parseInitFlags([]string{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	resolveInitEnvFallbacks(f)
	if f.soPin != "envso" || f.userPin != "envuser" {
		t.Fatalf("env PIN fallback failed: %+v", f)
	}
	if f.barrierStrategy != "shamir" || f.shares != 5 || f.threshold != 3 {
		t.Fatalf("env strategy/shares fallback failed: %+v", f)
	}
	if f.hostname != "env.example.com" || f.adminBundle != "/tmp/env-bundle" {
		t.Fatalf("env hostname/admin-bundle fallback failed: %+v", f)
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
		"--so-pin", "--user-pin", "--barrier-strategy", "--shares",
		"--threshold", "--hostname", "--sans", "--admin-bundle",
	} {
		// PrintDefaults uses single dash for go flag; we accept either.
		if !strings.Contains(help, flag) && !strings.Contains(help, strings.TrimPrefix(flag, "-")) {
			t.Errorf("help text missing canonical flag %s; help:\n%s", flag, help)
		}
	}
}
