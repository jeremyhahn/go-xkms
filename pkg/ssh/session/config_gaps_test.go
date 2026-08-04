// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}
	return signer
}

// TestBuildClientConfig_DefaultTimeout covers the zero-timeout fallback branch.
func TestBuildClientConfig_DefaultTimeout(t *testing.T) {
	signer := testSigner(t)
	cb := ssh.InsecureIgnoreHostKey()

	cfg := buildClientConfig(DialRequest{User: "alice"}, signer, cb)
	if cfg.User != "alice" {
		t.Fatalf("user not propagated: %q", cfg.User)
	}
	if cfg.Timeout != defaultTimeout {
		t.Fatalf("expected defaultTimeout, got %v", cfg.Timeout)
	}
	if len(cfg.Auth) != 1 {
		t.Fatalf("expected one auth method, got %d", len(cfg.Auth))
	}
	if cfg.HostKeyCallback == nil {
		t.Fatalf("host key callback not set")
	}
}

// TestBuildClientConfig_CustomTimeout covers the caller-provided timeout path.
func TestBuildClientConfig_CustomTimeout(t *testing.T) {
	signer := testSigner(t)
	cb := ssh.InsecureIgnoreHostKey()

	want := 42 * time.Second
	cfg := buildClientConfig(DialRequest{User: "bob", Timeout: want}, signer, cb)
	if cfg.Timeout != want {
		t.Fatalf("expected %v, got %v", want, cfg.Timeout)
	}
	if cfg.User != "bob" {
		t.Fatalf("user not propagated: %q", cfg.User)
	}
}
