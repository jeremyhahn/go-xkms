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

package bootstrap

import "testing"

// TestReExportsCompose is the consumer's-eye test this package did not have.
//
// go-quicbaas and go-trusted-platform reach the Noise_NK server through these
// re-exports and never through go-truststrap directly, so nothing inside this
// repository exercises the combination. The protected-memory migration changed
// NoiseStaticKey to a type the config cannot accept, and no build, test or lint
// here could see it — a consumer would have found it at their next bump.
func TestReExportsCompose(t *testing.T) {
	key, err := GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateNoiseStaticKey: %v", err)
	}
	defer key.Destroy()

	// Exactly what a consumer writes. If this stops compiling, the re-exports
	// have drifted apart again.
	cfg := &NoiseServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  NoiseServerStaticKey(key),
	}

	if cfg.StaticKey == nil {
		t.Fatal("NoiseServerStaticKey returned nil for a live key")
	}
	if len(cfg.StaticKey.Private) != len(key.Private) {
		t.Fatalf("adapted key pair does not carry the private half: %d vs %d",
			len(cfg.StaticKey.Private), len(key.Private))
	}
	if len(cfg.StaticKey.Public) == 0 {
		t.Fatal("adapted key pair has no public half")
	}
}

// TestNoiseServerStaticKeyNil keeps the adapter total: a nil key yields a nil
// pair rather than dereferencing.
func TestNoiseServerStaticKeyNil(t *testing.T) {
	if got := NoiseServerStaticKey(nil); got != nil {
		t.Fatalf("expected nil for a nil key, got %v", got)
	}
}
