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

//go:build integration

package bootstrap

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
)

// TestBootstrapShowKeys_Discovered proves the running server publishes its
// Noise_NK public key over the admin API (go-xkms#632) in the shape every
// other test in this package relies on through discoveredBootstrapKeys.
func TestBootstrapShowKeys_Discovered(t *testing.T) {
	keys := discoveredBootstrapKeys(t)

	if keys.NoisePublicKey == "" {
		t.Fatal("expected a Noise_NK public key from the non-FIPS test harness")
	}
	if len(keys.NoisePublicKey) != 64 {
		t.Fatalf("expected a 64-hex-char Curve25519 public key, got %d chars", len(keys.NoisePublicKey))
	}
}

// TestBootstrapShowKeys_PinsAWorkingNoiseHandshake proves the reported hex
// is exactly the value pkg/trust/bootstrap.NoiseConfig accepts: it pins the
// discovered key into NoiseConfig.ServerStaticKey — the same field
// `xkmsctl bootstrap auto --noise-key` sets, validated internally by
// decodeSuiteKey — and completes a real Noise_NK handshake against the
// running server through the canonical dispatch library. This is a
// different code path from this package's other Noise tests, which drive
// go-truststrap's lower-level bootstrapper directly; this one proves the
// value BootstrapListenerKeys reports is usable by the actual client
// surface operators are told to paste it into.
func TestBootstrapShowKeys_PinsAWorkingNoiseHandshake(t *testing.T) {
	keys := discoveredBootstrapKeys(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bundle, err := bootstrap.Fetch(ctx, bootstrap.Config{
		Mode: bootstrap.ModeNoise,
		Noise: &bootstrap.NoiseConfig{
			ServerAddr:      requiredEnv(t, EnvNoiseAddr),
			ServerStaticKey: keys.NoisePublicKey,
			Suite:           bootstrap.SuiteNoiseNK,
		},
	})
	if err != nil {
		t.Fatalf("Fetch(ModeNoise) with the reported Noise_NK key: %v", err)
	}
	if bundle == nil || len(bundle.PEM) == 0 {
		t.Fatal("expected a non-empty CA bundle over the pinned Noise_NK handshake")
	}
}

// TestBootstrapShowKeys_PinsAWorkingP256Handshake is
// TestBootstrapShowKeys_PinsAWorkingNoiseHandshake's counterpart for the
// FIPS-approved suite. The server always loads or generates its P-256 key
// when the listener starts, so an empty P256PublicKey is a failure.
func TestBootstrapShowKeys_PinsAWorkingP256Handshake(t *testing.T) {
	keys := discoveredBootstrapKeys(t)
	if keys.P256PublicKey == "" {
		t.Fatal("bootstrap listener reported no P-256 public key; the server always provisions one")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	bundle, err := bootstrap.Fetch(ctx, bootstrap.Config{
		Mode: bootstrap.ModeNoise,
		Noise: &bootstrap.NoiseConfig{
			ServerAddr:          requiredEnv(t, EnvNoiseAddr),
			ServerP256StaticKey: keys.P256PublicKey,
			Suite:               bootstrap.SuiteP256AESGCM,
		},
	})
	if err != nil {
		t.Fatalf("Fetch(ModeNoise) with the reported P-256 key: %v", err)
	}
	if bundle == nil || len(bundle.PEM) == 0 {
		t.Fatal("expected a non-empty CA bundle over the pinned P-256 handshake")
	}
}
