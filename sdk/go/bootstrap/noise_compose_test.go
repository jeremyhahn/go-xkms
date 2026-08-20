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

import (
	"bytes"
	"testing"
	"unsafe"
)

// TestSDKNoiseSurfaceComposes walks the whole protected-key flow using only
// what this package re-exports, because that is the only surface consumers
// are allowed to use.
//
// The same defect has now appeared at two layers, one after the other:
// pkg/trust/bootstrap re-exported a protected NoiseStaticKey and a config
// that could not accept it, and once that was fixed this package re-exported
// the two halves and not the adapter joining them. Each half compiled. The
// combination did not exist anywhere, so nothing failed until a consumer
// tried it.
//
// A test that only constructs a key proves nothing here. This one performs
// every step a consumer performs, in order.
func TestSDKNoiseSurfaceComposes(t *testing.T) {
	key, err := GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateNoiseStaticKey: %v", err)
	}
	defer key.Destroy()

	// 1. Hand the protected key to the server config.
	cfg := &NoiseServerConfig{
		ListenAddr: "127.0.0.1:0",
		StaticKey:  NoiseServerStaticKey(key),
	}
	if cfg.StaticKey == nil {
		t.Fatal("NoiseServerStaticKey returned nil for a live key")
	}
	if len(cfg.StaticKey.Public) == 0 {
		t.Fatal("adapted key pair has no public half")
	}

	// The adapter must ALIAS the protected pages, not copy them.
	//
	// Comparing contents cannot tell the difference — a copy is equal — and a
	// copy is the failure that matters: it puts the private scalar on the Go
	// heap, where it is unwipeable and outside every guarantee the protected
	// type provides, while every other assertion here still passes. So this
	// compares the backing pointers.
	if unsafe.SliceData(cfg.StaticKey.Private) != unsafe.SliceData(key.Private) {
		t.Fatal("the adapter copied the private scalar onto the Go heap instead " +
			"of aliasing the protected pages")
	}

	// 2. Persist it. The buffer has to be sized from the re-exported
	//    constant; without it a consumer is guessing.
	encoded := make([]byte, NoiseHexKeySize)
	if err := EncodeNoiseStaticKey(encoded, key); err != nil {
		t.Fatalf("EncodeNoiseStaticKey: %v", err)
	}

	// 3. Load it back. Decoding must reproduce the same identity, which the
	//    public half proves without reading the private one.
	restored, err := DecodeNoiseStaticKey(encoded)
	if err != nil {
		t.Fatalf("DecodeNoiseStaticKey: %v", err)
	}
	defer restored.Destroy()

	if !bytes.Equal(restored.Public, key.Public) {
		t.Fatal("the decoded key is not the one that was encoded")
	}

	// 4. Wipe the buffer the consumer now owns. Encoded key material is as
	//    sensitive as the key, and this is the only way to clear it.
	WipeNoiseBytes(encoded)
	for i, b := range encoded {
		if b != 0 {
			t.Fatalf("WipeNoiseBytes left byte %d set to %#x", i, b)
		}
	}
}
