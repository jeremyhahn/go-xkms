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

package usb

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WithNoiseConfig used to write t.noise with no synchronization while Connect
// read it and several of its fields under lifecycleMu. The chaining ergonomics
// make it read as setup-only, but it is exported and nothing stops a caller
// rotating keys while a connection is in flight.
//
// Run under -race: before the fix this reports a write/read data race on
// Transport.noise. It also asserts the outcome, not just the absence of a race
// report — a handshake must complete against one configuration, never a splice
// of two.
func TestWithNoiseConfigDoesNotRaceConnect(t *testing.T) {
	tr, g, ok := newGatedTransport(t)
	if !ok {
		return
	}
	close(g.gate) // no blocking; the point here is the concurrent reconfigure.

	rotated, ok := requireStaticKey(t)
	if !ok {
		return
	}
	t.Cleanup(rotated.Destroy)

	// Both the transport's configured key and the session key a successful
	// Connect retains are protected allocations owned by the transport, not by
	// this test's source keys. Release both rather than leaving locked pages
	// resident for the life of the test binary.
	t.Cleanup(func() {
		_ = tr.Close()
		tr.noise.destroy()
	})

	var wg sync.WaitGroup
	wg.Add(2)

	connectErr := make(chan error, 1)
	go func() {
		defer wg.Done()
		connectErr <- tr.Connect(context.Background())
	}()

	go func() {
		defer wg.Done()
		tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: rotated.Private})
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("Connect and WithNoiseConfig did not both finish")
	}

	// Either ordering is legitimate — the reconfigure lands before Connect
	// reads the pointer, or after it finishes — and BOTH configure a valid
	// key, so the handshake must succeed either way.
	//
	// Asserting success is the whole point. Discarding this error would let an
	// implementation that copies the configuration inconsistently, and so
	// hands the handshake a spliced key that fails, pass a test whose comment
	// claims it proved one complete configuration was used.
	require.NoError(t, <-connectErr, "the handshake must complete against one configuration, not fail")
}

// The transport must not retain the caller's pointer or its slices. Retaining
// them lets the key material change under a handshake that has already begun —
// the same defect as the unsynchronized write, reached without a second
// WithNoiseConfig call at all.
//
// The private scalar is additionally not kept as a []byte at all: it lives in a
// protected StaticKey, so the assertion here is that the loaded key still
// derives the same public key after the caller has scribbled over its slice.
func TestWithNoiseConfigCopiesTheCallersConfig(t *testing.T) {
	source, ok := requireStaticKey(t)
	if !ok {
		return
	}
	t.Cleanup(source.Destroy)

	local := bytes.Clone(source.Private)
	wantPublic := bytes.Clone(source.Public)
	remote := bytes.Repeat([]byte{0x02}, 32)
	fingerprint := bytes.Repeat([]byte{0x03}, 32)

	tr, err := New()
	require.NoError(t, err)

	cfg := &NoiseConfig{
		LocalStaticPrivateKey:     local,
		ExpectedRemoteStatic:      remote,
		ExpectedDeviceFingerprint: fingerprint,
	}
	tr.WithNoiseConfig(cfg)
	t.Cleanup(func() { tr.noise.destroy() })

	// Mutate everything the caller still holds, in place and by field.
	for i := range local {
		local[i] = 0xff
	}
	for i := range remote {
		remote[i] = 0xff
	}
	for i := range fingerprint {
		fingerprint[i] = 0xff
	}
	cfg.LocalStaticPrivateKey = nil
	cfg.ExpectedRemoteStatic = nil
	cfg.ExpectedDeviceFingerprint = nil

	require.NotNil(t, tr.noise.localKey, "the private key must have loaded")
	assert.Equal(t, wantPublic, []byte(tr.noise.localKey.Public),
		"the loaded key must not be reachable through the caller's slice")
	assert.Equal(t, bytes.Repeat([]byte{0x02}, 32), tr.noise.expectedRemoteStatic,
		"the expected remote static must not be reachable through the caller's slice")
	assert.Equal(t, bytes.Repeat([]byte{0x03}, 32), tr.noise.expectedDeviceFingerprint,
		"the expected fingerprint must not be reachable through the caller's slice")
}

// The private scalar must never be held as an ordinary heap slice: a defensive
// copy taken with bytes.Clone would be abandoned unzeroized on every rotation
// and would outlive any wipe the caller performs on its own copy.
func TestWithNoiseConfigHoldsThePrivateKeyInProtectedMemory(t *testing.T) {
	source, ok := requireStaticKey(t)
	if !ok {
		return
	}
	t.Cleanup(source.Destroy)

	tr, err := New()
	require.NoError(t, err)
	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: bytes.Clone(source.Private)})
	t.Cleanup(func() { tr.noise.destroy() })

	require.NotNil(t, tr.noise.localKey)
	assert.Equal(t, []byte(source.Public), []byte(tr.noise.localKey.Public),
		"the transport's key must be the one that was configured")
}

// Replacing the configuration must release the pages behind the key it
// displaces. Dropping the reference would strand a locked, unswappable page for
// the life of the process on every rotation.
func TestWithNoiseConfigDestroysTheDisplacedKey(t *testing.T) {
	first, ok := requireStaticKey(t)
	if !ok {
		return
	}
	t.Cleanup(first.Destroy)
	second, ok := requireStaticKey(t)
	if !ok {
		return
	}
	t.Cleanup(second.Destroy)

	tr, err := New()
	require.NoError(t, err)

	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: bytes.Clone(first.Private)})
	displaced := tr.noise.localKey
	require.NotNil(t, displaced)

	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: bytes.Clone(second.Private)})
	t.Cleanup(func() { tr.noise.destroy() })

	// Destroy clears the embedded key pair, so an emptied DHKey is the
	// observable evidence that the pages were released rather than dropped.
	assert.Empty(t, displaced.Private, "the displaced key's private scalar was not destroyed")
	assert.Empty(t, displaced.Public, "the displaced key was not cleared")
	assert.Equal(t, []byte(second.Public), []byte(tr.noise.localKey.Public),
		"the replacement key must be the one just configured")
}

// A nil configuration clears the keys rather than panicking, and Connect reads
// the result as "not configured".
func TestWithNoiseConfigNilClearsTheKeys(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)

	tr.WithNoiseConfig(nil)
	assert.Nil(t, tr.noise)

	err = tr.Connect(context.Background())
	assert.ErrorIs(t, err, ErrNoiseNotConfigured)
}
