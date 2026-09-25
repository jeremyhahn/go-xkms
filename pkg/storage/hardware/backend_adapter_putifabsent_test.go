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

package hardware

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildDERChain concatenates the raw DER of a small certificate chain, the
// encoding PutIfAbsent's "-chain.pem" branch expects (mirroring what Get
// emits for a stored chain).
func buildDERChain(t *testing.T, names ...string) []byte {
	t.Helper()

	var data []byte
	for _, name := range names {
		cert := generateTestCertForAdapter(t, name)
		data = append(data, cert.Raw...)
	}
	return data
}

// TestHardwareBackendAdapter_PutIfAbsent verifies the certificate adapter's
// atomic check-then-write: a fresh cert key is written (stored=true) and a
// second write to the same id is rejected (stored=false), leaving the original
// certificate intact.
func TestHardwareBackendAdapter_PutIfAbsent(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)

	cert := generateTestCertForAdapter(t, "first")
	const key = "certs/example.pem"

	stored, err := adapter.PutIfAbsent(ctx, key, cert.Raw)
	require.NoError(t, err)
	assert.True(t, stored, "fresh PutIfAbsent should store")

	got, err := adapter.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, got)

	// A second cert for the same id must be rejected, leaving the original.
	other := generateTestCertForAdapter(t, "second")
	stored, err = adapter.PutIfAbsent(ctx, key, other.Raw)
	require.NoError(t, err)
	assert.False(t, stored, "existing PutIfAbsent should not store")

	got, err = adapter.Get(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, cert.Raw, got, "original certificate must remain intact")
}

// TestHardwareBackendAdapter_PutIfAbsent_InvalidKey verifies non-certificate
// keys are rejected before any write.
func TestHardwareBackendAdapter_PutIfAbsent_InvalidKey(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)

	stored, err := adapter.PutIfAbsent(ctx, "keys/not-a-cert", []byte("x"))
	require.Error(t, err)
	assert.False(t, stored)
}

// TestHardwareBackendAdapter_PutIfAbsent_UnsupportedKeyShape verifies a key
// under the certs/ prefix that is neither a certificate nor a chain key
// (wrong extension) is rejected, rather than silently matching the single
// certificate branch.
func TestHardwareBackendAdapter_PutIfAbsent_UnsupportedKeyShape(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)

	stored, err := adapter.PutIfAbsent(ctx, "certs/example.crt", []byte("x"))
	require.Error(t, err)
	assert.False(t, stored)
	assert.Contains(t, err.Error(), "unsupported key format")
}

// TestHardwareBackendAdapter_PutIfAbsent_Chain verifies the chain branch: a
// fresh chain key is parsed and stored (stored=true), and a second write to
// the same id is rejected once GetCertChain reports the record present,
// leaving the original chain intact.
func TestHardwareBackendAdapter_PutIfAbsent_Chain(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)

	const key = "certs/example-chain.pem"
	der := buildDERChain(t, "leaf", "intermediate")

	stored, err := adapter.PutIfAbsent(ctx, key, der)
	require.NoError(t, err)
	assert.True(t, stored, "fresh chain PutIfAbsent should store")

	chain, err := hw.GetCertChain("example")
	require.NoError(t, err)
	require.Len(t, chain, 2)

	otherDER := buildDERChain(t, "replacement")
	stored, err = adapter.PutIfAbsent(ctx, key, otherDER)
	require.NoError(t, err)
	assert.False(t, stored, "existing chain PutIfAbsent should not store")

	chain, err = hw.GetCertChain("example")
	require.NoError(t, err)
	assert.Len(t, chain, 2, "original chain must remain intact")
}

// TestHardwareBackendAdapter_PutIfAbsent_Chain_MalformedDER verifies a chain
// value that does not parse as concatenated DER certificates is rejected
// with a wrapped error rather than writing a broken record.
func TestHardwareBackendAdapter_PutIfAbsent_Chain_MalformedDER(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)

	stored, err := adapter.PutIfAbsent(ctx, "certs/broken-chain.pem", []byte("not-a-certificate"))
	require.Error(t, err)
	assert.False(t, stored)
	assert.Contains(t, err.Error(), "failed to parse certificate chain")

	_, getErr := hw.GetCertChain("broken")
	assert.Error(t, getErr, "a malformed write must not leave a partial record")
}

// TestHardwareBackendAdapter_PutIfAbsent_Chain_ProbeError verifies a
// GetCertChain failure other than "not found" aborts the write rather than
// being treated as an absent record.
func TestHardwareBackendAdapter_PutIfAbsent_Chain_ProbeError(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	hw.failGet = true
	adapter := NewHardwareBackendAdapter(hw)

	stored, err := adapter.PutIfAbsent(ctx, "certs/example-chain.pem", buildDERChain(t, "leaf"))
	require.Error(t, err)
	assert.False(t, stored)
	assert.Equal(t, "mock get error", err.Error())
}

// TestHardwareBackendAdapter_PutIfAbsent_Chain_SaveError verifies a
// SaveCertChain failure surfaces unwrapped to the caller.
func TestHardwareBackendAdapter_PutIfAbsent_Chain_SaveError(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	hw.failSave = true
	adapter := NewHardwareBackendAdapter(hw)

	stored, err := adapter.PutIfAbsent(ctx, "certs/example-chain.pem", buildDERChain(t, "leaf"))
	require.Error(t, err)
	assert.False(t, stored)
	assert.Equal(t, "mock save error", err.Error())
}

// TestHardwareBackendAdapter_PutIfAbsent_SingleCert_ExistsError verifies a
// CertExists failure aborts the write rather than being treated as absent.
func TestHardwareBackendAdapter_PutIfAbsent_SingleCert_ExistsError(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	hw.failExists = true
	adapter := NewHardwareBackendAdapter(hw)

	cert := generateTestCertForAdapter(t, "example")
	stored, err := adapter.PutIfAbsent(ctx, "certs/example.pem", cert.Raw)
	require.Error(t, err)
	assert.False(t, stored)
	assert.Equal(t, "mock exists error", err.Error())
}

// TestHardwareBackendAdapter_PutIfAbsent_SingleCert_MalformedDER verifies a
// certificate value that does not parse as DER is rejected with a wrapped
// error.
func TestHardwareBackendAdapter_PutIfAbsent_SingleCert_MalformedDER(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)

	stored, err := adapter.PutIfAbsent(ctx, "certs/broken.pem", []byte("not-a-certificate"))
	require.Error(t, err)
	assert.False(t, stored)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

// TestHardwareBackendAdapter_PutIfAbsent_SingleCert_SaveError verifies a
// SaveCert failure surfaces unwrapped to the caller.
func TestHardwareBackendAdapter_PutIfAbsent_SingleCert_SaveError(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	hw.failSave = true
	adapter := NewHardwareBackendAdapter(hw)

	cert := generateTestCertForAdapter(t, "example")
	stored, err := adapter.PutIfAbsent(ctx, "certs/example.pem", cert.Raw)
	require.Error(t, err)
	assert.False(t, stored)
	assert.Equal(t, "mock save error", err.Error())
}
