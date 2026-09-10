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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCertForAdapter generates a test certificate for adapter testing
func generateTestCertForAdapter(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// TestNewHardwareBackendAdapter tests the constructor
func TestNewHardwareBackendAdapter(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)

	require.NotNil(t, adapter)
	assert.Implements(t, (*storage.Backend)(nil), adapter)
}

// TestHardwareBackendAdapter_Get tests Get operation
func TestHardwareBackendAdapter_Get(t *testing.T) {
	t.Run("GetSingleCertificate", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		cert := generateTestCertForAdapter(t, "test")

		// Store cert in hardware storage
		err := hw.SaveCert("test-cert", cert)
		require.NoError(t, err)

		// Get through adapter
		data, err := adapter.Get(context.Background(), "certs/test-cert.pem")
		require.NoError(t, err)
		assert.Equal(t, cert.Raw, data)
	})

	t.Run("GetCertificateChain", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		cert1 := generateTestCertForAdapter(t, "cert1")
		cert2 := generateTestCertForAdapter(t, "cert2")
		chain := []*x509.Certificate{cert1, cert2}

		// Store chain in hardware storage
		err := hw.SaveCertChain("chaintest", chain)
		require.NoError(t, err)

		// Get through adapter
		data, err := adapter.Get(context.Background(), "certs/chaintest-chain.pem")
		require.NoError(t, err)

		// Verify concatenated DER data
		expectedData := append(cert1.Raw, cert2.Raw...)
		assert.Equal(t, expectedData, data)
	})

	t.Run("InvalidKeyPrefix", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		_, err := adapter.Get(context.Background(), "keys/test.key")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hardware storage only supports certificate keys")
	})

	t.Run("UnsupportedKeyFormat", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		_, err := adapter.Get(context.Background(), "certs/test")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key format")
	})

	t.Run("CertificateNotFound", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		_, err := adapter.Get(context.Background(), "certs/nonexistent.pem")
		require.Error(t, err)
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("ChainNotFound", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		_, err := adapter.Get(context.Background(), "certs/nonexistent-chain.pem")
		require.Error(t, err)
		assert.Equal(t, storage.ErrNotFound, err)
	})
}

// TestHardwareBackendAdapter_Put tests Put operation
func TestHardwareBackendAdapter_Put(t *testing.T) {
	t.Run("PutSingleCertificate", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		cert := generateTestCertForAdapter(t, "test")

		// Put through adapter
		err := adapter.Put(context.Background(), "certs/test-cert.pem", cert.Raw)
		require.NoError(t, err)

		// Verify stored in hardware
		retrieved, err := hw.GetCert("test-cert")
		require.NoError(t, err)
		assert.True(t, cert.Equal(retrieved))
	})

	t.Run("PutSingleCertificateAsChain", func(t *testing.T) {
		// Test putting a single certificate using the chain key format
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		cert := generateTestCertForAdapter(t, "test")

		// Put single cert data through adapter using chain format
		// This tests the parseDERChain with a single valid cert
		err := adapter.Put(context.Background(), "certs/chaintest-chain.pem", cert.Raw)
		require.NoError(t, err)

		// Verify stored in hardware
		retrieved, err := hw.GetCertChain("chaintest")
		require.NoError(t, err)
		assert.Len(t, retrieved, 1)
		assert.True(t, cert.Equal(retrieved[0]))
	})

	t.Run("InvalidKeyPrefix", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		err := adapter.Put(context.Background(), "keys/test.key", []byte("data"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hardware storage only supports certificate keys")
	})

	t.Run("UnsupportedKeyFormat", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		err := adapter.Put(context.Background(), "certs/test", []byte("data"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key format")
	})

	t.Run("InvalidCertificateData", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		err := adapter.Put(context.Background(), "certs/test.pem", []byte("invalid cert data"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse certificate")
	})

	t.Run("InvalidChainData", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		err := adapter.Put(context.Background(), "certs/test-chain.pem", []byte("invalid chain data"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse certificate chain")
	})
}

// TestHardwareBackendAdapter_Delete tests Delete operation
func TestHardwareBackendAdapter_Delete(t *testing.T) {
	t.Run("DeleteCertificate", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		cert := generateTestCertForAdapter(t, "test")
		err := hw.SaveCert("test-cert", cert)
		require.NoError(t, err)

		// Delete through adapter
		err = adapter.Delete(context.Background(), "certs/test-cert.pem")
		require.NoError(t, err)

		// Verify deleted
		_, err = hw.GetCert("test-cert")
		assert.Equal(t, storage.ErrNotFound, err)
	})

	t.Run("DeleteWithChainSuffix", func(t *testing.T) {
		// A key ending in -chain.pem names the CHAIN record of the id before
		// the suffix, exactly as Get and Put read it: "certs/chaintest-chain.pem"
		// is the chain of "chaintest", never the certificate of
		// "chaintest-chain". Delete used to strip ".pem" first and so resolved
		// the same key to a different record than Get and Put did.
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		cert := generateTestCertForAdapter(t, "test")
		require.NoError(t, hw.SaveCert("chaintest-chain", cert))
		require.NoError(t, hw.SaveCert("chaintest", cert))
		require.NoError(t, hw.SaveCertChain("chaintest", []*x509.Certificate{cert}))

		require.NoError(t, adapter.Delete(context.Background(), "certs/chaintest-chain.pem"))

		_, err := hw.GetCertChain("chaintest")
		assert.ErrorIs(t, err, storage.ErrNotFound, "the chain of chaintest is what the key names")
		_, err = hw.GetCert("chaintest")
		require.NoError(t, err, "the certificate of chaintest is a separate record")
		_, err = hw.GetCert("chaintest-chain")
		require.NoError(t, err, "the certificate of chaintest-chain was never addressed")
	})

	t.Run("InvalidKeyPrefix", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		err := adapter.Delete(context.Background(), "keys/test.key")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "hardware storage only supports certificate keys")
	})

	t.Run("DeleteNonexistent", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		err := adapter.Delete(context.Background(), "certs/nonexistent.pem")
		require.Error(t, err)
		assert.Equal(t, storage.ErrNotFound, err)
	})
}

// TestHardwareBackendAdapter_List tests List operation
func TestHardwareBackendAdapter_List(t *testing.T) {
	t.Run("ListCertificates", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		cert1 := generateTestCertForAdapter(t, "cert1")
		cert2 := generateTestCertForAdapter(t, "cert2")
		err := hw.SaveCert("cert-a", cert1)
		require.NoError(t, err)
		err = hw.SaveCert("cert-b", cert2)
		require.NoError(t, err)

		// List through adapter
		keys, err := adapter.List(context.Background(), "")
		require.NoError(t, err)
		assert.Len(t, keys, 2)
		assert.Contains(t, keys, "certs/cert-a.pem")
		assert.Contains(t, keys, "certs/cert-b.pem")
	})

	t.Run("ListWithPrefix", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		cert := generateTestCertForAdapter(t, "test")
		err := hw.SaveCert("test-cert", cert)
		require.NoError(t, err)

		// List with matching prefix
		keys, err := adapter.List(context.Background(), "certs/test")
		require.NoError(t, err)
		assert.Len(t, keys, 1)
		assert.Equal(t, "certs/test-cert.pem", keys[0])
	})

	t.Run("ListWithNonMatchingPrefix", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		cert := generateTestCertForAdapter(t, "test")
		err := hw.SaveCert("test-cert", cert)
		require.NoError(t, err)

		// List with non-matching prefix
		keys, err := adapter.List(context.Background(), "keys/")
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("ListEmpty", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		keys, err := adapter.List(context.Background(), "")
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("ListError", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		hw.failList = true
		adapter := NewHardwareBackendAdapter(hw)

		_, err := adapter.List(context.Background(), "")
		require.Error(t, err)
	})
}

// TestHardwareBackendAdapter_Exists tests Exists operation
func TestHardwareBackendAdapter_Exists(t *testing.T) {
	t.Run("ExistsTrue", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		cert := generateTestCertForAdapter(t, "test")
		err := hw.SaveCert("test-cert", cert)
		require.NoError(t, err)

		exists, err := adapter.Exists(context.Background(), "certs/test-cert.pem")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("ExistsFalse", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		exists, err := adapter.Exists(context.Background(), "certs/nonexistent.pem")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("InvalidKeyPrefix", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		exists, err := adapter.Exists(context.Background(), "keys/test.key")
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("ExistsWithChainKeySuffix", func(t *testing.T) {
		// A -chain.pem key names the chain record, as Get, Put and Delete read
		// it: it is true for a chain-only record and false for an id that has
		// only a certificate, and "certs/chaintest-chain.pem" asks about the
		// chain of "chaintest", not the certificate of "chaintest-chain".
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)
		cert := generateTestCertForAdapter(t, "test")

		require.NoError(t, hw.SaveCertChain("chain-only", []*x509.Certificate{cert}))
		exists, err := adapter.Exists(context.Background(), "certs/chain-only-chain.pem")
		require.NoError(t, err)
		assert.True(t, exists, "a chain-only record exists under its chain key")
		exists, err = adapter.Exists(context.Background(), "certs/chain-only.pem")
		require.NoError(t, err)
		assert.False(t, exists, "and not under its certificate key")

		require.NoError(t, hw.SaveCert("chaintest-chain", cert))
		exists, err = adapter.Exists(context.Background(), "certs/chaintest-chain.pem")
		require.NoError(t, err)
		assert.False(t, exists, "the key names the chain of chaintest, which does not exist")
		require.NoError(t, hw.SaveCertChain("chaintest", []*x509.Certificate{cert}))
		exists, err = adapter.Exists(context.Background(), "certs/chaintest-chain.pem")
		require.NoError(t, err)
		assert.True(t, exists)
	})
}

// TestHardwareBackendAdapter_Close tests Close operation
func TestHardwareBackendAdapter_Close(t *testing.T) {
	t.Run("CloseSuccess", func(t *testing.T) {
		hw := newMockHardwareCertStorage(10)
		adapter := NewHardwareBackendAdapter(hw)

		err := adapter.Close()
		require.NoError(t, err)
		assert.True(t, hw.closed)
	})
}

// TestHardwareBackendAdapter_GetHardwareStorage tests GetHardwareStorage method
func TestHardwareBackendAdapter_GetHardwareStorage(t *testing.T) {
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw).(*HardwareBackendAdapter)

	retrieved := adapter.GetHardwareStorage()
	assert.Equal(t, hw, retrieved)
}

// TestParseDERChain tests the parseDERChain helper function
func TestParseDERChain(t *testing.T) {
	t.Run("SingleCertificate", func(t *testing.T) {
		cert := generateTestCertForAdapter(t, "test")

		chain, err := parseDERChain(cert.Raw)
		require.NoError(t, err)
		assert.Len(t, chain, 1)
		assert.True(t, cert.Equal(chain[0]))
	})

	t.Run("EmptyData", func(t *testing.T) {
		_, err := parseDERChain([]byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no certificates found")
	})

	t.Run("InvalidData", func(t *testing.T) {
		_, err := parseDERChain([]byte("invalid data"))
		require.Error(t, err)
	})

	t.Run("ConcatenatedCertsParseAsAChain", func(t *testing.T) {
		// The chain key's value is the members' DER concatenated, exactly
		// what Get emits for it, so Put must accept what Get produces.
		cert1 := generateTestCertForAdapter(t, "cert1")
		cert2 := generateTestCertForAdapter(t, "cert2")
		data := append(append([]byte{}, cert1.Raw...), cert2.Raw...)

		chain, err := parseDERChain(data)
		require.NoError(t, err)
		require.Len(t, chain, 2)
		assert.Equal(t, cert1.Raw, chain[0].Raw)
		assert.Equal(t, cert2.Raw, chain[1].Raw)
	})

	t.Run("TrailingGarbageIsAnError", func(t *testing.T) {
		cert1 := generateTestCertForAdapter(t, "cert1")
		data := append(append([]byte{}, cert1.Raw...), []byte("not a certificate")...)
		_, err := parseDERChain(data)
		require.Error(t, err, "bytes after the last certificate are not silently dropped")
	})
}

// TestHardwareBackendAdapter_ChainRoundTripsThroughTheAdapter proves a
// generic storage caller can write a multi-member chain through the adapter,
// read it back, and write what it read: the value Get emits for
// certs/{id}-chain.pem is the value Put accepts for it.
func TestHardwareBackendAdapter_ChainRoundTripsThroughTheAdapter(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)
	cert1 := generateTestCertForAdapter(t, "rt-1")
	cert2 := generateTestCertForAdapter(t, "rt-2")
	data := append(append([]byte{}, cert1.Raw...), cert2.Raw...)

	require.NoError(t, adapter.Put(ctx, "certs/rt-chain.pem", data))
	got, err := adapter.Get(ctx, "certs/rt-chain.pem")
	require.NoError(t, err)
	assert.Equal(t, data, got)
	require.NoError(t, adapter.Put(ctx, "certs/rt-chain.pem", got), "what Get emits, Put accepts")
	chain, err := hw.GetCertChain("rt")
	require.NoError(t, err)
	require.Len(t, chain, 2)
}

// TestHardwareBackendAdapter_DeleteRefusesUnsupportedKeys proves Delete
// dispatches only the two key shapes Get and Put accept: certs/test does not
// fall through to the certificate certs/test.pem.
func TestHardwareBackendAdapter_DeleteRefusesUnsupportedKeys(t *testing.T) {
	ctx := context.Background()
	hw := newMockHardwareCertStorage(10)
	adapter := NewHardwareBackendAdapter(hw)
	cert := generateTestCertForAdapter(t, "keep")
	require.NoError(t, hw.SaveCert("test", cert))

	for _, key := range []string{"certs/test", "certs/test.pem.bak", "certs/test.der"} {
		err := adapter.Delete(ctx, key)
		require.Error(t, err, key)
		assert.Contains(t, err.Error(), "unsupported key format", key)
	}
	_, err := hw.GetCert("test")
	require.NoError(t, err, "the certificate a malformed key resembled is untouched")
}

// TestHardwareBackendAdapter_InterfaceCompliance verifies interface implementation
func TestHardwareBackendAdapter_InterfaceCompliance(t *testing.T) {
	var _ storage.Backend = (*HardwareBackendAdapter)(nil)
}
