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

package xkms

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-truststrap/pkg/spkipin"
)

// parsedTestCert mints a self-signed certificate and returns its parsed form.
func parsedTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	pair := newTestClientCertificate(t)
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	require.NoError(t, err)
	return cert
}

// TestTrustFetcherSPKIHash_Nil keeps the nil-certificate contract: an empty
// pin, never a panic.
func TestTrustFetcherSPKIHash_Nil(t *testing.T) {
	assert.NotPanics(t, func() {
		assert.Equal(t, "", TrustFetcherSPKIHash(nil))
	})
}

// TestTrustFetcherSPKIHash_Cert matches the go-truststrap pin for a
// certificate.
func TestTrustFetcherSPKIHash_Cert(t *testing.T) {
	cert := parsedTestCert(t)
	assert.Equal(t, spkipin.ComputeSPKIPin(cert), TrustFetcherSPKIHash(cert))
}

// TestVerifySPKIPinnedConnection_LeafOnly proves the SDK verifier checks the
// leaf only: a pin of an intermediate in the chain is rejected, the leaf pin
// is accepted, and an empty pin or an absent chain fails closed.
func TestVerifySPKIPinnedConnection_LeafOnly(t *testing.T) {
	leaf := parsedTestCert(t)
	intermediate := parsedTestCert(t)
	chain := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, intermediate}}

	t.Run("leaf pin accepted", func(t *testing.T) {
		require.NoError(t, VerifySPKIPinnedConnection(spkipin.ComputeSPKIPin(leaf))(chain))
	})
	t.Run("upper-case leaf pin accepted", func(t *testing.T) {
		pin := spkipin.ComputeSPKIPin(leaf)
		upper := []byte(pin)
		for i, c := range upper {
			if c >= 'a' && c <= 'f' {
				upper[i] = c - 'a' + 'A'
			}
		}
		require.NoError(t, VerifySPKIPinnedConnection(string(upper))(chain))
	})
	t.Run("intermediate-only match rejected", func(t *testing.T) {
		err := VerifySPKIPinnedConnection(spkipin.ComputeSPKIPin(intermediate))(chain)
		require.ErrorIs(t, err, spkipin.ErrSPKIPinMismatch)
	})
	t.Run("empty pin rejected", func(t *testing.T) {
		err := VerifySPKIPinnedConnection("")(chain)
		require.ErrorIs(t, err, spkipin.ErrNoPinConfigured)
	})
	t.Run("absent certificates rejected", func(t *testing.T) {
		pin := spkipin.ComputeSPKIPin(leaf)
		require.ErrorIs(t, VerifySPKIPinnedConnection(pin)(tls.ConnectionState{}), spkipin.ErrNoCertificates)
		empty := tls.ConnectionState{PeerCertificates: []*x509.Certificate{}}
		require.ErrorIs(t, VerifySPKIPinnedConnection(pin)(empty), spkipin.ErrNoCertificates)
	})
}

// TestNewSPKIPinnedTLSConfig_LeafOnly proves the pinned config wires the
// same leaf-only verifier and its TLS 1.3 floor.
func TestNewSPKIPinnedTLSConfig_LeafOnly(t *testing.T) {
	leaf := parsedTestCert(t)
	intermediate := parsedTestCert(t)
	chain := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, intermediate}}

	cfg := NewSPKIPinnedTLSConfig(spkipin.ComputeSPKIPin(intermediate))
	require.NotNil(t, cfg.VerifyConnection)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	assert.True(t, cfg.SessionTicketsDisabled)
	require.ErrorIs(t, cfg.VerifyConnection(chain), spkipin.ErrSPKIPinMismatch)

	require.NoError(t, NewSPKIPinnedTLSConfig(spkipin.ComputeSPKIPin(leaf)).VerifyConnection(chain))
	require.ErrorIs(t, NewSPKIPinnedTLSConfig("").VerifyConnection(chain), spkipin.ErrNoPinConfigured)
	require.ErrorIs(t, NewSPKIPinnedTLSConfig("x").VerifyConnection(tls.ConnectionState{}), spkipin.ErrNoCertificates)
}
