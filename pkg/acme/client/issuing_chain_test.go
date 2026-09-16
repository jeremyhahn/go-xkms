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

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// twoCertChain returns a self-signed root and an intermediate it signed, as DER.
func twoCertChain(t *testing.T) (rootDER, interDER []byte) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root-ca.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err = x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ca01.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err = x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	require.NoError(t, err)
	return rootDER, interDER
}

// TestParseIssuingChain_PreservesServerOrder: the chain is ordered leaf-ward
// first, and a consumer that imports it depends on that order to walk from
// its own certificate up to a trust anchor.
func TestParseIssuingChain_PreservesServerOrder(t *testing.T) {
	rootDER, interDER := twoCertChain(t)

	chain, err := parseIssuingChain([][]byte{interDER, rootDER})
	require.NoError(t, err)
	require.Len(t, chain, 2)
	assert.Equal(t, "ca01.test", chain[0].Subject.CommonName)
	assert.Equal(t, "root-ca.test", chain[1].Subject.CommonName)
}

// TestParseIssuingChain_EmptyWhenServerSendsNone keeps an older enrollment
// server working: it returns only end-entity certificates, and that must
// enroll successfully rather than fail.
func TestParseIssuingChain_EmptyWhenServerSendsNone(t *testing.T) {
	chain, err := parseIssuingChain(nil)
	require.NoError(t, err)
	assert.Empty(t, chain)
}

// TestParseIssuingChain_RefusesAPartialChain: a malformed entry is an error,
// not a skip. Silently dropping it would hand back a chain that cannot reach
// a trust anchor, and the failure would surface much later.
func TestParseIssuingChain_RefusesAPartialChain(t *testing.T) {
	_, interDER := twoCertChain(t)

	_, err := parseIssuingChain([][]byte{interDER, []byte("not a certificate")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuing chain certificate 1")
}
