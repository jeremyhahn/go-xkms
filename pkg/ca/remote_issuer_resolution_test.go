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

package ca

import (
	"context"
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

// remoteIssuedIdentity builds what an enrollment server hands a device: an
// end-entity certificate issued by a REMOTE CA, plus that CA's issuing chain.
// Nothing here is signed by the local CA under test.
func remoteIssuedIdentity(t *testing.T) (leaf, intermediate, root *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "root-ca.cp.remote.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err = x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ca01.cp.remote.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey)
	require.NoError(t, err)
	intermediate, err = x509.ParseCertificate(interDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "device.remote.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, intermediate, &leafKey.PublicKey, interKey)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return leaf, intermediate, root
}

// TestRootCertificate_ResolvesARemoteIssuerOnceItsChainIsImported is the
// regression for the defect behind go-trusted-platform#653.
//
// A device enrolled over ACME enroll-01 receives an IDevID issued by the
// ENROLLMENT SERVER's CA. RootCertificate walks only this CA's own store and
// cached root/intermediate, so it cannot resolve that issuer — every enrolled
// node therefore compiled a caller-admission policy that admitted nobody. The
// enrollment response now carries the issuing chain (RFC 8555 §7.4.2), and
// importing it is what makes the walk terminate.
//
// The first half of this test is the pre-fix behaviour and must keep failing
// to resolve: that is what proves the second half is doing the work.
func TestRootCertificate_ResolvesARemoteIssuerOnceItsChainIsImported(t *testing.T) {
	ca := setupTestCA(t)
	ctx := context.Background()

	leaf, intermediate, root := remoteIssuedIdentity(t)

	// Before the chain is imported the issuer is simply unknown here.
	_, err := ca.RootCertificate(leaf)
	require.Error(t, err, "a remote issuer must not resolve out of a local store that never saw it")

	// What the enrollment client now hands back, in server order.
	for _, c := range []*x509.Certificate{intermediate, root} {
		require.NoError(t, ca.ImportCertificate(ctx, c))
	}

	got, err := ca.RootCertificate(leaf)
	require.NoError(t, err, "the imported chain must let the walk terminate")
	require.NotNil(t, got)
	assert.Equal(t, "root-ca.cp.remote.test", got.Subject.CommonName)
	assert.Equal(t, got.Subject.CommonName, got.Issuer.CommonName, "the result is the self-signed root")
}
