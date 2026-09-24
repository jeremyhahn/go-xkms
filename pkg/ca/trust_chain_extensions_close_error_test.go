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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTrustedRootCertPoolWithXSigner_ReaderCloseErrorStillIncludesCert
// verifies that a Close failure on the object-store reader behind
// getXSignedCertificates does not cause a successfully parsed cross-signed
// root to be dropped from the pool (#701): the certificate was already read
// and parsed correctly, so only the cleanup step failed, and the caller
// gates on the result rather than the error.
func TestTrustedRootCertPoolWithXSigner_ReaderCloseErrorStillIncludesCert(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	ca.mu.RLock()
	root := ca.rootCert
	ca.mu.RUnlock()
	require.NotNil(t, root)

	xsignedRoot, _ := makeSelfSignedCert(t, root.Subject.CommonName)
	require.NoError(t, ca.ImportXSignedCertificate("foreign-issuer", xsignedRoot))

	closeErr := errors.New("trust_chain_extensions_close_error_test: simulated reader close failure")
	ca.objectStore = &failCloseStore{Storage: ca.objectStore, closeErr: closeErr}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pool, err := ca.TrustedRootCertPoolWithXSigner(root, key)
	require.NoError(t, err)
	require.NotNil(t, pool)

	// The cross-signed root must still be in the pool despite the Close
	// failure: it verifies against itself as a trusted root.
	_, verifyErr := xsignedRoot.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	require.NoError(t, verifyErr)
}
