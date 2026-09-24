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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestXSignedCertificate_ReaderCloseErrorSurfaces verifies that a Close
// failure on the object-store reader backing readCrossSignedCertificate is
// reported to the caller rather than silently discarded (#701).
func TestXSignedCertificate_ReaderCloseErrorSurfaces(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	cert, _ := makeSelfSignedCert(t, "leaf-close-err")
	require.NoError(t, ca.ImportXSignedCertificate("issuer-close-err", cert))

	closeErr := errors.New("cross_signing_close_error_test: simulated reader close failure")
	ca.objectStore = &failCloseStore{Storage: ca.objectStore, closeErr: closeErr}

	_, err := ca.XSignedCertificate("issuer-close-err", &types.KeyAttributes{CN: "leaf-close-err"})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrStorageError)
	require.Contains(t, err.Error(), closeErr.Error())
}

// TestCrossSignedPEM_ReaderCloseErrorSurfaces verifies that a Close failure
// while aggregating cross-signed entries is joined into CrossSignedPEM's
// returned error rather than silently discarded (#701), even though the
// bundle itself is still returned since the entry was already read.
func TestCrossSignedPEM_ReaderCloseErrorSurfaces(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	cert, _ := makeSelfSignedCert(t, "leaf-bundle-close-err")
	require.NoError(t, ca.ImportXSignedCertificate("issuer-bundle-close-err", cert))

	closeErr := errors.New("cross_signing_close_error_test: simulated bundle reader close failure")
	ca.objectStore = &failCloseStore{Storage: ca.objectStore, closeErr: closeErr}

	pemBundle, err := ca.CrossSignedPEM(&types.KeyAttributes{CN: "leaf-bundle-close-err"})
	require.NotEmpty(t, pemBundle, "the entry was read successfully before Close failed")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrStorageError)
	require.Contains(t, err.Error(), closeErr.Error())
}

// TestGetXSignedCertificates_ReaderCloseErrorSurfaces verifies the same for
// getXSignedCertificates, the internal helper used by the cross-sign-aware
// trust pool builders.
func TestGetXSignedCertificates_ReaderCloseErrorSurfaces(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	cert, _ := makeSelfSignedCert(t, "leaf-getx-close-err")
	require.NoError(t, ca.ImportXSignedCertificate("issuer-getx-close-err", cert))

	closeErr := errors.New("cross_signing_close_error_test: simulated getx reader close failure")
	ca.objectStore = &failCloseStore{Storage: ca.objectStore, closeErr: closeErr}

	certs, err := ca.getXSignedCertificates("leaf-getx-close-err")
	require.Len(t, certs, 1, "the entry was parsed successfully before Close failed")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrStorageError)
	require.Contains(t, err.Error(), closeErr.Error())
}
