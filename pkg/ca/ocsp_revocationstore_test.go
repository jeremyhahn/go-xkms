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
	"crypto"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	gocsp "golang.org/x/crypto/ocsp"
)

// TestOCSPCheckCertificateStatus_ColdPath_RevocationStore is the replicated-
// state regression guard for go-xkms#275: before this fix,
// checkCertificateStatus's cold path only consulted ca.objectStore, so a CA
// configured with only the datastore-backed revocationStore (the preferred,
// replicated store -- see putRevocationBlob) never saw a revocation written
// by another process/instance once its in-memory map was reset. This models
// exactly that: a fresh in-memory map over a revocationStore that already
// holds the record.
//
// NOTE: NOT parallel -- mutates the shared CA revocation map.
func TestOCSPCheckCertificateStatus_ColdPath_RevocationStore(t *testing.T) {
	ca := setupTestCAWithRevocationStore(t)

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject: Subject{CommonName: "ocsp-cold-revocationstore"},
		Valid:   365,
	})
	require.NoError(t, err)
	cert := issued.Certificate
	require.NotNil(t, cert)

	require.NoError(t, ca.RevokeCert(context.Background(), cert, RevokeOptions{}))

	// Clear the in-memory revocations map to force the cold path, as if this
	// were a fresh process that has not (re)loaded persisted state yet.
	ca.revocationsMutex.Lock()
	ca.revocations = make(map[string]*RevocationInfo)
	ca.revocationsMutex.Unlock()

	issuerCert := ca.rootCert
	require.NotNil(t, issuerCert)
	ocspReqDER, err := gocsp.CreateRequest(cert, issuerCert, &gocsp.RequestOptions{Hash: crypto.SHA256})
	require.NoError(t, err)

	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())
	resp, handleErr := responder.HandleRequest(context.Background(), ocspReqDER)
	require.NoError(t, handleErr)

	ocspResp, parseErr := gocsp.ParseResponse(resp, issuerCert)
	require.NoError(t, parseErr)
	require.Equal(t, gocsp.Revoked, ocspResp.Status)
}

// TestOCSPCheckCertificateStatus_ColdPath_RevocationStore_NotRevoked is the
// error-handling counterpart: a serial with no revocation record in the
// revocationStore must answer ocsp.Good, not ocsp.Unknown or an error.
func TestOCSPCheckCertificateStatus_ColdPath_RevocationStore_NotRevoked(t *testing.T) {
	ca := setupTestCAWithRevocationStore(t)
	responder := NewOCSPResponder(ca, DefaultOCSPResponderConfig())

	status, _, _, err := responder.checkCertificateStatus(context.Background(), big.NewInt(424242))
	require.NoError(t, err)
	require.Equal(t, gocsp.Good, status)
}
