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

package xkmsdtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// servingCert issues a localhost serving certificate signed by parent, or
// self-signed, as xkmsd's bootstrap certificate is, when parent is nil.
func servingCert(t *testing.T, parent *issuedCert) *issuedCert {
	t.Helper()
	return issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, parent)
}

// barrierNode is a fake xkmsd serving TLS with presented. A sealed node is
// its sealed window: it refuses /health with 503 and reports state on
// /v1/barrier/status. An unsealed node is the full server: it answers
// /health and refuses the unauthenticated status read with 401. Every
// unseal is counted and answered 204.
type barrierNode struct {
	*httptest.Server
	unseals atomic.Int32
}

func newBarrierNode(t *testing.T, presented *issuedCert, sealed bool, state BarrierState) *barrierNode {
	t.Helper()
	cert, err := tls.X509KeyPair(presented.certPEM, presented.keyPEM)
	require.NoError(t, err)
	node := &barrierNode{}
	node.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/barrier/unseal":
			node.unseals.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/health" && sealed:
			w.WriteHeader(http.StatusServiceUnavailable)
		case r.URL.Path == "/health":
			w.WriteHeader(http.StatusOK)
		case !sealed:
			w.WriteHeader(http.StatusUnauthorized)
		default:
			require.NoError(t, json.NewEncoder(w).Encode(state))
		}
	}))
	node.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	node.StartTLS()
	t.Cleanup(node.Close)
	return node
}

// persistAnchors writes the bootstrap certificate, and the CA bundle when
// bundle is not nil, where xkmsd persists them under its datastore path data,
// and returns the bootstrap certificate's path.
func persistAnchors(t *testing.T, data string, bootstrap, bundle []byte) string {
	t.Helper()
	certPath := bootstrapCertPath(data)
	require.NoError(t, os.MkdirAll(filepath.Dir(certPath), 0o700))
	require.NoError(t, os.WriteFile(certPath, bootstrap, 0o600))
	if bundle != nil {
		require.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(certPath), unifiedCABundleFile), bundle, 0o600))
	}
	return certPath
}

func openBarrier(t *testing.T, certPath, url string, timeout time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client, err := SealedWindowClient(ctx, certPath)
	require.NoError(t, err)
	return OpenBarrier(ctx, client, url, []byte(barrierPassphrase))
}

func TestOpenBarrier_UnsealsASealedWindow(t *testing.T) {
	bootstrap := servingCert(t, nil)
	node := newBarrierNode(t, bootstrap, true, BarrierState{Sealed: true, InitializedAt: "2026-10-25T00:00:00Z"})

	err := openBarrier(t, persistAnchors(t, t.TempDir(), bootstrap.certPEM, nil), node.URL, 30*time.Second)
	require.NoError(t, err)
	require.EqualValues(t, 1, node.unseals.Load())
}

func TestOpenBarrier_UninitializedBarrierIsNeverUnsealed(t *testing.T) {
	bootstrap := servingCert(t, nil)
	node := newBarrierNode(t, bootstrap, true, BarrierState{Sealed: true})

	err := openBarrier(t, persistAnchors(t, t.TempDir(), bootstrap.certPEM, nil), node.URL, 30*time.Second)
	require.ErrorIs(t, err, ErrBarrierUninitialized)
	require.Zero(t, node.unseals.Load())
}

// TestOpenBarrier_LeavesAnUnsealedNodeOnItsCAIssuedCertificateAlone proves
// the case every suite after the first meets (DS-3769): the node is already
// unsealed, serves the certificate its CA issued, which only the persisted CA
// bundle verifies, and refuses the anonymous status read with 401.
func TestOpenBarrier_LeavesAnUnsealedNodeOnItsCAIssuedCertificateAlone(t *testing.T) {
	ca := issue(t, &x509.Certificate{
		SerialNumber:          big.NewInt(5),
		Subject:               pkix.Name{CommonName: "xkmsdtest Root CA"},
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil)
	node := newBarrierNode(t, servingCert(t, ca), false, BarrierState{})

	err := openBarrier(t, persistAnchors(t, t.TempDir(), servingCert(t, nil).certPEM, ca.certPEM), node.URL, 30*time.Second)
	require.NoError(t, err)
	require.Zero(t, node.unseals.Load(), "an unsealed node is never sent the passphrase")
}

func TestOpenBarrier_NodeTheAnchorsDoNotVerifyIsNeverSentThePassphrase(t *testing.T) {
	impostor := servingCert(t, nil)
	node := newBarrierNode(t, impostor, true, BarrierState{Sealed: true, InitializedAt: "2026-10-25T00:00:00Z"})

	err := openBarrier(t, persistAnchors(t, t.TempDir(), servingCert(t, nil).certPEM, nil), node.URL, 4*retryInterval)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	var unverified x509.UnknownAuthorityError
	require.True(t, errors.As(err, &unverified), "the error names the unverified server: %v", err)
	require.Zero(t, node.unseals.Load())
}

func TestSealedWindowClient_UnparsableCABundleIsReported(t *testing.T) {
	certPath := persistAnchors(t, t.TempDir(), servingCert(t, nil).certPEM, []byte("not a certificate"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*retryInterval)
	defer cancel()

	_, err := SealedWindowClient(ctx, certPath)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorIs(t, err, ErrNoAnchor)
}
