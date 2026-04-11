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

package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// truststrapTestBundle generates a self-signed CA certificate and returns
// both the parsed certificate and its PEM encoding.
func truststrapTestBundle(t *testing.T, commonName string) (*x509.Certificate, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes
}

// truststrapBundleHandler returns an http.Handler that serves the given PEM
// bundle at /v1/ca/bootstrap and 404 everywhere else.
func truststrapBundleHandler(t *testing.T, pemBundle []byte) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ca/bootstrap" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(pemBundle)
	})
}

// computeSPKIPin returns the hex-encoded SHA-256 hash of a certificate's
// Subject Public Key Info, matching the format expected by
// truststrap.SPKIConfig.SPKIPinSHA256.
func computeSPKIPin(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func TestImportFromTrustStrap_Direct_Success(t *testing.T) {
	_, pemBundle := truststrapTestBundle(t, "Truststrap Direct CA")

	srv := httptest.NewServer(truststrapBundleHandler(t, pemBundle))
	defer srv.Close()

	store := newTestFileStore(t)
	svc := NewTrustService(store)

	var mutateCalled atomic.Int32
	svc.SetOnMutate(func() { mutateCalled.Add(1) })

	added, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method: "direct",
		Server: srv.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, added, "one certificate must be imported")
	assert.Equal(t, int32(1), mutateCalled.Load(), "notifyMutate must fire exactly once on success")

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, count, "trust store must contain the imported certificate")
}

func TestImportFromTrustStrap_Direct_MultipleCerts(t *testing.T) {
	_, pem1 := truststrapTestBundle(t, "Truststrap Multi CA 1")
	_, pem2 := truststrapTestBundle(t, "Truststrap Multi CA 2")
	combined := append(append([]byte{}, pem1...), pem2...)

	srv := httptest.NewServer(truststrapBundleHandler(t, combined))
	defer srv.Close()

	svc := NewTrustService(newTestFileStore(t))

	added, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method: "direct",
		Server: srv.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, added, "both certificates in the bundle must be imported")
}

func TestImportFromTrustStrap_Direct_CustomBundlePath(t *testing.T) {
	_, pemBundle := truststrapTestBundle(t, "Truststrap Custom Path CA")

	mux := http.NewServeMux()
	mux.HandleFunc("/custom/bundle", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(pemBundle)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := NewTrustService(newTestFileStore(t))

	added, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method:     "direct",
		Server:     srv.URL,
		BundlePath: "/custom/bundle",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, added)
}

func TestImportFromTrustStrap_Direct_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	svc := NewTrustService(newTestFileStore(t))
	var mutateCalled atomic.Int32
	svc.SetOnMutate(func() { mutateCalled.Add(1) })

	_, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method: "direct",
		Server: srv.URL,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTrustStrapFetch)
	assert.Equal(t, int32(0), mutateCalled.Load(), "notifyMutate must not fire on fetch error")
}

func TestImportFromTrustStrap_Direct_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
	}))
	defer srv.Close()

	svc := NewTrustService(newTestFileStore(t))

	_, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method: "direct",
		Server: srv.URL,
	})
	require.Error(t, err, "empty bundle body must fail")
	require.ErrorIs(t, err, ErrTrustStrapFetch)
}

func TestImportFromTrustStrap_Direct_GarbageResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write([]byte("not a pem certificate, not even close"))
	}))
	defer srv.Close()

	svc := NewTrustService(newTestFileStore(t))

	_, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method: "direct",
		Server: srv.URL,
	})
	require.Error(t, err, "non-PEM payload must fail to parse")
}

func TestImportFromTrustStrap_Direct_Unreachable(t *testing.T) {
	svc := NewTrustService(newTestFileStore(t))

	// Bind to an ephemeral port then close the listener so the URL is
	// reachable syntactically but the connection is refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	_, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method: "direct",
		Server: url,
	})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrTrustStrapFetch)
}

func TestImportFromTrustStrap_SPKI_Success(t *testing.T) {
	_, pemBundle := truststrapTestBundle(t, "Truststrap SPKI CA")

	srv := httptest.NewTLSServer(truststrapBundleHandler(t, pemBundle))
	defer srv.Close()

	// Extract the SPKI pin from the httptest server's serving certificate.
	require.NotNil(t, srv.TLS)
	require.NotEmpty(t, srv.TLS.Certificates)
	require.NotEmpty(t, srv.TLS.Certificates[0].Certificate)
	serverCert, err := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	require.NoError(t, err)

	pin := computeSPKIPin(t, serverCert)

	store := newTestFileStore(t)
	svc := NewTrustService(store)

	added, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method:        "spki",
		Server:        srv.URL,
		SPKIPinSHA256: pin,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, added)

	count, err := store.Count()
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestImportFromTrustStrap_SPKI_WrongPin(t *testing.T) {
	_, pemBundle := truststrapTestBundle(t, "Truststrap SPKI Wrong Pin CA")

	srv := httptest.NewTLSServer(truststrapBundleHandler(t, pemBundle))
	defer srv.Close()

	svc := NewTrustService(newTestFileStore(t))

	// A pin that is syntactically valid (64 hex chars) but does not match
	// the server's public key.
	wrongPin := strings.Repeat("00", 32)

	_, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method:        "spki",
		Server:        srv.URL,
		SPKIPinSHA256: wrongPin,
	})
	require.Error(t, err, "wrong SPKI pin must reject the connection")
	require.ErrorIs(t, err, ErrTrustStrapFetch)
}

func TestImportFromTrustStrap_NotifyMutate_NotFiredOnZeroAdded(t *testing.T) {
	cert, pemBundle := truststrapTestBundle(t, "Truststrap Zero Added CA")

	srv := httptest.NewServer(truststrapBundleHandler(t, pemBundle))
	defer srv.Close()

	store := newTestFileStore(t)
	// Pre-populate the store with the same cert so that the import adds 0.
	require.NoError(t, store.AddCertificate(cert))

	svc := NewTrustService(store)
	var mutateCalled atomic.Int32
	svc.SetOnMutate(func() { mutateCalled.Add(1) })

	added, err := svc.ImportFromTrustStrap(TrustStrapImportRequest{
		Method: "direct",
		Server: srv.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, added, "duplicate cert must report 0 added")
	assert.Equal(t, int32(0), mutateCalled.Load(),
		"notifyMutate must not fire when nothing was added")
}
