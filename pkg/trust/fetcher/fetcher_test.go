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

package fetcher

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeTestCA creates a self-signed CA cert and returns the cert + PEM bytes.
func makeTestCA(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Fetcher Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, pemBytes
}

// startBundleServer returns an httptest.NewTLSServer that serves either PEM
// or JSON based on the Accept header. It records the server's leaf cert.
func startBundleServer(t *testing.T, bundlePEM []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ca/bundle", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") == "" || strings.Contains(r.Header.Get("Accept"), "application/x-pem-file") {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bundlePEM)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(map[string]any{"bundle": bundlePEM})
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/api/v1/ca/bundle.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := json.Marshal(map[string]any{"bundle": bundlePEM})
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	})
	mux.HandleFunc("/garbage", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte("not a pem file"))
	})
	mux.HandleFunc("/empty", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		// PEM block of wrong type so tryParsePEM finds zero CERTIFICATE blocks.
		_, _ = w.Write([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"))
	})
	mux.HandleFunc("/badjson", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// serverPin returns the SPKI hash for the test server's leaf certificate.
func serverPin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	cert, err := x509.ParseCertificate(srv.Certificate().Raw)
	require.NoError(t, err)
	return SPKIHash(cert)
}

func TestFetch_PEM_HappyPath(t *testing.T) {
	t.Parallel()
	_, bundlePEM := makeTestCA(t)
	srv := startBundleServer(t, bundlePEM)
	pin := serverPin(t, srv)

	bundle, err := Fetch(context.Background(), srv.URL+"/api/v1/ca/bundle", Options{
		SPKIPin: pin,
	})
	require.NoError(t, err)
	require.NotNil(t, bundle)
	assert.NotEmpty(t, bundle.PEM)
	assert.Len(t, bundle.Certificates, 1)
	assert.Equal(t, "Fetcher Test CA", bundle.Certificates[0].Subject.CommonName)
	assert.Equal(t, pin, bundle.LeafSPKI)
	assert.True(t, strings.HasPrefix(bundle.Source, "platform:"))
}

func TestFetch_JSON_Fallback(t *testing.T) {
	t.Parallel()
	_, bundlePEM := makeTestCA(t)
	srv := startBundleServer(t, bundlePEM)
	pin := serverPin(t, srv)

	// Hit the JSON-only endpoint to force the fallback decoder path.
	bundle, err := Fetch(context.Background(), srv.URL+"/api/v1/ca/bundle.json", Options{
		SPKIPin: pin,
	})
	require.NoError(t, err)
	require.Len(t, bundle.Certificates, 1)
	assert.Equal(t, bundlePEM, bundle.PEM)
}

func TestFetch_PinMismatch(t *testing.T) {
	t.Parallel()
	_, bundlePEM := makeTestCA(t)
	srv := startBundleServer(t, bundlePEM)

	wrongPin := strings.Repeat("a", 64)
	_, err := Fetch(context.Background(), srv.URL+"/api/v1/ca/bundle", Options{
		SPKIPin: wrongPin,
	})
	require.Error(t, err)
	// http.Client.Do wraps the verify error in url.Error; use errors.Is to
	// reach through the wrapper.
	assert.True(t, errors.Is(err, ErrPinMismatch),
		"expected ErrPinMismatch, got: %v", err)
}

func TestFetch_HTTPError(t *testing.T) {
	t.Parallel()
	_, bundlePEM := makeTestCA(t)
	srv := startBundleServer(t, bundlePEM)
	pin := serverPin(t, srv)

	_, err := Fetch(context.Background(), srv.URL+"/error", Options{
		SPKIPin: pin,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrHTTPStatus))
	assert.Contains(t, err.Error(), "boom")
}

func TestFetch_InvalidPEM(t *testing.T) {
	t.Parallel()
	_, bundlePEM := makeTestCA(t)
	srv := startBundleServer(t, bundlePEM)
	pin := serverPin(t, srv)

	_, err := Fetch(context.Background(), srv.URL+"/garbage", Options{
		SPKIPin: pin,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPEM))
}

func TestFetch_EmptyBundle(t *testing.T) {
	t.Parallel()
	_, bundlePEM := makeTestCA(t)
	srv := startBundleServer(t, bundlePEM)
	pin := serverPin(t, srv)

	// /empty returns a PEM body that has no CERTIFICATE blocks. The PEM
	// parser succeeds (no error) but returns an empty cert list, which
	// the fall-through path treats as ErrInvalidPEM.
	_, err := Fetch(context.Background(), srv.URL+"/empty", Options{
		SPKIPin: pin,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPEM) || errors.Is(err, ErrEmptyBundle),
		"expected ErrInvalidPEM or ErrEmptyBundle, got: %v", err)
}

func TestFetch_BadJSON(t *testing.T) {
	t.Parallel()
	_, bundlePEM := makeTestCA(t)
	srv := startBundleServer(t, bundlePEM)
	pin := serverPin(t, srv)

	_, err := Fetch(context.Background(), srv.URL+"/badjson", Options{
		SPKIPin: pin,
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidJSON))
}

func TestFetch_InvalidURL(t *testing.T) {
	t.Parallel()
	_, err := Fetch(context.Background(), "http://insecure.example/", Options{
		SPKIPin: strings.Repeat("a", 64),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidURL))

	_, err = Fetch(context.Background(), "https://", Options{
		SPKIPin: strings.Repeat("a", 64),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidURL))

	_, err = Fetch(context.Background(), "://", Options{
		SPKIPin: strings.Repeat("a", 64),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidURL))
}

func TestFetch_PinRequired(t *testing.T) {
	t.Parallel()
	_, err := Fetch(context.Background(), "https://example.com/api/v1/ca/bundle", Options{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPinRequired))
}

func TestFetch_BadPin(t *testing.T) {
	t.Parallel()
	_, err := Fetch(context.Background(), "https://example.com/api/v1/ca/bundle", Options{
		SPKIPin: "deadbeef",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPin))
}

func TestNormalizePin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "lowercase_no_colons",
			input: strings.Repeat("a", 64),
			want:  strings.Repeat("a", 64),
		},
		{
			name:  "mixed_case_with_colons",
			input: "AB:CD:" + strings.Repeat("EF", 30),
			want:  strings.ToLower("ABCD" + strings.Repeat("EF", 30)),
		},
		{
			name:    "too_short",
			input:   "deadbeef",
			wantErr: true,
		},
		{
			name:    "non_hex",
			input:   strings.Repeat("z", 64),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizePin(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrInvalidPin))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSPKIHash_Stable(t *testing.T) {
	t.Parallel()
	cert, _ := makeTestCA(t)
	h1 := SPKIHash(cert)
	h2 := SPKIHash(cert)
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64)
}

func TestSPKIHash_Nil(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", SPKIHash(nil))
}

func TestPinVerifier_NoCerts(t *testing.T) {
	t.Parallel()
	verify := PinVerifier(strings.Repeat("a", 64))
	err := verify(nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNoLeafCert))
}

func TestPinVerifier_ParseError(t *testing.T) {
	t.Parallel()
	verify := PinVerifier(strings.Repeat("a", 64))
	err := verify([][]byte{{0x00, 0x01, 0x02}}, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPinMismatch))
}

func TestBuildTLSConfig_Pin(t *testing.T) {
	t.Parallel()
	cfg, err := BuildTLSConfig(strings.Repeat("a", 64))
	require.NoError(t, err)
	// Pin mode disables system chain validation; PinVerifier is the sole gate.
	assert.NotNil(t, cfg.VerifyPeerCertificate)
	// SessionTicketsDisabled must be true to prevent session resumption from
	// bypassing PinVerifier (CWE-295).
	assert.True(t, cfg.SessionTicketsDisabled)
}

func TestBuildTLSConfig_PinRequired(t *testing.T) {
	t.Parallel()
	_, err := BuildTLSConfig("")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPinRequired))
}

func TestBuildTLSConfig_BadPin(t *testing.T) {
	t.Parallel()
	_, err := BuildTLSConfig("deadbeef")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPin))
}
