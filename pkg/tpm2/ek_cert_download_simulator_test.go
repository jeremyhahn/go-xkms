//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingRoundTripper fails the test the moment RoundTrip is invoked. It
// proves a negative: that EKCertificate makes no outbound HTTP request when
// EKConfig.CertDownload is left at its default (false), the behaviour #761
// requires for an air-gapped host.
type failingRoundTripper struct {
	t *testing.T
}

func (f failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	f.t.Fatal("unexpected HTTP request: EK certificate download must stay disabled by default")
	return nil, nil
}

// TestEKCertificate_DownloadDisabled_NoNetworkCall proves that with
// EKConfig.CertDownload left at its default (false) and no local EK
// certificate available, EKCertificate reports the typed "not found" sentinel
// without ever invoking the HTTP client -- an air-gapped host must never
// block on a manufacturer download it did not ask for.
func TestEKCertificate_DownloadDisabled_NoNetworkCall(t *testing.T) {
	h := newSimHarnessWithHTTPClient(t, nil, &http.Client{Transport: failingRoundTripper{t: t}})

	_, err := h.TPM.EKCertificate()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEndorsementCertNotFound),
		"disabled download must still report the canonical not-found sentinel, got: %v", err)
}

// TestEKCertificate_DownloadEnabled_ReturnsCertFromManufacturer proves the
// end-to-end path: with CertDownload true and every local lookup exhausted,
// EKCertificate reaches the manufacturer EK certificate service (here an
// httptest server) and returns the certificate it serves.
func TestEKCertificate_DownloadEnabled_ReturnsCertFromManufacturer(t *testing.T) {
	wantCert := newSelfSignedTestCert(t)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wantCert.Raw)
	}))
	t.Cleanup(server.Close)

	h := newSimHarnessWithHTTPClient(t, func(c *Config) {
		c.EK.CertDownload = true
		c.EK.CertDownloadURL = server.URL + "/ekcertservice/"
	}, server.Client())

	cert, err := h.TPM.EKCertificate()
	require.NoError(t, err)
	assert.Equal(t, wantCert.Raw, cert.Raw)
}

// TestDownloadEKCertFromManufacturer_Success covers the download function
// directly (rather than through EKCertificate's NV/cert-store fallbacks) and
// accepts a PEM-encoded response, proving fetchEKCertFromService handles both
// encodings documented on EKConfig.CertDownloadURL.
func TestDownloadEKCertFromManufacturer_Success(t *testing.T) {
	wantCert := newSelfSignedTestCert(t)
	pemBytes := pemEncodeCert(t, wantCert)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(pemBytes)
	}))
	t.Cleanup(server.Close)

	h := newSimHarnessWithHTTPClient(t, func(c *Config) {
		c.EK.CertDownload = true
		c.EK.CertDownloadURL = server.URL + "/ekcertservice/"
	}, server.Client())

	cert, err := h.TPM.downloadEKCertFromManufacturer(tpm2.TPMHandle(ekCertIndexRSA2048))
	require.NoError(t, err)
	assert.Equal(t, wantCert.Raw, cert.Raw)
}

// TestDownloadEKCertFromManufacturer_Timeout proves a slow manufacturer
// service is bounded by EKConfig.CertDownloadTimeout rather than blocking the
// caller indefinitely -- the unbounded http.Get behaviour #761 reported.
func TestDownloadEKCertFromManufacturer_Timeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // hold the response past the client's bound
	}))
	t.Cleanup(server.Close)

	h := newSimHarnessWithHTTPClient(t, func(c *Config) {
		c.EK.CertDownload = true
		c.EK.CertDownloadURL = server.URL + "/ekcertservice/"
		c.EK.CertDownloadTimeout = 50 * time.Millisecond
	}, server.Client())

	start := time.Now()
	_, err := h.TPM.downloadEKCertFromManufacturer(tpm2.TPMHandle(ekCertIndexRSA2048))
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEKCertServiceUnreachable),
		"a request exceeding CertDownloadTimeout must report ErrEKCertServiceUnreachable, got: %v", err)
	assert.Less(t, elapsed, 2*time.Second,
		"the request must be bounded by CertDownloadTimeout, not block indefinitely")
}

// TestDownloadEKCertFromManufacturer_MalformedResponse proves a response
// that is neither valid DER nor PEM surfaces the typed parse-failure
// sentinel rather than an ad-hoc error, so callers can match on it.
func TestDownloadEKCertFromManufacturer_MalformedResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("this is not a certificate"))
	}))
	t.Cleanup(server.Close)

	h := newSimHarnessWithHTTPClient(t, func(c *Config) {
		c.EK.CertDownload = true
		c.EK.CertDownloadURL = server.URL + "/ekcertservice/"
	}, server.Client())

	_, err := h.TPM.downloadEKCertFromManufacturer(tpm2.TPMHandle(ekCertIndexRSA2048))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrEKCertServiceParseFailed),
		"a malformed response must report ErrEKCertServiceParseFailed, got: %v", err)
}

// newSelfSignedTestCert generates a throwaway self-signed certificate for
// EK-certificate-service response fixtures. It stands in for a manufacturer
// EK certificate; the download path never verifies its chain, so a
// self-signed certificate exercises the parse/validate logic exactly as a
// real one would.
func newSelfSignedTestCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ek-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

// pemEncodeCert PEM-encodes cert's DER bytes as a "CERTIFICATE" block.
func pemEncodeCert(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
