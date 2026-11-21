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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const revokedSerialList = `{"entries":{"2c8cdddfd5e03bfc":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}`

var revokedSerial = new(big.Int).SetUint64(0x2c8cdddfd5e03bfc)

func TestNewAndroidHTTPStatusList_FetchesTheConfiguredURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		if _, err := w.Write([]byte(revokedSerialList)); err != nil {
			return
		}
	}))
	t.Cleanup(server.Close)

	source, err := NewAndroidHTTPStatusList(AndroidHTTPStatusListOptions{URL: server.URL})
	require.NoError(t, err)
	assert.Equal(t, server.URL, source.URL())

	list, err := source.Current()
	require.NoError(t, err)
	entry, listed := list.Lookup(revokedSerial)
	assert.True(t, listed)
	assert.Equal(t, "REVOKED", string(entry.Status))
}

func TestNewAndroidHTTPStatusList_Errors(t *testing.T) {
	_, err := NewAndroidHTTPStatusList(AndroidHTTPStatusListOptions{URL: "ftp://mirror.test/status"})
	require.ErrorIs(t, err, ErrAndroidInvalidStatusListURL)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	source, err := NewAndroidHTTPStatusList(AndroidHTTPStatusListOptions{URL: server.URL})
	require.NoError(t, err)
	_, err = source.Current()
	require.ErrorIs(t, err, ErrAndroidStatusListUnavailable, "an unfetchable list fails closed")
}

func TestParseAndroidStatusList(t *testing.T) {
	list, err := ParseAndroidStatusList([]byte(revokedSerialList))
	require.NoError(t, err)
	assert.Equal(t, 1, list.Len())

	_, err = ParseAndroidStatusList([]byte(`{"entries":{"ab":{"status":"VALID"}}}`))
	require.ErrorIs(t, err, ErrAndroidStatusListMalformed)
}

func TestLoadAndroidStatusListFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	require.NoError(t, os.WriteFile(path, []byte(revokedSerialList), 0o600))

	list, err := LoadAndroidStatusListFile(path)
	require.NoError(t, err)
	_, listed := list.Lookup(revokedSerial)
	assert.True(t, listed)

	_, err = LoadAndroidStatusListFile(filepath.Join(dir, "absent.json"))
	require.ErrorIs(t, err, ErrAndroidStatusListUnavailable)
}

// TestWithAttestationRevocation shows the option is what lets
// VerifyAndroidAttestation past its revocation gate: without it the verifier
// refuses before looking at the chain.
func TestWithAttestationRevocation(t *testing.T) {
	chain := []*x509.Certificate{selfSignedRevocationTestCert(t)}
	nonce := []byte("nonce")

	_, err := NewAttestationVerifier(nil).VerifyAndroidAttestation(chain, nonce)
	require.ErrorIs(t, err, ErrNoAndroidRevocationSource)

	verifier := NewAttestationVerifier(nil, WithAttestationRevocation(&AndroidStatusList{}))
	_, err = verifier.VerifyAndroidAttestation(chain, nonce)
	require.Error(t, err, "a verifier without a trust store still refuses")
	assert.NotErrorIs(t, err, ErrNoAndroidRevocationSource)
}

func selfSignedRevocationTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "revocation test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}
