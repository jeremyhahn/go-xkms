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

package rest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// accessClaims decodes a minted access token without verifying it, so a test
// can read exactly which claims the exchange put on it.
func accessClaims(t *testing.T, tokenString string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	require.NoError(t, err)
	return claims
}

// attestationAuthority stands in for a vendor's PIV attestation CA: it can
// attest any public key, which is exactly why the exchange must bind the
// attested key to the login key rather than trust the chain alone.
type attestationAuthority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newAttestationAuthority(t *testing.T) *attestationAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test PIV Attestation Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &attestationAuthority{cert: cert, key: key, pool: pool}
}

// attest issues the attestation certificate a device would present for a
// slot holding pub: signed by the authority, carrying pub.
func (a *attestationAuthority) attest(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "PIV Attestation 9a"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, pub, a.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// pivRequestWithChain builds a cert-login request presenting the login
// certificate and the chain material after it.
func pivRequestWithChain(certs ...*x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/piv", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: certs}
	return req
}

func newAttestedLoginServer(t *testing.T, authority *attestationAuthority, allowUnattested bool) *Server {
	t.Helper()
	return newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{
			Enabled:          true,
			AttestationRoots: authority.pool,
			AllowUnattested:  allowUnattested,
		}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{
			Username: "alice", Role: "admin", TenantID: "system", Enabled: true,
		}}
	})
}

// A certificate that chains to the configured attestation anchor and carries
// the login key proves the key is on a smartcard; the token says so.
func TestPIVLogin_AttestedKeyIsAcceptedAsHardware(t *testing.T) {
	authority := newAttestationAuthority(t)
	server := newAttestedLoginServer(t, authority, false)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	login := generateTestCertificate(t, key)
	attestation := authority.attest(t, &key.PublicKey)

	w := doAuthRequest(t, server, pivRequestWithChain(login, attestation))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp authTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, PIVAttestLevelHardware, accessClaims(t, resp.AccessToken)["attest_level"])
}

// A self-signed slot certificate presents nothing that chains to the anchor:
// a DN is not evidence, and the login is refused.
func TestPIVLogin_SelfSignedCertificateIsRefused(t *testing.T) {
	authority := newAttestationAuthority(t)
	server := newAttestedLoginServer(t, authority, false)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	login := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequestWithChain(login))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "not hardware-attested")
}

// A genuine attestation borrowed from another card attests a different key
// than the one the TLS handshake proved possession of, so it launders
// nothing: the binding is on the SubjectPublicKeyInfo, not on the chain.
func TestPIVLogin_AttestationForAnotherKeyIsRefused(t *testing.T) {
	authority := newAttestationAuthority(t)
	server := newAttestedLoginServer(t, authority, false)

	loginKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	login := generateTestCertificate(t, loginKey)
	borrowed := authority.attest(t, &otherKey.PublicKey)

	w := doAuthRequest(t, server, pivRequestWithChain(login, borrowed))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// An attestation signed by an authority the deployment does not trust is
// chain material from the client, never an anchor.
func TestPIVLogin_UntrustedAttestationAuthorityIsRefused(t *testing.T) {
	trusted := newAttestationAuthority(t)
	rogue := newAttestationAuthority(t)
	server := newAttestedLoginServer(t, trusted, false)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	login := generateTestCertificate(t, key)
	attestation := rogue.attest(t, &key.PublicKey)

	w := doAuthRequest(t, server, pivRequestWithChain(login, attestation, rogue.cert))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// With no anchor configured the exchange refuses rather than assumes
// hardware; the explicit opt-out accepts and records the login as unattested.
func TestPIVLogin_NoAnchorRefusesUnlessUnattestedIsAllowed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	login := generateTestCertificate(t, key)
	user := &fakeAuthUserStore{user: auth.MTLSUser{Username: "alice", Enabled: true}}

	strict := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true}
		c.AuthUserStore = user
	})
	w := doAuthRequest(t, strict, pivRequestWithChain(login))
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	lenient := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true, AllowUnattested: true}
		c.AuthUserStore = user
	})
	w = doAuthRequest(t, lenient, pivRequestWithChain(login))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp authTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, PIVAttestLevelUnattested, accessClaims(t, resp.AccessToken)["attest_level"])
}

// With an anchor configured and the opt-out set, a proven key still records
// hardware: the opt-out widens what is accepted, not what is claimed.
func TestPIVLogin_AllowUnattestedStillRecordsProvenHardware(t *testing.T) {
	authority := newAttestationAuthority(t)
	server := newAttestedLoginServer(t, authority, true)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	login := generateTestCertificate(t, key)

	w := doAuthRequest(t, server, pivRequestWithChain(login, authority.attest(t, &key.PublicKey)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp authTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, PIVAttestLevelHardware, accessClaims(t, resp.AccessToken)["attest_level"])

	w = doAuthRequest(t, server, pivRequestWithChain(login))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, PIVAttestLevelUnattested, accessClaims(t, resp.AccessToken)["attest_level"])
}
