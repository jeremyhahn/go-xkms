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
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
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

// attestationAuthority stands in for a vendor's PIV attestation CA, or for a
// device attestation certificate (slot f9) under it: it can attest any public
// key, which is exactly why the exchange must bind the attested key to the
// login key rather than trust the chain alone.
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

// device issues the device attestation certificate (slot f9) a YubiKey
// carries under the vendor root, and returns it as an authority of its own.
func (a *attestationAuthority) device(t *testing.T) *attestationAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Test PIV Device Attestation"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &attestationAuthority{cert: cert, key: key}
}

// issue signs a certificate for pub carrying exts.
func (a *attestationAuthority) issue(t *testing.T, pub crypto.PublicKey, exts []pkix.Extension) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "PIV Attestation 9a"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, pub, a.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// attest issues the slot attestation certificate a device would present for
// a slot holding pub, carrying the claims of slotClaims.
func (a *attestationAuthority) attest(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
	t.Helper()
	return a.attestWith(t, pub, slotClaims())
}

// attestWith issues a slot attestation certificate carrying claims.
func (a *attestationAuthority) attestWith(t *testing.T, pub crypto.PublicKey, claims *pivcert.Attestation) *x509.Certificate {
	t.Helper()
	exts, err := pivcert.BuildAttestationExtensions(claims)
	require.NoError(t, err)
	return a.issue(t, pub, exts)
}

// slotClaims returns the claims every PIV slot attestation carries.
func slotClaims() *pivcert.Attestation {
	serial := uint64(12345678)
	pin := pivcert.PINPolicyOnce
	touch := pivcert.TouchPolicyAlways
	return &pivcert.Attestation{
		FirmwareVersion: &pivcert.FirmwareVersion{Major: 5, Minor: 7, Patch: 1},
		SerialNumber:    &serial,
		PINPolicy:       &pin,
		TouchPolicy:     &touch,
	}
}

// pivRequestWithChain builds a cert-login request presenting the login
// certificate and the chain material after it.
func pivRequestWithChain(certs ...*x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/piv", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: certs}
	return req
}

func newAttestedLoginServer(t *testing.T, authority *attestationAuthority, auditLog *mockAuthAuditLogger, mutate func(*PIVLoginOptions)) *Server {
	t.Helper()
	return newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{
			Enabled:          true,
			AttestationRoots: authority.pool,
		}
		if mutate != nil {
			mutate(c.PIVLogin)
		}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{
			Username: "alice", Roles: []string{"admin"}, TenantID: "system", Enabled: true,
		}}
		c.AuditLogger = auditLog
	})
}

// recordedAs wires a RecordedLevel that reports level for every certificate.
func recordedAs(level types.AttestLevel) func(*PIVLoginOptions) {
	return func(o *PIVLoginOptions) {
		o.RecordedLevel = func(*x509.Certificate) (types.AttestLevel, bool) { return level, true }
	}
}

// requireTouchAlways is a deployment AttestationPolicy demanding a touch for
// every use of the slot key.
func requireTouchAlways(o *PIVLoginOptions) {
	o.AttestationPolicy = func(att *pivcert.Attestation) error {
		if *att.TouchPolicy != pivcert.TouchPolicyAlways {
			return errors.New("touch policy must be always")
		}
		return nil
	}
}

// With attestation roots configured the exchange is strict: a login proves
// its key with a separate slot attestation that chains to a configured root,
// carries the login key, and satisfies the PIV attestation profile, or it is
// refused with a stable reason on the audit record and a generic answer on
// the wire.
func TestPIVLogin_StrictAttestation(t *testing.T) {
	trusted := newAttestationAuthority(t)
	rogue := newAttestationAuthority(t)
	device := trusted.device(t)

	loginKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	login := generateTestCertificate(t, loginKey)
	pub := &loginKey.PublicKey

	noPolicies := slotClaims()
	noPolicies.PINPolicy, noPolicies.TouchPolicy = nil, nil
	unknownTouch := slotClaims()
	touch := pivcert.TouchPolicy(0x7f)
	unknownTouch.TouchPolicy = &touch
	touchNever := slotClaims()
	never := pivcert.TouchPolicyNever
	touchNever.TouchPolicy = &never
	malformedFirmware, err := pivcert.BuildAttestationExtensions(slotClaims())
	require.NoError(t, err)
	malformedFirmware[0].Value = []byte{5, 7}

	tests := []struct {
		name    string
		peers   []*x509.Certificate
		options func(*PIVLoginOptions)
		refusal PIVAttestationRefusal
	}{
		{
			name:  "slot attestation for the login key",
			peers: []*x509.Certificate{login, trusted.attest(t, pub)},
		},
		{
			name:  "slot attestation under the device attestation certificate",
			peers: []*x509.Certificate{login, device.attest(t, pub), device.cert},
		},
		{
			name:    "no attestation presented",
			peers:   []*x509.Certificate{login},
			refusal: PIVRefusalNoEvidence,
		},
		{
			name:    "login certificate chaining to the root is not its own evidence",
			peers:   []*x509.Certificate{trusted.attest(t, pub)},
			refusal: PIVRefusalNoEvidence,
		},
		{
			name:    "login certificate presented twice is not evidence",
			peers:   []*x509.Certificate{login, login},
			refusal: PIVRefusalNoEvidence,
		},
		{
			name:    "attestation under an untrusted root",
			peers:   []*x509.Certificate{login, rogue.attest(t, pub), rogue.cert},
			refusal: PIVRefusalUntrustedChain,
		},
		{
			name:    "attestation for another key",
			peers:   []*x509.Certificate{login, trusted.attest(t, &otherKey.PublicKey)},
			refusal: PIVRefusalKeyMismatch,
		},
		{
			name:    "key mismatch outranks an untrusted candidate",
			peers:   []*x509.Certificate{login, rogue.attest(t, pub), trusted.attest(t, &otherKey.PublicKey)},
			refusal: PIVRefusalKeyMismatch,
		},
		{
			name:    "trusted certificate for the login key without attestation claims",
			peers:   []*x509.Certificate{login, trusted.issue(t, pub, nil)},
			refusal: PIVRefusalProfile,
		},
		{
			name:    "attestation without the PIN and touch policy",
			peers:   []*x509.Certificate{login, trusted.attestWith(t, pub, noPolicies)},
			refusal: PIVRefusalProfile,
		},
		{
			name:    "attestation with an unrecognised touch policy",
			peers:   []*x509.Certificate{login, trusted.attestWith(t, pub, unknownTouch)},
			refusal: PIVRefusalProfile,
		},
		{
			name:    "attestation with an undecodable extension",
			peers:   []*x509.Certificate{login, trusted.issue(t, pub, malformedFirmware)},
			refusal: PIVRefusalProfile,
		},
		{
			name:    "attestation the deployment policy accepts",
			peers:   []*x509.Certificate{login, trusted.attest(t, pub)},
			options: requireTouchAlways,
		},
		{
			name:    "attestation the deployment policy refuses",
			peers:   []*x509.Certificate{login, trusted.attestWith(t, pub, touchNever)},
			options: requireTouchAlways,
			refusal: PIVRefusalAttestationPolicy,
		},
		{
			name:    "recorded hardware level is not evidence",
			peers:   []*x509.Certificate{login},
			options: recordedAs(types.AttestLevelHardware),
			refusal: PIVRefusalNoEvidence,
		},
		{
			name:    "recorded hardware level with evidence",
			peers:   []*x509.Certificate{login, trusted.attest(t, pub)},
			options: recordedAs(types.AttestLevelHardware),
		},
		{
			name:    "recorded software level is not upgraded by evidence",
			peers:   []*x509.Certificate{login, trusted.attest(t, pub)},
			options: recordedAs(types.AttestLevelSoftware),
			refusal: PIVRefusalRecordedNotHardware,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditLog := &mockAuthAuditLogger{}
			server := newAttestedLoginServer(t, trusted, auditLog, tt.options)

			w := doAuthRequest(t, server, pivRequestWithChain(tt.peers...))

			events := auditLog.Events()
			require.NotEmpty(t, events)
			last := events[len(events)-1]
			if tt.refusal == "" {
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
				var resp authTokenResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
				assert.Equal(t, PIVAttestLevelHardware, accessClaims(t, resp.AccessToken)["attest_level"])
				assert.Equal(t, audit.OutcomeAllow, last.Outcome)
				return
			}
			assert.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Contains(t, w.Body.String(), "not hardware-attested")
			assert.NotContains(t, w.Body.String(), string(tt.refusal), "the refusal reason is for the operator, not the client")
			assert.Equal(t, audit.OutcomeDeny, last.Outcome)
			assert.Equal(t, "attestation: "+string(tt.refusal), last.Details["reason"])
		})
	}
}

// With no anchor configured the exchange refuses rather than assumes
// hardware; the explicit opt-out accepts and records the login as unattested.
func TestPIVLogin_NoAnchorRefusesUnlessUnattestedIsAllowed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	login := generateTestCertificate(t, key)
	user := &fakeAuthUserStore{user: auth.MTLSUser{Username: "alice", Enabled: true}}

	auditLog := &mockAuthAuditLogger{}
	strict := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true}
		c.AuthUserStore = user
		c.AuditLogger = auditLog
	})
	w := doAuthRequest(t, strict, pivRequestWithChain(login))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	events := auditLog.Events()
	require.NotEmpty(t, events)
	assert.Equal(t, "attestation: "+string(PIVRefusalNoAnchor), events[len(events)-1].Details["reason"])

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

// Configured attestation trust and the unattested opt-out contradict each
// other: the opt-out would turn every failed attestation into an accepted
// "unattested" login. NewServer refuses the pair on an enabled exchange.
func TestNewServer_PIVLoginRefusesUnattestedWithAnchors(t *testing.T) {
	authority := newAttestationAuthority(t)
	tests := []struct {
		name    string
		options *PIVLoginOptions
		wantErr error
	}{
		{
			name:    "enabled with anchors and the opt-out",
			options: &PIVLoginOptions{Enabled: true, AttestationRoots: authority.pool, AllowUnattested: true},
			wantErr: ErrPIVLoginUnattestedWithAnchors,
		},
		{
			name:    "disabled with anchors and the opt-out",
			options: &PIVLoginOptions{AttestationRoots: authority.pool, AllowUnattested: true},
		},
		{
			name:    "enabled with anchors only",
			options: &PIVLoginOptions{Enabled: true, AttestationRoots: authority.pool},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServer(&Config{
				Authenticator: auth.NewNoOpAuthenticator(),
				Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
				Logger:        testLogger(),
				PIVLogin:      tt.options,
			})
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

// ErrPIVAttestationRefused carries its stable reason and unwraps to the
// verification failure behind it.
func TestErrPIVAttestationRefused(t *testing.T) {
	refusal := refusePIVAttestation(PIVRefusalProfile, ErrPIVAttestationClaimMissing)
	assert.ErrorIs(t, refusal, ErrPIVAttestationClaimMissing)
	assert.Contains(t, refusal.Error(), string(PIVRefusalProfile))
	assert.Contains(t, refusal.Error(), ErrPIVAttestationClaimMissing.Error())

	bare := refusePIVAttestation(PIVRefusalNoEvidence, nil)
	assert.NoError(t, bare.Unwrap())
	assert.Equal(t, "rest: piv login attestation refused: "+string(PIVRefusalNoEvidence), bare.Error())
}
