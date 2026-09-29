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

package pairing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	android "github.com/jeremyhahn/go-xkms/pkg/attestation/android"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPackage = "com.automatethethings.xkey"

// newTestPolicy returns a policy that would accept a well-formed request, so
// each test can spoil exactly one thing and see that refusal.
func newTestPolicy() *EnrollmentPolicy {
	p := NewEnrollmentPolicy()
	p.TrustedRoots = x509.NewCertPool()
	p.AllowedApplications = []AllowedApplication{{
		PackageName:    testPackage,
		SigningDigests: []string{"aa" + hexRepeat(31)},
	}}
	return p
}

func hexRepeat(n int) string {
	out := make([]byte, 0, n*2)
	for i := 0; i < n; i++ {
		out = append(out, 'b', 'b')
	}
	return string(out)
}

// signedCSR builds a CSR for a freshly generated key, and returns both so a
// test can attach the matching or a mismatching certificate.
func signedCSR(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "test device"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	require.NoError(t, err)
	return der, key
}

// selfSignedFor produces a certificate carrying key's public half, standing in
// for an attestation leaf where only the key matters.
func selfSignedFor(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestEnrollmentPolicy_DefaultsFailClosed(t *testing.T) {
	p := NewEnrollmentPolicy()

	// A policy nobody has configured must enroll nothing. The dangerous
	// default is the permissive one: a CA that trusts everything until told
	// otherwise hands out credentials during the window before it is set up.
	assert.Nil(t, p.TrustedRoots, "no roots are trusted until configured")
	assert.Empty(t, p.AllowedApplications, "no application is allowed until listed")
	assert.True(t, p.RequireVerifiedBoot, "verified boot is demanded by default")
	assert.Equal(t, SecurityLevelTEE, p.MinSecurityLevel,
		"software-held keys are refused by default")
	assert.Equal(t, DefaultEnrollmentValidity, p.Validity)

	_, err := p.Evaluate(&LocalGetDeviceEnrollmentRequestResult{
		AttestationChain: []string{"ignored"},
	}, []byte("nonce"), time.Now())
	assert.ErrorIs(t, err, ErrEnrollmentChainUntrusted)
}

// TestMinSecurityRank verifies the configured minimum resolves to the right
// rank, and that an unset minimum defaults to TEE rather than software.
func TestMinSecurityRank(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  int
	}{
		{"unset defaults to TEE", "", securityRank(SecurityLevelTEE)},
		{"software", SecurityLevelSoftware, securityRank(SecurityLevelSoftware)},
		{"TEE", SecurityLevelTEE, securityRank(SecurityLevelTEE)},
		{"StrongBox", SecurityLevelStrongBox, securityRank(SecurityLevelStrongBox)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &EnrollmentPolicy{MinSecurityLevel: tt.level}
			assert.Equal(t, tt.want, p.minSecurityRank())
		})
	}
}

// TestSecurityLevelName verifies each parsed Android security level renders
// as the corresponding wire name, and that an unrecognised level (the zero
// value included) renders as software rather than a blank string.
func TestSecurityLevelName(t *testing.T) {
	tests := []struct {
		name  string
		level android.SecurityLevel
		want  string
	}{
		{"StrongBox", android.SecurityLevelStrongBox, SecurityLevelStrongBox},
		{"TEE", android.SecurityLevelTrustedEnvironment, SecurityLevelTEE},
		{"software", android.SecurityLevelSoftware, SecurityLevelSoftware},
		{"unrecognised", android.SecurityLevel(99), SecurityLevelSoftware},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, securityLevelName(tt.level))
		})
	}
}

func TestEnrollmentPolicy_RefusesMissingEvidence(t *testing.T) {
	p := newTestPolicy()

	_, err := p.Evaluate(nil, []byte("nonce"), time.Now())
	assert.ErrorIs(t, err, ErrEnrollmentNoEvidence)

	_, err = p.Evaluate(&LocalGetDeviceEnrollmentRequestResult{}, []byte("nonce"), time.Now())
	assert.ErrorIs(t, err, ErrEnrollmentNoEvidence)
}

func TestEnrollmentPolicy_RefusesAnUnknownFormat(t *testing.T) {
	p := newTestPolicy()

	_, err := p.Evaluate(&LocalGetDeviceEnrollmentRequestResult{
		Format:           "tpm2-quote",
		AttestationChain: []string{"ignored"},
	}, []byte("nonce"), time.Now())

	// Refusing an unrecognised format is the point: evidence this CA cannot
	// verify must not be waved through on the assumption it resembles evidence
	// it can.
	assert.ErrorIs(t, err, ErrEnrollmentUnknownFormat)
}

func TestEnrollmentPolicy_RefusesAnEmptyAllowList(t *testing.T) {
	p := NewEnrollmentPolicy()
	p.TrustedRoots = x509.NewCertPool()

	_, err := p.Evaluate(&LocalGetDeviceEnrollmentRequestResult{
		AttestationChain: []string{"ignored"},
	}, []byte("nonce"), time.Now())

	assert.ErrorIs(t, err, ErrApplicationPolicyUnconfigured)
}

func TestDecodeAttestationChain_RefusesALoneCertificate(t *testing.T) {
	_, key := signedCSR(t)
	leaf := selfSignedFor(t, key)

	_, err := decodeAttestationChain([]string{
		base64.StdEncoding.EncodeToString(leaf.Raw),
	})

	// One certificate is self-signed, so it attests nothing. Accepting it
	// would let a device vouch for itself.
	assert.ErrorIs(t, err, ErrEnrollmentChainUntrusted)
}

func TestCSRMatchesAttestedKey_AcceptsTheAttestedKey(t *testing.T) {
	csrDER, key := signedCSR(t)
	leaf := selfSignedFor(t, key)

	assert.NoError(t, csrMatchesAttestedKey(csrDER, leaf))
}

// TestCSRMatchesAttestedKey_RefusesEvidenceForADifferentKey covers the check
// that is easiest to leave out and fatal to omit.
//
// Everything else can pass -- a genuine chain to a Google root, a fresh
// challenge, a locked bootloader -- while the key being certified is one the
// caller made in software, because nothing tied the evidence to the request.
func TestCSRMatchesAttestedKey_RefusesEvidenceForADifferentKey(t *testing.T) {
	csrDER, _ := signedCSR(t)

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	foreignLeaf := selfSignedFor(t, otherKey)

	err = csrMatchesAttestedKey(csrDER, foreignLeaf)
	assert.ErrorIs(t, err, ErrEnrollmentKeyMismatch)
}

func TestCSRMatchesAttestedKey_RefusesAnUnsignedCSR(t *testing.T) {
	csrDER, key := signedCSR(t)
	leaf := selfSignedFor(t, key)

	// Corrupt the signature: the requester must hold the private half of the
	// key it asks to have certified.
	tampered := make([]byte, len(csrDER))
	copy(tampered, csrDER)
	tampered[len(tampered)-1] ^= 0xFF

	err := csrMatchesAttestedKey(tampered, leaf)
	assert.ErrorIs(t, err, ErrEnrollmentKeyMismatch)
}

// TestBytesEqual verifies the constant-time comparison agrees with a normal
// byte comparison for equal, unequal, and different-length inputs.
func TestBytesEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"equal", []byte("challenge"), []byte("challenge"), true},
		{"different content, same length", []byte("challenge"), []byte("chocolate"), false},
		{"different length", []byte("short"), []byte("a much longer value"), false},
		{"both empty", nil, []byte{}, true},
		{"one empty", []byte{}, []byte("x"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, bytesEqual(tt.a, tt.b))
		})
	}
}

// TestEnrollmentPolicy_ValidityIsTheReattestationCadence records the design
// decision: there is no separate "re-attest every N days" knob.
//
// The credential's expiry is the cadence. Expressed that way it is enforceable
// by any RFC 5280 verifier, and it belongs to the relying party rather than to
// the device being judged.
func TestEnrollmentPolicy_ValidityIsTheReattestationCadence(t *testing.T) {
	p := NewEnrollmentPolicy()
	assert.Equal(t, DefaultEnrollmentValidity, p.effectiveValidity())

	p.Validity = 30 * 24 * time.Hour
	assert.Equal(t, 30*24*time.Hour, p.effectiveValidity())

	// A misconfigured zero or negative validity must not issue a credential
	// that has already expired.
	p.Validity = 0
	assert.Equal(t, DefaultEnrollmentValidity, p.effectiveValidity())
	p.Validity = -time.Hour
	assert.Equal(t, DefaultEnrollmentValidity, p.effectiveValidity())
}

func TestSecurityRank_UnknownLevelsRankAsSoftware(t *testing.T) {
	assert.Equal(t, 2, securityRank(SecurityLevelStrongBox))
	assert.Equal(t, 1, securityRank(SecurityLevelTEE))
	assert.Equal(t, 0, securityRank(SecurityLevelSoftware))

	// A typo in configuration must not silently weaken the policy by ranking
	// above the levels it is compared against.
	assert.Equal(t, 0, securityRank("Trusted_Environment"))
	assert.Equal(t, 0, securityRank(""))
}

func TestEnrollmentPolicy_ErrorsAreDistinguishable(t *testing.T) {
	// Each refusal carries its own sentinel so an operator can tell a device
	// that failed the boot check from one whose application is not allowed,
	// without parsing the message.
	sentinels := []error{
		ErrEnrollmentNoEvidence,
		ErrEnrollmentUnknownFormat,
		ErrEnrollmentChainUntrusted,
		ErrEnrollmentStaleChallenge,
		ErrEnrollmentKeyMismatch,
		ErrEnrollmentBootState,
		ErrEnrollmentSecurityLevel,
		ErrApplicationDenied,
		ErrApplicationPolicyUnconfigured,
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j {
				assert.False(t, errors.Is(a, b),
					"%v and %v must not be the same sentinel", a, b)
			}
		}
	}
}
