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

// The Evaluate tests live in the external test package because they build
// real attestation chains with attesttest, which itself imports pairing.
package pairing_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/pairingproto"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/attestation/attesttest"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// enrollmentEvidence is one phone's answer to local.getDeviceEnrollmentRequest,
// built the way a real handset builds it: an attested key under a hardware
// CA, and a CSR self-signed by that same key.
type enrollmentEvidence struct {
	ca     *attesttest.CA
	result *pairingproto.LocalGetDeviceEnrollmentRequestResult
}

// newEnrollmentEvidence attests a fresh key under nonce with the given
// security level and root of trust.
func newEnrollmentEvidence(
	t *testing.T,
	nonce []byte,
	level xkms.AndroidSecurityLevel,
	rot *xkms.AndroidRootOfTrust,
) *enrollmentEvidence {
	t.Helper()

	ca := attesttest.NewCA(t, "attestation root")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leaf := attesttest.AttestedLeafDER(t, ca, key, nonce, level, rot)
	return &enrollmentEvidence{
		ca: ca,
		result: &pairingproto.LocalGetDeviceEnrollmentRequestResult{
			Format: pairingproto.AttestationFormatAndroidKey,
			CSR:    csrFor(t, key),
			AttestationChain: []string{
				base64.StdEncoding.EncodeToString(leaf),
				base64.StdEncoding.EncodeToString(ca.Cert.Raw),
			},
		},
	}
}

// policy is the default enrollment policy trusting this evidence's CA and
// allowing the fixture application.
func (e *enrollmentEvidence) policy() *pairing.EnrollmentPolicy {
	p := pairing.NewEnrollmentPolicy()
	p.TrustedRoots = e.ca.Pool()
	p.ApplicationPolicy = attesttest.Applications()
	return p
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "enrolling device"},
	}, key)
	require.NoError(t, err)
	return der
}

func TestEnrollmentPolicyEvaluate_AcceptsGenuineEvidence(t *testing.T) {
	nonce := []byte("enrollment-nonce")
	ev := newEnrollmentEvidence(t, nonce, xkms.AndroidSecurityLevelTrustedEnvironment,
		attesttest.AttestedBootState())
	now := time.Now()

	decision, err := ev.policy().Evaluate(ev.result, nonce, now)
	require.NoError(t, err)

	assert.Equal(t, attesttest.AppPackage, decision.PackageName)
	assert.Equal(t, hex.EncodeToString(attesttest.AppSigningDigest()), decision.SigningDigest)
	assert.Equal(t, pairingproto.SecurityLevelTEE, decision.SecurityLevel)
	assert.True(t, decision.DeviceLocked)
	assert.Equal(t, now.Add(pairing.DefaultEnrollmentValidity), decision.NotAfter)
}

func TestEnrollmentPolicyEvaluate_StrongBoxMeetsTheTEEFloor(t *testing.T) {
	nonce := []byte("enrollment-nonce")
	ev := newEnrollmentEvidence(t, nonce, xkms.AndroidSecurityLevelStrongBox,
		attesttest.AttestedBootState())

	decision, err := ev.policy().Evaluate(ev.result, nonce, time.Now())
	require.NoError(t, err)
	assert.Equal(t, pairingproto.SecurityLevelStrongBox, decision.SecurityLevel)
}

func TestEnrollmentPolicyEvaluate_RefusesASoftwareKey(t *testing.T) {
	nonce := []byte("enrollment-nonce")
	ev := newEnrollmentEvidence(t, nonce, xkms.AndroidSecurityLevelSoftware,
		attesttest.AttestedBootState())

	_, err := ev.policy().Evaluate(ev.result, nonce, time.Now())
	assert.ErrorIs(t, err, pairing.ErrEnrollmentSecurityLevel)
}

func TestEnrollmentPolicyEvaluate_RefusesAnUntrustedChain(t *testing.T) {
	nonce := []byte("enrollment-nonce")
	ev := newEnrollmentEvidence(t, nonce, xkms.AndroidSecurityLevelTrustedEnvironment,
		attesttest.AttestedBootState())
	p := ev.policy()
	p.TrustedRoots = attesttest.NewCA(t, "some other root").Pool()

	_, err := p.Evaluate(ev.result, nonce, time.Now())
	assert.ErrorIs(t, err, pairing.ErrEnrollmentChainUntrusted)
}

func TestEnrollmentPolicyEvaluate_RefusesAChainThatIsNotBase64(t *testing.T) {
	nonce := []byte("enrollment-nonce")
	ev := newEnrollmentEvidence(t, nonce, xkms.AndroidSecurityLevelTrustedEnvironment,
		attesttest.AttestedBootState())
	ev.result.AttestationChain[1] = "not base64!"

	_, err := ev.policy().Evaluate(ev.result, nonce, time.Now())
	assert.ErrorIs(t, err, pairing.ErrEnrollmentChainUntrusted)
}

func TestEnrollmentPolicyEvaluate_RefusesWhenNoChallengeWasIssued(t *testing.T) {
	// With no expected nonce the chain verifier checks nothing, so Evaluate
	// itself must refuse: otherwise any old attestation would enroll.
	ev := newEnrollmentEvidence(t, []byte("enrollment-nonce"),
		xkms.AndroidSecurityLevelTrustedEnvironment, attesttest.AttestedBootState())

	_, err := ev.policy().Evaluate(ev.result, nil, time.Now())
	assert.ErrorIs(t, err, pairing.ErrEnrollmentStaleChallenge)
}

func TestEnrollmentPolicyEvaluate_RefusesAReplayedChallenge(t *testing.T) {
	ev := newEnrollmentEvidence(t, []byte("an earlier nonce"),
		xkms.AndroidSecurityLevelTrustedEnvironment, attesttest.AttestedBootState())

	// The chain verifier is handed the expected nonce and refuses the chain.
	_, err := ev.policy().Evaluate(ev.result, []byte("this enrollment's nonce"), time.Now())
	assert.ErrorIs(t, err, pairing.ErrEnrollmentChainUntrusted)
}

func TestEnrollmentPolicyEvaluate_RefusesACSRForAnotherKey(t *testing.T) {
	nonce := []byte("enrollment-nonce")
	ev := newEnrollmentEvidence(t, nonce, xkms.AndroidSecurityLevelTrustedEnvironment,
		attesttest.AttestedBootState())
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ev.result.CSR = csrFor(t, other)

	_, err = ev.policy().Evaluate(ev.result, nonce, time.Now())
	assert.ErrorIs(t, err, pairing.ErrEnrollmentKeyMismatch)
}

func TestEnrollmentPolicyEvaluate_RefusesAnUnsafeBootState(t *testing.T) {
	unlocked := attesttest.AttestedBootState()
	unlocked.DeviceLocked = false

	selfSigned := attesttest.AttestedBootState()
	selfSigned.VerifiedBootState = xkms.AndroidVerifiedBootSelfSigned

	tests := []struct {
		name string
		rot  *xkms.AndroidRootOfTrust
	}{
		{name: "no root of trust", rot: nil},
		{name: "unlocked bootloader", rot: unlocked},
		{name: "self-signed boot", rot: selfSigned},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nonce := []byte("enrollment-nonce")
			ev := newEnrollmentEvidence(t, nonce, xkms.AndroidSecurityLevelTrustedEnvironment, tt.rot)

			_, err := ev.policy().Evaluate(ev.result, nonce, time.Now())
			assert.ErrorIs(t, err, pairing.ErrEnrollmentBootState)
		})
	}
}

func TestEnrollmentPolicyEvaluate_BootStateIsOptionalWhenNotRequired(t *testing.T) {
	nonce := []byte("enrollment-nonce")
	ev := newEnrollmentEvidence(t, nonce, xkms.AndroidSecurityLevelTrustedEnvironment, nil)
	p := ev.policy()
	p.RequireVerifiedBoot = false

	decision, err := p.Evaluate(ev.result, nonce, time.Now())
	require.NoError(t, err)
	assert.False(t, decision.DeviceLocked)
}

func TestEnrollmentPolicyEvaluate_RefusesAnApplicationOffTheAllowList(t *testing.T) {
	nonce := []byte("enrollment-nonce")
	ev := newEnrollmentEvidence(t, nonce, xkms.AndroidSecurityLevelTrustedEnvironment,
		attesttest.AttestedBootState())
	p := ev.policy()
	p.AllowedApplications = []pairing.AllowedApplication{{
		PackageName:    "com.example.other",
		SigningDigests: []string{hex.EncodeToString(attesttest.AppSigningDigest())},
	}}

	_, err := p.Evaluate(ev.result, nonce, time.Now())
	assert.ErrorIs(t, err, pairing.ErrApplicationDenied)
}
