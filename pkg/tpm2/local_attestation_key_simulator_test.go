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

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/ecdsa"
	"crypto/x509"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLAKHarness is newSimHarness with an LAK configuration added and the
// Platform SRK enrolled: CreateLAK parents the LAK off the Platform SRK
// (go-xkms#715), which newSimConfig alone does not provision.
func newLAKHarness(t *testing.T) *simHarness {
	t.Helper()
	h := newSimHarness(t, func(c *Config) {
		c.LAK = &LAKConfig{
			CN:                 "lak-fixture",
			Handle:             0x81010003,
			KeyAlgorithm:       x509.ECDSA.String(),
			ECCConfig:          &store.ECCConfig{Curve: "P-256"},
			Hash:               "SHA-256",
			SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		}
	})

	pks, err := NewPlatformKeyStore(
		h.Logger,
		h.TPM,
		h.Backend,
		h.TPM.config,
		filepath.Join(t.TempDir(), "pin-state.json"),
	)
	require.NoError(t, err)
	require.NoError(t, pks.EnrollPlatformSRK("", "lak-harness-operator-pin"))

	return h
}

// TestCreateLAK_CertifiedByIAK_RoundTrip is the pkg/tpm2 half of go-xkms#715's
// round trip: create the LAK under the Platform SRK, certify it with the
// device's IAK via TPM2_Certify, and verify the evidence both through the raw
// TPMS_ATTEST structure and through this package's own stateless verifier
// (VerifyCertify) -- the same check ca.IssueLAKCertificate runs.
func TestCreateLAK_CertifiedByIAK_RoundTrip(t *testing.T) {
	h := newLAKHarness(t)

	lakAttrs, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)
	require.NotNil(t, lakAttrs)
	assert.Equal(t, tpm2.TPMHandle(h.TPM.config.LAK.Handle), lakAttrs.TPMAttributes.Handle,
		"the LAK must be persisted at the configured handle")

	lakPub, err := h.TPM.LAK()
	require.NoError(t, err)
	lakECDSA, ok := lakPub.(*ecdsa.PublicKey)
	require.True(t, ok, "the configured LAK is ECDSA, got %T", lakPub)

	nonce := []byte("lak-certify-round-trip-nonce-01")
	result, err := h.TPM.CertifyLAK(nonce, h.Backend)
	require.NoError(t, err)
	require.NotNil(t, result)

	// The IAK's signature over the certify structure must verify (the
	// simulator's configured IAK is RSA-PSS; verifyIAKSignature is shared
	// with attestation_certify_simulator_test.go).
	require.NoError(t, verifyIAKSignature(t, result.AttestingKeyPublic, result.CertifyInfo, result.Signature))
	assert.Equal(t, nonce, result.Nonce)

	attestedECDSA, ok := result.AttestedKeyPublic.(*ecdsa.PublicKey)
	require.True(t, ok, "the certified key must be the LAK, got %T", result.AttestedKeyPublic)
	assert.True(t, attestedECDSA.Equal(lakECDSA), "the certified key must be the LAK's own public key")

	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](result.CertifyInfo)
	require.NoError(t, err)
	assert.Equal(t, tpm2.TPMGeneratedValue, attest.Magic)
	assert.Equal(t, tpm2.TPMSTAttestCertify, attest.Type)
	assert.Equal(t, nonce, attest.ExtraData.Buffer)

	// pkg/ca's IssueLAKCertificate runs exactly this stateless check against
	// the device's IAK certificate before issuing; reproducing it here proves
	// the evidence CreateLAK/CertifyLAK produce is of the shape that check
	// accepts.
	verification, err := VerifyCertify(
		result.CertifyInfo,
		result.CertifyInfoSignature,
		result.AttestingKeyPublicArea,
		result.AttestedKeyPublicArea,
		&VerifyCertifyOptions{ExpectedQualifyingData: nonce},
	)
	require.NoError(t, err)
	assert.Equal(t, nonce, verification.QualifyingData)
}

// TestCreateLAK_NoConfig_ReturnsTypedError proves CreateLAK refuses to guess a
// handle, algorithm or CN when no LAK section is configured, rather than
// defaulting silently.
func TestCreateLAK_NoConfig_ReturnsTypedError(t *testing.T) {
	h := newSimHarness(t, nil) // no LAK config

	_, err := h.TPM.CreateLAK(nil, h.Backend, false)
	assert.ErrorIs(t, err, ErrLAKConfigNil)
}

// TestLAKAttributes_NoConfig_ReturnsTypedError is LAKAttributes' error-path
// twin of TestCreateLAK_NoConfig_ReturnsTypedError: the restart path refuses
// the same way the creation path does.
func TestLAKAttributes_NoConfig_ReturnsTypedError(t *testing.T) {
	h := newSimHarness(t, nil) // no LAK config

	_, err := h.TPM.LAKAttributes()
	assert.ErrorIs(t, err, ErrLAKConfigNil)
}

// TestCertifyLAK_NotCreated_ReturnsTypedError proves CertifyLAK refuses to
// certify a LAK that was never created, rather than certifying whatever
// public area happens to live at the configured (empty) handle.
func TestCertifyLAK_NotCreated_ReturnsTypedError(t *testing.T) {
	h := newLAKHarness(t) // LAK configured, but CreateLAK never called

	_, err := h.TPM.CertifyLAK([]byte("nonce"), h.Backend)
	assert.Error(t, err, "certifying an unprovisioned LAK must fail")
}

// TestLAKAttributes_RebuildsAfterCacheCleared proves the restart path: once
// the LAK is persisted, LAKAttributes rebuilds identical attributes from the
// handle alone, exactly as IAKAttributes does for the IAK.
func TestLAKAttributes_RebuildsAfterCacheCleared(t *testing.T) {
	h := newLAKHarness(t)

	original, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)

	// Simulate a restart: drop the in-memory cache, forcing the next call to
	// re-derive the attributes from the TPM-resident, persisted handle.
	h.TPM.lakAttrs = nil

	rebuilt, err := h.TPM.LAKAttributes()
	require.NoError(t, err)
	assert.Equal(t, original.TPMAttributes.Handle, rebuilt.TPMAttributes.Handle)
	assert.Equal(t, original.TPMAttributes.PublicKeyBytes, rebuilt.TPMAttributes.PublicKeyBytes)
	assert.Equal(t, original.CN, rebuilt.CN)
	assert.Equal(t, original.KeyType, rebuilt.KeyType)
}

// TestCreateLAK_WithoutKeyBackend_PersistsLAK proves a TPM opened without a
// key backend (the xkey CLI's) can still create the LAK: its blobs are only
// staged to reload it for TPM2_EvictControl, so CreateLAK stages them in
// scratch memory instead of dereferencing a nil backend.
func TestCreateLAK_WithoutKeyBackend_PersistsLAK(t *testing.T) {
	h := newLAKHarness(t)
	saved := h.TPM.backend
	h.TPM.backend = nil
	t.Cleanup(func() { h.TPM.backend = saved })

	lakAttrs, err := h.TPM.CreateLAK(nil, nil, false)
	require.NoError(t, err)

	h.TPM.lakAttrs = nil
	persisted, err := h.TPM.LAKAttributes()
	require.NoError(t, err)
	assert.Equal(t, lakAttrs.TPMAttributes.PublicKeyBytes, persisted.TPMAttributes.PublicKeyBytes)
}

// TestCreateLAK_Overwrite_ReplacesPersistedLAK proves overwrite evicts the LAK
// already persisted at the handle and persists a fresh key in its place,
// while a second create without overwrite is refused.
func TestCreateLAK_Overwrite_ReplacesPersistedLAK(t *testing.T) {
	h := newLAKHarness(t)

	original, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)

	_, err = h.TPM.CreateLAK(nil, h.Backend, false)
	require.Error(t, err, "a second create without overwrite must not replace the LAK")

	replaced, err := h.TPM.CreateLAK(nil, h.Backend, true)
	require.NoError(t, err)
	assert.Equal(t, original.TPMAttributes.Handle, replaced.TPMAttributes.Handle)
	assert.NotEqual(t, original.TPMAttributes.PublicKeyBytes, replaced.TPMAttributes.PublicKeyBytes,
		"overwrite must persist a fresh key, not keep the old one")
}

// =============================================================================
// Platform-policy-bound LAK: bindObjectPolicy / objectSession (go-xkms#715)
// =============================================================================
//
// Main's object-policy hardening (object_policy.go) clears USERWITHAUTH on
// every child object that carries an authPolicy, so its authValue -- even an
// empty one -- can no longer satisfy the USER role on its own (TCG TPM 2.0
// Part 1, section 19.7.5); only a session that actually walks the policy
// does. CreateECDSA/CreateRSA route every key they create, the LAK included,
// through bindObjectPolicy unconditionally.
//
// TPM2_Certify has two roles in play, and they are authorized differently:
// SignHandle (the signer) is USER role, which certifyKeyAs resolves through
// objectSession -- the signer's empty-password bypass is what go-xkms#715
// closes for the LAK, exercised below by CertifyKeyWithLAK (the LAK as
// signer). ObjectHandle (the target) is ADMIN role, and this package's
// generic templates never set adminWithPolicy, so TCG TPM 2.0 Part 1 section
// 19.7.5 makes the target's ADMIN role authorized by its authValue alone
// regardless of its USER-role policy binding -- confirmed directly against
// the simulator while diagnosing these tests (a policy session whose digest
// exactly matches the LAK's authPolicy still fails ADMIN-role authorization
// with TPM_RC_POLICY_FAIL). certifyKeyAs therefore keeps a plain password
// session for the non-DevID target branch; objectSession never applies
// there. CertifyLAK (the IAK certifying the LAK as target) exercises that
// the target side keeps working once the LAK carries a policy.

// newPlatformPolicyLAKHarness is newLAKHarness with the LAK bound to the
// platform policy instead of carrying no policy at all.
func newPlatformPolicyLAKHarness(t *testing.T) *simHarness {
	t.Helper()
	h := newSimHarness(t, func(c *Config) {
		c.LAK = &LAKConfig{
			CN:                 "lak-platform-policy-fixture",
			Handle:             0x81010003,
			KeyAlgorithm:       x509.ECDSA.String(),
			ECCConfig:          &store.ECCConfig{Curve: "P-256"},
			Hash:               "SHA-256",
			SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
			PlatformPolicy:     true,
		}
	})

	pks, err := NewPlatformKeyStore(
		h.Logger,
		h.TPM,
		h.Backend,
		h.TPM.config,
		filepath.Join(t.TempDir(), "pin-state.json"),
	)
	require.NoError(t, err)
	require.NoError(t, pks.EnrollPlatformSRK("", "lak-platform-policy-operator-pin"))

	return h
}

// TestCreateLAK_PlatformPolicyBound_ClearsUserWithAuth proves CreateLAK binds
// a platform-policy LAK through bindObjectPolicy exactly like every other
// child key: the persisted object's USERWITHAUTH attribute is CLEAR and it
// carries a non-empty authPolicy, so a bare password session -- even an empty
// one -- can no longer satisfy its USER role.
func TestCreateLAK_PlatformPolicyBound_ClearsUserWithAuth(t *testing.T) {
	h := newPlatformPolicyLAKHarness(t)

	lakAttrs, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)

	_, pub, err := h.TPM.ReadHandle(lakAttrs.TPMAttributes.Handle)
	require.NoError(t, err)
	assert.False(t, pub.ObjectAttributes.UserWithAuth,
		"a platform-policy-bound LAK must clear USERWITHAUTH so a bare (even empty) password session cannot satisfy its USER role")
	assert.NotEmpty(t, pub.AuthPolicy.Buffer,
		"a platform-policy-bound LAK must carry a non-empty authPolicy")
}

// TestCertifyLAK_PlatformPolicyBound_TargetUsesADMINRolePassword proves the
// IAK can still certify a platform-policy-bound LAK as its target.
// TPM2_Certify authorizes its objectHandle (the target) at the ADMIN role,
// not USER, and this package's generic key templates never set
// adminWithPolicy -- so, per TCG TPM 2.0 Part 1 section 19.7.5, ADMIN-role
// actions on the LAK are authorized by its authValue alone, exactly as
// before this file bound it to the platform policy: that policy governs the
// USER role (ordinary use), which TPM2_Certify naming the LAK as its subject
// never exercises. This is the empirical result of diagnosing the
// alternative directly against the simulator: presenting a policy session
// whose digest exactly matches the LAK's authPolicy for this role still
// fails with TPM_RC_POLICY_FAIL, because adminWithPolicy CLEAR makes a
// policy session the wrong tool for ADMIN role, not merely an unnecessary
// one.
func TestCertifyLAK_PlatformPolicyBound_TargetUsesADMINRolePassword(t *testing.T) {
	h := newPlatformPolicyLAKHarness(t)

	_, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)

	nonce := []byte("lak-platform-policy-certify-nonce")
	result, err := h.TPM.CertifyLAK(nonce, h.Backend)
	require.NoError(t, err, "TPM2_Certify of a platform-policy-bound LAK must succeed: its ADMIN role is password-authorized regardless of its USER-role policy binding")
	require.NotNil(t, result)
	assert.Equal(t, nonce, result.Nonce)
}

// TestCertifyKeyWithLAK_PlatformPolicyBound_SignerUsesPolicySession is the
// USER-role proof the target-side test above is not: when the LAK itself
// signs (CertifyKeyWithLAK, the path xkey's WebAuthn/FIDO2 "tpm" attestation
// uses), TPM2_Certify authorizes SignHandle at the USER role, which
// certifyKeyAs resolves through objectSession (object_policy.go) -- the
// policy-aware session builder bindObjectPolicy's invariant requires. This is
// where the empty-password bypass go-xkms#715 closes for the LAK actually
// lives: a bare password session, even an empty one, is refused by the
// simulator for this signer because its USERWITHAUTH is CLEAR.
func TestCertifyKeyWithLAK_PlatformPolicyBound_SignerUsesPolicySession(t *testing.T) {
	h := newPlatformPolicyLAKHarness(t)

	_, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)

	// An ordinary key to certify under the LAK, exactly as xkey certifies a
	// WebAuthn credential key (keybackend.GetAttestationStatement).
	srkAttrs, err := h.TPM.PlatformSRKAttributes()
	require.NoError(t, err)
	credAttrs := &types.KeyAttributes{
		CN:           "lak-signed-credential",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreTPM2,
		Parent:       srkAttrs,
	}
	_, err = h.TPM.CreateECDSA(credAttrs, h.Backend, false)
	require.NoError(t, err)

	nonce := []byte("lak-signer-platform-policy-certify-nonce")
	result, err := h.TPM.CertifyKeyWithLAK(credAttrs, nonce, h.Backend)
	require.NoError(t, err, "TPM2_Certify signed by a platform-policy-bound LAK must succeed through objectSession's policy branch")
	require.NotNil(t, result)
	assert.Equal(t, nonce, result.Nonce)
}
