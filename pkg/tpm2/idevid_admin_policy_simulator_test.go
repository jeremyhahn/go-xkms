//go:build tpm_simulator

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

package tpm2

import (
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise the IDevID authorization model of TCG "TPM 2.0 Keys
// for Device Identity and Attestation" v1.00 r12 against the TPM simulator:
//
//   - the created key carries the specification's IDevID/IAK Key Policy as
//     its authPolicy, with adminWithPolicy SET (section 7.3.4);
//   - its authValue authorizes USE but not ADMINISTRATION (section 7.2.4):
//     TPM2_Certify with the authValue is refused with TPM_RC_AUTH_TYPE;
//   - the Privacy Administrator administers it through the policy, one
//     command at a time (sections 7.3.6.2, 7.3.6.6).

// Table 19, "Signing Key PolicyIDevIDKeySHA256".
const tcgSigningKeyPolicySHA256 = "ad6b3a2284fd698a0710bf5cc1b9bdf15e2532e3f601fa4b93a6a8fa8de579ea"

func createPlatformPolicyIDevID(t *testing.T) (*simHarness, *tpm2.TPMTPublic, tpm2.TPM2BName, []byte, []byte) {
	t.Helper()
	h := newSimHarness(t, func(c *Config) {
		c.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
		c.IDevID = idevidTestConfig("device-id-001", x509.SHA256WithRSA.String())
		c.IDevID.PlatformPolicy = true
	})
	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)

	idevidAttrs, _, err := h.TPM.CreateIDevID(iakAttrs, selfSignedCertForKey(t, ekPub), nil)
	require.NoError(t, err, "a platform-policy IDevID must be creatable under the TCG template")
	require.NotNil(t, idevidAttrs.TPMAttributes)

	readPub, err := tpm2.ReadPublic{ObjectHandle: idevidAttrs.TPMAttributes.Handle}.Execute(h.TPM.transport)
	require.NoError(t, err, "the IDevID must be persisted at its configured handle")
	public, err := readPub.OutPublic.Contents()
	require.NoError(t, err)

	var iakAuth, hierarchyAuth []byte
	if iakAttrs.Password != nil {
		iakAuth = iakAttrs.Password.Bytes()
	}
	require.NotNil(t, iakAttrs.Parent, "the IAK's parent is the EK, which carries the endorsement auth")
	if iakAttrs.Parent.TPMAttributes != nil && iakAttrs.Parent.TPMAttributes.HierarchyAuth != nil {
		hierarchyAuth = iakAttrs.Parent.TPMAttributes.HierarchyAuth.Bytes()
	}
	return h, public, readPub.Name, iakAuth, hierarchyAuth
}

func certifyIDevID(h *simHarness, name tpm2.TPM2BName, objectAuth tpm2.Session, iakAuth []byte) error {
	iakAttrs, err := h.TPM.IAKAttributes()
	if err != nil {
		return err
	}
	_, err = tpm2.Certify{
		ObjectHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(h.TPM.config.IDevID.Handle),
			Name:   name,
			Auth:   objectAuth,
		},
		SignHandle: tpm2.AuthHandle{
			Handle: iakAttrs.TPMAttributes.Handle,
			Name:   iakAttrs.TPMAttributes.Name,
			Auth:   tpm2.PasswordAuth(iakAuth),
		},
		QualifyingData: tpm2.TPM2BData{Buffer: []byte("admin-role-probe")},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(h.TPM.transport)
	return err
}

// The created object is the specification's Template H-0 with the
// specification's Table 19 policy -- checked on the object the TPM actually
// holds, not on the template that was sent.
func TestCreateIDevID_CarriesTheTCGKeyPolicy(t *testing.T) {
	_, public, _, _, _ := createPlatformPolicyIDevID(t)

	a := public.ObjectAttributes
	assert.True(t, a.AdminWithPolicy, "section 7.2.4: the ADMIN role is reached only through policy")
	assert.True(t, a.UserWithAuth, "section 7.2.4: the authValue authorizes the USER role")
	assert.True(t, a.FixedTPM && a.FixedParent && a.SensitiveDataOrigin && a.SignEncrypt)
	assert.False(t, a.Restricted, "a signing DevID is Unrestricted (Template H-0)")

	want, err := hex.DecodeString(tcgSigningKeyPolicySHA256)
	require.NoError(t, err)
	assert.Equal(t, want, public.AuthPolicy.Buffer,
		"the object's authPolicy must be Table 19's PolicyIDevIDKey for SHA256")
	assert.NoError(t, assertAdminAuthorizable(*public))
}

// Section 7.2.4: "someone who knows the IDevID/IAK key's authValue password
// can use the IDevID/IAK key, but can't administer the IDevID/IAK key."
// TPM2_Certify authorizes the object at the ADMIN role, so the authValue is
// refused and the Privacy Administrator's policy session is required.
func TestCreateIDevID_AdminRoleIsPolicyOnly(t *testing.T) {
	h, public, name, iakAuth, hierarchyAuth := createPlatformPolicyIDevID(t)

	err := certifyIDevID(h, name, tpm2.PasswordAuth(nil), iakAuth)
	require.Error(t, err, "the authValue must not administer the key")
	assert.ErrorIs(t, err, tpm2.TPMRCAuthType,
		"adminWithPolicy SET makes the TPM refuse the authValue for an ADMIN-role command")

	session, closer, err := h.TPM.DevIDAdminSession(
		DevIDKeySigning, public.NameAlg, tpm2.TPMCCCertify, hierarchyAuth)
	require.NoError(t, err)
	defer func() { _ = closer() }()
	assert.NoError(t, certifyIDevID(h, name, session, iakAuth),
		"the Certify branch of the key policy, satisfied with endorsementAuth, must administer the key")
}

// The command code is part of the policy digest, so a session built for one
// ADMIN-role command cannot authorize another. This is what confines the
// Privacy Administrator to exactly the operations the policy enumerates.
func TestDevIDAdminSession_IsBoundToOneCommand(t *testing.T) {
	h, public, name, iakAuth, hierarchyAuth := createPlatformPolicyIDevID(t)

	session, closer, err := h.TPM.DevIDAdminSession(
		DevIDKeySigning, public.NameAlg, tpm2.TPMCCActivateCredential, hierarchyAuth)
	require.NoError(t, err)
	defer func() { _ = closer() }()

	err = certifyIDevID(h, name, session, iakAuth)
	require.Error(t, err, "a session for TPM_CC_ActivateCredential must not authorize TPM2_Certify")
	// The session's commandCode is ActivateCredential, so the TPM reports the
	// mismatch as TPM_RC_POLICY_CC rather than a digest failure (TCG TPM 2.0
	// Part 3, TPM2_PolicyCommandCode): the refusal is by command code, which
	// is exactly the confinement the policy is built for.
	assert.ErrorIs(t, err, tpm2.TPMRCPolicyCC)

	_, _, err = h.TPM.DevIDAdminSession(DevIDKeySigning, public.NameAlg, tpm2.TPMCCSign, hierarchyAuth)
	assert.ErrorIs(t, err, ErrDevIDPolicySession,
		"a command with no branch in the key policy is refused before a session is opened")
}

// A wrong endorsementAuth cannot satisfy PolicySecret, so the Privacy
// Administrator's authority is what the policy actually checks.
func TestDevIDAdminSession_RequiresTheEndorsementAuth(t *testing.T) {
	h, public, _, _, hierarchyAuth := createPlatformPolicyIDevID(t)
	wrong := append([]byte("not-"), hierarchyAuth...)

	_, closer, err := h.TPM.DevIDAdminSession(DevIDKeySigning, public.NameAlg, tpm2.TPMCCCertify, wrong)
	if closer != nil {
		_ = closer()
	}
	require.Error(t, err, "PolicySecret must fail under a wrong endorsement auth")
	assert.ErrorIs(t, err, ErrDevIDPolicySession)
}

// The policy is assigned on the creation path, so a template that arrives
// with the wrong shape is refused rather than shipped. Each case mutates the
// global template in a way the specification's Template H-0 forbids.
func TestCreateIDevID_RefusesANonConformantTemplate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*tpm2.TPMTPublic)
	}{
		{"adminWithPolicy cleared", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.AdminWithPolicy = false }},
		{"userWithAuth cleared", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.UserWithAuth = false }},
		{"restricted set", func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := RSASSAIDevIDTemplate
			t.Cleanup(func() { RSASSAIDevIDTemplate = original })
			tc.mutate(&RSASSAIDevIDTemplate)

			h := newSimHarness(t, func(c *Config) {
				c.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
				c.IDevID = idevidTestConfig("device-id-001", x509.SHA256WithRSA.String())
			})
			iakAttrs, err := h.TPM.IAKAttributes()
			require.NoError(t, err)
			ekPub, err := h.TPM.EKRSA()
			require.NoError(t, err)

			idevidAttrs, csr, err := h.TPM.CreateIDevID(iakAttrs, selfSignedCertForKey(t, ekPub), nil)
			require.Error(t, err, "a non-conformant IDevID template must not create a key")
			assert.ErrorIs(t, err, ErrDevIDTemplateNonConformant)
			assert.Nil(t, idevidAttrs)
			assert.Nil(t, csr)

			_, err = tpm2.ReadPublic{
				ObjectHandle: tpm2.TPMHandle(h.TPM.config.IDevID.Handle),
			}.Execute(h.TPM.transport)
			assert.Error(t, err, "the refusal happened before TPM2_CreatePrimary; nothing exists at the handle")
		})
	}
}
