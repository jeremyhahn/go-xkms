//go:build tpm_simulator
// +build tpm_simulator

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

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateIDevID_PlatformPolicyLeavesTheAdminRoleAuthorizable is the
// verification issue #278 asked for: create an IDevID with
// `platform-policy: true`, read the created object's public area back from
// the TPM, and assert adminWithPolicy and authPolicy agree with each other.
//
// They agree by both being absent. The IDevID is administered by its auth
// value, which is what TPM2_Certify inside CreateIDevID already relies on.
// The pair the issue feared -- adminWithPolicy SET with an empty authPolicy
// -- would make TPM2_Certify answer TPM_RC_AUTH_TYPE, so the second half of
// this test drives the ADMIN role directly rather than trusting the
// attribute bits alone.
//
// `platform-policy: true` is the configuration under test because it is the
// only one that ever reached the removed guard. Asserting the outcome under
// that setting is what stops the guard from being revived without a policy
// to go with it.
func TestCreateIDevID_PlatformPolicyLeavesTheAdminRoleAuthorizable(t *testing.T) {
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
	require.NoError(t, err, "a platform-policy IDevID must be creatable")
	require.NotNil(t, idevidAttrs.TPMAttributes)
	require.True(t, idevidAttrs.PlatformPolicy,
		"the attributes must carry the configured platform-policy setting")

	// Read the public area of the persisted object, not the one the call
	// returned: the TPM's own copy is what every later command authorizes
	// against.
	handle := idevidAttrs.TPMAttributes.Handle
	readPub, err := tpm2.ReadPublic{ObjectHandle: handle}.Execute(h.TPM.transport)
	require.NoError(t, err, "the IDevID must be persisted at its configured handle")

	public, err := readPub.OutPublic.Contents()
	require.NoError(t, err)

	assert.False(t, public.ObjectAttributes.AdminWithPolicy,
		"the created IDevID must not claim policy administration")
	assert.Empty(t, public.AuthPolicy.Buffer,
		"the created IDevID carries no authPolicy")
	assert.True(t, public.ObjectAttributes.UserWithAuth,
		"the auth value must authorize the user role")
	assert.NoError(t, assertAdminAuthorizable(*public),
		"the attribute and the policy must agree on the created object")

	var iakAuth []byte
	if iakAttrs.Password != nil {
		iakAuth = iakAttrs.Password.Bytes()
	}

	// TPM2_Certify authorizes objectHandle at the ADMIN role, so a
	// successful call with password auth is direct proof the role is
	// reachable. With adminWithPolicy SET and no policy this answers
	// TPM_RC_AUTH_TYPE, and no policy session can rescue it.
	_, err = tpm2.Certify{
		ObjectHandle: tpm2.AuthHandle{
			Handle: handle,
			Name:   readPub.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		SignHandle: tpm2.AuthHandle{
			Handle: iakAttrs.TPMAttributes.Handle,
			Name:   iakAttrs.TPMAttributes.Name,
			Auth:   tpm2.PasswordAuth(iakAuth),
		},
		QualifyingData: tpm2.TPM2BData{Buffer: []byte("admin-role-probe")},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
	}.Execute(h.TPM.transport)
	assert.NoError(t, err,
		"the admin role of a platform-policy IDevID must remain authorizable")
}

// TestCreateIDevID_RefusesATemplateWithPolicyAdministrationAndNoPolicy proves
// the error path: when the template CreateIDevID is about to create a key
// from claims policy-only administration without a policy, the call reports
// ErrAdminWithPolicyNoAuthPolicy and creates nothing.
//
// The check runs before TPM2_CreatePrimary because that is the last moment it
// can help. Once the object exists the pair cannot be repaired -- the
// attribute is an input to the derivation, so the same key cannot be
// re-derived without it -- which is why this is refused rather than reported
// afterwards.
//
// The package template is mutated for the duration of the test because
// CreateIDevID selects it internally; there is no seam to inject one. The
// original is restored by t.Cleanup so the mutation cannot leak into another
// test.
func TestCreateIDevID_RefusesATemplateWithPolicyAdministrationAndNoPolicy(t *testing.T) {
	original := RSASSAIDevIDTemplate
	t.Cleanup(func() { RSASSAIDevIDTemplate = original })

	RSASSAIDevIDTemplate.ObjectAttributes.AdminWithPolicy = true
	RSASSAIDevIDTemplate.AuthPolicy = tpm2.TPM2BDigest{}
	require.True(t, RSASSAIDevIDTemplate.ObjectAttributes.AdminWithPolicy,
		"the mutation under test must have applied")

	h := newSimHarness(t, func(c *Config) {
		c.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
		c.IDevID = idevidTestConfig("device-id-001", x509.SHA256WithRSA.String())
		c.IDevID.PlatformPolicy = true
	})

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err)
	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)

	idevidAttrs, csr, err := h.TPM.CreateIDevID(iakAttrs, selfSignedCertForKey(t, ekPub), nil)

	require.Error(t, err, "an unadministrable IDevID must not be created")
	assert.ErrorIs(t, err, ErrAdminWithPolicyNoAuthPolicy)
	assert.Nil(t, idevidAttrs, "no attributes may be returned alongside the refusal")
	assert.Nil(t, csr, "no CSR may be returned alongside the refusal")

	// Nothing was persisted at the configured handle: the refusal happened
	// before TPM2_CreatePrimary, not after a key already existed.
	_, err = tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(h.TPM.config.IDevID.Handle),
	}.Execute(h.TPM.transport)
	assert.Error(t, err, "the refused IDevID must not exist at its configured handle")
}
