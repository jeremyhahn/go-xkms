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

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAssertAdminAuthorizable_RejectsPolicyAdministrationWithoutAPolicy proves
// the one combination that makes an object's ADMIN role permanently
// unauthorizable is refused before the object can be created.
//
// adminWithPolicy SET routes the ADMIN role through the object's authPolicy
// and makes the TPM refuse the auth value with TPM_RC_AUTH_TYPE. An empty
// authPolicy is satisfiable by no session, so the role is closed to every
// caller forever, and the attribute is an input to a primary key's derivation
// so the key cannot be recreated without it either (#278).
func TestAssertAdminAuthorizable_RejectsPolicyAdministrationWithoutAPolicy(t *testing.T) {
	template := RSASSAIDevIDTemplate
	template.ObjectAttributes.AdminWithPolicy = true
	template.AuthPolicy = tpm2.TPM2BDigest{}

	err := assertAdminAuthorizable(template)

	require.Error(t, err, "a template claiming policy administration with no policy must be refused")
	assert.ErrorIs(t, err, ErrAdminWithPolicyNoAuthPolicy,
		"the refusal must be matchable as ErrAdminWithPolicyNoAuthPolicy")
}

// TestAssertAdminAuthorizable_AcceptsEveryAuthorizableCombination proves the
// check refuses only the unauthorizable pair and nothing else, so it cannot
// block a legitimate template.
//
// Each accepted row leaves the ADMIN role reachable by something: the auth
// value when adminWithPolicy is CLEAR, and a policy session satisfying the
// digest when it is SET alongside one.
func TestAssertAdminAuthorizable_AcceptsEveryAuthorizableCombination(t *testing.T) {
	policy := tpm2.TPM2BDigest{Buffer: make([]byte, 32)}

	tests := []struct {
		name            string
		adminWithPolicy bool
		authPolicy      tpm2.TPM2BDigest
	}{
		{"auth value administers, no policy", false, tpm2.TPM2BDigest{}},
		{"auth value administers, policy present for the user role", false, policy},
		{"policy administers, policy present", true, policy},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			template := RSASSAIDevIDTemplate
			template.ObjectAttributes.AdminWithPolicy = tc.adminWithPolicy
			template.AuthPolicy = tc.authPolicy

			assert.NoError(t, assertAdminAuthorizable(template),
				"an authorizable admin role must not be refused")
		})
	}
}

// TestIDevIDTemplates_ShipTheTCGAdminPolicyShape pins the IDevID templates to
// TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12, Template
// H-0 (section 7.3.4.1): userWithAuth SET so the authValue can USE the key,
// adminWithPolicy SET so only a policy can ADMINISTER it (section 7.2.4).
//
// The templates deliberately ship with an EMPTY authPolicy. The IDevID/IAK
// Key Policy depends on the key's nameAlg, so CreateIDevID computes and
// assigns it at creation. That makes the raw template unauthorizable on its
// own -- assertAdminAuthorizable must refuse it -- which is the invariant that
// stops anyone creating a key from the template without going through the
// path that assigns the policy.
func TestIDevIDTemplates_ShipTheTCGAdminPolicyShape(t *testing.T) {
	templates := map[string]tpm2.TPMTPublic{
		"RSASSAIDevIDTemplate":  RSASSAIDevIDTemplate,
		"RSAPSSIDevIDTemplate":  RSAPSSIDevIDTemplate,
		"ECCIDevIDP256Template": ECCIDevIDP256Template,
	}

	for name, template := range templates {
		t.Run(name, func(t *testing.T) {
			a := template.ObjectAttributes
			assert.True(t, a.AdminWithPolicy,
				"section 7.2.4: adminWithPolicy SET disables the ADMIN role with authValue")
			assert.True(t, a.UserWithAuth,
				"section 7.2.4: userWithAuth SET enables the USER role via authValue")
			assert.True(t, a.FixedTPM && a.FixedParent && a.SensitiveDataOrigin && a.SignEncrypt,
				"Template H-0: fixedTPM, fixedParent, sensitiveDataOrigin, sign")
			assert.False(t, a.Restricted, "Template H-0: DevID (signing): Restricted = 0")
			assert.False(t, a.Decrypt, "Template H-0: decrypt = 0")
			assert.Empty(t, template.AuthPolicy.Buffer,
				"the key policy is per-nameAlg and is assigned by CreateIDevID, not by the template")
			assert.ErrorIs(t, assertAdminAuthorizable(template), ErrAdminWithPolicyNoAuthPolicy,
				"a raw template must be refused until the policy is assigned")

			// Assigning the policy CreateIDevID computes makes the template
			// authorizable, and the value is the specification's.
			policy, err := DevIDKeyPolicyDigest(DevIDKeySigning, template.NameAlg)
			require.NoError(t, err)
			template.AuthPolicy = tpm2.TPM2BDigest{Buffer: policy}
			assert.NoError(t, assertAdminAuthorizable(template))
		})
	}
}

// TestIDevIDAttributesFromConfig_AlwaysCarriesANonNilPassword pins the fact
// that made the removed guard dead code.
//
// The guard read `idevidAttrs.Password == nil && idevidAttrs.PlatformPolicy`,
// and CreateIDevID builds those attributes from this constructor alone.
// types.NewPassword documents that it never returns nil, so the guard could
// not fire and adminWithPolicy was never set. Pinning it here means a change
// that makes Password nil-able has to confront the guard's history rather
// than silently reviving the state #278 describes.
func TestIDevIDAttributesFromConfig_AlwaysCarriesANonNilPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
	}{
		{"no password configured", ""},
		{"password configured", "s3cret"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs, err := IDevIDAttributesFromConfig(IDevIDConfig{
				CN:           "device-id-001",
				Handle:       0x81020000,
				Hash:         "SHA-256",
				KeyAlgorithm: x509.RSA.String(),
				Password:     secrettest.Literal(t, []byte(tc.password)),

				PlatformPolicy:     true,
				SignatureAlgorithm: x509.SHA256WithRSA.String(),
			})
			require.NoError(t, err)

			assert.NotNil(t, attrs.Password,
				"types.NewPassword never returns nil, so a Password == nil guard is unreachable")
			assert.Equal(t, tc.password, string(attrs.Password.Bytes()))
			assert.True(t, (attrs.TPMPolicy == types.TPMPolicyPlatform))
		})
	}
}

// TestIDevIDAttributesFromConfig_RejectsAnUnparseableConfiguration proves the
// constructor reports a configuration it cannot build attributes from instead
// of returning a half-populated struct that CreateIDevID would carry into the
// TPM.
func TestIDevIDAttributesFromConfig_RejectsAnUnparseableConfiguration(t *testing.T) {
	attrs, err := IDevIDAttributesFromConfig(IDevIDConfig{
		CN:                 "device-id-001",
		Handle:             0x81020000,
		Hash:               "not-a-hash",
		KeyAlgorithm:       x509.RSA.String(),
		SignatureAlgorithm: x509.SHA256WithRSA.String(),
	})

	require.Error(t, err)
	assert.Nil(t, attrs, "no attributes may be returned alongside an error")
	assert.ErrorIs(t, err, ErrInvalidHashFunction)
}
