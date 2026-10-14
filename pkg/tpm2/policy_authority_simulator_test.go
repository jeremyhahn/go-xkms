//go:build tpm_simulator

package tpm2

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthorityName_FallsBackToTPMBackend proves a nil backend argument uses
// the TPM's own backend, and that with neither the call fails typed.
func TestAuthorityName_FallsBackToTPMBackend(t *testing.T) {
	f := newPolicyFixture(t)
	want, _, err := f.h.TPM.AuthorityName(f.authority, f.h.Backend)
	require.NoError(t, err)

	f.h.TPM.backend = f.h.Backend
	got, _, err := f.h.TPM.AuthorityName(f.authority, nil)
	require.NoError(t, err)
	assert.Equal(t, want.Buffer, got.Buffer)

	f.h.TPM.backend = nil
	_, _, err = f.h.TPM.AuthorityName(f.authority, nil)
	assert.ErrorIs(t, err, ErrNoStorageBackend)
}

// TestSignApproval_RefusesNonECCAuthority proves an RSA authority is refused
// before the TPM signs anything: approvals are ECDSA-only.
func TestSignApproval_RefusesNonECCAuthority(t *testing.T) {
	f := newPolicyFixture(t)
	attrs := f.keyAttrs("rsa-authority", nil)
	attrs.KeyAlgorithm = x509.RSA
	attrs.SignatureAlgorithm = x509.SHA256WithRSA
	attrs.ECCAttributes = nil
	attrs.RSAAttributes = &types.RSAAttributes{KeySize: 2048}
	_, err := f.h.TPM.CreateRSA(attrs, f.h.Backend, false)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("approval"))
	_, err = f.h.TPM.SignApproval(attrs, f.h.Backend, digest[:])
	assert.ErrorIs(t, err, ErrInvalidAuthoritySignature)
}

// TestVerifyApproval_SignatureAndKeyErrors proves the TPM, not the caller,
// judges an approval: a signature over another digest and an authority public
// area the TPM cannot load are both rejected without a ticket.
func TestVerifyApproval_SignatureAndKeyErrors(t *testing.T) {
	f := newPolicyFixture(t)
	_, public, err := f.h.TPM.AuthorityName(f.authority, f.h.Backend)
	require.NoError(t, err)
	signed := sha256.Sum256([]byte("approved"))
	signature, err := f.h.TPM.SignApproval(f.authority, f.h.Backend, signed[:])
	require.NoError(t, err)

	ticket, _, err := f.h.TPM.verifyApproval(public, signed[:], *signature)
	require.NoError(t, err)
	require.NotNil(t, ticket)

	other := sha256.Sum256([]byte("not approved"))
	ticket, _, err = f.h.TPM.verifyApproval(public, other[:], *signature)
	assert.Error(t, err)
	assert.Nil(t, ticket)

	ticket, _, err = f.h.TPM.verifyApproval(tpm2.TPM2BPublic{}, signed[:], *signature)
	assert.Error(t, err)
	assert.Nil(t, ticket)
}
