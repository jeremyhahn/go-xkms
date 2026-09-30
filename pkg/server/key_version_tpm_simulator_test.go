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

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
)

// TestKeyVersions_TPM2TenantKeyRotatesUnderItsPolicy drives a key rotation
// through xkmsd over the TPM simulator: a tenant's TPM2 key bound to a named
// policy rotates into a new TPM object in the same tenant scope, bound to
// the same policy; both versions sign; the old version's signature still
// verifies; and deleting the key deletes both TPM objects and their policy
// assignments.
func TestKeyVersions_TPM2TenantKeyRotatesUnderItsPolicy(t *testing.T) {
	svc := newTPMPolicyServer(t)
	acme := identityCtx("acme")
	require.NotNil(t, svc.KeyVersionStore(), "xkmsd wires the key-version store")

	_, err := svc.TPMPolicyCreate(acme, &transport.TPMPolicyCreateRequest{Name: "acme-boot", Bank: "sha256", PCRs: []uint{policyPCR}})
	require.NoError(t, err)
	pubV1 := generateTPMKey(t, svc, "acme", "signer", "acme-boot")

	msg := []byte("signed before the rotation")
	oldSig, err := svc.Sign(acme, &transport.SignRequest{Backend: "tpm2", KeyID: "signer", Data: msg, TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, uint32(1), oldSig.KeyVersion)

	rotated, err := svc.RotateKey(acme, &transport.RotateKeyRequest{Backend: "tpm2", KeyID: "signer", TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), rotated.KeyVersion)
	pubV2 := ecdsaFromPEM(t, rotated.PublicKeyPEM)
	assert.False(t, pubV1.Equal(pubV2), "version 2 is a new TPM key")

	// The new version is a TPM object of acme's scope bound to acme's policy.
	assignment, err := svc.TPMPolicyService().PolicyOf(context.Background(), "acme", tpmpolicy.ObjectKey, "signer--v2")
	require.NoError(t, err)
	assert.Equal(t, "acme-boot", assignment.Policy)
	objects, err := svc.TPMPolicyObjects(acme, &transport.TPMPolicyRequest{Name: "acme-boot"})
	require.NoError(t, err)
	assert.Equal(t, []string{"key/signer", "key/signer--v2"}, objects.Objects)
	_, err = svc.TPMPolicyService().PolicyOf(context.Background(), "", tpmpolicy.ObjectKey, "signer--v2")
	assert.Error(t, err, "the version is not in the system scope")

	// Sign uses version 2; both versions' signatures verify.
	newSig, err := svc.Sign(acme, &transport.SignRequest{Backend: "tpm2", KeyID: "signer", Data: msg, TenantID: "acme"})
	require.NoError(t, err)
	assert.Equal(t, uint32(2), newSig.KeyVersion)
	digest := sha256.Sum256(msg)
	assert.True(t, ecdsa.VerifyASN1(pubV2, digest[:], newSig.Signature), "version 2 signed")
	assert.True(t, ecdsa.VerifyASN1(pubV1, digest[:], oldSig.Signature), "version 1 signed")

	verified, err := svc.Verify(acme, &transport.VerifyRequest{Backend: "tpm2", KeyID: "signer", Data: msg, Signature: oldSig.Signature, TenantID: "acme"})
	require.NoError(t, err)
	assert.True(t, verified.Valid, "the old signature verifies without key_version")
	assert.Equal(t, uint32(1), verified.KeyVersion)
	verified, err = svc.Verify(acme, &transport.VerifyRequest{Backend: "tpm2", KeyID: "signer", Data: msg, Signature: newSig.Signature, TenantID: "acme", KeyVersion: 2})
	require.NoError(t, err)
	assert.True(t, verified.Valid)

	// The key is listed once, at its current version; another tenant sees
	// nothing of it.
	listed, err := svc.ListKeys(acme, "tpm2")
	require.NoError(t, err)
	var seen int
	for _, k := range listed.Keys {
		if k.KeyID == "signer" {
			seen++
			assert.Equal(t, uint32(2), k.KeyVersion)
		}
		assert.NotEqual(t, "signer--v2", k.KeyID, "a version is never listed on its own")
	}
	assert.Equal(t, 1, seen)
	_, err = svc.RotateKey(identityCtx("globex"), &transport.RotateKeyRequest{Backend: "tpm2", KeyID: "signer", TenantID: "globex"})
	assert.Error(t, err, "globex cannot rotate acme's key")

	// Deleting the key deletes both TPM objects and frees the policy.
	require.NoError(t, svc.DeleteKey(acme, "tpm2", "signer"))
	objects, err = svc.TPMPolicyObjects(acme, &transport.TPMPolicyRequest{Name: "acme-boot"})
	require.NoError(t, err)
	assert.Empty(t, objects.Objects)
	require.NoError(t, svc.TPMPolicyDelete(acme, &transport.TPMPolicyDeleteRequest{Name: "acme-boot"}))
}

// ecdsaFromPEM parses a PEM-encoded ECDSA public key.
func ecdsaFromPEM(t *testing.T, pemStr string) *ecdsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	return ecPub
}
