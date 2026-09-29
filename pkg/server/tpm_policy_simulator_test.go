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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/tpmpolicy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// policyPCR is the application PCR the end-to-end policies select.
const policyPCR = 23

// newTPMPolicyServer starts xkmsd over the TPM simulator and returns its
// XKMSService, whose TPM policy service is built and installed.
func newTPMPolicyServer(t *testing.T) *xkms.XKMSService {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	cfg := createMinimalConfig(t)
	cfg.Backends.TPM2 = &config.TPM2Config{Enabled: true, UseSimulator: true}
	server, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Shutdown()) })

	require.NotNil(t, server.TPMPolicyService(), "a TPM2 backend turns the TPM policy service on")
	svc := server.XKMSService()
	require.Same(t, server.TPMPolicyService(), svc.TPMPolicyService(), "the service is wired into the XKMSService")
	return svc
}

// identityCtx is a caller of tenant; the system tenant is cross-tenant.
func identityCtx(tenant string) context.Context {
	return auth.WithIdentity(context.Background(), &auth.Identity{Subject: "admin@" + tenant, TenantID: tenant, Roles: []string{"admin"}})
}

// generateTPMKey generates an ECDSA P-256 TPM2 key in tenant bound to policy.
func generateTPMKey(t *testing.T, svc *xkms.XKMSService, tenant, keyID, policy string) *ecdsa.PublicKey {
	t.Helper()
	resp, err := svc.GenerateKey(identityCtx(tenant), &transport.GenerateKeyRequest{
		KeyID:     keyID,
		Backend:   "tpm2",
		KeyType:   "signing",
		Algorithm: "ecdsa",
		Curve:     "P-256",
		TPMPolicy: policy,
		TenantID:  tenantOf(tenant),
	})
	require.NoError(t, err)
	block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
	require.NotNil(t, block)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err)
	ecPub, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	return ecPub
}

// tenantOf is the request TenantID a transport fills for a caller of tenant:
// empty for the system tenant.
func tenantOf(tenant string) string {
	if tenant == qrdbsdk.SystemTenantID {
		return ""
	}
	return tenant
}

// signWith signs a message with keyID as a caller of tenant and verifies the
// signature against pub, so a pass proves the TPM used that very key.
func signWith(t *testing.T, svc *xkms.XKMSService, tenant, keyID string, pub *ecdsa.PublicKey) {
	t.Helper()
	msg := []byte("tpm policy end to end")
	resp, err := svc.Sign(identityCtx(tenant), &transport.SignRequest{Backend: "tpm2", KeyID: keyID, Data: msg, TenantID: tenantOf(tenant)})
	require.NoError(t, err)
	digest := sha256.Sum256(msg)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], resp.Signature), "signature by %s verifies", keyID)
}

// TestTPMPolicy_EndToEnd drives xkmsd's TPM policy API over the simulator:
// a policy is created, two keys are generated bound to it, the registry
// answers in both directions, the policy cannot be deleted while the keys
// exist, and both keys sign.
func TestTPMPolicy_EndToEnd(t *testing.T) {
	svc := newTPMPolicyServer(t)
	sys := identityCtx(qrdbsdk.SystemTenantID)

	created, err := svc.TPMPolicyCreate(sys, &transport.TPMPolicyCreateRequest{Name: "boot", Bank: "sha256", PCRs: []uint{policyPCR}})
	require.NoError(t, err)
	assert.Equal(t, "boot", created.Name)
	assert.True(t, created.Approved)
	assert.Len(t, created.PCRValues, 1)

	pubA := generateTPMKey(t, svc, qrdbsdk.SystemTenantID, "boot-signer-a", "boot")
	pubB := generateTPMKey(t, svc, qrdbsdk.SystemTenantID, "boot-signer-b", "boot")

	objects, err := svc.TPMPolicyObjects(sys, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, []string{"key/boot-signer-a", "key/boot-signer-b"}, objects.Objects)

	obj, err := svc.TPMObjectPolicy(sys, &transport.TPMObjectPolicyRequest{KeyID: "boot-signer-a"})
	require.NoError(t, err)
	assert.Equal(t, "boot", obj.Policy)
	assert.NotEmpty(t, obj.AuthPolicy)

	err = svc.TPMPolicyDelete(sys, &transport.TPMPolicyDeleteRequest{Name: "boot"})
	var inUse *tpmpolicy.PolicyInUseError
	require.ErrorAs(t, err, &inUse, "a policy keys are bound to cannot be deleted")
	assert.Equal(t, []string{"key/boot-signer-a", "key/boot-signer-b"}, inUse.Objects)
	assert.Contains(t, err.Error(), "key/boot-signer-a, key/boot-signer-b")

	signWith(t, svc, qrdbsdk.SystemTenantID, "boot-signer-a", pubA)
	signWith(t, svc, qrdbsdk.SystemTenantID, "boot-signer-b", pubB)

	verified, err := svc.TPMPolicyVerify(sys, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.True(t, verified.Match)
	assert.True(t, verified.Approved)

	updated, err := svc.TPMPolicyUpdate(sys, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Greater(t, updated.Epoch, created.Epoch, "an update re-approves at the next epoch")
	signWith(t, svc, qrdbsdk.SystemTenantID, "boot-signer-a", pubA)

	list, err := svc.ListKeys(sys, "tpm2")
	require.NoError(t, err)
	assert.True(t, anyKeyHasCN(list.Keys, "boot-signer-a"), "the key is listed")
	for _, k := range list.Keys {
		assert.NotContains(t, k.KeyID, "tpm-policy-authority", "the policy service's objects are never listed")
	}

	require.NoError(t, svc.DeleteKey(sys, "tpm2", "boot-signer-a"))
	require.NoError(t, svc.DeleteKey(sys, "tpm2", "boot-signer-b"))
	require.NoError(t, svc.TPMPolicyDelete(sys, &transport.TPMPolicyDeleteRequest{Name: "boot"}), "the unused policy deletes")
}

// anyKeyHasCN reports whether a listed key's ID ends in cn.
func anyKeyHasCN(keys []transport.KeyInfo, cn string) bool {
	for _, k := range keys {
		if len(k.KeyID) >= len(cn) && k.KeyID[len(k.KeyID)-len(cn):] == cn {
			return true
		}
	}
	return false
}

// TestTPMPolicy_TenantsAreIsolated proves two tenant-scoped callers each see
// only their own TPM2 keys and policies, cannot use the other's key ID, and
// sign with keys of the same name that are different keys.
func TestTPMPolicy_TenantsAreIsolated(t *testing.T) {
	svc := newTPMPolicyServer(t)
	acme, globex := identityCtx("acme"), identityCtx("globex")

	_, err := svc.TPMPolicyCreate(acme, &transport.TPMPolicyCreateRequest{Name: "acme-boot", Bank: "sha256", PCRs: []uint{policyPCR}})
	require.NoError(t, err)

	acmePub := generateTPMKey(t, svc, "acme", "signer", "acme-boot")
	globexPub := generateTPMKey(t, svc, "globex", "signer", "")
	generateTPMKey(t, svc, "acme", "acme-only", "")
	assert.False(t, acmePub.Equal(globexPub), "the same key ID in two tenants is two keys")

	acmeKeys, err := svc.ListKeys(acme, "tpm2")
	require.NoError(t, err)
	assert.True(t, anyKeyHasCN(acmeKeys.Keys, "signer"))
	assert.True(t, anyKeyHasCN(acmeKeys.Keys, "acme-only"))
	globexKeys, err := svc.ListKeys(globex, "tpm2")
	require.NoError(t, err)
	assert.True(t, anyKeyHasCN(globexKeys.Keys, "signer"))
	assert.False(t, anyKeyHasCN(globexKeys.Keys, "acme-only"), "globex does not see acme's keys")

	acmePolicies, err := svc.TPMPolicyList(acme, &transport.TPMPolicyListRequest{})
	require.NoError(t, err)
	require.Len(t, acmePolicies.Policies, 1)
	assert.Equal(t, "acme-boot", acmePolicies.Policies[0].Name)
	globexPolicies, err := svc.TPMPolicyList(globex, &transport.TPMPolicyListRequest{})
	require.NoError(t, err)
	assert.Empty(t, globexPolicies.Policies, "globex does not see acme's policies")

	_, err = svc.TPMPolicyGet(globex, &transport.TPMPolicyRequest{TenantID: "acme", Name: "acme-boot"})
	require.ErrorIs(t, err, qrdbsdk.ErrTenantMissing, "globex cannot address acme's scope")
	_, err = svc.TPMObjectPolicy(globex, &transport.TPMObjectPolicyRequest{KeyID: "acme-only"})
	require.ErrorIs(t, err, tpmpolicy.ErrNotAssigned, "acme's key ID means nothing to globex")
	_, err = svc.Sign(globex, &transport.SignRequest{Backend: "tpm2", KeyID: "acme-only", Data: []byte("x"), TenantID: "globex"})
	require.ErrorIs(t, err, xkms.ErrKeyNotFound, "globex cannot sign with acme's key")

	obj, err := svc.TPMObjectPolicy(acme, &transport.TPMObjectPolicyRequest{KeyID: "signer"})
	require.NoError(t, err)
	assert.Equal(t, "acme-boot", obj.Policy)
	obj, err = svc.TPMObjectPolicy(globex, &transport.TPMObjectPolicyRequest{KeyID: "signer"})
	require.NoError(t, err)
	assert.Equal(t, tpmpolicy.PlatformPolicy, obj.Policy)

	signWith(t, svc, "acme", "signer", acmePub)
	signWith(t, svc, "globex", "signer", globexPub)

	sys := identityCtx(qrdbsdk.SystemTenantID)
	_, err = svc.SetTenantTPMMode(sys, &transport.SetTenantTPMModeRequest{TenantID: "acme", Mode: "none"})
	var scopeInUse *tpmpolicy.ScopeInUseError
	require.ErrorAs(t, err, &scopeInUse, "a tenant holding keys cannot leave its TPM")
}

// TestTPMPolicy_ModeNoneRefusesTenantKeys proves a tenant the system
// administrator set to TPM mode none cannot create a TPM2 key, with the
// policy service's typed error.
func TestTPMPolicy_ModeNoneRefusesTenantKeys(t *testing.T) {
	svc := newTPMPolicyServer(t)
	_, err := svc.SetTenantTPMMode(identityCtx(qrdbsdk.SystemTenantID), &transport.SetTenantTPMModeRequest{TenantID: "initech", Mode: "none"})
	require.NoError(t, err)

	_, err = svc.GenerateKey(identityCtx("initech"), &transport.GenerateKeyRequest{
		KeyID: "signer", Backend: "tpm2", KeyType: "signing", Algorithm: "ecdsa", Curve: "P-256", TenantID: "initech",
	})
	require.ErrorIs(t, err, tpmpolicy.ErrTPMModeNone)
}
