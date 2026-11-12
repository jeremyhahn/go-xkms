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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grpcinternal "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal/appraisaltest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	pkgtpm2 "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// policyPCR is the application PCR the end-to-end policies select.
const policyPCR = 23

// newTPMPolicyServer starts xkmsd over the TPM simulator and returns its
// XKMSService, whose TPM policy service is built and installed.
func newTPMPolicyServer(t *testing.T) *xkms.XKMSService {
	t.Helper()
	return newTPMPolicyServerWith(t, &config.TPM2Config{Enabled: true, UseSimulator: true})
}

// newReferenceTPMPolicyServer starts xkmsd over the TPM simulator with
// backends.tpm2.reference_signer pinned to signer's public key.
func newReferenceTPMPolicyServer(t *testing.T, signer *ecdsa.PrivateKey) *xkms.XKMSService {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&signer.PublicKey)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "reference-signer.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600))
	return newTPMPolicyServerWith(t, &config.TPM2Config{Enabled: true, UseSimulator: true, ReferenceSigner: &config.ReferenceSignerConfig{PublicKey: path}})
}

// newTPMPolicyServerWith starts xkmsd with the tpm2 backend config.
func newTPMPolicyServerWith(t *testing.T, tpm2 *config.TPM2Config) *xkms.XKMSService {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	cfg := createMinimalConfig(t)
	cfg.Backends.TPM2 = tpm2
	cfg.CA = testFirstBootCAConfig()
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

	created, err := svc.TPMPolicyCreate(sys, &transport.TPMPolicyCreateRequest{Name: "boot", Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{policyPCR})}})
	require.NoError(t, err)
	assert.Equal(t, "boot", created.Name)
	assert.True(t, created.Approved)
	require.Len(t, created.Branches, 1)
	assert.Len(t, created.Branches[0].Conditions[0].PCRValues, 1)

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

	updated, err := svc.TPMPolicyUpdate(sys, &transport.TPMPolicyUpdateRequest{Name: "boot"})
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

// TestTPMPolicy_VerifyReportsReference drives a signed reference manifest
// through xkmsd's reference_signer config, the XKMSService, the gRPC server
// and the MCP server, and reads the branch Reference back from verify on each.
func TestTPMPolicy_VerifyReportsReference(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	svc := newReferenceTPMPolicyServer(t, signer)
	sys := identityCtx(qrdbsdk.SystemTenantID)
	grpcSvc := grpcinternal.NewService(nil, nil, svc)
	mcpSrv, err := mcp.NewServer(&mcp.Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)
	mcpParams := func(v any) json.RawMessage {
		raw, err := json.Marshal(v)
		require.NoError(t, err)
		return raw
	}

	final := sha256.Sum256([]byte("next boot"))
	pcrs := map[uint32][]byte{policyPCR: final[:]}
	corim, err := appraisaltest.SignCoRIM(pcrs, signer, nil)
	require.NoError(t, err)
	forged, err := appraisaltest.SignCoRIM(pcrs, other, nil)
	require.NoError(t, err)

	branch := func(name string) transport.TPMPolicyBranch {
		return transport.TPMPolicyBranch{Name: name, Conditions: transport.TPMPolicyPCRBranch("sha256", []uint{policyPCR}).Conditions}
	}
	_, err = svc.TPMPolicyCreate(sys, &transport.TPMPolicyCreateRequest{Name: "boot", Branches: []transport.TPMPolicyBranch{branch("current"), branch("next")}})
	require.NoError(t, err)

	// A manifest signed by another key is refused on both paths.
	_, err = svc.TPMPolicyUpdate(sys, &transport.TPMPolicyUpdateRequest{Name: "boot", Branch: "next", ReferenceValues: forged})
	require.Error(t, err, "the XKMSService refuses a manifest the pinned signer did not sign")
	_, err = grpcSvc.TPMPolicyUpdate(sys, &pb.TPMPolicyUpdateRequest{Name: "boot", Branch: "next", ReferenceValues: forged})
	require.Error(t, err, "the gRPC server refuses a manifest the pinned signer did not sign")
	_, err = mcpSrv.InvokeMethod(sys, "tpm.policy.update", mcpParams(transport.TPMPolicyUpdateRequest{Name: "boot", Branch: "next", ReferenceValues: forged}))
	var keyOpErr *mcp.KeyOpError
	require.ErrorAs(t, err, &keyOpErr, "the MCP server refuses a manifest the pinned signer did not sign")
	before, err := svc.TPMPolicyVerify(sys, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	for _, b := range before.Branches {
		assert.Nil(t, b.Reference, "a refused update leaves branch %q without a reference", b.Name)
	}

	updated, err := svc.TPMPolicyUpdate(sys, &transport.TPMPolicyUpdateRequest{Name: "boot", Branch: "next", ReferenceValues: corim})
	require.NoError(t, err)
	digest := sha256.Sum256(corim)
	var ref *transport.TPMPolicyReference
	for _, b := range updated.Branches {
		switch b.Name {
		case "current":
			assert.Nil(t, b.Reference, "the branch not updated carries no reference")
		case "next":
			ref = b.Reference
		}
	}
	require.NotNil(t, ref, "the updated branch carries its reference")
	assert.Equal(t, digest[:], ref.Digest)

	verified, err := svc.TPMPolicyVerify(sys, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.False(t, verified.Match, "the policy matches only if every branch does")
	assert.True(t, verified.Approved)
	require.Len(t, verified.Branches, 2)
	for _, b := range verified.Branches {
		assert.True(t, b.Approved, "branch %q", b.Name)
		switch b.Name {
		case "current":
			assert.True(t, b.Match)
			assert.Nil(t, b.Reference)
		case "next":
			assert.False(t, b.Match)
			assert.Equal(t, []uint{policyPCR}, b.Mismatched)
			assert.Equal(t, ref, b.Reference)
		default:
			t.Fatalf("unexpected branch %q", b.Name)
		}
	}

	_, err = grpcSvc.TPMPolicyUpdate(sys, &pb.TPMPolicyUpdateRequest{Name: "boot", Branch: "next", ReferenceValues: corim})
	require.NoError(t, err, "the gRPC server updates the branch from the same manifest")
	got, err := grpcSvc.TPMPolicyVerify(sys, &pb.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	require.Len(t, got.GetBranches(), 2)
	for _, b := range got.GetBranches() {
		assert.True(t, b.GetApproved(), "branch %q", b.GetName())
		switch b.GetName() {
		case "current":
			assert.True(t, b.GetMatch())
			assert.Nil(t, b.GetReference())
		case "next":
			assert.False(t, b.GetMatch())
			assert.Equal(t, []uint32{policyPCR}, b.GetMismatched())
			require.NotNil(t, b.GetReference(), "the gRPC server reports the reference")
			assert.Equal(t, digest[:], b.GetReference().GetDigest())
		default:
			t.Fatalf("unexpected branch %q", b.GetName())
		}
	}

	_, err = mcpSrv.InvokeMethod(sys, "tpm.policy.update", mcpParams(transport.TPMPolicyUpdateRequest{Name: "boot", Branch: "next", ReferenceValues: corim}))
	require.NoError(t, err, "the MCP server updates the branch from the same manifest")
	result, err := mcpSrv.InvokeMethod(sys, "tpm.policy.verify", mcpParams(transport.TPMPolicyRequest{Name: "boot"}))
	require.NoError(t, err)
	var mcpVerified transport.TPMPolicyVerifyResponse
	require.NoError(t, json.Unmarshal(mcpParams(result), &mcpVerified), "the MCP result decodes off the wire")
	require.Len(t, mcpVerified.Branches, 2)
	for _, b := range mcpVerified.Branches {
		assert.True(t, b.Approved, "branch %q", b.Name)
		switch b.Name {
		case "current":
			assert.True(t, b.Match)
			assert.Nil(t, b.Reference)
		case "next":
			assert.False(t, b.Match)
			assert.Equal(t, []uint{policyPCR}, b.Mismatched)
			require.NotNil(t, b.Reference, "the MCP server reports the reference")
			assert.Equal(t, digest[:], b.Reference.Digest)
		default:
			t.Fatalf("unexpected branch %q", b.Name)
		}
	}
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

	_, err := svc.TPMPolicyCreate(acme, &transport.TPMPolicyCreateRequest{Name: "acme-boot", Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{policyPCR})}})
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

// TestTPMPolicy_SealsWithoutKeyIDAreDistinctObjects proves each TPM2 seal
// without a key ID creates its own sealed object: a second seal does not
// overwrite the first's blobs, policy binding or registry assignment, and
// the first still unseals, by the key ID its seal returned, to its own
// plaintext.
func TestTPMPolicy_SealsWithoutKeyIDAreDistinctObjects(t *testing.T) {
	svc := newTPMPolicyServer(t)
	sys := identityCtx(qrdbsdk.SystemTenantID)
	_, err := svc.TPMPolicyCreate(sys, &transport.TPMPolicyCreateRequest{Name: "boot", Branches: []transport.TPMPolicyBranch{transport.TPMPolicyPCRBranch("sha256", []uint{policyPCR})}})
	require.NoError(t, err)

	first, err := svc.Seal(sys, &transport.SealRequest{Backend: "tpm2", Data: []byte("first"), TPMPolicy: "boot"})
	require.NoError(t, err)
	second, err := svc.Seal(sys, &transport.SealRequest{Backend: "tpm2", Data: []byte("second"), TPMPolicy: "platform"})
	require.NoError(t, err)
	require.NotEmpty(t, first.KeyID, "the seal names the object it created")
	require.NotEmpty(t, second.KeyID)
	assert.NotEqual(t, first.KeyID, second.KeyID, "two seals are two objects")

	objects, err := svc.TPMPolicyObjects(sys, &transport.TPMPolicyRequest{Name: "boot"})
	require.NoError(t, err)
	assert.Equal(t, []string{"sealed/" + first.KeyID}, objects.Objects, "the first object's assignment survives the second seal")

	for _, tc := range []struct {
		sealed *transport.SealResponse
		want   string
	}{{first, "first"}, {second, "second"}} {
		got, err := svc.Unseal(sys, &transport.UnsealRequest{
			Backend:    "tpm2",
			KeyID:      tc.sealed.KeyID,
			TPMPublic:  tc.sealed.TPMPublic,
			TPMPrivate: tc.sealed.TPMPrivate,
		})
		require.NoError(t, err, tc.want)
		assert.Equal(t, []byte(tc.want), got.Plaintext)
	}
}

// TestTPMPolicy_SealWithoutPolicyOrPasswordRefused proves a TPM2 seal through
// the service that names neither a policy nor a password is refused rather
// than creating an object any holder of its blobs could unseal.
func TestTPMPolicy_SealWithoutPolicyOrPasswordRefused(t *testing.T) {
	svc := newTPMPolicyServer(t)
	sys := identityCtx(qrdbsdk.SystemTenantID)

	_, err := svc.Seal(sys, &transport.SealRequest{Backend: "tpm2", Data: []byte("unprotected")})
	require.ErrorIs(t, err, pkgtpm2.ErrSealUnprotected)

	protected, err := svc.Seal(sys, &transport.SealRequest{Backend: "tpm2", Data: []byte("protected"), Password: []byte("object-password")})
	require.NoError(t, err)
	got, err := svc.Unseal(sys, &transport.UnsealRequest{
		Backend:    "tpm2",
		KeyID:      protected.KeyID,
		TPMPublic:  protected.TPMPublic,
		TPMPrivate: protected.TPMPrivate,
		Password:   []byte("object-password"),
	})
	require.NoError(t, err)
	assert.Equal(t, []byte("protected"), got.Plaintext)
}
