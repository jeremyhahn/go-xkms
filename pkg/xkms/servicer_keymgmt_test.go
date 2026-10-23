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

package xkms

import (
	"crypto/ecdsa"
	"crypto/fips140"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/keypolicy"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// keyManagementService returns a service with the key policy store wired, an
// ECDSA key "signer" and an AES-256-GCM key "aead".
func keyManagementService(t *testing.T) *XKMSService {
	t.Helper()
	svc := setupDeriveService(t)
	store, err := keypolicy.NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	svc.SetKeyPolicyStore(store)
	genKey(t, svc, "", "signer", "ecdsa", 0)
	genKey(t, svc, "", "aead", "aes-256-gcm", 0)
	return svc
}

// keyRequest names a key on the software backend.
func keyRequest(keyID string) *transport.KeyManagementRequest {
	return &transport.KeyManagementRequest{Backend: "software", KeyID: keyID}
}

func TestGetPublicKey_ReturnsDERSubjectPublicKeyInfo(t *testing.T) {
	svc := keyManagementService(t)
	resp, err := svc.GetPublicKey(ctxFor(""), &transport.GetPublicKeyRequest{Backend: "software", KeyID: "signer"})
	require.NoError(t, err)
	pub, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PublicKey{}, pub)
	assert.Equal(t, "signer", resp.KeyID)
	assert.Equal(t, uint64(1), resp.Version)
}

func TestGetPublicKey_RefusesSymmetricKey(t *testing.T) {
	svc := keyManagementService(t)
	_, err := svc.GetPublicKey(ctxFor(""), &transport.GetPublicKeyRequest{Backend: "software", KeyID: "aead"})
	var kindErr *KeyKindError
	require.ErrorAs(t, err, &kindErr)

	_, err = svc.GetPublicKey(ctxFor(""), nil)
	var validation *ErrValidation
	require.ErrorAs(t, err, &validation)
}

func TestRevokeKey_IsTerminal(t *testing.T) {
	svc := keyManagementService(t)
	ctx := ctxFor("")
	resp, err := svc.RevokeKey(ctx, &transport.RevokeKeyRequest{Backend: "software", KeyID: "signer", Reason: "compromised"})
	require.NoError(t, err)
	assert.Equal(t, transport.KeyStatusCompromised, resp.Status)

	meta, err := svc.GetKeyMetadata(ctx, keyRequest("signer"))
	require.NoError(t, err)
	assert.Equal(t, transport.KeyStatusCompromised, meta.Metadata.Status)

	_, err = svc.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "signer", Status: transport.KeyStatusEnabled})
	var transition *KeyStatusTransitionError
	require.ErrorAs(t, err, &transition)
}

// TestDeleteKey_RemovesThePolicyRecord deletes a revoked, usage-limited key
// and creates it again under the same backend and ID: the new key inherits
// none of its predecessor's metadata, status, limits or counters.
func TestDeleteKey_RemovesThePolicyRecord(t *testing.T) {
	svc := keyManagementService(t)
	ctx := ctxFor("")
	_, err := svc.UpdateKeyMetadata(ctx, &transport.UpdateKeyMetadataRequest{Backend: "software", KeyID: "aead", Name: "old"})
	require.NoError(t, err)
	_, err = svc.SetKeySafety(ctx, &transport.SetKeySafetyRequest{Backend: "software", KeyID: "aead", MaxOperations: 1})
	require.NoError(t, err)
	encrypt := &transport.EncryptRequest{Backend: "software", KeyID: "aead", Plaintext: []byte("x")}
	_, err = svc.Encrypt(ctx, encrypt)
	require.NoError(t, err)
	_, err = svc.RevokeKey(ctx, &transport.RevokeKeyRequest{Backend: "software", KeyID: "aead", Reason: "retired"})
	require.NoError(t, err)

	require.NoError(t, svc.DeleteKey(ctx, "software", "aead"))
	genKey(t, svc, "", "aead", "aes-256-gcm", 0)

	meta, err := svc.GetKeyMetadata(ctx, keyRequest("aead"))
	require.NoError(t, err)
	assert.Equal(t, transport.KeyStatusEnabled, meta.Metadata.Status)
	assert.Empty(t, meta.Metadata.Name)
	report, err := svc.SafetyReport(ctx, &transport.SafetyReportRequest{})
	require.NoError(t, err)
	assert.Empty(t, report.AllItems, "the limits went with the deleted key")
	for range 2 {
		_, err = svc.Encrypt(ctx, encrypt)
		require.NoError(t, err)
	}
}

// TestDeleteKey_UnknownKeyKeepsOtherRecords refuses to delete a key that does
// not exist and leaves the records of the keys that do untouched.
func TestDeleteKey_UnknownKeyKeepsOtherRecords(t *testing.T) {
	svc := keyManagementService(t)
	ctx := ctxFor("")
	_, err := svc.RevokeKey(ctx, &transport.RevokeKeyRequest{Backend: "software", KeyID: "signer", Reason: "compromised"})
	require.NoError(t, err)

	require.ErrorIs(t, svc.DeleteKey(ctx, "software", "ghost"), ErrKeyNotFound)
	meta, err := svc.GetKeyMetadata(ctx, keyRequest("signer"))
	require.NoError(t, err)
	assert.Equal(t, transport.KeyStatusCompromised, meta.Metadata.Status)
}

func TestRevokeKey_UnknownKey(t *testing.T) {
	svc := keyManagementService(t)
	_, err := svc.RevokeKey(ctxFor(""), &transport.RevokeKeyRequest{Backend: "software", KeyID: "missing"})
	require.Error(t, err)

	_, err = svc.RevokeKey(ctxFor(""), nil)
	var validation *ErrValidation
	require.ErrorAs(t, err, &validation)
}

func TestUpdateKeyStatus_DisablesAndEnables(t *testing.T) {
	svc := keyManagementService(t)
	ctx := ctxFor("")
	for _, status := range []transport.KeyStatus{transport.KeyStatusDisabled, transport.KeyStatusEnabled} {
		resp, err := svc.UpdateKeyStatus(ctx, &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "signer", Status: status})
		require.NoError(t, err)
		assert.Equal(t, status, resp.Status)

		meta, err := svc.GetKeyMetadata(ctx, keyRequest("signer"))
		require.NoError(t, err)
		assert.Equal(t, status, meta.Metadata.Status)
	}
}

func TestUpdateKeyStatus_RejectsUnsettableStatus(t *testing.T) {
	svc := keyManagementService(t)
	var invalid *InvalidKeyPolicyError
	_, err := svc.UpdateKeyStatus(ctxFor(""), &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "signer", Status: transport.KeyStatusDeleted})
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "status", invalid.Field)

	_, err = svc.UpdateKeyStatus(ctxFor(""), &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: "signer", Version: 1 << 33})
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, "version", invalid.Field)
}

func TestKeyMetadata_UpdateMergesTags(t *testing.T) {
	svc := keyManagementService(t)
	ctx := ctxFor("")
	_, err := svc.UpdateKeyMetadata(ctx, &transport.UpdateKeyMetadataRequest{
		Backend: "software", KeyID: "signer", Name: "Signer", Description: "release signing",
		Tags: map[string]string{"env": "prod", "team": "pki"},
	})
	require.NoError(t, err)
	resp, err := svc.UpdateKeyMetadata(ctx, &transport.UpdateKeyMetadataRequest{
		Backend: "software", KeyID: "signer", RemoveTags: []string{"team"},
	})
	require.NoError(t, err)
	assert.Equal(t, "Signer", resp.Metadata.Name)

	got, err := svc.GetKeyMetadata(ctx, keyRequest("signer"))
	require.NoError(t, err)
	assert.Equal(t, "release signing", got.Metadata.Description)
	assert.Equal(t, map[string]string{"env": "prod"}, got.Metadata.Tags)
	assert.Equal(t, transport.KeyStatusEnabled, got.Metadata.Status)
}

func TestKeyMetadata_RejectsEmptyTagName(t *testing.T) {
	svc := keyManagementService(t)
	_, err := svc.UpdateKeyMetadata(ctxFor(""), &transport.UpdateKeyMetadataRequest{
		Backend: "software", KeyID: "signer", Tags: map[string]string{"": "x"},
	})
	var invalid *InvalidKeyPolicyError
	require.ErrorAs(t, err, &invalid)

	_, err = svc.GetKeyMetadata(ctxFor(""), keyRequest("missing"))
	require.Error(t, err)
}

func TestKeyPolicy_SetVersionsGetAndDelete(t *testing.T) {
	svc := keyManagementService(t)
	ctx := ctxFor("")
	policy := &transport.KeyPolicy{AllowedOperations: []transport.KeyUsage{transport.KeyUsageSign}, MaxUsageCount: 10}
	for want := uint64(1); want <= 2; want++ {
		resp, err := svc.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{Backend: "software", KeyID: "signer", Policy: policy})
		require.NoError(t, err)
		assert.Equal(t, want, resp.PolicyVersion)
	}

	got, err := svc.GetKeyPolicy(ctx, keyRequest("signer"))
	require.NoError(t, err)
	require.NotNil(t, got.Policy)
	assert.Equal(t, uint64(2), got.Policy.Version)
	assert.Equal(t, []transport.KeyUsage{transport.KeyUsageSign}, got.Policy.AllowedOperations)

	_, err = svc.DeleteKeyPolicy(ctx, keyRequest("signer"))
	require.NoError(t, err)
	got, err = svc.GetKeyPolicy(ctx, keyRequest("signer"))
	require.NoError(t, err)
	assert.Nil(t, got.Policy)
}

func TestKeyPolicy_RefusesUnenforceableAndInvalid(t *testing.T) {
	svc := keyManagementService(t)
	ctx := ctxFor("")
	set := func(p *transport.KeyPolicy) error {
		_, err := svc.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{Backend: "software", KeyID: "signer", Policy: p})
		return err
	}

	var unenforceable *UnenforceablePolicyError
	require.ErrorAs(t, set(&transport.KeyPolicy{RequireMFA: true}), &unenforceable)

	var invalid *InvalidKeyPolicyError
	require.ErrorAs(t, set(&transport.KeyPolicy{AllowedOperations: []transport.KeyUsage{"teleport"}}), &invalid)
	require.ErrorAs(t, set(&transport.KeyPolicy{ExpiresAt: -1}), &invalid)

	var validation *ErrValidation
	require.ErrorAs(t, set(nil), &validation)

	_, err := svc.DeleteKeyPolicy(ctx, keyRequest("missing"))
	require.Error(t, err)
}

func TestKeyPolicy_WritesNeedTheStore(t *testing.T) {
	svc := setupDeriveService(t)
	genKey(t, svc, "", "signer", "ecdsa", 0)
	ctx := ctxFor("")

	_, err := svc.SetKeyPolicy(ctx, &transport.SetKeyPolicyRequest{Backend: "software", KeyID: "signer", Policy: &transport.KeyPolicy{}})
	require.ErrorIs(t, err, ErrKeyPoliciesNotConfigured)
	_, err = svc.RevokeKey(ctx, &transport.RevokeKeyRequest{Backend: "software", KeyID: "signer"})
	require.ErrorIs(t, err, ErrKeyPoliciesNotConfigured)

	// Reads answer from the implicit record.
	got, err := svc.GetKeyPolicy(ctx, keyRequest("signer"))
	require.NoError(t, err)
	assert.Nil(t, got.Policy)
}

func TestKeyRotationPolicy_SetGetAndDelete(t *testing.T) {
	svc := keyManagementService(t)
	ctx := ctxFor("")
	resp, err := svc.SetKeyRotationPolicy(ctx, &transport.SetKeyRotationPolicyRequest{
		Backend: "software", KeyID: "signer", Policy: &transport.RotationPolicy{Enabled: true, IntervalSeconds: 3600},
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Policy)
	assert.Positive(t, resp.Policy.NextRotation, "an enabled policy schedules the next rotation")

	got, err := svc.GetKeyRotationPolicy(ctx, keyRequest("signer"))
	require.NoError(t, err)
	require.NotNil(t, got.Policy)
	assert.Equal(t, int64(3600), got.Policy.IntervalSeconds)

	_, err = svc.DeleteKeyRotationPolicy(ctx, keyRequest("signer"))
	require.NoError(t, err)
	got, err = svc.GetKeyRotationPolicy(ctx, keyRequest("signer"))
	require.NoError(t, err)
	assert.Nil(t, got.Policy)
}

func TestKeyRotationPolicy_RefusesWhatTheServiceCannotEnforce(t *testing.T) {
	svc := keyManagementService(t)
	set := func(p *transport.RotationPolicy) error {
		_, err := svc.SetKeyRotationPolicy(ctxFor(""), &transport.SetKeyRotationPolicyRequest{Backend: "software", KeyID: "signer", Policy: p})
		return err
	}

	var unenforceable *UnenforceablePolicyError
	require.ErrorAs(t, set(&transport.RotationPolicy{AutoRotate: true}), &unenforceable)
	require.ErrorAs(t, set(&transport.RotationPolicy{RetainVersions: 3}), &unenforceable)

	var invalid *InvalidKeyPolicyError
	require.ErrorAs(t, set(&transport.RotationPolicy{Enabled: true}), &invalid)
	require.ErrorAs(t, set(&transport.RotationPolicy{IntervalSeconds: -1}), &invalid)
	require.ErrorAs(t, set(&transport.RotationPolicy{NextRotation: -1}), &invalid)

	_, err := svc.GetKeyRotationPolicy(ctxFor(""), nil)
	var validation *ErrValidation
	require.ErrorAs(t, err, &validation)
}

func TestKeySafety_SetReportAndClear(t *testing.T) {
	svc := keyManagementService(t)
	ctx := ctxFor("")
	_, err := svc.SetKeySafety(ctx, &transport.SetKeySafetyRequest{Backend: "software", KeyID: "aead", MaxOperations: 1000, WarningPercent: 80})
	require.NoError(t, err)

	report, err := svc.SafetyReport(ctx, &transport.SafetyReportRequest{Format: "json"})
	require.NoError(t, err)
	require.Len(t, report.AllItems, 1)
	assert.Equal(t, int32(1), report.TotalKeys)
	assert.Equal(t, "software/aead", report.AllItems[0].Path)
	assert.Equal(t, uint64(1000), report.AllItems[0].MaxOperations)

	check, err := svc.SafetyCheck(ctx, &transport.SafetyCheckRequest{})
	require.NoError(t, err)
	assert.Empty(t, check.Warnings, "an unused key is below its warning level")

	_, err = svc.ClearKeySafety(ctx, keyRequest("aead"))
	require.NoError(t, err)
	report, err = svc.SafetyReport(ctx, &transport.SafetyReportRequest{})
	require.NoError(t, err)
	assert.Empty(t, report.AllItems)
}

// TestKeySafety_RotationKeepsThePerVersionLimit rotates a usage-limited key
// while encryptions run against it. Every encryption is charged to the
// version it encrypts under, so no version's material is used past the limit
// and a rotation never erases what was charged to the version it published.
func TestKeySafety_RotationKeepsThePerVersionLimit(t *testing.T) {
	svc := keyManagementService(t)
	ctx := ctxFor("")
	const limit, encryptions, rotations = 4, 48, 3
	_, err := svc.SetKeySafety(ctx, &transport.SetKeySafetyRequest{Backend: "software", KeyID: "aead", MaxOperations: limit})
	require.NoError(t, err)

	var mu sync.Mutex
	perVersion := map[uint32]uint64{}
	var wg sync.WaitGroup
	for range encryptions {
		wg.Go(func() {
			resp, err := svc.Encrypt(ctx, &transport.EncryptRequest{Backend: "software", KeyID: "aead", Plaintext: []byte("x")})
			if err != nil {
				var limitErr *keypolicy.SafetyLimitError
				assert.ErrorAs(t, err, &limitErr)
				return
			}
			mu.Lock()
			perVersion[resp.KeyVersion]++
			mu.Unlock()
		})
	}
	for range rotations {
		wg.Go(func() {
			_, err := svc.RotateKey(ctx, &transport.RotateKeyRequest{Backend: "software", KeyID: "aead"})
			assert.NoError(t, err)
		})
	}
	wg.Wait()

	for v, n := range perVersion {
		assert.LessOrEqual(t, n, uint64(limit), "version %d encrypted past its limit", v)
	}
	report, err := svc.SafetyReport(ctx, &transport.SafetyReportRequest{})
	require.NoError(t, err)
	require.Len(t, report.AllItems, 1)
	assert.Equal(t, perVersion[rotations+1], report.AllItems[0].OperationsUsed,
		"the counters are the newest version's and hold every encryption under it")
}

func TestKeySafety_RefusesInvalidLimits(t *testing.T) {
	svc := keyManagementService(t)
	set := func(keyID string, ops uint64, percent int32) error {
		_, err := svc.SetKeySafety(ctxFor(""), &transport.SetKeySafetyRequest{Backend: "software", KeyID: keyID, MaxOperations: ops, WarningPercent: percent})
		return err
	}

	var invalid *InvalidKeyPolicyError
	require.ErrorAs(t, set("aead", 0, 0), &invalid)
	require.ErrorAs(t, set("aead", 10, 101), &invalid)
	// NIST SP 800-38D §8.3 caps one AES-GCM key at 2^32 invocations.
	require.ErrorAs(t, set("aead", keypolicy.MaxGCMInvocations+1, 0), &invalid)
	assert.Equal(t, "max_operations", invalid.Field)

	var kindErr *KeyKindError
	require.ErrorAs(t, set("signer", 10, 0), &kindErr)

	_, err := svc.ClearKeySafety(ctxFor(""), nil)
	var validation *ErrValidation
	require.ErrorAs(t, err, &validation)
}

func TestSafetyReport_RejectsUnknownFormat(t *testing.T) {
	svc := keyManagementService(t)
	_, err := svc.SafetyReport(ctxFor(""), &transport.SafetyReportRequest{Format: "xml"})
	var invalid *InvalidKeyPolicyError
	require.ErrorAs(t, err, &invalid)

	var validation *ErrValidation
	_, err = svc.SafetyCheck(ctxFor(""), nil)
	require.ErrorAs(t, err, &validation)
}

func TestGetSupportedAlgorithms_FollowsFIPSMode(t *testing.T) {
	svc := keyManagementService(t)
	resp, err := svc.GetSupportedAlgorithms(ctxFor(""), &transport.BackendRequest{Backend: "software"})
	require.NoError(t, err)
	assert.Contains(t, resp.Algorithms, transport.KeyAlgorithmECDSAP256)
	assert.Contains(t, resp.Algorithms, transport.KeyAlgorithmAES256GCM)
	if fips140.Enabled() {
		assert.NotContains(t, resp.Algorithms, transport.KeyAlgorithmChaCha20Poly1305)
		assert.NotContains(t, resp.Algorithms, transport.KeyAlgorithmX25519)
	} else {
		assert.Contains(t, resp.Algorithms, transport.KeyAlgorithmChaCha20Poly1305)
	}
}

func TestGetSupportedAlgorithms_UnknownBackend(t *testing.T) {
	svc := keyManagementService(t)
	_, err := svc.GetSupportedAlgorithms(ctxFor(""), &transport.BackendRequest{Backend: "nope"})
	require.Error(t, err)

	_, err = svc.GetSupportedAlgorithms(ctxFor(""), nil)
	var validation *ErrValidation
	require.ErrorAs(t, err, &validation)
}

func TestBackendStatus_ReportsHealthyBackend(t *testing.T) {
	svc := keyManagementService(t)
	resp, err := svc.BackendStatus(ctxFor(""), &transport.BackendRequest{Backend: "software"})
	require.NoError(t, err)
	assert.Equal(t, backendHealthy, resp.Status)
	assert.NotEmpty(t, resp.BackendType)
	assert.True(t, resp.Capabilities["keys"])

	_, err = svc.BackendStatus(ctxFor(""), &transport.BackendRequest{Backend: "nope"})
	require.Error(t, err)
}

func TestBackendTest_SealRoundTrip(t *testing.T) {
	svc := backendTestService(t)
	resp, err := svc.BackendTest(ctxFor(""), &transport.BackendRequest{Backend: "software"})
	require.NoError(t, err)
	assert.True(t, resp.Success, resp.Message)

	_, err = svc.BackendTest(ctxFor(""), &transport.BackendRequest{Backend: "nope"})
	require.Error(t, err)
	_, err = svc.BackendTest(ctxFor(""), nil)
	var validation *ErrValidation
	require.ErrorAs(t, err, &validation)
}

// backendTestService is keyManagementService with the software backend's
// default sealing key created by a first Seal, and that key's ID.
func backendTestService(t *testing.T) *XKMSService {
	t.Helper()
	svc := keyManagementService(t)
	_, err := svc.Seal(ctxFor(""), &transport.SealRequest{Backend: "software", Data: []byte("first seal")})
	require.NoError(t, err)
	return svc
}

// softwareSealingKeyID is the ID of the software backend's default sealing
// key.
func softwareSealingKeyID(t *testing.T) string {
	t.Helper()
	b, err := GetBackend("software")
	require.NoError(t, err)
	return defaultSealingKeyAttributes(b.KeyProvider().Type()).CN
}

// TestBackendTest_NeverCreatesTheSealingKey probes a backend whose default
// sealing key does not exist yet: the probe is refused and the keystore is
// left exactly as it was.
func TestBackendTest_NeverCreatesTheSealingKey(t *testing.T) {
	svc := keyManagementService(t)
	before, err := svc.ListKeys(ctxFor(""), "software")
	require.NoError(t, err)

	_, err = svc.BackendTest(ctxFor(""), &transport.BackendRequest{Backend: "software"})
	var unsupported *BackendTestUnsupportedError
	require.ErrorAs(t, err, &unsupported)

	after, err := svc.ListKeys(ctxFor(""), "software")
	require.NoError(t, err)
	assert.Equal(t, before.Keys, after.Keys)
}

// TestBackendTest_AdmitsTheSealingKey fails the probe when the sealing key's
// record refuses the seal or the unseal, as Seal and Unseal would.
func TestBackendTest_AdmitsTheSealingKey(t *testing.T) {
	refusals := map[string]func(t *testing.T, svc *XKMSService, keyID string){
		"revoked": func(t *testing.T, svc *XKMSService, keyID string) {
			_, err := svc.RevokeKey(ctxFor(""), &transport.RevokeKeyRequest{Backend: "software", KeyID: keyID, Reason: "compromised"})
			require.NoError(t, err)
		},
		"disabled": func(t *testing.T, svc *XKMSService, keyID string) {
			_, err := svc.UpdateKeyStatus(ctxFor(""), &transport.UpdateKeyStatusRequest{Backend: "software", KeyID: keyID, Status: transport.KeyStatusDisabled})
			require.NoError(t, err)
		},
		"policy refuses the operation": func(t *testing.T, svc *XKMSService, keyID string) {
			setPolicy(t, svc, keyID, transport.KeyUsageSign)
		},
	}
	for name, refuse := range refusals {
		t.Run(name, func(t *testing.T) {
			svc := backendTestService(t)
			refuse(t, svc, softwareSealingKeyID(t))
			resp, err := svc.BackendTest(ctxFor(""), &transport.BackendRequest{Backend: "software"})
			require.NoError(t, err)
			assert.False(t, resp.Success)
			assert.NotEmpty(t, resp.Message)
		})
	}
}

// TestBackendTest_CountsTowardTheUsageLimit charges the probe's seal and
// unseal to the sealing key's usage count, so a probe past it fails.
func TestBackendTest_CountsTowardTheUsageLimit(t *testing.T) {
	svc := backendTestService(t)
	keyID := softwareSealingKeyID(t)
	_, err := svc.SetKeyPolicy(ctxFor(""), &transport.SetKeyPolicyRequest{
		Backend: "software", KeyID: keyID, Policy: &transport.KeyPolicy{MaxUsageCount: 2},
	})
	require.NoError(t, err)

	resp, err := svc.BackendTest(ctxFor(""), &transport.BackendRequest{Backend: "software"})
	require.NoError(t, err)
	assert.True(t, resp.Success, resp.Message)
	resp, err = svc.BackendTest(ctxFor(""), &transport.BackendRequest{Backend: "software"})
	require.NoError(t, err)
	assert.False(t, resp.Success, "the first probe used both uses")
}
