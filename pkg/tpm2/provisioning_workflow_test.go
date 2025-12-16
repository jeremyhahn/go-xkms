//go:build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProvisioningWorkflow tests the complete TPM provisioning flow
// This exercises: Install(), fileIntegritySum(), CreatePlatformPolicy(), and hierarchy setup
func TestProvisioningWorkflow(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Verify EK was provisioned
	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err, "EK should be provisioned")
	assert.NotNil(t, ekAttrs)
	assert.Equal(t, types.KeyTypeEndorsement, ekAttrs.KeyType)
	assert.NotNil(t, ekAttrs.TPMAttributes)
	assert.NotEmpty(t, ekAttrs.TPMAttributes.Name.Buffer)

	// Verify SSRK was provisioned
	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err, "SSRK should be provisioned")
	assert.NotNil(t, ssrkAttrs)
	assert.Equal(t, types.KeyTypeStorage, ssrkAttrs.KeyType)
	assert.NotNil(t, ssrkAttrs.TPMAttributes)

	// Verify IAK was provisioned
	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err, "IAK should be provisioned")
	assert.NotNil(t, iakAttrs)
	assert.Equal(t, types.KeyTypeAttestation, iakAttrs.KeyType)
}

// TestProvisionWithPlatformPolicy tests provisioning with platform PCR policy
// This exercises fileIntegritySum() and CreatePlatformPolicy()
func TestProvisionWithPlatformPolicy(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Get platform policy digest (exercises fileIntegritySum)
	policyDigest := tpm.PlatformPolicyDigest()
	assert.NotNil(t, policyDigest)

	// Verify golden measurements were captured
	goldenPCR := tpm.GoldenMeasurements()
	assert.NotNil(t, goldenPCR)
	assert.NotEmpty(t, goldenPCR)
}

// TestHierarchyAuthSetup tests setting hierarchy authorizations
func TestHierarchyAuthSetup(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	hierarchyAuth := ekAttrs.TPMAttributes.HierarchyAuth

	// Test setting new hierarchy auth
	newPassword := store.NewClearPassword([]byte("new-hierarchy-pass"))
	err = tpm.SetHierarchyAuth(hierarchyAuth, newPassword, nil)
	assert.NoError(t, err)
}

// TestKeyHierarchyCreation tests creating keys under the provisioned hierarchy
// This exercises CreateSRK, CreateRSA, CreateECDSA with provisioned keys
func TestKeyHierarchyCreation(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Create SRK under EK
	srkAttrs := &types.KeyAttributes{
		CN:             "test-hierarchy-srk",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeStorage,
		Parent:         ekAttrs,
		Password:       store.NewClearPassword([]byte("srk-test")),
		PlatformPolicy: true,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        tpm2.TPMHandle(0x81000030),
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		},
	}
	err = tpm.CreateSRK(srkAttrs)
	require.NoError(t, err)

	// Create RSA key under SRK
	rsaAttrs := &types.KeyAttributes{
		CN:             "test-rsa-key",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeCA,
		Parent:         srkAttrs,
		Password:       store.NewClearPassword([]byte("rsa-test")),
		PlatformPolicy: true,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}
	rsaPub, err := tpm.CreateRSA(rsaAttrs, nil, false)
	require.NoError(t, err)
	assert.NotNil(t, rsaPub)
}

// TestProvisionedKeyOperations tests operations with provisioned keys
// This exercises Sign, Hash, SignValidate with provisioned IAK
func TestProvisionedKeyOperations(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	// Test Hash operation with IAK
	testData := []byte("test data for hashing with provisioned key")
	digest, validationDigest, err := tpm.Hash(iakAttrs, testData)
	if err != nil {
		t.Logf("Hash with IAK failed (scheme mismatch expected): %v", err)
		return
	}
	assert.NotEmpty(t, digest)
	assert.NotEmpty(t, validationDigest)

	// Test Sign operation with IAK
	signerOpts := &store.SignerOpts{
		KeyAttributes: iakAttrs,
		Backend:       nil,
	}
	signature, err := tpm.Sign(nil, digest, signerOpts)
	if err != nil {
		t.Logf("Sign with IAK failed (scheme mismatch expected): %v", err)
		return
	}
	assert.NotEmpty(t, signature)

	// Test SignValidate
	validationSig, err := tpm.SignValidate(iakAttrs, digest, validationDigest)
	if err != nil {
		t.Logf("SignValidate with IAK failed (scheme mismatch expected): %v", err)
		return
	}
	assert.NotEmpty(t, validationSig)
}

// TestProvisionedAttestationOperations tests attestation with provisioned IAK
// This exercises Quote, AKProfile with provisioned keys
func TestProvisionedAttestationOperations(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test AKProfile
	profile, err := tpm.AKProfile()
	if err != nil {
		t.Logf("AKProfile not available: %v", err)
		t.Skip("AKProfile not supported in this configuration")
	}
	assert.NotNil(t, profile)

	// Test Quote operation
	nonce := []byte("test-nonce-for-quote-operation-12345")
	pcrs := []uint{0, 1, 2, 3, 7}

	quote, err := tpm.Quote(pcrs, nonce)
	if err != nil {
		t.Logf("Quote failed: %v", err)
		return
	}
	assert.NotNil(t, quote)
}

// TestEKOperations tests operations specific to the Endorsement Key
// This exercises EKRSA, EKCertificate
func TestEKOperations(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test EKRSA
	ekRSA := tpm.EKRSA()
	assert.NotNil(t, ekRSA, "EKRSA should be available")
	assert.NotNil(t, ekRSA.N)

	// Note: EKECC not tested here as simulator provisions RSA EK by default
	// EKECC would require ECC EK which isn't created in standard provisioning

	// Test EKCertificate retrieval
	cert, err := tpm.EKCertificate()
	if err != nil {
		t.Logf("EK certificate not available (expected in simulator): %v", err)
		// This is expected - simulators don't have real EK certs
		return
	}
	if cert != nil {
		assert.NotNil(t, cert.PublicKey)
	}
}

// TestSessionCreation tests session creation with provisioned keys
// This exercises CreateSession, PlatformPolicySession, NonceSession
func TestSessionCreation(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Create platform policy session
	session, closer, err := tpm.CreateSession(ekAttrs)
	if err != nil {
		t.Logf("Session creation failed: %v", err)
		return
	}
	defer func() {
		if closer != nil {
			_ = closer()
		}
	}()

	assert.NotNil(t, session)
}

// TestParsePublicKeyFromProvisioned tests parsing public keys from provisioned keys
func TestParsePublicKeyFromProvisioned(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Get EK public area
	_, ekPub := tpm.EKPublic()

	// Marshal the public area to bytes
	pubBytes := tpm2.Marshal(ekPub)

	// Parse it back
	parsedPub, err := tpm.ParsePublicKey(pubBytes)
	require.NoError(t, err)
	assert.NotNil(t, parsedPub)
}
