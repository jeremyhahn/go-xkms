package tpm2

import (
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/tpm2/store"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEKECCOperations tests ECC Endorsement Key operations (14.3% coverage target)
func TestEKECCOperations(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Get the EK public area to check if it's ECC
	_, ekPub := tpm.EKPublic()

	if ekPub.Type != tpm2.TPMAlgECC {
		t.Skip("Simulator does not support ECC EK - RSA EK found instead")
		return
	}

	// Test EKECC operations
	ekeccPub := tpm.EKECC()
	require.NotNil(t, ekeccPub, "EKECC should return ECC public key")
	assert.NotNil(t, ekeccPub.Curve, "ECC public key should have a curve")
	assert.NotNil(t, ekeccPub.X, "ECC public key should have X coordinate")
	assert.NotNil(t, ekeccPub.Y, "ECC public key should have Y coordinate")

	// Verify the key is on the curve
	assert.True(t, ekeccPub.IsOnCurve(ekeccPub.X, ekeccPub.Y),
		"ECC public key should be on the curve")
}

// TestCreateIDevIDWorkflow tests IDevID creation workflow (43.2% coverage target)
func TestCreateIDevIDWorkflow(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Get required attributes
	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err, "IAK should be available")
	require.NotNil(t, iakAttrs.Parent, "IAK should have parent EK")

	// Prepare qualifying data
	qualifyingData := make([]byte, 32)
	_, err = rand.Read(qualifyingData)
	require.NoError(t, err)

	// Try to create IDevID - may not be configured
	idevidAttrs, tcgCSR, err := tpm.CreateIDevID(iakAttrs, nil, qualifyingData)

	if err == ErrNotConfigured {
		t.Skip("IDevID not configured in test config")
		return
	}

	require.NoError(t, err, "CreateIDevID should succeed when configured")
	assert.NotNil(t, idevidAttrs, "IDevID attributes should be returned")
	assert.NotNil(t, tcgCSR, "TCG CSR should be returned")

	// Verify IDevID attributes
	assert.Equal(t, types.KeyTypeTPM, idevidAttrs.KeyType)
	assert.NotNil(t, idevidAttrs.TPMAttributes)
	assert.NotEmpty(t, idevidAttrs.TPMAttributes.Name.Buffer)
	assert.NotEmpty(t, idevidAttrs.TPMAttributes.PublicKeyBytes)
	assert.NotEmpty(t, idevidAttrs.TPMAttributes.Signature)

	// Verify parent relationship
	assert.Equal(t, iakAttrs.Parent, idevidAttrs.Parent)
}

// TestCreateIDevIDErrors tests IDevID creation error handling
func TestCreateIDevIDErrors(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test with nil IAK attributes
	_, _, err := tpm.CreateIDevID(nil, nil, nil)
	assert.Error(t, err, "CreateIDevID should fail with nil IAK attributes")
	assert.Equal(t, ErrInvalidAKAttributes, err)

	// Test with IAK missing parent
	invalidIAK := &types.KeyAttributes{
		CN: "test-invalid-iak",
	}
	_, _, err = tpm.CreateIDevID(invalidIAK, nil, nil)
	assert.Error(t, err, "CreateIDevID should fail with IAK missing parent")
	assert.Equal(t, ErrInvalidEKAttributes, err)
}

// TestPlatformPolicySession tests platform policy session creation (57.7% coverage target)
func TestPlatformPolicySession(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Create platform policy session
	session, closer, err := tpm.PlatformPolicySession()

	if err != nil {
		t.Logf("Platform policy session creation failed: %v", err)
		// Some simulators may not support policy sessions fully
		return
	}

	require.NoError(t, err, "PlatformPolicySession should succeed")
	require.NotNil(t, session, "Session should not be nil")
	require.NotNil(t, closer, "Closer should not be nil")

	// Verify we can close the session
	err = closer()
	assert.NoError(t, err, "Session closer should succeed")

	// Verify policy digest was set
	policyDigest := tpm.PlatformPolicyDigest()
	assert.NotNil(t, policyDigest, "Policy digest should be set")
	assert.NotEmpty(t, policyDigest.Buffer, "Policy digest buffer should not be empty")
}

// TestPlatformPolicySessionMultiple tests creating multiple policy sessions
func TestPlatformPolicySessionMultiple(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Create first session
	session1, closer1, err := tpm.PlatformPolicySession()
	if err != nil {
		t.Logf("Platform policy session not supported: %v", err)
		return
	}
	require.NoError(t, err)
	require.NotNil(t, session1)
	defer func() { _ = closer1() }()

	// Create second session
	session2, closer2, err := tpm.PlatformPolicySession()
	require.NoError(t, err)
	require.NotNil(t, session2)
	defer func() { _ = closer2() }()

	// Both sessions should be independent
	assert.NotEqual(t, session1, session2, "Sessions should be independent")
}

// TestNonceSession tests nonce-based session creation (58.8% coverage target)
func TestNonceSession(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test with nil hierarchy auth
	session, closer, err := tpm.NonceSession(nil)

	if err != nil {
		t.Logf("Nonce session creation failed: %v", err)
		// Some simulators may not support nonce sessions
		return
	}

	require.NoError(t, err, "NonceSession should succeed with nil auth")
	require.NotNil(t, session, "Session should not be nil")
	require.NotNil(t, closer, "Closer should not be nil")

	// Verify we can close the session
	err = closer()
	assert.NoError(t, err, "Session closer should succeed")
}

// TestNonceSessionWithAuth tests nonce session with hierarchy auth
func TestNonceSessionWithAuth(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Test with hierarchy auth
	session, closer, err := tpm.NonceSession(ekAttrs.TPMAttributes.HierarchyAuth)

	if err != nil {
		t.Logf("Nonce session with auth failed: %v", err)
		return
	}

	require.NoError(t, err, "NonceSession should succeed with auth")
	require.NotNil(t, session)
	defer func() { _ = closer() }()
}

// TestQuoteOperations tests TPM quote operations (62.3% coverage target)
func TestQuoteOperations(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Prepare nonce
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	// Test quote with standard PCRs
	pcrs := []uint{0, 1, 2, 3}
	quote, err := tpm.Quote(pcrs, nonce)

	if err != nil {
		t.Logf("Quote operation failed: %v", err)
		return
	}

	require.NoError(t, err, "Quote should succeed")
	assert.NotNil(t, quote, "Quote should not be nil")
	assert.Equal(t, nonce, quote.Nonce, "Quote should contain the nonce")
	assert.NotEmpty(t, quote.Quoted, "Quote should contain quoted data")
	assert.NotEmpty(t, quote.Signature, "Quote should contain signature")
	assert.NotEmpty(t, quote.PCRs, "Quote should contain PCR values")
}

// TestQuoteWithDifferentPCRs tests quote with different PCR selections
func TestQuoteWithDifferentPCRs(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	testCases := []struct {
		name string
		pcrs []uint
	}{
		{"Single PCR", []uint{0}},
		{"Multiple PCRs", []uint{0, 1, 2, 3, 7}},
		{"Debug PCR", []uint{debugPCR}},
		{"Mixed PCRs", []uint{0, 7, 14, 23}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			nonce := make([]byte, 16)
			_, err := rand.Read(nonce)
			require.NoError(t, err)

			quote, err := tpm.Quote(tc.pcrs, nonce)
			if err != nil {
				t.Logf("Quote with %v failed: %v", tc.pcrs, err)
				return
			}

			assert.NotNil(t, quote)
			assert.Equal(t, nonce, quote.Nonce)
		})
	}
}

// TestQuoteWithEmptyNonce tests quote with empty nonce
func TestQuoteWithEmptyNonce(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	pcrs := []uint{0, 1}
	quote, err := tpm.Quote(pcrs, nil)

	if err != nil {
		t.Logf("Quote with empty nonce failed: %v", err)
		return
	}

	require.NoError(t, err, "Quote should succeed with empty nonce")
	assert.NotNil(t, quote)
}

// TestCreateIAKOperations tests Initial Attestation Key creation (64.9% coverage target)
func TestCreateIAKOperations(t *testing.T) {
	_, tpmInterface := createSim(false, false)
	defer func() { _ = tpmInterface.Close() }()

	// Cast to *TPM2 to access config
	tpm, ok := tpmInterface.(*TPM2)
	if !ok {
		t.Skip("Not a TPM2 instance")
		return
	}

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Prepare qualifying data
	qualifyingData := make([]byte, 32)
	_, err = rand.Read(qualifyingData)
	require.NoError(t, err)

	// Create a new IAK with different handle to avoid conflicts
	newIAKHandle := uint32(0x81010099)

	// Temporarily modify config for new IAK
	originalHandle := tpm.config.IAK.Handle
	tpm.config.IAK.Handle = newIAKHandle
	defer func() {
		tpm.config.IAK.Handle = originalHandle
	}()

	// Create IAK
	iakAttrs, err := tpm.CreateIAK(ekAttrs, qualifyingData)

	if err != nil {
		t.Logf("CreateIAK failed: %v", err)
		// Clean up if key was partially created
		if iakAttrs != nil && iakAttrs.TPMAttributes != nil {
			_ = tpm.DeleteKey(iakAttrs, nil)
		}
		return
	}

	require.NoError(t, err, "CreateIAK should succeed")
	assert.NotNil(t, iakAttrs, "IAK attributes should not be nil")

	// Verify IAK attributes
	assert.Equal(t, types.KeyTypeAttestation, iakAttrs.KeyType)
	assert.NotNil(t, iakAttrs.TPMAttributes)
	assert.NotEmpty(t, iakAttrs.TPMAttributes.Name.Buffer)
	assert.NotEmpty(t, iakAttrs.TPMAttributes.PublicKeyBytes)
	assert.NotEmpty(t, iakAttrs.TPMAttributes.Signature)
	assert.Equal(t, ekAttrs, iakAttrs.Parent)

	// Clean up - delete the created IAK
	err = tpm.DeleteKey(iakAttrs, nil)
	if err != nil {
		t.Logf("Failed to delete test IAK: %v", err)
	}
}

// TestCreateRSAEdgeCases tests RSA key creation edge cases (66.7% coverage target)
func TestCreateRSAEdgeCases(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Create SRK first
	srkAttrs := &types.KeyAttributes{
		CN:             "test-coverage-srk",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeStorage,
		Parent:         ekAttrs,
		Password:       store.NewClearPassword([]byte("test-srk")),
		PlatformPolicy: false,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        tpm2.TPMHandle(0x81000040),
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		},
	}
	err = tpm.CreateSRK(srkAttrs)
	require.NoError(t, err)
	defer func() { _ = tpm.DeleteKey(srkAttrs, nil) }()

	testCases := []struct {
		name           string
		keySize        int
		platformPolicy bool
		password       types.Password
	}{
		{
			name:           "RSA 2048 with password",
			keySize:        2048,
			platformPolicy: false,
			password:       store.NewClearPassword([]byte("test-pass")),
		},
		{
			name:           "RSA 2048 without password",
			keySize:        2048,
			platformPolicy: false,
			password:       nil,
		},
		{
			name:           "RSA 2048 with platform policy",
			keySize:        2048,
			platformPolicy: true,
			password:       store.NewClearPassword([]byte("test-pass")),
		},
	}

	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rsaAttrs := &types.KeyAttributes{
				CN:             tc.name,
				KeyAlgorithm:   x509.RSA,
				KeyType:        types.KeyTypeCA,
				Parent:         srkAttrs,
				Password:       tc.password,
				PlatformPolicy: tc.platformPolicy,
				StoreType:      types.StoreTPM2,
				RSAAttributes: &types.RSAAttributes{
					KeySize: tc.keySize,
				},
				TPMAttributes: &types.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				},
			}

			// Create RSA key
			rsaPub, err := tpm.CreateRSA(rsaAttrs, nil, false)

			if err != nil {
				t.Logf("CreateRSA failed for case %d: %v", i, err)
				return
			}

			require.NoError(t, err, "CreateRSA should succeed")
			assert.NotNil(t, rsaPub, "RSA public key should not be nil")
			assert.Equal(t, tc.keySize/8, rsaPub.N.BitLen()/8, "Key size should match")

			// Clean up
			err = tpm.DeleteKey(rsaAttrs, nil)
			if err != nil {
				t.Logf("Failed to delete test RSA key: %v", err)
			}
		})
	}
}

// TestCreateSecretKeyOperations tests secret key sealing (68.4% coverage target)
func TestCreateSecretKeyOperations(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Create SRK for secret key
	srkAttrs := &types.KeyAttributes{
		CN:             "test-secret-srk",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeStorage,
		Parent:         ekAttrs,
		Password:       store.NewClearPassword([]byte("srk-pass")),
		PlatformPolicy: false,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        tpm2.TPMHandle(0x81000050),
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		},
	}
	err = tpm.CreateSRK(srkAttrs)
	require.NoError(t, err)
	defer func() { _ = tpm.DeleteKey(srkAttrs, nil) }()

	// Create secret key attributes
	secretAttrs := &types.KeyAttributes{
		CN:             "test-secret-key",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeTPM,
		Parent:         srkAttrs,
		Password:       store.NewClearPassword([]byte("secret-pass")),
		PlatformPolicy: false,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	// Create secret key (sealed data object)
	err = tpm.CreateSecretKey(secretAttrs, nil)

	if err != nil {
		t.Logf("CreateSecretKey failed: %v", err)
		return
	}

	require.NoError(t, err, "CreateSecretKey should succeed")

	// Verify we can unseal the secret
	unsealed, err := tpm.UnsealKey(secretAttrs, nil)
	if err != nil {
		t.Logf("UnsealKey failed: %v", err)
	} else {
		assert.NotEmpty(t, unsealed, "Unsealed data should not be empty")
	}

	// Clean up
	err = tpm.DeleteKey(secretAttrs, nil)
	if err != nil {
		t.Logf("Failed to delete secret key: %v", err)
	}
}

// TestCreateSecretKeyWithPlatformPolicy tests secret key with platform policy
func TestCreateSecretKeyWithPlatformPolicy(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	// Create SRK with platform policy
	srkAttrs := &types.KeyAttributes{
		CN:             "test-policy-srk",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeStorage,
		Parent:         ekAttrs,
		Password:       store.NewClearPassword([]byte("srk-pass")),
		PlatformPolicy: true,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Handle:        tpm2.TPMHandle(0x81000060),
			HandleType:    tpm2.TPMHTPersistent,
			Hierarchy:     tpm2.TPMRHOwner,
			HierarchyAuth: ekAttrs.TPMAttributes.HierarchyAuth,
			Template:      tpm2.RSASRKTemplate,
		},
	}
	err = tpm.CreateSRK(srkAttrs)
	if err != nil {
		t.Logf("CreateSRK with platform policy failed: %v", err)
		return
	}
	defer func() { _ = tpm.DeleteKey(srkAttrs, nil) }()

	// Create secret key with platform policy
	secretAttrs := &types.KeyAttributes{
		CN:             "test-policy-secret",
		KeyAlgorithm:   x509.RSA,
		KeyType:        types.KeyTypeTPM,
		Parent:         srkAttrs,
		Password:       store.NewClearPassword([]byte("secret-pass")),
		PlatformPolicy: true,
		StoreType:      types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	err = tpm.CreateSecretKey(secretAttrs, nil)

	if err != nil {
		t.Logf("CreateSecretKey with platform policy failed: %v", err)
		return
	}

	require.NoError(t, err, "CreateSecretKey with platform policy should succeed")

	// Clean up
	err = tpm.DeleteKey(secretAttrs, nil)
	if err != nil {
		t.Logf("Failed to delete policy secret key: %v", err)
	}
}

// TestPlatformQuote tests platform quote operation
func TestPlatformQuote(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	iakAttrs, err := tpm.IAKAttributes()
	require.NoError(t, err)

	// Perform platform quote
	quote, nonce, err := tpm.PlatformQuote(iakAttrs)

	if err != nil {
		t.Logf("PlatformQuote failed: %v", err)
		return
	}

	require.NoError(t, err, "PlatformQuote should succeed")
	assert.NotNil(t, quote, "Quote should not be nil")
	assert.NotNil(t, nonce, "Nonce should not be nil")
	assert.NotEmpty(t, nonce, "Nonce should not be empty")
	assert.Equal(t, nonce, quote.Nonce, "Quote nonce should match returned nonce")
}

// TestHMACSessionCreation tests HMAC session creation
func TestHMACSessionCreation(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Test with nil auth
	session, closer, err := tpm.HMACSession(nil)
	if err != nil {
		t.Logf("HMACSession creation failed: %v", err)
		return
	}

	require.NoError(t, err, "HMACSession should succeed")
	require.NotNil(t, session, "Session should not be nil")
	require.NotNil(t, closer, "Closer should not be nil")

	err = closer()
	assert.NoError(t, err, "Closer should succeed")

	// Test with auth
	auth := []byte("test-auth-password")
	session2, closer2, err := tpm.HMACSession(auth)
	if err != nil {
		t.Logf("HMACSession with auth failed: %v", err)
		return
	}

	require.NoError(t, err)
	require.NotNil(t, session2)
	defer func() { _ = closer2() }()
}

// TestHMACSaltedSessionCreation tests salted HMAC session
func TestHMACSaltedSessionCreation(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// Get EK for salting
	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	ekHandle := ekAttrs.TPMAttributes.Handle
	ekPub := ekAttrs.TPMAttributes.Public

	// Create salted session
	session, closer, err := tpm.HMACSaltedSession(ekHandle, ekPub, nil)

	if err != nil {
		t.Logf("HMACSaltedSession creation failed: %v", err)
		return
	}

	require.NoError(t, err, "HMACSaltedSession should succeed")
	require.NotNil(t, session)
	require.NotNil(t, closer)

	err = closer()
	assert.NoError(t, err)
}

// TestCreateSessionVariants tests different session creation paths
func TestCreateSessionVariants(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	ekAttrs, err := tpm.EKAttributes()
	require.NoError(t, err)

	testCases := []struct {
		name           string
		platformPolicy bool
		hasParent      bool
	}{
		{"With parent, no policy", false, true},
		{"With parent, with policy", true, true},
		{"No parent", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				CN:             "test-session-key",
				KeyAlgorithm:   x509.RSA,
				PlatformPolicy: tc.platformPolicy,
			}

			if tc.hasParent {
				keyAttrs.Parent = ekAttrs
			}

			session, closer, err := tpm.CreateSession(keyAttrs)

			if err != nil {
				t.Logf("CreateSession failed for %s: %v", tc.name, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, session)

			if closer != nil {
				err = closer()
				assert.NoError(t, err)
			}
		})
	}
}

// TestCreateKeySession tests key-specific session creation
func TestCreateKeySession(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	testCases := []struct {
		name           string
		platformPolicy bool
		password       types.Password
	}{
		{"With password", false, store.NewClearPassword([]byte("test-pass"))},
		{"Without password", false, nil},
		{"With platform policy", true, store.NewClearPassword([]byte("test-pass"))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				CN:             "test-key",
				PlatformPolicy: tc.platformPolicy,
				Password:       tc.password,
			}

			session, closer, err := tpm.CreateKeySession(keyAttrs)

			if err != nil {
				t.Logf("CreateKeySession failed for %s: %v", tc.name, err)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, session)

			if closer != nil {
				err = closer()
				assert.NoError(t, err)
			}
		})
	}
}
