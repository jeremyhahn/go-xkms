//go:build integration && tpm2

package integration

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-keychain/internal/tpm/store"
	tpm2lib "github.com/jeremyhahn/go-keychain/pkg/tpm2"
	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// TestIntegration_TPM2_Hash_SmallData tests Hash operation with data < 1024 bytes
func TestIntegration_TPM2_Hash_SmallData(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	// Provision TPM if needed
	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v (may already be provisioned)", err)
	}

	// Get IAK attributes for hashing
	iakAttrs, err := tpmInstance.IAKAttributes()
	if err != nil {
		t.Fatalf("Failed to get IAK attributes: %v", err)
	}

	// Ensure TPMAttributes has HashAlg set
	if iakAttrs.TPMAttributes == nil {
		t.Fatal("IAK TPMAttributes is nil")
	}
	if iakAttrs.TPMAttributes.HashAlg == 0 {
		iakAttrs.TPMAttributes.HashAlg = tpm2.TPMAlgSHA256
	}

	tests := []struct {
		name    string
		data    []byte
		wantLen int
	}{
		{
			name:    "Empty data",
			data:    []byte{},
			wantLen: 32, // SHA-256
		},
		{
			name:    "Small data 32 bytes",
			data:    bytes.Repeat([]byte{0xAB}, 32),
			wantLen: 32,
		},
		{
			name:    "Medium data 512 bytes",
			data:    bytes.Repeat([]byte{0xCD}, 512),
			wantLen: 32,
		},
		{
			name:    "Max buffer size 1024 bytes",
			data:    bytes.Repeat([]byte{0xEF}, 1024),
			wantLen: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, validationDigest, err := tpmInstance.Hash(iakAttrs, tt.data)
			if err != nil {
				t.Fatalf("Hash failed: %v", err)
			}

			if len(digest) != tt.wantLen {
				t.Errorf("Digest length = %d, want %d", len(digest), tt.wantLen)
			}

			if len(validationDigest) == 0 {
				t.Error("Validation digest is empty")
			}

			// Verify hash consistency by hashing same data again
			digest2, _, err := tpmInstance.Hash(iakAttrs, tt.data)
			if err != nil {
				t.Fatalf("Second Hash failed: %v", err)
			}

			if !bytes.Equal(digest, digest2) {
				t.Error("Hash is not deterministic")
			}

			t.Logf("Hash successful: digest=%x, validation=%x", digest[:8], validationDigest[:8])
		})
	}
}

// TestIntegration_TPM2_Hash_LargeData tests Hash operation with data > 1024 bytes (triggers HashSequence)
func TestIntegration_TPM2_Hash_LargeData(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	// Provision TPM
	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// Get IAK attributes
	iakAttrs, err := tpmInstance.IAKAttributes()
	if err != nil {
		t.Fatalf("Failed to get IAK attributes: %v", err)
	}

	if iakAttrs.TPMAttributes.HashAlg == 0 {
		iakAttrs.TPMAttributes.HashAlg = tpm2.TPMAlgSHA256
	}

	tests := []struct {
		name string
		size int
	}{
		{"1025 bytes", 1025},
		{"2048 bytes", 2048},
		{"4096 bytes", 4096},
		{"8192 bytes", 8192},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{0x42}, tt.size)

			digest, validationDigest, err := tpmInstance.Hash(iakAttrs, data)
			if err != nil {
				t.Fatalf("Hash (sequence) failed for %d bytes: %v", tt.size, err)
			}

			if len(digest) != 32 {
				t.Errorf("Digest length = %d, want 32", len(digest))
			}

			if len(validationDigest) == 0 {
				t.Error("Validation digest is empty")
			}

			// Verify against software hash
			h := sha256.New()
			h.Write(data)
			expectedDigest := h.Sum(nil)

			if !bytes.Equal(digest, expectedDigest) {
				t.Errorf("TPM hash differs from software hash\nTPM: %x\nSW:  %x", digest, expectedDigest)
			}

			t.Logf("HashSequence successful for %d bytes: digest=%x", tt.size, digest[:8])
		})
	}
}

// TestIntegration_TPM2_Hash_InvalidInput tests Hash with invalid inputs
func TestIntegration_TPM2_Hash_InvalidInput(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	t.Run("Nil key attributes", func(t *testing.T) {
		_, _, err := tpmInstance.Hash(nil, []byte("test"))
		if err == nil {
			t.Error("Expected error for nil key attributes")
		}
		if err != tpm2lib.ErrInvalidKeyAttributes {
			t.Errorf("Expected ErrInvalidKeyAttributes, got: %v", err)
		}
	})

	t.Run("Nil TPM attributes", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN: "test-key",
		}
		_, _, err := tpmInstance.Hash(attrs, []byte("test"))
		if err == nil {
			t.Error("Expected error for nil TPM attributes")
		}
	})
}

// TestIntegration_TPM2_CreateRSA tests RSA key creation
func TestIntegration_TPM2_CreateRSA(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK attributes: %v", err)
	}

	// Note: TPM simulator has limited object memory, so we only test one key type
	// to avoid TPM_RC_OBJECT_MEMORY errors. The CreateRSA implementation is
	// tested more thoroughly in unit tests.
	tests := []struct {
		name     string
		keyType  types.KeyType
		sigAlgo  x509.SignatureAlgorithm
		wantBits int
	}{
		{
			name:     "RSA PKCS1 Signing Key",
			keyType:  types.KeyTypeCA,
			sigAlgo:  x509.SHA256WithRSA,
			wantBits: 2048,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				CN:                 "test-rsa-" + tt.name,
				KeyAlgorithm:       x509.RSA,
				KeyType:            tt.keyType,
				Parent:             srkAttrs,
				Password:           types.NewClearPassword(nil),
				StoreType:          types.StoreTPM2,
				SignatureAlgorithm: tt.sigAlgo,
				TPMAttributes: &types.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				},
			}

			rsaPub, err := tpmInstance.CreateRSA(keyAttrs, nil, true)
			if err != nil {
				t.Fatalf("CreateRSA failed: %v", err)
			}

			if rsaPub == nil {
				t.Fatal("RSA public key is nil")
			}

			if rsaPub.N == nil {
				t.Fatal("RSA modulus is nil")
			}

			if rsaPub.N.BitLen() != tt.wantBits {
				t.Errorf("RSA key size = %d bits, want %d", rsaPub.N.BitLen(), tt.wantBits)
			}

			if rsaPub.E != 65537 {
				t.Errorf("RSA exponent = %d, want 65537", rsaPub.E)
			}

			t.Logf("Created RSA key with %d-bit modulus", rsaPub.N.BitLen())

			// Clean up key to free TPM handle
			if err := tpmInstance.DeleteKey(keyAttrs, nil); err != nil {
				t.Logf("Warning: failed to delete key: %v", err)
			}
		})
	}
}

// TestIntegration_TPM2_CreateRSA_InvalidParent tests RSA creation with invalid parent
func TestIntegration_TPM2_CreateRSA_InvalidParent(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	keyAttrs := &types.KeyAttributes{
		CN:           "test-invalid-parent",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       nil, // Missing parent
		Password:     types.NewClearPassword(nil),
		StoreType:    types.StoreTPM2,
	}

	_, err := tpmInstance.CreateRSA(keyAttrs, nil, true)
	if err == nil {
		t.Error("Expected error for nil parent")
	}

	t.Logf("Got expected error: %v", err)
}

// TestIntegration_TPM2_CreateECDSA tests ECDSA key creation
func TestIntegration_TPM2_CreateECDSA(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK attributes: %v", err)
	}

	tests := []struct {
		name      string
		curveName string
	}{
		{"P-256", "P-256"},
		{"P-384", "P-384"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyAttrs := &types.KeyAttributes{
				CN:           "test-ecdsa-" + tt.curveName,
				KeyAlgorithm: x509.ECDSA,
				KeyType:      types.KeyTypeCA,
				Parent:       srkAttrs,
				Password:     types.NewClearPassword(nil),
				StoreType:    types.StoreTPM2,
				TPMAttributes: &types.TPMAttributes{
					Hierarchy: tpm2.TPMRHOwner,
				},
			}

			ecdsaPub, err := tpmInstance.CreateECDSA(keyAttrs, nil, true)
			if err != nil {
				t.Fatalf("CreateECDSA failed: %v", err)
			}

			if ecdsaPub == nil {
				t.Fatal("ECDSA public key is nil")
			}

			if ecdsaPub.X == nil || ecdsaPub.Y == nil {
				t.Fatal("ECDSA coordinates are nil")
			}

			if ecdsaPub.Curve == nil {
				t.Fatal("ECDSA curve is nil")
			}

			curveName := ecdsaPub.Curve.Params().Name
			t.Logf("Created ECDSA key on curve %s", curveName)

			// Verify point is on curve
			if !ecdsaPub.Curve.IsOnCurve(ecdsaPub.X, ecdsaPub.Y) {
				t.Error("ECDSA public key point is not on curve")
			}

			// Clean up key to free TPM handle
			if err := tpmInstance.DeleteKey(keyAttrs, nil); err != nil {
				t.Logf("Warning: failed to delete key: %v", err)
			}
		})
	}
}

// TestIntegration_TPM2_CreateECDSA_InvalidParent tests ECDSA creation with invalid parent
func TestIntegration_TPM2_CreateECDSA_InvalidParent(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	keyAttrs := &types.KeyAttributes{
		CN:           "test-ecdsa-invalid-parent",
		KeyAlgorithm: x509.ECDSA,
		KeyType:      types.KeyTypeCA,
		Parent:       nil, // Missing parent
		Password:     types.NewClearPassword(nil),
		StoreType:    types.StoreTPM2,
	}

	_, err := tpmInstance.CreateECDSA(keyAttrs, nil, true)
	if err == nil {
		t.Error("Expected error for nil parent")
	}

	t.Logf("Got expected error: %v", err)
}

// TestIntegration_TPM2_SignRSA tests signing with RSA attestation key
func TestIntegration_TPM2_SignRSA(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// Get SRK to create a dedicated signing key
	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK attributes: %v", err)
	}

	// Create a dedicated RSA signing key instead of using IAK
	// (IAK scheme may not match what we expect)
	// Use SHA256WithRSA (PKCS1v15) which is supported by TPM
	keyAttrs := &types.KeyAttributes{
		CN:                 "test-sign-rsa",
		KeyAlgorithm:       x509.RSA,
		KeyType:            types.KeyTypeCA,
		Parent:             srkAttrs,
		Password:           types.NewClearPassword(nil),
		StoreType:          types.StoreTPM2,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Hash:               crypto.SHA256,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	rsaPub, err := tpmInstance.CreateRSA(keyAttrs, nil, true)
	if err != nil {
		t.Fatalf("Failed to create RSA signing key: %v", err)
	}

	// Create test data and hash it
	testData := []byte("Test data for signing with TPM")
	h := sha256.Sum256(testData)
	digest := h[:]

	// Create signer options
	signerOpts := &store.SignerOpts{
		KeyAttributes: keyAttrs,
	}

	// Sign the digest
	signature, err := tpmInstance.Sign(rand.Reader, digest, signerOpts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Signature is empty")
	}

	// Verify signature using PKCS1v15
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest, signature)

	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}

	t.Logf("Signed and verified digest successfully, signature length: %d bytes", len(signature))

	// Clean up the signing key
	if err := tpmInstance.DeleteKey(keyAttrs, nil); err != nil {
		t.Logf("Warning: failed to delete signing key: %v", err)
	}
}

// TestIntegration_TPM2_Sign_InvalidOpts tests Sign with invalid options
func TestIntegration_TPM2_Sign_InvalidOpts(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	digest := make([]byte, 32)

	// Test with non-store.SignerOpts
	_, err := tpmInstance.Sign(rand.Reader, digest, crypto.SHA256)
	if err == nil {
		t.Error("Expected error for invalid signer opts type")
	}
	if err != store.ErrInvalidSignerOpts {
		t.Errorf("Expected ErrInvalidSignerOpts, got: %v", err)
	}

	t.Logf("Got expected error: %v", err)
}

// TestIntegration_TPM2_ParsePublicKey tests parsing TPM public keys
func TestIntegration_TPM2_ParsePublicKey(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// Get EK public area
	_, ekPub := tpmInstance.EKPublic()

	// Marshal the public area
	ekPubBytes := tpm2.Marshal(ekPub)

	// Parse it back
	pubKey, err := tpmInstance.ParsePublicKey(ekPubBytes)
	if err != nil {
		t.Fatalf("ParsePublicKey failed: %v", err)
	}

	if pubKey == nil {
		t.Fatal("Parsed public key is nil")
	}

	// Check the key type
	switch key := pubKey.(type) {
	case *rsa.PublicKey:
		t.Logf("Parsed RSA public key with %d-bit modulus", key.N.BitLen())
	case *ecdsa.PublicKey:
		t.Logf("Parsed ECDSA public key on curve %s", key.Curve.Params().Name)
	default:
		t.Errorf("Unknown key type: %T", pubKey)
	}
}

// TestIntegration_TPM2_SealUnseal_WithSecret tests sealing with provided secret
func TestIntegration_TPM2_SealUnseal_WithSecret(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK attributes: %v", err)
	}

	// Create custom secret
	secretData := []byte("my-super-secret-data-to-seal")

	keyAttrs := &types.KeyAttributes{
		CN:           "test-seal-custom-secret",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       srkAttrs,
		Password:     types.NewClearPassword(nil),
		StoreType:    types.StoreTPM2,
		Secret:       types.NewClearPassword(secretData),
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	// Seal the secret
	_, err = tpmInstance.Seal(keyAttrs, nil, true)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Unseal and verify
	unsealed, err := tpmInstance.Unseal(keyAttrs, nil)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if !bytes.Equal(unsealed, secretData) {
		t.Errorf("Unsealed data mismatch\nGot: %s\nWant: %s", unsealed, secretData)
	}

	t.Logf("Successfully sealed and unsealed custom secret: %s", unsealed)
}

// TestIntegration_TPM2_SealUnseal_AutoGenerated tests sealing with auto-generated secret
func TestIntegration_TPM2_SealUnseal_AutoGenerated(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK attributes: %v", err)
	}

	keyAttrs := &types.KeyAttributes{
		CN:           "test-seal-auto-secret",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       srkAttrs,
		Password:     types.NewClearPassword(nil),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	// Seal without providing secret (auto-generates 32-byte AES key)
	_, err = tpmInstance.Seal(keyAttrs, nil, true)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Unseal
	unsealed, err := tpmInstance.Unseal(keyAttrs, nil)
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if len(unsealed) != 32 {
		t.Errorf("Auto-generated secret length = %d, want 32", len(unsealed))
	}

	t.Logf("Successfully sealed and unsealed auto-generated %d-byte secret", len(unsealed))
}

// TestIntegration_TPM2_Seal_InvalidParent tests Seal with invalid parent
func TestIntegration_TPM2_Seal_InvalidParent(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	keyAttrs := &types.KeyAttributes{
		CN:           "test-seal-invalid-parent",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       nil, // Missing parent
		Password:     types.NewClearPassword(nil),
		StoreType:    types.StoreTPM2,
	}

	_, err := tpmInstance.Seal(keyAttrs, nil, true)
	if err == nil {
		t.Error("Expected error for nil parent")
	}

	t.Logf("Got expected error: %v", err)
}

// TestIntegration_TPM2_Quote tests quote generation
func TestIntegration_TPM2_Quote(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// Load IAK attributes (needed for Quote when TPM already provisioned)
	if _, err := tpmInstance.IAKAttributes(); err != nil {
		t.Fatalf("Failed to get IAK attributes: %v", err)
	}

	// Generate nonce
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	if err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	// Quote PCR 16 (debug PCR)
	pcrs := []uint{16}

	quote, err := tpmInstance.Quote(pcrs, nonce)
	if err != nil {
		t.Fatalf("Quote failed: %v", err)
	}

	// Verify quote structure
	if len(quote.Quoted) == 0 {
		t.Error("Quote data is empty")
	}

	if len(quote.Signature) == 0 {
		t.Error("Quote signature is empty")
	}

	if !bytes.Equal(quote.Nonce, nonce) {
		t.Error("Quote nonce mismatch")
	}

	if len(quote.PCRs) == 0 {
		t.Error("Quote PCRs are empty")
	}

	t.Logf("Quote successful: quoted=%d bytes, signature=%d bytes", len(quote.Quoted), len(quote.Signature))
}

// TestIntegration_TPM2_Quote_MultiplePCRs tests quote with multiple PCRs
func TestIntegration_TPM2_Quote_MultiplePCRs(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// Load IAK attributes (needed for Quote when TPM already provisioned)
	if _, err := tpmInstance.IAKAttributes(); err != nil {
		t.Fatalf("Failed to get IAK attributes: %v", err)
	}

	nonce := make([]byte, 32)
	rand.Read(nonce)

	// Quote multiple PCRs
	pcrs := []uint{0, 1, 2, 7, 16}

	quote, err := tpmInstance.Quote(pcrs, nonce)
	if err != nil {
		t.Fatalf("Quote with multiple PCRs failed: %v", err)
	}

	if len(quote.Quoted) == 0 {
		t.Error("Quote data is empty")
	}

	if len(quote.Signature) == 0 {
		t.Error("Quote signature is empty")
	}

	t.Logf("Multi-PCR quote successful: quoted=%d bytes", len(quote.Quoted))
}

// TestIntegration_TPM2_Random tests random number generation
func TestIntegration_TPM2_Random(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// Test Random()
	randomBytes, err := tpmInstance.Random()
	if err != nil {
		t.Fatalf("Random failed: %v", err)
	}

	if len(randomBytes) == 0 {
		t.Error("Random returned empty bytes")
	}

	t.Logf("Random() returned %d bytes", len(randomBytes))

	// Test RandomBytes with specific length
	fixedLen := 64
	randomFixed, err := tpmInstance.RandomBytes(fixedLen)
	if err != nil {
		t.Fatalf("RandomBytes failed: %v", err)
	}

	if len(randomFixed) != fixedLen {
		t.Errorf("RandomBytes length = %d, want %d", len(randomFixed), fixedLen)
	}

	t.Logf("RandomBytes(%d) successful", fixedLen)

	// Verify randomness (two calls should produce different results)
	randomBytes2, _ := tpmInstance.Random()
	if bytes.Equal(randomBytes, randomBytes2) {
		t.Error("Random is not producing unique values")
	}
}

// TestIntegration_TPM2_ReadPCRs tests PCR reading
func TestIntegration_TPM2_ReadPCRs(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	pcrList := []uint{0, 1, 7, 16}

	banks, err := tpmInstance.ReadPCRs(pcrList)
	if err != nil {
		t.Fatalf("ReadPCRs failed: %v", err)
	}

	if len(banks) == 0 {
		t.Error("No PCR banks returned")
	}

	for _, bank := range banks {
		t.Logf("PCR Bank: %s", bank.Algorithm)
		for _, pcr := range bank.PCRs {
			t.Logf("  PCR %d: %s", pcr.ID, string(pcr.Value[:16]))
		}
	}
}

// TestIntegration_TPM2_ReadPCRs_InvalidIndex tests PCR reading with invalid index
func TestIntegration_TPM2_ReadPCRs_InvalidIndex(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// PCR index 24 is invalid (max is 23)
	pcrList := []uint{24}

	_, err := tpmInstance.ReadPCRs(pcrList)
	if err == nil {
		t.Error("Expected error for invalid PCR index")
	}

	t.Logf("Got expected error: %v", err)
}

// TestIntegration_TPM2_RSAEncryptDecrypt tests RSA encryption/decryption
func TestIntegration_TPM2_RSAEncryptDecrypt(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK attributes: %v", err)
	}

	// Create an encryption key
	keyAttrs := &types.KeyAttributes{
		CN:                 "test-rsa-encryption",
		KeyAlgorithm:       x509.RSA,
		KeyType:            types.KeyTypeEncryption,
		Parent:             srkAttrs,
		Password:           types.NewClearPassword(nil),
		StoreType:          types.StoreTPM2,
		SignatureAlgorithm: x509.SHA256WithRSA,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	_, err = tpmInstance.CreateRSA(keyAttrs, nil, true)
	if err != nil {
		t.Fatalf("CreateRSA for encryption failed: %v", err)
	}

	// Test message
	message := []byte("Secret message to encrypt")

	// Encrypt using the key handle
	handle := keyAttrs.TPMAttributes.Handle
	name := keyAttrs.TPMAttributes.Name

	ciphertext, err := tpmInstance.RSAEncrypt(handle.(tpm2.TPMHandle), name.(tpm2.TPM2BName), message)
	if err != nil {
		t.Fatalf("RSAEncrypt failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Error("Ciphertext is empty")
	}

	// Decrypt
	decrypted, err := tpmInstance.RSADecrypt(handle.(tpm2.TPMHandle), name.(tpm2.TPM2BName), ciphertext)
	if err != nil {
		t.Fatalf("RSADecrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, message) {
		t.Errorf("Decrypted message mismatch\nGot: %s\nWant: %s", decrypted, message)
	}

	t.Logf("RSA encrypt/decrypt successful: %s", decrypted)
}

// TestIntegration_TPM2_MakeActivateCredential tests make and activate credential
func TestIntegration_TPM2_MakeActivateCredential(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// Get IAK attributes
	iakAttrs, err := tpmInstance.IAKAttributes()
	if err != nil {
		t.Fatalf("Failed to get IAK attributes: %v", err)
	}

	// Create credential with auto-generated secret
	credentialBlob, encryptedSecret, secret, err := tpmInstance.MakeCredential(iakAttrs.TPMAttributes.Name.(tpm2.TPM2BName), nil)
	if err != nil {
		t.Fatalf("MakeCredential failed: %v", err)
	}

	if len(credentialBlob) == 0 {
		t.Error("Credential blob is empty")
	}

	if len(encryptedSecret) == 0 {
		t.Error("Encrypted secret is empty")
	}

	if len(secret) != 32 {
		t.Errorf("Secret length = %d, want 32", len(secret))
	}

	t.Logf("MakeCredential successful: blob=%d bytes, secret=%d bytes", len(credentialBlob), len(secret))

	// Activate the credential
	activatedSecret, err := tpmInstance.ActivateCredential(credentialBlob, encryptedSecret)
	if err != nil {
		t.Fatalf("ActivateCredential failed: %v", err)
	}

	if !bytes.Equal(activatedSecret, secret) {
		t.Errorf("Activated secret mismatch\nGot: %x\nWant: %x", activatedSecret, secret)
	}

	t.Logf("ActivateCredential successful: recovered secret matches original")
}

// TestIntegration_TPM2_MakeCredential_CustomSecret tests make credential with custom secret
func TestIntegration_TPM2_MakeCredential_CustomSecret(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	iakAttrs, err := tpmInstance.IAKAttributes()
	if err != nil {
		t.Fatalf("Failed to get IAK attributes: %v", err)
	}

	// Create credential with custom secret
	customSecret := []byte("my-custom-credential-secret!!")

	credentialBlob, encryptedSecret, secret, err := tpmInstance.MakeCredential(iakAttrs.TPMAttributes.Name.(tpm2.TPM2BName), customSecret)
	if err != nil {
		t.Fatalf("MakeCredential with custom secret failed: %v", err)
	}

	if !bytes.Equal(secret, customSecret) {
		t.Errorf("Secret mismatch\nGot: %s\nWant: %s", secret, customSecret)
	}

	// Activate and verify
	activatedSecret, err := tpmInstance.ActivateCredential(credentialBlob, encryptedSecret)
	if err != nil {
		t.Fatalf("ActivateCredential failed: %v", err)
	}

	if !bytes.Equal(activatedSecret, customSecret) {
		t.Errorf("Activated secret mismatch\nGot: %s\nWant: %s", activatedSecret, customSecret)
	}

	t.Logf("Custom secret credential activation successful")
}

// TestIntegration_TPM2_EKAttributes tests EK attribute retrieval
func TestIntegration_TPM2_EKAttributes(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	ekAttrs, err := tpmInstance.EKAttributes()
	if err != nil {
		t.Fatalf("EKAttributes failed: %v", err)
	}

	if ekAttrs == nil {
		t.Fatal("EK attributes are nil")
	}

	if ekAttrs.KeyType != types.KeyTypeEndorsement {
		t.Errorf("EK key type = %v, want KEY_TYPE_ENDORSEMENT", ekAttrs.KeyType)
	}

	if ekAttrs.StoreType != types.StoreTPM2 {
		t.Errorf("EK store type = %v, want STORE_TPM2", ekAttrs.StoreType)
	}

	if ekAttrs.TPMAttributes == nil {
		t.Fatal("EK TPM attributes are nil")
	}

	if ekAttrs.TPMAttributes.Handle == 0 {
		t.Error("EK handle is zero")
	}

	t.Logf("EK attributes: Handle=0x%x, Algorithm=%v", ekAttrs.TPMAttributes.Handle, ekAttrs.KeyAlgorithm)
}

// TestIntegration_TPM2_SSRKAttributes tests SSRK attribute retrieval
func TestIntegration_TPM2_SSRKAttributes(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("SSRKAttributes failed: %v", err)
	}

	if srkAttrs == nil {
		t.Fatal("SRK attributes are nil")
	}

	if srkAttrs.KeyType != types.KeyTypeStorage {
		t.Errorf("SRK key type = %v, want KEY_TYPE_STORAGE", srkAttrs.KeyType)
	}

	if srkAttrs.StoreType != types.StoreTPM2 {
		t.Errorf("SRK store type = %v, want STORE_TPM2", srkAttrs.StoreType)
	}

	if srkAttrs.TPMAttributes == nil {
		t.Fatal("SRK TPM attributes are nil")
	}

	if srkAttrs.TPMAttributes.Handle == 0 {
		t.Error("SRK handle is zero")
	}

	t.Logf("SRK attributes: Handle=0x%x, Algorithm=%v", srkAttrs.TPMAttributes.Handle, srkAttrs.KeyAlgorithm)
}

// TestIntegration_TPM2_IAKAttributes tests IAK attribute retrieval
func TestIntegration_TPM2_IAKAttributes(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	iakAttrs, err := tpmInstance.IAKAttributes()
	if err != nil {
		t.Fatalf("IAKAttributes failed: %v", err)
	}

	if iakAttrs == nil {
		t.Fatal("IAK attributes are nil")
	}

	if iakAttrs.KeyType != types.KeyTypeAttestation {
		t.Errorf("IAK key type = %v, want KEY_TYPE_ATTESTATION", iakAttrs.KeyType)
	}

	if iakAttrs.StoreType != types.StoreTPM2 {
		t.Errorf("IAK store type = %v, want STORE_TPM2", iakAttrs.StoreType)
	}

	if iakAttrs.TPMAttributes == nil {
		t.Fatal("IAK TPM attributes are nil")
	}

	if iakAttrs.TPMAttributes.Handle == 0 {
		t.Error("IAK handle is zero")
	}

	if iakAttrs.Parent == nil {
		t.Error("IAK parent (EK) is nil")
	}

	t.Logf("IAK attributes: Handle=0x%x, Algorithm=%v, SignatureAlgo=%v",
		iakAttrs.TPMAttributes.Handle, iakAttrs.KeyAlgorithm, iakAttrs.SignatureAlgorithm)
}

// TestIntegration_TPM2_ReadHandle tests reading handle public data
func TestIntegration_TPM2_ReadHandle(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// Get EK handle from config
	config := tpmInstance.Config()
	ekHandle := tpm2.TPMHandle(config.EK.Handle)

	name, pub, err := tpmInstance.ReadHandle(ekHandle)
	if err != nil {
		t.Fatalf("ReadHandle failed: %v", err)
	}

	if len(name.Buffer) == 0 {
		t.Error("Handle name is empty")
	}

	if pub.Type == 0 {
		t.Error("Public area type is zero")
	}

	t.Logf("ReadHandle successful: Name=%x, Type=%v", name.Buffer[:8], pub.Type)
}

// TestIntegration_TPM2_Config tests configuration retrieval
func TestIntegration_TPM2_Config(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	config := tpmInstance.Config()
	if config == nil {
		t.Fatal("Config is nil")
	}

	if config.EK == nil {
		t.Error("EK config is nil")
	}

	if config.SSRK == nil {
		t.Error("SSRK config is nil")
	}

	if config.IAK == nil {
		t.Error("IAK config is nil")
	}

	t.Logf("Config: Hash=%s, PlatformPCR=%d", config.Hash, config.PlatformPCR)
}

// TestIntegration_TPM2_Transport tests transport access
func TestIntegration_TPM2_Transport(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	transport := tpmInstance.Transport()
	if transport == nil {
		t.Fatal("Transport is nil")
	}

	t.Log("Transport access successful")
}

// TestIntegration_TPM2_AlgID tests algorithm ID retrieval
func TestIntegration_TPM2_AlgID(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	algID := tpmInstance.AlgID()
	if algID == 0 {
		t.Error("AlgID is zero")
	}

	// Verify it's a valid hash algorithm
	validAlgs := []tpm2.TPMAlgID{
		tpm2.TPMAlgSHA1,
		tpm2.TPMAlgSHA256,
		tpm2.TPMAlgSHA384,
		tpm2.TPMAlgSHA512,
	}

	valid := false
	for _, alg := range validAlgs {
		if algID == alg {
			valid = true
			break
		}
	}

	if !valid {
		t.Errorf("AlgID %v is not a valid hash algorithm", algID)
	}

	t.Logf("AlgID: %v", algID)
}

// TestIntegration_TPM2_Flush tests handle flushing
func TestIntegration_TPM2_Flush(t *testing.T) {
	tpmInstance, cleanup := createTPM2Instance(t)
	defer cleanup()

	if err := tpmInstance.Provision(nil); err != nil {
		t.Logf("Provision returned: %v", err)
	}

	// Create a transient object to flush
	srkAttrs, err := tpmInstance.SSRKAttributes()
	if err != nil {
		t.Fatalf("Failed to get SRK attributes: %v", err)
	}

	keyAttrs := &types.KeyAttributes{
		CN:           "test-flush-key",
		KeyAlgorithm: x509.RSA,
		KeyType:      types.KeyTypeCA,
		Parent:       srkAttrs,
		Password:     types.NewClearPassword(nil),
		StoreType:    types.StoreTPM2,
		TPMAttributes: &types.TPMAttributes{
			Hierarchy: tpm2.TPMRHOwner,
		},
	}

	_, err = tpmInstance.CreateRSA(keyAttrs, nil, true)
	if err != nil {
		t.Fatalf("CreateRSA failed: %v", err)
	}

	// Flush should not panic or error
	handle := keyAttrs.TPMAttributes.Handle
	tpmInstance.Flush(handle.(tpm2.TPMHandle))

	t.Log("Flush successful")
}
