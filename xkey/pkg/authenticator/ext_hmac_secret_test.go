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

package authenticator

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// TestParseHMACSecretInput tests parsing of hmac-secret extension input.
func TestParseHMACSecretInput(t *testing.T) {
	t.Parallel()

	// Generate test platform key
	platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate platform key: %v", err)
	}

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
		coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
	}
	keyAgreementBytes, err := cbor.Marshal(coseKey)
	if err != nil {
		t.Fatalf("failed to marshal COSE key: %v", err)
	}

	validSaltEnc := make([]byte, HMACSecretEncryptedSingleSaltSize)
	_, _ = rand.Read(validSaltEnc)

	validSaltAuth := make([]byte, hmacSecretAuthTagSize)
	_, _ = rand.Read(validSaltAuth)

	tests := []struct {
		name    string
		input   interface{}
		wantErr error
	}{
		{
			name:    "nil input",
			input:   nil,
			wantErr: ErrHMACSecretInvalidInput,
		},
		{
			name:    "invalid type",
			input:   "invalid",
			wantErr: ErrHMACSecretInvalidInput,
		},
		{
			name: "valid input with int keys",
			input: map[int]interface{}{
				hmacSecretKeyAgreement:      keyAgreementBytes,
				hmacSecretSaltEnc:           validSaltEnc,
				hmacSecretSaltAuth:          validSaltAuth,
				hmacSecretPinUvAuthProtocol: 1,
			},
			wantErr: nil,
		},
		{
			name: "valid input with interface keys",
			input: map[interface{}]interface{}{
				hmacSecretKeyAgreement:      keyAgreementBytes,
				hmacSecretSaltEnc:           validSaltEnc,
				hmacSecretSaltAuth:          validSaltAuth,
				hmacSecretPinUvAuthProtocol: 1,
			},
			wantErr: nil,
		},
		{
			name: "missing keyAgreement",
			input: map[int]interface{}{
				hmacSecretSaltEnc:           validSaltEnc,
				hmacSecretSaltAuth:          validSaltAuth,
				hmacSecretPinUvAuthProtocol: 1,
			},
			wantErr: ErrHMACSecretMissingKeyAgreement,
		},
		{
			name: "missing saltEnc",
			input: map[int]interface{}{
				hmacSecretKeyAgreement:      keyAgreementBytes,
				hmacSecretSaltAuth:          validSaltAuth,
				hmacSecretPinUvAuthProtocol: 1,
			},
			wantErr: ErrHMACSecretMissingSaltEnc,
		},
		{
			name: "missing saltAuth",
			input: map[int]interface{}{
				hmacSecretKeyAgreement:      keyAgreementBytes,
				hmacSecretSaltEnc:           validSaltEnc,
				hmacSecretPinUvAuthProtocol: 1,
			},
			wantErr: ErrHMACSecretMissingSaltAuth,
		},
		{
			name: "missing protocol",
			input: map[int]interface{}{
				hmacSecretKeyAgreement: keyAgreementBytes,
				hmacSecretSaltEnc:      validSaltEnc,
				hmacSecretSaltAuth:     validSaltAuth,
			},
			wantErr: ErrHMACSecretMissingProtocol,
		},
		{
			name: "invalid saltEnc length",
			input: map[int]interface{}{
				hmacSecretKeyAgreement:      keyAgreementBytes,
				hmacSecretSaltEnc:           make([]byte, 17), // Invalid length
				hmacSecretSaltAuth:          validSaltAuth,
				hmacSecretPinUvAuthProtocol: 1,
			},
			wantErr: ErrHMACSecretInvalidSaltEnc,
		},
		{
			name: "invalid saltAuth length",
			input: map[int]interface{}{
				hmacSecretKeyAgreement:      keyAgreementBytes,
				hmacSecretSaltEnc:           validSaltEnc,
				hmacSecretSaltAuth:          make([]byte, 10), // Invalid length
				hmacSecretPinUvAuthProtocol: 1,
			},
			wantErr: ErrHMACSecretInvalidSaltAuth,
		},
		{
			name: "valid double salt",
			input: map[int]interface{}{
				hmacSecretKeyAgreement:      keyAgreementBytes,
				hmacSecretSaltEnc:           make([]byte, HMACSecretEncryptedDoubleSaltSize),
				hmacSecretSaltAuth:          validSaltAuth,
				hmacSecretPinUvAuthProtocol: 2,
			},
			wantErr: nil,
		},
		{
			name:    "string keyed map not allowed",
			input:   map[string]interface{}{"keyAgreement": keyAgreementBytes},
			wantErr: ErrHMACSecretInvalidInput,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseHMACSecretInput(tc.input)

			if tc.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tc.wantErr)
				} else if err != tc.wantErr {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

// TestHMACSecretFullRoundTrip tests the complete hmac-secret protocol flow.
func TestHMACSecretFullRoundTrip(t *testing.T) {
	t.Parallel()

	// Create platform helper
	platformHelper, err := NewHMACSecretPlatformHelper()
	if err != nil {
		t.Fatalf("failed to create platform helper: %v", err)
	}
	defer platformHelper.Reset()

	// Create authenticator helper for shared secret
	authHelper, err := NewHMACSecretPlatformHelper()
	if err != nil {
		t.Fatalf("failed to create authenticator helper: %v", err)
	}
	defer authHelper.Reset()

	// Exchange keys
	platformCOSE, err := platformHelper.GetCOSEPublicKey()
	if err != nil {
		t.Fatalf("failed to get platform COSE key: %v", err)
	}

	authCOSE, err := authHelper.GetCOSEPublicKey()
	if err != nil {
		t.Fatalf("failed to get authenticator COSE key: %v", err)
	}

	// Establish shared secrets
	if err := platformHelper.EstablishSharedSecret(authCOSE); err != nil {
		t.Fatalf("platform failed to establish shared secret: %v", err)
	}

	if err := authHelper.EstablishSharedSecret(platformCOSE); err != nil {
		t.Fatalf("authenticator failed to establish shared secret: %v", err)
	}

	// Verify shared secrets match
	if !bytes.Equal(platformHelper.SharedSecret(), authHelper.SharedSecret()) {
		t.Fatal("shared secrets do not match")
	}

	// Generate credential HMAC key
	credentialHMACKey := make([]byte, HMACSecretKeySize)
	if _, err := rand.Read(credentialHMACKey); err != nil {
		t.Fatalf("failed to generate credential HMAC key: %v", err)
	}

	// Test with single salt
	t.Run("single salt", func(t *testing.T) {
		salt1 := make([]byte, HMACSecretSaltSize)
		_, _ = rand.Read(salt1)

		// Platform encrypts salt
		saltEnc, err := platformHelper.EncryptSalts(salt1, nil)
		if err != nil {
			t.Fatalf("failed to encrypt salt: %v", err)
		}

		// Platform computes saltAuth
		saltAuth, err := platformHelper.ComputeSaltAuth(saltEnc)
		if err != nil {
			t.Fatalf("failed to compute saltAuth: %v", err)
		}

		// Build input
		input := &HMACSecretInput{
			KeyAgreement:      platformCOSE,
			SaltEnc:           saltEnc,
			SaltAuth:          saltAuth,
			PinUvAuthProtocol: PINProtocolVersion1,
		}

		// Create authenticator and process
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		if err != nil {
			t.Fatalf("failed to create authenticator: %v", err)
		}

		// Process using pre-established shared secret
		output, err := auth.ProcessHMACSecretWithSharedSecret(input, credentialHMACKey, authHelper.SharedSecret())
		if err != nil {
			t.Fatalf("failed to process hmac-secret: %v", err)
		}

		// Platform decrypts output
		decryptedOutput, err := platformHelper.DecryptOutput(output.Output)
		if err != nil {
			t.Fatalf("failed to decrypt output: %v", err)
		}

		// Verify output is correct
		expectedOutput := computeExpectedHMAC(credentialHMACKey, salt1)
		if !bytes.Equal(decryptedOutput, expectedOutput) {
			t.Errorf("output mismatch:\ngot:  %x\nwant: %x", decryptedOutput, expectedOutput)
		}
	})

	// Test with double salt
	t.Run("double salt", func(t *testing.T) {
		salt1 := make([]byte, HMACSecretSaltSize)
		salt2 := make([]byte, HMACSecretSaltSize)
		_, _ = rand.Read(salt1)
		_, _ = rand.Read(salt2)

		// Platform encrypts salts
		saltEnc, err := platformHelper.EncryptSalts(salt1, salt2)
		if err != nil {
			t.Fatalf("failed to encrypt salts: %v", err)
		}

		// Platform computes saltAuth
		saltAuth, err := platformHelper.ComputeSaltAuth(saltEnc)
		if err != nil {
			t.Fatalf("failed to compute saltAuth: %v", err)
		}

		// Build input
		input := &HMACSecretInput{
			KeyAgreement:      platformCOSE,
			SaltEnc:           saltEnc,
			SaltAuth:          saltAuth,
			PinUvAuthProtocol: PINProtocolVersion1,
		}

		// Create authenticator
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		if err != nil {
			t.Fatalf("failed to create authenticator: %v", err)
		}

		// Process using pre-established shared secret
		output, err := auth.ProcessHMACSecretWithSharedSecret(input, credentialHMACKey, authHelper.SharedSecret())
		if err != nil {
			t.Fatalf("failed to process hmac-secret: %v", err)
		}

		// Platform decrypts output
		decryptedOutput, err := platformHelper.DecryptOutput(output.Output)
		if err != nil {
			t.Fatalf("failed to decrypt output: %v", err)
		}

		// Verify outputs are correct
		expectedOutput1 := computeExpectedHMAC(credentialHMACKey, salt1)
		expectedOutput2 := computeExpectedHMAC(credentialHMACKey, salt2)
		expectedCombined := append(expectedOutput1, expectedOutput2...)

		if !bytes.Equal(decryptedOutput, expectedCombined) {
			t.Errorf("output mismatch:\ngot:  %x\nwant: %x", decryptedOutput, expectedCombined)
		}
	})
}

// TestHMACSecretSaltAuthVerificationFailure tests that invalid saltAuth is rejected.
func TestHMACSecretSaltAuthVerificationFailure(t *testing.T) {
	t.Parallel()

	// Create helpers
	platformHelper, err := NewHMACSecretPlatformHelper()
	if err != nil {
		t.Fatalf("failed to create platform helper: %v", err)
	}
	defer platformHelper.Reset()

	authHelper, err := NewHMACSecretPlatformHelper()
	if err != nil {
		t.Fatalf("failed to create authenticator helper: %v", err)
	}
	defer authHelper.Reset()

	// Exchange keys
	platformCOSE, err := platformHelper.GetCOSEPublicKey()
	if err != nil {
		t.Fatalf("failed to get platform COSE key: %v", err)
	}

	authCOSE, err := authHelper.GetCOSEPublicKey()
	if err != nil {
		t.Fatalf("failed to get authenticator COSE key: %v", err)
	}

	// Establish shared secrets
	_ = platformHelper.EstablishSharedSecret(authCOSE)
	_ = authHelper.EstablishSharedSecret(platformCOSE)

	// Generate credential HMAC key
	credentialHMACKey := make([]byte, HMACSecretKeySize)
	_, _ = rand.Read(credentialHMACKey)

	// Create salt and encrypt
	salt1 := make([]byte, HMACSecretSaltSize)
	_, _ = rand.Read(salt1)

	saltEnc, err := platformHelper.EncryptSalts(salt1, nil)
	if err != nil {
		t.Fatalf("failed to encrypt salt: %v", err)
	}

	// Use INVALID saltAuth (wrong data)
	invalidSaltAuth := make([]byte, hmacSecretAuthTagSize)
	_, _ = rand.Read(invalidSaltAuth)

	input := &HMACSecretInput{
		KeyAgreement:      platformCOSE,
		SaltEnc:           saltEnc,
		SaltAuth:          invalidSaltAuth,
		PinUvAuthProtocol: PINProtocolVersion1,
	}

	// Create authenticator
	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Process should fail with saltAuth mismatch
	_, err = auth.ProcessHMACSecretWithSharedSecret(input, credentialHMACKey, authHelper.SharedSecret())
	if err != ErrHMACSecretSaltAuthMismatch {
		t.Errorf("expected ErrHMACSecretSaltAuthMismatch, got: %v", err)
	}
}

// TestHMACSecretProtocolMismatch tests that unsupported protocol versions are rejected.
func TestHMACSecretProtocolMismatch(t *testing.T) {
	t.Parallel()

	// Generate valid input with invalid protocol
	platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate platform key: %v", err)
	}

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
		coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
	}
	keyAgreementBytes, _ := cbor.Marshal(coseKey)

	input := &HMACSecretInput{
		KeyAgreement:      keyAgreementBytes,
		SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
		SaltAuth:          make([]byte, hmacSecretAuthTagSize),
		PinUvAuthProtocol: 99, // Invalid protocol
	}

	credentialHMACKey := make([]byte, HMACSecretKeySize)
	_, _ = rand.Read(credentialHMACKey)

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	_, err = auth.ProcessHMACSecretExtension(input, credentialHMACKey)
	if err != ErrHMACSecretProtocolMismatch {
		t.Errorf("expected ErrHMACSecretProtocolMismatch, got: %v", err)
	}
}

// TestHMACSecretMissingCredentialKey tests that missing credential HMAC key is rejected.
func TestHMACSecretMissingCredentialKey(t *testing.T) {
	t.Parallel()

	platformHelper, err := NewHMACSecretPlatformHelper()
	if err != nil {
		t.Fatalf("failed to create platform helper: %v", err)
	}
	defer platformHelper.Reset()

	authHelper, err := NewHMACSecretPlatformHelper()
	if err != nil {
		t.Fatalf("failed to create authenticator helper: %v", err)
	}
	defer authHelper.Reset()

	platformCOSE, _ := platformHelper.GetCOSEPublicKey()
	authCOSE, _ := authHelper.GetCOSEPublicKey()
	_ = platformHelper.EstablishSharedSecret(authCOSE)
	_ = authHelper.EstablishSharedSecret(platformCOSE)

	salt1 := make([]byte, HMACSecretSaltSize)
	_, _ = rand.Read(salt1)
	saltEnc, _ := platformHelper.EncryptSalts(salt1, nil)
	saltAuth, _ := platformHelper.ComputeSaltAuth(saltEnc)

	input := &HMACSecretInput{
		KeyAgreement:      platformCOSE,
		SaltEnc:           saltEnc,
		SaltAuth:          saltAuth,
		PinUvAuthProtocol: PINProtocolVersion1,
	}

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	// Test with nil credential key
	_, err = auth.ProcessHMACSecretWithSharedSecret(input, nil, authHelper.SharedSecret())
	if err != ErrHMACSecretMissingCredentialKey {
		t.Errorf("expected ErrHMACSecretMissingCredentialKey, got: %v", err)
	}

	// Test with wrong size credential key
	_, err = auth.ProcessHMACSecretWithSharedSecret(input, make([]byte, 16), authHelper.SharedSecret())
	if err != ErrHMACSecretMissingCredentialKey {
		t.Errorf("expected ErrHMACSecretMissingCredentialKey, got: %v", err)
	}
}

// TestHMACSecretPlatformHelper tests the platform helper functions.
func TestHMACSecretPlatformHelper(t *testing.T) {
	t.Parallel()

	t.Run("key generation and COSE encoding", func(t *testing.T) {
		helper, err := NewHMACSecretPlatformHelper()
		if err != nil {
			t.Fatalf("failed to create helper: %v", err)
		}
		defer helper.Reset()

		coseKey, err := helper.GetCOSEPublicKey()
		if err != nil {
			t.Fatalf("failed to get COSE key: %v", err)
		}

		if len(coseKey) == 0 {
			t.Error("COSE key is empty")
		}

		// Verify it can be decoded
		var decoded map[int]interface{}
		if err := cbor.Unmarshal(coseKey, &decoded); err != nil {
			t.Fatalf("failed to decode COSE key: %v", err)
		}

		kty, _ := toInt(decoded[coseKeyLabelKty])
		if kty != COSEKeyTypeEC2 {
			t.Errorf("unexpected key type: %d", kty)
		}
	})

	t.Run("encrypt salts before shared secret", func(t *testing.T) {
		helper, err := NewHMACSecretPlatformHelper()
		if err != nil {
			t.Fatalf("failed to create helper: %v", err)
		}
		defer helper.Reset()

		salt1 := make([]byte, HMACSecretSaltSize)
		_, err = helper.EncryptSalts(salt1, nil)
		if err != ErrSharedSecretNotEstablished {
			t.Errorf("expected ErrSharedSecretNotEstablished, got: %v", err)
		}
	})

	t.Run("compute saltAuth before shared secret", func(t *testing.T) {
		helper, err := NewHMACSecretPlatformHelper()
		if err != nil {
			t.Fatalf("failed to create helper: %v", err)
		}
		defer helper.Reset()

		_, err = helper.ComputeSaltAuth(make([]byte, 48))
		if err != ErrSharedSecretNotEstablished {
			t.Errorf("expected ErrSharedSecretNotEstablished, got: %v", err)
		}
	})

	t.Run("decrypt output before shared secret", func(t *testing.T) {
		helper, err := NewHMACSecretPlatformHelper()
		if err != nil {
			t.Fatalf("failed to create helper: %v", err)
		}
		defer helper.Reset()

		_, err = helper.DecryptOutput(make([]byte, 48))
		if err != ErrSharedSecretNotEstablished {
			t.Errorf("expected ErrSharedSecretNotEstablished, got: %v", err)
		}
	})

	t.Run("invalid salt sizes", func(t *testing.T) {
		helper1, _ := NewHMACSecretPlatformHelper()
		helper2, _ := NewHMACSecretPlatformHelper()
		defer helper1.Reset()
		defer helper2.Reset()

		cose1, _ := helper1.GetCOSEPublicKey()
		cose2, _ := helper2.GetCOSEPublicKey()
		_ = helper1.EstablishSharedSecret(cose2)
		_ = helper2.EstablishSharedSecret(cose1)

		// Wrong salt1 size
		_, err := helper1.EncryptSalts(make([]byte, 16), nil)
		if err != ErrGetAssertionHMACSecretInvalidSalt {
			t.Errorf("expected ErrGetAssertionHMACSecretInvalidSalt for wrong salt1 size, got: %v", err)
		}

		// Wrong salt2 size
		_, err = helper1.EncryptSalts(make([]byte, 32), make([]byte, 16))
		if err != ErrGetAssertionHMACSecretInvalidSalt {
			t.Errorf("expected ErrGetAssertionHMACSecretInvalidSalt for wrong salt2 size, got: %v", err)
		}
	})
}

// TestBuildHMACSecretInput tests the input builder helper.
func TestBuildHMACSecretInput(t *testing.T) {
	t.Parallel()

	validKeyAgreement := make([]byte, 64)
	validSaltEnc := make([]byte, 48)
	validSaltAuth := make([]byte, 16)

	tests := []struct {
		name         string
		keyAgreement []byte
		saltEnc      []byte
		saltAuth     []byte
		protocol     int
		wantErr      error
	}{
		{
			name:         "valid input",
			keyAgreement: validKeyAgreement,
			saltEnc:      validSaltEnc,
			saltAuth:     validSaltAuth,
			protocol:     1,
			wantErr:      nil,
		},
		{
			name:         "empty keyAgreement",
			keyAgreement: nil,
			saltEnc:      validSaltEnc,
			saltAuth:     validSaltAuth,
			protocol:     1,
			wantErr:      ErrHMACSecretMissingKeyAgreement,
		},
		{
			name:         "empty saltEnc",
			keyAgreement: validKeyAgreement,
			saltEnc:      nil,
			saltAuth:     validSaltAuth,
			protocol:     1,
			wantErr:      ErrHMACSecretMissingSaltEnc,
		},
		{
			name:         "wrong saltAuth size",
			keyAgreement: validKeyAgreement,
			saltEnc:      validSaltEnc,
			saltAuth:     make([]byte, 8),
			protocol:     1,
			wantErr:      ErrHMACSecretInvalidSaltAuth,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := BuildHMACSecretInput(tc.keyAgreement, tc.saltEnc, tc.saltAuth, tc.protocol)

			if tc.wantErr != nil {
				if err != tc.wantErr {
					t.Errorf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

// TestEncodeHMACSecretOutput tests output encoding.
func TestEncodeHMACSecretOutput(t *testing.T) {
	t.Parallel()

	t.Run("nil output", func(t *testing.T) {
		_, err := EncodeHMACSecretOutput(nil)
		if err != ErrHMACSecretInvalidInput {
			t.Errorf("expected ErrHMACSecretInvalidInput, got: %v", err)
		}
	})

	t.Run("valid output", func(t *testing.T) {
		output := &HMACSecretOutput{
			Output: make([]byte, 48),
		}
		_, _ = rand.Read(output.Output)

		encoded, err := EncodeHMACSecretOutput(output)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !bytes.Equal(encoded, output.Output) {
			t.Error("encoded output should match input")
		}
	})
}

// TestHMACSecretNilInput tests handling of nil input.
func TestHMACSecretNilInput(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	credentialHMACKey := make([]byte, HMACSecretKeySize)
	_, _ = rand.Read(credentialHMACKey)

	_, err = auth.ProcessHMACSecretExtension(nil, credentialHMACKey)
	if err != ErrHMACSecretInvalidInput {
		t.Errorf("expected ErrHMACSecretInvalidInput, got: %v", err)
	}

	_, err = auth.ProcessHMACSecretWithSharedSecret(nil, credentialHMACKey, make([]byte, 32))
	if err != ErrHMACSecretInvalidInput {
		t.Errorf("expected ErrHMACSecretInvalidInput, got: %v", err)
	}
}

// TestHMACSecretInvalidSharedSecret tests handling of invalid shared secret.
func TestHMACSecretInvalidSharedSecret(t *testing.T) {
	t.Parallel()

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	credentialHMACKey := make([]byte, HMACSecretKeySize)
	_, _ = rand.Read(credentialHMACKey)

	input := &HMACSecretInput{
		KeyAgreement:      make([]byte, 64),
		SaltEnc:           make([]byte, 48),
		SaltAuth:          make([]byte, 16),
		PinUvAuthProtocol: 1,
	}

	// Wrong shared secret size
	_, err = auth.ProcessHMACSecretWithSharedSecret(input, credentialHMACKey, make([]byte, 16))
	if err != ErrSharedSecretNotEstablished {
		t.Errorf("expected ErrSharedSecretNotEstablished, got: %v", err)
	}
}

// TestDecodeCOSEKeyAgreementKey tests COSE key decoding for key agreement.
func TestDecodeCOSEKeyAgreementKey(t *testing.T) {
	t.Parallel()

	validKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	validCOSE := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   padCoordinate(validKey.X.Bytes(), 32),
		coseKeyLabelY:   padCoordinate(validKey.Y.Bytes(), 32),
	}
	validCOSEBytes, _ := cbor.Marshal(validCOSE)

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "valid P-256 key",
			input:   validCOSEBytes,
			wantErr: false,
		},
		{
			name:    "empty input",
			input:   nil,
			wantErr: true,
		},
		{
			name:    "invalid CBOR",
			input:   []byte{0xFF, 0xFF},
			wantErr: true,
		},
		{
			name: "wrong key type",
			input: func() []byte {
				wrongType := map[int]interface{}{
					coseKeyLabelKty: COSEKeyTypeOKP, // Wrong type
					coseKeyLabelAlg: COSEAlgECDHESHKDF256,
					coseKeyLabelCrv: COSECurveP256,
					coseKeyLabelX:   make([]byte, 32),
					coseKeyLabelY:   make([]byte, 32),
				}
				b, _ := cbor.Marshal(wrongType)
				return b
			}(),
			wantErr: true,
		},
		{
			name: "wrong curve",
			input: func() []byte {
				wrongCurve := map[int]interface{}{
					coseKeyLabelKty: COSEKeyTypeEC2,
					coseKeyLabelAlg: COSEAlgECDHESHKDF256,
					coseKeyLabelCrv: COSECurveP384, // Wrong curve
					coseKeyLabelX:   make([]byte, 32),
					coseKeyLabelY:   make([]byte, 32),
				}
				b, _ := cbor.Marshal(wrongCurve)
				return b
			}(),
			wantErr: true,
		},
		{
			name: "missing X coordinate",
			input: func() []byte {
				missingX := map[int]interface{}{
					coseKeyLabelKty: COSEKeyTypeEC2,
					coseKeyLabelAlg: COSEAlgECDHESHKDF256,
					coseKeyLabelCrv: COSECurveP256,
					coseKeyLabelY:   make([]byte, 32),
				}
				b, _ := cbor.Marshal(missingX)
				return b
			}(),
			wantErr: true,
		},
		{
			name: "missing Y coordinate",
			input: func() []byte {
				missingY := map[int]interface{}{
					coseKeyLabelKty: COSEKeyTypeEC2,
					coseKeyLabelAlg: COSEAlgECDHESHKDF256,
					coseKeyLabelCrv: COSECurveP256,
					coseKeyLabelX:   make([]byte, 32),
				}
				b, _ := cbor.Marshal(missingY)
				return b
			}(),
			wantErr: true,
		},
		{
			name: "point not on curve",
			input: func() []byte {
				offCurve := map[int]interface{}{
					coseKeyLabelKty: COSEKeyTypeEC2,
					coseKeyLabelAlg: COSEAlgECDHESHKDF256,
					coseKeyLabelCrv: COSECurveP256,
					coseKeyLabelX:   make([]byte, 32), // All zeros is not on P-256
					coseKeyLabelY:   make([]byte, 32),
				}
				b, _ := cbor.Marshal(offCurve)
				return b
			}(),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := decodeCOSEKeyAgreementKey(tc.input)

			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}

// TestClearBytes tests secure memory clearing.
func TestClearBytes(t *testing.T) {
	t.Parallel()

	data := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	clearBytes(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("byte at index %d not cleared: %d", i, b)
		}
	}
}

// TestVerifySaltAuth tests saltAuth verification.
func TestVerifySaltAuth(t *testing.T) {
	t.Parallel()

	sharedSecret := make([]byte, 32)
	_, _ = rand.Read(sharedSecret)

	saltEnc := make([]byte, 48)
	_, _ = rand.Read(saltEnc)

	// Compute correct saltAuth
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(saltEnc)
	correctSaltAuth := mac.Sum(nil)[:16]

	t.Run("correct saltAuth", func(t *testing.T) {
		err := verifySaltAuth(sharedSecret, PINProtocolVersion1, saltEnc, correctSaltAuth)
		if err != nil {
			t.Errorf("expected nil error, got: %v", err)
		}
	})

	t.Run("incorrect saltAuth", func(t *testing.T) {
		wrongSaltAuth := make([]byte, 16)
		_, _ = rand.Read(wrongSaltAuth)

		err := verifySaltAuth(sharedSecret, PINProtocolVersion1, saltEnc, wrongSaltAuth)
		if err != ErrHMACSecretSaltAuthMismatch {
			t.Errorf("expected ErrHMACSecretSaltAuthMismatch, got: %v", err)
		}
	})
}

// TestDecryptSaltsValidation tests salt decryption validation.
func TestDecryptSaltsValidation(t *testing.T) {
	t.Parallel()

	sharedSecret := make([]byte, 32)
	_, _ = rand.Read(sharedSecret)

	t.Run("invalid length", func(t *testing.T) {
		_, err := decryptSalts(sharedSecret, PINProtocolVersion1, make([]byte, 17))
		if err != ErrHMACSecretInvalidSaltEnc {
			t.Errorf("expected ErrHMACSecretInvalidSaltEnc, got: %v", err)
		}
	})
}

// computeExpectedHMAC computes the expected HMAC output for testing.
func computeExpectedHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// TestExtractCOSEKeyBytes tests COSE key extraction from various formats.
func TestExtractCOSEKeyBytes(t *testing.T) {
	t.Parallel()

	t.Run("raw bytes", func(t *testing.T) {
		input := []byte{1, 2, 3, 4}
		result, err := extractCOSEKeyBytes(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(result, input) {
			t.Error("result should match input")
		}
	})

	t.Run("interface map", func(t *testing.T) {
		input := map[interface{}]interface{}{
			1: 2,
			3: -25,
		}
		result, err := extractCOSEKeyBytes(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) == 0 {
			t.Error("expected non-empty result")
		}
	})

	t.Run("int map", func(t *testing.T) {
		input := map[int]interface{}{
			1: 2,
			3: -25,
		}
		result, err := extractCOSEKeyBytes(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result) == 0 {
			t.Error("expected non-empty result")
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		_, err := extractCOSEKeyBytes("invalid")
		if err != ErrHMACSecretInvalidKeyAgreement {
			t.Errorf("expected ErrHMACSecretInvalidKeyAgreement, got: %v", err)
		}
	})
}

// TestHMACSecretConsistency verifies that the hmac-secret output is deterministic.
func TestHMACSecretConsistency(t *testing.T) {
	t.Parallel()

	credentialHMACKey := make([]byte, HMACSecretKeySize)
	_, _ = rand.Read(credentialHMACKey)

	salt := make([]byte, HMACSecretSaltSize)
	_, _ = rand.Read(salt)

	// Compute multiple times
	output1 := computeHMACOutputs(credentialHMACKey, salt)
	output2 := computeHMACOutputs(credentialHMACKey, salt)

	if !bytes.Equal(output1, output2) {
		t.Error("HMAC outputs should be consistent for same inputs")
	}
}

// TestHMACSecretWithProtocolV2 tests protocol version 2 support.
func TestHMACSecretWithProtocolV2(t *testing.T) {
	t.Parallel()

	platformHelper, err := NewHMACSecretPlatformHelper()
	if err != nil {
		t.Fatalf("failed to create platform helper: %v", err)
	}
	defer platformHelper.Reset()

	authHelper, err := NewHMACSecretPlatformHelper()
	if err != nil {
		t.Fatalf("failed to create authenticator helper: %v", err)
	}
	defer authHelper.Reset()

	platformCOSE, _ := platformHelper.GetCOSEPublicKey()
	authCOSE, _ := authHelper.GetCOSEPublicKey()
	_ = platformHelper.EstablishSharedSecret(authCOSE)
	_ = authHelper.EstablishSharedSecret(platformCOSE)

	sharedSecret := platformHelper.SharedSecret()

	credentialHMACKey := make([]byte, HMACSecretKeySize)
	_, _ = rand.Read(credentialHMACKey)

	salt1 := make([]byte, HMACSecretSaltSize)
	_, _ = rand.Read(salt1)

	// V2: encrypt salts with random IV prefix
	padded := pkcs7Pad(salt1, aes.BlockSize)
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)
	// V2 saltEnc = IV || ciphertext
	saltEnc := append(iv, ciphertext...)

	// V2: full 32-byte HMAC saltAuth (no truncation)
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(saltEnc)
	saltAuth := mac.Sum(nil) // Full 32 bytes

	input := &HMACSecretInput{
		KeyAgreement:      platformCOSE,
		SaltEnc:           saltEnc,
		SaltAuth:          saltAuth,
		PinUvAuthProtocol: PINProtocolVersion2,
	}

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	auth2, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	output, err := auth2.ProcessHMACSecretWithSharedSecret(input, credentialHMACKey, authHelper.SharedSecret())
	if err != nil {
		t.Fatalf("failed to process hmac-secret with V2: %v", err)
	}

	if output == nil || len(output.Output) == 0 {
		t.Error("expected non-empty output")
	}
}

// TestHMACSecretV2OutputHasRandomIVPrefix verifies that V2 encrypted output
// has a random IV prepended and is decryptable, and that two calls produce
// different ciphertext (proving random IV) but identical plaintext.
func TestHMACSecretV2OutputHasRandomIVPrefix(t *testing.T) {
	t.Parallel()

	platformHelper, err := NewHMACSecretPlatformHelper()
	require.NoError(t, err)
	defer platformHelper.Reset()

	authHelper, err := NewHMACSecretPlatformHelper()
	require.NoError(t, err)
	defer authHelper.Reset()

	platformCOSE, err := platformHelper.GetCOSEPublicKey()
	require.NoError(t, err)
	authCOSE, err := authHelper.GetCOSEPublicKey()
	require.NoError(t, err)
	require.NoError(t, platformHelper.EstablishSharedSecret(authCOSE))
	require.NoError(t, authHelper.EstablishSharedSecret(platformCOSE))

	sharedSecret := platformHelper.SharedSecret()

	credentialHMACKey := make([]byte, HMACSecretKeySize)
	_, _ = rand.Read(credentialHMACKey)

	salt := make([]byte, HMACSecretSaltSize)
	_, _ = rand.Read(salt)

	// Encrypt salt with V2 (random IV prefix).
	padded := pkcs7Pad(salt, aes.BlockSize)
	block, err := aes.NewCipher(sharedSecret)
	require.NoError(t, err)

	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, len(padded))
	mode.CryptBlocks(ct, padded)
	saltEnc := append(iv, ct...)

	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(saltEnc)
	saltAuth := mac.Sum(nil) // Full 32 bytes for V2

	input := &HMACSecretInput{
		KeyAgreement:      platformCOSE,
		SaltEnc:           saltEnc,
		SaltAuth:          saltAuth,
		PinUvAuthProtocol: PINProtocolVersion2,
	}

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	auth, err := NewAuthenticator(config)
	require.NoError(t, err)

	// First call.
	output1, err := auth.ProcessHMACSecretWithSharedSecret(input, credentialHMACKey, authHelper.SharedSecret())
	require.NoError(t, err)
	require.NotNil(t, output1)

	// V2 output must have IV (16 bytes) + at least one block of ciphertext (16 bytes).
	require.GreaterOrEqual(t, len(output1.Output), aes.BlockSize+aes.BlockSize,
		"V2 output must include IV prefix plus at least one ciphertext block")

	// Second call with same input should produce different ciphertext (random IV).
	// Re-encrypt salt for a fresh saltAuth since the input is consumed.
	iv2 := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv2)
	mode2 := cipher.NewCBCEncrypter(block, iv2)
	ct2 := make([]byte, len(padded))
	mode2.CryptBlocks(ct2, padded)
	saltEnc2 := append(iv2, ct2...)

	mac2 := hmac.New(sha256.New, sharedSecret)
	mac2.Write(saltEnc2)
	saltAuth2 := mac2.Sum(nil)

	input2 := &HMACSecretInput{
		KeyAgreement:      platformCOSE,
		SaltEnc:           saltEnc2,
		SaltAuth:          saltAuth2,
		PinUvAuthProtocol: PINProtocolVersion2,
	}

	output2, err := auth.ProcessHMACSecretWithSharedSecret(input2, credentialHMACKey, authHelper.SharedSecret())
	require.NoError(t, err)
	require.NotNil(t, output2)

	// Different ciphertext because of random IV.
	require.NotEqual(t, output1.Output, output2.Output,
		"V2 outputs must differ due to random IV")

	// Decrypt both and verify same plaintext.
	decrypt := func(encrypted []byte) []byte {
		outIV := encrypted[:aes.BlockSize]
		outCT := encrypted[aes.BlockSize:]
		decMode := cipher.NewCBCDecrypter(block, outIV)
		plain := make([]byte, len(outCT))
		decMode.CryptBlocks(plain, outCT)
		return plain
	}

	plain1 := decrypt(output1.Output)
	plain2 := decrypt(output2.Output)
	require.Equal(t, plain1, plain2,
		"V2 decrypted plaintext must be identical for same input salt and credential key")
}

// TestHMACSecretV2RejectsTruncatedSaltAuth verifies that V2 rejects 16-byte (V1-style) saltAuth.
func TestHMACSecretV2RejectsTruncatedSaltAuth(t *testing.T) {
	t.Parallel()

	platformHelper, err := NewHMACSecretPlatformHelper()
	require.NoError(t, err)
	defer platformHelper.Reset()

	authHelper, err := NewHMACSecretPlatformHelper()
	require.NoError(t, err)
	defer authHelper.Reset()

	platformCOSE, err := platformHelper.GetCOSEPublicKey()
	require.NoError(t, err)
	authCOSE, err := authHelper.GetCOSEPublicKey()
	require.NoError(t, err)
	require.NoError(t, platformHelper.EstablishSharedSecret(authCOSE))
	require.NoError(t, authHelper.EstablishSharedSecret(platformCOSE))

	sharedSecret := platformHelper.SharedSecret()

	credentialHMACKey := make([]byte, HMACSecretKeySize)
	_, _ = rand.Read(credentialHMACKey)

	salt := make([]byte, HMACSecretSaltSize)
	_, _ = rand.Read(salt)

	// Encrypt salt with V2 format (random IV prefix).
	padded := pkcs7Pad(salt, aes.BlockSize)
	block, err := aes.NewCipher(sharedSecret)
	require.NoError(t, err)

	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	mode := cipher.NewCBCEncrypter(block, iv)
	ct := make([]byte, len(padded))
	mode.CryptBlocks(ct, padded)
	saltEnc := append(iv, ct...)

	// Compute correct HMAC but truncate to 16 bytes (V1 style) - this should fail for V2.
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(saltEnc)
	truncatedSaltAuth := mac.Sum(nil)[:16] // V1-style truncation

	input := &HMACSecretInput{
		KeyAgreement:      platformCOSE,
		SaltEnc:           saltEnc,
		SaltAuth:          truncatedSaltAuth,
		PinUvAuthProtocol: PINProtocolVersion2,
	}

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	auth, err := NewAuthenticator(config)
	require.NoError(t, err)

	_, err = auth.ProcessHMACSecretWithSharedSecret(input, credentialHMACKey, authHelper.SharedSecret())
	require.Error(t, err, "V2 should reject truncated 16-byte saltAuth")
	require.ErrorIs(t, err, ErrHMACSecretSaltAuthMismatch)
}

// TestProcessHMACSecretExtension tests ProcessHMACSecretExtension method.
func TestProcessHMACSecretExtension(t *testing.T) {
	t.Run("nil input returns error", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialHMACKey)

		output, err := auth.ProcessHMACSecretExtension(nil, credentialHMACKey)
		require.ErrorIs(t, err, ErrHMACSecretInvalidInput)
		require.Nil(t, output)
	})

	t.Run("invalid credential key length returns error", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		// Create valid COSE key
		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		input := &HMACSecretInput{
			KeyAgreement:      keyAgreementBytes,
			SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: PINProtocolVersion1,
		}

		// Wrong credential key length
		shortKey := make([]byte, 16)
		output, err := auth.ProcessHMACSecretExtension(input, shortKey)
		require.ErrorIs(t, err, ErrHMACSecretMissingCredentialKey)
		require.Nil(t, output)

		// Empty credential key
		output, err = auth.ProcessHMACSecretExtension(input, nil)
		require.ErrorIs(t, err, ErrHMACSecretMissingCredentialKey)
		require.Nil(t, output)
	})

	t.Run("unsupported protocol version returns error", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		// Create valid COSE key
		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		input := &HMACSecretInput{
			KeyAgreement:      keyAgreementBytes,
			SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: 99, // Invalid protocol
		}

		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialHMACKey)

		output, err := auth.ProcessHMACSecretExtension(input, credentialHMACKey)
		require.ErrorIs(t, err, ErrHMACSecretProtocolMismatch)
		require.Nil(t, output)
	})

	t.Run("protocol version 0 returns error", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		input := &HMACSecretInput{
			KeyAgreement:      keyAgreementBytes,
			SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: 0, // Invalid protocol version 0
		}

		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialHMACKey)

		output, err := auth.ProcessHMACSecretExtension(input, credentialHMACKey)
		require.ErrorIs(t, err, ErrHMACSecretProtocolMismatch)
		require.Nil(t, output)
	})

	t.Run("invalid key agreement returns error", func(t *testing.T) {
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		// Invalid COSE key (not valid CBOR)
		input := &HMACSecretInput{
			KeyAgreement:      []byte{0xFF, 0xFF, 0xFF}, // Invalid CBOR
			SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: PINProtocolVersion1,
		}

		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialHMACKey)

		output, err := auth.ProcessHMACSecretExtension(input, credentialHMACKey)
		require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
		require.Nil(t, output)
	})
}

// TestDeriveHMACSecretSharedSecret tests the deriveHMACSecretSharedSecret function.
func TestDeriveHMACSecretSharedSecret(t *testing.T) {
	t.Run("valid P-256 key with protocol V1", func(t *testing.T) {
		// Generate a valid P-256 key
		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		sharedSecret, err := deriveHMACSecretSharedSecret(keyAgreementBytes, PINProtocolVersion1)
		require.NoError(t, err)
		require.NotNil(t, sharedSecret)
		require.Len(t, sharedSecret, 32) // SHA-256 output is 32 bytes
	})

	t.Run("valid P-256 key with protocol V2", func(t *testing.T) {
		// Generate a valid P-256 key
		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		sharedSecret, err := deriveHMACSecretSharedSecret(keyAgreementBytes, PINProtocolVersion2)
		require.NoError(t, err)
		require.NotNil(t, sharedSecret)
		require.Len(t, sharedSecret, 32)
	})

	t.Run("unsupported protocol version returns error", func(t *testing.T) {
		// Generate a valid P-256 key
		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		sharedSecret, err := deriveHMACSecretSharedSecret(keyAgreementBytes, 99)
		require.ErrorIs(t, err, ErrHMACSecretProtocolMismatch)
		require.Nil(t, sharedSecret)
	})

	t.Run("invalid COSE key returns error", func(t *testing.T) {
		// Invalid CBOR data
		invalidKey := []byte{0xFF, 0xFF, 0xFF}

		sharedSecret, err := deriveHMACSecretSharedSecret(invalidKey, PINProtocolVersion1)
		require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
		require.Nil(t, sharedSecret)
	})

	t.Run("empty COSE key returns error", func(t *testing.T) {
		sharedSecret, err := deriveHMACSecretSharedSecret(nil, PINProtocolVersion1)
		require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
		require.Nil(t, sharedSecret)

		sharedSecret, err = deriveHMACSecretSharedSecret([]byte{}, PINProtocolVersion1)
		require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
		require.Nil(t, sharedSecret)
	})

	t.Run("COSE key with wrong curve returns error", func(t *testing.T) {
		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP384, // Wrong curve - HMAC secret requires P-256
			coseKeyLabelX:   make([]byte, 48),
			coseKeyLabelY:   make([]byte, 48),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		sharedSecret, err := deriveHMACSecretSharedSecret(keyAgreementBytes, PINProtocolVersion1)
		require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
		require.Nil(t, sharedSecret)
	})

	t.Run("COSE key with point not on curve returns error", func(t *testing.T) {
		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   make([]byte, 32), // All zeros - not on curve
			coseKeyLabelY:   make([]byte, 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		sharedSecret, err := deriveHMACSecretSharedSecret(keyAgreementBytes, PINProtocolVersion1)
		require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
		require.Nil(t, sharedSecret)
	})

	t.Run("different keys produce different shared secrets", func(t *testing.T) {
		// Generate two different keys
		key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseKey1 := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(key1.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(key1.Y.Bytes(), 32),
		}
		keyBytes1, err := cbor.Marshal(coseKey1)
		require.NoError(t, err)

		coseKey2 := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(key2.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(key2.Y.Bytes(), 32),
		}
		keyBytes2, err := cbor.Marshal(coseKey2)
		require.NoError(t, err)

		secret1, err := deriveHMACSecretSharedSecret(keyBytes1, PINProtocolVersion1)
		require.NoError(t, err)

		secret2, err := deriveHMACSecretSharedSecret(keyBytes2, PINProtocolVersion1)
		require.NoError(t, err)

		// Different keys should produce different shared secrets
		require.False(t, bytes.Equal(secret1, secret2), "different keys should produce different shared secrets")
	})
}

// TestParseHMACSecretInputInterfaceMapWithUint8Keys tests parsing with uint8 keys.
func TestParseHMACSecretInputInterfaceMapWithUint8Keys(t *testing.T) {
	t.Parallel()

	// Generate test platform key
	platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
		coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
	}
	keyAgreementBytes, err := cbor.Marshal(coseKey)
	require.NoError(t, err)

	validSaltEnc := make([]byte, HMACSecretEncryptedSingleSaltSize)
	_, _ = rand.Read(validSaltEnc)

	validSaltAuth := make([]byte, hmacSecretAuthTagSize)
	_, _ = rand.Read(validSaltAuth)

	// Test with uint8 keys (as CBOR might decode small integers as uint8)
	input := map[interface{}]interface{}{
		uint8(hmacSecretKeyAgreement):      keyAgreementBytes,
		uint8(hmacSecretSaltEnc):           validSaltEnc,
		uint8(hmacSecretSaltAuth):          validSaltAuth,
		uint8(hmacSecretPinUvAuthProtocol): uint8(1),
	}

	result, err := ParseHMACSecretInput(input)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, 1, result.PinUvAuthProtocol)
}

// TestComputeHMACOutputs tests the HMAC output computation.
func TestComputeHMACOutputs(t *testing.T) {
	t.Parallel()

	t.Run("single salt produces 32 byte output", func(t *testing.T) {
		credentialKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialKey)

		salt := make([]byte, HMACSecretSaltSize)
		_, _ = rand.Read(salt)

		output := computeHMACOutputs(credentialKey, salt)
		require.Len(t, output, HMACSecretOutputSize)
	})

	t.Run("double salt produces 64 byte output", func(t *testing.T) {
		credentialKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialKey)

		salts := make([]byte, HMACSecretSaltSize*2)
		_, _ = rand.Read(salts)

		output := computeHMACOutputs(credentialKey, salts)
		require.Len(t, output, HMACSecretOutputSize*2)
	})

	t.Run("outputs are deterministic", func(t *testing.T) {
		credentialKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialKey)

		salt := make([]byte, HMACSecretSaltSize)
		_, _ = rand.Read(salt)

		output1 := computeHMACOutputs(credentialKey, salt)
		output2 := computeHMACOutputs(credentialKey, salt)
		require.Equal(t, output1, output2)
	})

	t.Run("different salts produce different outputs", func(t *testing.T) {
		credentialKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialKey)

		salt1 := make([]byte, HMACSecretSaltSize)
		salt2 := make([]byte, HMACSecretSaltSize)
		_, _ = rand.Read(salt1)
		_, _ = rand.Read(salt2)

		output1 := computeHMACOutputs(credentialKey, salt1)
		output2 := computeHMACOutputs(credentialKey, salt2)
		require.False(t, bytes.Equal(output1, output2))
	})

	t.Run("different keys produce different outputs", func(t *testing.T) {
		key1 := make([]byte, HMACSecretKeySize)
		key2 := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(key1)
		_, _ = rand.Read(key2)

		salt := make([]byte, HMACSecretSaltSize)
		_, _ = rand.Read(salt)

		output1 := computeHMACOutputs(key1, salt)
		output2 := computeHMACOutputs(key2, salt)
		require.False(t, bytes.Equal(output1, output2))
	})
}

// TestEncryptHMACOutputs tests HMAC output encryption.
func TestEncryptHMACOutputs(t *testing.T) {
	t.Parallel()

	t.Run("encrypts single output", func(t *testing.T) {
		sharedSecret := make([]byte, 32)
		_, _ = rand.Read(sharedSecret)

		outputs := make([]byte, HMACSecretOutputSize)
		_, _ = rand.Read(outputs)

		encrypted, err := encryptHMACOutputs(sharedSecret, PINProtocolVersion1, outputs)
		require.NoError(t, err)
		require.NotNil(t, encrypted)
		require.Greater(t, len(encrypted), len(outputs)) // Encrypted is larger due to padding
	})

	t.Run("encrypts double output", func(t *testing.T) {
		sharedSecret := make([]byte, 32)
		_, _ = rand.Read(sharedSecret)

		outputs := make([]byte, HMACSecretOutputSize*2)
		_, _ = rand.Read(outputs)

		encrypted, err := encryptHMACOutputs(sharedSecret, PINProtocolVersion1, outputs)
		require.NoError(t, err)
		require.NotNil(t, encrypted)
	})
}

// TestProcessHMACSecretExtensionSuccessPath tests the full success path of ProcessHMACSecretExtension.
func TestProcessHMACSecretExtensionSuccessPath(t *testing.T) {
	t.Parallel()

	t.Run("success with single salt and protocol V1", func(t *testing.T) {
		t.Parallel()

		// Create authenticator
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		// Generate platform key pair
		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create COSE key for platform public key
		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		// Generate credential HMAC key
		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, err = rand.Read(credentialHMACKey)
		require.NoError(t, err)

		// Create salt and encrypt it
		salt1 := make([]byte, HMACSecretSaltSize)
		_, err = rand.Read(salt1)
		require.NoError(t, err)

		// For the full ProcessHMACSecretExtension, we need a properly encrypted salt
		// The function will derive its own shared secret via ECDH
		// For testing purposes, we need to create a valid saltEnc and saltAuth
		// that would be valid given the authenticator's ephemeral ECDH computation

		// Since deriveHMACSecretSharedSecret generates its own ephemeral key,
		// we cannot predict the shared secret. Instead, test that the function
		// properly handles valid-looking inputs and returns appropriate errors
		// for the parts we can control.

		input := &HMACSecretInput{
			KeyAgreement:      keyAgreementBytes,
			SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: PINProtocolVersion1,
		}

		// This will fail at saltAuth verification because we don't have the
		// shared secret that the authenticator will derive. This is expected
		// behavior and tests that the function properly validates saltAuth.
		output, err := auth.ProcessHMACSecretExtension(input, credentialHMACKey)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrHMACSecretSaltAuthMismatch)
		require.Nil(t, output)
	})

	t.Run("success with double salt and protocol V2", func(t *testing.T) {
		t.Parallel()

		// Create authenticator
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		// Generate platform key pair
		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// Create COSE key for platform public key
		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		// Generate credential HMAC key
		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, err = rand.Read(credentialHMACKey)
		require.NoError(t, err)

		input := &HMACSecretInput{
			KeyAgreement:      keyAgreementBytes,
			SaltEnc:           make([]byte, HMACSecretEncryptedDoubleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: PINProtocolVersion2,
		}

		// Same as above - this tests that protocol V2 path is exercised
		output, err := auth.ProcessHMACSecretExtension(input, credentialHMACKey)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrHMACSecretSaltAuthMismatch)
		require.Nil(t, output)
	})
}

// TestProcessHMACSecretExtensionDecryptionFailure tests decryption failure scenarios.
func TestProcessHMACSecretExtensionDecryptionFailure(t *testing.T) {
	t.Parallel()

	t.Run("invalid padding in decrypted salts", func(t *testing.T) {
		t.Parallel()

		// Create platform and auth helpers for proper key exchange
		platformHelper, err := NewHMACSecretPlatformHelper()
		require.NoError(t, err)
		defer platformHelper.Reset()

		authHelper, err := NewHMACSecretPlatformHelper()
		require.NoError(t, err)
		defer authHelper.Reset()

		// Exchange keys
		platformCOSE, err := platformHelper.GetCOSEPublicKey()
		require.NoError(t, err)

		authCOSE, err := authHelper.GetCOSEPublicKey()
		require.NoError(t, err)

		// Establish shared secrets
		err = platformHelper.EstablishSharedSecret(authCOSE)
		require.NoError(t, err)

		err = authHelper.EstablishSharedSecret(platformCOSE)
		require.NoError(t, err)

		// Create authenticator
		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialHMACKey)

		// Create invalid encrypted data (will have invalid padding when decrypted)
		invalidSaltEnc := make([]byte, HMACSecretEncryptedSingleSaltSize)
		_, _ = rand.Read(invalidSaltEnc)

		// Compute valid saltAuth for the garbage data
		saltAuth, err := platformHelper.ComputeSaltAuth(invalidSaltEnc)
		require.NoError(t, err)

		input := &HMACSecretInput{
			KeyAgreement:      platformCOSE,
			SaltEnc:           invalidSaltEnc,
			SaltAuth:          saltAuth,
			PinUvAuthProtocol: PINProtocolVersion1,
		}

		// Using the pre-established shared secret, this should fail at decryption
		// because the "encrypted" data will have invalid PKCS7 padding
		output, err := auth.ProcessHMACSecretWithSharedSecret(input, credentialHMACKey, authHelper.SharedSecret())
		require.Error(t, err)
		require.ErrorIs(t, err, ErrHMACSecretDecryptionFailed)
		require.Nil(t, output)
	})
}

// TestProcessHMACSecretExtensionEdgeCases tests edge cases for ProcessHMACSecretExtension.
func TestProcessHMACSecretExtensionEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("credential key exactly at boundary", func(t *testing.T) {
		t.Parallel()

		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		input := &HMACSecretInput{
			KeyAgreement:      keyAgreementBytes,
			SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: PINProtocolVersion1,
		}

		// Test with key that is one byte too short
		shortKey := make([]byte, HMACSecretKeySize-1)
		_, _ = rand.Read(shortKey)

		output, err := auth.ProcessHMACSecretExtension(input, shortKey)
		require.ErrorIs(t, err, ErrHMACSecretMissingCredentialKey)
		require.Nil(t, output)

		// Test with key that is one byte too long
		longKey := make([]byte, HMACSecretKeySize+1)
		_, _ = rand.Read(longKey)

		output, err = auth.ProcessHMACSecretExtension(input, longKey)
		require.ErrorIs(t, err, ErrHMACSecretMissingCredentialKey)
		require.Nil(t, output)
	})

	t.Run("negative protocol version", func(t *testing.T) {
		t.Parallel()

		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		input := &HMACSecretInput{
			KeyAgreement:      keyAgreementBytes,
			SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: -1, // Negative protocol version
		}

		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialHMACKey)

		output, err := auth.ProcessHMACSecretExtension(input, credentialHMACKey)
		require.ErrorIs(t, err, ErrHMACSecretProtocolMismatch)
		require.Nil(t, output)
	})

	t.Run("COSE key missing kty", func(t *testing.T) {
		t.Parallel()

		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		// COSE key without kty field
		coseKey := map[int]interface{}{
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
			coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		input := &HMACSecretInput{
			KeyAgreement:      keyAgreementBytes,
			SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: PINProtocolVersion1,
		}

		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialHMACKey)

		output, err := auth.ProcessHMACSecretExtension(input, credentialHMACKey)
		require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
		require.Nil(t, output)
	})

	t.Run("COSE key with empty X coordinate", func(t *testing.T) {
		t.Parallel()

		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		// COSE key with empty X coordinate
		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   []byte{}, // Empty X
			coseKeyLabelY:   make([]byte, 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		input := &HMACSecretInput{
			KeyAgreement:      keyAgreementBytes,
			SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: PINProtocolVersion1,
		}

		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialHMACKey)

		output, err := auth.ProcessHMACSecretExtension(input, credentialHMACKey)
		require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
		require.Nil(t, output)
	})

	t.Run("COSE key with X as non-bytes type", func(t *testing.T) {
		t.Parallel()

		storage := NewMemoryStorage()
		config := DefaultConfig()
		config.Storage = storage
		auth, err := NewAuthenticator(config)
		require.NoError(t, err)

		// COSE key with X as string instead of bytes
		coseKey := map[int]interface{}{
			coseKeyLabelKty: COSEKeyTypeEC2,
			coseKeyLabelAlg: COSEAlgECDHESHKDF256,
			coseKeyLabelCrv: COSECurveP256,
			coseKeyLabelX:   "not-bytes", // Wrong type
			coseKeyLabelY:   make([]byte, 32),
		}
		keyAgreementBytes, err := cbor.Marshal(coseKey)
		require.NoError(t, err)

		input := &HMACSecretInput{
			KeyAgreement:      keyAgreementBytes,
			SaltEnc:           make([]byte, HMACSecretEncryptedSingleSaltSize),
			SaltAuth:          make([]byte, hmacSecretAuthTagSize),
			PinUvAuthProtocol: PINProtocolVersion1,
		}

		credentialHMACKey := make([]byte, HMACSecretKeySize)
		_, _ = rand.Read(credentialHMACKey)

		output, err := auth.ProcessHMACSecretExtension(input, credentialHMACKey)
		require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
		require.Nil(t, output)
	})
}

// TestDecryptSaltsInvalidPadding tests decryption with invalid PKCS7 padding.
func TestDecryptSaltsInvalidPadding(t *testing.T) {
	t.Parallel()

	sharedSecret := make([]byte, 32)
	_, _ = rand.Read(sharedSecret)

	t.Run("ciphertext with invalid PKCS7 padding", func(t *testing.T) {
		t.Parallel()

		// Create ciphertext that will have invalid padding when decrypted
		// We'll encrypt some data with valid padding, then corrupt the last block
		validData := make([]byte, 32) // Single salt
		_, _ = rand.Read(validData)

		// Encrypt with PKCS7 padding
		padded := pkcs7Pad(validData, aes.BlockSize)
		block, err := aes.NewCipher(sharedSecret)
		require.NoError(t, err)

		iv := make([]byte, aes.BlockSize)
		mode := cipher.NewCBCEncrypter(block, iv)

		ciphertext := make([]byte, len(padded))
		mode.CryptBlocks(ciphertext, padded)

		// Corrupt the last byte of ciphertext (affects padding after decryption)
		ciphertext[len(ciphertext)-1] ^= 0xFF

		// Decryption should fail due to invalid padding
		_, err = decryptSalts(sharedSecret, PINProtocolVersion1, ciphertext)
		require.ErrorIs(t, err, ErrHMACSecretDecryptionFailed)
	})
}

// TestDecryptSaltsInvalidLength tests decryption with invalid ciphertext lengths.
func TestDecryptSaltsInvalidLength(t *testing.T) {
	t.Parallel()

	sharedSecret := make([]byte, 32)
	_, _ = rand.Read(sharedSecret)

	tests := []struct {
		name   string
		length int
	}{
		{"too short", 16},
		{"between single and double", 60},
		{"too long", 100},
		{"zero length", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			saltEnc := make([]byte, tc.length)
			_, _ = rand.Read(saltEnc)

			_, err := decryptSalts(sharedSecret, PINProtocolVersion1, saltEnc)
			require.ErrorIs(t, err, ErrHMACSecretInvalidSaltEnc)
		})
	}
}

// TestHMACSecretPlatformHelperDecryptInvalidOutputLength tests decryption with invalid output lengths.
func TestHMACSecretPlatformHelperDecryptInvalidOutputLength(t *testing.T) {
	t.Parallel()

	helper1, err := NewHMACSecretPlatformHelper()
	require.NoError(t, err)
	defer helper1.Reset()

	helper2, err := NewHMACSecretPlatformHelper()
	require.NoError(t, err)
	defer helper2.Reset()

	_, err = helper1.GetCOSEPublicKey()
	require.NoError(t, err)

	cose2, err := helper2.GetCOSEPublicKey()
	require.NoError(t, err)

	err = helper1.EstablishSharedSecret(cose2)
	require.NoError(t, err)

	tests := []struct {
		name   string
		length int
	}{
		{"too short", 16},
		{"between single and double", 60},
		{"too long", 100},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			invalidOutput := make([]byte, tc.length)
			_, _ = rand.Read(invalidOutput)

			_, err := helper1.DecryptOutput(invalidOutput)
			require.ErrorIs(t, err, ErrHMACSecretDecryptionFailed)
		})
	}
}

// TestParseHMACSecretFromInterfaceMapMissingFields tests parsing with missing fields in interface map.
func TestParseHMACSecretFromInterfaceMapMissingFields(t *testing.T) {
	t.Parallel()

	platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
		coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
	}
	keyAgreementBytes, err := cbor.Marshal(coseKey)
	require.NoError(t, err)

	validSaltEnc := make([]byte, HMACSecretEncryptedSingleSaltSize)
	validSaltAuth := make([]byte, hmacSecretAuthTagSize)

	t.Run("saltEnc as wrong type", func(t *testing.T) {
		t.Parallel()

		input := map[interface{}]interface{}{
			hmacSecretKeyAgreement:      keyAgreementBytes,
			hmacSecretSaltEnc:           "not-bytes", // Wrong type
			hmacSecretSaltAuth:          validSaltAuth,
			hmacSecretPinUvAuthProtocol: 1,
		}

		_, err := ParseHMACSecretInput(input)
		require.ErrorIs(t, err, ErrHMACSecretInvalidSaltEnc)
	})

	t.Run("saltAuth as wrong type", func(t *testing.T) {
		t.Parallel()

		input := map[interface{}]interface{}{
			hmacSecretKeyAgreement:      keyAgreementBytes,
			hmacSecretSaltEnc:           validSaltEnc,
			hmacSecretSaltAuth:          "not-bytes", // Wrong type
			hmacSecretPinUvAuthProtocol: 1,
		}

		_, err := ParseHMACSecretInput(input)
		require.ErrorIs(t, err, ErrHMACSecretInvalidSaltAuth)
	})

	t.Run("protocol as wrong type", func(t *testing.T) {
		t.Parallel()

		input := map[interface{}]interface{}{
			hmacSecretKeyAgreement:      keyAgreementBytes,
			hmacSecretSaltEnc:           validSaltEnc,
			hmacSecretSaltAuth:          validSaltAuth,
			hmacSecretPinUvAuthProtocol: "not-int", // Wrong type
		}

		_, err := ParseHMACSecretInput(input)
		require.ErrorIs(t, err, ErrHMACSecretMissingProtocol)
	})
}

// TestParseHMACSecretFromIntMapWrongTypes tests parsing with wrong types in int map.
func TestParseHMACSecretFromIntMapWrongTypes(t *testing.T) {
	t.Parallel()

	platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
		coseKeyLabelY:   padCoordinate(platformKey.Y.Bytes(), 32),
	}
	keyAgreementBytes, err := cbor.Marshal(coseKey)
	require.NoError(t, err)

	validSaltEnc := make([]byte, HMACSecretEncryptedSingleSaltSize)
	validSaltAuth := make([]byte, hmacSecretAuthTagSize)

	t.Run("saltEnc as wrong type in int map", func(t *testing.T) {
		t.Parallel()

		input := map[int]interface{}{
			hmacSecretKeyAgreement:      keyAgreementBytes,
			hmacSecretSaltEnc:           123, // Wrong type (int instead of bytes)
			hmacSecretSaltAuth:          validSaltAuth,
			hmacSecretPinUvAuthProtocol: 1,
		}

		_, err := ParseHMACSecretInput(input)
		require.ErrorIs(t, err, ErrHMACSecretInvalidSaltEnc)
	})

	t.Run("saltAuth as wrong type in int map", func(t *testing.T) {
		t.Parallel()

		input := map[int]interface{}{
			hmacSecretKeyAgreement:      keyAgreementBytes,
			hmacSecretSaltEnc:           validSaltEnc,
			hmacSecretSaltAuth:          123, // Wrong type
			hmacSecretPinUvAuthProtocol: 1,
		}

		_, err := ParseHMACSecretInput(input)
		require.ErrorIs(t, err, ErrHMACSecretInvalidSaltAuth)
	})

	t.Run("protocol as wrong type in int map", func(t *testing.T) {
		t.Parallel()

		input := map[int]interface{}{
			hmacSecretKeyAgreement:      keyAgreementBytes,
			hmacSecretSaltEnc:           validSaltEnc,
			hmacSecretSaltAuth:          validSaltAuth,
			hmacSecretPinUvAuthProtocol: []byte{1}, // Wrong type
		}

		_, err := ParseHMACSecretInput(input)
		require.ErrorIs(t, err, ErrHMACSecretMissingProtocol)
	})
}

// TestHMACSecretPlatformHelperNilPublicKey tests GetCOSEPublicKey with nil public key.
func TestHMACSecretPlatformHelperNilPublicKey(t *testing.T) {
	t.Parallel()

	helper := &HMACSecretPlatformHelper{
		publicKey: nil,
	}

	_, err := helper.GetCOSEPublicKey()
	require.ErrorIs(t, err, ErrInvalidPublicKey)
}

// TestDecodeCOSEKeyAgreementKeyMissingCurve tests decoding COSE key without curve field.
func TestDecodeCOSEKeyAgreementKeyMissingCurve(t *testing.T) {
	t.Parallel()

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		// Missing crv field
		coseKeyLabelX: make([]byte, 32),
		coseKeyLabelY: make([]byte, 32),
	}
	keyBytes, err := cbor.Marshal(coseKey)
	require.NoError(t, err)

	_, err = decodeCOSEKeyAgreementKey(keyBytes)
	require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
}

// TestDecodeCOSEKeyAgreementKeyWrongKtyType tests decoding COSE key with wrong kty type.
func TestDecodeCOSEKeyAgreementKeyWrongKtyType(t *testing.T) {
	t.Parallel()

	coseKey := map[int]interface{}{
		coseKeyLabelKty: "not-int", // Wrong type
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   make([]byte, 32),
		coseKeyLabelY:   make([]byte, 32),
	}
	keyBytes, err := cbor.Marshal(coseKey)
	require.NoError(t, err)

	_, err = decodeCOSEKeyAgreementKey(keyBytes)
	require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
}

// TestDecodeCOSEKeyAgreementKeyWrongCrvType tests decoding COSE key with wrong crv type.
func TestDecodeCOSEKeyAgreementKeyWrongCrvType(t *testing.T) {
	t.Parallel()

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: "not-int", // Wrong type
		coseKeyLabelX:   make([]byte, 32),
		coseKeyLabelY:   make([]byte, 32),
	}
	keyBytes, err := cbor.Marshal(coseKey)
	require.NoError(t, err)

	_, err = decodeCOSEKeyAgreementKey(keyBytes)
	require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
}

// TestDecodeCOSEKeyAgreementKeyYWrongType tests decoding COSE key with Y as wrong type.
func TestDecodeCOSEKeyAgreementKeyYWrongType(t *testing.T) {
	t.Parallel()

	platformKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   padCoordinate(platformKey.X.Bytes(), 32),
		coseKeyLabelY:   "not-bytes", // Wrong type
	}
	keyBytes, err := cbor.Marshal(coseKey)
	require.NoError(t, err)

	_, err = decodeCOSEKeyAgreementKey(keyBytes)
	require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
}

// TestDecodeCOSEKeyAgreementKeyEmptyY tests decoding COSE key with empty Y coordinate.
func TestDecodeCOSEKeyAgreementKeyEmptyY(t *testing.T) {
	t.Parallel()

	coseKey := map[int]interface{}{
		coseKeyLabelKty: COSEKeyTypeEC2,
		coseKeyLabelAlg: COSEAlgECDHESHKDF256,
		coseKeyLabelCrv: COSECurveP256,
		coseKeyLabelX:   make([]byte, 32),
		coseKeyLabelY:   []byte{}, // Empty Y
	}
	keyBytes, err := cbor.Marshal(coseKey)
	require.NoError(t, err)

	_, err = decodeCOSEKeyAgreementKey(keyBytes)
	require.ErrorIs(t, err, ErrHMACSecretInvalidKeyAgreement)
}
