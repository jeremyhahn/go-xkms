// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package authenticator

import (
	"bytes"
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
		err := verifySaltAuth(sharedSecret, saltEnc, correctSaltAuth)
		if err != nil {
			t.Errorf("expected nil error, got: %v", err)
		}
	})

	t.Run("incorrect saltAuth", func(t *testing.T) {
		wrongSaltAuth := make([]byte, 16)
		_, _ = rand.Read(wrongSaltAuth)

		err := verifySaltAuth(sharedSecret, saltEnc, wrongSaltAuth)
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
		_, err := decryptSalts(sharedSecret, make([]byte, 17))
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

	credentialHMACKey := make([]byte, HMACSecretKeySize)
	_, _ = rand.Read(credentialHMACKey)

	salt1 := make([]byte, HMACSecretSaltSize)
	_, _ = rand.Read(salt1)

	saltEnc, _ := platformHelper.EncryptSalts(salt1, nil)
	saltAuth, _ := platformHelper.ComputeSaltAuth(saltEnc)

	input := &HMACSecretInput{
		KeyAgreement:      platformCOSE,
		SaltEnc:           saltEnc,
		SaltAuth:          saltAuth,
		PinUvAuthProtocol: PINProtocolVersion2, // Test V2
	}

	storage := NewMemoryStorage()
	config := DefaultConfig()
	config.Storage = storage
	auth, err := NewAuthenticator(config)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}

	output, err := auth.ProcessHMACSecretWithSharedSecret(input, credentialHMACKey, authHelper.SharedSecret())
	if err != nil {
		t.Fatalf("failed to process hmac-secret with V2: %v", err)
	}

	if output == nil || len(output.Output) == 0 {
		t.Error("expected non-empty output")
	}
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

		encrypted, err := encryptHMACOutputs(sharedSecret, outputs)
		require.NoError(t, err)
		require.NotNil(t, encrypted)
		require.Greater(t, len(encrypted), len(outputs)) // Encrypted is larger due to padding
	})

	t.Run("encrypts double output", func(t *testing.T) {
		sharedSecret := make([]byte, 32)
		_, _ = rand.Read(sharedSecret)

		outputs := make([]byte, HMACSecretOutputSize*2)
		_, _ = rand.Read(outputs)

		encrypted, err := encryptHMACOutputs(sharedSecret, outputs)
		require.NoError(t, err)
		require.NotNil(t, encrypted)
	})
}
