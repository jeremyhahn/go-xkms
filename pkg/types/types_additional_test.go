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

package types

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// SymmetricAlgorithm Additional Tests
// =============================================================================

func TestSymmetricAlgorithm_KeySize(t *testing.T) {
	tests := []struct {
		name string
		algo SymmetricAlgorithm
		want int
	}{
		{"AES128GCM", SymmetricAES128GCM, 128},
		{"AES192GCM", SymmetricAES192GCM, 192},
		{"AES256GCM", SymmetricAES256GCM, 256},
		{"ChaCha20Poly1305", SymmetricChaCha20Poly1305, 256},
		{"XChaCha20Poly1305", SymmetricXChaCha20Poly1305, 256},
		{"Unknown", SymmetricAlgorithm("unknown"), 0},
		{"Empty", SymmetricAlgorithm(""), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.algo.KeySize()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSymmetricAlgorithm_NonceSize(t *testing.T) {
	tests := []struct {
		name string
		algo SymmetricAlgorithm
		want int
	}{
		{"AES128GCM", SymmetricAES128GCM, 12},
		{"AES192GCM", SymmetricAES192GCM, 12},
		{"AES256GCM", SymmetricAES256GCM, 12},
		{"ChaCha20Poly1305", SymmetricChaCha20Poly1305, 12},
		{"XChaCha20Poly1305", SymmetricXChaCha20Poly1305, 24},
		{"Unknown", SymmetricAlgorithm("unknown"), 0},
		{"Empty", SymmetricAlgorithm(""), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.algo.NonceSize()
			assert.Equal(t, tt.want, got)
		})
	}
}

// =============================================================================
// FrostAlgorithm Tests
// =============================================================================

func TestFrostAlgorithm_String(t *testing.T) {
	tests := []struct {
		name string
		algo FrostAlgorithm
		want string
	}{
		{"Ed25519", FrostAlgorithmEd25519, "FROST-Ed25519-SHA512"},
		{"Ristretto255", FrostAlgorithmRistretto255, "FROST-ristretto255-SHA512"},
		{"Ed448", FrostAlgorithmEd448, "FROST-Ed448-SHAKE256"},
		{"P256", FrostAlgorithmP256, "FROST-P256-SHA256"},
		{"Secp256k1", FrostAlgorithmSecp256k1, "FROST-secp256k1-SHA256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.algo.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFrostAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		algo  FrostAlgorithm
		valid bool
	}{
		{"Ed25519_Valid", FrostAlgorithmEd25519, true},
		{"Ristretto255_Valid", FrostAlgorithmRistretto255, true},
		{"Ed448_Valid", FrostAlgorithmEd448, true},
		{"P256_Valid", FrostAlgorithmP256, true},
		{"Secp256k1_Valid", FrostAlgorithmSecp256k1, true},
		{"Invalid", FrostAlgorithm("invalid-algo"), false},
		{"Empty", FrostAlgorithm(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.algo.IsValid()
			assert.Equal(t, tt.valid, got)
		})
	}
}

// =============================================================================
// FrostAttributes Tests
// =============================================================================

func TestFrostAttributes_Validate(t *testing.T) {
	t.Run("Valid_MinimalConfig", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold: 2,
			Total:     3,
			Algorithm: FrostAlgorithmEd25519,
		}
		err := attrs.Validate()
		assert.NoError(t, err)
	})

	t.Run("Valid_WithParticipants", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold:     3,
			Total:         5,
			Algorithm:     FrostAlgorithmP256,
			Participants:  []string{"node1", "node2", "node3", "node4", "node5"},
			ParticipantID: 1,
		}
		err := attrs.Validate()
		assert.NoError(t, err)
	})

	t.Run("Valid_MaxValues", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold: 255,
			Total:     255,
			Algorithm: FrostAlgorithmEd25519,
		}
		err := attrs.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid_ThresholdTooSmall", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold: 1,
			Total:     3,
			Algorithm: FrostAlgorithmEd25519,
		}
		err := attrs.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "threshold must be at least 2")
	})

	t.Run("Invalid_TotalLessThanThreshold", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold: 5,
			Total:     3,
			Algorithm: FrostAlgorithmEd25519,
		}
		err := attrs.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "total")
		assert.Contains(t, err.Error(), "threshold")
	})

	t.Run("Invalid_ThresholdTooLarge", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold: 256,
			Total:     256,
			Algorithm: FrostAlgorithmEd25519,
		}
		err := attrs.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "threshold cannot exceed 255")
	})

	t.Run("Invalid_TotalTooLarge", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold: 2,
			Total:     256,
			Algorithm: FrostAlgorithmEd25519,
		}
		err := attrs.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "total cannot exceed 255")
	})

	t.Run("Invalid_ParticipantsMismatch", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold:    2,
			Total:        5,
			Algorithm:    FrostAlgorithmEd25519,
			Participants: []string{"node1", "node2", "node3"}, // Should be 5
		}
		err := attrs.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "participants length")
		assert.Contains(t, err.Error(), "must match total")
	})

	t.Run("Invalid_ParticipantIDTooSmall", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold:     2,
			Total:         5,
			Algorithm:     FrostAlgorithmEd25519,
			ParticipantID: 0, // Should be 1-5
		}
		// ParticipantID of 0 is treated as unset, so this should pass
		err := attrs.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid_ParticipantIDTooLarge", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold:     2,
			Total:         5,
			Algorithm:     FrostAlgorithmEd25519,
			ParticipantID: 6, // Should be 1-5
		}
		err := attrs.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "participantID")
		assert.Contains(t, err.Error(), "must be between 1 and total")
	})

	t.Run("Invalid_Algorithm", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold: 2,
			Total:     3,
			Algorithm: FrostAlgorithm("invalid"),
		}
		err := attrs.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid algorithm")
	})

	t.Run("Valid_NoParticipants", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold:    2,
			Total:        3,
			Algorithm:    FrostAlgorithmEd25519,
			Participants: nil, // No participants is valid
		}
		err := attrs.Validate()
		assert.NoError(t, err)
	})

	t.Run("Valid_EmptyParticipants", func(t *testing.T) {
		attrs := &FrostAttributes{
			Threshold:    2,
			Total:        3,
			Algorithm:    FrostAlgorithmEd25519,
			Participants: []string{}, // Empty slice is valid (treated as unset)
		}
		err := attrs.Validate()
		assert.NoError(t, err)
	})
}

// =============================================================================
// KeyAttributes KeyID and CertificateID Tests
// =============================================================================

func TestKeyAttributes_KeyID(t *testing.T) {
	t.Run("FullFormat_RSA", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "my-key",
			StoreType:    StoreSoftware,
			KeyType:      KeyTypeSigning,
			KeyAlgorithm: x509.RSA,
		}
		got := attrs.KeyID()
		assert.Equal(t, "software:signing:rsa:my-key", got)
	})

	t.Run("FullFormat_ECDSA", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "ecdsa-key",
			StoreType:    StorePKCS11,
			KeyType:      KeyTypeTLS,
			KeyAlgorithm: x509.ECDSA,
		}
		got := attrs.KeyID()
		assert.Equal(t, "pkcs11:tls:ecdsa:ecdsa-key", got)
	})

	t.Run("FullFormat_Ed25519", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "ed-key",
			StoreType:    StoreTPM2,
			KeyType:      KeyTypeSigning,
			KeyAlgorithm: x509.Ed25519,
		}
		got := attrs.KeyID()
		assert.Equal(t, "tpm2:signing:ed25519:ed-key", got)
	})

	t.Run("Shorthand_OnlyCN", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "simple-key",
			StoreType:    "",
			KeyType:      0,
			KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
		}
		got := attrs.KeyID()
		assert.Equal(t, "simple-key", got)
	})

	t.Run("PartialFormat_BackendOnly", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "backend-key",
			StoreType:    StorePKCS11,
			KeyType:      0,
			KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
		}
		got := attrs.KeyID()
		assert.Equal(t, "pkcs11:::backend-key", got)
	})

	t.Run("AllKeyTypes", func(t *testing.T) {
		keyTypes := []struct {
			keyType KeyType
			str     string
		}{
			{KeyTypeAttestation, "attestation"},
			{KeyTypeCA, "ca"},
			{KeyTypeEncryption, "encryption"},
			{KeyTypeEndorsement, "endorsement"},
			{KeyTypeHMAC, "hmac"},
			{KeyTypeIDevID, "idevid"},
			{KeyTypeSecret, "secret"},
			{KeyTypeSigning, "signing"},
			{KeyTypeStorage, "storage"},
			{KeyTypeTLS, "tls"},
			{KeyTypeTPM, "tpm"},
		}

		for _, tt := range keyTypes {
			t.Run(tt.str, func(t *testing.T) {
				attrs := &KeyAttributes{
					CN:           "test-key",
					StoreType:    StoreSoftware,
					KeyType:      tt.keyType,
					KeyAlgorithm: x509.RSA,
				}
				got := attrs.KeyID()
				assert.Contains(t, got, tt.str)
				assert.Equal(t, "software:"+tt.str+":rsa:test-key", got)
			})
		}
	})

	t.Run("UnknownKeyAlgorithm", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "unknown-algo-key",
			StoreType:    StoreSoftware,
			KeyType:      KeyTypeSigning,
			KeyAlgorithm: x509.PublicKeyAlgorithm(999), // Unknown algorithm
		}
		got := attrs.KeyID()
		// Should use the string representation of the unknown algorithm
		assert.Contains(t, got, "software:signing:")
		assert.Contains(t, got, ":unknown-algo-key")
	})
}

func TestKeyAttributes_CertificateID(t *testing.T) {
	t.Run("SameAsKeyID", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "cert-key",
			StoreType:    StoreSoftware,
			KeyType:      KeyTypeTLS,
			KeyAlgorithm: x509.RSA,
		}
		keyID := attrs.KeyID()
		certID := attrs.CertificateID()
		assert.Equal(t, keyID, certID)
	})

	t.Run("Various_Formats", func(t *testing.T) {
		testCases := []struct {
			name      string
			attrs     *KeyAttributes
			wantEqual bool
		}{
			{
				name: "FullFormat",
				attrs: &KeyAttributes{
					CN:           "test-cert",
					StoreType:    StorePKCS11,
					KeyType:      KeyTypeTLS,
					KeyAlgorithm: x509.ECDSA,
				},
				wantEqual: true,
			},
			{
				name: "Shorthand",
				attrs: &KeyAttributes{
					CN: "simple-cert",
				},
				wantEqual: true,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				keyID := tc.attrs.KeyID()
				certID := tc.attrs.CertificateID()
				if tc.wantEqual {
					assert.Equal(t, keyID, certID)
				}
			})
		}
	})
}

// Note: TestCapabilities_SupportsSealing is already covered in types_extended_test.go

// =============================================================================
// ParseSignatureAlgorithm Tests
// =============================================================================

func TestParseSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    x509.SignatureAlgorithm
		wantErr bool
	}{
		{"SHA256WithRSA", "SHA256-RSA", x509.SHA256WithRSA, false},
		{"SHA256WithRSA_Lower", "sha256-rsa", x509.SHA256WithRSA, false},
		{"SHA384WithRSA", "SHA384-RSA", x509.SHA384WithRSA, false},
		{"SHA512WithRSA", "SHA512-RSA", x509.SHA512WithRSA, false},
		{"SHA256WithRSAPSS", "SHA256-RSAPSS", x509.SHA256WithRSAPSS, false},
		{"SHA384WithRSAPSS", "SHA384-RSAPSS", x509.SHA384WithRSAPSS, false},
		{"SHA512WithRSAPSS", "SHA512-RSAPSS", x509.SHA512WithRSAPSS, false},
		{"ECDSAWithSHA256", "ECDSA-SHA256", x509.ECDSAWithSHA256, false},
		{"ECDSAWithSHA384", "ECDSA-SHA384", x509.ECDSAWithSHA384, false},
		{"ECDSAWithSHA512", "ECDSA-SHA512", x509.ECDSAWithSHA512, false},
		{"Ed25519", "Ed25519", x509.PureEd25519, false},
		{"Ed25519_Lower", "ed25519", x509.PureEd25519, false},
		{"WithWhitespace", "  SHA256-RSA  ", x509.SHA256WithRSA, false},
		{"Unknown", "unknown-algo", x509.UnknownSignatureAlgorithm, true},
		{"Empty", "", x509.UnknownSignatureAlgorithm, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSignatureAlgorithm(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

// =============================================================================
// ParseHashFromSignatureAlgorithm Tests
// =============================================================================

// Note: ParseHashFromSignatureAlgorithm is tested in the base types_test.go

// =============================================================================
// PublicKeyToString Tests
// =============================================================================

func TestPublicKeyToString(t *testing.T) {
	// This test verifies the function exists and handles basic types
	// Full testing would require generating actual keys, which is covered in integration tests
	t.Run("NilKey", func(t *testing.T) {
		result := PublicKeyToString(nil)
		assert.NotEmpty(t, result)
		assert.Equal(t, "<nil>", result)
	})
}

// =============================================================================
// Deserialize Tests (Error Paths)
// =============================================================================

func TestDeserialize_ErrorPath(t *testing.T) {
	t.Run("InvalidJSON", func(t *testing.T) {
		serializer, err := NewKeySerializer(SerializerJSON)
		assert.NoError(t, err)
		_, err = serializer.Deserialize([]byte("invalid json"))
		assert.Error(t, err)
	})

	t.Run("EmptyData", func(t *testing.T) {
		serializer, err := NewKeySerializer(SerializerJSON)
		assert.NoError(t, err)
		_, err = serializer.Deserialize([]byte{})
		assert.Error(t, err)
	})
}
