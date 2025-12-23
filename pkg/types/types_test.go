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
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStoreType_String(t *testing.T) {
	tests := []struct {
		name string
		st   StoreType
		want string
	}{
		{"Software", StoreSoftware, "software"},
		{"PKCS11", StorePKCS11, "pkcs11"},
		{"TPM2", StoreTPM2, "tpm2"},
		{"AWSKMS", StoreAWSKMS, "awskms"},
		{"GCPKMS", StoreGCPKMS, "gcpkms"},
		{"AzureKV", StoreAzureKV, "azurekv"},
		{"Vault", StoreVault, "vault"},
		{"Unknown", StoreUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.st.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestStoreType_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		st    StoreType
		valid bool
	}{
		{"Software_Valid", StoreSoftware, true},
		{"PKCS11_Valid", StorePKCS11, true},
		{"TPM2_Valid", StoreTPM2, true},
		{"AWSKMS_Valid", StoreAWSKMS, true},
		{"GCPKMS_Valid", StoreGCPKMS, true},
		{"AzureKV_Valid", StoreAzureKV, true},
		{"Vault_Valid", StoreVault, true},
		{"Unknown_Invalid", StoreUnknown, false},
		{"Custom_Invalid", StoreType("custom"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.st.IsValid()
			assert.Equal(t, tt.valid, got)
		})
	}
}

func TestParseStoreType(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want StoreType
	}{
		{"software", "software", StoreSoftware},
		{"pkcs11", "pkcs11", StorePKCS11},
		{"tpm2", "tpm2", StoreTPM2},
		{"awskms", "awskms", StoreAWSKMS},
		{"gcpkms", "gcpkms", StoreGCPKMS},
		{"azurekv", "azurekv", StoreAzureKV},
		{"vault", "vault", StoreVault},
		{"uppercase", "SOFTWARE", StoreSoftware},
		{"mixed", "Tpm2", StoreTPM2},
		{"unknown", "invalid", StoreUnknown},
		{"empty", "", StoreUnknown},
		{"whitespace", "  software  ", StoreSoftware},
		{"pkcs8_no_longer_valid", "pkcs8", StoreUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseStoreType(tt.s)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKeyType_String(t *testing.T) {
	tests := []struct {
		name string
		kt   KeyType
		want string
	}{
		{"Attestation", KeyTypeAttestation, "ATTESTATION"},
		{"CA", KeyTypeCA, "CA"},
		{"Encryption", KeyTypeEncryption, "ENCRYPTION"},
		{"Endorsement", KeyTypeEndorsement, "ENDORSEMENT"},
		{"HMAC", KeyTypeHMAC, "HMAC"},
		{"IDevID", KeyTypeIDevID, "IDevID"},
		{"LDevID", KeyTypeLDevID, "LDevID"},
		{"Secret", KeyTypeSecret, "SECRET"},
		{"Signing", KeyTypeSigning, "SIGNING"},
		{"Storage", KeyTypeStorage, "STORAGE"},
		{"TLS", KeyTypeTLS, "TLS"},
		{"TPM", KeyTypeTPM, "TPM"},
		{"Unknown", KeyType(255), "UNKNOWN(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.kt.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSymmetricAlgorithm_String(t *testing.T) {
	tests := []struct {
		name string
		sa   SymmetricAlgorithm
		want string
	}{
		{"AES128GCM", SymmetricAES128GCM, "aes128-gcm"},
		{"AES192GCM", SymmetricAES192GCM, "aes192-gcm"},
		{"AES256GCM", SymmetricAES256GCM, "aes256-gcm"},
		{"ChaCha20", SymmetricChaCha20Poly1305, "chacha20-poly1305"},
		{"XChaCha20", SymmetricXChaCha20Poly1305, "xchacha20-poly1305"},
		{"Unknown", SymmetricAlgorithm("invalid"), "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.sa.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSymmetricAlgorithm_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		sa    SymmetricAlgorithm
		valid bool
	}{
		{"AES128_Valid", SymmetricAES128GCM, true},
		{"AES192_Valid", SymmetricAES192GCM, true},
		{"AES256_Valid", SymmetricAES256GCM, true},
		{"ChaCha20_Valid", SymmetricChaCha20Poly1305, true},
		{"XChaCha20_Valid", SymmetricXChaCha20Poly1305, true},
		{"Invalid", SymmetricAlgorithm("invalid"), false},
		{"Empty", SymmetricAlgorithm(""), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.sa.IsValid()
			assert.Equal(t, tt.valid, got)
		})
	}
}

func TestAEADOptions_Validate(t *testing.T) {
	t.Run("Valid_DefaultOptions", func(t *testing.T) {
		opts := DefaultAEADOptions()
		err := opts.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid_NonceSize_TooSmall", func(t *testing.T) {
		opts := &AEADOptions{
			NonceSize:          4, // Too small
			BytesTracking:      true,
			BytesTrackingLimit: 1000,
		}
		err := opts.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "nonce size must be at least 12 bytes")
	})

	t.Run("Valid_ZeroNonceSize_UsesDefault", func(t *testing.T) {
		opts := &AEADOptions{
			NonceSize:          0, // Should use default
			BytesTracking:      true,
			BytesTrackingLimit: 1000,
		}
		err := opts.Validate()
		assert.NoError(t, err)
		assert.Equal(t, 12, opts.NonceSize) // Default nonce size
	})

	t.Run("Valid_ZeroBytesLimit_SetsDefault", func(t *testing.T) {
		opts := &AEADOptions{
			NonceSize:          12,
			BytesTracking:      true,
			BytesTrackingLimit: 0, // Should set default
		}
		err := opts.Validate()
		assert.NoError(t, err)
		assert.Equal(t, int64(350*1024*1024*1024), opts.BytesTrackingLimit) // 350 GB
	})

	t.Run("Valid_NonceSizeExactly12", func(t *testing.T) {
		opts := &AEADOptions{
			NonceSize:          12,
			BytesTracking:      true,
			BytesTrackingLimit: 1000,
		}
		err := opts.Validate()
		assert.NoError(t, err)
	})

	t.Run("Valid_LargeNonceSize", func(t *testing.T) {
		opts := &AEADOptions{
			NonceSize:          16,
			BytesTracking:      true,
			BytesTrackingLimit: 1000,
		}
		err := opts.Validate()
		assert.NoError(t, err)
	})
}

func TestDefaultAEADOptions(t *testing.T) {
	opts := DefaultAEADOptions()
	require.NotNil(t, opts)
	assert.Equal(t, 12, opts.NonceSize)
	assert.Equal(t, int64(350*1024*1024*1024), opts.BytesTrackingLimit) // 350 GB
	assert.True(t, opts.NonceTracking)
	assert.True(t, opts.BytesTracking)
}

func TestKeyAttributes_String(t *testing.T) {
	attrs := &KeyAttributes{
		CN:           "test-key",
		KeyType:      KeyTypeTLS,
		StoreType:    StoreSoftware,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
		RSAAttributes: &RSAAttributes{
			KeySize: 2048,
		},
	}

	str := attrs.String()
	assert.Contains(t, str, "test-key")
	assert.Contains(t, str, "TLS")
	assert.Contains(t, str, "software")
	assert.Contains(t, str, "2048")
}

func TestKeyAttributes_Validate(t *testing.T) {
	t.Run("Valid_RSA_Attributes", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "test-rsa",
			KeyType:      KeyTypeTLS,
			StoreType:    StoreSoftware,
			KeyAlgorithm: x509.RSA,
			RSAAttributes: &RSAAttributes{
				KeySize: 2048,
			},
			Hash: crypto.SHA256,
		}
		err := attrs.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid_EmptyCN", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "",
			KeyType:      KeyTypeTLS,
			StoreType:    StoreSoftware,
			KeyAlgorithm: x509.RSA,
		}
		err := attrs.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "common name")
	})

	t.Run("Invalid_EmptyStoreType", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "test",
			KeyType:      KeyTypeTLS,
			StoreType:    "",
			KeyAlgorithm: x509.RSA,
		}
		err := attrs.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "store type")
	})

	t.Run("Valid_ECDSA_Attributes", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "test-ecdsa",
			KeyType:      KeyTypeTLS,
			StoreType:    StoreSoftware,
			KeyAlgorithm: x509.ECDSA,
			ECCAttributes: &ECCAttributes{
				Curve: elliptic.P256(),
			},
			Hash: crypto.SHA256,
		}
		err := attrs.Validate()
		assert.NoError(t, err)
	})

	t.Run("Valid_Ed25519_Attributes", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "test-ed25519",
			KeyType:      KeyTypeSigning,
			StoreType:    StoreSoftware,
			KeyAlgorithm: x509.Ed25519,
		}
		err := attrs.Validate()
		assert.NoError(t, err)
	})

	t.Run("Valid_Symmetric_AES", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:                 "test-aes",
			KeyType:            KeyTypeSecret,
			StoreType:          StoreSoftware,
			SymmetricAlgorithm: SymmetricAES256GCM,
		}
		err := attrs.Validate()
		assert.NoError(t, err)
	})

	t.Run("Valid_Symmetric_ChaCha20", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:                 "test-chacha",
			KeyType:            KeyTypeSecret,
			StoreType:          StoreSoftware,
			SymmetricAlgorithm: SymmetricChaCha20Poly1305,
		}
		err := attrs.Validate()
		assert.NoError(t, err)
	})


	t.Run("Invalid_NoAlgorithm", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:        "test-key",
			KeyType:   KeyTypeTLS,
			StoreType: StoreSoftware,
			// No KeyAlgorithm or SymmetricAlgorithm
		}
		err := attrs.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "either KeyAlgorithm, SymmetricAlgorithm, QuantumAttributes, or FrostAttributes must be set")
	})
}

func TestKeyAttributes_IsSymmetric(t *testing.T) {
	t.Run("Symmetric_WithAlgorithm", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:                 "symmetric-key",
			KeyType:            KeyTypeSecret,
			SymmetricAlgorithm: SymmetricAES256GCM,
		}
		assert.True(t, attrs.IsSymmetric())
	})

	t.Run("Asymmetric_RSA", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "rsa-key",
			KeyType:      KeyTypeTLS,
			KeyAlgorithm: x509.RSA,
		}
		assert.False(t, attrs.IsSymmetric())
	})

	t.Run("Asymmetric_ECDSA", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "ecdsa-key",
			KeyType:      KeyTypeTLS,
			KeyAlgorithm: x509.ECDSA,
		}
		assert.False(t, attrs.IsSymmetric())
	})

	t.Run("NoAlgorithm", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:      "no-algo-key",
			KeyType: KeyTypeTLS,
		}
		assert.False(t, attrs.IsSymmetric())
	})
}

func TestKeyAttributes_ID(t *testing.T) {
	t.Run("Asymmetric_NoPartition", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "test-key",
			StoreType:    StoreSoftware,
			KeyType:      KeyTypeTLS,
			KeyAlgorithm: x509.RSA,
		}
		id := attrs.ID()
		assert.Equal(t, "software:tls:test-key:rsa", id)
	})

	t.Run("Asymmetric_WithPartition", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:           "test-key",
			StoreType:    StoreSoftware,
			KeyType:      KeyTypeTLS,
			KeyAlgorithm: x509.RSA,
			Partition:    PartitionTLS,
		}
		id := attrs.ID()
		assert.Equal(t, "issued:software:tls:test-key:rsa", id)
	})

	t.Run("Symmetric_NoPartition", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:                 "test-aes-key",
			StoreType:          StoreSoftware,
			KeyType:            KeyTypeSecret,
			SymmetricAlgorithm: SymmetricAES256GCM,
		}
		id := attrs.ID()
		assert.Equal(t, "software:secret:test-aes-key:aes256-gcm", id)
	})

	t.Run("Symmetric_WithPartition", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:                 "test-aes-key",
			StoreType:          StoreSoftware,
			KeyType:            KeyTypeSecret,
			SymmetricAlgorithm: SymmetricAES256GCM,
			Partition:          PartitionSecrets,
		}
		id := attrs.ID()
		assert.Equal(t, "secrets:software:secret:test-aes-key:aes256-gcm", id)
	})

	t.Run("NoAlgorithm", func(t *testing.T) {
		attrs := &KeyAttributes{
			CN:        "test-key",
			StoreType: StoreSoftware,
			KeyType:   KeyTypeTLS,
		}
		id := attrs.ID()
		assert.Equal(t, "software:tls:test-key:unknown", id)
	})
}

func TestCapabilities_SupportsSymmetricEncryption(t *testing.T) {
	caps := Capabilities{
		SymmetricEncryption: true,
	}
	assert.True(t, caps.SupportsSymmetricEncryption())

	caps.SymmetricEncryption = false
	assert.False(t, caps.SupportsSymmetricEncryption())
}

func TestCapabilities_SupportsImportExport(t *testing.T) {
	caps := Capabilities{
		Import: true,
		Export: true,
	}
	assert.True(t, caps.SupportsImportExport())

	caps.Import = false
	caps.Export = true
	assert.False(t, caps.SupportsImportExport())

	caps.Import = true
	caps.Export = false
	assert.False(t, caps.SupportsImportExport())

	caps.Import = false
	caps.Export = false
	assert.False(t, caps.SupportsImportExport())
}

func TestCapabilities_SupportsKeyAgreement(t *testing.T) {
	caps := Capabilities{
		KeyAgreement: true,
	}
	assert.True(t, caps.SupportsKeyAgreement())

	caps.KeyAgreement = false
	assert.False(t, caps.SupportsKeyAgreement())
}

func TestCapabilities_SupportsECIES(t *testing.T) {
	caps := Capabilities{
		ECIES: true,
	}
	assert.True(t, caps.SupportsECIES())

	caps.ECIES = false
	assert.False(t, caps.SupportsECIES())
}

func TestCapabilities_HasKeys(t *testing.T) {
	caps := Capabilities{
		Keys: true,
	}
	assert.True(t, caps.HasKeys())

	caps.Keys = false
	assert.False(t, caps.HasKeys())
}

func TestCapabilities_IsHardwareBacked(t *testing.T) {
	caps := Capabilities{
		HardwareBacked: true,
	}
	assert.True(t, caps.IsHardwareBacked())

	caps.HardwareBacked = false
	assert.False(t, caps.IsHardwareBacked())
}

func TestCapabilities_SupportsSign(t *testing.T) {
	caps := Capabilities{
		Signing: true,
	}
	assert.True(t, caps.SupportsSign())

	caps.Signing = false
	assert.False(t, caps.SupportsSign())
}

func TestCapabilities_SupportsDecrypt(t *testing.T) {
	caps := Capabilities{
		Decryption: true,
	}
	assert.True(t, caps.SupportsDecrypt())

	caps.Decryption = false
	assert.False(t, caps.SupportsDecrypt())
}

func TestCapabilities_SupportsKeyRotation(t *testing.T) {
	caps := Capabilities{
		KeyRotation: true,
	}
	assert.True(t, caps.SupportsKeyRotation())

	caps.KeyRotation = false
	assert.False(t, caps.SupportsKeyRotation())
}

func TestCapabilities_AllCapabilities(t *testing.T) {
	caps := Capabilities{
		Keys:                true,
		HardwareBacked:      true,
		Signing:             true,
		Decryption:          true,
		KeyRotation:         true,
		SymmetricEncryption: true,
		Import:              true,
		Export:              true,
		KeyAgreement:        true,
		ECIES:               true,
	}

	assert.True(t, caps.HasKeys())
	assert.True(t, caps.IsHardwareBacked())
	assert.True(t, caps.SupportsSign())
	assert.True(t, caps.SupportsDecrypt())
	assert.True(t, caps.SupportsKeyRotation())
	assert.True(t, caps.SupportsSymmetricEncryption())
	assert.True(t, caps.SupportsImportExport())
	assert.True(t, caps.SupportsKeyAgreement())
	assert.True(t, caps.SupportsECIES())
}

func TestCapabilities_String(t *testing.T) {
	caps := Capabilities{
		Keys:           true,
		HardwareBacked: true,
		Signing:        true,
		Decryption:     true,
		KeyRotation:    true,
	}

	str := caps.String()
	assert.Contains(t, str, "Keys: true")
	assert.Contains(t, str, "HardwareBacked: true")
	assert.Contains(t, str, "Signing: true")
	assert.Contains(t, str, "Decryption: true")
	assert.Contains(t, str, "KeyRotation: true")
}

func TestNewSoftwareCapabilities(t *testing.T) {
	caps := NewSoftwareCapabilities()
	assert.True(t, caps.Keys)
	assert.False(t, caps.HardwareBacked)
	assert.True(t, caps.Signing)
	assert.True(t, caps.Decryption)
	assert.False(t, caps.KeyRotation)
}

func TestNewHardwareCapabilities(t *testing.T) {
	caps := NewHardwareCapabilities()
	assert.True(t, caps.Keys)
	assert.True(t, caps.HardwareBacked)
	assert.True(t, caps.Signing)
	assert.True(t, caps.Decryption)
	assert.False(t, caps.KeyRotation)
}

func TestNewUnifiedSoftwareCapabilities(t *testing.T) {
	caps := NewUnifiedSoftwareCapabilities()
	assert.True(t, caps.Keys)
	assert.False(t, caps.HardwareBacked)
	assert.True(t, caps.Signing)
	assert.True(t, caps.Decryption)
	assert.True(t, caps.KeyRotation)
	assert.True(t, caps.SymmetricEncryption)
}

func TestPartitions(t *testing.T) {
	assert.NotEmpty(t, Partitions)
	assert.Contains(t, Partitions, PartitionRoot)
	assert.Contains(t, Partitions, PartitionTLS)
	assert.Contains(t, Partitions, PartitionEncryptionKeys)
	assert.Contains(t, Partitions, PartitionSigningKeys)
	assert.Contains(t, Partitions, PartitionHMAC)
	assert.Contains(t, Partitions, PartitionSecrets)
}

func TestRSAAttributes(t *testing.T) {
	attrs := &RSAAttributes{
		KeySize: 2048,
	}
	assert.Equal(t, 2048, attrs.KeySize)
}

func TestECCAttributes(t *testing.T) {
	attrs := &ECCAttributes{
		Curve: elliptic.P256(),
	}
	assert.NotNil(t, attrs.Curve)
	assert.Equal(t, "P-256", attrs.Curve.Params().Name)
}


func TestBackendType(t *testing.T) {
	tests := []struct {
		name string
		bt   BackendType
		want string
	}{
		{"Symmetric", BackendTypeSymmetric, "symmetric"},
		{"Software", BackendTypeSoftware, "software"},
		{"PKCS11", BackendTypePKCS11, "pkcs11"},
		{"TPM2", BackendTypeTPM2, "tpm2"},
		{"AWSKMS", BackendTypeAWSKMS, "awskms"},
		{"GCPKMS", BackendTypeGCPKMS, "gcpkms"},
		{"AzureKV", BackendTypeAzureKV, "azurekv"},
		{"Vault", BackendTypeVault, "vault"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.bt))
		})
	}
}

func TestFSExtension(t *testing.T) {
	tests := []struct {
		name string
		ext  FSExtension
		want string
	}{
		{"Blob", FSExtBlob, ""},
		{"PrivatePKCS8", FSExtPrivatePKCS8, ".key"},
		{"PrivatePKCS8PEM", FSExtPrivatePKCS8PEM, ".key.pem"},
		{"PublicPKCS1", FSExtPublicPKCS1, ".pub"},
		{"PublicPEM", FSExtPublicPEM, ".pub.pem"},
		{"PrivateBlob", FSExtPrivateBlob, ".key.bin"},
		{"PublicBlob", FSExtPublicBlob, ".pub.bin"},
		{"Digest", FSExtDigest, ".digest"},
		{"Signature", FSExtSignature, ".sig"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.ext))
		})
	}
}

func TestPartition(t *testing.T) {
	tests := []struct {
		name string
		part Partition
		want string
	}{
		{"Root", PartitionRoot, ""},
		{"TLS", PartitionTLS, "issued"},
		{"EncryptionKeys", PartitionEncryptionKeys, "crypto"},
		{"SigningKeys", PartitionSigningKeys, "signing"},
		{"HMAC", PartitionHMAC, "hmac"},
		{"Secrets", PartitionSecrets, "secrets"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.part))
		})
	}
}

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestAvailableHashes(t *testing.T) {
	hashes := AvailableHashes()
	require.NotNil(t, hashes)
	assert.NotEmpty(t, hashes)

	// Test a few common hashes
	assert.Equal(t, crypto.SHA256, hashes["SHA-256"])
	assert.Equal(t, crypto.SHA384, hashes["SHA-384"])
	assert.Equal(t, crypto.SHA512, hashes["SHA-512"])
	assert.Equal(t, crypto.SHA1, hashes["SHA-1"])
	assert.Equal(t, crypto.MD5, hashes["MD5"])
	assert.Equal(t, crypto.SHA3_256, hashes["SHA3-256"])
	assert.Equal(t, crypto.BLAKE2b_256, hashes["BLAKE2b-256"])
}

func TestAvailableSignatureAlgorithms(t *testing.T) {
	sigAlgos := AvailableSignatureAlgorithms()
	require.NotNil(t, sigAlgos)
	assert.NotEmpty(t, sigAlgos)

	// Test RSA algorithms
	assert.Equal(t, x509.SHA256WithRSA, sigAlgos["SHA256-RSA"])
	assert.Equal(t, x509.SHA384WithRSA, sigAlgos["SHA384-RSA"])
	assert.Equal(t, x509.SHA512WithRSA, sigAlgos["SHA512-RSA"])

	// Test ECDSA algorithms
	assert.Equal(t, x509.ECDSAWithSHA256, sigAlgos["ECDSA-SHA256"])
	assert.Equal(t, x509.ECDSAWithSHA384, sigAlgos["ECDSA-SHA384"])
	assert.Equal(t, x509.ECDSAWithSHA512, sigAlgos["ECDSA-SHA512"])

	// Test RSA-PSS algorithms
	assert.Equal(t, x509.SHA256WithRSAPSS, sigAlgos["SHA256-RSAPSS"])
	assert.Equal(t, x509.SHA384WithRSAPSS, sigAlgos["SHA384-RSAPSS"])
	assert.Equal(t, x509.SHA512WithRSAPSS, sigAlgos["SHA512-RSAPSS"])

	// Test Ed25519
	assert.Equal(t, x509.PureEd25519, sigAlgos["Ed25519"])
}

func TestSignatureAlgorithmHashes(t *testing.T) {
	hashes := SignatureAlgorithmHashes()
	require.NotNil(t, hashes)
	assert.NotEmpty(t, hashes)

	// Test RSA mappings
	assert.Equal(t, crypto.SHA256, hashes[x509.SHA256WithRSA])
	assert.Equal(t, crypto.SHA384, hashes[x509.SHA384WithRSA])
	assert.Equal(t, crypto.SHA512, hashes[x509.SHA512WithRSA])

	// Test ECDSA mappings
	assert.Equal(t, crypto.SHA256, hashes[x509.ECDSAWithSHA256])
	assert.Equal(t, crypto.SHA384, hashes[x509.ECDSAWithSHA384])
	assert.Equal(t, crypto.SHA512, hashes[x509.ECDSAWithSHA512])

	// Test RSA-PSS mappings
	assert.Equal(t, crypto.SHA256, hashes[x509.SHA256WithRSAPSS])
	assert.Equal(t, crypto.SHA384, hashes[x509.SHA384WithRSAPSS])
	assert.Equal(t, crypto.SHA512, hashes[x509.SHA512WithRSAPSS])

	// Test Ed25519 (no hash)
	assert.Equal(t, crypto.Hash(0), hashes[x509.PureEd25519])
}

func TestAvailableKeyAlgorithms(t *testing.T) {
	keyAlgos := AvailableKeyAlgorithms()
	require.NotNil(t, keyAlgos)
	assert.NotEmpty(t, keyAlgos)

	assert.Equal(t, x509.RSA, keyAlgos["RSA"])
	assert.Equal(t, x509.ECDSA, keyAlgos["ECDSA"])
	assert.Equal(t, x509.Ed25519, keyAlgos["Ed25519"])
}

func TestIsRSAPSS(t *testing.T) {
	tests := []struct {
		name    string
		sigAlgo x509.SignatureAlgorithm
		want    bool
	}{
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, true},
		{"SHA384WithRSAPSS", x509.SHA384WithRSAPSS, true},
		{"SHA512WithRSAPSS", x509.SHA512WithRSAPSS, true},
		{"SHA256WithRSA", x509.SHA256WithRSA, false},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, false},
		{"PureEd25519", x509.PureEd25519, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsRSAPSS(tt.sigAlgo)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsECDSA(t *testing.T) {
	tests := []struct {
		name    string
		sigAlgo x509.SignatureAlgorithm
		want    bool
	}{
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, true},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, true},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, true},
		{"SHA256WithRSA", x509.SHA256WithRSA, false},
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, false},
		{"PureEd25519", x509.PureEd25519, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsECDSA(tt.sigAlgo)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKeyAlgorithmFromSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		sigAlgo x509.SignatureAlgorithm
		want    x509.PublicKeyAlgorithm
		wantErr bool
	}{
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, x509.ECDSA, false},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, x509.ECDSA, false},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, x509.ECDSA, false},
		{"SHA256WithRSA", x509.SHA256WithRSA, x509.RSA, false},
		{"SHA384WithRSA", x509.SHA384WithRSA, x509.RSA, false},
		{"SHA512WithRSA", x509.SHA512WithRSA, x509.RSA, false},
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, x509.RSA, false},
		{"SHA384WithRSAPSS", x509.SHA384WithRSAPSS, x509.RSA, false},
		{"SHA512WithRSAPSS", x509.SHA512WithRSAPSS, x509.RSA, false},
		{"PureEd25519", x509.PureEd25519, x509.Ed25519, false},
		{"UnknownSigAlgo", x509.UnknownSignatureAlgorithm, 0, true},
		{"MD5WithRSA", x509.MD5WithRSA, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := KeyAlgorithmFromSignatureAlgorithm(tt.sigAlgo)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid signature algorithm")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestFSHashName(t *testing.T) {
	tests := []struct {
		name string
		hash crypto.Hash
		want string
	}{
		{"SHA256", crypto.SHA256, "sha256"},
		{"SHA384", crypto.SHA384, "sha384"},
		{"SHA512", crypto.SHA512, "sha512"},
		{"SHA3_256", crypto.SHA3_256, "sha3256"},
		{"BLAKE2b_256", crypto.BLAKE2b_256, "blake2b256"},
		{"MD5SHA1", crypto.MD5SHA1, "md5+sha1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FSHashName(tt.hash)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFSExtKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		algo x509.PublicKeyAlgorithm
		want string
	}{
		{"RSA", x509.RSA, ".rsa"},
		{"ECDSA", x509.ECDSA, ".ecdsa"},
		{"Ed25519", x509.Ed25519, ".ed25519"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FSExtKeyAlgorithm(tt.algo)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKeyFileExtension(t *testing.T) {
	hmacKeyType := KeyTypeHMAC

	tests := []struct {
		name      string
		algo      x509.PublicKeyAlgorithm
		extension FSExtension
		keyType   *KeyType
		want      FSExtension
	}{
		{"RSA_PrivateKey", x509.RSA, FSExtPrivatePKCS8, nil, ".rsa.key"},
		{"ECDSA_PublicKey", x509.ECDSA, FSExtPublicPKCS1, nil, ".ecdsa.pub"},
		{"Ed25519_PEM", x509.Ed25519, FSExtPrivatePKCS8PEM, nil, ".ed25519.key.pem"},
		{"HMAC_Key", x509.RSA, FSExtPrivatePKCS8, &hmacKeyType, ".hmac.key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := KeyFileExtension(tt.algo, tt.extension, tt.keyType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestHashFileExtension(t *testing.T) {
	tests := []struct {
		name string
		hash crypto.Hash
		want string
	}{
		{"SHA256", crypto.SHA256, ".sha256"},
		{"SHA384", crypto.SHA384, ".sha384"},
		{"SHA512", crypto.SHA512, ".sha512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashFileExtension(tt.hash)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDigest(t *testing.T) {
	testData := []byte("Hello, World!")

	t.Run("ValidHash_SHA256", func(t *testing.T) {
		digest, err := Digest(crypto.SHA256, testData)
		assert.NoError(t, err)
		assert.NotNil(t, digest)
		assert.Equal(t, 32, len(digest)) // SHA256 produces 32 bytes
	})

	t.Run("ValidHash_SHA512", func(t *testing.T) {
		digest, err := Digest(crypto.SHA512, testData)
		assert.NoError(t, err)
		assert.NotNil(t, digest)
		assert.Equal(t, 64, len(digest)) // SHA512 produces 64 bytes
	})

	t.Run("ValidHash_SHA384", func(t *testing.T) {
		digest, err := Digest(crypto.SHA384, testData)
		assert.NoError(t, err)
		assert.NotNil(t, digest)
		assert.Equal(t, 48, len(digest)) // SHA384 produces 48 bytes
	})

	t.Run("InvalidHash_NotAvailable", func(t *testing.T) {
		// Use an unavailable hash
		_, err := Digest(crypto.Hash(999), testData)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "hash function not available")
	})

	t.Run("EmptyData", func(t *testing.T) {
		digest, err := Digest(crypto.SHA256, []byte{})
		assert.NoError(t, err)
		assert.NotNil(t, digest)
		assert.Equal(t, 32, len(digest))
	})
}

func TestParseCurve(t *testing.T) {
	tests := []struct {
		name      string
		curveName string
		want      elliptic.Curve
		wantErr   bool
	}{
		{"P224_Standard", "P-224", elliptic.P224(), false},
		{"P224_NoHyphen", "P224", elliptic.P224(), false},
		{"P224_LongName", "secp224r1", elliptic.P224(), false},
		{"P256_Standard", "P-256", elliptic.P256(), false},
		{"P256_NoHyphen", "P256", elliptic.P256(), false},
		{"P256_SECP", "secp256r1", elliptic.P256(), false},
		{"P256_Prime", "prime256v1", elliptic.P256(), false},
		{"P384_Standard", "P-384", elliptic.P384(), false},
		{"P384_NoHyphen", "P384", elliptic.P384(), false},
		{"P384_SECP", "secp384r1", elliptic.P384(), false},
		{"P521_Standard", "P-521", elliptic.P521(), false},
		{"P521_NoHyphen", "P521", elliptic.P521(), false},
		{"P521_SECP", "secp521r1", elliptic.P521(), false},
		{"LowercaseP256", "p-256", elliptic.P256(), false},
		{"WithWhitespace", "  P-256  ", elliptic.P256(), false},
		{"Invalid", "P-192", nil, true},
		{"Empty", "", nil, true},
		{"Unknown", "invalid", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCurve(tt.curveName)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, tt.want.Params().Name, got.Params().Name)
			}
		})
	}
}

func TestParseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		want    x509.PublicKeyAlgorithm
		wantErr bool
	}{
		{"RSA", "rsa", x509.RSA, false},
		{"RSA_2048", "rsa-2048", x509.RSA, false},
		{"RSA_4096", "rsa-4096", x509.RSA, false},
		{"RSA_Uppercase", "RSA", x509.RSA, false},
		{"ECDSA", "ecdsa", x509.ECDSA, false},
		{"EC", "ec", x509.ECDSA, false},
		{"ECC", "ecc", x509.ECDSA, false},
		{"Ed25519", "ed25519", x509.Ed25519, false},
		{"Ed25519_Mixed", "Ed25519", x509.Ed25519, false},
		{"WithWhitespace", "  rsa  ", x509.RSA, false},
		{"Unknown", "unknown", x509.UnknownPublicKeyAlgorithm, true},
		{"Empty", "", x509.UnknownPublicKeyAlgorithm, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKeyAlgorithm(tt.s)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseKeyType(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want KeyType
	}{
		{"Attestation", "ATTESTATION", KeyTypeAttestation},
		{"CA", "CA", KeyTypeCA},
		{"Encryption", "ENCRYPTION", KeyTypeEncryption},
		{"Endorsement", "ENDORSEMENT", KeyTypeEndorsement},
		{"HMAC", "HMAC", KeyTypeHMAC},
		{"IDevID", "IDEVID", KeyTypeIDevID},
		{"LDevID", "LDEVID", KeyTypeLDevID},
		{"Secret", "SECRET", KeyTypeSecret},
		{"Signing", "SIGNING", KeyTypeSigning},
		{"Storage", "STORAGE", KeyTypeStorage},
		{"TLS", "TLS", KeyTypeTLS},
		{"TPM", "TPM", KeyTypeTPM},
		{"Lowercase", "tls", KeyTypeTLS},
		{"WithWhitespace", "  TLS  ", KeyTypeTLS},
		{"Unknown", "unknown", KeyType(0)},
		{"Empty", "", KeyType(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseKeyType(tt.s)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseHash(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want crypto.Hash
	}{
		{"MD4", "MD4", crypto.MD4},
		{"MD5", "MD5", crypto.MD5},
		{"SHA1", "SHA1", crypto.SHA1},
		{"SHA224", "SHA224", crypto.SHA224},
		{"SHA256", "SHA256", crypto.SHA256},
		{"SHA384", "SHA384", crypto.SHA384},
		{"SHA512", "SHA512", crypto.SHA512},
		{"MD5SHA1", "MD5SHA1", crypto.MD5SHA1},
		{"RIPEMD160", "RIPEMD160", crypto.RIPEMD160},
		{"SHA3_224", "SHA3_224", crypto.SHA3_224},
		{"SHA3_256", "SHA3_256", crypto.SHA3_256},
		{"SHA3_384", "SHA3_384", crypto.SHA3_384},
		{"SHA3_512", "SHA3_512", crypto.SHA3_512},
		{"SHA512_224", "SHA512_224", crypto.SHA512_224},
		{"SHA512_256", "SHA512_256", crypto.SHA512_256},
		{"BLAKE2s_256", "BLAKE2s_256", crypto.BLAKE2s_256},
		{"BLAKE2b_256", "BLAKE2b_256", crypto.BLAKE2b_256},
		{"BLAKE2b_384", "BLAKE2b_384", crypto.BLAKE2b_384},
		{"BLAKE2b_512", "BLAKE2b_512", crypto.BLAKE2b_512},
		{"WithHyphen", "SHA3-256", crypto.SHA3_256},
		{"Lowercase", "sha256", crypto.SHA256},
		{"WithWhitespace", "  SHA256  ", crypto.SHA256},
		{"Unknown", "unknown", crypto.Hash(0)},
		{"Empty", "", crypto.Hash(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseHash(tt.s)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCurveName(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		want  string
	}{
		{"P224", elliptic.P224(), "P-224"},
		{"P256", elliptic.P256(), "P-256"},
		{"P384", elliptic.P384(), "P-384"},
		{"P521", elliptic.P521(), "P-521"},
		{"Nil", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CurveName(tt.curve)
			assert.Equal(t, tt.want, got)
		})
	}
}

// =============================================================================
// KeyAttributes Additional Coverage Tests
// =============================================================================

func TestKeyAttributes_String_WithECCAttributes(t *testing.T) {
	attrs := &KeyAttributes{
		CN:           "test-ecc-key",
		KeyType:      KeyTypeTLS,
		StoreType:    StoreSoftware,
		KeyAlgorithm: x509.ECDSA,
		Hash:         crypto.SHA256,
		ECCAttributes: &ECCAttributes{
			Curve: elliptic.P384(),
		},
	}

	str := attrs.String()
	assert.Contains(t, str, "test-ecc-key")
	assert.Contains(t, str, "TLS")
	assert.Contains(t, str, "P-384")
	assert.Contains(t, str, "ECC Attributes")
}

func TestKeyAttributes_String_WithX25519Attributes(t *testing.T) {
	attrs := &KeyAttributes{
		CN:               "test-x25519-key",
		KeyType:          KeyTypeEncryption,
		StoreType:        StoreSoftware,
		Hash:             crypto.SHA256,
		X25519Attributes: &X25519Attributes{},
	}

	str := attrs.String()
	assert.Contains(t, str, "test-x25519-key")
	assert.Contains(t, str, "ENCRYPTION")
	assert.Contains(t, str, "X25519")
	assert.Contains(t, str, "Curve25519")
}

func TestKeyAttributes_Validate_X25519(t *testing.T) {
	attrs := &KeyAttributes{
		CN:               "test-x25519",
		KeyType:          KeyTypeEncryption,
		StoreType:        StoreSoftware,
		X25519Attributes: &X25519Attributes{},
	}
	err := attrs.Validate()
	assert.NoError(t, err)
}

func TestKeyAttributes_Validate_MissingKeyType(t *testing.T) {
	attrs := &KeyAttributes{
		CN:           "test-key",
		StoreType:    StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &RSAAttributes{
			KeySize: 2048,
		},
	}
	err := attrs.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key type is required")
}

func TestKeyAttributes_Validate_RSA_TooSmall(t *testing.T) {
	attrs := &KeyAttributes{
		CN:           "test-rsa-small",
		KeyType:      KeyTypeTLS,
		StoreType:    StoreSoftware,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &RSAAttributes{
			KeySize: 1024, // Too small
		},
	}
	err := attrs.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "RSA key size must be at least 2048")
}

func TestKeyAttributes_Validate_RSA_MissingAttributes(t *testing.T) {
	attrs := &KeyAttributes{
		CN:           "test-rsa",
		KeyType:      KeyTypeTLS,
		StoreType:    StoreSoftware,
		KeyAlgorithm: x509.RSA,
		// Missing RSAAttributes
	}
	err := attrs.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "RSA attributes are required")
}

func TestKeyAttributes_Validate_ECDSA_MissingAttributes(t *testing.T) {
	attrs := &KeyAttributes{
		CN:           "test-ecdsa",
		KeyType:      KeyTypeTLS,
		StoreType:    StoreSoftware,
		KeyAlgorithm: x509.ECDSA,
		// Missing ECCAttributes
	}
	err := attrs.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ECC attributes are required")
}

func TestKeyAttributes_Validate_ECDSA_MissingCurve(t *testing.T) {
	attrs := &KeyAttributes{
		CN:            "test-ecdsa",
		KeyType:       KeyTypeTLS,
		StoreType:     StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &ECCAttributes{
			// Curve is nil
		},
	}
	err := attrs.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "curve is required")
}

func TestKeyAttributes_Validate_UnsupportedKeyAlgorithm(t *testing.T) {
	attrs := &KeyAttributes{
		CN:           "test-unsupported",
		KeyType:      KeyTypeTLS,
		StoreType:    StoreSoftware,
		KeyAlgorithm: x509.DSA, // Unsupported
	}
	err := attrs.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key algorithm")
}


func TestKeyAttributes_Validate_UnsupportedSymmetricAlgorithm(t *testing.T) {
	attrs := &KeyAttributes{
		CN:                 "test-unsupported",
		KeyType:            KeyTypeSecret,
		StoreType:          StoreSoftware,
		SymmetricAlgorithm: SymmetricAlgorithm("invalid"),
	}
	err := attrs.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported symmetric algorithm")
}

func TestKeyAttributes_ID_X25519(t *testing.T) {
	attrs := &KeyAttributes{
		CN:               "test-x25519",
		StoreType:        StoreSoftware,
		KeyType:          KeyTypeEncryption,
		X25519Attributes: &X25519Attributes{},
	}
	id := attrs.ID()
	assert.Equal(t, "software:encryption:test-x25519:x25519", id)
}

func TestKeyAttributes_ID_X25519_WithPartition(t *testing.T) {
	attrs := &KeyAttributes{
		CN:               "test-x25519",
		StoreType:        StoreSoftware,
		KeyType:          KeyTypeEncryption,
		X25519Attributes: &X25519Attributes{},
		Partition:        PartitionEncryptionKeys,
	}
	id := attrs.ID()
	assert.Equal(t, "crypto:software:encryption:test-x25519:x25519", id)
}

// TestPassword is a simple test implementation of the Password interface
type TestPassword struct {
	value string
	err   error
}

func (p *TestPassword) Bytes() []byte {
	return []byte(p.value)
}

func (p *TestPassword) String() (string, error) {
	if p.err != nil {
		return "", p.err
	}
	return p.value, nil
}

func (p *TestPassword) Clear() {
	p.value = ""
}

func TestKeyAttributes_String_WithDebugAndPassword(t *testing.T) {
	password := &TestPassword{value: "test-password"}
	sealData := NewSealData([]byte("test-seal-data"))

	attrs := &KeyAttributes{
		CN:           "test-key-debug",
		KeyType:      KeyTypeTLS,
		StoreType:    StoreSoftware,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
		Debug:        true,
		Password:     password,
		SealData:     sealData,
		RSAAttributes: &RSAAttributes{
			KeySize: 2048,
		},
	}

	str := attrs.String()
	assert.Contains(t, str, "test-key-debug")
	assert.Contains(t, str, "Debug: true")
	assert.Contains(t, str, "Secrets")
	assert.Contains(t, str, "test-password")
	assert.Contains(t, str, "test-seal-data")
}

func TestKeyAttributes_String_WithDebugNoPassword(t *testing.T) {
	attrs := &KeyAttributes{
		CN:           "test-key-debug-no-pw",
		KeyType:      KeyTypeTLS,
		StoreType:    StoreSoftware,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
		Debug:        true,
		RSAAttributes: &RSAAttributes{
			KeySize: 2048,
		},
	}

	str := attrs.String()
	assert.Contains(t, str, "test-key-debug-no-pw")
	assert.Contains(t, str, "Debug: true")
	assert.Contains(t, str, "Secrets")
}

func TestKeyAttributes_String_WithPasswordError(t *testing.T) {
	password := &TestPassword{value: "test-password", err: assert.AnError}

	attrs := &KeyAttributes{
		CN:           "test-key-pw-error",
		KeyType:      KeyTypeTLS,
		StoreType:    StoreSoftware,
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.SHA256,
		Debug:        true,
		Password:     password,
		RSAAttributes: &RSAAttributes{
			KeySize: 2048,
		},
	}

	str := attrs.String()
	assert.Contains(t, str, "test-key-pw-error")
	assert.Contains(t, str, "Debug: true")
	// Password error should result in empty string for password
	assert.Contains(t, str, "Secrets")
}

// =============================================================================
// SealData Interface Tests
// =============================================================================

func TestSealData_NewSealData(t *testing.T) {
	data := []byte("test-secret-data")
	sealData := NewSealData(data)
	require.NotNil(t, sealData)

	// Verify data was copied
	result := sealData.Bytes()
	assert.Equal(t, data, result)

	// Verify modification of original doesn't affect sealData
	data[0] = 'X'
	assert.NotEqual(t, data[0], sealData.Bytes()[0])
}

func TestSealData_NewSealData_Empty(t *testing.T) {
	sealData := NewSealData([]byte{})
	require.NotNil(t, sealData)
	assert.Empty(t, sealData.Bytes())
}

func TestSealData_NewSealData_Nil(t *testing.T) {
	sealData := NewSealData(nil)
	require.NotNil(t, sealData)
	assert.Empty(t, sealData.Bytes())
}

func TestSealData_Bytes(t *testing.T) {
	data := []byte("secret-bytes-test")
	sealData := NewSealData(data)

	result := sealData.Bytes()
	assert.Equal(t, data, result)

	// Calling Bytes() multiple times should return same data
	result2 := sealData.Bytes()
	assert.Equal(t, result, result2)
}

func TestSealData_Clear(t *testing.T) {
	data := []byte("sensitive-data-to-clear")
	sealData := NewSealData(data)

	// Verify data is present before Clear
	assert.Equal(t, data, sealData.Bytes())

	// Clear the sealData
	sealData.Clear()

	// Verify data is zeroed
	for _, b := range sealData.Bytes() {
		assert.Equal(t, byte(0), b, "Expected all bytes to be zeroed after Clear()")
	}
}

func TestSealData_Clear_AlreadyEmpty(t *testing.T) {
	sealData := NewSealData([]byte{})

	// Clear should not panic on empty sealData
	sealData.Clear()
	assert.Empty(t, sealData.Bytes())
}

func TestSealData_Clear_MultipleTimes(t *testing.T) {
	sealData := NewSealData([]byte("test-data"))

	// Clear multiple times should not panic
	sealData.Clear()
	sealData.Clear()
	sealData.Clear()

	// Data should remain zeroed
	for _, b := range sealData.Bytes() {
		assert.Equal(t, byte(0), b)
	}
}

func TestSealData_Interface(t *testing.T) {
	// Verify sealData implements SealData interface
	var _ SealData = (*sealData)(nil)
	_ = NewSealData([]byte("test"))
}

func TestSealData_SecureMemoryZeroing(t *testing.T) {
	// Create sealData with known pattern
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i + 1) // Non-zero values 1-32
	}

	sealData := NewSealData(data)

	// Verify pattern is stored
	stored := sealData.Bytes()
	for i := range stored {
		assert.Equal(t, byte(i+1), stored[i])
	}

	// Clear the sealData
	sealData.Clear()

	// Verify all bytes are zeroed
	cleared := sealData.Bytes()
	for i, b := range cleared {
		assert.Equal(t, byte(0), b, "Byte at index %d should be zeroed", i)
	}
}

func TestSealData_LargeData(t *testing.T) {
	// Test with larger data (simulate real secret like AES key)
	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	sealData := NewSealData(largeData)
	assert.Equal(t, largeData, sealData.Bytes())

	sealData.Clear()
	for _, b := range sealData.Bytes() {
		assert.Equal(t, byte(0), b)
	}
}

func TestClearPassword_BackwardCompatibility(t *testing.T) {
	// Test that deprecated NewClearPassword still works
	data := []byte("backward-compat-password")
	password := NewClearPassword(data)
	require.NotNil(t, password)
	assert.Equal(t, data, password.Bytes())

	// Test NewClearPasswordFromString
	password2 := NewClearPasswordFromString("test-string")
	require.NotNil(t, password2)
	str, err := password2.String()
	assert.NoError(t, err)
	assert.Equal(t, "test-string", str)
}
