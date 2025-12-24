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

package keychain

import (
	"crypto"
	"crypto/elliptic"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

// Type aliases for backward compatibility in tests
type (
	StoreType     = types.StoreType
	KeyType       = types.KeyType
	KeyAttributes = types.KeyAttributes
	RSAAttributes = types.RSAAttributes
	ECCAttributes = types.ECCAttributes
	TPMAttributes = types.TPMAttributes
	FSExtension   = types.FSExtension
)

// Function aliases for backward compatibility in tests
var NewSealData = types.NewSealData

// Constant aliases for backward compatibility in tests
const (
	StoreSoftware = types.StoreSoftware
	StorePKCS11   = types.StorePKCS11
	StoreTPM2     = types.StoreTPM2
	StoreAWSKMS   = types.StoreAWSKMS
	StoreGCPKMS   = types.StoreGCPKMS
	StoreAzureKV  = types.StoreAzureKV
	StoreVault    = types.StoreVault
	StoreUnknown  = types.StoreUnknown

	KeyTypeAttestation = types.KeyTypeAttestation
	KeyTypeCA          = types.KeyTypeCA
	KeyTypeEncryption  = types.KeyTypeEncryption
	KeyTypeEndorsement = types.KeyTypeEndorsement
	KeyTypeHMAC        = types.KeyTypeHMAC
	KeyTypeIDevID      = types.KeyTypeIDevID
	KeyTypeLDevID      = types.KeyTypeLDevID
	KeyTypeSecret      = types.KeyTypeSecret
	KeyTypeSigning     = types.KeyTypeSigning
	KeyTypeStorage     = types.KeyTypeStorage
	KeyTypeTLS         = types.KeyTypeTLS
	KeyTypeTPM         = types.KeyTypeTPM

	FSExtPrivatePKCS8    = types.FSExtPrivatePKCS8
	FSExtPrivatePKCS8PEM = types.FSExtPrivatePKCS8PEM
	FSExtPublicPKCS1     = types.FSExtPublicPKCS1
	FSExtPublicPEM       = types.FSExtPublicPEM
	FSExtPrivateBlob     = types.FSExtPrivateBlob
	FSExtPublicBlob      = types.FSExtPublicBlob
	FSExtDigest          = types.FSExtDigest
	FSExtSignature       = types.FSExtSignature
)

// Function aliases for backward compatibility in tests
var (
	AvailableHashes                    = types.AvailableHashes
	AvailableSignatureAlgorithms       = types.AvailableSignatureAlgorithms
	SignatureAlgorithmHashes           = types.SignatureAlgorithmHashes
	AvailableKeyAlgorithms             = types.AvailableKeyAlgorithms
	IsRSAPSS                           = types.IsRSAPSS
	IsECDSA                            = types.IsECDSA
	KeyAlgorithmFromSignatureAlgorithm = types.KeyAlgorithmFromSignatureAlgorithm
	FSHashName                         = types.FSHashName
	FSExtKeyAlgorithm                  = types.FSExtKeyAlgorithm
	KeyFileExtension                   = types.KeyFileExtension
	HashFileExtension                  = types.HashFileExtension
	Digest                             = types.Digest
)

// testPassword wraps a keychain.Password to implement types.Password interface
type testPassword struct {
	pw Password
}

func (tp *testPassword) Bytes() []byte {
	b, _ := tp.pw.Bytes()
	return b
}

func (tp *testPassword) String() (string, error) {
	return tp.pw.String()
}

func (tp *testPassword) Clear() {
	// No-op for test password
}

// wrapPassword converts keychain.Password to types.Password for tests
func wrapPassword(pw Password) types.Password {
	if pw == nil {
		return nil
	}
	return &testPassword{pw: pw}
}

func TestStoreType_String(t *testing.T) {
	tests := []struct {
		name      string
		storeType StoreType
		want      string
	}{
		{"Software", StoreSoftware, "software"},
		{"PKCS11", StorePKCS11, "pkcs11"},
		{"TPM2", StoreTPM2, "tpm2"},
		{"AWS KMS", StoreAWSKMS, "awskms"},
		{"GCP KMS", StoreGCPKMS, "gcpkms"},
		{"Azure KV", StoreAzureKV, "azurekv"},
		{"Unknown", StoreUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.storeType.String(); got != tt.want {
				t.Errorf("StoreType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStoreType_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		storeType StoreType
		want      bool
	}{
		{"PKCS8 valid", StoreSoftware, true},
		{"PKCS11 valid", StorePKCS11, true},
		{"TPM2 valid", StoreTPM2, true},
		{"AWS KMS valid", StoreAWSKMS, true},
		{"GCP KMS valid", StoreGCPKMS, true},
		{"Azure KV valid", StoreAzureKV, true},
		{"Unknown invalid", StoreUnknown, false},
		{"Empty invalid", StoreType(""), false},
		{"Random invalid", StoreType("random"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.storeType.IsValid(); got != tt.want {
				t.Errorf("StoreType.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyType_String(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		want    string
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
			if got := tt.keyType.String(); got != tt.want {
				t.Errorf("KeyType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyAttributes_String(t *testing.T) {
	tests := []struct {
		name  string
		attrs KeyAttributes
		check func(string) bool
	}{
		{
			name: "Basic RSA attributes",
			attrs: KeyAttributes{
				CN:                 "test-key",
				Debug:              false,
				Hash:               crypto.SHA256,
				KeyAlgorithm:       x509.RSA,
				KeyType:            KeyTypeSigning,
				PlatformPolicy:     false,
				SignatureAlgorithm: x509.SHA256WithRSA,
				StoreType:          StoreSoftware,
				RSAAttributes: &RSAAttributes{
					KeySize: 2048,
				},
			},
			check: func(s string) bool {
				return strings.Contains(s, "Common Name: test-key") &&
					strings.Contains(s, "Hash: SHA-256") &&
					strings.Contains(s, "Key Algorithm: RSA") &&
					strings.Contains(s, "Type: SIGNING") &&
					strings.Contains(s, "RSA Attributes") &&
					strings.Contains(s, "Size: 2048")
			},
		},
		{
			name: "ECDSA attributes",
			attrs: KeyAttributes{
				CN:                 "ecdsa-key",
				Debug:              false,
				Hash:               crypto.SHA384,
				KeyAlgorithm:       x509.ECDSA,
				KeyType:            KeyTypeTLS,
				SignatureAlgorithm: x509.ECDSAWithSHA384,
				StoreType:          StorePKCS11,
				ECCAttributes: &ECCAttributes{
					Curve: elliptic.P384(),
				},
			},
			check: func(s string) bool {
				return strings.Contains(s, "Common Name: ecdsa-key") &&
					strings.Contains(s, "Hash: SHA-384") &&
					strings.Contains(s, "Key Algorithm: ECDSA") &&
					strings.Contains(s, "Type: TLS") &&
					strings.Contains(s, "ECC Attributes") &&
					strings.Contains(s, "Curve: P-384")
			},
		},
		{
			name: "Debug mode with password",
			attrs: KeyAttributes{
				CN:                 "debug-key",
				Debug:              true,
				Hash:               crypto.SHA256,
				KeyAlgorithm:       x509.RSA,
				KeyType:            KeyTypeEncryption,
				SignatureAlgorithm: x509.SHA256WithRSA,
				StoreType:          StoreSoftware,
				Password:           wrapPassword(NewClearPassword([]byte("test-password"))),
				SealData:           NewSealData([]byte("test-seal-data")),
				TPMAttributes:      &TPMAttributes{},
				RSAAttributes: &RSAAttributes{
					KeySize: 4096,
				},
			},
			check: func(s string) bool {
				return strings.Contains(s, "Debug: true") &&
					strings.Contains(s, "Secrets") &&
					strings.Contains(s, "Password: test-password") &&
					strings.Contains(s, "SealData: test-seal-data")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.attrs.String()
			if !tt.check(got) {
				t.Errorf("KeyAttributes.String() output check failed:\n%s", got)
			}
		})
	}
}

func TestAvailableHashes(t *testing.T) {
	hashes := AvailableHashes()

	// Verify all expected hashes are present
	expected := []crypto.Hash{
		crypto.MD4,
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
		crypto.MD5SHA1,
		crypto.RIPEMD160,
		crypto.SHA3_224,
		crypto.SHA3_256,
		crypto.SHA3_384,
		crypto.SHA3_512,
		crypto.SHA512_224,
		crypto.SHA512_256,
		crypto.BLAKE2s_256,
		crypto.BLAKE2b_256,
		crypto.BLAKE2b_384,
		crypto.BLAKE2b_512,
	}

	for _, hash := range expected {
		name := hash.String()
		got, ok := hashes[name]
		if !ok {
			t.Errorf("AvailableHashes() missing hash %s", name)
			continue
		}
		if got != hash {
			t.Errorf("AvailableHashes()[%s] = %v, want %v", name, got, hash)
		}
	}

	// The function now includes aliases (lowercase, uppercase) for flexibility
	// So the count will be greater than the number of unique hash types
	if len(hashes) < len(expected) {
		t.Errorf("AvailableHashes() returned %d hashes, expected at least %d", len(hashes), len(expected))
	}
}

func TestAvailableSignatureAlgorithms(t *testing.T) {
	sigAlgos := AvailableSignatureAlgorithms()

	// Verify all expected signature algorithms are present
	expected := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS,
		x509.SHA512WithRSAPSS,
		x509.PureEd25519,
	}

	for _, algo := range expected {
		name := algo.String()
		got, ok := sigAlgos[name]
		if !ok {
			t.Errorf("AvailableSignatureAlgorithms() missing algorithm %s", name)
			continue
		}
		if got != algo {
			t.Errorf("AvailableSignatureAlgorithms()[%s] = %v, want %v", name, got, algo)
		}
	}

	if len(sigAlgos) != len(expected) {
		t.Errorf("AvailableSignatureAlgorithms() returned %d algorithms, expected %d", len(sigAlgos), len(expected))
	}
}

func TestSignatureAlgorithmHashes(t *testing.T) {
	tests := []struct {
		sigAlgo x509.SignatureAlgorithm
		want    crypto.Hash
	}{
		{x509.SHA256WithRSA, crypto.SHA256},
		{x509.SHA384WithRSA, crypto.SHA384},
		{x509.SHA512WithRSA, crypto.SHA512},
		{x509.ECDSAWithSHA256, crypto.SHA256},
		{x509.ECDSAWithSHA384, crypto.SHA384},
		{x509.ECDSAWithSHA512, crypto.SHA512},
		{x509.SHA256WithRSAPSS, crypto.SHA256},
		{x509.SHA384WithRSAPSS, crypto.SHA384},
		{x509.SHA512WithRSAPSS, crypto.SHA512},
		{x509.PureEd25519, 0},
	}

	hashes := SignatureAlgorithmHashes()

	for _, tt := range tests {
		t.Run(tt.sigAlgo.String(), func(t *testing.T) {
			got, ok := hashes[tt.sigAlgo]
			if !ok {
				t.Errorf("SignatureAlgorithmHashes() missing algorithm %s", tt.sigAlgo)
				return
			}
			if got != tt.want {
				t.Errorf("SignatureAlgorithmHashes()[%s] = %v, want %v", tt.sigAlgo, got, tt.want)
			}
		})
	}
}

func TestAvailableKeyAlgorithms(t *testing.T) {
	keyAlgos := AvailableKeyAlgorithms()

	expected := []x509.PublicKeyAlgorithm{
		x509.RSA,
		x509.ECDSA,
		x509.Ed25519,
	}

	for _, algo := range expected {
		name := algo.String()
		got, ok := keyAlgos[name]
		if !ok {
			t.Errorf("AvailableKeyAlgorithms() missing algorithm %s", name)
			continue
		}
		if got != algo {
			t.Errorf("AvailableKeyAlgorithms()[%s] = %v, want %v", name, got, algo)
		}
	}

	if len(keyAlgos) != len(expected) {
		t.Errorf("AvailableKeyAlgorithms() returned %d algorithms, expected %d", len(keyAlgos), len(expected))
	}
}

func TestIsRSAPSS(t *testing.T) {
	tests := []struct {
		name    string
		sigAlgo x509.SignatureAlgorithm
		want    bool
	}{
		{"SHA256 RSA-PSS", x509.SHA256WithRSAPSS, true},
		{"SHA384 RSA-PSS", x509.SHA384WithRSAPSS, true},
		{"SHA512 RSA-PSS", x509.SHA512WithRSAPSS, true},
		{"SHA256 RSA", x509.SHA256WithRSA, false},
		{"ECDSA SHA256", x509.ECDSAWithSHA256, false},
		{"Ed25519", x509.PureEd25519, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRSAPSS(tt.sigAlgo); got != tt.want {
				t.Errorf("IsRSAPSS(%v) = %v, want %v", tt.sigAlgo, got, tt.want)
			}
		})
	}
}

func TestIsECDSA(t *testing.T) {
	tests := []struct {
		name    string
		sigAlgo x509.SignatureAlgorithm
		want    bool
	}{
		{"ECDSA SHA256", x509.ECDSAWithSHA256, true},
		{"ECDSA SHA384", x509.ECDSAWithSHA384, true},
		{"ECDSA SHA512", x509.ECDSAWithSHA512, true},
		{"SHA256 RSA", x509.SHA256WithRSA, false},
		{"SHA256 RSA-PSS", x509.SHA256WithRSAPSS, false},
		{"Ed25519", x509.PureEd25519, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsECDSA(tt.sigAlgo); got != tt.want {
				t.Errorf("IsECDSA(%v) = %v, want %v", tt.sigAlgo, got, tt.want)
			}
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
		// ECDSA
		{"ECDSA SHA256", x509.ECDSAWithSHA256, x509.ECDSA, false},
		{"ECDSA SHA384", x509.ECDSAWithSHA384, x509.ECDSA, false},
		{"ECDSA SHA512", x509.ECDSAWithSHA512, x509.ECDSA, false},
		// RSA
		{"RSA SHA256", x509.SHA256WithRSA, x509.RSA, false},
		{"RSA SHA384", x509.SHA384WithRSA, x509.RSA, false},
		{"RSA SHA512", x509.SHA512WithRSA, x509.RSA, false},
		// RSA-PSS
		{"RSA-PSS SHA256", x509.SHA256WithRSAPSS, x509.RSA, false},
		{"RSA-PSS SHA384", x509.SHA384WithRSAPSS, x509.RSA, false},
		{"RSA-PSS SHA512", x509.SHA512WithRSAPSS, x509.RSA, false},
		// Ed25519
		{"Ed25519", x509.PureEd25519, x509.Ed25519, false},
		// Invalid
		{"Unknown", x509.UnknownSignatureAlgorithm, 0, true},
		{"MD5WithRSA", x509.MD5WithRSA, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := KeyAlgorithmFromSignatureAlgorithm(tt.sigAlgo)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyAlgorithmFromSignatureAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("KeyAlgorithmFromSignatureAlgorithm(%v) = %v, want %v", tt.sigAlgo, got, tt.want)
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
		{"SHA3-256", crypto.SHA3_256, "sha3256"},
		{"BLAKE2b-256", crypto.BLAKE2b_256, "blake2b256"},
		{"MD5", crypto.MD5, "md5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FSHashName(tt.hash)
			if got != tt.want {
				t.Errorf("FSHashName(%v) = %v, want %v", tt.hash, got, tt.want)
			}
			// Verify no special characters
			if strings.Contains(got, "-") || strings.Contains(got, "/") {
				t.Errorf("FSHashName(%v) contains invalid characters: %v", tt.hash, got)
			}
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
			if got != tt.want {
				t.Errorf("FSExtKeyAlgorithm(%v) = %v, want %v", tt.algo, got, tt.want)
			}
		})
	}
}

func TestKeyFileExtension(t *testing.T) {
	hmacType := KeyTypeHMAC
	signingType := KeyTypeSigning

	tests := []struct {
		name      string
		algo      x509.PublicKeyAlgorithm
		extension FSExtension
		keyType   *KeyType
		want      FSExtension
	}{
		{"RSA private key", x509.RSA, FSExtPrivatePKCS8, nil, ".rsa.key"},
		{"ECDSA public key", x509.ECDSA, FSExtPublicPKCS1, nil, ".ecdsa.pub"},
		{"Ed25519 PEM", x509.Ed25519, FSExtPrivatePKCS8PEM, nil, ".ed25519.key.pem"},
		{"HMAC key", x509.RSA, FSExtPrivatePKCS8, &hmacType, ".hmac.key"},
		{"Signing key", x509.ECDSA, FSExtPrivatePKCS8, &signingType, ".ecdsa.key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := KeyFileExtension(tt.algo, tt.extension, tt.keyType)
			if got != tt.want {
				t.Errorf("KeyFileExtension(%v, %v, %v) = %v, want %v",
					tt.algo, tt.extension, tt.keyType, got, tt.want)
			}
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
		{"SHA3-256", crypto.SHA3_256, ".sha3256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HashFileExtension(tt.hash)
			if got != tt.want {
				t.Errorf("HashFileExtension(%v) = %v, want %v", tt.hash, got, tt.want)
			}
		})
	}
}

func TestDigest(t *testing.T) {
	testData := []byte("test data for hashing")

	tests := []struct {
		name    string
		hash    crypto.Hash
		wantErr bool
	}{
		{"SHA256", crypto.SHA256, false},
		{"SHA384", crypto.SHA384, false},
		{"SHA512", crypto.SHA512, false},
		{"SHA3-256", crypto.SHA3_256, false},
		{"Unavailable hash", crypto.Hash(999), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Digest(tt.hash, testData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Digest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) == 0 {
					t.Error("Digest() returned empty digest")
				}
				// Verify digest is deterministic
				got2, err2 := Digest(tt.hash, testData)
				if err2 != nil {
					t.Errorf("Digest() second call error = %v", err2)
					return
				}
				if string(got) != string(got2) {
					t.Error("Digest() not deterministic")
				}
			}
		})
	}
}

func TestDigest_ErrorCases(t *testing.T) {
	t.Run("Unavailable hash", func(t *testing.T) {
		_, err := Digest(crypto.Hash(999), []byte("test"))
		if err == nil {
			t.Error("Digest() with unavailable hash should return error")
		}
		// The crypto package returns an error for unavailable hash functions
		// We just verify an error is returned, not the specific error type
	})
}

// TestDigest_EmptyData tests Digest with empty data
func TestDigest_EmptyData(t *testing.T) {
	tests := []struct {
		name         string
		hash         crypto.Hash
		expectedSize int
	}{
		{"SHA256 empty", crypto.SHA256, 32},
		{"SHA384 empty", crypto.SHA384, 48},
		{"SHA512 empty", crypto.SHA512, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := Digest(tt.hash, []byte{})
			if err != nil {
				t.Errorf("Digest() with empty data error = %v", err)
				return
			}
			if len(digest) != tt.expectedSize {
				t.Errorf("Digest() with empty data size = %d, want %d", len(digest), tt.expectedSize)
			}
			// Verify it matches direct hash computation
			hasher := tt.hash.New()
			hasher.Write([]byte{})
			expected := hasher.Sum(nil)
			if string(digest) != string(expected) {
				t.Error("Digest() with empty data doesn't match expected hash")
			}
		})
	}
}

// TestDigest_LargeData tests Digest with large data
func TestDigest_LargeData(t *testing.T) {
	// Create 10MB of data
	largeData := make([]byte, 10*1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	digest, err := Digest(crypto.SHA256, largeData)
	if err != nil {
		t.Errorf("Digest() with large data error = %v", err)
		return
	}
	if len(digest) != 32 {
		t.Errorf("Digest() with large data size = %d, want 32", len(digest))
	}

	// Verify it's deterministic
	digest2, err := Digest(crypto.SHA256, largeData)
	if err != nil {
		t.Errorf("Digest() second call with large data error = %v", err)
		return
	}
	if string(digest) != string(digest2) {
		t.Error("Digest() not deterministic for large data")
	}
}

// TestDigest_AllHashes tests Digest with all available hash functions
func TestDigest_AllHashes(t *testing.T) {
	testData := []byte("test data for all hashes")

	tests := []struct {
		name string
		hash crypto.Hash
	}{
		{"SHA224", crypto.SHA224},
		{"SHA256", crypto.SHA256},
		{"SHA384", crypto.SHA384},
		{"SHA512", crypto.SHA512},
		{"SHA3_224", crypto.SHA3_224},
		{"SHA3_256", crypto.SHA3_256},
		{"SHA3_384", crypto.SHA3_384},
		{"SHA3_512", crypto.SHA3_512},
		{"SHA512_224", crypto.SHA512_224},
		{"SHA512_256", crypto.SHA512_256},
		{"BLAKE2s_256", crypto.BLAKE2s_256},
		{"BLAKE2b_256", crypto.BLAKE2b_256},
		{"BLAKE2b_384", crypto.BLAKE2b_384},
		{"BLAKE2b_512", crypto.BLAKE2b_512},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.hash.Available() {
				t.Logf("⚠ Hash %s not available in this Go build (known limitation)", tt.name)
				return
			}

			digest, err := Digest(tt.hash, testData)
			if err != nil {
				t.Errorf("Digest() error = %v", err)
				return
			}
			if len(digest) == 0 {
				t.Error("Digest() returned empty digest")
			}

			// Verify it matches direct computation
			hasher := tt.hash.New()
			hasher.Write(testData)
			expected := hasher.Sum(nil)
			if string(digest) != string(expected) {
				t.Errorf("Digest() mismatch for %s", tt.name)
			}
		})
	}
}

// TestDigest_NilData tests Digest with nil data
func TestDigest_NilData(t *testing.T) {
	digest, err := Digest(crypto.SHA256, nil)
	if err != nil {
		t.Errorf("Digest() with nil data error = %v", err)
		return
	}
	if len(digest) == 0 {
		t.Error("Digest() with nil data returned empty digest")
	}

	// Verify it matches hash of empty data
	hasher := crypto.SHA256.New()
	hasher.Write(nil)
	expected := hasher.Sum(nil)
	if string(digest) != string(expected) {
		t.Error("Digest() with nil data doesn't match expected hash")
	}
}
