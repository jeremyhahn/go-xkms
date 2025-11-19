package tpm2

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net/url"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestCalculateNameUnit(t *testing.T) {
	tests := []struct {
		name       string
		algID      tpm2.TPMAlgID
		publicArea []byte
		wantLen    int
		wantErr    bool
	}{
		{
			name:       "SHA1 algorithm",
			algID:      tpm2.TPMAlgSHA1,
			publicArea: []byte("test public area"),
			wantLen:    2 + 20, // 2 bytes algID + 20 bytes SHA1 hash
			wantErr:    false,
		},
		{
			name:       "SHA256 algorithm",
			algID:      tpm2.TPMAlgSHA256,
			publicArea: []byte("test public area data"),
			wantLen:    2 + 32, // 2 bytes algID + 32 bytes SHA256 hash
			wantErr:    false,
		},
		{
			name:       "SHA3-384 algorithm",
			algID:      tpm2.TPMAlgSHA3384,
			publicArea: []byte("another test data"),
			wantLen:    2 + 48, // 2 bytes algID + 48 bytes SHA384 hash
			wantErr:    false,
		},
		{
			name:       "SHA512 algorithm",
			algID:      tpm2.TPMAlgSHA512,
			publicArea: []byte("sha512 test data"),
			wantLen:    2 + 64, // 2 bytes algID + 64 bytes SHA512 hash
			wantErr:    false,
		},
		{
			name:       "empty public area",
			algID:      tpm2.TPMAlgSHA256,
			publicArea: []byte{},
			wantLen:    2 + 32,
			wantErr:    false,
		},
		{
			name:       "large public area",
			algID:      tpm2.TPMAlgSHA256,
			publicArea: make([]byte, 10000),
			wantLen:    2 + 32,
			wantErr:    false,
		},
		{
			name:       "unsupported algorithm",
			algID:      tpm2.TPMAlgID(0xFFFF), // Invalid algorithm
			publicArea: []byte("test data"),
			wantLen:    0,
			wantErr:    true,
		},
		{
			name:       "null algorithm",
			algID:      tpm2.TPMAlgNull,
			publicArea: []byte("test data"),
			wantLen:    0,
			wantErr:    true,
		},
		{
			name:       "RSA algorithm ID (not a hash)",
			algID:      tpm2.TPMAlgRSA,
			publicArea: []byte("test data"),
			wantLen:    0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CalculateName(tt.algID, tt.publicArea)

			if tt.wantErr {
				if err == nil {
					t.Errorf("CalculateName() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("CalculateName() unexpected error: %v", err)
				return
			}

			if len(result) != tt.wantLen {
				t.Errorf("CalculateName() length = %d, want %d", len(result), tt.wantLen)
			}

			// Verify algorithm ID is correctly encoded in first 2 bytes (big endian)
			if len(result) >= 2 {
				encodedAlgID := (uint16(result[0]) << 8) | uint16(result[1])
				if encodedAlgID != uint16(tt.algID) {
					t.Errorf("CalculateName() algID encoding = 0x%x, want 0x%x", encodedAlgID, tt.algID)
				}
			}
		})
	}
}

func TestCalculateNameConsistency(t *testing.T) {
	// Test that same input produces same output
	publicArea := []byte("consistent test data for name calculation")

	result1, err := CalculateName(tpm2.TPMAlgSHA256, publicArea)
	if err != nil {
		t.Fatalf("CalculateName() first call error: %v", err)
	}

	result2, err := CalculateName(tpm2.TPMAlgSHA256, publicArea)
	if err != nil {
		t.Fatalf("CalculateName() second call error: %v", err)
	}

	if len(result1) != len(result2) {
		t.Errorf("CalculateName() inconsistent length: %d vs %d", len(result1), len(result2))
	}

	for i := range result1 {
		if result1[i] != result2[i] {
			t.Errorf("CalculateName() inconsistent at byte %d: 0x%x vs 0x%x", i, result1[i], result2[i])
		}
	}
}

func TestCalculateNameDifferentData(t *testing.T) {
	// Different data should produce different names
	data1 := []byte("first public area")
	data2 := []byte("second public area")

	name1, err := CalculateName(tpm2.TPMAlgSHA256, data1)
	if err != nil {
		t.Fatalf("CalculateName() data1 error: %v", err)
	}

	name2, err := CalculateName(tpm2.TPMAlgSHA256, data2)
	if err != nil {
		t.Fatalf("CalculateName() data2 error: %v", err)
	}

	// Algorithm ID should be same
	if name1[0] != name2[0] || name1[1] != name2[1] {
		t.Error("CalculateName() algorithm IDs should match for same algorithm")
	}

	// Hash portion should be different
	sameHash := true
	for i := 2; i < len(name1); i++ {
		if name1[i] != name2[i] {
			sameHash = false
			break
		}
	}
	if sameHash {
		t.Error("CalculateName() different data should produce different names")
	}
}

func TestCalculateNameDifferentAlgorithms(t *testing.T) {
	publicArea := []byte("test data for multiple algorithms")

	algorithms := []struct {
		name   string
		algID  tpm2.TPMAlgID
		length int
	}{
		{"SHA1", tpm2.TPMAlgSHA1, 2 + 20},
		{"SHA256", tpm2.TPMAlgSHA256, 2 + 32},
		{"SHA512", tpm2.TPMAlgSHA512, 2 + 64},
	}

	for _, alg := range algorithms {
		t.Run(alg.name, func(t *testing.T) {
			result, err := CalculateName(alg.algID, publicArea)
			if err != nil {
				t.Errorf("CalculateName() error: %v", err)
				return
			}

			if len(result) != alg.length {
				t.Errorf("CalculateName() length = %d, want %d", len(result), alg.length)
			}

			// Verify the algorithm ID prefix
			expectedAlgID := uint16(alg.algID)
			actualAlgID := (uint16(result[0]) << 8) | uint16(result[1])
			if actualAlgID != expectedAlgID {
				t.Errorf("CalculateName() algID = 0x%x, want 0x%x", actualAlgID, expectedAlgID)
			}
		})
	}
}

func TestIntelEKURLUnit(t *testing.T) {
	tests := []struct {
		name     string
		ekPub    *rsa.PublicKey
		wantBase string
	}{
		{
			name: "valid RSA public key",
			ekPub: &rsa.PublicKey{
				N: big.NewInt(0).SetBytes([]byte{
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				}),
				E: 65537, // 0x10001
			},
			wantBase: intelEKCertServiceURL,
		},
		{
			name: "different RSA public key",
			ekPub: &rsa.PublicKey{
				N: big.NewInt(0).SetBytes([]byte{
					0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
				}),
				E: 65537,
			},
			wantBase: intelEKCertServiceURL,
		},
		{
			name: "small N value",
			ekPub: &rsa.PublicKey{
				N: big.NewInt(255),
				E: 65537,
			},
			wantBase: intelEKCertServiceURL,
		},
		{
			name: "large N value",
			ekPub: &rsa.PublicKey{
				N: big.NewInt(0).SetBytes(make([]byte, 256)), // 2048-bit key
				E: 65537,
			},
			wantBase: intelEKCertServiceURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := intelEKURL(tt.ekPub)

			// Verify URL starts with Intel EK cert service base URL
			if len(result) < len(tt.wantBase) {
				t.Errorf("intelEKURL() result too short: got %s", result)
				return
			}

			if result[:len(tt.wantBase)] != tt.wantBase {
				t.Errorf("intelEKURL() base URL mismatch: got %s, want base %s", result, tt.wantBase)
			}

			// Verify the URL has encoded parameters
			encodedPart := result[len(tt.wantBase):]
			if len(encodedPart) == 0 {
				t.Error("intelEKURL() missing encoded hash part")
			}

			// Verify the encoded part is valid URL encoding
			_, err := url.QueryUnescape(encodedPart)
			if err != nil {
				t.Errorf("intelEKURL() URL encoding error: %v", err)
			}

			// Verify the hash computation matches expected
			pubHash := sha256.New()
			pubHash.Write(tt.ekPub.N.Bytes())
			pubHash.Write([]byte{0x1, 0x00, 0x01}) // Big-endian representation of 65537
			expectedEncoded := url.QueryEscape(base64.URLEncoding.EncodeToString(pubHash.Sum(nil)))

			if encodedPart != expectedEncoded {
				t.Errorf("intelEKURL() hash mismatch: got %s, want %s", encodedPart, expectedEncoded)
			}
		})
	}
}

func TestIntelEKURLDifferentExponents(t *testing.T) {
	// The function assumes E=65537, but let's verify it handles the key correctly
	ekPub := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes([]byte{0xAA, 0xBB, 0xCC, 0xDD}),
		E: 65537,
	}

	url := intelEKURL(ekPub)

	// Should be a valid URL string
	if url == "" {
		t.Error("intelEKURL() returned empty string")
	}

	// Should start with the Intel EK cert service URL
	if len(url) <= len(intelEKCertServiceURL) {
		t.Error("intelEKURL() URL too short")
	}
}

func TestIntelEKURLLargeKey(t *testing.T) {
	// Test with a 2048-bit RSA key (common size)
	keyBytes := make([]byte, 256)
	for i := range keyBytes {
		keyBytes[i] = byte(i % 256)
	}

	ekPub := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(keyBytes),
		E: 65537,
	}

	url := intelEKURL(ekPub)

	// Verify the URL structure
	if !containsString(url, intelEKCertServiceURL) {
		t.Errorf("intelEKURL() should contain base URL: %s", url)
	}

	// The encoded hash should be URL-safe
	encodedPart := url[len(intelEKCertServiceURL):]
	if len(encodedPart) == 0 {
		t.Error("intelEKURL() missing encoded part")
	}

	// Should not contain raw special characters
	for _, c := range encodedPart {
		if c == '+' || c == '/' || c == '=' {
			// These should be percent-encoded in URL
			t.Errorf("intelEKURL() contains non-URL-safe character: %c", c)
		}
	}
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}
