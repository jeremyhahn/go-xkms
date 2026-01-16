// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package store

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsRSAPSS(t *testing.T) {
	tests := []struct {
		name     string
		sigAlgo  x509.SignatureAlgorithm
		expected bool
	}{
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, true},
		{"SHA384WithRSAPSS", x509.SHA384WithRSAPSS, true},
		{"SHA512WithRSAPSS", x509.SHA512WithRSAPSS, true},
		{"SHA256WithRSA", x509.SHA256WithRSA, false},
		{"SHA384WithRSA", x509.SHA384WithRSA, false},
		{"SHA512WithRSA", x509.SHA512WithRSA, false},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, false},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, false},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, false},
		{"PureEd25519", x509.PureEd25519, false},
		{"UnknownSignatureAlgorithm", x509.UnknownSignatureAlgorithm, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsRSAPSS(tc.sigAlgo)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsECDSA(t *testing.T) {
	tests := []struct {
		name     string
		sigAlgo  x509.SignatureAlgorithm
		expected bool
	}{
		{"ECDSAWithSHA1", x509.ECDSAWithSHA1, true},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, true},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, true},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, true},
		{"SHA256WithRSA", x509.SHA256WithRSA, false},
		{"SHA256WithRSAPSS", x509.SHA256WithRSAPSS, false},
		{"PureEd25519", x509.PureEd25519, false},
		{"UnknownSignatureAlgorithm", x509.UnknownSignatureAlgorithm, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsECDSA(tc.sigAlgo)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestEncodePubKey(t *testing.T) {
	t.Run("RSA public key", func(t *testing.T) {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		encoded, err := EncodePubKey(&privateKey.PublicKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)

		// Verify the encoded key can be parsed back
		parsed, err := x509.ParsePKIXPublicKey(encoded)
		require.NoError(t, err)

		rsaPub, ok := parsed.(*rsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, privateKey.N, rsaPub.N)
		assert.Equal(t, privateKey.E, rsaPub.E)
	})

	t.Run("ECDSA public key", func(t *testing.T) {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		encoded, err := EncodePubKey(&privateKey.PublicKey)
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)

		// Verify the encoded key can be parsed back
		parsed, err := x509.ParsePKIXPublicKey(encoded)
		require.NoError(t, err)

		ecdsaPub, ok := parsed.(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.True(t, privateKey.PublicKey.Equal(ecdsaPub))
	})

	t.Run("nil key returns error", func(t *testing.T) {
		_, err := EncodePubKey(nil)
		assert.Error(t, err)
	})
}

func TestDecodePEM(t *testing.T) {
	t.Run("valid PEM block", func(t *testing.T) {
		// Create a valid PEM block
		data := []byte("test data")
		pemBlock := &pem.Block{
			Type:  "TEST DATA",
			Bytes: data,
		}
		pemBytes := pem.EncodeToMemory(pemBlock)

		decoded, err := DecodePEM(pemBytes)
		require.NoError(t, err)
		assert.Equal(t, "TEST DATA", decoded.Type)
		assert.Equal(t, data, decoded.Bytes)
	})

	t.Run("invalid PEM block", func(t *testing.T) {
		invalidPEM := []byte("this is not a valid PEM block")

		decoded, err := DecodePEM(invalidPEM)
		assert.Error(t, err)
		assert.Nil(t, decoded)
		assert.Contains(t, err.Error(), "failed to decode PEM block")
	})

	t.Run("empty input", func(t *testing.T) {
		decoded, err := DecodePEM([]byte{})
		assert.Error(t, err)
		assert.Nil(t, decoded)
	})
}

func TestDebugKeyAttributes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("debug enabled", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:                 "test-key",
			KeyAlgorithm:       x509.RSA,
			KeyType:            types.KeyTypeCA,
			StoreType:          types.StoreTPM2,
			Hash:               crypto.SHA256,
			SignatureAlgorithm: x509.SHA256WithRSAPSS,
			PlatformPolicy:     true,
			Debug:              true,
		}

		// Should not panic
		DebugKeyAttributes(logger, attrs)
	})

	t.Run("debug disabled", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			CN:                 "test-key",
			KeyAlgorithm:       x509.RSA,
			KeyType:            types.KeyTypeCA,
			StoreType:          types.StoreTPM2,
			Hash:               crypto.SHA256,
			SignatureAlgorithm: x509.SHA256WithRSAPSS,
			PlatformPolicy:     false,
			Debug:              false,
		}

		// Should not panic or log when debug is disabled
		DebugKeyAttributes(logger, attrs)
	})
}

func TestParseSignatureAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    x509.SignatureAlgorithm
		expectError bool
	}{
		// RSA algorithms
		{"SHA256-RSA", "SHA256-RSA", x509.SHA256WithRSA, false},
		{"SHA256WithRSA", "SHA256WithRSA", x509.SHA256WithRSA, false},
		{"SHA384-RSA", "SHA384-RSA", x509.SHA384WithRSA, false},
		{"SHA384WithRSA", "SHA384WithRSA", x509.SHA384WithRSA, false},
		{"SHA512-RSA", "SHA512-RSA", x509.SHA512WithRSA, false},
		{"SHA512WithRSA", "SHA512WithRSA", x509.SHA512WithRSA, false},

		// RSA-PSS algorithms
		{"SHA256-RSA-PSS", "SHA256-RSA-PSS", x509.SHA256WithRSAPSS, false},
		{"SHA256-RSAPSS", "SHA256-RSAPSS", x509.SHA256WithRSAPSS, false},
		{"SHA256WithRSAPSS", "SHA256WithRSAPSS", x509.SHA256WithRSAPSS, false},
		{"SHA384-RSA-PSS", "SHA384-RSA-PSS", x509.SHA384WithRSAPSS, false},
		{"SHA384-RSAPSS", "SHA384-RSAPSS", x509.SHA384WithRSAPSS, false},
		{"SHA384WithRSAPSS", "SHA384WithRSAPSS", x509.SHA384WithRSAPSS, false},
		{"SHA512-RSA-PSS", "SHA512-RSA-PSS", x509.SHA512WithRSAPSS, false},
		{"SHA512-RSAPSS", "SHA512-RSAPSS", x509.SHA512WithRSAPSS, false},
		{"SHA512WithRSAPSS", "SHA512WithRSAPSS", x509.SHA512WithRSAPSS, false},

		// ECDSA algorithms
		{"ECDSA-SHA256", "ECDSA-SHA256", x509.ECDSAWithSHA256, false},
		{"ECDSAWithSHA256", "ECDSAWithSHA256", x509.ECDSAWithSHA256, false},
		{"ECDSA-SHA384", "ECDSA-SHA384", x509.ECDSAWithSHA384, false},
		{"ECDSAWithSHA384", "ECDSAWithSHA384", x509.ECDSAWithSHA384, false},
		{"ECDSA-SHA512", "ECDSA-SHA512", x509.ECDSAWithSHA512, false},
		{"ECDSAWithSHA512", "ECDSAWithSHA512", x509.ECDSAWithSHA512, false},

		// Ed25519
		{"ED25519", "ED25519", x509.PureEd25519, false},

		// Case insensitive
		{"lowercase sha256-rsa", "sha256-rsa", x509.SHA256WithRSA, false},
		{"mixed case Sha256-RSA", "Sha256-RSA", x509.SHA256WithRSA, false},

		// With whitespace
		{"with leading space", "  SHA256-RSA", x509.SHA256WithRSA, false},
		{"with trailing space", "SHA256-RSA  ", x509.SHA256WithRSA, false},

		// Invalid algorithms
		{"unknown algorithm", "UNKNOWN", x509.UnknownSignatureAlgorithm, true},
		{"empty string", "", x509.UnknownSignatureAlgorithm, true},
		{"invalid format", "SHA256", x509.UnknownSignatureAlgorithm, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseSignatureAlgorithm(tc.input)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    x509.PublicKeyAlgorithm
		expectError bool
	}{
		{"RSA", "RSA", x509.RSA, false},
		{"ECDSA", "ECDSA", x509.ECDSA, false},
		{"ED25519", "ED25519", x509.Ed25519, false},
		{"lowercase rsa", "rsa", x509.RSA, false},
		{"lowercase ecdsa", "ecdsa", x509.ECDSA, false},
		{"lowercase ed25519", "ed25519", x509.Ed25519, false},
		{"with whitespace", "  RSA  ", x509.RSA, false},
		{"unknown algorithm", "DSA", x509.UnknownPublicKeyAlgorithm, true},
		{"empty string", "", x509.UnknownPublicKeyAlgorithm, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseKeyAlgorithm(tc.input)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseCurve(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    elliptic.Curve
		expectError bool
	}{
		{"P224", "P224", elliptic.P224(), false},
		{"P-224", "P-224", elliptic.P224(), false},
		{"P256", "P256", elliptic.P256(), false},
		{"P-256", "P-256", elliptic.P256(), false},
		{"P384", "P384", elliptic.P384(), false},
		{"P-384", "P-384", elliptic.P384(), false},
		{"P521", "P521", elliptic.P521(), false},
		{"P-521", "P-521", elliptic.P521(), false},
		{"lowercase p256", "p256", elliptic.P256(), false},
		{"with whitespace", "  P256  ", elliptic.P256(), false},
		{"unknown curve", "P192", nil, true},
		{"empty string", "", nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseCurve(tc.input)
			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestAvailableHashes(t *testing.T) {
	hashes := AvailableHashes()

	expectedHashes := map[string]crypto.Hash{
		"SHA-1":   crypto.SHA1,
		"SHA-224": crypto.SHA224,
		"SHA-256": crypto.SHA256,
		"SHA-384": crypto.SHA384,
		"SHA-512": crypto.SHA512,
	}

	assert.Equal(t, len(expectedHashes), len(hashes))

	for name, expected := range expectedHashes {
		actual, ok := hashes[name]
		assert.True(t, ok, "missing hash: %s", name)
		assert.Equal(t, expected, actual)
	}
}
