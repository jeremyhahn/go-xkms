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

package grpc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestParseHashAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		hashStr  string
		expected crypto.Hash
	}{
		{
			name:     "Empty string defaults to SHA256",
			hashStr:  "",
			expected: crypto.SHA256,
		},
		{
			name:     "SHA256",
			hashStr:  "SHA256",
			expected: crypto.SHA256,
		},
		{
			name:     "SHA384",
			hashStr:  "SHA384",
			expected: crypto.SHA384,
		},
		{
			name:     "SHA512",
			hashStr:  "SHA512",
			expected: crypto.SHA512,
		},
		{
			name:     "Unknown defaults to SHA256",
			hashStr:  "unknown",
			expected: crypto.SHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHashAlgorithm(tt.hashStr)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestExtractPublicKeyPEM(t *testing.T) {
	t.Run("RSA key", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		pem, err := extractPublicKeyPEM(privKey)
		if err != nil {
			t.Errorf("extractPublicKeyPEM failed: %v", err)
		}
		if !strings.Contains(pem, "BEGIN PUBLIC KEY") {
			t.Error("PEM does not contain public key header")
		}
		if !strings.Contains(pem, "END PUBLIC KEY") {
			t.Error("PEM does not contain public key footer")
		}
	})

	t.Run("ECDSA key", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		pem, err := extractPublicKeyPEM(privKey)
		if err != nil {
			t.Errorf("extractPublicKeyPEM failed: %v", err)
		}
		if !strings.Contains(pem, "BEGIN PUBLIC KEY") {
			t.Error("PEM does not contain public key header")
		}
	})

	t.Run("Ed25519 key", func(t *testing.T) {
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		pem, err := extractPublicKeyPEM(privKey)
		if err != nil {
			t.Errorf("extractPublicKeyPEM failed: %v", err)
		}
		if !strings.Contains(pem, "BEGIN PUBLIC KEY") {
			t.Error("PEM does not contain public key header")
		}
	})

	t.Run("Unsupported key type", func(t *testing.T) {
		_, err := extractPublicKeyPEM("invalid-key")
		if err == nil {
			t.Error("Expected error for unsupported key type")
		}
	})
}

func TestParseCertFromPEM(t *testing.T) {
	// Generate a test certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	validPEM := encodeCertToPEM(cert)

	t.Run("Valid PEM", func(t *testing.T) {
		parsed, err := parseCertFromPEM(validPEM)
		if err != nil {
			t.Errorf("parseCertFromPEM failed: %v", err)
		}
		if parsed == nil {
			t.Error("Parsed certificate is nil")
		}
	})

	t.Run("Invalid PEM - not a certificate", func(t *testing.T) {
		invalidPEM := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC
-----END PRIVATE KEY-----`
		_, err := parseCertFromPEM(invalidPEM)
		if err == nil {
			t.Error("Expected error for non-certificate PEM")
		}
	})

	t.Run("Invalid PEM - no PEM block", func(t *testing.T) {
		_, err := parseCertFromPEM("not a pem")
		if err == nil {
			t.Error("Expected error for invalid PEM")
		}
	})
}

func TestEncodeCertToPEM(t *testing.T) {
	// Generate a test certificate
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	pem := encodeCertToPEM(cert)
	if !strings.Contains(pem, "BEGIN CERTIFICATE") {
		t.Error("PEM does not contain certificate header")
	}
	if !strings.Contains(pem, "END CERTIFICATE") {
		t.Error("PEM does not contain certificate footer")
	}
}

func TestEncodePrivateKeyToPEM(t *testing.T) {
	t.Run("RSA key", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		pem, err := encodePrivateKeyToPEM(privKey)
		if err != nil {
			t.Errorf("encodePrivateKeyToPEM failed: %v", err)
		}
		if !strings.Contains(pem, "BEGIN RSA PRIVATE KEY") {
			t.Error("PEM does not contain RSA private key header")
		}
	})

	t.Run("ECDSA key", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		pem, err := encodePrivateKeyToPEM(privKey)
		if err != nil {
			t.Errorf("encodePrivateKeyToPEM failed: %v", err)
		}
		if !strings.Contains(pem, "BEGIN EC PRIVATE KEY") {
			t.Error("PEM does not contain EC private key header")
		}
	})

	t.Run("Ed25519 key", func(t *testing.T) {
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate Ed25519 key: %v", err)
		}

		pem, err := encodePrivateKeyToPEM(privKey)
		if err != nil {
			t.Errorf("encodePrivateKeyToPEM failed: %v", err)
		}
		if !strings.Contains(pem, "BEGIN PRIVATE KEY") {
			t.Error("PEM does not contain private key header")
		}
	})

	t.Run("Unsupported key type", func(t *testing.T) {
		_, err := encodePrivateKeyToPEM("invalid-key")
		if err == nil {
			t.Error("Expected error for unsupported key type")
		}
	})
}

func TestGetAlgorithmString(t *testing.T) {
	tests := []struct {
		name     string
		attrs    *types.KeyAttributes
		expected string
	}{
		{
			name: "Symmetric algorithm",
			attrs: &types.KeyAttributes{
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
			expected: string(types.SymmetricAES256GCM),
		},
		{
			name: "RSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.RSA,
			},
			expected: x509.RSA.String(),
		},
		{
			name: "ECDSA algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.ECDSA,
			},
			expected: x509.ECDSA.String(),
		},
		{
			name: "Ed25519 algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.Ed25519,
			},
			expected: x509.Ed25519.String(),
		},
		{
			name: "Unknown algorithm",
			attrs: &types.KeyAttributes{
				KeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
			},
			expected: "",
		},
		{
			name: "Symmetric takes precedence",
			attrs: &types.KeyAttributes{
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				KeyAlgorithm:       x509.RSA,
			},
			expected: string(types.SymmetricAES256GCM),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getAlgorithmString(tt.attrs)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}
