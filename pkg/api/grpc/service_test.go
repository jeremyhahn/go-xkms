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
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

func TestParseHashAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		hashStr  string
		expected crypto.Hash
		wantErr  bool
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
			name:     "SHA3-256",
			hashStr:  "SHA3-256",
			expected: crypto.SHA3_256,
		},
		// A name the caller did supply that does not resolve is an error, not
		// a SHA-256 substitution: the caller cannot tell a downgrade from
		// having got what it asked for.
		{
			name:    "Unknown is an error",
			hashStr: "unknown",
			wantErr: true,
		},
		{
			name:    "Weak hash is refused",
			hashStr: "MD5",
			wantErr: true,
		},
		{
			name:    "SHA-1 is refused",
			hashStr: "SHA-1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseHashAlgorithm(tt.hashStr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Expected an error for %q, got hash %v", tt.hashStr, result)
				}
				if !errors.Is(err, xkms.ErrInvalidHashFunction) {
					t.Errorf("Expected ErrInvalidHashFunction, got %v", err)
				}
				if result != 0 {
					t.Errorf("Expected the zero hash on refusal, got %v", result)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
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

func TestAlgorithmString(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attrs.AlgorithmString()
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}

	// A descriptor claiming both families must display the family
	// KeyAttributes.ID addresses it under. This transport's local
	// getAlgorithmString used to give SymmetricAlgorithm precedence over
	// KeyAlgorithm — the opposite of ID's order (go-xkms#336). The expected
	// value is computed from ID's own resolution (its final colon-separated
	// segment, lowercased there for storage) rather than hardcoded.
	t.Run("Two-family descriptor agrees with ID", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			KeyAlgorithm:       x509.RSA,
		}
		id := attrs.ID()
		want := id[strings.LastIndex(id, ":")+1:]
		result := attrs.AlgorithmString()
		if !strings.EqualFold(result, want) {
			t.Errorf("displayed algorithm %q disagrees with ID's family %q", result, want)
		}
	})
}
