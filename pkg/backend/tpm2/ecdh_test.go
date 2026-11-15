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

package tpm2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestDeriveKeyECDH_Success tests successful ECDH key derivation
func TestDeriveKeyECDH_Success(t *testing.T) {
	// Create mock TPM with successful ECDH response
	mockTPM := &mockTPM{
		ssrkAttrsValue: &types.KeyAttributes{
			CN: "ssrk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
		// Return a mock 32-byte shared secret
		ecdhZGenValue: make([]byte, 32),
	}

	// Create mock key backend
	mockBackend := &mockKeyBackend{
		getData: []byte("mock-blob-data"),
	}

	// Create backend
	backend := &Backend{
		tpm:        mockTPM,
		keyBackend: mockBackend,
		srkAttrs: &types.KeyAttributes{
			CN: "srk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
		closed: false,
	}

	// Generate a test peer public key (P-256)
	peerPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate peer key: %v", err)
	}
	peerPubKeyDER, err := x509.MarshalPKIXPublicKey(&peerPrivKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal peer public key: %v", err)
	}

	// Create private key attributes
	privateKeyAttrs := &types.KeyAttributes{
		CN:           "test-ecdh-key",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		Parent: &types.KeyAttributes{
			CN: "srk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
	}

	// Test with default KDF params
	kdfParams := types.DefaultKDFParams()

	// Perform ECDH key derivation
	derivedKey, err := backend.DeriveKeyECDH(context.Background(), privateKeyAttrs, peerPubKeyDER, kdfParams)
	if err != nil {
		t.Fatalf("DeriveKeyECDH failed: %v", err)
	}

	// Verify derived key length matches requested length
	if len(derivedKey) != kdfParams.KeyLength {
		t.Errorf("derived key length = %d, want %d", len(derivedKey), kdfParams.KeyLength)
	}
}

// TestDeriveKeyECDH_NilAttrs tests error handling for nil attributes
func TestDeriveKeyECDH_NilAttrs(t *testing.T) {
	backend := &Backend{
		closed: false,
	}

	_, err := backend.DeriveKeyECDH(context.Background(), nil, []byte{0x04}, nil)
	if !errors.Is(err, ErrInvalidKeyAttributes) {
		t.Errorf("expected ErrInvalidKeyAttributes, got %v", err)
	}
}

// TestDeriveKeyECDH_EmptyPeerKey tests error handling for empty peer public key
func TestDeriveKeyECDH_EmptyPeerKey(t *testing.T) {
	backend := &Backend{
		closed: false,
	}

	attrs := &types.KeyAttributes{
		CN: "test-key",
	}

	_, err := backend.DeriveKeyECDH(context.Background(), attrs, nil, nil)
	if err == nil {
		t.Error("expected error for empty peer public key")
	}
}

// TestDeriveKeyECDH_BackendClosed tests error handling when backend is closed
func TestDeriveKeyECDH_BackendClosed(t *testing.T) {
	backend := &Backend{
		closed: true,
	}

	attrs := &types.KeyAttributes{
		CN: "test-key",
	}

	_, err := backend.DeriveKeyECDH(context.Background(), attrs, []byte{0x04}, nil)
	if !errors.Is(err, ErrNotInitialized) {
		t.Errorf("expected ErrNotInitialized, got %v", err)
	}
}

// TestDeriveKeyECDH_InvalidKDFParams tests error handling for invalid KDF params
func TestDeriveKeyECDH_InvalidKDFParams(t *testing.T) {
	backend := &Backend{
		closed: false,
		srkAttrs: &types.KeyAttributes{
			CN: "srk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
	}

	attrs := &types.KeyAttributes{
		CN: "test-key",
	}

	// Invalid KDF params (negative key length)
	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		KeyLength: -1,
	}

	_, err := backend.DeriveKeyECDH(context.Background(), attrs, []byte{0x04, 0x01, 0x02}, kdfParams)
	if err == nil {
		t.Error("expected error for invalid KDF params")
	}
}

// TestDeriveKeyECDH_ECDHZGenError tests error handling when TPM ECDH operation fails
func TestDeriveKeyECDH_ECDHZGenError(t *testing.T) {
	expectedErr := errors.New("TPM ECDH error")
	mockTPM := &mockTPM{
		ssrkAttrsValue: &types.KeyAttributes{
			CN: "ssrk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
		ecdhZGenErr: expectedErr,
	}

	mockBackend := &mockKeyBackend{
		getData: []byte("mock-blob-data"),
	}

	backend := &Backend{
		tpm:        mockTPM,
		keyBackend: mockBackend,
		srkAttrs: &types.KeyAttributes{
			CN: "srk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
		closed: false,
	}

	// Generate peer public key
	peerPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	peerPubKeyDER, _ := x509.MarshalPKIXPublicKey(&peerPrivKey.PublicKey)

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		Parent: &types.KeyAttributes{
			CN: "srk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
	}

	_, err := backend.DeriveKeyECDH(context.Background(), attrs, peerPubKeyDER, nil)
	if err == nil {
		t.Error("expected error from TPM ECDH operation")
	}
}

// TestDeriveKeyECDH_SEC1Format tests parsing of SEC1 uncompressed point format
func TestDeriveKeyECDH_SEC1Format(t *testing.T) {
	mockTPM := &mockTPM{
		ssrkAttrsValue: &types.KeyAttributes{
			CN: "ssrk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
		ecdhZGenValue: make([]byte, 32),
	}

	mockBackend := &mockKeyBackend{
		getData: []byte("mock-blob-data"),
	}

	backend := &Backend{
		tpm:        mockTPM,
		keyBackend: mockBackend,
		srkAttrs: &types.KeyAttributes{
			CN: "srk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
		closed: false,
	}

	// Generate a peer public key and convert to SEC1 format
	peerPrivKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1Point, _ := peerPrivKey.PublicKey.Bytes()

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
		Parent: &types.KeyAttributes{
			CN: "srk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
	}

	derivedKey, err := backend.DeriveKeyECDH(context.Background(), attrs, sec1Point, nil)
	if err != nil {
		t.Fatalf("DeriveKeyECDH with SEC1 format failed: %v", err)
	}

	if len(derivedKey) != 32 { // Default key length
		t.Errorf("derived key length = %d, want 32", len(derivedKey))
	}
}

// TestDeriveKeyECDH_CurveMismatch tests error handling for curve mismatch
func TestDeriveKeyECDH_CurveMismatch(t *testing.T) {
	mockTPM := &mockTPM{
		ssrkAttrsValue: &types.KeyAttributes{
			CN: "ssrk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
		ecdhZGenValue: make([]byte, 32),
	}

	mockBackend := &mockKeyBackend{
		getData: []byte("mock-blob-data"),
	}

	backend := &Backend{
		tpm:        mockTPM,
		keyBackend: mockBackend,
		srkAttrs: &types.KeyAttributes{
			CN: "srk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
		closed: false,
	}

	// Generate a P-384 peer public key
	peerPrivKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	peerPubKeyDER, _ := x509.MarshalPKIXPublicKey(&peerPrivKey.PublicKey)

	// Create P-256 private key attributes (curve mismatch)
	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(), // Different from peer's P-384
		},
		Parent: &types.KeyAttributes{
			CN: "srk",
			TPMAttributes: &types.TPMAttributes{
				Handle: tpm2.TPMHandle(0x81000001),
			},
		},
	}

	_, err := backend.DeriveKeyECDH(context.Background(), attrs, peerPubKeyDER, nil)
	if err == nil {
		t.Error("expected error for curve mismatch")
	}
}

// TestSupportedCurves tests that SupportedCurves returns expected values
func TestSupportedCurves(t *testing.T) {
	backend := &Backend{}

	curves := backend.SupportedCurves()

	expectedCurves := []string{"P-256", "P-384", "P-521"}
	if len(curves) != len(expectedCurves) {
		t.Errorf("SupportedCurves returned %d curves, want %d", len(curves), len(expectedCurves))
	}

	curveSet := make(map[string]bool)
	for _, c := range curves {
		curveSet[c] = true
	}

	for _, expected := range expectedCurves {
		if !curveSet[expected] {
			t.Errorf("SupportedCurves missing expected curve: %s", expected)
		}
	}
}

// TestParsePeerPublicKey_SEC1Format tests parsing SEC1 uncompressed point
func TestParsePeerPublicKey_SEC1Format(t *testing.T) {
	backend := &Backend{}

	testCases := []struct {
		name      string
		curve     elliptic.Curve
		curveName string
	}{
		{"P-256", elliptic.P256(), "P-256"},
		{"P-384", elliptic.P384(), "P-384"},
		{"P-521", elliptic.P521(), "P-521"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate a key for the curve
			privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			// Convert to SEC1 uncompressed format
			sec1Point, _ := privKey.PublicKey.Bytes()

			// Parse the key
			eccPoint, curve, err := backend.parsePeerPublicKey(sec1Point)
			if err != nil {
				t.Fatalf("parsePeerPublicKey failed: %v", err)
			}

			// Verify the curve
			if curve.Params().Name != tc.curve.Params().Name {
				t.Errorf("curve = %s, want %s", curve.Params().Name, tc.curve.Params().Name)
			}

			// Verify the point coordinates are not empty
			if len(eccPoint.X.Buffer) == 0 || len(eccPoint.Y.Buffer) == 0 {
				t.Error("ECC point coordinates are empty")
			}
		})
	}
}

// TestParsePeerPublicKey_InvalidFormat tests error handling for invalid format
func TestParsePeerPublicKey_InvalidFormat(t *testing.T) {
	backend := &Backend{}

	testCases := []struct {
		name  string
		input []byte
	}{
		{"Empty", []byte{}},
		{"TooShort", []byte{0x04, 0x01}},
		{"InvalidPrefix", []byte{0x02, 0x01, 0x02, 0x03}},
		{"Garbage", []byte("not a public key")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := backend.parsePeerPublicKey(tc.input)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

// TestParsePeerPublicKey_NonECDSA tests error handling for non-ECDSA key
func TestParsePeerPublicKey_NonECDSA(t *testing.T) {
	backend := &Backend{}

	// Generate an RSA key
	rsaKey, err := generateTestRSAKey()
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Marshal to DER
	derBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}

	// Try to parse as ECDSA - should fail
	_, _, err = backend.parsePeerPublicKey(derBytes)
	if err == nil {
		t.Error("expected error for RSA key")
	}
}

// generateTestRSAKey generates an RSA key for testing
func generateTestRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}
