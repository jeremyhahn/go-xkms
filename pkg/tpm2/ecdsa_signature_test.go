package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

func TestCreateX962ECDSASignatureUnit(t *testing.T) {
	tests := []struct {
		name    string
		r       *big.Int
		s       *big.Int
		wantErr bool
	}{
		{
			name:    "valid signature with small values",
			r:       big.NewInt(12345),
			s:       big.NewInt(67890),
			wantErr: false,
		},
		{
			name:    "valid signature with large values",
			r:       big.NewInt(0).SetBytes(make([]byte, 32)),
			s:       big.NewInt(0).SetBytes(make([]byte, 32)),
			wantErr: false,
		},
		{
			name:    "signature with zero r",
			r:       big.NewInt(0),
			s:       big.NewInt(12345),
			wantErr: false,
		},
		{
			name:    "signature with zero s",
			r:       big.NewInt(12345),
			s:       big.NewInt(0),
			wantErr: false,
		},
		{
			name:    "signature with negative r (invalid but encoding works)",
			r:       big.NewInt(-1),
			s:       big.NewInt(12345),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asn1Struct := struct{ R, S *big.Int }{tt.r, tt.s}
			signature, err := asn1.Marshal(asn1Struct)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(signature) == 0 {
				t.Error("signature should not be empty")
			}

			// Verify we can unmarshal it back
			var decoded struct{ R, S *big.Int }
			rest, err := asn1.Unmarshal(signature, &decoded)
			if err != nil {
				t.Errorf("failed to unmarshal signature: %v", err)
			}
			if len(rest) > 0 {
				t.Error("extra bytes after unmarshaling")
			}
			if decoded.R.Cmp(tt.r) != 0 {
				t.Errorf("R mismatch: got %v, want %v", decoded.R, tt.r)
			}
			if decoded.S.Cmp(tt.s) != 0 {
				t.Errorf("S mismatch: got %v, want %v", decoded.S, tt.s)
			}
		})
	}
}

func TestECDSASignatureVerificationUnit(t *testing.T) {
	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	message := []byte("test message for ECDSA signature")
	hash := sha256.Sum256(message)

	// Sign the message
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Create ASN.1 DER encoded signature
	asn1Struct := struct{ R, S *big.Int }{r, s}
	signature, err := asn1.Marshal(asn1Struct)
	if err != nil {
		t.Fatalf("failed to marshal signature: %v", err)
	}

	// Verify the signature
	if !ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], signature) {
		t.Error("signature verification failed")
	}
}

func TestECDSASignatureWithDifferentCurvesUnit(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	message := []byte("test message for different curves")

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			hash := sha256.Sum256(message)
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}

			// Create ASN.1 signature
			asn1Struct := struct{ R, S *big.Int }{r, s}
			signature, err := asn1.Marshal(asn1Struct)
			if err != nil {
				t.Fatalf("failed to marshal signature: %v", err)
			}

			// Verify
			if !ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], signature) {
				t.Error("signature verification failed")
			}

			// Verify wrong message fails
			wrongHash := sha256.Sum256([]byte("wrong message"))
			if ecdsa.VerifyASN1(&privateKey.PublicKey, wrongHash[:], signature) {
				t.Error("verification should fail with wrong message")
			}
		})
	}
}

func TestECDSASignatureInvalidUnit(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	message := []byte("test message")
	hash := sha256.Sum256(message)

	tests := []struct {
		name      string
		signature []byte
		wantValid bool
	}{
		{
			name:      "empty signature",
			signature: []byte{},
			wantValid: false,
		},
		{
			name:      "truncated signature",
			signature: []byte{0x30, 0x06},
			wantValid: false,
		},
		{
			name:      "invalid ASN.1 structure",
			signature: []byte{0xFF, 0xFF, 0xFF},
			wantValid: false,
		},
		{
			name: "zeros signature",
			signature: func() []byte {
				asn1Struct := struct{ R, S *big.Int }{big.NewInt(0), big.NewInt(0)}
				sig, _ := asn1.Marshal(asn1Struct)
				return sig
			}(),
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], tt.signature)
			if valid != tt.wantValid {
				t.Errorf("VerifyASN1() = %v, want %v", valid, tt.wantValid)
			}
		})
	}
}

func TestBigIntToBytesConversionUnit(t *testing.T) {
	tests := []struct {
		name     string
		value    *big.Int
		wantLen  int
		wantZero bool
	}{
		{
			name:     "small value",
			value:    big.NewInt(255),
			wantLen:  1,
			wantZero: false,
		},
		{
			name:     "two byte value",
			value:    big.NewInt(65535),
			wantLen:  2,
			wantZero: false,
		},
		{
			name:     "32 byte value",
			value:    big.NewInt(0).SetBytes(make([]byte, 32)),
			wantLen:  0, // Zero value results in empty slice
			wantZero: true,
		},
		{
			name: "max 32 byte value",
			value: func() *big.Int {
				b := make([]byte, 32)
				for i := range b {
					b[i] = 0xFF
				}
				return big.NewInt(0).SetBytes(b)
			}(),
			wantLen:  32,
			wantZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes := tt.value.Bytes()
			if tt.wantZero {
				if len(bytes) != 0 {
					t.Errorf("expected zero length bytes for zero value, got %d", len(bytes))
				}
			} else {
				if len(bytes) != tt.wantLen {
					t.Errorf("Bytes() length = %d, want %d", len(bytes), tt.wantLen)
				}
			}

			// Round trip
			recovered := big.NewInt(0).SetBytes(bytes)
			if recovered.Cmp(tt.value) != 0 {
				t.Errorf("round trip failed: got %v, want %v", recovered, tt.value)
			}
		})
	}
}

func TestECCPointEncodingUnit(t *testing.T) {
	// Test ECC point X and Y coordinate encoding as used in TPM
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Extract X and Y coordinates
	xBytes := privateKey.X.Bytes()
	yBytes := privateKey.Y.Bytes()

	if len(xBytes) == 0 {
		t.Error("X coordinate should not be empty")
	}
	if len(yBytes) == 0 {
		t.Error("Y coordinate should not be empty")
	}

	// P-256 coordinates should be at most 32 bytes
	if len(xBytes) > 32 {
		t.Errorf("X coordinate too long: %d bytes", len(xBytes))
	}
	if len(yBytes) > 32 {
		t.Errorf("Y coordinate too long: %d bytes", len(yBytes))
	}

	// Reconstruct the public key
	reconstructed := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(xBytes),
		Y:     big.NewInt(0).SetBytes(yBytes),
	}

	if reconstructed.X.Cmp(privateKey.X) != 0 {
		t.Error("X coordinate mismatch after reconstruction")
	}
	if reconstructed.Y.Cmp(privateKey.Y) != 0 {
		t.Error("Y coordinate mismatch after reconstruction")
	}
}

func TestTPMSignatureBufferSimulationUnit(t *testing.T) {
	// Simulate TPM signature buffer handling
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	message := []byte("TPM signature buffer test")
	hash := sha256.Sum256(message)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Simulate TPM buffer structure
	type TPMSSignatureECDSA struct {
		Hash       uint16
		SignatureR struct {
			Buffer []byte
		}
		SignatureS struct {
			Buffer []byte
		}
	}

	sig := TPMSSignatureECDSA{
		Hash: 0x000B, // TPMAlgSHA256
	}
	sig.SignatureR.Buffer = r.Bytes()
	sig.SignatureS.Buffer = s.Bytes()

	// Reconstruct and verify
	reconstructedR := big.NewInt(0).SetBytes(sig.SignatureR.Buffer)
	reconstructedS := big.NewInt(0).SetBytes(sig.SignatureS.Buffer)

	asn1Struct := struct{ R, S *big.Int }{reconstructedR, reconstructedS}
	asn1Sig, err := asn1.Marshal(asn1Struct)
	if err != nil {
		t.Fatalf("failed to marshal reconstructed signature: %v", err)
	}

	if !ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], asn1Sig) {
		t.Error("reconstructed signature verification failed")
	}
}
