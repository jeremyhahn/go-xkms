package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func TestParsePublicKeyRSAUnit(t *testing.T) {
	// Generate a real RSA key for testing
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Marshal to DER format
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	// Parse it back
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("parsed key is not RSA")
	}

	if rsaPub.N.Cmp(rsaKey.PublicKey.N) != 0 { //nolint:staticcheck // QF1008
		t.Error("N value mismatch")
	}
	if rsaPub.E != rsaKey.PublicKey.E { //nolint:staticcheck // QF1008
		t.Error("E value mismatch")
	}
}

func TestParsePublicKeyECDSAUnit(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			ecKey, err := ecdsa.GenerateKey(c.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate ECDSA key: %v", err)
			}

			der, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
			if err != nil {
				t.Fatalf("failed to marshal public key: %v", err)
			}

			pub, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Fatalf("failed to parse public key: %v", err)
			}

			ecPub, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				t.Fatal("parsed key is not ECDSA")
			}

			if ecPub.X.Cmp(ecKey.PublicKey.X) != 0 { //nolint:staticcheck // QF1008
				t.Error("X value mismatch")
			}
			if ecPub.Y.Cmp(ecKey.PublicKey.Y) != 0 { //nolint:staticcheck // QF1008
				t.Error("Y value mismatch")
			}
			if ecPub.Curve.Params().Name != c.curve.Params().Name {
				t.Errorf("curve mismatch: got %s, want %s", ecPub.Curve.Params().Name, c.curve.Params().Name)
			}
		})
	}
}

func TestParsePublicKeyInvalidUnit(t *testing.T) {
	tests := []struct {
		name    string
		der     []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			der:     []byte{},
			wantErr: true,
		},
		{
			name:    "invalid ASN.1",
			der:     []byte{0xFF, 0xFF, 0xFF},
			wantErr: true,
		},
		{
			name:    "truncated DER",
			der:     []byte{0x30, 0x82, 0x01, 0x22},
			wantErr: true,
		},
		{
			name:    "random bytes",
			der:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := x509.ParsePKIXPublicKey(tt.der)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestMarshalPKIXPublicKeyUnit(t *testing.T) {
	tests := []struct {
		name    string
		keyGen  func() (interface{}, error)
		wantErr bool
	}{
		{
			name: "RSA 2048",
			keyGen: func() (interface{}, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
			wantErr: false,
		},
		{
			name: "ECDSA P-256",
			keyGen: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
			wantErr: false,
		},
		{
			name: "ECDSA P-384",
			keyGen: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, err := tt.keyGen()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			der, err := x509.MarshalPKIXPublicKey(pub)
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

			if len(der) == 0 {
				t.Error("DER encoding should not be empty")
			}

			// Verify round trip
			parsed, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				t.Errorf("failed to parse encoded key: %v", err)
			}

			if parsed == nil {
				t.Error("parsed key should not be nil")
			}
		})
	}
}

func TestRSAPublicKeyComponentsUnit(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Test N (modulus)
	n := rsaKey.PublicKey.N //nolint:staticcheck // QF1008
	if n == nil {
		t.Fatal("N should not be nil")
	}
	if n.BitLen() != 2048 {
		t.Errorf("N bit length = %d, want 2048", n.BitLen())
	}

	// Test E (public exponent)
	e := rsaKey.PublicKey.E //nolint:staticcheck // QF1008
	if e != 65537 {         // Common default
		t.Errorf("E = %d, want 65537", e)
	}

	// Test N bytes length
	nBytes := n.Bytes()
	if len(nBytes) < 255 || len(nBytes) > 257 {
		t.Errorf("N bytes length = %d, expected around 256", len(nBytes))
	}
}

func TestECDSAPublicKeyComponentsUnit(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	// Test X and Y coordinates
	if ecKey.PublicKey.X == nil { //nolint:staticcheck // QF1008
		t.Fatal("X should not be nil")
	}
	if ecKey.PublicKey.Y == nil { //nolint:staticcheck // QF1008
		t.Fatal("Y should not be nil")
	}

	// Test curve
	if ecKey.PublicKey.Curve == nil { //nolint:staticcheck // QF1008
		t.Fatal("Curve should not be nil")
	}
	if ecKey.PublicKey.Curve.Params().Name != "P-256" {
		t.Errorf("curve name = %s, want P-256", ecKey.PublicKey.Curve.Params().Name)
	}

	// Test coordinate sizes (P-256 coordinates should be 32 bytes)
	xBytes := ecKey.PublicKey.X.Bytes() //nolint:staticcheck // QF1008
	yBytes := ecKey.PublicKey.Y.Bytes() //nolint:staticcheck // QF1008
	if len(xBytes) > 32 {
		t.Errorf("X bytes length = %d, max expected 32", len(xBytes))
	}
	if len(yBytes) > 32 {
		t.Errorf("Y bytes length = %d, max expected 32", len(yBytes))
	}

	// Verify point is on curve
	if !ecKey.PublicKey.Curve.IsOnCurve(ecKey.PublicKey.X, ecKey.PublicKey.Y) { //nolint:staticcheck // QF1008
		t.Error("point should be on curve")
	}
}

func TestPublicKeyTypeAssertionUnit(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name    string
		key     interface{}
		isRSA   bool
		isECDSA bool
	}{
		{
			name:    "RSA public key",
			key:     &rsaKey.PublicKey,
			isRSA:   true,
			isECDSA: false,
		},
		{
			name:    "ECDSA public key",
			key:     &ecKey.PublicKey,
			isRSA:   false,
			isECDSA: true,
		},
		{
			name:    "string type",
			key:     "not a key",
			isRSA:   false,
			isECDSA: false,
		},
		{
			name:    "nil",
			key:     nil,
			isRSA:   false,
			isECDSA: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, isRSA := tt.key.(*rsa.PublicKey)
			_, isECDSA := tt.key.(*ecdsa.PublicKey)

			if isRSA != tt.isRSA {
				t.Errorf("RSA assertion = %v, want %v", isRSA, tt.isRSA)
			}
			if isECDSA != tt.isECDSA {
				t.Errorf("ECDSA assertion = %v, want %v", isECDSA, tt.isECDSA)
			}
		})
	}
}

func TestKeyAlgorithmDetectionUnit(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	tests := []struct {
		name      string
		key       interface{}
		wantAlgo  x509.PublicKeyAlgorithm
		wantError bool
	}{
		{
			name:      "RSA key",
			key:       &rsaKey.PublicKey,
			wantAlgo:  x509.RSA,
			wantError: false,
		},
		{
			name:      "ECDSA key",
			key:       &ecKey.PublicKey,
			wantAlgo:  x509.ECDSA,
			wantError: false,
		},
		{
			name:      "unknown type",
			key:       "string",
			wantAlgo:  x509.UnknownPublicKeyAlgorithm,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var algo x509.PublicKeyAlgorithm
			switch tt.key.(type) {
			case *rsa.PublicKey:
				algo = x509.RSA
			case *ecdsa.PublicKey:
				algo = x509.ECDSA
			default:
				algo = x509.UnknownPublicKeyAlgorithm
			}

			if algo != tt.wantAlgo {
				t.Errorf("algorithm = %v, want %v", algo, tt.wantAlgo)
			}
		})
	}
}
