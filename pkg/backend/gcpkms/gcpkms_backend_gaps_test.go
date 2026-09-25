// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build gcpkms

package gcpkms

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// validTestServiceAccountJSON is a syntactically and cryptographically
// valid (freshly generated, single-use, never registered with GCP) service
// account key. NewBackend's CredentialsJSON path hands this to
// google.golang.org/api/option.WithCredentialsJSON, which parses the PEM
// key and builds a token source without ever dialing GCP (the gRPC client
// connects lazily on first RPC) -- so this proves the CredentialsJSON
// option-building branch and successful client construction without
// contacting any real GCP endpoint.
const validTestServiceAccountJSON = `{
	"type": "service_account",
	"project_id": "test-project",
	"private_key_id": "abc123",
	"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDLD4ZTSNO+spr/\nY3sFZNA3NP2jkI6cdtWBxh/YXUlL6ITKRD/gbf77vCtfuYVEcnL+ItzTaFzON94n\n+0iuwoieyltKjWSgEZ4c5dLxV4avKmn1quW2g3kE80RACil/v28g8P+PTNCPwiJ1\n93waWV12dEwUaDX5mL3lscn0FwWbVFCP07YSktzI8TTzStbq2JmIbVrRtHMvPfL0\naImfxYZlvOM5wSLdw+EEuE8U5EIsvLtjXSEISO+dvHLsH9SQOoSWz+9cJv4Y5Onh\nC+NpKrpp74K3sv6XNnUWVtZz8OxjJQJmbZCiN/g6dWHr8ouWaaxSMfB99kcklnBJ\njWLEnUUpAgMBAAECggEAB5DD2wIgz1ff0BwpxmfJWHv9DsLBN+8P0F6f/zEJCS7c\n2ib791lgkDvLuIVDjbny99pLDUDlMiGP4/FgnRAYK679ZVy5K2NCzaEN+RykDyvT\npG7OjJUTLNzZG+4p60UKcEB82pUizr3mQyw2m+ehxJ/H7WgZomf7j9/rm7y3Ymoe\n2b0k5IfZEIYGi0umQ/6lv8wQ3kXsPNBbsa11Ui1ibgqsQWNgIsLt68A4ceeyuTTE\npNHP0MuXd2rj3P2oAduSJ6Pz036HC5k15xsCTNET+oCba8HpCTxHYKhii7iK61CY\nmIdhL4oI/kmxwr538VNSzjlkBLvT72r5T61FOet7ywKBgQD3JbP2RiVqXZjtC7f5\ntXSWXu1iezBulL8dPhGpKdp0on8Qde6xfBhWT56KYdHXpWGWevDbMa6qvIIDSqcE\nI3+TjvKlqZzmn+A9kpB+3wewZDfbly/9fwx26XodmxXVdf2bL3xQswZVwD/xAOHN\nhLrPah+3qblKoLSisavKx+sEjwKBgQDSVY4YcRE9M1AF/SCCcXR92Nuy8b0NQ7s3\nQvJss/nq8Bub7N/w5sMlERkmqalNCIlRwGrqc6fyqk8rcUMP01DLR+3DkVC2v9JG\ngKOHjz0U/ofZH5cBt1s1ixryEpRAwwiMVhqLMUAerunQw449rF48iwvUTZ5y935q\nXwXwtIimxwKBgQCALhfGFN926RBVcQx8ADZ1fspTl1ypHZB5VCXIvKJGd7i7Cs8/\nUgM1UJoDX3R8CZQxfZXJuVzDxH0Rw/gXV2nlV/BVJ0DvA+BDTu6OPpI4U+H8i88i\nBHCsg68IB9UtHsLnZ5tsJ02Tz9/Z2QFDnCFfTcUhdm9ZWzwUXV2iEEm91QKBgQCL\nsgUBGL9xXU4t3BOmb0IGf2xTahi84ZpLNqyaI+K99iDwK6AEeM9tI/EHa7GlFyFU\n6a5Y7t3B3vlcCgqXTSshCDHTLQVlivtWlgOGek0AT5jcTQ3XNvdeFXidBFfwt1hL\nFLjmb5x9hICIhglHzt576YG+zJqLEvOkJF5moxELawKBgQDj0YaY5ouUwkLsaHls\ngqsz2QDeoE+Lr3AWAJxwT+JHL1DmwqyWkd8W6bQiV6kIAN2hBPl4RqzAvXjrVBly\nbDdR7HUzFh/6wQVpFEc2vCDUYBEAXKXn3tz97j3Xwm8hygB1NWxetm57y8kXZL+w\nSZwDR/TfmlJL05smOi70NPLqrA==\n-----END PRIVATE KEY-----\n",
	"client_email": "test@test-project.iam.gserviceaccount.com",
	"client_id": "123456789",
	"auth_uri": "https://accounts.google.com/o/oauth2/auth",
	"token_uri": "https://oauth2.googleapis.com/token"
}`

func baseGCPKMSConfig() *Config {
	return &Config{
		ProjectID:   "test-project",
		LocationID:  "us-central1",
		KeyRingID:   "test-keyring",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
}

// TestNewBackend_CredentialsJSON proves NewBackend's CredentialsJSON branch
// builds a working client from a valid service account key.
func TestNewBackend_CredentialsJSON(t *testing.T) {
	config := baseGCPKMSConfig()
	config.CredentialsJSON = []byte(validTestServiceAccountJSON)

	b, err := NewBackend(context.Background(), config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	if b == nil {
		t.Fatal("NewBackend() returned nil backend")
	}
}

// TestNewBackend_CredentialsJSON_Malformed proves a malformed private key
// in CredentialsJSON surfaces a wrapped "failed to create KMS client"
// error instead of silently building a client with no usable credentials.
func TestNewBackend_CredentialsJSON_Malformed(t *testing.T) {
	config := baseGCPKMSConfig()
	config.CredentialsJSON = []byte(`{"type":"service_account","private_key":"not a real key","client_email":"test@test.iam.gserviceaccount.com"}`)

	_, err := NewBackend(context.Background(), config)
	if err == nil {
		t.Fatal("NewBackend() expected error for malformed CredentialsJSON, got nil")
	}
	if !strings.Contains(err.Error(), "failed to create KMS client") {
		t.Errorf("NewBackend() error = %v, want it to mention KMS client creation", err)
	}
}

// TestNewBackend_CredentialsFile proves NewBackend's CredentialsFile branch
// reads and applies a valid service account key from disk.
func TestNewBackend_CredentialsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	if err := os.WriteFile(path, []byte(validTestServiceAccountJSON), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	config := baseGCPKMSConfig()
	config.CredentialsFile = path

	b, err := NewBackend(context.Background(), config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	if b == nil {
		t.Fatal("NewBackend() returned nil backend")
	}
}

// TestNewBackend_InsecureWithEndpoint proves NewBackend's Insecure branch
// (plaintext gRPC without authentication, for local emulators) builds a
// client against a custom Endpoint without dialing it: the gRPC client
// connects lazily on first RPC, so this proves the option-building branch
// without contacting anything.
func TestNewBackend_InsecureWithEndpoint(t *testing.T) {
	config := baseGCPKMSConfig()
	config.Endpoint = "127.0.0.1:1"
	config.Insecure = true

	b, err := NewBackend(context.Background(), config)
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}
	if b == nil {
		t.Fatal("NewBackend() returned nil backend")
	}
}

// TestMapCurveToAlgorithm covers every branch of mapCurveToAlgorithm: the
// two supported curves and the unsupported-curve error, none of which
// GenerateECDSA's own tests exercise directly (they only ever request the
// P-256 default).
func TestMapCurveToAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		curve   elliptic.Curve
		wantErr bool
	}{
		{name: "P-256", curve: elliptic.P256()},
		{name: "P-384", curve: elliptic.P384()},
		{name: "unsupported P-521", curve: elliptic.P521(), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mapCurveToAlgorithm(tt.curve)
			if (err != nil) != tt.wantErr {
				t.Errorf("mapCurveToAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestGCPKMSSymmetricKey_Raw proves gcpKMSSymmetricKey.Raw refuses to
// expose key material, since it never leaves GCP KMS.
func TestGCPKMSSymmetricKey_Raw(t *testing.T) {
	k := &gcpKMSSymmetricKey{keyName: "test-key", algorithm: "aes256-gcm", keySize: 256}
	if _, err := k.Raw(); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("Raw() error = %v, want ErrNotSupported", err)
	}
}

// TestMapWrappingAlgorithmToImportMethod covers every branch, including the
// two distinct WrappingAlgorithm values that both map to
// RSA_OAEP_4096_SHA256, which existing GetImportParameters-level tests
// never exercised directly.
func TestMapWrappingAlgorithmToImportMethod(t *testing.T) {
	tests := []struct {
		name    string
		alg     backend.WrappingAlgorithm
		wantErr bool
	}{
		{name: "RSA_OAEP_3072_SHA256_AES_256", alg: backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256},
		{name: "RSA_OAEP_4096_SHA256_AES_256", alg: backend.WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256},
		{name: "RSA_OAEP_4096_SHA256", alg: backend.WrappingAlgorithmRSA_OAEP_4096_SHA256},
		{name: "RSAES_OAEP_SHA_256 alias", alg: backend.WrappingAlgorithmRSAES_OAEP_SHA_256},
		{name: "unsupported", alg: backend.WrappingAlgorithmRSAES_OAEP_SHA_1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mapWrappingAlgorithmToImportMethod(tt.alg)
			if (err != nil) != tt.wantErr {
				t.Errorf("mapWrappingAlgorithmToImportMethod() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMapKeyAttributesToAlgorithm covers every branch: symmetric, RSA,
// ECDSA, and an unsupported key algorithm.
func TestMapKeyAttributesToAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		wantErr bool
	}{
		{name: "symmetric", attrs: &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES256GCM}},
		{name: "RSA", attrs: &types.KeyAttributes{KeyAlgorithm: x509.RSA}},
		{name: "ECDSA", attrs: &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}},
		{name: "unsupported", attrs: &types.KeyAttributes{KeyAlgorithm: x509.Ed25519}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mapKeyAttributesToAlgorithm(tt.attrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("mapKeyAttributesToAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestDetermineKeySpec covers every branch: each symmetric algorithm size
// and each asymmetric key algorithm, including the unknown-algorithm
// fallback.
func TestDetermineKeySpec(t *testing.T) {
	tests := []struct {
		name  string
		attrs *types.KeyAttributes
		want  string
	}{
		{name: "AES-192", attrs: &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES192GCM}, want: "AES_192"},
		{name: "AES-256", attrs: &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES256GCM}, want: "AES_256"},
		{name: "AES-128 (default symmetric case)", attrs: &types.KeyAttributes{SymmetricAlgorithm: types.SymmetricAES128GCM}, want: "AES_128"},
		{name: "RSA", attrs: &types.KeyAttributes{KeyAlgorithm: x509.RSA}, want: "RSA_2048"},
		{name: "ECDSA", attrs: &types.KeyAttributes{KeyAlgorithm: x509.ECDSA}, want: "EC_P256"},
		{name: "unknown", attrs: &types.KeyAttributes{KeyAlgorithm: x509.Ed25519}, want: "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := determineKeySpec(tt.attrs); got != tt.want {
				t.Errorf("determineKeySpec() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExportKey_NilAttributes proves ExportKey rejects nil attributes
// before reaching the always-refuse response.
func TestExportKey_NilAttributes(t *testing.T) {
	b, err := NewBackendWithClient(baseGCPKMSConfig(), &MockKMSClient{})
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	if _, err := b.ExportKey(context.Background(), nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKey(nil) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestWaitForKeyEnabled_GetVersionError proves waitForKeyEnabled surfaces a
// GetCryptoKeyVersion RPC failure wrapped rather than retrying forever or
// reporting success.
func TestWaitForKeyEnabled_GetVersionError(t *testing.T) {
	mockClient := &MockKMSClient{
		GetCryptoKeyVersionFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
			return nil, errors.New("kms: transient failure")
		},
	}
	b, err := NewBackendWithClient(baseGCPKMSConfig(), mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	if err := b.waitForKeyEnabled(context.Background(), "test-version-name", time.Second); err == nil {
		t.Error("waitForKeyEnabled() expected error when GetCryptoKeyVersion fails, got nil")
	}
}

// TestWaitForKeyEnabled_UnexpectedState proves waitForKeyEnabled reports an
// error immediately for a version state that is neither ENABLED nor
// PENDING_GENERATION (e.g. DESTROYED), instead of polling until timeout.
func TestWaitForKeyEnabled_UnexpectedState(t *testing.T) {
	mockClient := &MockKMSClient{
		GetCryptoKeyVersionFunc: func(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest, opts ...interface{}) (*kmspb.CryptoKeyVersion, error) {
			return &kmspb.CryptoKeyVersion{State: kmspb.CryptoKeyVersion_DESTROYED}, nil
		},
	}
	b, err := NewBackendWithClient(baseGCPKMSConfig(), mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	if err := b.waitForKeyEnabled(context.Background(), "test-version-name", time.Second); err == nil {
		t.Error("waitForKeyEnabled() expected error for an unexpected version state, got nil")
	}
}
