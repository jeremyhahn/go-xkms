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

//go:build vault

package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	vault "github.com/hashicorp/vault/api"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestGetImportParameters_MalformedWrappingKeyResponses drives
// GetImportParameters against a series of well-formed-JSON but malformed
// transit/wrapping_key responses, proving each of its own response-parsing
// guards rejects the response instead of returning a zero-value wrapping
// key.
func TestGetImportParameters_MalformedWrappingKeyResponses(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{name: "missing public_key", data: map[string]interface{}{}},
		{name: "public_key wrong type", data: map[string]interface{}{"public_key": 123}},
		{name: "public_key empty string", data: map[string]interface{}{"public_key": ""}},
		{name: "public_key not PEM", data: map[string]interface{}{"public_key": "not a pem block"}},
		{
			name: "PEM contains invalid DER",
			data: map[string]interface{}{
				"public_key": "-----BEGIN PUBLIC KEY-----\nbm90IHZhbGlkIGRlcg==\n-----END PUBLIC KEY-----\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeVaultData(w, tt.data)
			}))
			t.Cleanup(server.Close)

			config := &Config{
				Address:     server.URL,
				Token:       "test-token",
				TransitPath: "transit",
				KeyStorage:  storage.New(),
				CertStorage: storage.New(),
			}
			b, err := NewBackend(config)
			if err != nil {
				t.Fatalf("NewBackend() error = %v", err)
			}
			t.Cleanup(func() { _ = b.Close() })

			attrs := &types.KeyAttributes{CN: "malformed-wrapping-key", SymmetricAlgorithm: types.SymmetricAES256GCM}
			if _, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmVaultTransitBYOK); err == nil {
				t.Errorf("GetImportParameters() expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestGetImportParameters_TransitError proves a wrapping_key read failure
// surfaces from GetImportParameters wrapped rather than being swallowed.
func TestGetImportParameters_TransitError(t *testing.T) {
	config := &Config{
		Address:     newFailingTransitServer(t),
		Token:       "test-token",
		TransitPath: "transit",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	// A vault.Client built directly (MaxRetries: 0) rather than through
	// NewBackend, so this test observes the failure on the first response
	// instead of waiting out the client's default retry backoff (matches
	// TestBackend_GetSymmetricKey_TransitRetrievalError's pattern).
	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = config.Address
	vaultConfig.MaxRetries = 0
	raw, err := vault.NewClient(vaultConfig)
	if err != nil {
		t.Fatalf("vault.NewClient() error = %v", err)
	}
	raw.SetToken(config.Token)

	b, err := NewBackendWithClient(config, newDefaultVaultClient(raw))
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	attrs := &types.KeyAttributes{CN: "transit-error-wrapping-key", SymmetricAlgorithm: types.SymmetricAES256GCM}
	if _, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmVaultTransitBYOK); err == nil {
		t.Error("GetImportParameters() expected error when Transit read fails, got nil")
	}
}
