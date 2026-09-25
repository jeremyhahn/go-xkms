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

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newMalformedTransitKeyServer starts a server that answers every Transit
// "read key" request with the fixed data envelope given, standing in for a
// reachable Vault whose response is malformed or unexpectedly shaped --
// exercising getPublicKeyVersion's own response-parsing guards, which the
// transitDouble (a well-behaved stand-in) never triggers.
func newMalformedTransitKeyServer(t *testing.T, data map[string]interface{}) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeVaultData(w, data)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

// newSignerBackendAgainst builds a Backend pointed at addr with a local
// metadata record already seeded for cn, so Signer reaches
// getPublicKeyVersion instead of failing its own existence check first.
func newSignerBackendAgainst(t *testing.T, addr, cn string) *Backend {
	t.Helper()
	config := &Config{
		Address:     addr,
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
	if err := storage.SaveKey(context.Background(), config.KeyStorage, cn, []byte("{}")); err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}
	return b
}

// TestGetPublicKeyVersion_MalformedResponses drives Signer against a series
// of Vault Transit "read key" responses that are well-formed JSON but
// missing or misshapen in exactly the ways getPublicKeyVersion's own guards
// check for, proving each guard rejects the response instead of panicking
// or returning a zero-value public key.
func TestGetPublicKeyVersion_MalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{
			name: "missing keys field",
			data: map[string]interface{}{},
		},
		{
			name: "keys field wrong type",
			data: map[string]interface{}{"keys": "not-a-map"},
		},
		{
			name: "missing latest_version",
			data: map[string]interface{}{"keys": map[string]interface{}{"1": map[string]interface{}{}}},
		},
		{
			name: "latest_version not present in keys",
			data: map[string]interface{}{
				"keys":           map[string]interface{}{"1": map[string]interface{}{}},
				"latest_version": 2,
			},
		},
		{
			name: "key data wrong type",
			data: map[string]interface{}{
				"keys":           map[string]interface{}{"1": "not-a-map"},
				"latest_version": 1,
			},
		},
		{
			name: "missing public_key",
			data: map[string]interface{}{
				"keys":           map[string]interface{}{"1": map[string]interface{}{}},
				"latest_version": 1,
			},
		},
		{
			name: "public_key wrong type",
			data: map[string]interface{}{
				"keys":           map[string]interface{}{"1": map[string]interface{}{"public_key": 123}},
				"latest_version": 1,
			},
		},
		{
			name: "ed25519 public key not base64",
			data: map[string]interface{}{
				"keys":           map[string]interface{}{"1": map[string]interface{}{"public_key": "not-base64!!"}},
				"latest_version": 1,
				"type":           "ed25519",
			},
		},
		{
			name: "ed25519 public key wrong length",
			data: map[string]interface{}{
				// valid base64, but decodes to fewer than 32 bytes
				"keys":           map[string]interface{}{"1": map[string]interface{}{"public_key": "dGVzdA=="}},
				"latest_version": 1,
				"type":           "ed25519",
			},
		},
		{
			name: "non-ed25519 public key not PEM",
			data: map[string]interface{}{
				"keys":           map[string]interface{}{"1": map[string]interface{}{"public_key": "not a pem block"}},
				"latest_version": 1,
				"type":           "rsa-2048",
			},
		},
		{
			name: "non-ed25519 PEM contains invalid DER",
			data: map[string]interface{}{
				"keys": map[string]interface{}{"1": map[string]interface{}{
					"public_key": "-----BEGIN PUBLIC KEY-----\nbm90IHZhbGlkIGRlcg==\n-----END PUBLIC KEY-----\n",
				}},
				"latest_version": 1,
				"type":           "rsa-2048",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cn := "malformed-" + tt.name
			addr := newMalformedTransitKeyServer(t, tt.data)
			b := newSignerBackendAgainst(t, addr, cn)

			attrs := &types.KeyAttributes{CN: cn}
			if _, err := b.Signer(context.Background(), attrs); err == nil {
				t.Errorf("Signer() expected error for %s, got nil", tt.name)
			}
		})
	}
}
