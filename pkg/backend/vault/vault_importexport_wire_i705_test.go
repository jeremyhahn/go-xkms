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

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newExportableSymmetricBackendAgainst mirrors newSignerBackendAgainst
// (vault_getpublickey_malformed_test.go) for ExportKeyMaterial: it seeds a
// metadata record that passes ExportKeyMaterial's own local checks
// (exportable=true, a vault_name to build the export path from) so the
// call reaches the Transit "export" response-parsing guards this file
// targets, instead of failing earlier on its own precondition checks.
func newExportableSymmetricBackendAgainst(t *testing.T, addr, cn string) *Backend {
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

	metadata := []byte(`{"exportable":true,"vault_name":"` + cn + `","symmetric":true,"symmetric_algorithm":"aes-256-gcm"}`)
	if err := storage.SaveKey(context.Background(), config.KeyStorage, cn, metadata); err != nil {
		t.Fatalf("SaveKey() error = %v", err)
	}
	return b
}

// TestExportKeyMaterial_MalformedResponses drives ExportKeyMaterial against
// a series of Transit "export" responses that are well-formed JSON but
// missing or misshapen in exactly the ways ExportKeyMaterial's own guards
// check for (go-xkms#705), proving each guard returns a typed error instead
// of panicking or returning zero-value key material.
func TestExportKeyMaterial_MalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{
			name: "no keys field",
			data: map[string]interface{}{},
		},
		{
			name: "keys field wrong type",
			data: map[string]interface{}{"keys": "not-a-map"},
		},
		{
			name: "keys field empty",
			data: map[string]interface{}{"keys": map[string]interface{}{}},
		},
		{
			name: "key material not a string",
			data: map[string]interface{}{"keys": map[string]interface{}{"1": 12345}},
		},
		{
			name: "key material not valid base64",
			data: map[string]interface{}{"keys": map[string]interface{}{"1": "not-base64!!"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cn := "export-malformed-" + tt.name
			addr := newMalformedTransitKeyServer(t, tt.data)
			b := newExportableSymmetricBackendAgainst(t, addr, cn)

			attrs := &types.KeyAttributes{CN: cn, SymmetricAlgorithm: types.SymmetricAES256GCM}
			if _, err := b.ExportKeyMaterial(context.Background(), attrs); err == nil {
				t.Errorf("ExportKeyMaterial() expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestExportKeyMaterial_NoDataInResponse proves ExportKeyMaterial rejects a
// response whose envelope carries no "data" object at all (Vault returns
// this for e.g. a sealed/misconfigured mount), which
// newMalformedTransitKeyServer's fixed envelope can't express since it
// always wraps a data object.
func TestExportKeyMaterial_NoDataInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	cn := "export-no-data"
	b := newExportableSymmetricBackendAgainst(t, server.URL, cn)
	attrs := &types.KeyAttributes{CN: cn, SymmetricAlgorithm: types.SymmetricAES256GCM}
	if _, err := b.ExportKeyMaterial(context.Background(), attrs); err == nil {
		t.Error("ExportKeyMaterial() expected error for a response with no data object, got nil")
	}
}

// TestExportKeyMaterial_TransitError proves ExportKeyMaterial surfaces a
// Vault Transit export RPC failure wrapped, rather than a zero-length
// result.
func TestExportKeyMaterial_TransitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeVaultError(w, http.StatusForbidden, "permission denied")
	}))
	t.Cleanup(server.Close)

	cn := "export-transit-error"
	b := newExportableSymmetricBackendAgainst(t, server.URL, cn)
	attrs := &types.KeyAttributes{CN: cn, SymmetricAlgorithm: types.SymmetricAES256GCM}
	if _, err := b.ExportKeyMaterial(context.Background(), attrs); err == nil {
		t.Error("ExportKeyMaterial() expected error when Transit export RPC fails, got nil")
	}
}

// TestImportKey_TransitError proves ImportKey surfaces a Vault Transit
// import RPC failure wrapped, rather than reporting success for a key that
// was never actually created server-side.
func TestImportKey_TransitError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeVaultError(w, http.StatusBadRequest, "invalid ciphertext")
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

	attrs := &types.KeyAttributes{CN: "import-transit-error", SymmetricAlgorithm: types.SymmetricAES256GCM}
	wrapped := &backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped-key-material")}
	if err := b.ImportKey(context.Background(), attrs, wrapped); err == nil {
		t.Error("ImportKey() expected error when Transit import RPC fails, got nil")
	}
}
