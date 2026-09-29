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

//go:build azurekv

package azurekv

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestInitSecretsClient_DefaultCredentialPath mirrors
// TestInitClient_DefaultCredentialPath (azurekv_coverage_test.go) for
// initSecretsClient (go-xkms#705): every existing test reaches the secrets
// client exclusively through NewBackendWithClients' injected mock, so
// initSecretsClient's own double-checked-locking slow path -- both the
// DefaultAzureCredential branch and the fast-path short-circuit -- had
// never run. azidentity.NewDefaultAzureCredential builds its credential
// chain without any network I/O, so this runs fully offline.
func TestInitSecretsClient_DefaultCredentialPath(t *testing.T) {
	b, err := NewBackend(&Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	if err := b.initSecretsClient(context.Background()); err != nil {
		t.Fatalf("initSecretsClient() error = %v", err)
	}
	if b.secretsClient == nil {
		t.Fatal("initSecretsClient() did not set secretsClient")
	}

	// Fast path: calling again with a client already set is a no-op.
	existing := b.secretsClient
	if err := b.initSecretsClient(context.Background()); err != nil {
		t.Fatalf("initSecretsClient() second call error = %v", err)
	}
	if b.secretsClient != existing {
		t.Error("initSecretsClient() replaced an already-initialized secretsClient")
	}
}

// TestInitSecretsClient_ServicePrincipalPath mirrors
// TestInitClient_ServicePrincipalPath for initSecretsClient's
// ClientSecretCredential branch.
func TestInitSecretsClient_ServicePrincipalPath(t *testing.T) {
	b, err := NewBackend(&Config{
		VaultURL:     "https://test-vault.vault.azure.net/",
		TenantID:     "11111111-1111-1111-1111-111111111111",
		ClientID:     "22222222-2222-2222-2222-222222222222",
		ClientSecret: types.NewLiteralSecretValue([]byte("super-secret")),
		KeyStorage:   storage.New(),
		CertStorage:  storage.New(),
	})
	if err != nil {
		t.Fatalf("NewBackend() error = %v", err)
	}

	if err := b.initSecretsClient(context.Background()); err != nil {
		t.Fatalf("initSecretsClient() error = %v", err)
	}
	if b.secretsClient == nil {
		t.Fatal("initSecretsClient() did not set secretsClient")
	}
}

// TestInitSecretsClient_InjectedClientNeverOverwritten proves a
// secretsClient injected through NewBackendWithClients (the production path
// GenerateSymmetricKey/GetSymmetricKey normally take in tests) is what
// initSecretsClient's fast path sees, so a lazy caller can never silently
// discard the caller-supplied mock/fake for a real one.
func TestInitSecretsClient_InjectedClientNeverOverwritten(t *testing.T) {
	injected := NewMockSecretsClient()
	b, err := NewBackendWithClients(&Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}, NewMockKeyVaultClient(), injected)
	if err != nil {
		t.Fatalf("NewBackendWithClients() error = %v", err)
	}

	if err := b.initSecretsClient(context.Background()); err != nil {
		t.Fatalf("initSecretsClient() error = %v", err)
	}
	if b.secretsClient != injected {
		t.Error("initSecretsClient() overwrote the injected secretsClient")
	}
}
