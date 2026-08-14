// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration && cloud_real && awskms && gcpkms && azurekv

package sshbackend

import (
	"context"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/awskms"
	"github.com/jeremyhahn/go-xkms/pkg/backend/azurekv"
	"github.com/jeremyhahn/go-xkms/pkg/backend/gcpkms"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestSSHBackend_CloudReal exercises SSH key generation + signing against LIVE
// cloud KMS providers using real credentials. It is opt-in: the cloud_real
// build tag excludes the whole file from every other run, so a build without
// credentials never compiles it in and never pretends to have covered it.
//
// Opting in is a promise that all three providers are configured. Missing
// credentials are therefore a hard failure naming the variable that is absent,
// not a silent pass. ECDSA-P256 is the cross-cloud SSH-valid algorithm.
func TestSSHBackend_CloudReal(t *testing.T) {
	t.Run("awskms", func(t *testing.T) {
		region := os.Getenv("AWS_REGION")
		if region == "" || os.Getenv("AWS_ACCESS_KEY_ID") == "" {
			t.Fatal("live AWS KMS lane requires AWS_REGION and AWS_ACCESS_KEY_ID " +
				"(build tag cloud_real was requested)")
		}
		be, err := awskms.NewBackend(&awskms.Config{
			Region:          region,
			AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
			KeyStorage:      mustMemory(t),
			CertStorage:     mustMemory(t),
		})
		if err != nil {
			t.Fatalf("awskms.NewBackend: %v", err)
		}
		runMatrix(t, resolverFor("awskms", be), "awskms", cloudAlgos, true)
		assertRejects(t, resolverFor("awskms", be), "awskms", keys.AlgorithmEd25519)
	})

	t.Run("gcpkms", func(t *testing.T) {
		project := os.Getenv("GCPKMS_PROJECT_ID")
		if project == "" {
			t.Fatal("live GCP KMS lane requires GCPKMS_PROJECT_ID " +
				"(build tag cloud_real was requested)")
		}
		be, err := gcpkms.NewBackend(context.Background(), &gcpkms.Config{
			ProjectID:   project,
			LocationID:  envOrReal("GCPKMS_LOCATION", "global"),
			KeyRingID:   envOrReal("GCPKMS_KEYRING", "ssh-backend-test"),
			KeyStorage:  mustMemory(t),
			CertStorage: mustMemory(t),
		})
		if err != nil {
			t.Fatalf("gcpkms.NewBackend: %v", err)
		}
		runMatrix(t, resolverFor("gcpkms", be), "gcpkms", cloudAlgos, true)
		assertRejects(t, resolverFor("gcpkms", be), "gcpkms", keys.AlgorithmEd25519)
	})

	t.Run("azurekv", func(t *testing.T) {
		vault := os.Getenv("AZURE_KEYVAULT_URL")
		if vault == "" || os.Getenv("AZURE_TENANT_ID") == "" {
			t.Fatal("live Azure Key Vault lane requires AZURE_KEYVAULT_URL and AZURE_TENANT_ID " +
				"(build tag cloud_real was requested)")
		}
		be, err := azurekv.NewBackend(&azurekv.Config{
			VaultURL:     vault,
			TenantID:     os.Getenv("AZURE_TENANT_ID"),
			ClientID:     os.Getenv("AZURE_CLIENT_ID"),
			ClientSecret: os.Getenv("AZURE_CLIENT_SECRET"),
			KeyStorage:   mustMemory(t),
			CertStorage:  mustMemory(t),
		})
		if err != nil {
			t.Fatalf("azurekv.NewBackend: %v", err)
		}
		runMatrix(t, resolverFor("azurekv", be), "azurekv", cloudAlgos, true)
		assertRejects(t, resolverFor("azurekv", be), "azurekv", keys.AlgorithmEd25519)
	})
}

func mustMemory(t *testing.T) storage.Backend {
	t.Helper()
	b, err := xkms.NewMemoryBackend()
	if err != nil {
		t.Fatalf("NewMemoryBackend: %v", err)
	}
	return b
}

func envOrReal(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
