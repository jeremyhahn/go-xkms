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
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
)

// TestMockKMSClient_DefaultBehaviors drives every MockKMSClient method that
// has a canned fallback body (go-xkms#705) with its *Func field left nil,
// proving the fallback itself -- not just the caller-injected override
// every other test in this package configures -- returns a sane response
// instead of the zero value. Without this, a MockKMSClient{} used the way
// its doc comment describes (as a "just works" stand-in when a test doesn't
// care about a particular RPC) would be relying on code paths no test had
// ever run.
func TestMockKMSClient_DefaultBehaviors(t *testing.T) {
	m := &MockKMSClient{}
	ctx := context.Background()

	t.Run("ListCryptoKeys", func(t *testing.T) {
		keys, err := m.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: "projects/p/locations/l/keyRings/r"})
		if err != nil {
			t.Fatalf("ListCryptoKeys() error = %v", err)
		}
		if keys == nil {
			t.Error("ListCryptoKeys() default must return an empty slice, not nil")
		}
		if len(keys) != 0 {
			t.Errorf("ListCryptoKeys() default = %d keys, want 0", len(keys))
		}
	})

	t.Run("AsymmetricDecrypt", func(t *testing.T) {
		resp, err := m.AsymmetricDecrypt(ctx, &kmspb.AsymmetricDecryptRequest{Name: "v1", Ciphertext: []byte("ct")})
		if err != nil {
			t.Fatalf("AsymmetricDecrypt() error = %v", err)
		}
		if len(resp.Plaintext) == 0 {
			t.Error("AsymmetricDecrypt() default must return non-empty plaintext")
		}
		if resp.PlaintextCrc32C == nil {
			t.Error("AsymmetricDecrypt() default must set PlaintextCrc32C")
		}
	})

	t.Run("CreateCryptoKeyVersion", func(t *testing.T) {
		resp, err := m.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{Parent: "projects/p/locations/l/keyRings/r/cryptoKeys/k"})
		if err != nil {
			t.Fatalf("CreateCryptoKeyVersion() error = %v", err)
		}
		if !strings.HasSuffix(resp.Name, "/cryptoKeyVersions/2") {
			t.Errorf("CreateCryptoKeyVersion() default Name = %q, want suffix /cryptoKeyVersions/2", resp.Name)
		}
		if resp.State != kmspb.CryptoKeyVersion_ENABLED {
			t.Errorf("CreateCryptoKeyVersion() default State = %v, want ENABLED", resp.State)
		}
	})

	t.Run("UpdateCryptoKeyPrimaryVersion", func(t *testing.T) {
		resp, err := m.UpdateCryptoKeyPrimaryVersion(ctx, &kmspb.UpdateCryptoKeyPrimaryVersionRequest{
			Name:               "projects/p/locations/l/keyRings/r/cryptoKeys/k",
			CryptoKeyVersionId: "3",
		})
		if err != nil {
			t.Fatalf("UpdateCryptoKeyPrimaryVersion() error = %v", err)
		}
		if resp.Primary == nil || !strings.HasSuffix(resp.Primary.Name, "/cryptoKeyVersions/3") {
			t.Errorf("UpdateCryptoKeyPrimaryVersion() default Primary = %+v, want version 3", resp.Primary)
		}
	})

	t.Run("CreateImportJob", func(t *testing.T) {
		resp, err := m.CreateImportJob(ctx, &kmspb.CreateImportJobRequest{
			Parent:      "projects/p/locations/l/keyRings/r",
			ImportJobId: "job-1",
			ImportJob:   &kmspb.ImportJob{ImportMethod: kmspb.ImportJob_RSA_OAEP_3072_SHA256_AES_256, ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE},
		})
		if err != nil {
			t.Fatalf("CreateImportJob() error = %v", err)
		}
		if !strings.HasSuffix(resp.Name, "/importJobs/job-1") {
			t.Errorf("CreateImportJob() default Name = %q, want suffix /importJobs/job-1", resp.Name)
		}
		if resp.State != kmspb.ImportJob_ACTIVE {
			t.Errorf("CreateImportJob() default State = %v, want ACTIVE", resp.State)
		}
		if resp.PublicKey == nil || resp.PublicKey.Pem == "" {
			t.Error("CreateImportJob() default must return a non-empty wrapping public key PEM")
		}
	})

	t.Run("ImportCryptoKeyVersion", func(t *testing.T) {
		resp, err := m.ImportCryptoKeyVersion(ctx, &kmspb.ImportCryptoKeyVersionRequest{
			Parent:    "projects/p/locations/l/keyRings/r/cryptoKeys/k",
			Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		})
		if err != nil {
			t.Fatalf("ImportCryptoKeyVersion() error = %v", err)
		}
		if !strings.HasSuffix(resp.Name, "/cryptoKeyVersions/1") {
			t.Errorf("ImportCryptoKeyVersion() default Name = %q, want suffix /cryptoKeyVersions/1", resp.Name)
		}
		if resp.Algorithm != kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256 {
			t.Errorf("ImportCryptoKeyVersion() default Algorithm = %v, want RSA_SIGN_PKCS1_2048_SHA256", resp.Algorithm)
		}
	})
}
