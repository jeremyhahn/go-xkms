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

package config

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/secrettest"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestBarrierAWSKMSConfig_Validate(t *testing.T) {
	valid := &BarrierAWSKMSConfig{Region: "us-east-1"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a region-only (ambient credentials) config", err)
	}

	withCreds := &BarrierAWSKMSConfig{
		Region:          "us-east-1",
		AccessKeyID:     "AKIAEXAMPLE",
		SecretAccessKey: secrettest.Literal(t, []byte("s3cr3t")),
	}
	if err := withCreds.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil when both access_key_id and secret_access_key are set", err)
	}
}

func TestBarrierAWSKMSConfig_Validate_Errors(t *testing.T) {
	cases := []struct {
		name string
		cfg  *BarrierAWSKMSConfig
	}{
		{"nil config", nil},
		{"missing region", &BarrierAWSKMSConfig{}},
		{"access key without secret", &BarrierAWSKMSConfig{Region: "us-east-1", AccessKeyID: "AKIAEXAMPLE"}},
		{"secret without access key", &BarrierAWSKMSConfig{Region: "us-east-1", SecretAccessKey: secrettest.Literal(t, []byte("x"))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			if !errors.Is(err, ErrBarrierCloudKMSConfigInvalid) {
				t.Fatalf("err = %v, want errors.Is match against ErrBarrierCloudKMSConfigInvalid", err)
			}
		})
	}
}

// TestBarrierAWSKMSConfig_KeyIDRoundTrip proves an operator-configured
// KeyID (go-xkms#842) survives Save/Load intact, the same as every other
// aws_kms connection setting, so unseal and headless serve read back the
// same CMK the operator named at "barrier init" without repeating the flag.
func TestBarrierAWSKMSConfig_KeyIDRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	SetConfigDir(tmpDir)
	t.Cleanup(ResetConfigDir)

	cfg := DefaultConfig()
	cfg.Barrier.CloudKMS.AWSKMS.Region = "us-east-1"
	cfg.Barrier.CloudKMS.AWSKMS.KeyID = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab"

	if err := Save(cfg); err != nil {
		t.Fatalf("Save() = %v, want nil", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if got := loaded.Barrier.CloudKMS.AWSKMS.KeyID; got != cfg.Barrier.CloudKMS.AWSKMS.KeyID {
		t.Fatalf("KeyID = %q, want %q", got, cfg.Barrier.CloudKMS.AWSKMS.KeyID)
	}
}

// TestBarrierAWSKMSConfig_Validate_KeyIDNotCheckedHere proves Validate does
// not itself reject an operator-supplied KeyID of any shape: format
// validation happens where the backend is actually constructed
// (awskms.Config.Validate, via sdk/go.NewAWSKMSBackend), the single
// authority both xkmsd and xkey build the backend through -- duplicating
// that check here would be a second, driftable copy of the same AWS format
// rules.
func TestBarrierAWSKMSConfig_Validate_KeyIDNotCheckedHere(t *testing.T) {
	cfg := &BarrierAWSKMSConfig{Region: "us-east-1", KeyID: "not a real AWS key identifier"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil (KeyID format is validated at backend construction, not here)", err)
	}
}

func TestBarrierGCPKMSConfig_Validate(t *testing.T) {
	valid := &BarrierGCPKMSConfig{ProjectID: "p", LocationID: "us-east1", KeyRingID: "ring"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestBarrierGCPKMSConfig_Validate_Errors(t *testing.T) {
	cases := []struct {
		name string
		cfg  *BarrierGCPKMSConfig
	}{
		{"nil config", nil},
		{"missing project_id", &BarrierGCPKMSConfig{LocationID: "us-east1", KeyRingID: "ring"}},
		{"missing location_id", &BarrierGCPKMSConfig{ProjectID: "p", KeyRingID: "ring"}},
		{"missing key_ring_id", &BarrierGCPKMSConfig{ProjectID: "p", LocationID: "us-east1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			if !errors.Is(err, ErrBarrierCloudKMSConfigInvalid) {
				t.Fatalf("err = %v, want errors.Is match against ErrBarrierCloudKMSConfigInvalid", err)
			}
		})
	}
}

func TestBarrierAzureKVConfig_Validate(t *testing.T) {
	valid := &BarrierAzureKVConfig{VaultURL: "https://my-vault.vault.azure.net/"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for a URL-only (ambient credentials) config", err)
	}

	withCreds := &BarrierAzureKVConfig{
		VaultURL:     "https://my-vault.vault.azure.net/",
		TenantID:     "tenant",
		ClientID:     "client",
		ClientSecret: secrettest.Literal(t, []byte("s3cr3t")),
	}
	if err := withCreds.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil when tenant_id, client_id and client_secret are all set", err)
	}
}

func TestBarrierAzureKVConfig_Validate_Errors(t *testing.T) {
	cases := []struct {
		name string
		cfg  *BarrierAzureKVConfig
	}{
		{"nil config", nil},
		{"missing vault_url", &BarrierAzureKVConfig{}},
		{"tenant only", &BarrierAzureKVConfig{VaultURL: "https://v.vault.azure.net/", TenantID: "t"}},
		{"client id and secret without tenant", &BarrierAzureKVConfig{
			VaultURL: "https://v.vault.azure.net/", ClientID: "c", ClientSecret: secrettest.Literal(t, []byte("x")),
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			if !errors.Is(err, ErrBarrierCloudKMSConfigInvalid) {
				t.Fatalf("err = %v, want errors.Is match against ErrBarrierCloudKMSConfigInvalid", err)
			}
		})
	}
}

func TestBarrierVaultConfig_Validate(t *testing.T) {
	valid := &BarrierVaultConfig{Address: "https://vault.example.com:8200"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil for an address-only (ambient VAULT_TOKEN) config", err)
	}
}

// TestBarrierCloudKMSConfig_SecretValueRoundTrip proves a cloud KMS
// credential's *xkms.SecretValue reference survives Save/Load intact: it is
// still the same reference string (never a literal, never lost) after
// going through YAML on disk and back through viper's decode path (see
// secretValueDecodeHookFunc in load.go for why that path needs its own
// hook to decode a SecretValue at all).
func TestBarrierCloudKMSConfig_SecretValueRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	SetConfigDir(tmpDir)
	t.Cleanup(ResetConfigDir)

	cfg := DefaultConfig()
	cfg.Barrier.CloudKMS.AWSKMS.Region = "us-east-1"
	cfg.Barrier.CloudKMS.AWSKMS.SecretAccessKey = &xkms.SecretValue{Raw: "credential://aws-secret"}

	if err := Save(cfg); err != nil {
		t.Fatalf("Save() = %v, want nil", err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() = %v, want nil", err)
	}
	if loaded.Barrier.CloudKMS.AWSKMS.SecretAccessKey == nil {
		t.Fatal("SecretAccessKey is nil after round trip, want the reference to survive")
	}
	if got := loaded.Barrier.CloudKMS.AWSKMS.SecretAccessKey.Raw; got != "credential://aws-secret" {
		t.Fatalf("Raw = %q, want %q", got, "credential://aws-secret")
	}
}

func TestBarrierVaultConfig_Validate_Errors(t *testing.T) {
	cases := []struct {
		name string
		cfg  *BarrierVaultConfig
	}{
		{"nil config", nil},
		{"missing address", &BarrierVaultConfig{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			if !errors.Is(err, ErrBarrierCloudKMSConfigInvalid) {
				t.Fatalf("err = %v, want errors.Is match against ErrBarrierCloudKMSConfigInvalid", err)
			}
		})
	}
}
