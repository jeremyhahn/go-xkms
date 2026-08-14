// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package services

import (
	"context"
	"log/slog"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// The GCP Cloud KMS liveness probe is only compiled when the gcpkms backend
// is, so availability reported to the Add Backend dialog is genuine.
func init() {
	registerCloudProbe(CloudProviderGCPKMS, probeGCPKMS)
}

// probeGCPKMS verifies connectivity to GCP Cloud KMS by listing the crypto
// keys of the configured key ring. ListKeys issues a real ListCryptoKeys RPC,
// so it proves the credentials resolve, the caller is authorized, and the
// project, location, and key ring all exist. It creates no key material.
func probeGCPKMS(ctx context.Context, config map[string]string) error {
	cfg := &xkms.GCPKMSBackendConfig{
		ProjectID:       config["project"],
		LocationID:      config["location"],
		KeyRingID:       config["keyring"],
		CredentialsFile: config["credentials_file"],
		KeyStorage:      xkms.NewStorageMemory(),
		CertStorage:     xkms.NewStorageMemory(),
	}

	backend, err := xkms.NewGCPKMSBackend(ctx, cfg)
	if err != nil {
		return &WrappedError{Msg: "GCP Cloud KMS client", Err: err}
	}
	defer func() {
		if closeErr := backend.Close(); closeErr != nil {
			slog.Warn("gcpkms connection probe: failed to close backend", "error", closeErr)
		}
	}()

	if _, err := backend.ListKeys(ctx); err != nil {
		return &WrappedError{Msg: "GCP Cloud KMS key ring", Err: err}
	}
	return nil
}
