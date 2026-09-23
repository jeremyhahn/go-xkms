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

//go:build integration && tpm_simulator

package sshbackend

import (
	"log/slog"
	"os"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestSSHBackend_TPM2 proves SSH key generation + signing on a TPM 2.0 backend
// using the in-process Microsoft reference simulator (build tag tpm_simulator).
// The TPM private key never leaves the device; signing is delegated. It NEVER
// touches host /dev/tpmrm0. The simulator uses a global mutex, so this test
// must not run in parallel with other simulator users.
func TestSSHBackend_TPM2(t *testing.T) {
	kp := newSimulatorTPMProvider(t)
	runMatrix(t, resolverFor("tpm2", kp), "tpm2", hardwareAlgos, true)
}

// newSimulatorTPMProvider builds a simulator-backed TPM2 KeyProvider, mirroring
// the proven FIDO2 recipe (xkey/test/integration/fido2/backend_test.go).
func newSimulatorTPMProvider(t *testing.T) types.KeyProvider {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	fsBackend, err := xkms.NewFileStorageBackend(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStorageBackend: %v", err)
	}
	keyBackend := xkms.NewFileBackend(logger, fsBackend)

	tpmConfig := xkms.DefaultTPMConfig
	tpmConfig.UseSimulator = true
	tpmConfig.EK.PlatformPolicy = false
	tpmConfig.EK.HierarchyAuth = types.SecretValue{}
	tpmConfig.SSRK.HierarchyAuth = types.SecretValue{}
	tpmConfig.IDevID = nil
	tpmConfig.IAK = nil

	tpm, err := xkms.NewTPM2(&xkms.TPMParams{
		Config:  &tpmConfig,
		Backend: keyBackend,
		Logger:  logger,
	})
	if err != nil && tpm == nil {
		t.Fatalf("open TPM simulator: %v", err)
	}
	// NewTPM2 returns a non-nil error alongside a usable TPM when EK/SRK are not
	// yet provisioned; provision them.
	if err != nil {
		ekAttrs, ekErr := xkms.EKAttributesFromConfig(*tpmConfig.EK, nil, nil)
		if ekErr != nil {
			tpm.Close()
			t.Fatalf("EK attributes: %v", ekErr)
		}
		if cerr := tpm.CreateEK(ekAttrs); cerr != nil {
			tpm.Close()
			t.Fatalf("CreateEK: %v", cerr)
		}
		srkAttrs, srkErr := xkms.SRKAttributesFromConfig(*tpmConfig.SSRK)
		if srkErr != nil {
			tpm.Close()
			t.Fatalf("SRK attributes: %v", srkErr)
		}
		srkAttrs.Parent = ekAttrs
		if cerr := tpm.CreateSRK(srkAttrs); cerr != nil {
			tpm.Close()
			t.Fatalf("CreateSRK: %v", cerr)
		}
	}
	t.Cleanup(func() { tpm.Close() })

	provider, err := xkms.NewTPM2BackendWithTPM(&xkms.TPM2BackendExternalConfig{
		TPM:        tpm,
		KeyBackend: keyBackend,
		Logger:     logger,
	})
	if err != nil {
		t.Fatalf("NewTPM2BackendWithTPM: %v", err)
	}
	return provider
}
