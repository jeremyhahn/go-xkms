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

// tls_run_test.go exercises the "xkmsctl tls get" command's Run closure
// (flag reads + delegation to the already-tested getTLSCertLocal), using the
// same mock backend + real file-backed cert storage pattern as tls_test.go.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func TestTLSGetCmd_Run_Success(t *testing.T) {
	tmpDir := t.TempDir()

	ca, err := testutil.GenerateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	mockBackend := mocks.NewExtendedMockBackend()
	mockBackend.StoreKey("run-tls-key", rsaKey)

	cfg := NewConfig()
	cfg.KeyDir = tmpDir
	cfg.OutputFormat = "text"
	cfg.Protocol = "embedded"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return mockBackend, nil
	}

	storageBackend, err := file.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create storage backend: %v", err)
	}
	certStorage := storage.NewCertAdapter(storageBackend)
	if err := certStorage.SaveCert(context.Background(), "run-tls-key", ca.Cert); err != nil {
		t.Fatalf("failed to save certificate: %v", err)
	}

	withGlobalConfig(t, cfg)

	cmd := tlsGetCmd
	_ = cmd.Flags().Set("key-type", "tls")
	_ = cmd.Flags().Set("key-algorithm", "rsa")
	_ = cmd.Flags().Set("key-size", "2048")
	_ = cmd.Flags().Set("curve", "P-256")

	captureStdout(t, func() {
		cmd.Run(cmd, []string{"run-tls-key"})
	})
}

func TestTLSGetCmd_Run_BackendError(t *testing.T) {
	cfg := NewConfig()
	cfg.OutputFormat = "text"
	cfg.BackendFactory = func(c *Config) (types.KeyProvider, error) {
		return nil, errTenantRunBoom
	}
	withGlobalConfig(t, cfg)

	cmd := tlsGetCmd
	code := captureExit(t, func() {
		cmd.Run(cmd, []string{"missing-key"})
	})
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}
