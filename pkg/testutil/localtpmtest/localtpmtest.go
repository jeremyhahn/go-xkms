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

// Package localtpmtest opens the local TPM policy service (pkg/localtpm)
// over the in-process TPM simulator, provisioned, for tests. The simulator
// keeps its state -- NV indexes included -- only while it is open, so a test
// keeps the returned host open for its whole run; it is closed when the test
// ends.
package localtpmtest

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/localtpm"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// OpenSimulator opens a fresh, provisioned simulator TPM with its key store
// and the policy service under dataDir, its stores opened with openStore.
func OpenSimulator(t testing.TB, dataDir string, openStore func(string) (storage.Backend, error)) *localtpm.Host {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	params := localtpm.DeviceParams{DataDir: dataDir, UseSimulator: true, Logger: logger}
	device, err := localtpm.OpenDevice(params)
	if err != nil {
		t.Fatalf("localtpmtest: open the simulator: %v", err)
	}
	cfg := tpm2.DefaultConfig
	cfg.UseSimulator = true
	if err := tpm2.ProvisionFresh(device.TPM(), &cfg); err != nil {
		t.Fatalf("localtpmtest: provision the simulator: %v", err)
	}
	policies, err := localtpm.Open(localtpm.Params{
		TPM: device.TPM(), Keys: device.Keys(), DataDir: dataDir, OpenStore: openStore, Logger: logger,
	})
	if err != nil {
		t.Fatalf("localtpmtest: open the policy service: %v", err)
	}
	host := &localtpm.Host{Policies: policies, Device: device}
	t.Cleanup(func() {
		if err := host.Close(); err != nil {
			t.Errorf("localtpmtest: close: %v", err)
		}
	})
	return host
}

// MemoryStores opens every service store in memory.
func MemoryStores(string) (storage.Backend, error) { return storage.New(), nil }
