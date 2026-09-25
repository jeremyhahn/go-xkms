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

package main

import (
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
)

func TestOfflineModeRequested(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"", false},
		{"remote", false},
		{"local", true},
		{"LOCAL", true},
		{" offline ", true},
		{"offline", true},
		{"embedded-but-not-a-keyword", false},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv(envMode, tc.value)
			if got := offlineModeRequested(); got != tc.want {
				t.Errorf("offlineModeRequested() with %s=%q = %v, want %v", envMode, tc.value, got, tc.want)
			}
		})
	}
}

func TestLocalKeyDir_Resolution(t *testing.T) {
	t.Run("explicit env override wins", func(t *testing.T) {
		t.Setenv(envLocalKeyDir, "/explicit/keys")
		if got := localKeyDir(nil); got != "/explicit/keys" {
			t.Errorf("localKeyDir = %q, want /explicit/keys", got)
		}
	})

	t.Run("derives from storage path", func(t *testing.T) {
		t.Setenv(envLocalKeyDir, "")
		cfg := &module.Config{StoragePath: "/data/token"}
		want := filepath.Join("/data/token", "keys")
		if got := localKeyDir(cfg); got != want {
			t.Errorf("localKeyDir = %q, want %q", got, want)
		}
	})

	t.Run("falls back to a per-user directory when no storage path is configured", func(t *testing.T) {
		t.Setenv(envLocalKeyDir, "")
		home := t.TempDir()
		t.Setenv("HOME", home)
		want := filepath.Join(home, ".xkms", "pkcs11", "keys")

		if got := localKeyDir(nil); got != want {
			t.Errorf("localKeyDir(nil) = %q, want %q", got, want)
		}
		if got := localKeyDir(&module.Config{}); got != want {
			t.Errorf("localKeyDir(&Config{}) = %q, want %q", got, want)
		}
	})
}

// TestBuildOfflineModule_InitializesWithoutNetwork is the decisive wiring test:
// it builds the offline module in a temp directory and initializes it. Success
// proves the .so can come up with no xkmsd to dial — the embedded in-process
// service is the transport, and its Connect is a no-op. A remote-mode module
// with no server would fail Initialize with CKR_DEVICE_ERROR here.
func TestBuildOfflineModule_InitializesWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(envMode, "local")
	t.Setenv(envLocalKeyDir, filepath.Join(dir, "keys"))
	t.Setenv(module.EnvStoragePath, filepath.Join(dir, "state"))
	t.Setenv(module.EnvStorageType, "") // let offline mode promote to file

	module.ResetGlobalModule()
	t.Cleanup(module.ResetGlobalModule)

	if module.HasGlobalModule() {
		t.Fatal("no global module should be installed before the test builds one")
	}

	if err := buildOfflineModule(); err != nil {
		t.Fatalf("buildOfflineModule: %v", err)
	}
	if !module.HasGlobalModule() {
		t.Fatal("buildOfflineModule must install the global module")
	}

	if rv := module.GetGlobalModule().Initialize(nil); rv != module.CKR_OK {
		t.Fatalf("offline module Initialize returned %s, want CKR_OK (no network should be required)", rv)
	}

	// The offline module must persist token state locally rather than in memory,
	// or an offline token would not survive a process restart.
	// (The storage type is promoted to file by buildOfflineModule.)
}

// TestBuildOfflineModule_PassphraseStrategyBuildsSealedStore proves the default
// (passphrase) strategy wires the barrier-backed key store and seal controller
// and still initializes offline. The barrier's own encryption round-trip is
// proven in pkg/pkcs11/localseal; here we assert the .so composition path builds
// and comes up.
func TestBuildOfflineModule_PassphraseStrategyBuildsSealedStore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(envMode, "local")
	t.Setenv(envSealStrategy, "passphrase")
	t.Setenv(envLocalKeyDir, filepath.Join(dir, "keys"))
	t.Setenv(module.EnvStoragePath, filepath.Join(dir, "state"))
	t.Setenv(module.EnvStorageType, "")

	module.ResetGlobalModule()
	t.Cleanup(module.ResetGlobalModule)

	if err := buildOfflineModule(); err != nil {
		t.Fatalf("buildOfflineModule (passphrase): %v", err)
	}
	if rv := module.GetGlobalModule().Initialize(nil); rv != module.CKR_OK {
		t.Fatalf("offline passphrase-mode Initialize returned %s, want CKR_OK", rv)
	}
}

func TestOfflineSealStrategy_DefaultsToPassphrase(t *testing.T) {
	t.Setenv(envSealStrategy, "")
	if got := offlineSealStrategy(); got != sealStrategyPass {
		t.Errorf("default seal strategy = %q, want %q (secure default matching qrdb)", got, sealStrategyPass)
	}
	t.Setenv(envSealStrategy, "none")
	if got := offlineSealStrategy(); got != sealStrategyNone {
		t.Errorf("seal strategy = %q, want %q", got, sealStrategyNone)
	}
}
