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

package pinselect

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

func TestResolve_FreshDataDirAutoSelectsAndPersists(t *testing.T) {
	pinDir := t.TempDir()

	backend, strategy, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			TPM:      fakeTPMProvider{available: false},
			Software: softwareProvider{},
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strategy != qrdbsdk.PINStrategySoftware {
		t.Fatalf("strategy = %q, want software", strategy)
	}
	if backend.Strategy() != qrdbsdk.PINStrategySoftware {
		t.Fatalf("backend.Strategy() = %q, want software", backend.Strategy())
	}

	persisted, err := LoadStrategy(pinDir)
	if err != nil {
		t.Fatalf("Load after Resolve: %v", err)
	}
	if persisted != qrdbsdk.PINStrategySoftware {
		t.Fatalf("persisted strategy = %q, want software", persisted)
	}
}

func TestResolve_FreshDataDirPersistsTPMWhenAvailable(t *testing.T) {
	pinDir := t.TempDir()

	// StrategyAuto means exactly what an unset strategy means:
	// pinselect's hardware-first choice.
	_, strategy, err := Resolve(ResolveConfig{
		PINDir:   pinDir,
		Strategy: StrategyAuto,
		Config: Config{
			TPM:      fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true, authReady: true}, available: true},
			Software: softwareProvider{},
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strategy != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("strategy = %q, want tpm2", strategy)
	}

	persisted, err := LoadStrategy(pinDir)
	if err != nil {
		t.Fatalf("Load after Resolve: %v", err)
	}
	if persisted != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("persisted strategy = %q, want tpm2", persisted)
	}
}

func TestResolve_PersistedSoftwareGoverns(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, qrdbsdk.PINStrategySoftware); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// A TPM is available, but the persisted strategy is software, so
	// Resolve must not switch to it: the persisted record governs.
	backend, strategy, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			TPM:      fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true, authReady: true}, available: true},
			Software: softwareProvider{},
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strategy != qrdbsdk.PINStrategySoftware {
		t.Fatalf("strategy = %q, want software", strategy)
	}
	if backend.Strategy() != qrdbsdk.PINStrategySoftware {
		t.Fatalf("backend.Strategy() = %q, want software", backend.Strategy())
	}
}

func TestResolve_PersistedTPM2Governs(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, qrdbsdk.PINStrategyTPM2); err != nil {
		t.Fatalf("Save: %v", err)
	}

	backend, strategy, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			TPM:      fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true, authReady: true}, available: true},
			Software: softwareProvider{},
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strategy != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("strategy = %q, want tpm2", strategy)
	}
	if backend.Strategy() != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("backend.Strategy() = %q, want tpm2", backend.Strategy())
	}
}

func TestResolve_PersistedTPM2WithoutProviderRefuses(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, qrdbsdk.PINStrategyTPM2); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// No TPM provider configured at all in this environment (e.g. a
	// build without TPM support, or a host with no device).
	_, _, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			Software: softwareProvider{},
		},
	})

	var unavailable *ProviderUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("Resolve: got %T %v, want *ProviderUnavailableError", err, err)
	}
	if unavailable.Strategy != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("unavailable.Strategy = %q, want tpm2", unavailable.Strategy)
	}
}

func TestResolve_PersistedTPM2WithUnavailableProviderRefuses(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, qrdbsdk.PINStrategyTPM2); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The TPM provider exists but cannot answer right now (device
	// missing, SRK unprovisioned, ...): never fall back to software.
	_, _, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			TPM:      fakeTPMProvider{available: false},
			Software: softwareProvider{},
		},
	})

	var unavailable *ProviderUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("Resolve: got %T %v, want *ProviderUnavailableError", err, err)
	}
}

func TestResolve_PersistedPKCS11WithoutProviderRefuses(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, qrdbsdk.PINStrategyPKCS11); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, _, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			Software: softwareProvider{},
		},
	})

	var unavailable *ProviderUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("Resolve: got %T %v, want *ProviderUnavailableError", err, err)
	}
	if unavailable.Strategy != qrdbsdk.PINStrategyPKCS11 {
		t.Fatalf("unavailable.Strategy = %q, want pkcs11", unavailable.Strategy)
	}
}

func TestResolve_PersistedSoftwareWithNilProviderIsSentinelError(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, qrdbsdk.PINStrategySoftware); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, _, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{},
	})
	if !errors.Is(err, ErrNoSoftwareProvider) {
		t.Fatalf("Resolve: got %v, want ErrNoSoftwareProvider", err)
	}
}

func TestResolve_UnknownPersistedStrategyIsTypedError(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, "quantum"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, _, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			Software: softwareProvider{},
		},
	})

	var unknown *UnknownStrategyError
	if !errors.As(err, &unknown) {
		t.Fatalf("Resolve: got %T %v, want *UnknownStrategyError", err, err)
	}
}

func TestResolve_PersistedPKCS11Governs(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, qrdbsdk.PINStrategyPKCS11); err != nil {
		t.Fatalf("Save: %v", err)
	}

	stand, err := qrdbsdk.NewSoftwareBackend(nil, qrdbsdk.DefaultHashConfig())
	if err != nil {
		t.Fatalf("stand-in backend: %v", err)
	}

	backend, strategy, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			PKCS11:   fakePKCS11Provider{backend: stand, available: true},
			Software: softwareProvider{},
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strategy != qrdbsdk.PINStrategyPKCS11 {
		t.Fatalf("strategy = %q, want pkcs11", strategy)
	}
	if backend != stand {
		t.Fatal("expected the PKCS#11 provider's backend instance to be returned")
	}
}

func TestResolve_PersistedSoftwareStorageFailureIsWrapped(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, qrdbsdk.PINStrategySoftware); err != nil {
		t.Fatalf("Save: %v", err)
	}

	sentinel := errors.New("disk gone")
	_, _, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			Software: softwareProvider{failErr: sentinel},
		},
	})

	var storageErr *SoftwareStorageError
	if !errors.As(err, &storageErr) {
		t.Fatalf("Resolve: got %T %v, want *SoftwareStorageError", err, err)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("Resolve: expected wrapped sentinel, got %v", err)
	}
}

func TestResolve_SelectFailurePropagatesOnFreshDataDir(t *testing.T) {
	pinDir := t.TempDir()

	// No software provider at all: pinselect.Select itself fails, and a
	// fresh data directory must surface that rather than persist nothing.
	_, _, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{},
	})
	if !errors.Is(err, ErrNoSoftwareProvider) {
		t.Fatalf("Resolve: got %v, want ErrNoSoftwareProvider", err)
	}

	// Nothing must have been persisted from the failed attempt.
	if _, loadErr := LoadStrategy(pinDir); !errors.Is(loadErr, ErrStrategyNotPersisted) {
		t.Fatalf("Load after failed Resolve: got %v, want ErrStrategyNotPersisted", loadErr)
	}
}

func TestResolve_SaveFailureOnFreshDataDirPropagates(t *testing.T) {
	// A dangling symlink at the strategy path reads as "not persisted", so
	// Resolve goes on to save, and the atomic writer refuses to write through
	// the symlink. Unlike a read-only directory, this fails for root too.
	pinDir := t.TempDir()
	missing := filepath.Join(t.TempDir(), "missing")
	if err := os.Symlink(missing, StrategyPath(pinDir)); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, _, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			Software: softwareProvider{},
		},
	})

	var saveErr *StrategySaveError
	if !errors.As(err, &saveErr) {
		t.Fatalf("Resolve: got %T %v, want *StrategySaveError", err, err)
	}
}

func TestResolve_LoadFailurePropagates(t *testing.T) {
	pinDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pinDir, "strategy"), []byte("{bad"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, _, err := Resolve(ResolveConfig{
		PINDir: pinDir,
		Config: Config{
			Software: softwareProvider{},
		},
	})
	var loadErr *StrategyLoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("Resolve: got %T %v, want *StrategyLoadError", err, err)
	}
}

// TestResolve_ExplicitStrategyOnFreshDirBuildsAndPersistsIt proves a
// configured strategy is honoured exactly -- a TPM being available does not
// override an operator's "software" -- and is recorded so every other entry
// point resolves the same backend.
func TestResolve_ExplicitStrategyOnFreshDirBuildsAndPersistsIt(t *testing.T) {
	pinDir := t.TempDir()

	backend, strategy, err := Resolve(ResolveConfig{
		PINDir:   pinDir,
		Strategy: qrdbsdk.PINStrategySoftware,
		Config: Config{
			TPM:      fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true, authReady: true}, available: true},
			Software: softwareProvider{},
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strategy != qrdbsdk.PINStrategySoftware || backend.Strategy() != qrdbsdk.PINStrategySoftware {
		t.Fatalf("strategy = %q (backend %q), want software", strategy, backend.Strategy())
	}
	persisted, err := LoadStrategy(pinDir)
	if err != nil {
		t.Fatalf("LoadStrategy: %v", err)
	}
	if persisted != qrdbsdk.PINStrategySoftware {
		t.Fatalf("persisted = %q, want software", persisted)
	}
}

// TestResolve_ExplicitTPM2WithoutTPMRefusesAndPersistsNothing proves an
// explicit tpm2 strategy never falls back to software when no TPM can serve
// it, and records nothing a later start would trust.
func TestResolve_ExplicitTPM2WithoutTPMRefusesAndPersistsNothing(t *testing.T) {
	pinDir := t.TempDir()

	_, _, err := Resolve(ResolveConfig{
		PINDir:   pinDir,
		Strategy: qrdbsdk.PINStrategyTPM2,
		Config:   Config{Software: softwareProvider{}},
	})
	var unavailable *ProviderUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("err = %v, want *ProviderUnavailableError", err)
	}
	if _, err := LoadStrategy(pinDir); !errors.Is(err, ErrStrategyNotPersisted) {
		t.Fatalf("LoadStrategy err = %v, want ErrStrategyNotPersisted", err)
	}
}

// TestResolve_ExplicitStrategyDisagreeingWithRecordIsRefused proves a
// configured strategy that differs from the recorded one is refused by name:
// switching would orphan every PIN set under the recorded backend.
func TestResolve_ExplicitStrategyDisagreeingWithRecordIsRefused(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, qrdbsdk.PINStrategySoftware); err != nil {
		t.Fatalf("SaveStrategy: %v", err)
	}

	_, _, err := Resolve(ResolveConfig{
		PINDir:   pinDir,
		Strategy: qrdbsdk.PINStrategyTPM2,
		Config: Config{
			TPM:      fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true, authReady: true}, available: true},
			Software: softwareProvider{},
		},
	})
	var mismatch *StrategyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want *StrategyMismatchError", err)
	}
	if mismatch.Configured != qrdbsdk.PINStrategyTPM2 || mismatch.Persisted != qrdbsdk.PINStrategySoftware {
		t.Fatalf("mismatch = %+v", mismatch)
	}
}

// TestResolve_ExplicitStrategyMatchingRecordBuildsIt proves a configured
// strategy equal to the recorded one resolves normally.
func TestResolve_ExplicitStrategyMatchingRecordBuildsIt(t *testing.T) {
	pinDir := t.TempDir()
	if err := SaveStrategy(pinDir, qrdbsdk.PINStrategyTPM2); err != nil {
		t.Fatalf("SaveStrategy: %v", err)
	}

	backend, strategy, err := Resolve(ResolveConfig{
		PINDir:   pinDir,
		Strategy: qrdbsdk.PINStrategyTPM2,
		Config: Config{
			TPM:      fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true, authReady: true}, available: true},
			Software: softwareProvider{},
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strategy != qrdbsdk.PINStrategyTPM2 || backend.Strategy() != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("strategy = %q (backend %q), want tpm2", strategy, backend.Strategy())
	}
}

// TestResolve_UnknownExplicitStrategyIsRefused proves a configured strategy
// this build does not know is a typed error, not a silent default.
func TestResolve_UnknownExplicitStrategyIsRefused(t *testing.T) {
	_, _, err := Resolve(ResolveConfig{
		PINDir:   t.TempDir(),
		Strategy: "hsm9000",
		Config:   Config{Software: softwareProvider{}},
	})
	var unknown *UnknownStrategyError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want *UnknownStrategyError", err)
	}
}
