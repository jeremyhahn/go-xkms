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

package pinstrategy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// fakePlatformAuth is a minimal xkmssdk.TPMPlatformAuthProvider for resolver
// tests.
type fakePlatformAuth struct {
	provisioned bool
	authReady   bool
}

func (f *fakePlatformAuth) VerifyAuth(string) error                     { return nil }
func (f *fakePlatformAuth) ChangeAuth(string, string) error             { return nil }
func (f *fakePlatformAuth) GetLockoutInfo() (int, int, int, int, error) { return 0, 0, 0, 0, nil }
func (f *fakePlatformAuth) DictionaryAttackLockoutReset([]byte) error   { return nil }
func (f *fakePlatformAuth) IsProvisioned() bool                         { return f.provisioned }
func (f *fakePlatformAuth) IsAuthReady() bool                           { return f.authReady }

var _ xkmssdk.TPMPlatformAuthProvider = (*fakePlatformAuth)(nil)

type fakeTPMProvider struct {
	pa        xkmssdk.TPMPlatformAuthProvider
	available bool
}

func (p fakeTPMProvider) PlatformAuth() (xkmssdk.TPMPlatformAuthProvider, bool) {
	return p.pa, p.available
}

type fakePKCS11Provider struct {
	backend   qrdbsdk.PINBackend
	available bool
}

func (p fakePKCS11Provider) Backend() (qrdbsdk.PINBackend, bool) { return p.backend, p.available }

// fakeSoftwareProvider builds an in-memory software backend for tests.
// failErr, when set, makes Storage return an error to exercise the
// failure path.
type fakeSoftwareProvider struct{ failErr error }

func (s fakeSoftwareProvider) Storage() (qrdbsdk.PINStorage, error) {
	if s.failErr != nil {
		return nil, s.failErr
	}
	return nil, nil // nil store => in-memory software backend
}

func (s fakeSoftwareProvider) HashConfig() qrdbsdk.PINHashConfig {
	return qrdbsdk.DefaultHashConfig()
}

func TestResolve_FreshDataDirAutoSelectsAndPersists(t *testing.T) {
	pinDir := t.TempDir()

	backend, strategy, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			TPM:      fakeTPMProvider{available: false},
			Software: fakeSoftwareProvider{},
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

	persisted, err := Load(pinDir)
	if err != nil {
		t.Fatalf("Load after Resolve: %v", err)
	}
	if persisted != qrdbsdk.PINStrategySoftware {
		t.Fatalf("persisted strategy = %q, want software", persisted)
	}
}

func TestResolve_FreshDataDirPersistsTPMWhenAvailable(t *testing.T) {
	pinDir := t.TempDir()

	_, strategy, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			TPM:      fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true, authReady: true}, available: true},
			Software: fakeSoftwareProvider{},
		},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if strategy != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("strategy = %q, want tpm2", strategy)
	}

	persisted, err := Load(pinDir)
	if err != nil {
		t.Fatalf("Load after Resolve: %v", err)
	}
	if persisted != qrdbsdk.PINStrategyTPM2 {
		t.Fatalf("persisted strategy = %q, want tpm2", persisted)
	}
}

func TestResolve_PersistedSoftwareGoverns(t *testing.T) {
	pinDir := t.TempDir()
	if err := Save(pinDir, qrdbsdk.PINStrategySoftware); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// A TPM is available, but the persisted strategy is software, so
	// Resolve must not switch to it: the persisted record governs.
	backend, strategy, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			TPM:      fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true, authReady: true}, available: true},
			Software: fakeSoftwareProvider{},
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
	if err := Save(pinDir, qrdbsdk.PINStrategyTPM2); err != nil {
		t.Fatalf("Save: %v", err)
	}

	backend, strategy, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			TPM:      fakeTPMProvider{pa: &fakePlatformAuth{provisioned: true, authReady: true}, available: true},
			Software: fakeSoftwareProvider{},
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
	if err := Save(pinDir, qrdbsdk.PINStrategyTPM2); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// No TPM provider configured at all in this environment (e.g. a
	// build without TPM support, or a host with no device).
	_, _, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			Software: fakeSoftwareProvider{},
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
	if err := Save(pinDir, qrdbsdk.PINStrategyTPM2); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The TPM provider exists but cannot answer right now (device
	// missing, SRK unprovisioned, ...): never fall back to software.
	_, _, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			TPM:      fakeTPMProvider{available: false},
			Software: fakeSoftwareProvider{},
		},
	})

	var unavailable *ProviderUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("Resolve: got %T %v, want *ProviderUnavailableError", err, err)
	}
}

func TestResolve_PersistedPKCS11WithoutProviderRefuses(t *testing.T) {
	pinDir := t.TempDir()
	if err := Save(pinDir, qrdbsdk.PINStrategyPKCS11); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, _, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			Software: fakeSoftwareProvider{},
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
	if err := Save(pinDir, qrdbsdk.PINStrategySoftware); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, _, err := Resolve(Config{
		PINDir:          pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{},
	})
	if !errors.Is(err, xkmssdk.ErrPINSelectNoSoftwareProvider) {
		t.Fatalf("Resolve: got %v, want xkmssdk.ErrPINSelectNoSoftwareProvider", err)
	}
}

func TestResolve_UnknownPersistedStrategyIsTypedError(t *testing.T) {
	pinDir := t.TempDir()
	if err := Save(pinDir, "quantum"); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, _, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			Software: fakeSoftwareProvider{},
		},
	})

	var unknown *UnknownStrategyError
	if !errors.As(err, &unknown) {
		t.Fatalf("Resolve: got %T %v, want *UnknownStrategyError", err, err)
	}
}

func TestResolve_PersistedPKCS11Governs(t *testing.T) {
	pinDir := t.TempDir()
	if err := Save(pinDir, qrdbsdk.PINStrategyPKCS11); err != nil {
		t.Fatalf("Save: %v", err)
	}

	stand, err := qrdbsdk.NewSoftwareBackend(nil, qrdbsdk.DefaultHashConfig())
	if err != nil {
		t.Fatalf("stand-in backend: %v", err)
	}

	backend, strategy, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			PKCS11:   fakePKCS11Provider{backend: stand, available: true},
			Software: fakeSoftwareProvider{},
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
	if err := Save(pinDir, qrdbsdk.PINStrategySoftware); err != nil {
		t.Fatalf("Save: %v", err)
	}

	sentinel := errors.New("disk gone")
	_, _, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			Software: fakeSoftwareProvider{failErr: sentinel},
		},
	})

	var storageErr *xkmssdk.PINSelectSoftwareStorageError
	if !errors.As(err, &storageErr) {
		t.Fatalf("Resolve: got %T %v, want *xkmssdk.PINSelectSoftwareStorageError", err, err)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("Resolve: expected wrapped sentinel, got %v", err)
	}
}

func TestResolve_SelectFailurePropagatesOnFreshDataDir(t *testing.T) {
	pinDir := t.TempDir()

	// No software provider at all: pinselect.Select itself fails, and a
	// fresh data directory must surface that rather than persist nothing.
	_, _, err := Resolve(Config{
		PINDir:          pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{},
	})
	if !errors.Is(err, xkmssdk.ErrPINSelectNoSoftwareProvider) {
		t.Fatalf("Resolve: got %v, want xkmssdk.ErrPINSelectNoSoftwareProvider", err)
	}

	// Nothing must have been persisted from the failed attempt.
	if _, loadErr := Load(pinDir); !errors.Is(loadErr, ErrStrategyNotPersisted) {
		t.Fatalf("Load after failed Resolve: got %v, want ErrStrategyNotPersisted", loadErr)
	}
}

func TestResolve_SaveFailureOnFreshDataDirPropagates(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permission bits")
	}

	pinDir := t.TempDir()
	if err := os.Chmod(pinDir, 0500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(pinDir, 0700) })

	_, _, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			Software: fakeSoftwareProvider{},
		},
	})

	var saveErr *SaveError
	if !errors.As(err, &saveErr) {
		t.Fatalf("Resolve: got %T %v, want *SaveError", err, err)
	}
}

func TestResolve_LoadFailurePropagates(t *testing.T) {
	pinDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pinDir, "strategy"), []byte("{bad"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	_, _, err := Resolve(Config{
		PINDir: pinDir,
		PINSelectConfig: xkmssdk.PINSelectConfig{
			Software: fakeSoftwareProvider{},
		},
	})
	var loadErr *LoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("Resolve: got %T %v, want *LoadError", err, err)
	}
}
