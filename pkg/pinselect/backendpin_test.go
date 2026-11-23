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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func backendPINCfg(t *testing.T) BackendPINConfig {
	t.Helper()
	return BackendPINConfig{
		PINDir:           filepath.Join(t.TempDir(), "pin"),
		BarrierAvailable: true,
	}
}

func TestResolveBackendPIN_AutoPicksTPM2WhenPresent(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.TPMPresent = true
	got, err := ResolveBackendPIN(cfg)
	if err != nil {
		t.Fatalf("ResolveBackendPIN: %v", err)
	}
	if got != BackendPINTPM2 {
		t.Fatalf("strategy = %q, want %q", got, BackendPINTPM2)
	}
	persisted, err := LoadBackendPINStrategy(cfg.PINDir)
	if err != nil || persisted != BackendPINTPM2 {
		t.Fatalf("persisted = %q, %v; want %q", persisted, err, BackendPINTPM2)
	}
}

func TestResolveBackendPIN_AutoPicksSealedWithoutTPM(t *testing.T) {
	// The i.MX 95 has no TPM 2.0: auto selects sealed.
	cfg := backendPINCfg(t)
	got, err := ResolveBackendPIN(cfg)
	if err != nil {
		t.Fatalf("ResolveBackendPIN: %v", err)
	}
	if got != BackendPINSealed {
		t.Fatalf("strategy = %q, want %q", got, BackendPINSealed)
	}
	persisted, err := LoadBackendPINStrategy(cfg.PINDir)
	if err != nil || persisted != BackendPINSealed {
		t.Fatalf("persisted = %q, %v; want %q", persisted, err, BackendPINSealed)
	}
}

func TestResolveBackendPIN_EmptyStrategyIsAuto(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.Strategy = ""
	got, err := ResolveBackendPIN(cfg)
	if err != nil || got != BackendPINSealed {
		t.Fatalf("got %q, %v; want %q", got, err, BackendPINSealed)
	}
}

func TestResolveBackendPIN_PersistedGovernsAuto(t *testing.T) {
	cfg := backendPINCfg(t)
	if err := SaveBackendPINStrategy(cfg.PINDir, BackendPINManual); err != nil {
		t.Fatalf("SaveBackendPINStrategy: %v", err)
	}
	cfg.TPMPresent = true
	got, err := ResolveBackendPIN(cfg)
	if err != nil || got != BackendPINManual {
		t.Fatalf("got %q, %v; want %q", got, err, BackendPINManual)
	}
}

func TestResolveBackendPIN_ExplicitManualNeedsNothing(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.BarrierAvailable = false
	cfg.Strategy = BackendPINManual
	got, err := ResolveBackendPIN(cfg)
	if err != nil || got != BackendPINManual {
		t.Fatalf("got %q, %v; want %q", got, err, BackendPINManual)
	}
}

func TestResolveBackendPIN_PKCS11StrategyIsRefused(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.Strategy = "pkcs11"
	_, err := ResolveBackendPIN(cfg)
	if !errors.Is(err, ErrBackendPINSelfStore) {
		t.Fatalf("err = %v, want ErrBackendPINSelfStore", err)
	}
	assertNoBackendPINRecord(t, cfg.PINDir)
}

func TestResolveBackendPIN_SealedOnPKCS11BarrierIsRefused(t *testing.T) {
	// A barrier whose key lives on the PKCS#11 backend would make the
	// backend the store of its own PIN.
	cfg := backendPINCfg(t)
	cfg.Strategy = BackendPINSealed
	cfg.SealerIsPKCS11 = true
	_, err := ResolveBackendPIN(cfg)
	if !errors.Is(err, ErrBackendPINSelfStore) {
		t.Fatalf("err = %v, want ErrBackendPINSelfStore", err)
	}
	assertNoBackendPINRecord(t, cfg.PINDir)
}

func TestResolveBackendPIN_AutoWithPKCS11BarrierAndNoTPMFailsClosed(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.SealerIsPKCS11 = true
	_, err := ResolveBackendPIN(cfg)
	if !errors.Is(err, ErrBackendPINSelfStore) {
		t.Fatalf("err = %v, want ErrBackendPINSelfStore", err)
	}
	assertNoBackendPINRecord(t, cfg.PINDir)
}

func TestResolveBackendPIN_ExplicitTPM2WithoutTPMFailsClosed(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.Strategy = BackendPINTPM2
	_, err := ResolveBackendPIN(cfg)
	var unavailable *BackendPINUnavailableError
	if !errors.As(err, &unavailable) || unavailable.Strategy != BackendPINTPM2 {
		t.Fatalf("err = %v, want BackendPINUnavailableError for tpm2", err)
	}
	assertNoBackendPINRecord(t, cfg.PINDir)
}

func TestResolveBackendPIN_PersistedTPM2WithoutTPMNeverDowngrades(t *testing.T) {
	cfg := backendPINCfg(t)
	if err := SaveBackendPINStrategy(cfg.PINDir, BackendPINTPM2); err != nil {
		t.Fatalf("SaveBackendPINStrategy: %v", err)
	}
	got, err := ResolveBackendPIN(cfg)
	var unavailable *BackendPINUnavailableError
	if !errors.As(err, &unavailable) {
		t.Fatalf("got %q, %v; want BackendPINUnavailableError", got, err)
	}
	persisted, _ := LoadBackendPINStrategy(cfg.PINDir)
	if persisted != BackendPINTPM2 {
		t.Fatalf("record rewritten to %q", persisted)
	}
}

func TestResolveBackendPIN_SealedWithoutBarrierFailsClosed(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.BarrierAvailable = false
	_, err := ResolveBackendPIN(cfg)
	var unavailable *BackendPINUnavailableError
	if !errors.As(err, &unavailable) || unavailable.Strategy != BackendPINSealed {
		t.Fatalf("err = %v, want BackendPINUnavailableError for sealed", err)
	}
	assertNoBackendPINRecord(t, cfg.PINDir)
}

func TestResolveBackendPIN_ExplicitDisagreeingWithRecordIsRefused(t *testing.T) {
	cfg := backendPINCfg(t)
	if err := SaveBackendPINStrategy(cfg.PINDir, BackendPINManual); err != nil {
		t.Fatalf("SaveBackendPINStrategy: %v", err)
	}
	cfg.Strategy = BackendPINSealed
	_, err := ResolveBackendPIN(cfg)
	var mismatch *BackendPINMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v, want BackendPINMismatchError", err)
	}
}

func TestResolveBackendPIN_UnknownStrategyIsRefused(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.Strategy = "plaintext"
	_, err := ResolveBackendPIN(cfg)
	var unknown *UnknownBackendPINStrategyError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want UnknownBackendPINStrategyError", err)
	}
}

func TestResolveBackendPIN_MinimumRefusesBelow(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.Minimum = BackendPINTPM2
	_, err := ResolveBackendPIN(cfg) // auto -> sealed, below tpm2
	var below *BackendPINBelowMinimumError
	if !errors.As(err, &below) || below.Strategy != BackendPINSealed || below.Minimum != BackendPINTPM2 {
		t.Fatalf("err = %v, want BackendPINBelowMinimumError sealed<tpm2", err)
	}
	assertNoBackendPINRecord(t, cfg.PINDir)
}

func TestResolveBackendPIN_MinimumRefusesPersistedBelow(t *testing.T) {
	cfg := backendPINCfg(t)
	if err := SaveBackendPINStrategy(cfg.PINDir, BackendPINTPM2); err != nil {
		t.Fatalf("SaveBackendPINStrategy: %v", err)
	}
	cfg.TPMPresent = true
	cfg.Minimum = BackendPINManual
	_, err := ResolveBackendPIN(cfg)
	var below *BackendPINBelowMinimumError
	if !errors.As(err, &below) {
		t.Fatalf("err = %v, want BackendPINBelowMinimumError", err)
	}
}

func TestResolveBackendPIN_MinimumMetPasses(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.TPMPresent = true
	cfg.Minimum = BackendPINSealed
	got, err := ResolveBackendPIN(cfg)
	if err != nil || got != BackendPINTPM2 {
		t.Fatalf("got %q, %v; want %q", got, err, BackendPINTPM2)
	}
}

func TestResolveBackendPIN_InvalidMinimumIsRefused(t *testing.T) {
	cfg := backendPINCfg(t)
	cfg.Minimum = BackendPINAuto
	_, err := ResolveBackendPIN(cfg)
	var unknown *UnknownBackendPINStrategyError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v, want UnknownBackendPINStrategyError", err)
	}
}

func TestLoadBackendPINStrategy_NotPersisted(t *testing.T) {
	_, err := LoadBackendPINStrategy(filepath.Join(t.TempDir(), "pin"))
	if !errors.Is(err, ErrBackendPINStrategyNotPersisted) {
		t.Fatalf("err = %v, want ErrBackendPINStrategyNotPersisted", err)
	}
}

func TestLoadBackendPINStrategy_CorruptIsLoadError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(BackendPINStrategyPath(dir), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadBackendPINStrategy(dir)
	var loadErr *StrategyLoadError
	if !errors.As(err, &loadErr) {
		t.Fatalf("err = %v, want StrategyLoadError", err)
	}
}

// An existing record with no strategy ({} or null) is a load error, never
// "not persisted": ResolveBackendPIN must not treat it as a fresh install
// and overwrite a pinned strategy (docs/SPEC.md:78, fail closed).
func TestLoadBackendPINStrategy_EmptyRecordIsLoadError(t *testing.T) {
	for _, body := range []string{"{}", "null", `{"strategy":""}`} {
		dir := t.TempDir()
		if err := os.WriteFile(BackendPINStrategyPath(dir), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := LoadBackendPINStrategy(dir)
		var loadErr *StrategyLoadError
		if !errors.As(err, &loadErr) {
			t.Fatalf("record %s: err = %v, want StrategyLoadError", body, err)
		}
		if errors.Is(err, ErrBackendPINStrategyNotPersisted) {
			t.Fatalf("record %s: reported as not persisted", body)
		}
	}
}

func TestResolveBackendPIN_EmptyRecordIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := BackendPINStrategyPath(dir)
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ResolveBackendPIN(BackendPINConfig{PINDir: dir, TPMPresent: true, BarrierAvailable: true})
	if err == nil {
		t.Fatal("ResolveBackendPIN accepted an empty strategy record")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != "{}" {
		t.Fatalf("record overwritten: %s", got)
	}
}

func TestBackendPINStrategyPath_DistinctFromQRDBStrategy(t *testing.T) {
	dir := t.TempDir()
	if BackendPINStrategyPath(dir) == StrategyPath(dir) {
		t.Fatal("backend PIN record must not share the qrdb PIN strategy record")
	}
}

func assertNoBackendPINRecord(t *testing.T, pinDir string) {
	t.Helper()
	if _, err := LoadBackendPINStrategy(pinDir); !errors.Is(err, ErrBackendPINStrategyNotPersisted) {
		t.Fatalf("a refused resolution persisted a record: %v", err)
	}
}

// --- holder lifecycle ---

func fixedRelease(pin string, calls *int) BackendPINRelease {
	return func(context.Context) ([]byte, error) {
		*calls++
		return []byte(pin), nil
	}
}

func TestBackendPIN_SealedReleasedOnlyAfterUnseal(t *testing.T) {
	calls := 0
	h := NewBackendPIN(BackendPINSealed, fixedRelease("1234", &calls))
	if h.AvailableAtStart() {
		t.Fatal("sealed PIN must not be available at start")
	}
	if _, err := h.PIN(); !errors.Is(err, ErrBackendPINSealed) {
		t.Fatalf("PIN before unseal: err = %v, want ErrBackendPINSealed", err)
	}
	if calls != 0 {
		t.Fatal("release called before unseal")
	}
	if err := h.Unseal(context.Background(), nil); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	pin, err := h.PIN()
	if err != nil || string(pin) != "1234" {
		t.Fatal("sealed PIN not released after unseal")
	}
	if calls != 1 {
		t.Fatalf("release calls = %d, want 1", calls)
	}
}

func TestBackendPIN_SealedRefusesSuppliedPIN(t *testing.T) {
	calls := 0
	h := NewBackendPIN(BackendPINSealed, fixedRelease("1234", &calls))
	if err := h.Unseal(context.Background(), []byte("9999")); !errors.Is(err, ErrBackendPINNotManual) {
		t.Fatalf("err = %v, want ErrBackendPINNotManual", err)
	}
}

func TestBackendPIN_SealedReleaseFailureFailsClosed(t *testing.T) {
	boom := errors.New("barrier sealed")
	h := NewBackendPIN(BackendPINSealed, func(context.Context) ([]byte, error) { return nil, boom })
	if err := h.Unseal(context.Background(), nil); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want release error", err)
	}
	if _, err := h.PIN(); !errors.Is(err, ErrBackendPINSealed) {
		t.Fatalf("PIN after failed release: err = %v", err)
	}
}

func TestBackendPIN_TPM2AvailableAtStart(t *testing.T) {
	calls := 0
	h := NewBackendPIN(BackendPINTPM2, fixedRelease("1234", &calls))
	if !h.AvailableAtStart() {
		t.Fatal("tpm2 PIN must be available at start")
	}
	if h.StopsAtSeal() {
		t.Fatal("tpm2 PIN backend does not depend on the barrier and keeps running at seal")
	}
	if err := h.Unseal(context.Background(), nil); err != nil {
		t.Fatalf("start-up release: %v", err)
	}
	if pin, err := h.PIN(); err != nil || string(pin) != "1234" {
		t.Fatal("tpm2 PIN not released at start")
	}
}

func TestBackendPIN_ManualFromUnsealRequestZeroizedAtSeal(t *testing.T) {
	h := NewBackendPIN(BackendPINManual, nil)
	if h.AvailableAtStart() {
		t.Fatal("manual PIN must not be available at start")
	}
	if !h.StopsAtSeal() {
		t.Fatal("manual PIN backend must stop at seal")
	}
	if err := h.Unseal(context.Background(), nil); !errors.Is(err, ErrBackendPINRequired) {
		t.Fatalf("Unseal without PIN: err = %v, want ErrBackendPINRequired", err)
	}
	supplied := []byte("4321")
	if err := h.Unseal(context.Background(), supplied); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	// The holder keeps its own copy: the caller may zeroize the request.
	for i := range supplied {
		supplied[i] = 0
	}
	pin, err := h.PIN()
	if err != nil || string(pin) != "4321" {
		t.Fatal("manual PIN not held after unseal")
	}
	held := h.pin
	h.Seal()
	for i, b := range held {
		if b != 0 {
			t.Fatalf("byte %d not zeroized at seal", i)
		}
	}
	if _, err := h.PIN(); !errors.Is(err, ErrBackendPINSealed) {
		t.Fatalf("PIN after seal: err = %v, want ErrBackendPINSealed", err)
	}
}

func TestBackendPIN_ManualNeverPersisted(t *testing.T) {
	pinDir := filepath.Join(t.TempDir(), "pin")
	cfg := BackendPINConfig{PINDir: pinDir, Strategy: BackendPINManual}
	if _, err := ResolveBackendPIN(cfg); err != nil {
		t.Fatalf("ResolveBackendPIN: %v", err)
	}
	h := NewBackendPIN(BackendPINManual, nil)
	if err := h.Unseal(context.Background(), []byte("4321")); err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(pinDir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if containsBytes(data, []byte("4321")) {
			t.Fatalf("manual PIN written to %s", e.Name())
		}
	}
}

func TestBackendPIN_PINReturnsCopy(t *testing.T) {
	h := NewBackendPIN(BackendPINManual, nil)
	if err := h.Unseal(context.Background(), []byte("4321")); err != nil {
		t.Fatal(err)
	}
	pin, _ := h.PIN()
	pin[0] = 'x'
	again, _ := h.PIN()
	if string(again) != "4321" {
		t.Fatal("PIN returned the held buffer, not a copy")
	}
}

func TestBackendPIN_SealedSealZeroizesAndRequiresUnsealAgain(t *testing.T) {
	calls := 0
	h := NewBackendPIN(BackendPINSealed, fixedRelease("1234", &calls))
	if h.StopsAtSeal() {
		t.Fatal("sealed PIN backend keeps its session at seal; only manual stops")
	}
	if err := h.Unseal(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	held := h.pin
	h.Seal()
	for i, b := range held {
		if b != 0 {
			t.Fatalf("byte %d not zeroized at seal", i)
		}
	}
	if _, err := h.PIN(); !errors.Is(err, ErrBackendPINSealed) {
		t.Fatalf("PIN after seal: err = %v", err)
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
