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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
)

// BackendPINStrategy names how xkmsd obtains the PIN of a PIN-protected
// PKCS#11 backend (backends.pkcs11.pin, rng.pkcs11.pin). Owner decision
// 230 (#2262).
type BackendPINStrategy string

const (
	// BackendPINAuto selects tpm2 when a TPM 2.0 is present, otherwise
	// sealed. It is never persisted: the concrete choice is.
	BackendPINAuto BackendPINStrategy = "auto"
	// BackendPINTPM2 seals the PIN to the TPM; it is released at start.
	BackendPINTPM2 BackendPINStrategy = "tpm2"
	// BackendPINSealed seals the PIN under the barrier; it is released at
	// unseal and the PKCS#11 backend starts after unseal.
	BackendPINSealed BackendPINStrategy = "sealed"
	// BackendPINManual never stores the PIN: it is supplied with the
	// unseal request, held in memory only and zeroized at seal, and the
	// backend stops at seal.
	BackendPINManual BackendPINStrategy = "manual"

	// backendPINPKCS11 is the refused self-store strategy.
	backendPINPKCS11 BackendPINStrategy = "pkcs11"

	backendPINStrategyFileName = "backend-strategy"
)

// backendPINRank orders the concrete strategies for the minimum check:
// sealed < tpm2 < manual.
var backendPINRank = map[BackendPINStrategy]int{
	BackendPINSealed: 1,
	BackendPINTPM2:   2,
	BackendPINManual: 3,
}

var (
	// ErrBackendPINSelfStore refuses a configuration in which the PKCS#11
	// backend would store its own PIN.
	ErrBackendPINSelfStore = errors.New("pinselect: PKCS#11 cannot be the store of its own PIN")
	// ErrBackendPINStrategyNotPersisted reports a data dir with no backend
	// PIN strategy record yet.
	ErrBackendPINStrategyNotPersisted = errors.New("pinselect: backend PIN strategy not persisted")
	// ErrBackendPINSealed reports the PIN is not released (before unseal or
	// after seal).
	ErrBackendPINSealed = errors.New("pinselect: backend PIN is sealed")
	// ErrBackendPINRequired reports a manual-strategy unseal without a PIN.
	ErrBackendPINRequired = errors.New("pinselect: manual backend PIN strategy needs the PIN in the unseal request")
	// ErrBackendPINNotManual refuses a PIN supplied in the unseal request
	// when the strategy is not manual.
	ErrBackendPINNotManual = errors.New("pinselect: backend PIN strategy is not manual; the unseal request must not carry a PIN")
)

// BackendPINUnavailableError reports a strategy whose store is absent on
// this node. Resolution fails closed: it never downgrades.
type BackendPINUnavailableError struct {
	Strategy BackendPINStrategy
	Reason   string
}

func (e *BackendPINUnavailableError) Error() string {
	return fmt.Sprintf("pinselect: backend PIN strategy %q unavailable: %s", e.Strategy, e.Reason)
}

// BackendPINMismatchError reports a configured strategy that disagrees with
// the persisted record.
type BackendPINMismatchError struct {
	Configured BackendPINStrategy
	Persisted  BackendPINStrategy
}

func (e *BackendPINMismatchError) Error() string {
	return fmt.Sprintf("pinselect: backend PIN strategy %q configured but %q persisted", e.Configured, e.Persisted)
}

// BackendPINBelowMinimumError refuses a strategy weaker than the
// configured minimum.
type BackendPINBelowMinimumError struct {
	Strategy BackendPINStrategy
	Minimum  BackendPINStrategy
}

func (e *BackendPINBelowMinimumError) Error() string {
	return fmt.Sprintf("pinselect: backend PIN strategy %q is below the minimum %q", e.Strategy, e.Minimum)
}

// UnknownBackendPINStrategyError reports an unrecognised strategy name.
type UnknownBackendPINStrategyError struct {
	Strategy BackendPINStrategy
}

func (e *UnknownBackendPINStrategyError) Error() string {
	return fmt.Sprintf("pinselect: unknown backend PIN strategy %q", e.Strategy)
}

// BackendPINConfig is the input of ResolveBackendPIN.
type BackendPINConfig struct {
	// PINDir holds <PINDir>/backend-strategy.
	PINDir string
	// Strategy is backend_pin.strategy; empty means auto.
	Strategy BackendPINStrategy
	// Minimum is backend_pin.minimum; empty means none.
	Minimum BackendPINStrategy
	// TPMPresent reports a usable TPM 2.0 on this node.
	TPMPresent bool
	// BarrierAvailable reports a barrier able to seal the PIN.
	BarrierAvailable bool
	// SealerIsPKCS11 reports a barrier whose key is on the PKCS#11 backend
	// itself: sealed would make the backend the store of its own PIN.
	SealerIsPKCS11 bool
	// Store names where the configured PIN is actually stored: tpm2 for a
	// PIN sealed to the TPM, sealed for a PIN stored under the barrier, or
	// any other value (for example a cloud seal strategy) for storage that
	// is neither. When set, a resolved or persisted strategy that differs
	// from it is refused with BackendPINStoreError before anything is
	// persisted: the strategy never claims a protection the store lacks.
	// Empty skips the check; manual, never stored, is not checked.
	Store BackendPINStrategy
	// TPMSealerAvailable reports a TPM the caller seals the PIN to itself
	// (whatever Store is): tpm2 then needs no TPM-sealed Store.
	TPMSealerAvailable bool
}

// BackendPINStoreError refuses a strategy that the PIN's actual storage
// does not provide.
type BackendPINStoreError struct {
	Strategy BackendPINStrategy
	Store    BackendPINStrategy
}

func (e *BackendPINStoreError) Error() string {
	return fmt.Sprintf("pinselect: backend PIN strategy %q resolved but the PIN is stored under %q", e.Strategy, e.Store)
}

// ResolveBackendPIN resolves and persists the backend PIN strategy. The
// persisted record governs later starts; a configured strategy that
// disagrees with it, an unavailable strategy, a self-store and a strategy
// below the minimum are refused, and nothing is persisted on refusal.
func ResolveBackendPIN(cfg BackendPINConfig) (BackendPINStrategy, error) {
	configured := cfg.Strategy
	if configured == "" {
		configured = BackendPINAuto
	}
	if err := checkBackendPINName(configured, true); err != nil {
		return "", err
	}
	if cfg.Minimum != "" {
		if err := checkBackendPINName(cfg.Minimum, false); err != nil {
			return "", err
		}
	}

	persisted, err := LoadBackendPINStrategy(cfg.PINDir)
	fresh := errors.Is(err, ErrBackendPINStrategyNotPersisted)
	if err != nil && !fresh {
		return "", err
	}

	var chosen BackendPINStrategy
	switch {
	case !fresh:
		if err := checkBackendPINName(persisted, false); err != nil {
			return "", err
		}
		if configured != BackendPINAuto && configured != persisted {
			return "", &BackendPINMismatchError{Configured: configured, Persisted: persisted}
		}
		chosen = persisted
	case configured == BackendPINAuto:
		chosen = BackendPINSealed
		if cfg.TPMPresent {
			chosen = BackendPINTPM2
		}
	default:
		chosen = configured
	}

	if err := checkBackendPINAvailable(cfg, chosen); err != nil {
		return "", err
	}
	// manual is never stored, so no store provides or contradicts it; tpm2
	// with a TPM sealer seals the PIN to the TPM whatever the store.
	tpmSealed := chosen == BackendPINTPM2 && cfg.TPMSealerAvailable
	if cfg.Store != "" && chosen != BackendPINManual && chosen != cfg.Store && !tpmSealed {
		return "", &BackendPINStoreError{Strategy: chosen, Store: cfg.Store}
	}
	if cfg.Minimum != "" && backendPINRank[chosen] < backendPINRank[cfg.Minimum] {
		return "", &BackendPINBelowMinimumError{Strategy: chosen, Minimum: cfg.Minimum}
	}
	if fresh {
		if err := SaveBackendPINStrategy(cfg.PINDir, chosen); err != nil {
			return "", err
		}
	}
	return chosen, nil
}

func checkBackendPINName(s BackendPINStrategy, allowAuto bool) error {
	if s == backendPINPKCS11 {
		return ErrBackendPINSelfStore
	}
	if s == BackendPINAuto && allowAuto {
		return nil
	}
	if _, ok := backendPINRank[s]; !ok {
		return &UnknownBackendPINStrategyError{Strategy: s}
	}
	return nil
}

func checkBackendPINAvailable(cfg BackendPINConfig, s BackendPINStrategy) error {
	switch s {
	case BackendPINTPM2:
		if !cfg.TPMPresent {
			return &BackendPINUnavailableError{Strategy: s, Reason: "no TPM 2.0 present"}
		}
	case BackendPINSealed:
		if cfg.SealerIsPKCS11 {
			return fmt.Errorf("%w: the barrier key is on the PKCS#11 backend", ErrBackendPINSelfStore)
		}
		if !cfg.BarrierAvailable {
			return &BackendPINUnavailableError{Strategy: s, Reason: "no barrier"}
		}
	}
	return nil
}

// BackendPINStrategyPath returns <pinDir>/backend-strategy, distinct from
// the qrdb PIN strategy record.
func BackendPINStrategyPath(pinDir string) string {
	return filepath.Join(pinDir, backendPINStrategyFileName)
}

type backendPINRecord struct {
	Strategy BackendPINStrategy `json:"strategy"`
}

// LoadBackendPINStrategy reads the persisted backend PIN strategy, for
// start-up and status.
func LoadBackendPINStrategy(pinDir string) (BackendPINStrategy, error) {
	path := BackendPINStrategyPath(pinDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrBackendPINStrategyNotPersisted
		}
		return "", &StrategyLoadError{Path: path, Cause: err}
	}
	var rec backendPINRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return "", &StrategyLoadError{Path: path, Cause: err}
	}
	if rec.Strategy == "" {
		// Only a missing file means unpersisted: an existing record with
		// no strategy ({} or null) fails closed so it is never treated as
		// a fresh install and overwritten (docs/SPEC.md:78).
		return "", &StrategyLoadError{Path: path, Cause: errors.New("record has no strategy")}
	}
	return rec.Strategy, nil
}

// SaveBackendPINStrategy persists the backend PIN strategy atomically.
func SaveBackendPINStrategy(pinDir string, s BackendPINStrategy) error {
	path := BackendPINStrategyPath(pinDir)
	if err := checkBackendPINName(s, false); err != nil {
		return &StrategySaveError{Path: path, Cause: err}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return &StrategySaveError{Path: path, Cause: err}
	}
	data, err := json.MarshalIndent(backendPINRecord{Strategy: s}, "", "  ")
	if err != nil {
		return &StrategySaveError{Path: path, Cause: err}
	}
	if err := fsutil.WriteFileAtomic(path, data, 0o600); err != nil {
		return &StrategySaveError{Path: path, Cause: err}
	}
	return nil
}

// BackendPINRelease returns the stored PIN (tpm2: TPM-unsealed; sealed:
// read under the unsealed barrier). The holder owns the returned slice.
type BackendPINRelease func(ctx context.Context) ([]byte, error)

// BackendPIN holds the backend PIN in memory between unseal and seal.
type BackendPIN struct {
	strategy BackendPINStrategy
	release  BackendPINRelease

	mu  sync.Mutex
	pin []byte
}

// NewBackendPIN returns a sealed holder. release is unused for manual.
func NewBackendPIN(s BackendPINStrategy, release BackendPINRelease) *BackendPIN {
	return &BackendPIN{strategy: s, release: release}
}

// Strategy returns the holder's strategy.
func (b *BackendPIN) Strategy() BackendPINStrategy { return b.strategy }

// AvailableAtStart reports a PIN released at start (tpm2): the PKCS#11
// backend may start before unseal. Otherwise it starts after unseal.
func (b *BackendPIN) AvailableAtStart() bool { return b.strategy == BackendPINTPM2 }

// StopsAtSeal reports a backend that must stop at seal (manual).
func (b *BackendPIN) StopsAtSeal() bool { return b.strategy == BackendPINManual }

// Unseal releases the PIN: manual takes a copy of supplied; the others
// call release and refuse a supplied PIN.
func (b *BackendPIN) Unseal(ctx context.Context, supplied []byte) error {
	var pin []byte
	if b.strategy == BackendPINManual {
		if len(supplied) == 0 {
			return ErrBackendPINRequired
		}
		pin = append([]byte(nil), supplied...)
	} else {
		if len(supplied) != 0 {
			return ErrBackendPINNotManual
		}
		if b.release == nil {
			return &BackendPINUnavailableError{Strategy: b.strategy, Reason: "no release function"}
		}
		got, err := b.release(ctx)
		if err != nil {
			return err
		}
		if len(got) == 0 {
			return &BackendPINUnavailableError{Strategy: b.strategy, Reason: "empty PIN released"}
		}
		pin = got
	}
	b.mu.Lock()
	zeroize(b.pin)
	b.pin = pin
	b.mu.Unlock()
	return nil
}

// PIN returns a copy of the released PIN, or ErrBackendPINSealed.
func (b *BackendPIN) PIN() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pin == nil {
		return nil, ErrBackendPINSealed
	}
	return append([]byte(nil), b.pin...), nil
}

// Seal zeroizes the held PIN.
func (b *BackendPIN) Seal() {
	b.mu.Lock()
	zeroize(b.pin)
	b.pin = nil
	b.mu.Unlock()
}

func zeroize(p []byte) {
	for i := range p {
		p[i] = 0
	}
}
