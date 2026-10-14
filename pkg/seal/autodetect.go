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

package seal

import (
	"errors"
	"log/slog"
	"time"

	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// This file is the ONE canonical hardware-seal autodetect for the stack. It
// generalizes the policy previously duplicated in go-quicbaas
// (pkg/server/seal_autodetect.go) and xkey (barrier_service ProbeStrategies):
// probe a TPM exactly once, bounded and non-provisioning, and — only when a
// provisioned, seal-capable device answers — build the go-xkms TPM2 sealing
// strategy. Consumers (go-quicbaas, xkey, xkms's own barrier, cluster CA key
// protection) call this instead of re-implementing the probe. go-xkms owns all
// hardware crypto, so this is its to provide.
//
// Hardening carried over verbatim from the quicbaas original, and it matters:
//   - The probe is OPT-IN at the caller: an absent TPM2 config yields an empty
//     result (software fallback), never a blind hardware default.
//   - Autodetect NEVER provisions. A fresh device returns
//     ErrTPM2BackendNotInitialized; that is treated as "not usable" so a slow
//     or unprovisioned TPM can never stall boot. Only an already-provisioned,
//     CanSeal() device is selected. An operator wanting boot-time provisioning
//     must construct the tpm2 backend explicitly.
//   - The TPM is opened EXACTLY ONCE. The single open's backend is returned in
//     the result and reused for the barrier / key stores for its whole life —
//     there is no probe-then-reopen. A swtpm emulator empirically HANGS on a
//     second open within a process, so never relying on reopen keeps every
//     path emulator-safe.

// DefaultProbeTimeout bounds the single autodetect TPM open so a slow or wedged
// TPM can never stall a daemon boot.
const DefaultProbeTimeout = 3 * time.Second

// RequiredTPMOpenTimeout bounds the TPM open when the configuration requires
// the tpm2 strategy. DefaultProbeTimeout only keeps an optional probe from
// delaying startup; a required TPM that is slow to open (a loaded host, the
// simulator under the race detector) must not be reported as missing, while a
// wedged one still fails startup.
const RequiredTPMOpenTimeout = 30 * time.Second

// TPM2ProbeConfig is the subset of the TPM2 backend configuration the
// autodetect probe needs. Callers map their own config onto it so this package
// does not depend on any consumer's config type.
type TPM2ProbeConfig struct {
	Device          string
	KeyDir          string
	UseSimulator    bool
	SimulatorHost   string
	SimulatorPort   int
	SRKHandle       uint32
	PlatformPCR     uint
	PlatformPCRBank string
}

// AutodetectOptions configures BuildBestStrategy.
type AutodetectOptions struct {
	// TPM2 enables the TPM probe when non-nil. Nil skips it (software fallback).
	TPM2 *TPM2ProbeConfig

	// ProbeTimeout bounds the single TPM open. Zero uses DefaultProbeTimeout.
	ProbeTimeout time.Duration

	// Logger receives probe diagnostics. Nil uses slog.Default().
	Logger *slog.Logger
}

// AutodetectResult holds the selected hardware strategy (if any) and the
// underlying open sealer, so the caller can reuse the single TPM open for the
// barrier and node-local key stores, and Close it on shutdown.
type AutodetectResult struct {
	// Strategy is the selected hardware SealingStrategy, or nil when no usable
	// hardware sealer was found (the caller then uses the software strategy).
	Strategy SealingStrategy

	// Sealer is the underlying types.Sealer (the open TPM backend) for reuse in
	// sealed key stores; nil when Strategy is nil.
	Sealer types.Sealer

	// ID is the selected strategy ID ("tpm2"), or empty when none.
	ID StrategyID

	// closer releases the single TPM open. Nil when no backend was opened.
	closer interface{ Close() error }
}

// HardwareAvailable reports whether a usable hardware sealer was selected.
func (r *AutodetectResult) HardwareAvailable() bool {
	return r != nil && r.Strategy != nil
}

// Close releases the underlying TPM open, if any. Safe on a nil receiver and
// when no backend was opened.
func (r *AutodetectResult) Close() error {
	if r == nil || r.closer == nil {
		return nil
	}
	return r.closer.Close()
}

// tpm2Sealer is the surface a probed TPM backend must expose: seal capability
// plus lifecycle. *tpm2backend.Backend satisfies it.
type tpm2Sealer interface {
	types.Sealer
	Close() error
}

// openTPM2Backend opens a TPM2 backend from the probe config. It is a package
// var so tests can stub the open deterministically without touching hardware,
// mirroring quicbaas's tpm2AutoSealStrategy seam. errTPM2NotInitialized lets
// the probe classify a fresh/unprovisioned device as "not usable".
//
// cfg.KeyDir is resolved to a TPM blob store over a file-based
// storage.Backend here, not passed through as a directory: tpm2backend.Config
// takes its key store exclusively through Keys. The directory itself is
// genuinely pre-datastore material (the node-barrier seal strategy's own key,
// which must exist before -- and can seal -- the datastore it protects), so it
// stays a real file-based engine here rather than a qrdb-backed one.
var openTPM2Backend = func(cfg *TPM2ProbeConfig) (tpm2Sealer, error) {
	keyStorage, err := file.New(cfg.KeyDir)
	if err != nil {
		return nil, err
	}
	keys, err := store.NewBackendBlobStore(slog.Default(), keyStorage)
	if err != nil {
		return nil, err
	}
	return tpm2backend.NewBackend(&tpm2backend.Config{
		Device:          cfg.Device,
		Keys:            keys,
		UseSimulator:    cfg.UseSimulator,
		SimulatorHost:   cfg.SimulatorHost,
		SimulatorPort:   cfg.SimulatorPort,
		SRKHandle:       cfg.SRKHandle,
		PlatformPCR:     cfg.PlatformPCR,
		PlatformPCRBank: cfg.PlatformPCRBank,
	})
}

// errTPM2NotInitialized is the sentinel a fresh/unprovisioned TPM open returns;
// autodetect treats it as "not usable" (no provisioning).
var errTPM2NotInitialized = tpm2backend.ErrNotInitialized

// BuildBestStrategy runs the single bounded, non-provisioning TPM probe and
// returns the best available hardware seal strategy. When no provisioned,
// seal-capable TPM is present (or TPM2 config is nil), it returns a result with
// a nil Strategy; the caller then falls back to the software strategy. The
// returned result owns the single TPM open — call Close() on shutdown.
func BuildBestStrategy(opts AutodetectOptions) *AutodetectResult {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if opts.TPM2 == nil {
		return &AutodetectResult{}
	}
	res, err := OpenTPM2Strategy(opts)
	switch {
	case err == nil:
		logger.Info("seal autodetect: provisioned, seal-capable TPM present; selecting tpm2 strategy")
		return res
	case errors.Is(err, errTPM2NotInitialized):
		logger.Debug("seal autodetect: TPM present but unprovisioned; not selecting (construct the tpm2 backend explicitly to provision)")
	case errors.Is(err, ErrTPM2ProbeTimeout):
		logger.Warn("seal autodetect: TPM open timed out; selecting software", slog.Duration("timeout", probeTimeout(opts)))
	case errors.Is(err, ErrTPM2NotSealCapable):
		logger.Debug("seal autodetect: TPM open but not seal-capable; selecting software")
	default:
		logger.Debug("seal autodetect: TPM open failed; selecting software", slog.String("error", err.Error()))
	}
	return &AutodetectResult{}
}

// OpenTPM2Strategy makes the single bounded, non-provisioning TPM open that
// BuildBestStrategy makes, but reports why no TPM was selected as a
// *TPM2ProbeError instead of falling back. Callers whose configuration
// requires the TPM use it so a slow TPM is not reported as an absent one.
// opts.TPM2 must be non-nil. The returned result owns the TPM open — call
// Close() on shutdown.
func OpenTPM2Strategy(opts AutodetectOptions) (*AutodetectResult, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	type openResult struct {
		backend tpm2Sealer
		err     error
	}
	resultCh := make(chan openResult, 1)
	go func() {
		backend, err := openTPM2Backend(opts.TPM2)
		resultCh <- openResult{backend: backend, err: err}
	}()

	select {
	case r := <-resultCh:
		if r.err != nil {
			return nil, &TPM2ProbeError{Err: r.err}
		}
		if !r.backend.CanSeal() {
			if cerr := r.backend.Close(); cerr != nil {
				logger.Debug("seal autodetect: failed to close a non-seal-capable TPM backend", slog.String("error", cerr.Error()))
			}
			return nil, &TPM2ProbeError{Err: ErrTPM2NotSealCapable}
		}
		return &AutodetectResult{
			Strategy: NewTPM2Strategy(r.backend, nil),
			Sealer:   r.backend,
			ID:       StrategyTPM2,
			closer:   r.backend,
		}, nil
	case <-time.After(probeTimeout(opts)):
		// Drain and close the late open so a wedged TPM session cannot leak.
		go func() {
			r := <-resultCh
			if r.err == nil && r.backend != nil {
				if cerr := r.backend.Close(); cerr != nil {
					logger.Debug("seal autodetect: failed to close a late-arriving TPM open", slog.String("error", cerr.Error()))
				}
			}
		}()
		return nil, &TPM2ProbeError{Err: ErrTPM2ProbeTimeout}
	}
}

// probeTimeout returns opts.ProbeTimeout, or DefaultProbeTimeout when unset.
func probeTimeout(opts AutodetectOptions) time.Duration {
	if opts.ProbeTimeout == 0 {
		return DefaultProbeTimeout
	}
	return opts.ProbeTimeout
}

// ProbeStrategies returns the hardware strategy IDs currently available,
// alongside the always-present software fallback — the surface a UI (e.g. the
// xkey setup wizard) needs to LIST selectable seal modes. It shares the single
// probe with BuildBestStrategy; when a TPM is selected the returned result owns
// its open (Close on shutdown), so listing and auto-selecting are one path.
func ProbeStrategies(opts AutodetectOptions) (available []StrategyID, result *AutodetectResult) {
	result = BuildBestStrategy(opts)
	available = []StrategyID{StrategyPassphrase, StrategyNone}
	if result.HardwareAvailable() {
		available = append([]StrategyID{result.ID}, available...)
	}
	return available, result
}
