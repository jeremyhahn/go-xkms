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
	"log/slog"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// PlatformKeyStoreProvider is the minimal TPM surface pinstrategy needs:
// access to the platform key store that backs TPM2 PIN verification. Any
// xkmssdk.TrustedPlatformModule already satisfies it; NewTPMProvider is
// declared against this narrower interface, not the full TPM surface, so
// callers (and their tests) only need to supply the one method this
// package actually calls.
type PlatformKeyStoreProvider interface {
	// PlatformKeyStore returns the TPM-backed key store used for user-PIN
	// auth, or nil when the module has none.
	PlatformKeyStore() xkmssdk.PlatformKeyStorer
}

// TPMAcquireFunc opens, or returns a cached handle to, a TPM module for
// the current environment, or reports it is unavailable right now (device
// absent, simulator not requested, an accessor shutting down, ...).
// Implementations serialize concurrent hardware access themselves; the
// provider built by NewTPMProvider only needs the module long enough to
// read its PlatformKeyStore.
type TPMAcquireFunc func() (PlatformKeyStoreProvider, error)

// NewTPMProvider adapts a TPM module accessor to pinselect.TPMProvider,
// the one rule every xKey entry point (GUI, headless daemon, `xkey pin`)
// uses to decide whether TPM2 governs PIN verification in this session.
// It exists so that rule is written once: the xKey GUI's TPM provider and
// the CLI/daemon's both call it, supplying only how each environment
// reaches its own TPM module (the GUI's shared, mutex-serialized
// TPMAccessor; the CLI/daemon's own short-lived open).
//
// persistedTPM2 reports whether the strategy recorded under the data
// directory is already "tpm2". An SRK can exist
// (PlatformKeyStorer.IsInitialized) without a confirmed auth value — left
// by a prior TPM owner, or from a provisioning step that has not run in
// this process yet — and IsInitialized alone must never be read as "a PIN
// is configured here": every PIN check that follows would spend one of
// the TPM's limited dictionary-attack retries against a value nobody has
// confirmed.
//
//   - persistedTPM2 == false: an unconfirmed SRK is never offered. This is
//     the path pinselect.Select probes on a fresh install; offering an
//     inherited, unverified SRK there would silently make it the user's
//     PIN store.
//   - persistedTPM2 == true: an unconfirmed SRK IS offered, because the
//     data directory already says TPM2 governs and Resolve must build
//     that backend rather than refuse it outright. The backend itself
//     still reports the PIN as unset until a verification against the
//     real auth value succeeds, so no attempt is spent on an unconfirmed
//     value without the caller actually supplying one.
func NewTPMProvider(acquire TPMAcquireFunc, persistedTPM2 bool, log *slog.Logger) xkmssdk.PINTPMProvider {
	if log == nil {
		log = slog.Default()
	}
	return tpmProvider{acquire: acquire, persistedTPM2: persistedTPM2, log: log}
}

// tpmProvider implements xkmssdk.PINTPMProvider (pkg/pinselect.TPMProvider)
// over a TPMAcquireFunc.
type tpmProvider struct {
	acquire       TPMAcquireFunc
	persistedTPM2 bool
	log           *slog.Logger
}

// PlatformAuth implements xkmssdk.PINTPMProvider.
func (p tpmProvider) PlatformAuth() (xkmssdk.TPMPlatformAuthProvider, bool) {
	if p.acquire == nil {
		return nil, false
	}

	tpm, err := p.acquire()
	if err != nil || tpm == nil {
		return nil, false
	}

	pks := tpm.PlatformKeyStore()
	if pks == nil || !pks.IsInitialized() {
		return nil, false
	}

	if !pks.IsAuthReady() {
		if !p.persistedTPM2 {
			p.log.Warn("PIN backend: TPM2 SRK exists but auth not confirmed, not offering it")
			return nil, false
		}
		p.log.Warn("PIN backend: TPM2 governs per persisted strategy, SRK auth unconfirmed this session")
	}

	provider, ok := pks.(xkmssdk.TPMPlatformAuthProvider)
	if !ok {
		return nil, false
	}
	return provider, true
}
