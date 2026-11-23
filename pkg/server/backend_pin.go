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

package server

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/jeremyhahn/go-xkms/pkg/pinselect"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// ErrBackendPINNotConfigured reports a backend PIN operation on a server
// with no PKCS#11 backend (and so no backend PIN strategy).
var ErrBackendPINNotConfigured = errors.New("server: no backend PIN strategy (PKCS#11 backend not enabled)")

// errBackendPINNoConfiguredPIN reports a sealed/tpm2 release with no
// resolved backends.pkcs11.pin.
var errBackendPINNoConfiguredPIN = errors.New("server: backends.pkcs11.pin is not set")

// errBackendPINNotTPMSealed reports a tpm2 release whose PIN is not sealed
// to the TPM (credentials.seal_strategy is not tpm2).
var errBackendPINNotTPMSealed = errors.New("server: backend PIN strategy tpm2 needs credentials.seal_strategy tpm2")

// ErrBackendPINManualUnavailable refuses backend_pin.strategy manual (and
// minimum manual) until manual can be operational: the go-qrdb unseal
// request carries no backend PIN, and the xkms service cannot register a
// keystore after start-up (docs/SPEC.md:78).
var ErrBackendPINManualUnavailable = errors.New("server: backend PIN strategy manual is unavailable: the unseal request carries no backend PIN")

// backendPINDir is <datastore>/pin, the directory pinselect persists the
// backend PIN strategy record in (beside the qrdb PIN strategy record).
func (s *Server) backendPINDir() string {
	return filepath.Join(s.config.Datastore.Path, "pin")
}

// pkcs11Enabled reports an enabled PKCS#11 key backend.
func (s *Server) pkcs11Enabled() bool {
	return s.config.Backends.PKCS11 != nil && s.config.Backends.PKCS11.Enabled
}

// resolveBackendPIN resolves the backend PIN strategy through
// pinselect.ResolveBackendPIN at start-up, beside buildSecretRegistry
// (owner decision 230, #2262). It persists the strategy and installs the
// in-memory holder; it starts nothing. A refused resolution is returned
// unchanged so start-up stops (fail closed, never a silent downgrade).
func (s *Server) resolveBackendPIN() error {
	if !s.pkcs11Enabled() {
		return nil
	}
	// Manual is refused before anything is persisted or released: no
	// unseal request carries the PIN yet (ErrBackendPINManualUnavailable).
	if s.config.BackendPIN.Strategy == string(pinselect.BackendPINManual) ||
		s.config.BackendPIN.Minimum == string(pinselect.BackendPINManual) {
		return ErrBackendPINManualUnavailable
	}
	tpmPresent, barrierAvailable := s.probeBackendPIN()
	strategy, err := pinselect.ResolveBackendPIN(pinselect.BackendPINConfig{
		PINDir:   s.backendPINDir(),
		Strategy: pinselect.BackendPINStrategy(s.config.BackendPIN.Strategy),
		Minimum:  pinselect.BackendPINStrategy(s.config.BackendPIN.Minimum),
		// tpm2 is only available when the PIN is actually sealed to the
		// TPM: a TPM beside a barrier-sealed PIN protects nothing, so it
		// never satisfies strategy or minimum tpm2 (docs/SPEC.md:78).
		TPMPresent:       tpmPresent && s.pinSealedToTPM(),
		BarrierAvailable: barrierAvailable,
		SealerIsPKCS11:   s.sealerIsPKCS11(),
	})
	if err != nil {
		return err
	}
	if strategy == pinselect.BackendPINManual {
		// A record persisted as manual by an earlier release.
		return ErrBackendPINManualUnavailable
	}
	s.installBackendPIN(strategy)
	return nil
}

// installBackendPIN installs the in-memory holder for strategy and ties its
// zeroization to the running barrier's seal.
func (s *Server) installBackendPIN(strategy pinselect.BackendPINStrategy) {
	s.backendPIN = pinselect.NewBackendPIN(strategy, s.backendPINRelease(strategy))
	// Zeroize at every seal of the running barrier, not only at shutdown:
	// the barrier runs this before it wipes its own root key.
	if s.barrier != nil {
		s.barrier.OnSealing(func(context.Context) error {
			return s.SealBackendPIN()
		})
	}
}

// pinSealedToTPM reports backend credentials sealed to the TPM
// (credentials.seal_strategy tpm2), the protection strategy tpm2 asserts.
func (s *Server) pinSealedToTPM() bool {
	return s.config.Credentials.SealStrategy == "tpm2"
}

// sealerIsPKCS11 reports a PKCS#11 token as the actual sealer of a sealed
// backend PIN: the barrier itself sealed by PKCS#11 (barrier.strategy
// pkcs11), or credentials sealed directly to PKCS#11. Either way the token
// would store its own PIN (docs/SPEC.md:78).
func (s *Server) sealerIsPKCS11() bool {
	return s.config.Barrier.Strategy == "pkcs11" || s.config.Credentials.SealStrategy == "pkcs11"
}

// backendPINRelease is the strategy-specific release: tpm2 re-checks at
// every release that the PIN is still sealed to the TPM, so a holder never
// releases a PIN whose protection is weaker than the persisted strategy.
func (s *Server) backendPINRelease(strategy pinselect.BackendPINStrategy) func(context.Context) ([]byte, error) {
	if strategy != pinselect.BackendPINTPM2 {
		return s.releaseConfiguredPKCS11PIN
	}
	return func(ctx context.Context) ([]byte, error) {
		if !s.pinSealedToTPM() {
			return nil, errBackendPINNotTPMSealed
		}
		return s.releaseConfiguredPKCS11PIN(ctx)
	}
}

// probeBackendPIN reports a usable TPM 2.0 and a barrier able to seal.
func (s *Server) probeBackendPIN() (bool, bool) {
	if s.backendPINProbe != nil {
		return s.backendPINProbe()
	}
	tpm := s.config.Backends.TPM2 != nil && s.config.Backends.TPM2.Enabled
	return tpm, s.barrier != nil
}

// releaseConfiguredPKCS11PIN releases the sealed/tpm2 PIN: the resolved
// backends.pkcs11.pin, readable only after unseal (resolveConfigSecrets
// runs after the barrier is unsealed). The copy is owned by the holder.
func (s *Server) releaseConfiguredPKCS11PIN(ctx context.Context) ([]byte, error) {
	if !s.pkcs11Enabled() || s.config.Backends.PKCS11.Pin == nil {
		return nil, errBackendPINNoConfiguredPIN
	}
	var pin []byte
	err := s.config.Backends.PKCS11.Pin.WithBytes(ctx, func(b []byte) error {
		pin = append([]byte(nil), b...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pin, nil
}

// startPKCS11AfterUnseal starts the PKCS#11 backend once the barrier is
// unsealed: sealed and tpm2 release the PIN and open the token; manual
// waits for UnsealBackendPIN.
func (s *Server) startPKCS11AfterUnseal() error {
	if s.backendPIN == nil || s.backendPIN.Strategy() == pinselect.BackendPINManual {
		return nil
	}
	if err := s.backendPIN.Unseal(s.ctx, nil); err != nil {
		return &ErrBackendInit{Backend: "PKCS#11", Err: err}
	}
	return s.openPKCS11WithHeldPIN()
}

// UnsealBackendPIN takes the manual backend PIN carried by the unseal
// request, holds a copy in memory only, and starts the PKCS#11 backend.
// It refuses a PIN under any other strategy.
func (s *Server) UnsealBackendPIN(ctx context.Context, pin []byte) error {
	if s.backendPIN == nil {
		return ErrBackendPINNotConfigured
	}
	if s.backendPIN.Strategy() != pinselect.BackendPINManual {
		return pinselect.ErrBackendPINNotManual
	}
	if err := s.backendPIN.Unseal(ctx, pin); err != nil {
		return err
	}
	return s.openPKCS11WithHeldPIN()
}

// openPKCS11WithHeldPIN opens the token with the held PIN and registers it.
func (s *Server) openPKCS11WithHeldPIN() error {
	if _, ok := s.keyProviders["pkcs11"]; ok {
		return nil
	}
	pin, err := s.backendPIN.PIN()
	if err != nil {
		return &ErrBackendInit{Backend: "PKCS#11", Err: err}
	}
	// PIN returns a fresh plaintext copy: wipe it once the opener returns,
	// on success and failure (the opener keeps its own sealed copy).
	defer clear(pin)
	opener := s.pkcs11PINOpener
	if opener == nil {
		opener = s.defaultPKCS11PINOpener
	}
	provider, err := opener(pin)
	if err != nil {
		return &ErrBackendInit{Backend: "PKCS#11", Err: err}
	}
	if s.keyProviders == nil {
		s.keyProviders = map[string]types.KeyProvider{}
	}
	s.keyProviders["pkcs11"] = provider
	return nil
}

// SealBackendPIN runs at seal: under manual the PKCS#11 backend stops;
// under every strategy the held PIN is zeroized.
func (s *Server) SealBackendPIN() error {
	if s.backendPIN == nil {
		return nil
	}
	var closeErr error
	if s.backendPIN.StopsAtSeal() {
		if provider, ok := s.keyProviders["pkcs11"]; ok {
			delete(s.keyProviders, "pkcs11")
			closeErr = provider.Close()
		}
	}
	s.backendPIN.Seal()
	return closeErr
}

// BackendPINStrategy reports the persisted backend PIN strategy for
// status; empty when no PKCS#11 backend is enabled.
func (s *Server) BackendPINStrategy() string {
	if s.backendPIN == nil {
		return ""
	}
	return string(s.backendPIN.Strategy())
}
