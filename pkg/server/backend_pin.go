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
	tpmPresent, barrierAvailable := s.probeBackendPIN()
	strategy, err := pinselect.ResolveBackendPIN(pinselect.BackendPINConfig{
		PINDir:           s.backendPINDir(),
		Strategy:         pinselect.BackendPINStrategy(s.config.BackendPIN.Strategy),
		Minimum:          pinselect.BackendPINStrategy(s.config.BackendPIN.Minimum),
		TPMPresent:       tpmPresent,
		BarrierAvailable: barrierAvailable,
		SealerIsPKCS11:   s.config.Credentials.SealStrategy == "pkcs11",
	})
	if err != nil {
		return err
	}
	s.backendPIN = pinselect.NewBackendPIN(strategy, s.releaseConfiguredPKCS11PIN)
	return nil
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
