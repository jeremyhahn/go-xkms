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

// Package localseal builds a go-qrdb barrier that protects a PKCS#11 token's
// private key material at rest, and adapts it to the module's SealController
// seam. It is the composition-root piece of the offline (local) mode's at-rest
// protection: the module drives WHEN to unseal (at the user login), and this
// package holds the barrier that actually does the encryption.
//
// go-xkms builds NO sealing here — it CONSUMES go-qrdb's barrier through the SDK
// re-export (pkg/seal, surfaced from qrdbsdk). go-qrdb is the single barrier
// authority (stack ownership doc L1; docs/pkcs11-provider-module/architecture.md, Trust boundaries). This
// package only wires the barrier's lifecycle to the PKCS#11 user PIN.
package localseal

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Controller wraps a qrdb barrier and satisfies module.SealController. It is
// unsealed with the user PIN at C_Login(CKU_USER) and resealed at logout /
// finalize. The barrier is initialized lazily on the first unseal, so the first
// user login after C_InitPIN keys the store to that PIN (there is no sensitive
// object to protect before then).
type Controller struct {
	barrier *seal.Barrier
}

// Compile-time check that a Controller is a module.SealController.
var _ module.SealController = (*Controller)(nil)

// New builds a passphrase-protected barrier over base and returns the Controller
// plus the barrier-backed storage.Backend the caller must use for the token's
// private key material. Reads and writes through that backend are encrypted once
// the Controller is unsealed and fail while it is sealed.
//
// rootKeyPath is the storage key under which the sealed root-key blob lives; it
// must be stable across process restarts so the same token re-opens.
func New(base storage.Backend, rootKeyPath string, logger *slog.Logger) (*Controller, storage.Backend, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	barrier, err := seal.NewBarrier(logger, base, seal.BarrierConfig{
		RootKeyPath:     rootKeyPath,
		PreferenceOrder: []seal.StrategyID{seal.StrategyPassphrase},
	}, seal.NewSoftwareStrategy())
	if err != nil {
		return nil, nil, err
	}
	return &Controller{barrier: barrier}, seal.NewBarrierBackend(barrier), nil
}

// Unseal makes the private key material readable using the user PIN as the
// barrier passphrase. It initializes the barrier on first use, so the first
// user login keys the store; subsequent logins just unseal. Both "already
// initialized" and "already unsealed" are benign and tolerated.
func (c *Controller) Unseal(passphrase []byte) (err error) {
	ctx := context.Background()
	creds, credErr := seal.CredentialsFor(ctx, passphrase)
	if credErr != nil {
		return credErr
	}
	defer func() { err = errors.Join(err, creds.Secret.Destroy()) }()

	if initErr := c.barrier.Initialize(ctx, creds); initErr != nil && !isAlreadyInitialized(initErr) {
		return initErr
	}
	if unsealErr := c.barrier.Unseal(ctx, creds); unsealErr != nil && !isAlreadyUnsealed(unsealErr) {
		return unsealErr
	}
	return nil
}

// Seal drops the unsealed key from memory. Sealing an already-sealed barrier is
// a no-op success, so it is safe to call on every logout and finalize.
func (c *Controller) Seal() error {
	if c.barrier.IsSealed() {
		return nil
	}
	return c.barrier.Seal()
}

// Rekey re-wraps the barrier's root key under the new user PIN (qrdb's cheap
// ChangePassword — no data is re-encrypted). It preserves the seal state: a
// barrier sealed on entry (a public-session C_SetPIN) is resealed on exit, so
// the change does not leave key material exposed. If the barrier was never
// initialized — the user changed the PIN before ever logging in and creating a
// key — there is nothing to rekey and the next login keys it to the new PIN.
// CredentialsFor, never NewCredentials, at both sites: NewCredentials wipes
// the caller's slice, and Module.SetPIN reads newPin AFTER this returns —
// it sets the token PIN and hashes its verifier (pkg/pkcs11/module:1580,
// :1584). Wiping here would key the token to NUL bytes while the barrier
// held the real PIN. The cgo boundary already copies these out of the
// application's memory, so nothing is aliased; if PIN wiping is wanted it
// belongs in Module.SetPIN after its last read, not in a constructor here.
//
// The two reseal-on-failure paths below no longer discard the reseal's own
// error. qrdb's StorageBarrier.Seal() (pkg/seal/barrier.go) guarantees the
// barrier's observable state is sealed once it returns, regardless of
// whether it reports an error: it stores stateSealed unconditionally and
// only surfaces an error for observability of a lower-level fault. So the
// barrier is never left in an unsealed or ambiguous state here — Seal's
// error, when non-nil, is joined onto the failure that triggered the reseal
// so both are visible to the caller, not because the barrier's state is in
// doubt.
func (c *Controller) Rekey(oldPassphrase, newPassphrase []byte) (err error) {
	ctx := context.Background()

	wasSealed := c.barrier.IsSealed()
	if wasSealed {
		oldCreds, credErr := seal.CredentialsFor(ctx, oldPassphrase)
		if credErr != nil {
			return credErr
		}
		defer func() { err = errors.Join(err, oldCreds.Secret.Destroy()) }()
		unsealErr := c.barrier.Unseal(ctx, oldCreds)
		if isUninitialized(unsealErr) {
			return nil // no barrier yet; first login will key it to the new PIN
		}
		if unsealErr != nil && !isAlreadyUnsealed(unsealErr) {
			return unsealErr
		}
	}

	newCreds, credErr := seal.CredentialsFor(ctx, newPassphrase)
	if credErr != nil {
		if wasSealed {
			if sealErr := c.barrier.Seal(); sealErr != nil {
				return errors.Join(credErr, sealErr)
			}
		}
		return credErr
	}
	defer func() { err = errors.Join(err, newCreds.Secret.Destroy()) }()
	if changeErr := c.barrier.ChangePassword(ctx, newCreds); changeErr != nil {
		if wasSealed {
			if sealErr := c.barrier.Seal(); sealErr != nil {
				return errors.Join(changeErr, sealErr)
			}
		}
		return changeErr
	}

	if wasSealed {
		return c.barrier.Seal()
	}
	return nil
}

func isAlreadyInitialized(err error) bool {
	return errors.Is(err, seal.ErrAlreadyInitialized)
}

func isAlreadyUnsealed(err error) bool {
	return errors.Is(err, seal.ErrAlreadyUnsealed)
}

// isUninitialized reports whether err means the barrier has no root key yet. A
// never-initialized barrier surfaces this as storage.ErrNotFound (the sealed
// root-key blob is absent) rather than seal.ErrNotInitialized, so both are
// treated as "no barrier yet".
func isUninitialized(err error) bool {
	return errors.Is(err, seal.ErrNotInitialized) || errors.Is(err, storage.ErrNotFound)
}
