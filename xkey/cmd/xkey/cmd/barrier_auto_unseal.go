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

package cmd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
	pcrpolicy "github.com/jeremyhahn/go-xkms/xkey/pkg/pcr_policy"
)

// pcrPolicyStoreSubdir is the data-directory subpath for the PCR policy
// store. It matches the xKey GUI's own PCR policy store exactly
// (pkg/gui/app.go, initializeDataDir: filepath.Join(dir, "pcr_policies")),
// so a policy created or designated for auto-unseal through either surface
// -- the GUI's TPM wizard or `xkey policy set-auto-unseal` -- is visible to
// the other, and to every headless command in this file.
const pcrPolicyStoreSubdir = "pcr_policies"

// ErrBarrierAutoUnsealPolicyStoreFailed indicates the PCR policy store
// backing `xkey policy set-auto-unseal` could not be opened.
var ErrBarrierAutoUnsealPolicyStoreFailed = errors.New("barrier: failed to open PCR policy store")

// tryBarrierPolicyAutoUnseal is the headless counterpart of the xKey GUI's
// boot-time PCR-policy auto-unseal (pkg/gui/app.go initializeDataDir /
// runtime startup, around barrierAutoUnsealService.TryAutoUnseal): both
// drive the same services.BarrierAutoUnsealService against the canonical
// pcrpolicy.DAOStore at <dataDir>/pcr_policies, so a policy designated with
// `xkey policy set-auto-unseal` unseals a tpm2-strategy barrier for any of
// them without a password.
//
// Returns (true, closer, nil) when the barrier was auto-unsealed. closer
// releases the TPM transport that the unsealed barrier's TPM2 strategy now
// holds; the caller owns it and must keep it open for as long as the
// barrier may be used (a long-running daemon should defer its Close until
// shutdown) rather than closing it immediately.
//
// Returns (false, nil, nil) when no auto-unseal policy is configured at
// all -- the expected, silent state for any barrier that never had
// `xkey policy set-auto-unseal` run against it. Callers fall back to their
// normal password/direct-TPM unseal path without logging anything.
//
// Returns (false, nil, err) for every other failure: the policy store
// could not be opened, no TPM is available, or -- critically -- a policy IS
// configured but the current PCR values do not match it
// (services.ErrBarrierAutoUnsealPCRMismatch). Callers MUST log err before
// falling back in this case; a PCR mismatch means the platform state
// changed, and silently trying a password next without a trace would hide
// exactly the event an operator most needs to see.
func tryBarrierPolicyAutoUnseal(ctx context.Context, logger *slog.Logger, barrierSvc *services.BarrierService, dataDir, tpmDevice string, tpmSimulator bool) (unsealed bool, closer io.Closer, err error) {
	store, err := openPolicyStore(filepath.Join(dataDir, pcrPolicyStoreSubdir))
	if err != nil {
		return false, nil, &SentinelCauseError{Sentinel: ErrBarrierAutoUnsealPolicyStoreFailed, Cause: err}
	}
	defer func() {
		err = finalizeAutoUnsealStoreClose(logger, unsealed, err, store.Close())
	}()

	if _, err := store.GetAutoUnsealPolicy(ctx); err != nil {
		if errors.Is(err, pcrpolicy.ErrPolicyNotFound) {
			return false, nil, nil
		}
		return false, nil, &SentinelCauseError{Sentinel: ErrBarrierAutoUnsealPolicyStoreFailed, Cause: err}
	}

	tpm, tpmCloser := probeTPMModule(logger, dataDir, tpmDevice, tpmSimulator)
	if tpm == nil {
		return false, nil, services.ErrBarrierAutoUnsealTPMUnavailable
	}

	barrierSvc.SetTPMSealerFunc(func() xkms.Sealer { return tpm })

	accessor := services.NewTPMAccessor(func() xkms.TrustedPlatformModule { return tpm })
	autoSvc := services.NewBarrierAutoUnsealService(store,
		services.WithBarrierAutoUnsealTPMAccessor(accessor),
		services.WithBarrierAutoUnsealBarrier(barrierSvc),
		services.WithBarrierAutoUnsealLogger(logger),
	)

	ok, unsealErr := autoSvc.TryAutoUnseal(ctx)
	if !ok {
		// Auto-unseal did not succeed (PCR mismatch, TPM error, or the
		// barrier's own Unseal failed): release the TPM here. The caller's
		// fallback (direct TPM unseal or a password) opens its own
		// connection if it needs one, so nothing downstream depends on
		// this transport staying open.
		joinedErr := unsealErr
		if closeErr := tpmCloser.Close(); closeErr != nil {
			joinedErr = errors.Join(joinedErr, closeErr)
		}
		return false, nil, joinedErr
	}
	return true, tpmCloser, nil
}

// finalizeAutoUnsealStoreClose folds the PCR policy store's Close error, if
// any, into tryBarrierPolicyAutoUnseal's result. When the barrier was
// already successfully auto-unsealed (unsealed == true), a Close failure
// doesn't invalidate that result -- the caller already has what it asked
// for -- so it is logged rather than turned into a failure of an
// otherwise-successful call. Otherwise it is joined into err so it isn't
// lost.
func finalizeAutoUnsealStoreClose(logger *slog.Logger, unsealed bool, err, closeErr error) error {
	if closeErr == nil {
		return err
	}
	if unsealed {
		logger.Warn("barrier: failed to close PCR policy store after successful auto-unseal", "error", closeErr)
		return err
	}
	return errors.Join(err, closeErr)
}
