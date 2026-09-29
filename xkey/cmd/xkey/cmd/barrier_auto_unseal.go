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

package cmd

import (
	"context"
	"errors"
	"io"
	"log/slog"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/services"
)

// ErrLocalTPMPoliciesOpenFailed indicates the TPM policy service over this
// host's TPM could not be opened: no TPM, or its registry could not be
// opened under the data directory.
var ErrLocalTPMPoliciesOpenFailed = errors.New("tpm policy: failed to open the local TPM policy service")

// localTPMPolicies is the TPM policy service the CLI runs in-process over
// this host's TPM, and the TPM it runs on. Close closes both.
type localTPMPolicies struct {
	*services.LocalTPMPolicies
	tpm *openedTPM
}

// Close closes the policy service, then the TPM and its key store.
func (l *localTPMPolicies) Close() error {
	return errors.Join(l.LocalTPMPolicies.Close(), l.tpm.Close())
}

// openLocalTPMPolicies opens the TPM policy service over this host's TPM --
// the device at the resolved path, or the in-process simulator -- with its
// registry under dataDir: the same service, over the same stores, as the
// xKey GUI's local mode.
func openLocalTPMPolicies(logger *slog.Logger, dataDir, device string, useSimulator bool) (*localTPMPolicies, error) {
	opened, err := openTPMWithKeyStore(logger, dataDir, device, useSimulator)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLocalTPMPoliciesOpenFailed, Cause: err}
	}
	local, err := services.OpenLocalTPMPolicies(services.LocalTPMPolicyParams{
		TPM:       opened.tpm,
		Keys:      opened.keys(),
		DataDir:   dataDir,
		OpenStore: openEngineStore,
		Logger:    logger,
	})
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrLocalTPMPoliciesOpenFailed, Cause: errors.Join(err, opened.Close())}
	}
	return &localTPMPolicies{LocalTPMPolicies: local, tpm: opened}, nil
}

// openEngineStore opens the store rooted at dir with the storage engine the
// unified config selects ("file" unless state.storage_engine says
// otherwise), exactly as the xKey GUI opens its local stores, so both read
// the same data.
func openEngineStore(dir string) (xkms.StorageBackend, error) {
	kind := "file"
	if cfg := GetConfig(); cfg != nil && cfg.State.StorageEngine != "" {
		kind = cfg.State.StorageEngine
	}
	return xkms.StorageOpenEngine(xkms.StorageEngineConfig{Kind: xkms.StorageEngineKind(kind), Path: dir})
}

// tryBarrierPolicyAutoUnseal is the headless counterpart of the xKey GUI's
// boot-time auto-unseal: both drive services.BarrierAutoUnsealService over
// the local TPM policy service, so the TPM releases the barrier credential
// sealed under the scope's auto-unseal policy (see `xkey tpm policy
// auto-unseal`) through a policy session, and the barrier -- sealed with
// strategy -- is unsealed with it.
//
// Returns (true, closer, nil) when the barrier was auto-unsealed. closer
// releases the TPM the unsealed barrier may still use (a tpm2 strategy); the
// caller owns it and keeps it open for as long as the barrier is used.
//
// Returns (false, nil, nil) when no policy carries the auto-unseal mark --
// the expected, silent state. Callers fall back to their normal unseal path.
//
// Returns (false, nil, err) for every other failure: no TPM, the registry
// could not be opened, or -- critically -- the TPM refused the policy session
// (services.ErrBarrierAutoUnsealRefused: the PCRs changed or the approval was
// revoked). Callers MUST log err before falling back: a refusal means the
// platform state changed, which is exactly the event an operator needs to
// see.
func tryBarrierPolicyAutoUnseal(ctx context.Context, logger *slog.Logger, barrierSvc *services.BarrierService, dataDir string, strategy xkms.StrategyID, tpmDevice string, tpmSimulator bool) (bool, io.Closer, error) {
	local, err := openLocalTPMPolicies(logger, dataDir, tpmDevice, tpmSimulator)
	if err != nil {
		return false, nil, err
	}

	// A tpm2-strategy barrier unseals its root key with the same TPM.
	barrierSvc.SetTPMSealerFunc(func() xkms.Sealer { return local.tpm.tpm })

	autoSvc := services.NewBarrierAutoUnsealService(
		services.WithBarrierAutoUnsealLocal(local.LocalTPMPolicies),
		services.WithBarrierAutoUnsealBarrier(barrierSvc),
		services.WithBarrierAutoUnsealLogger(logger),
	)
	unsealed, err := autoSvc.TryAutoUnseal(ctx, string(strategy))
	if !unsealed {
		// The caller's fallback opens its own TPM connection if it needs one.
		return false, nil, errors.Join(err, local.Close())
	}
	return true, local, nil
}
